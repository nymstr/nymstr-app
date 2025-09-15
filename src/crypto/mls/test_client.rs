//! Test-only MLS client following mls-rs basic_usage.rs pattern

#[cfg(test)]
pub mod test_client {
    use crate::crypto::mls::test_storage::test_providers::TestStorageProvider;
    use crate::crypto::mls::types::{EncryptedMessage, MlsMessageType, ConversationInfo, MlsGroupInfo, ConversationType};
    use mls_rs::{
        client_builder::MlsConfig,
        identity::{
            basic::{BasicCredential, BasicIdentityProvider},
            SigningIdentity,
        },
        CipherSuite, Client, ExtensionList, MlsMessage, CryptoProvider, CipherSuiteProvider,
        group::ReceivedMessage,
        error::MlsError,
        crypto::SignatureSecretKey,
    };
    use mls_rs_crypto_openssl::OpensslCryptoProvider;
    use anyhow::{Result, anyhow};

    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

    pub struct TestMlsClient {
        identity: String,
        storage: TestStorageProvider,
        signing_identity: SigningIdentity,
        secret_key: SignatureSecretKey,
    }

    impl TestMlsClient {
        pub fn new(identity: &str) -> Result<Self> {
            let storage = TestStorageProvider::new();

            // Generate keys once and store them
            let crypto_provider = OpensslCryptoProvider::default();
            let cipher_suite = crypto_provider.cipher_suite_provider(TEST_CIPHER_SUITE).unwrap();
            let (secret, public) = cipher_suite.signature_key_generate().unwrap();

            let basic_identity = BasicCredential::new(identity.as_bytes().to_vec());
            let signing_identity = SigningIdentity::new(basic_identity.into_credential(), public);

            Ok(Self {
                identity: identity.to_string(),
                storage,
                signing_identity,
                secret_key: secret,
            })
        }

        pub fn identity(&self) -> &str {
            &self.identity
        }

        fn make_client(&self) -> Result<Client<impl MlsConfig>, MlsError> {
            let crypto_provider = OpensslCryptoProvider::default();

            Ok(Client::builder()
                .identity_provider(BasicIdentityProvider)
                .crypto_provider(crypto_provider)
                .group_state_storage(self.storage.group_storage.clone())
                .key_package_repo(self.storage.key_package_storage.clone())
                .psk_store(self.storage.psk_storage.clone())
                .signing_identity(self.signing_identity.clone(), self.secret_key.clone(), TEST_CIPHER_SUITE)
                .build())
        }

        pub fn generate_key_package(&self) -> Result<Vec<u8>> {
            let client = self.make_client().map_err(|e| anyhow!("Failed to create client: {}", e))?;
            let key_package = client
                .generate_key_package_message(Default::default(), Default::default(), None)
                .map_err(|e| anyhow!("Failed to generate key package: {}", e))?;

            key_package.to_bytes()
                .map_err(|e| anyhow!("Failed to serialize key package: {}", e))
        }

        pub async fn start_conversation(&self, recipient_key_package: &[u8]) -> Result<ConversationInfo> {
            let client = self.make_client().map_err(|e| anyhow!("Failed to create client: {}", e))?;

            // Parse recipient's key package
            let key_package_msg = MlsMessage::from_bytes(recipient_key_package)
                .map_err(|e| anyhow!("Failed to parse recipient key package: {}", e))?;

            // Create a new MLS group
            let mut group = client
                .create_group(ExtensionList::default(), Default::default(), None)
                .map_err(|e| anyhow!("Failed to create MLS group: {}", e))?;

            let group_id = group.group_id().to_vec();

            // Add the recipient to the group
            let commit_result = group.commit_builder()
                .add_member(key_package_msg)
                .map_err(|e| anyhow!("Failed to add member to group: {}", e))?
                .build()
                .map_err(|e| anyhow!("Failed to build commit: {}", e))?;

            // Apply the pending commit locally
            group.apply_pending_commit()
                .map_err(|e| anyhow!("Failed to apply pending commit: {}", e))?;

            // Save the group state
            group.write_to_storage()
                .map_err(|e| anyhow!("Failed to save group state: {}", e))?;

            // Extract welcome message for the recipient
            let welcome_message = if !commit_result.welcome_messages.is_empty() {
                Some(commit_result.welcome_messages[0].to_bytes()
                    .map_err(|e| anyhow!("Failed to serialize welcome message: {}", e))?)
            } else {
                None
            };

            Ok(ConversationInfo {
                conversation_id: group_id.clone(),
                conversation_type: ConversationType::OneToOne,
                participants: 2,
                welcome_message,
                group_info: MlsGroupInfo {
                    group_id,
                    client_identity: self.identity.clone(),
                },
            })
        }

        pub async fn join_conversation(&self, welcome_bytes: &[u8]) -> Result<ConversationInfo> {
            let client = self.make_client().map_err(|e| anyhow!("Failed to create client: {}", e))?;

            // Parse welcome message
            let welcome_message = MlsMessage::from_bytes(welcome_bytes)
                .map_err(|e| anyhow!("Failed to parse welcome message: {}", e))?;

            // Join the group using the welcome message
            let (mut group, _roster_update) = client
                .join_group(None, &welcome_message, None)
                .map_err(|e| anyhow!("Failed to join MLS group: {}", e))?;

            let group_id = group.group_id().to_vec();

            // Save the joined group state
            group.write_to_storage()
                .map_err(|e| anyhow!("Failed to save joined group state: {}", e))?;

            Ok(ConversationInfo {
                conversation_id: group_id.clone(),
                conversation_type: ConversationType::OneToOne,
                participants: 2,
                welcome_message: None,
                group_info: MlsGroupInfo {
                    group_id,
                    client_identity: self.identity.clone(),
                },
            })
        }

        pub async fn encrypt_message(&self, conversation_id: &[u8], plaintext: &[u8]) -> Result<EncryptedMessage> {
            let client = self.make_client().map_err(|e| anyhow!("Failed to create client: {}", e))?;

            // Load the group from storage
            let mut group = client.load_group(conversation_id)
                .map_err(|e| anyhow!("Failed to load MLS group: {}", e))?;

            // Encrypt the message using MLS
            let application_message = group.encrypt_application_message(plaintext, Default::default())
                .map_err(|e| anyhow!("Failed to encrypt MLS message: {}", e))?;

            // Serialize the MLS message
            let mls_message_bytes = application_message.to_bytes()
                .map_err(|e| anyhow!("Failed to serialize MLS message: {}", e))?;

            // Save the group state after encryption
            group.write_to_storage()
                .map_err(|e| anyhow!("Failed to save group state after encryption: {}", e))?;

            Ok(EncryptedMessage {
                conversation_id: conversation_id.to_vec(),
                mls_message: mls_message_bytes,
                message_type: MlsMessageType::Application,
            })
        }

        pub async fn decrypt_message(&self, encrypted: &EncryptedMessage) -> Result<Vec<u8>> {
            let client = self.make_client().map_err(|e| anyhow!("Failed to create client: {}", e))?;

            // Load the group from storage
            let mut group = client.load_group(&encrypted.conversation_id)
                .map_err(|e| anyhow!("Failed to load MLS group: {}", e))?;

            // Parse the MLS message
            let mls_message = MlsMessage::from_bytes(&encrypted.mls_message)
                .map_err(|e| anyhow!("Failed to parse MLS message: {}", e))?;

            // Process the incoming message and decrypt using MLS
            let received_message = group.process_incoming_message(mls_message)
                .map_err(|e| anyhow!("Failed to process incoming MLS message: {}", e))?;

            // Save the group state after processing
            group.write_to_storage()
                .map_err(|e| anyhow!("Failed to save group state after decryption: {}", e))?;

            // Extract the plaintext from the processed message
            match received_message {
                ReceivedMessage::ApplicationMessage(app_msg) => {
                    Ok(app_msg.data().to_vec())
                }
                _ => {
                    Err(anyhow!("Expected application message, got different message type"))
                }
            }
        }

        pub async fn add_member(&self, conversation_id: &[u8], key_package_bytes: &[u8]) -> Result<EncryptedMessage> {
            let client = self.make_client().map_err(|e| anyhow!("Failed to create client: {}", e))?;

            // Load the existing group
            let mut group = client.load_group(conversation_id)
                .map_err(|e| anyhow!("Failed to load MLS group: {}", e))?;

            // Parse the new member's key package
            let key_package = MlsMessage::from_bytes(key_package_bytes)
                .map_err(|e| anyhow!("Failed to parse key package: {}", e))?;

            // Create a commit that adds the new member
            let commit_result = group.commit_builder()
                .add_member(key_package)
                .map_err(|e| anyhow!("Failed to add member to group: {}", e))?
                .build()
                .map_err(|e| anyhow!("Failed to build add member commit: {}", e))?;

            // Apply the pending commit locally
            group.apply_pending_commit()
                .map_err(|e| anyhow!("Failed to apply pending commit: {}", e))?;

            // Save the updated group state
            group.write_to_storage()
                .map_err(|e| anyhow!("Failed to save updated group state: {}", e))?;

            // Convert the commit to bytes for sending to other members
            let commit_bytes = commit_result.commit_message.to_bytes()
                .map_err(|e| anyhow!("Failed to serialize commit message: {}", e))?;

            Ok(EncryptedMessage {
                conversation_id: conversation_id.to_vec(),
                mls_message: commit_bytes,
                message_type: MlsMessageType::Commit,
            })
        }

        pub async fn export_group_state(&self, conversation_id: &[u8]) -> Result<Vec<u8>> {
            let client = self.make_client().map_err(|e| anyhow!("Failed to create client: {}", e))?;

            // For test client, we'll export the raw group state
            let _group = client.load_group(conversation_id)
                .map_err(|e| anyhow!("Failed to load MLS group: {}", e))?;

            // This is a simplified export - in real implementation we'd serialize the entire group state
            Ok(conversation_id.to_vec())
        }
    }
}