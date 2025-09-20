//! MLS client wrapper with proper group state persistence using MLS-RS 0.49.0
//!
//! This implementation uses the correct MLS-RS ClientBuilder API with proper
//! storage providers for maintaining group state consistency.

use anyhow::{Result, anyhow};
use mls_rs::{
    client_builder::MlsConfig,
    identity::SigningIdentity,
    CipherSuite, Client, ExtensionList, MlsMessage,
    IdentityProvider, CryptoProvider, CipherSuiteProvider,
    crypto::SignatureSecretKey,
    group::ReceivedMessage,
};
use mls_rs_crypto_openssl::OpensslCryptoProvider;
use pgp::composed::{SignedSecretKey, SignedPublicKey};
use std::sync::Arc;
use base64::Engine;

use crate::core::db::Db;
use crate::crypto::pgp::{PgpKeyManager, PgpSigner};
use super::types::{EncryptedMessage, MlsMessageType, MlsGroupInfo, ConversationInfo, ConversationType};
use mls_rs_provider_sqlite::{
    SqLiteDataStorageEngine,
    connection_strategy::FileConnectionStrategy,
};

/// MLS client wrapper with proper group state persistence
/// This wraps a single mls-rs Client that manages multiple conversations
pub struct MlsClient {
    identity: String,
    pgp_secret_key: SignedSecretKey,
    pgp_public_key: SignedPublicKey,
    db: Arc<Db>,
    // We'll store the client components and create it lazily
    storage_engine: SqLiteDataStorageEngine<FileConnectionStrategy>,
    signing_identity: SigningIdentity,
    secret_key: SignatureSecretKey,
    cipher_suite: CipherSuite,
    // Note: We create clients fresh each time since it's cheap and avoids type complexity
}

impl MlsClient {
    /// Create a new MLS client with persistent storage
    pub fn new(identity: &str, pgp_secret_key: SignedSecretKey, pgp_public_key: SignedPublicKey, db: Arc<Db>) -> Result<Self> {
        // Create MLS database path (separate from main app database)
        let mls_db_path = crate::core::db::get_mls_db_path(identity);
        let connection_strategy = FileConnectionStrategy::new(std::path::Path::new(&mls_db_path));
        let storage_engine = SqLiteDataStorageEngine::new(connection_strategy)
            .map_err(|e| anyhow!("Failed to create MLS storage engine: {}", e))?;

        // Create PGP credential for MLS
        let pgp_credential = PgpCredential::new(identity.to_string(), &pgp_public_key)?;
        let credential = pgp_credential.into_credential()?;

        // Generate MLS signature keys
        let crypto_provider = OpensslCryptoProvider::default();
        let cipher_suite = CipherSuite::CURVE25519_AES128;
        let cipher_suite_provider = crypto_provider.cipher_suite_provider(cipher_suite)
            .ok_or_else(|| anyhow!("Cipher suite not supported"))?;

        let (secret_key, public_key) = cipher_suite_provider.signature_key_generate()
            .map_err(|e| anyhow!("Failed to generate MLS signature keys: {}", e))?;

        let signing_identity = SigningIdentity::new(credential, public_key);

        Ok(Self {
            identity: identity.to_string(),
            pgp_secret_key,
            pgp_public_key,
            db,
            storage_engine,
            signing_identity,
            secret_key,
            cipher_suite,
        })
    }

    /// Create a new MLS client and generate PGP keys
    pub fn new_with_generated_keys(identity: &str, db: Arc<Db>) -> Result<Self> {
        let (pgp_secret_key, pgp_public_key) = PgpKeyManager::generate_keypair(identity)?;
        Self::new(identity, pgp_secret_key, pgp_public_key, db)
    }

    /// Create an MLS client with the configured storage
    pub fn create_client(&self) -> Result<Client<impl MlsConfig>> {
        let crypto_provider = OpensslCryptoProvider::default();

        // Note: build() returns Client directly, no Result wrapping
        let client = Client::builder()
            .group_state_storage(self.storage_engine.group_state_storage()
                .map_err(|e| anyhow!("Failed to create group storage: {}", e))?)
            .key_package_repo(self.storage_engine.key_package_storage()
                .map_err(|e| anyhow!("Failed to create key package storage: {}", e))?)
            .psk_store(self.storage_engine.pre_shared_key_storage()
                .map_err(|e| anyhow!("Failed to create PSK storage: {}", e))?)
            .identity_provider(PgpIdentityProvider)
            .crypto_provider(crypto_provider)
            .signing_identity(self.signing_identity.clone(), self.secret_key.clone(), self.cipher_suite)
            .build();

        Ok(client)
    }

    /// Create a new MLS group
    pub async fn create_group(&self) -> Result<MlsGroupInfo> {
        log::info!("Creating MLS group for user {}", self.identity);

        let client = self.create_client()?;
        let mut group = client.create_group(ExtensionList::default(), ExtensionList::default(), None)
            .map_err(|e| anyhow!("Failed to create group: {}", e))?;

        let group_id = group.group_id().to_vec();

        // Save the group (it will persist via our storage provider)
        group.write_to_storage()
            .map_err(|e| anyhow!("Failed to save group: {}", e))?;

        Ok(MlsGroupInfo {
            group_id,
            client_identity: self.identity.clone(),
        })
    }

    /// Generate a key package for joining groups
    pub fn generate_key_package(&self) -> Result<Vec<u8>> {
        log::info!("Generating key package for user {}", self.identity);

        let client = self.create_client()?;
        let key_package = client.generate_key_package_message(ExtensionList::default(), ExtensionList::default(), None)
            .map_err(|e| anyhow!("Failed to generate key package: {}", e))?;

        key_package.to_bytes()
            .map_err(|e| anyhow!("Failed to serialize key package: {}", e))
    }

    /// Start a 1:1 conversation (creates a 2-person MLS group)
    pub async fn start_conversation(&self, recipient_key_package: &[u8]) -> Result<ConversationInfo> {
        log::info!("Starting conversation for user {}", self.identity);

        // Parse recipient's key package
        let key_package_msg = MlsMessage::from_bytes(recipient_key_package)
            .map_err(|e| anyhow!("Failed to parse recipient key package: {}", e))?;

        // Create a new MLS group
        let client = self.create_client()?;
        let mut group = client.create_group(ExtensionList::default(), ExtensionList::default(), None)
            .map_err(|e| anyhow!("Failed to create MLS group: {}", e))?;

        let group_id = group.group_id().to_vec();
        let conversation_id_str = base64::engine::general_purpose::STANDARD.encode(&group_id);

        // Add the recipient to the group
        log::info!("Adding member to group for conversation {} (user: {})", conversation_id_str, self.identity);
        let commit_result = group.commit_builder()
            .add_member(key_package_msg)
            .map_err(|e| anyhow!("Failed to add member to group: {}", e))?
            .build()
            .map_err(|e| anyhow!("Failed to build commit: {}", e))?;
        log::info!("Built commit for conversation {} (user: {})", conversation_id_str, self.identity);

        // Apply the pending commit locally
        log::info!("Applying pending commit for conversation {} (user: {})", conversation_id_str, self.identity);
        group.apply_pending_commit()
            .map_err(|e| anyhow!("Failed to apply pending commit for user {} in conversation {}: {}", self.identity, conversation_id_str, e))?;
        log::info!("Successfully applied pending commit for conversation {} (user: {})", conversation_id_str, self.identity);

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

        log::info!("Successfully created MLS conversation {} with recipient", conversation_id_str);

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

    /// Join a 1:1 conversation using a welcome message
    pub async fn join_conversation(&self, welcome_bytes: &[u8]) -> Result<ConversationInfo> {
        log::info!("Joining conversation for user {}", self.identity);

        // Parse welcome message
        let welcome_message = MlsMessage::from_bytes(welcome_bytes)
            .map_err(|e| anyhow!("Failed to parse welcome message: {}", e))?;

        // Join the group using the welcome message
        let client = self.create_client()?;
        let (mut group, _roster_update) = client.join_group(None, &welcome_message, None)
            .map_err(|e| anyhow!("Failed to join MLS group: {}", e))?;

        let group_id = group.group_id().to_vec();
        let conversation_id_str = base64::engine::general_purpose::STANDARD.encode(&group_id);

        // Save the joined group state
        group.write_to_storage()
            .map_err(|e| anyhow!("Failed to save joined group state: {}", e))?;

        // TODO: Get actual participant count from roster
        let participant_count = 2; // Placeholder - in reality we'd check the roster

        log::info!("Successfully joined MLS conversation {}", conversation_id_str);

        Ok(ConversationInfo {
            conversation_id: group_id.clone(),
            conversation_type: ConversationType::OneToOne,
            participants: participant_count,
            welcome_message: None, // Joiners don't need to send welcome messages
            group_info: MlsGroupInfo {
                group_id,
                client_identity: self.identity.clone(),
            },
        })
    }

    /// Encrypt message for any conversation using persistent group state
    pub async fn encrypt_message(&self, conversation_id: &[u8], plaintext: &[u8]) -> Result<EncryptedMessage> {
        let conversation_id_str = base64::engine::general_purpose::STANDARD.encode(conversation_id);
        log::info!("Encrypting message for user {} in conversation {}", self.identity, conversation_id_str);

        // Load the group from storage
        let client = self.create_client()?;
        let mut group = client.load_group(conversation_id)
            .map_err(|e| anyhow!("Failed to load MLS group for conversation {}: {}", conversation_id_str, e))?;

        // Encrypt the message using MLS
        let application_message = group.encrypt_application_message(plaintext, Default::default())
            .map_err(|e| anyhow!("Failed to encrypt MLS message: {}", e))?;

        // Serialize the MLS message
        let mls_message_bytes = application_message.to_bytes()
            .map_err(|e| anyhow!("Failed to serialize MLS message: {}", e))?;

        // Save the group state after encryption (epoch might have advanced)
        group.write_to_storage()
            .map_err(|e| anyhow!("Failed to save group state after encryption: {}", e))?;

        log::info!("Successfully encrypted message using MLS group for conversation {}", conversation_id_str);

        Ok(EncryptedMessage {
            conversation_id: conversation_id.to_vec(),
            mls_message: mls_message_bytes,
            message_type: MlsMessageType::Application,
        })
    }

    /// Decrypt message from any conversation using persistent group state
    pub async fn decrypt_message(&self, encrypted: &EncryptedMessage) -> Result<Vec<u8>> {
        let conversation_id_str = base64::engine::general_purpose::STANDARD.encode(&encrypted.conversation_id);
        log::info!("Decrypting message for user {} in conversation {}", self.identity, conversation_id_str);

        // Load the group from storage
        let client = self.create_client()?;
        let mut group = client.load_group(&encrypted.conversation_id)
            .map_err(|e| anyhow!("Failed to load MLS group for conversation {}: {}", conversation_id_str, e))?;

        // Parse the MLS message
        let mls_message = MlsMessage::from_bytes(&encrypted.mls_message)
            .map_err(|e| anyhow!("Failed to parse MLS message: {}", e))?;

        // Process the incoming message and decrypt using MLS
        let received_message = group.process_incoming_message(mls_message)
            .map_err(|e| anyhow!("Failed to process incoming MLS message: {}", e))?;

        // Save the group state after processing (epoch might have advanced)
        group.write_to_storage()
            .map_err(|e| anyhow!("Failed to save group state after decryption: {}", e))?;

        // Extract the plaintext from the processed message
        match received_message {
            ReceivedMessage::ApplicationMessage(app_msg) => {
                log::info!("Successfully decrypted application message for conversation {}", conversation_id_str);
                Ok(app_msg.data().to_vec())
            }
            _ => {
                log::warn!("Received non-application message in conversation {}", conversation_id_str);
                Err(anyhow!("Expected application message, got different message type"))
            }
        }
    }

    /// Add member to existing conversation (converts 1:1 to group)
    pub async fn add_member(&self, conversation_id: &[u8], key_package_bytes: &[u8]) -> Result<EncryptedMessage> {
        let conversation_id_str = base64::engine::general_purpose::STANDARD.encode(conversation_id);
        log::info!("Adding member for user {} in conversation {}", self.identity, conversation_id_str);

        // Load the existing group
        let client = self.create_client()?;
        let mut group = client.load_group(conversation_id)
            .map_err(|e| anyhow!("Failed to load MLS group for conversation {}: {}", conversation_id_str, e))?;

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

        log::info!("Successfully added member to conversation {}", conversation_id_str);

        Ok(EncryptedMessage {
            conversation_id: conversation_id.to_vec(),
            mls_message: commit_bytes,
            message_type: MlsMessageType::Commit,
        })
    }

    /// Get identity
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Get PGP public key
    pub fn pgp_public_key(&self) -> &SignedPublicKey {
        &self.pgp_public_key
    }

    /// Get PGP secret key
    pub fn pgp_secret_key(&self) -> &SignedSecretKey {
        &self.pgp_secret_key
    }

    /// Sign data with PGP key (for backward compatibility)
    pub fn pgp_sign(&self, data: &[u8]) -> Result<String> {
        PgpSigner::sign_detached(&self.pgp_secret_key, data)
    }

    /// Export group state for backup/migration purposes
    pub async fn export_group_state(&self, conversation_id: &[u8]) -> Result<Vec<u8>> {
        let group_id_str = base64::engine::general_purpose::STANDARD.encode(conversation_id);

        // Load the group from the MLS client and export its state
        let client = self.create_client()?;
        let group = client.load_group(conversation_id)
            .map_err(|e| anyhow!("Failed to load MLS group for conversation {}: {}", group_id_str, e))?;

        // Export the group state (this gets the serialized state)
        let state = group.group_id().to_vec(); // This is a placeholder - in practice you might export more data

        log::info!("Exported group state for conversation {} (size: {} bytes)",
                  group_id_str, state.len());
        Ok(state)
    }

    /// Create welcome message for a conversation
    pub fn create_welcome_message(&self, conversation_info: &ConversationInfo) -> Result<String> {
        // Use the actual welcome message from the conversation info if available
        if let Some(welcome_bytes) = &conversation_info.welcome_message {
            return Ok(base64::engine::general_purpose::STANDARD.encode(welcome_bytes));
        }

        // If no welcome message, this is an error since all conversations should have welcome messages
        Err(anyhow!("No welcome message available in conversation info"))
    }
}

// Import the PGP credential and identity provider types
use serde::{Deserialize, Serialize};
use mls_rs_core::identity::{
    Credential, CredentialType, CustomCredential, MemberValidationContext, MlsCredential,
};
use mls_rs_core::error::IntoAnyError;
use mls_rs_core::time::MlsTime;

/// PGP-based credential for MLS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgpCredential {
    pub user_id: String,
    pub public_key_armored: String,
}

impl PgpCredential {
    pub fn new(user_id: String, public_key: &SignedPublicKey) -> Result<Self> {
        let public_key_armored = PgpKeyManager::public_key_armored(public_key)?;
        Ok(Self {
            user_id,
            public_key_armored,
        })
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    pub fn public_key_armored(&self) -> &str {
        &self.public_key_armored
    }
}

impl MlsCredential for PgpCredential {
    type Error = anyhow::Error;

    fn credential_type() -> CredentialType {
        CredentialType::new(0x1000) // Custom PGP credential type
    }

    fn into_credential(self) -> Result<Credential, Self::Error> {
        let serialized = serde_json::to_vec(&self)
            .map_err(|e| anyhow!("Failed to serialize PGP credential: {}", e))?;

        let custom_cred = CustomCredential::new(Self::credential_type(), serialized);
        Ok(Credential::Custom(custom_cred))
    }
}

/// PGP Identity Provider for MLS
#[derive(Debug, Clone)]
pub struct PgpIdentityProvider;

/// Error type for PGP identity validation
#[derive(Debug)]
pub struct PgpIdentityError(String);

impl std::fmt::Display for PgpIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PGP identity error: {}", self.0)
    }
}

impl std::error::Error for PgpIdentityError {}

impl IntoAnyError for PgpIdentityError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

impl IdentityProvider for PgpIdentityProvider {
    type Error = PgpIdentityError;

    fn validate_member(
        &self,
        signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _context: MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        // Extract and validate PGP credential
        let credential = &signing_identity.credential;
        if let Some(custom_cred) = credential.as_custom() {
            if custom_cred.credential_type == PgpCredential::credential_type() {
                let pgp_cred: PgpCredential = serde_json::from_slice(&custom_cred.data)
                    .map_err(|e| PgpIdentityError(format!("Failed to deserialize PGP credential: {}", e)))?;

                // Validate PGP credential
                if pgp_cred.user_id.is_empty() {
                    return Err(PgpIdentityError("Empty user ID in PGP credential".to_string()));
                }

                if pgp_cred.public_key_armored.is_empty() {
                    return Err(PgpIdentityError("Empty public key in PGP credential".to_string()));
                }

                // TODO: Add PGP key format validation and signature verification
                return Ok(());
            }
        }

        Err(PgpIdentityError("Invalid or missing PGP credential".to_string()))
    }

    fn validate_external_sender(
        &self,
        signing_identity: &SigningIdentity,
        timestamp: Option<MlsTime>,
        _extensions: Option<&mls_rs_core::extension::ExtensionList>,
    ) -> Result<(), Self::Error> {
        // For now, use same validation as member
        self.validate_member(signing_identity, timestamp, MemberValidationContext::None)
    }

    fn identity(
        &self,
        signing_identity: &SigningIdentity,
        _extensions: &mls_rs_core::extension::ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        // Extract user ID as identity
        let credential = &signing_identity.credential;
        if let Some(custom_cred) = credential.as_custom() {
            if custom_cred.credential_type == PgpCredential::credential_type() {
                let pgp_cred: PgpCredential = serde_json::from_slice(&custom_cred.data)
                    .map_err(|e| PgpIdentityError(format!("Failed to deserialize PGP credential: {}", e)))?;
                return Ok(pgp_cred.user_id.into_bytes());
            }
        }
        Err(PgpIdentityError("Invalid or missing PGP credential".to_string()))
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
        _extensions: &mls_rs_core::extension::ExtensionList,
    ) -> Result<bool, Self::Error> {
        // Check if both have the same user ID
        let pred_id = self.identity(predecessor, _extensions)?;
        let succ_id = self.identity(successor, _extensions)?;
        Ok(pred_id == succ_id)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![PgpCredential::credential_type()]
    }
}