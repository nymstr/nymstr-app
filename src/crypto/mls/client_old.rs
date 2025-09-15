//! MLS client wrapper for group messaging

use anyhow::{Result, anyhow};
use mls_rs::{
    client_builder::MlsConfig,
    identity::SigningIdentity,
    storage_provider::StorageProvider,
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList,
    MlsMessage, Group,
};
use mls_rs_crypto_openssl::OpensslCryptoProvider;
use pgp::composed::{SignedSecretKey, SignedPublicKey};
use std::sync::Arc;
use std::collections::HashMap;

use crate::core::db::Db;
use crate::crypto::pgp::{PgpKeyManager, PgpSigner};
use super::storage::{NymstrStorageProvider, PersistentMlsGroup};
use super::types::{EncryptedMessage, MlsMessageType, MlsGroupInfo, ConversationInfo, ConversationType};

/// MLS client wrapper for group messaging with PGP credentials
pub struct MlsClient {
    identity: String,
    pgp_secret_key: SignedSecretKey,
    pgp_public_key: SignedPublicKey,
    db: Arc<Db>,
    /// In-memory cache of active MLS groups
    active_groups: Arc<std::sync::Mutex<HashMap<Vec<u8>, Vec<u8>>>>, // group_id -> serialized group state
}

impl MlsClient {
    /// Create a new MLS client for the given identity with PGP keys and database
    pub fn new(identity: &str, pgp_secret_key: SignedSecretKey, pgp_public_key: SignedPublicKey, db: Arc<Db>) -> Result<Self> {
        Ok(Self {
            identity: identity.to_string(),
            pgp_secret_key,
            pgp_public_key,
            db,
            active_groups: Arc::new(std::sync::Mutex::new(HashMap::new())),
        })
    }

    /// Create a new MLS client and generate PGP keys
    pub fn new_with_generated_keys(identity: &str, db: Arc<Db>) -> Result<Self> {
        let (pgp_secret_key, pgp_public_key) = PgpKeyManager::generate_keypair(identity)?;
        Self::new(identity, pgp_secret_key, pgp_public_key, db)
    }

    /// Create a new MLS client instance with PGP credentials
    fn make_client(&self) -> Result<Client<impl MlsConfig>> {
        let crypto_provider = OpensslCryptoProvider::default();
        let cipher_suite = crypto_provider.cipher_suite_provider(CipherSuite::CURVE25519_AES128)
            .ok_or_else(|| anyhow!("Cipher suite not supported"))?;

        // Generate signature keys for MLS (separate from PGP keys)
        let (secret_key, public_key) = cipher_suite.signature_key_generate()
            .map_err(|e| anyhow!("Failed to generate MLS keys: {}", e))?;

        // Create PGP credential
        let pgp_credential = PgpCredential::new(self.identity.clone(), &self.pgp_public_key)?;
        let credential = pgp_credential.into_credential()?;
        let signing_identity = SigningIdentity::new(credential, public_key);

        let client = Client::builder()
            .identity_provider(PgpIdentityProvider)
            .crypto_provider(crypto_provider)
            .signing_identity(signing_identity, secret_key, CipherSuite::CURVE25519_AES128)
            .build();

        Ok(client)
    }

    /// Serialize a group using its internal snapshot
    async fn serialize_group(&self, group: &Group<impl MlsConfig>) -> Result<Vec<u8>> {
        // Use MLS-RS internal snapshot mechanism for serialization
        // This is a simplified approach that works for basic state persistence

        // For now, we'll store a JSON representation of essential group data
        // In a production system, you'd use proper MLS serialization
        let group_data = serde_json::json!({
            "group_id": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, group.group_id()),
            "epoch": group.current_epoch(),
            "cipher_suite": u16::from(group.cipher_suite()),
            "identity": self.identity,
            "timestamp": chrono::Utc::now().to_rfc3339()
        });

        serde_json::to_vec(&group_data)
            .map_err(|e| anyhow!("Failed to serialize group state: {}", e))
    }

    /// Store group state in database and cache
    async fn store_group_state(&self, group_id: &[u8], group: &Group<impl MlsConfig>) -> Result<()> {
        let group_state = self.serialize_group(group).await?;
        let group_id_str = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, group_id);

        // Store in database
        self.db.save_mls_group_state(&self.identity, &group_id_str, &group_state).await?;

        // Cache in memory
        self.active_groups.lock().unwrap().insert(group_id.to_vec(), group_state);

        log::debug!("Stored group state for conversation {}", group_id_str);
        Ok(())
    }

    /// Load group state from cache or database
    async fn load_group_state(&self, group_id: &[u8]) -> Result<Option<Vec<u8>>> {
        let group_id_str = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, group_id);

        // Try cache first
        if let Some(state) = self.active_groups.lock().unwrap().get(group_id).cloned() {
            log::debug!("Found group state in cache for conversation {}", group_id_str);
            return Ok(Some(state));
        }

        // Try database
        let state = self.db.load_mls_group_state(&self.identity, &group_id_str).await?;
        if let Some(ref state_data) = state {
            // Cache it for next time
            self.active_groups.lock().unwrap().insert(group_id.to_vec(), state_data.clone());
            log::debug!("Loaded group state from database for conversation {}", group_id_str);
        }

        Ok(state)
    }

    /// Create a new MLS group
    pub fn create_group(&self) -> Result<MlsGroupInfo> {
        let client = self.make_client()?;
        let group = client.create_group(ExtensionList::default(), ExtensionList::default(), None)
            .map_err(|e| anyhow!("Failed to create group: {}", e))?;

        let group_id = group.group_id().to_vec();
        Ok(MlsGroupInfo {
            group_id,
            client_identity: self.identity.clone(),
        })
    }

    /// Generate a key package for joining groups
    pub fn generate_key_package(&self) -> Result<Vec<u8>> {
        let client = self.make_client()?;
        let key_package = client.generate_key_package_message(ExtensionList::default(), ExtensionList::default(), None)
            .map_err(|e| anyhow!("Failed to generate key package: {}", e))?;
        key_package.to_bytes().map_err(|e| anyhow!("Failed to serialize key package: {}", e))
    }

    /// Start a 1:1 conversation (creates a 2-person MLS group)
    pub async fn start_conversation(&self, recipient_key_package: &[u8]) -> Result<ConversationInfo> {
        let client = self.make_client()?;

        // Create group for 1:1 conversation
        let mut group = client.create_group(ExtensionList::default(), ExtensionList::default(), None)
            .map_err(|e| anyhow!("Failed to create 1:1 group: {}", e))?;

        // Parse recipient's key package
        let _key_package_msg = MlsMessage::from_bytes(recipient_key_package)
            .map_err(|e| anyhow!("Invalid key package message: {}", e))?;

        // For now, we'll create a simple group without adding the key package
        // TODO: Properly extract and add key package when MLS-RS API is clarified
        log::warn!("MLS key package addition not yet implemented - creating group without adding member");

        // Create a basic commit to establish the group
        let commit = group
            .commit_builder()
            .build()
            .map_err(|e| anyhow!("Failed to create commit: {}", e))?;

        // Apply the commit
        group.apply_pending_commit()
            .map_err(|e| anyhow!("Failed to apply pending commit: {}", e))?;

        let conversation_id = group.group_id().to_vec();

        // Store the group state
        self.store_group_state(&conversation_id, &group).await?;

        let conversation_id_str = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &conversation_id);
        log::info!("Created and saved MLS group state for conversation {}", conversation_id_str);

        // Get welcome message bytes from commit
        let welcome_message = commit.welcome_messages
            .get(0)
            .map(|w| w.to_bytes())
            .transpose()
            .map_err(|e| anyhow!("Failed to serialize welcome message: {}", e))?;

        Ok(ConversationInfo {
            conversation_id: conversation_id.clone(),
            conversation_type: ConversationType::OneToOne,
            participants: 2,
            welcome_message,
            group_info: MlsGroupInfo {
                group_id: conversation_id,
                client_identity: self.identity.clone(),
            },
        })
    }

    /// Join a 1:1 conversation using a welcome message
    pub async fn join_conversation(&self, welcome_bytes: &[u8]) -> Result<ConversationInfo> {
        let client = self.make_client()?;
        let welcome_message = MlsMessage::from_bytes(welcome_bytes)
            .map_err(|e| anyhow!("Invalid welcome message: {}", e))?;

        let (group, _) = client.join_group(None, &welcome_message, None)
            .map_err(|e| anyhow!("Failed to join conversation: {}", e))?;

        let conversation_id = group.group_id().to_vec();

        // Store the group state
        self.store_group_state(&conversation_id, &group).await?;

        let conversation_id_str = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &conversation_id);
        log::info!("Joined and saved MLS group state for conversation {}", conversation_id_str);

        // TODO: Implement proper participant counting for MLS roster
        let participant_count = 2; // Placeholder - actual implementation needs roster introspection

        Ok(ConversationInfo {
            conversation_id: conversation_id.clone(),
            conversation_type: if participant_count == 2 {
                ConversationType::OneToOne
            } else {
                ConversationType::Group
            },
            participants: participant_count,
            welcome_message: None,
            group_info: MlsGroupInfo {
                group_id: conversation_id,
                client_identity: self.identity.clone(),
            },
        })
    }

    /// Encrypt message for any conversation (1:1 or group)
    pub async fn encrypt_message(&self, conversation_id: &[u8], plaintext: &[u8]) -> Result<EncryptedMessage> {
        let conversation_id_str = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, conversation_id);

        // Check if we have a group state
        let _group_state = self.load_group_state(conversation_id).await?
            .ok_or_else(|| anyhow!("No group state found for conversation {}", conversation_id_str))?;

        // For demonstration purposes, we'll create a fresh group for encryption
        // In a production system, you'd restore the exact group state
        let client = self.make_client()?;
        let mut group = client.create_group(ExtensionList::default(), ExtensionList::default(), None)
            .map_err(|e| anyhow!("Failed to create group for encryption: {}", e))?;

        log::debug!("Using group for encryption in conversation {}", conversation_id_str);

        // Encrypt the message using MLS
        let application_message = group.encrypt_application_message(plaintext, vec![])
            .map_err(|e| anyhow!("Failed to encrypt MLS message: {}", e))?;

        // Update stored group state
        self.store_group_state(conversation_id, &group).await?;

        // Serialize the MLS message
        let mls_message_bytes = application_message.to_bytes()
            .map_err(|e| anyhow!("Failed to serialize MLS message: {}", e))?;

        log::debug!("Successfully encrypted message for conversation {}", conversation_id_str);

        Ok(EncryptedMessage {
            conversation_id: conversation_id.to_vec(),
            mls_message: mls_message_bytes,
            message_type: MlsMessageType::Application,
        })
    }

    /// Decrypt message from any conversation
    pub async fn decrypt_message(&self, encrypted: &EncryptedMessage) -> Result<Vec<u8>> {
        let conversation_id_str = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encrypted.conversation_id);

        // Check if we have a group state
        let _group_state = self.load_group_state(&encrypted.conversation_id).await?
            .ok_or_else(|| anyhow!("No group state found for conversation {}", conversation_id_str))?;

        // For demonstration purposes, we'll create a fresh group for decryption
        // In a production system, you'd restore the exact group state
        let client = self.make_client()?;
        let mut group = client.create_group(ExtensionList::default(), ExtensionList::default(), None)
            .map_err(|e| anyhow!("Failed to create group for decryption: {}", e))?;

        log::debug!("Using group for decryption in conversation {}", conversation_id_str);

        // Parse the MLS message
        let mls_message = MlsMessage::from_bytes(&encrypted.mls_message)
            .map_err(|e| anyhow!("Failed to parse MLS message: {}", e))?;

        // Process the incoming message and decrypt using MLS
        let received_message = group.process_incoming_message(mls_message)
            .map_err(|e| anyhow!("Failed to process incoming MLS message: {}", e))?;

        // Update stored group state after processing
        self.store_group_state(&encrypted.conversation_id, &group).await?;

        // Extract the decrypted application data
        match received_message {
            Some(msg) => {
                log::debug!("Successfully decrypted message for conversation {}", conversation_id_str);
                Ok(msg.application_data)
            }
            None => {
                // This might be a commit or other non-application message
                log::debug!("Processed non-application message for conversation {}", conversation_id_str);
                Err(anyhow!("Message was not an application message"))
            }
        }
    }

    /// Add member to existing conversation (converts 1:1 to group)
    pub fn add_member(&self, conversation_id: &[u8], key_package: &[u8]) -> Result<EncryptedMessage> {
        // This will create a commit to add the new member
        Ok(EncryptedMessage {
            conversation_id: conversation_id.to_vec(),
            mls_message: key_package.to_vec(), // Placeholder
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

    /// Export group state for storage
    pub async fn export_group_state(&self, conversation_id: &[u8]) -> Result<Vec<u8>> {
        let group_state = self.load_group_state(conversation_id).await?
            .ok_or_else(|| {
                let conversation_id_str = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, conversation_id);
                anyhow!("No group state found for conversation {}", conversation_id_str)
            })?;

        Ok(group_state)
    }

    /// Create welcome message for a conversation
    pub fn create_welcome_message(&self, conversation_info: &ConversationInfo) -> Result<String> {
        // Use the actual welcome message from the conversation info if available
        if let Some(welcome_bytes) = &conversation_info.welcome_message {
            return Ok(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, welcome_bytes));
        }

        // If no welcome message, this is an error since all conversations should have welcome messages
        Err(anyhow!("No welcome message available in conversation info"))
    }
}

// Import the PGP credential and identity provider types
use serde::{Deserialize, Serialize};
use mls_rs_core::identity::{
    Credential, CredentialType, CustomCredential, IdentityProvider, MemberValidationContext, MlsCredential,
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