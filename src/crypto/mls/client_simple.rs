//! Simplified MLS client with working group state persistence
//!
//! This implementation uses a simpler approach that works with MLS-RS 0.49.0
//! by using basic group serialization and the existing database structure.

use anyhow::{Result, anyhow};
use mls_rs::{
    client_builder::ClientBuilder,
    CipherSuite, Client, ExtensionList, MlsMessage, Group,
};
use mls_rs_crypto_openssl::OpensslCryptoProvider;
use mls_rs_provider_sqlite::SqliteStorageProvider;
use pgp::composed::{SignedSecretKey, SignedPublicKey};
use std::sync::Arc;
use base64::Engine;

use crate::core::db::Db;
use crate::crypto::pgp::{PgpKeyManager, PgpSigner};
use super::persistence::MlsGroupPersistence;
use super::types::{EncryptedMessage, MlsMessageType, MlsGroupInfo, ConversationInfo, ConversationType};

/// MLS client with simplified group state persistence
pub struct MlsClient {
    identity: String,
    pgp_secret_key: SignedSecretKey,
    pgp_public_key: SignedPublicKey,
    db: Arc<Db>,
    client: Client<mls_rs_provider_sqlite::SqLiteConfig>,
    persistence: MlsGroupPersistence,
    /// In-memory cache of loaded groups
    group_cache: Arc<tokio::sync::Mutex<std::collections::HashMap<Vec<u8>, Group<mls_rs_provider_sqlite::SqLiteConfig>>>>,
}

impl MlsClient {
    /// Create a new MLS client with persistence
    pub async fn new(identity: &str, pgp_secret_key: SignedSecretKey, pgp_public_key: SignedPublicKey, db: Arc<Db>) -> Result<Self> {
        let persistence = MlsGroupPersistence::new(identity.to_string(), db.clone());

        // Create a temporary SQLite storage for MLS-RS
        let temp_db_path = format!("/tmp/mls_storage_{}.db", identity);
        let storage_provider = SqliteStorageProvider::new(&temp_db_path).await
            .map_err(|e| anyhow!("Failed to create MLS storage provider: {}", e))?;

        // Build the client using the SQLite provider
        let client = ClientBuilder::new()
            .storage_provider(storage_provider)
            .crypto_provider(OpensslCryptoProvider::default())
            .build();

        Ok(Self {
            identity: identity.to_string(),
            pgp_secret_key,
            pgp_public_key,
            db,
            client,
            persistence,
            group_cache: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        })
    }

    /// Create a new MLS client and generate PGP keys
    pub async fn new_with_generated_keys(identity: &str, db: Arc<Db>) -> Result<Self> {
        let (pgp_secret_key, pgp_public_key) = PgpKeyManager::generate_keypair(identity)?;
        Self::new(identity, pgp_secret_key, pgp_public_key, db).await
    }

    /// Serialize a group to bytes for storage
    async fn serialize_group(&self, group: &Group<mls_rs_provider_sqlite::SqLiteConfig>) -> Result<Vec<u8>> {
        // Use the group's tree export functionality
        let tree_data = group.export_tree()
            .map_err(|e| anyhow!("Failed to export group tree: {}", e))?;

        // Create a simple JSON representation with essential group data
        let group_data = serde_json::json!({
            "group_id": base64::engine::general_purpose::STANDARD.encode(group.group_id()),
            "epoch": group.current_epoch(),
            "tree_data": base64::engine::general_purpose::STANDARD.encode(&tree_data),
            "identity": self.identity,
            "timestamp": chrono::Utc::now().to_rfc3339()
        });

        serde_json::to_vec(&group_data)
            .map_err(|e| anyhow!("Failed to serialize group state: {}", e))
    }

    /// Save group state to persistent storage
    async fn save_group(&self, group: &Group<mls_rs_provider_sqlite::SqLiteConfig>) -> Result<()> {
        let group_id = group.group_id();

        // First save to MLS-RS internal storage
        group.write_to_storage().await
            .map_err(|e| anyhow!("Failed to write group to MLS storage: {}", e))?;

        // Then serialize and save to our persistent storage
        let serialized_state = self.serialize_group(group).await?;
        self.persistence.save_group_state(group_id, &serialized_state).await?;

        // Cache the group
        self.group_cache.lock().await.insert(group_id.to_vec(), group.clone());

        log::info!("Successfully saved MLS group to storage for conversation {}",
                  base64::engine::general_purpose::STANDARD.encode(group_id));
        Ok(())
    }

    /// Load an existing group, first from cache, then from storage
    async fn load_group(&self, group_id: &[u8]) -> Result<Option<Group<mls_rs_provider_sqlite::SqLiteConfig>>> {
        // Check cache first
        if let Some(group) = self.group_cache.lock().await.get(group_id).cloned() {
            log::debug!("Found MLS group in cache for conversation {}",
                       base64::engine::general_purpose::STANDARD.encode(group_id));
            return Ok(Some(group));
        }

        // Try to load from MLS-RS storage first
        match self.client.load_group(group_id).await {
            Ok(group) => {
                log::info!("Successfully loaded MLS group from MLS storage for conversation {}",
                          base64::engine::general_purpose::STANDARD.encode(group_id));
                // Cache it
                self.group_cache.lock().await.insert(group_id.to_vec(), group.clone());
                return Ok(Some(group));
            }
            Err(e) => {
                log::debug!("Failed to load MLS group from MLS storage: {}", e);
            }
        }

        // Check if we have persistent state (for recovery/migration)
        if let Some(_state) = self.persistence.load_group_state(group_id).await? {
            log::debug!("Found persistent group state but cannot restore directly");
            // Note: Direct restoration from serialized state is complex in MLS-RS
            // For now, we return None and let the caller handle group recreation
        }

        Ok(None)
    }

    /// Create a new MLS group
    pub async fn create_group(&self) -> Result<MlsGroupInfo> {
        let mut group = self.client.create_group(ExtensionList::default(), ExtensionList::default())
            .map_err(|e| anyhow!("Failed to create group: {}", e))?;

        let group_id = group.group_id().to_vec();

        // Save the newly created group
        self.save_group(&group).await?;

        Ok(MlsGroupInfo {
            group_id,
            client_identity: self.identity.clone(),
        })
    }

    /// Generate a key package for joining groups
    pub fn generate_key_package(&self) -> Result<Vec<u8>> {
        let key_package = self.client.generate_key_package_message(ExtensionList::default(), ExtensionList::default())
            .map_err(|e| anyhow!("Failed to generate key package: {}", e))?;
        key_package.to_bytes().map_err(|e| anyhow!("Failed to serialize key package: {}", e))
    }

    /// Start a 1:1 conversation (creates a 2-person MLS group)
    pub async fn start_conversation(&self, recipient_key_package: &[u8]) -> Result<ConversationInfo> {
        // Create group for 1:1 conversation
        let mut group = self.client.create_group(ExtensionList::default(), ExtensionList::default())
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

        // Save the group to persistent storage
        self.save_group(&group).await?;

        let conversation_id_str = base64::engine::general_purpose::STANDARD.encode(&conversation_id);
        log::info!("Created and saved MLS group for conversation {}", conversation_id_str);

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
        let welcome_message = MlsMessage::from_bytes(welcome_bytes)
            .map_err(|e| anyhow!("Invalid welcome message: {}", e))?;

        let (mut group, _) = self.client.join_group(None, &welcome_message)
            .map_err(|e| anyhow!("Failed to join conversation: {}", e))?;

        let conversation_id = group.group_id().to_vec();

        // Save the group to persistent storage
        self.save_group(&group).await?;

        let conversation_id_str = base64::engine::general_purpose::STANDARD.encode(&conversation_id);
        log::info!("Joined and saved MLS group for conversation {}", conversation_id_str);

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

    /// Encrypt message for any conversation using persistent group state
    pub async fn encrypt_message(&self, conversation_id: &[u8], plaintext: &[u8]) -> Result<EncryptedMessage> {
        let conversation_id_str = base64::engine::general_purpose::STANDARD.encode(conversation_id);

        // Load the existing group from storage
        let mut group = self.load_group(conversation_id).await?
            .ok_or_else(|| anyhow!("No MLS group found for conversation {}", conversation_id_str))?;

        log::debug!("Using persistent MLS group for encryption in conversation {}", conversation_id_str);

        // Encrypt the message using MLS with the persistent group state
        let application_message = group.encrypt_application_message(plaintext, ExtensionList::default())
            .map_err(|e| anyhow!("Failed to encrypt MLS message: {}", e))?;

        // Save the updated group state after encryption
        self.save_group(&group).await?;

        // Serialize the MLS message
        let mls_message_bytes = application_message.to_bytes()
            .map_err(|e| anyhow!("Failed to serialize MLS message: {}", e))?;

        log::info!("Successfully encrypted message using persistent MLS group for conversation {}", conversation_id_str);

        Ok(EncryptedMessage {
            conversation_id: conversation_id.to_vec(),
            mls_message: mls_message_bytes,
            message_type: MlsMessageType::Application,
        })
    }

    /// Decrypt message from any conversation using persistent group state
    pub async fn decrypt_message(&self, encrypted: &EncryptedMessage) -> Result<Vec<u8>> {
        let conversation_id_str = base64::engine::general_purpose::STANDARD.encode(&encrypted.conversation_id);

        // Load the existing group from storage
        let mut group = self.load_group(&encrypted.conversation_id).await?
            .ok_or_else(|| anyhow!("No MLS group found for conversation {}", conversation_id_str))?;

        log::debug!("Using persistent MLS group for decryption in conversation {}", conversation_id_str);

        // Parse the MLS message
        let mls_message = MlsMessage::from_bytes(&encrypted.mls_message)
            .map_err(|e| anyhow!("Failed to parse MLS message: {}", e))?;

        // Process the incoming message and decrypt using MLS with persistent group state
        let received_message = group.process_incoming_message(mls_message)
            .map_err(|e| anyhow!("Failed to process incoming MLS message: {}", e))?;

        // Save the updated group state after decryption
        self.save_group(&group).await?;

        // Extract the decrypted application data
        match received_message {
            Some(msg) => {
                log::info!("Successfully decrypted message using persistent MLS group for conversation {}", conversation_id_str);
                Ok(msg.application_data)
            }
            None => {
                // This might be a commit or other non-application message
                log::debug!("Processed non-application message for conversation {}", conversation_id_str);
                Err(anyhow!("Message was not an application message"))
            }
        }
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

        // Load the group state from persistence
        match self.persistence.load_group_state(conversation_id).await? {
            Some(state) => {
                log::info!("Exported group state for conversation {} (size: {} bytes)",
                          group_id_str, state.len());
                Ok(state)
            }
            None => Err(anyhow!("No group state found for conversation {}", group_id_str))
        }
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

    /// Clear group cache (for testing)
    pub async fn clear_cache(&self) {
        self.group_cache.lock().await.clear();
        self.persistence.clear_cache().await;
    }
}