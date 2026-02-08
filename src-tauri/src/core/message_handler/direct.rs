//! Direct messaging methods with MLS encryption
//!
//! This module handles direct (1:1) encrypted messaging using MLS protocol.
//! It manages:
//! - Establishing MLS conversations between two users
//! - Key package exchange for MLS handshakes
//! - Encrypting/decrypting messages with MLS
//! - Storing and retrieving conversation history

use std::sync::Arc;

use anyhow::{anyhow, Result};
use base64::Engine;
use serde_json::json;
use sqlx::SqlitePool;

use crate::crypto::mls::{EncryptedMessage, MlsClient, MlsMessageType};
use crate::crypto::pgp::{ArcPassphrase, ArcSecretKey, PgpSigner};
use crate::core::mixnet_client::MixnetService;

/// Normalize conversation ID to ensure consistent ordering (alphabetical)
/// This ensures Alice->Bob and Bob->Alice use the same conversation
pub fn normalize_conversation_id(user1: &str, user2: &str) -> String {
    let mut participants = vec![user1, user2];
    participants.sort();
    format!("dm:{}:{}", participants[0], participants[1])
}

/// Wrap plaintext message in standard JSON format
/// Type 0 = text message
pub fn wrap_message(content: &str) -> String {
    json!({"type": 0, "message": content}).to_string()
}

/// Unwrap a received message JSON to extract content
pub fn unwrap_message(wrapped: &str) -> Result<String> {
    let value: serde_json::Value = serde_json::from_str(wrapped)
        .map_err(|e| anyhow!("Failed to parse message JSON: {}", e))?;

    // Try to extract the message field
    if let Some(message) = value.get("message").and_then(|m| m.as_str()) {
        return Ok(message.to_string());
    }

    // Fallback: return the raw content if not wrapped
    Err(anyhow!("Message does not have expected format"))
}

/// Direct messaging handler for MLS-encrypted 1:1 chats
pub struct DirectMessageHandler {
    mls_client: Arc<MlsClient>,
    mixnet_service: Arc<MixnetService>,
    pgp_secret_key: ArcSecretKey,
    pgp_passphrase: ArcPassphrase,
    current_user: String,
    db: SqlitePool,
}

impl DirectMessageHandler {
    /// Create a new direct message handler
    pub fn new(
        mls_client: Arc<MlsClient>,
        mixnet_service: Arc<MixnetService>,
        pgp_secret_key: ArcSecretKey,
        pgp_passphrase: ArcPassphrase,
        current_user: String,
        db: SqlitePool,
    ) -> Self {
        Self {
            mls_client,
            mixnet_service,
            pgp_secret_key,
            pgp_passphrase,
            current_user,
            db,
        }
    }

    /// Store the DM conversation → MLS group ID mapping
    async fn store_conversation_mapping(&self, recipient: &str, mls_group_id: &[u8]) -> Result<()> {
        let conversation_id = normalize_conversation_id(&self.current_user, recipient);
        let mls_group_id_b64 = base64::engine::general_purpose::STANDARD.encode(mls_group_id);
        sqlx::query(
            "INSERT OR REPLACE INTO conversations (id, mls_group_id)
             VALUES (?, ?)"
        )
        .bind(&conversation_id)
        .bind(&mls_group_id_b64)
        .execute(&self.db).await
        .map_err(|e| anyhow!("Failed to store conversation mapping: {}", e))?;
        log::info!(
            "Stored conversation mapping: {} → MLS group {}",
            conversation_id,
            mls_group_id_b64
        );
        Ok(())
    }

    /// Look up the real MLS group ID for a conversation
    async fn get_mls_group_id(&self, recipient: &str) -> Result<Vec<u8>> {
        let conversation_id = normalize_conversation_id(&self.current_user, recipient);
        let result: Option<(String,)> = sqlx::query_as(
            "SELECT mls_group_id FROM conversations WHERE id = ?"
        )
        .bind(&conversation_id)
        .fetch_optional(&self.db).await
        .map_err(|e| anyhow!("Failed to query conversation: {}", e))?;

        let mls_group_id_b64 = result
            .ok_or_else(|| anyhow!("No conversation found with {}", recipient))?.0;
        base64::engine::general_purpose::STANDARD.decode(&mls_group_id_b64)
            .map_err(|e| anyhow!("Invalid MLS group ID: {}", e))
    }

    /// Check if an MLS conversation exists with a recipient
    pub async fn conversation_exists(&self, recipient: &str) -> bool {
        match self.get_mls_group_id(recipient).await {
            Ok(mls_group_id) => self.mls_client.group_exists(&mls_group_id),
            Err(_) => false,
        }
    }

    /// Get the normalized conversation ID for a recipient
    pub fn get_conversation_id(&self, recipient: &str) -> String {
        normalize_conversation_id(&self.current_user, recipient)
    }

    /// Generate a key package for establishing new conversations
    pub fn generate_key_package(&self) -> Result<String> {
        let key_package_bytes = self.mls_client.generate_key_package()?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&key_package_bytes))
    }

    /// Initiate MLS conversation with recipient
    /// Returns the welcome message to send to recipient
    pub async fn establish_conversation(&self, recipient_key_package_b64: &str) -> Result<(String, Vec<u8>)> {
        log::info!(
            "Establishing MLS conversation between {} and recipient",
            self.current_user
        );

        // Decode recipient's key package
        let recipient_key_package = base64::engine::general_purpose::STANDARD
            .decode(recipient_key_package_b64)
            .map_err(|e| anyhow!("Invalid key package base64: {}", e))?;

        // Start the conversation (creates MLS group and adds recipient)
        let conversation_info = self.mls_client.start_conversation(&recipient_key_package).await?;

        // Get the welcome message
        let welcome_b64 = self.mls_client.create_welcome_message(&conversation_info)?;

        log::info!(
            "MLS conversation established, group ID: {}",
            base64::engine::general_purpose::STANDARD.encode(&conversation_info.conversation_id)
        );

        Ok((welcome_b64, conversation_info.conversation_id))
    }

    /// Join a conversation using a welcome message
    pub async fn join_conversation(&self, welcome_b64: &str) -> Result<Vec<u8>> {
        log::info!("Joining MLS conversation for user {}", self.current_user);

        let welcome_bytes = base64::engine::general_purpose::STANDARD
            .decode(welcome_b64)
            .map_err(|e| anyhow!("Invalid welcome base64: {}", e))?;

        let conversation_info = self.mls_client.join_conversation(&welcome_bytes).await?;

        log::info!(
            "Successfully joined MLS conversation, group ID: {}",
            base64::engine::general_purpose::STANDARD.encode(&conversation_info.conversation_id)
        );

        Ok(conversation_info.conversation_id)
    }

    /// Sign a message with PGP key
    fn sign_message(&self, content: &str) -> Result<String> {
        PgpSigner::sign_detached_secure(&self.pgp_secret_key, content.as_bytes(), &self.pgp_passphrase)
    }

    /// Send an encrypted direct message
    pub async fn send_message(&self, recipient: &str, content: &str) -> Result<()> {
        // Look up the real MLS group ID from DB
        let mls_group_id = self.get_mls_group_id(recipient).await.map_err(|_| {
            anyhow!(
                "No MLS conversation exists with {}. Call establish_conversation first.",
                recipient
            )
        })?;

        // Verify the MLS group actually exists
        if !self.mls_client.group_exists(&mls_group_id) {
            return Err(anyhow!(
                "MLS group not found for conversation with {}",
                recipient
            ));
        }

        log::info!(
            "Sending encrypted message from {} to {}",
            self.current_user,
            recipient
        );

        // Wrap plaintext in type/message JSON
        let wrapped = wrap_message(content);

        // Encrypt message using MLS
        let encrypted = self
            .mls_client
            .encrypt_message(&mls_group_id, wrapped.as_bytes())
            .await?;

        // Build the same payload that will be sent, and sign the serialized form
        let conversation_id_b64 =
            base64::engine::general_purpose::STANDARD.encode(&encrypted.conversation_id);
        let ciphertext_b64 =
            base64::engine::general_purpose::STANDARD.encode(&encrypted.mls_message);
        let payload = serde_json::json!({
            "conversation_id": conversation_id_b64,
            "mls_message": ciphertext_b64
        });
        let payload_str = serde_json::to_string(&payload)
            .map_err(|e| anyhow!("Failed to serialize payload: {}", e))?;
        let signature = self.sign_message(&payload_str)?;

        // Send via mixnet
        self.mixnet_service
            .send_mls_message(
                &self.current_user,
                recipient,
                &encrypted.conversation_id,
                &encrypted.mls_message,
                &signature,
            )
            .await?;

        log::info!(
            "Successfully sent encrypted message to {} in conversation {}",
            recipient,
            conversation_id_b64
        );

        Ok(())
    }

    /// Decrypt an incoming MLS message
    pub async fn decrypt_message(&self, encrypted: &EncryptedMessage) -> Result<String> {
        let conversation_id_str =
            base64::engine::general_purpose::STANDARD.encode(&encrypted.conversation_id);

        log::info!(
            "Decrypting message in conversation {} for user {}",
            conversation_id_str,
            self.current_user
        );

        // Decrypt using MLS
        let plaintext_bytes = self.mls_client.decrypt_message(encrypted).await?;

        // Parse the plaintext
        let plaintext = String::from_utf8(plaintext_bytes)
            .map_err(|e| anyhow!("Decrypted message is not valid UTF-8: {}", e))?;

        // Try to unwrap the message format
        match unwrap_message(&plaintext) {
            Ok(content) => Ok(content),
            Err(_) => {
                // Return raw plaintext if not in expected format
                Ok(plaintext)
            }
        }
    }

    /// Process an incoming MLS message (could be Welcome, Commit, or Application)
    pub async fn process_incoming_message(
        &self,
        sender: &str,
        mls_message_b64: &str,
        message_type: MlsMessageType,
    ) -> Result<Option<String>> {
        let mls_message_bytes = base64::engine::general_purpose::STANDARD
            .decode(mls_message_b64)
            .map_err(|e| anyhow!("Invalid MLS message base64: {}", e))?;

        match message_type {
            MlsMessageType::Welcome => {
                // Join the conversation using the welcome message
                log::info!("Processing Welcome message from {}", sender);
                let mls_group_id = self.join_conversation(mls_message_b64).await?;
                let mls_group_id_str =
                    base64::engine::general_purpose::STANDARD.encode(&mls_group_id);

                // Store the conversation mapping so we can decrypt future messages
                self.store_conversation_mapping(sender, &mls_group_id).await?;

                log::info!(
                    "Joined conversation {} from Welcome message and stored mapping",
                    mls_group_id_str
                );
                Ok(None)
            }
            MlsMessageType::Commit => {
                // Process commit to advance epoch
                log::info!("Processing Commit message from {}", sender);
                let mls_group_id = self.get_mls_group_id(sender).await?;
                let mls_group_id_b64 = base64::engine::general_purpose::STANDARD.encode(&mls_group_id);
                let new_epoch = self
                    .mls_client
                    .process_commit(&mls_group_id_b64, &mls_message_bytes)?;
                log::info!(
                    "Processed commit, new epoch: {} for MLS group {}",
                    new_epoch,
                    mls_group_id_b64
                );
                Ok(None)
            }
            MlsMessageType::Application => {
                // Decrypt application message
                log::info!("Processing Application message from {}", sender);
                let mls_group_id = self.get_mls_group_id(sender).await?;
                let encrypted = EncryptedMessage {
                    conversation_id: mls_group_id,
                    mls_message: mls_message_bytes,
                    message_type: MlsMessageType::Application,
                };
                let content = self.decrypt_message(&encrypted).await?;
                log::info!(
                    "Decrypted application message from {} in conversation {}",
                    sender,
                    normalize_conversation_id(&self.current_user, sender)
                );
                Ok(Some(content))
            }
            MlsMessageType::KeyPackage => {
                // Key package received - this is part of handshake
                log::info!("Received KeyPackage from {}", sender);
                // KeyPackages are typically handled at a higher level
                Ok(None)
            }
        }
    }

    /// Send a key package request to initiate conversation with a recipient
    ///
    /// The initiator no longer includes their own KP in the request — only the
    /// responder's KP is needed (consumed by the Add proposal when the group is created).
    pub async fn request_key_package(&self, recipient: &str) -> Result<()> {
        log::info!(
            "Requesting key package from {} for user {}",
            recipient,
            self.current_user
        );

        // Sign the request using our identity
        let sign_content = format!("keyPackageRequest:{}:{}", self.current_user, recipient);
        let signature = self.sign_message(&sign_content)?;

        // Send key package request via mixnet
        self.mixnet_service
            .send_key_package_request(&self.current_user, recipient, &signature)
            .await?;

        log::info!("Key package request sent to {}", recipient);
        Ok(())
    }

    /// Respond to a key package request
    pub async fn respond_to_key_package_request(
        &self,
        requester: &str,
        their_key_package: &str,
    ) -> Result<()> {
        log::info!(
            "Responding to key package request from {} for user {}",
            requester,
            self.current_user
        );

        // Generate our key package
        let our_key_package = self.generate_key_package()?;

        // Sign the response
        let signature = self.sign_message(&format!("{}:{}", our_key_package, their_key_package))?;

        // Send key package response via mixnet
        self.mixnet_service
            .send_key_package_response(
                &self.current_user,
                requester,
                &our_key_package,
                their_key_package,
                &signature,
            )
            .await?;

        log::info!("Key package response sent to {}", requester);
        Ok(())
    }

    /// Complete the MLS handshake after receiving key package response
    ///
    /// Creates the MLS group, generates Welcome + Commit, and sends them to the
    /// recipient. Does NOT finalize the conversation yet — stores a pending handshake
    /// record and waits for p2pWelcomeAck before applying the commit.
    pub async fn complete_handshake(
        &self,
        recipient: &str,
        recipient_key_package: &str,
    ) -> Result<()> {
        log::info!(
            "Completing MLS handshake with {} for user {} (deferred commit)",
            recipient,
            self.current_user
        );

        // Establish the conversation using their key package
        // start_conversation() no longer applies the pending commit
        let (welcome_b64, mls_group_id, commit_b64, ratchet_tree_b64) =
            self.establish_conversation_deferred(recipient_key_package).await?;

        // Use the normalized conversation ID as the groupId in the welcome payload
        let conversation_id = normalize_conversation_id(&self.current_user, recipient);

        // Store pending handshake — do NOT store conversation mapping yet
        self.store_pending_handshake(recipient, &mls_group_id, &conversation_id).await?;

        // Sign the welcome message
        let signature = self.sign_message(&welcome_b64)?;

        // Send welcome + commit + ratchet tree via discovery server relay
        self.mixnet_service
            .send_p2p_welcome(
                &self.current_user,
                recipient,
                &welcome_b64,
                &conversation_id,
                commit_b64.as_deref(),
                ratchet_tree_b64.as_deref(),
                &signature,
            )
            .await?;

        log::info!(
            "MLS handshake Welcome sent to {} (pending ack before finalization)",
            recipient
        );
        Ok(())
    }

    /// Establish conversation with deferred commit — returns welcome, group ID, commit, and ratchet tree
    async fn establish_conversation_deferred(
        &self,
        recipient_key_package_b64: &str,
    ) -> Result<(String, Vec<u8>, Option<String>, Option<String>)> {
        log::info!(
            "Establishing MLS conversation (deferred) between {} and recipient",
            self.current_user
        );

        let recipient_key_package = base64::engine::general_purpose::STANDARD
            .decode(recipient_key_package_b64)
            .map_err(|e| anyhow!("Invalid key package base64: {}", e))?;

        let conversation_info = self.mls_client.start_conversation(&recipient_key_package).await?;

        let welcome_b64 = self.mls_client.create_welcome_message(&conversation_info)?;

        let commit_b64 = conversation_info.commit_message.as_ref().map(|bytes| {
            base64::engine::general_purpose::STANDARD.encode(bytes)
        });

        let ratchet_tree_b64 = conversation_info.ratchet_tree.as_ref().map(|bytes| {
            base64::engine::general_purpose::STANDARD.encode(bytes)
        });

        log::info!(
            "MLS conversation created (deferred), group ID: {}",
            base64::engine::general_purpose::STANDARD.encode(&conversation_info.conversation_id)
        );

        Ok((welcome_b64, conversation_info.conversation_id, commit_b64, ratchet_tree_b64))
    }

    // ========== Pending Handshake DB Helpers ==========

    /// Store a pending handshake record awaiting p2pWelcomeAck
    async fn store_pending_handshake(
        &self,
        recipient: &str,
        mls_group_id: &[u8],
        conversation_id: &str,
    ) -> Result<()> {
        let mls_group_id_b64 = base64::engine::general_purpose::STANDARD.encode(mls_group_id);
        sqlx::query(
            "INSERT OR REPLACE INTO pending_handshakes (recipient, mls_group_id, conversation_id, created_at)
             VALUES (?, ?, ?, datetime('now'))"
        )
        .bind(recipient)
        .bind(&mls_group_id_b64)
        .bind(conversation_id)
        .execute(&self.db).await
        .map_err(|e| anyhow!("Failed to store pending handshake: {}", e))?;
        log::info!("Stored pending handshake for {} (group: {})", recipient, mls_group_id_b64);
        Ok(())
    }

    /// Retrieve a pending handshake record for a recipient
    async fn get_pending_handshake(&self, recipient: &str) -> Result<(String, String)> {
        let result: Option<(String, String)> = sqlx::query_as(
            "SELECT mls_group_id, conversation_id FROM pending_handshakes WHERE recipient = ?"
        )
        .bind(recipient)
        .fetch_optional(&self.db).await
        .map_err(|e| anyhow!("Failed to query pending handshake: {}", e))?;

        result.ok_or_else(|| anyhow!("No pending handshake found for {}", recipient))
    }

    /// Delete a pending handshake record after finalization
    async fn delete_pending_handshake(&self, recipient: &str) -> Result<()> {
        sqlx::query("DELETE FROM pending_handshakes WHERE recipient = ?")
            .bind(recipient)
            .execute(&self.db).await
            .map_err(|e| anyhow!("Failed to delete pending handshake: {}", e))?;
        Ok(())
    }

    /// Finalize handshake after receiving p2pWelcomeAck.
    /// Applies the pending commit and stores the conversation mapping.
    pub async fn finalize_handshake(&self, recipient: &str) -> Result<()> {
        log::info!("Finalizing handshake with {} for user {}", recipient, self.current_user);

        let (mls_group_id_b64, conversation_id) = self.get_pending_handshake(recipient).await?;
        let mls_group_id = base64::engine::general_purpose::STANDARD
            .decode(&mls_group_id_b64)
            .map_err(|e| anyhow!("Invalid MLS group ID: {}", e))?;

        // Apply the deferred pending commit
        let new_epoch = self.mls_client.apply_pending_commit_for_group(&mls_group_id)?;

        // Now store the conversation mapping
        self.store_conversation_mapping(recipient, &mls_group_id).await?;

        // Clean up pending handshake
        self.delete_pending_handshake(recipient).await?;

        log::info!(
            "Handshake finalized with {}, conversation: {}, epoch: {}",
            recipient, conversation_id, new_epoch
        );
        Ok(())
    }

    /// Clean up a failed handshake (when Bob rejects or never responds)
    pub async fn cleanup_failed_handshake(&self, recipient: &str) -> Result<()> {
        log::info!("Cleaning up failed handshake with {}", recipient);
        self.delete_pending_handshake(recipient).await?;
        Ok(())
    }

    /// Send a p2pWelcomeAck back to the conversation initiator
    pub async fn send_welcome_ack(
        &self,
        recipient: &str,
        conversation_id: &str,
        accepted: bool,
    ) -> Result<()> {
        let sign_content = format!("p2pWelcomeAck:{}:{}:{}", self.current_user, conversation_id, accepted);
        let signature = self.sign_message(&sign_content)?;

        self.mixnet_service
            .send_p2p_welcome_ack(
                &self.current_user,
                recipient,
                conversation_id,
                accepted,
                &signature,
            )
            .await?;

        log::info!("Sent p2pWelcomeAck to {} (accepted={})", recipient, accepted);
        Ok(())
    }
}

/// Builder for creating DirectMessageHandler
pub struct DirectMessageHandlerBuilder {
    mls_client: Option<Arc<MlsClient>>,
    mixnet_service: Option<Arc<MixnetService>>,
    pgp_secret_key: Option<ArcSecretKey>,
    pgp_passphrase: Option<ArcPassphrase>,
    current_user: Option<String>,
    db: Option<SqlitePool>,
}

impl DirectMessageHandlerBuilder {
    pub fn new() -> Self {
        Self {
            mls_client: None,
            mixnet_service: None,
            pgp_secret_key: None,
            pgp_passphrase: None,
            current_user: None,
            db: None,
        }
    }

    pub fn mls_client(mut self, client: Arc<MlsClient>) -> Self {
        self.mls_client = Some(client);
        self
    }

    pub fn mixnet_service(mut self, service: Arc<MixnetService>) -> Self {
        self.mixnet_service = Some(service);
        self
    }

    pub fn pgp_keys(mut self, secret_key: ArcSecretKey, passphrase: ArcPassphrase) -> Self {
        self.pgp_secret_key = Some(secret_key);
        self.pgp_passphrase = Some(passphrase);
        self
    }

    pub fn current_user(mut self, user: String) -> Self {
        self.current_user = Some(user);
        self
    }

    pub fn db(mut self, db: SqlitePool) -> Self {
        self.db = Some(db);
        self
    }

    pub fn build(self) -> Result<DirectMessageHandler> {
        Ok(DirectMessageHandler::new(
            self.mls_client
                .ok_or_else(|| anyhow!("MLS client not provided"))?,
            self.mixnet_service
                .ok_or_else(|| anyhow!("Mixnet service not provided"))?,
            self.pgp_secret_key
                .ok_or_else(|| anyhow!("PGP secret key not provided"))?,
            self.pgp_passphrase
                .ok_or_else(|| anyhow!("PGP passphrase not provided"))?,
            self.current_user
                .ok_or_else(|| anyhow!("Current user not provided"))?,
            self.db
                .ok_or_else(|| anyhow!("Database pool not provided"))?,
        ))
    }
}

impl Default for DirectMessageHandlerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
