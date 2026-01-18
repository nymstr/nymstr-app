//! MLS conversation management
//!
//! Handles MLS protocol operations for conversation establishment and group management.
//! Includes epoch-aware message buffering for handling out-of-order mixnet delivery.

#![allow(dead_code)] // Many methods are part of the public API for conversation management

use crate::core::{db::Db, mixnet_client::MixnetService};
use crate::crypto::{Crypto, SecurePassphrase};
use super::MlsClient;
use super::epoch_buffer::EpochAwareBuffer;
use super::types::{MlsWelcome, MlsCredential, MlsGroupInfoPublic};
use anyhow::{Result, anyhow};
use base64::Engine;
use log::{info, warn, debug};
use pgp::composed::{SignedSecretKey, SignedPublicKey};
use std::sync::Arc;

/// Type alias for Arc-wrapped PGP secret key to reduce expensive cloning
pub type ArcSecretKey = Arc<SignedSecretKey>;
/// Type alias for Arc-wrapped PGP public key to reduce expensive cloning
pub type ArcPublicKey = Arc<SignedPublicKey>;
/// Type alias for Arc-wrapped secure passphrase to reduce expensive cloning
pub type ArcPassphrase = Arc<SecurePassphrase>;

/// Manages MLS conversations and protocol operations
pub struct MlsConversationManager {
    /// Database for persistence
    pub db: Arc<Db>,
    /// Mixnet service for communication
    pub service: Arc<MixnetService>,
    /// Current user (for conversation IDs)
    pub current_user: Option<String>,
    /// PGP keys for signing (Arc-wrapped to avoid expensive cloning)
    pub pgp_secret_key: Option<ArcSecretKey>,
    pub pgp_public_key: Option<ArcPublicKey>,
    pub pgp_passphrase: Option<ArcPassphrase>,
    /// MLS storage path
    pub mls_storage_path: Option<String>,
    /// Epoch-aware message buffer for out-of-order delivery handling
    pub epoch_buffer: EpochAwareBuffer,
}

impl MlsConversationManager {
    pub fn new(
        db: Arc<Db>,
        service: Arc<MixnetService>,
        current_user: Option<String>,
        pgp_secret_key: Option<ArcSecretKey>,
        pgp_public_key: Option<ArcPublicKey>,
        pgp_passphrase: Option<ArcPassphrase>,
        mls_storage_path: Option<String>,
    ) -> Self {
        let epoch_buffer = EpochAwareBuffer::new(db.clone());
        Self {
            db,
            service,
            current_user,
            pgp_secret_key,
            pgp_public_key,
            pgp_passphrase,
            mls_storage_path,
            epoch_buffer,
        }
    }

    /// Initialize the epoch buffer with the current username
    /// Call this after setting current_user
    pub async fn init_epoch_buffer(&self) -> Result<()> {
        if let Some(ref username) = self.current_user {
            self.epoch_buffer.set_username(username).await;
            // Reload any pending messages from database
            let loaded = self.epoch_buffer.reload_from_db().await?;
            if loaded > 0 {
                info!("Loaded {} pending messages from database on init", loaded);
            }
        }
        Ok(())
    }

    /// Handle incoming key package request for MLS handshake
    pub async fn handle_key_package_request(&mut self, sender: &str, sender_key_package: &str) -> Result<()> {
        info!("Handling key package request from: {}", sender);

        // Create MLS client for this conversation
        let client = self.create_mls_client().await?;

        // Generate our key package in response
        let our_key_package = client.generate_key_package()?;

        // Create conversation ID (consistent ordering)
        let user = self.current_user.as_deref().unwrap_or("");
        let _conversation_id = if user < sender {
            format!("{}-{}", user, sender)
        } else {
            format!("{}-{}", sender, user)
        };

        // Sign our key package for authenticity
        let signature = if let (Some(secret_key), Some(passphrase)) = (&self.pgp_secret_key, &self.pgp_passphrase) {
            Crypto::pgp_sign_detached_secure(secret_key, &our_key_package, passphrase)?
        } else {
            return Err(anyhow!("PGP keys not available for signing"));
        };

        // Convert key package to base64 for transmission
        let our_key_package_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &our_key_package);
        let sender_key_package_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sender_key_package.as_bytes());

        // Send key package response back to sender
        self.service
            .send_key_package_response(user, sender, &sender_key_package_b64, &our_key_package_b64, &signature)
            .await?;

        info!("Sent key package response to: {}", sender);
        Ok(())
    }

    /// Handle incoming group welcome message
    pub async fn handle_group_welcome(&mut self, sender: &str, welcome_message: &str, group_id: &str) -> Result<()> {
        info!("Handling group welcome from: {} for group: {}", sender, group_id);

        // Create MLS client for processing the welcome
        let client = self.create_mls_client().await?;

        // Decode and process the welcome message
        let welcome_bytes = base64::engine::general_purpose::STANDARD.decode(welcome_message)
            .map_err(|e| anyhow!("Failed to decode welcome message: {}", e))?;

        // Join the MLS group using the welcome message
        let conversation_info = client.join_conversation(&welcome_bytes).await?;

        info!("Successfully joined MLS group: {}", group_id);

        // Store group state in database
        let group_state = client.export_group_state(&conversation_info.conversation_id).await?;
        let user = self.current_user.as_deref().unwrap_or("");
        self.db.save_mls_group_state(user, group_id, &group_state).await?;

        // Send confirmation back to sender
        let user = self.current_user.as_deref().unwrap_or("");
        self.service
            .send_group_join_response(user, sender, group_id, true, "")
            .await?;

        info!("Sent group join confirmation to: {}", sender);
        Ok(())
    }

    /// Establish MLS conversation with a recipient
    pub async fn establish_conversation(&mut self, recipient: &str) -> Result<()> {
        info!("Establishing MLS conversation with: {}", recipient);

        // Create MLS client
        let client = self.create_mls_client().await?;

        // Generate our key package for the handshake
        let our_key_package = client.generate_key_package()?;

        // Sign our key package for authenticity
        let signature = if let (Some(secret_key), Some(passphrase)) = (&self.pgp_secret_key, &self.pgp_passphrase) {
            Crypto::pgp_sign_detached_secure(secret_key, &our_key_package, passphrase)?
        } else {
            return Err(anyhow!("PGP keys not available for signing"));
        };

        // Convert key package to base64 for transmission
        let our_key_package_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &our_key_package);
        let user = self.current_user.as_deref().unwrap_or("");

        // Send key package request to recipient
        self.service
            .send_key_package_request(user, recipient, &our_key_package_b64, &signature)
            .await?;

        info!("Sent key package request to: {}", recipient);
        Ok(())
    }

    /// Create an MLS client instance using existing PGP keys
    /// Uses Arc::clone for cheap reference counting instead of expensive key cloning
    async fn create_mls_client(&self) -> Result<MlsClient> {
        let user = self.current_user.as_deref()
            .ok_or_else(|| anyhow!("No current user set"))?;

        let secret_key = self.pgp_secret_key.as_ref()
            .ok_or_else(|| anyhow!("PGP secret key not available"))?;

        let public_key = self.pgp_public_key.as_ref()
            .ok_or_else(|| anyhow!("PGP public key not available"))?;

        let passphrase = self.pgp_passphrase.as_ref()
            .ok_or_else(|| anyhow!("PGP passphrase not available"))?;

        // Create MLS client with existing PGP keys (Arc::clone is cheap - just increments ref count)
        MlsClient::new(user, Arc::clone(secret_key), Arc::clone(public_key), self.db.clone(), passphrase)
    }

    /// Update manager state
    pub fn update_state(
        &mut self,
        current_user: Option<String>,
        pgp_secret_key: Option<ArcSecretKey>,
        pgp_public_key: Option<ArcPublicKey>,
        pgp_passphrase: Option<ArcPassphrase>,
        mls_storage_path: Option<String>,
    ) {
        self.current_user = current_user;
        self.pgp_secret_key = pgp_secret_key;
        self.pgp_public_key = pgp_public_key;
        self.pgp_passphrase = pgp_passphrase;
        self.mls_storage_path = mls_storage_path;
    }

    /// Check if conversation exists with recipient
    #[allow(dead_code)] // Part of public API for conversation management
    pub async fn conversation_exists(&self, recipient: &str) -> Result<bool> {
        let user = self.current_user.as_deref().unwrap_or("");
        let _conversation_id = if user < recipient {
            format!("{}-{}", user, recipient)
        } else {
            format!("{}-{}", recipient, user)
        };

        // Try to create MLS client and check if group exists
        if let Ok(_client) = self.create_mls_client().await {
            // For now, just return false as we need to implement proper group loading
            Ok(false)
        } else {
            Ok(false)
        }
    }

    /// Handle MLS protocol messages - centralized routing
    pub async fn handle_mls_protocol_message(&mut self, envelope: &crate::core::messages::MixnetMessage) -> Result<(String, String)> {
        match envelope.action.as_str() {
            "keyPackageRequest" => {
                if let Ok(sender_key_package) = crate::crypto::MessageCrypto::extract_key_package(envelope) {
                    self.handle_key_package_request(&envelope.sender, &sender_key_package).await?;
                }
                Ok((String::new(), String::new())) // No chat message to return
            }
            "groupWelcome" => {
                if let Ok((welcome_message, group_id)) = crate::crypto::MessageCrypto::extract_group_welcome(envelope) {
                    self.handle_group_welcome(&envelope.sender, &welcome_message, &group_id).await?;
                }
                Ok((String::new(), String::new())) // No chat message to return
            }
            "send" | "incomingMessage" => {
                // Handle MLS chat messages with epoch-aware buffering
                if let Ok((conversation_id, mls_message)) = crate::crypto::MessageCrypto::extract_mls_message(envelope) {
                    // Use buffered processing to handle out-of-order messages
                    match self.process_incoming_message_buffered(&conversation_id, &envelope.sender, &mls_message).await {
                        Ok(Some((sender, message))) => Ok((sender, message)),
                        Ok(None) => {
                            // Message was buffered for later - return empty
                            log::info!("Message buffered for conversation {} (epoch mismatch)", conversation_id);
                            Ok((String::new(), String::new()))
                        }
                        Err(e) => {
                            log::error!("Failed to process MLS chat message: {}", e);
                            Err(e)
                        }
                    }
                } else {
                    log::error!("Failed to extract MLS message data from envelope");
                    Ok((String::new(), String::new()))
                }
            }
            _ => {
                log::warn!("Unknown MLS protocol action: {}", envelope.action);
                Ok((String::new(), String::new()))
            }
        }
    }

    /// Handle incoming MLS chat messages
    pub async fn handle_mls_chat_message(&mut self, sender: &str, conversation_id: &str, mls_message: &str) -> Result<(String, String)> {
        log::info!("Processing MLS chat message from {} in conversation {}", sender, conversation_id);

        // Decode the base64 MLS message
        let mls_message_bytes = base64::engine::general_purpose::STANDARD.decode(mls_message)
            .map_err(|e| anyhow!("Failed to decode MLS message: {}", e))?;

        // Parse the MLS message
        let mls_msg = mls_rs::MlsMessage::from_bytes(&mls_message_bytes)
            .map_err(|e| anyhow!("Failed to parse MLS message: {}", e))?;

        // Decode conversation ID
        let conversation_id_bytes = base64::engine::general_purpose::STANDARD.decode(conversation_id)
            .map_err(|e| anyhow!("Failed to decode conversation ID: {}", e))?;

        // Create MLS client and load the group
        let mls_client_wrapper = self.create_mls_client().await?;
        let client = mls_client_wrapper.create_client()?;
        let mut group = client.load_group(&conversation_id_bytes)
            .map_err(|e| anyhow!("Failed to load MLS group: {}", e))?;

        // Process the incoming message
        let processed = group.process_incoming_message(mls_msg)
            .map_err(|e| anyhow!("Failed to process MLS message: {}", e))?;

        // Save group state
        group.write_to_storage()
            .map_err(|e| anyhow!("Failed to save group state: {}", e))?;

        // Extract decrypted content if it's an application message
        let decrypted = match processed {
            mls_rs::group::ReceivedMessage::ApplicationMessage(app_msg) => app_msg.data().to_vec(),
            _ => {
                log::info!("Received non-application MLS message (handshake/control)");
                return Ok((String::new(), String::new()));
            }
        };

        let message_text = String::from_utf8(decrypted)
            .map_err(|e| anyhow!("Failed to decode message text: {}", e))?;

        log::info!("Successfully decrypted MLS message: {}", message_text);
        Ok((sender.to_string(), message_text))
    }

    // ========== Epoch-Aware Buffered Processing ==========

    /// Process an incoming MLS message with epoch-aware buffering
    ///
    /// If the message cannot be processed due to epoch mismatch, it's buffered
    /// for retry when the epoch advances.
    ///
    /// Returns:
    /// - Ok(Some((sender, message))) if message was processed successfully
    /// - Ok(None) if message was buffered for later processing
    /// - Err(e) for non-epoch-related errors
    pub async fn process_incoming_message_buffered(
        &mut self,
        conv_id: &str,
        sender: &str,
        mls_message_b64: &str,
    ) -> Result<Option<(String, String)>> {
        // Try to process the message directly
        match self.try_process_mls_message(conv_id, mls_message_b64).await {
            Ok(result) => {
                // Message processed successfully
                info!("Successfully processed MLS message from {} in {}", sender, conv_id);

                // After successful processing, try to process any buffered messages
                let (processed, failed) = self.process_buffered_messages(conv_id).await?;
                if processed > 0 || failed > 0 {
                    info!(
                        "Processed {} buffered messages ({} failed) for conversation {}",
                        processed, failed, conv_id
                    );
                }

                Ok(Some((sender.to_string(), result)))
            }
            Err(e) if self.is_epoch_error(&e) => {
                // Epoch mismatch - buffer the message for later
                warn!(
                    "Epoch mismatch for message from {} in {}: {}. Buffering for retry.",
                    sender, conv_id, e
                );

                self.epoch_buffer
                    .queue_message(conv_id, sender, mls_message_b64)
                    .await?;

                Ok(None)
            }
            Err(e) => {
                // Non-epoch error - propagate
                Err(e)
            }
        }
    }

    /// Try to process an MLS message, returning the decrypted content or an error
    async fn try_process_mls_message(
        &self,
        conv_id: &str,
        mls_message_b64: &str,
    ) -> Result<String> {
        // Decode the base64 MLS message
        let mls_message_bytes = base64::engine::general_purpose::STANDARD
            .decode(mls_message_b64)
            .map_err(|e| anyhow!("Failed to decode MLS message: {}", e))?;

        // Parse the MLS message
        let mls_msg = mls_rs::MlsMessage::from_bytes(&mls_message_bytes)
            .map_err(|e| anyhow!("Failed to parse MLS message: {}", e))?;

        // Create MLS client and load the group
        let mls_client_wrapper = self.create_mls_client().await?;
        let client = mls_client_wrapper.create_client()?;

        // Decode conversation ID from base64 to get actual group ID bytes
        let conversation_id_bytes = base64::engine::general_purpose::STANDARD
            .decode(conv_id)
            .map_err(|e| anyhow!("Failed to decode conversation ID: {}", e))?;

        let mut group = client
            .load_group(&conversation_id_bytes)
            .map_err(|e| anyhow!("Failed to load MLS group: {}", e))?;

        // Get current epoch before processing
        let epoch_before = group.current_epoch();

        // Process the incoming message
        let processed = group
            .process_incoming_message(mls_msg)
            .map_err(|e| anyhow!("Failed to process MLS message: {}", e))?;

        // Get epoch after processing (may have advanced if this was a Commit)
        let epoch_after = group.current_epoch();

        // Save group state
        group
            .write_to_storage()
            .map_err(|e| anyhow!("Failed to save group state: {}", e))?;

        // Update epoch tracking if changed
        if epoch_after > epoch_before {
            self.epoch_buffer.update_epoch(conv_id, epoch_after).await;
            info!(
                "Epoch advanced in conversation {}: {} -> {}",
                conv_id, epoch_before, epoch_after
            );
        }

        // Extract decrypted content if it's an application message
        match processed {
            mls_rs::group::ReceivedMessage::ApplicationMessage(app_msg) => {
                let decrypted = app_msg.data().to_vec();
                let message_text = String::from_utf8(decrypted)
                    .map_err(|e| anyhow!("Failed to decode message text: {}", e))?;
                Ok(message_text)
            }
            mls_rs::group::ReceivedMessage::Commit(_) => {
                info!("Processed Commit message, epoch may have advanced");
                Ok(String::new()) // Commit messages don't have content
            }
            _ => {
                debug!("Received non-application MLS message (handshake/control)");
                Ok(String::new())
            }
        }
    }

    /// Check if an error is related to epoch mismatch
    fn is_epoch_error(&self, error: &anyhow::Error) -> bool {
        let msg = error.to_string().to_lowercase();

        // Check for common epoch-related error patterns
        msg.contains("epoch")
            || msg.contains("generation")
            || msg.contains("stale")
            || msg.contains("wrong epoch")
            || msg.contains("future epoch")
            || msg.contains("old epoch")
            || msg.contains("message from wrong epoch")
            || msg.contains("cannot decrypt")
            || msg.contains("secret tree")
            || msg.contains("ratchet")
    }

    /// Process all buffered messages for a conversation
    ///
    /// Returns (processed_count, failed_count)
    pub async fn process_buffered_messages(&self, conv_id: &str) -> Result<(usize, usize)> {
        let candidates = self.epoch_buffer.get_retry_candidates(conv_id).await?;
        let mut processed = 0;
        let mut failed = 0;

        for msg in candidates {
            // Check if max retries exceeded
            if msg.retry_count >= super::epoch_buffer::MAX_RETRY_COUNT {
                self.epoch_buffer
                    .mark_failed(conv_id, &msg.mls_message_b64, "Max retry count exceeded")
                    .await?;
                failed += 1;
                continue;
            }

            // Check if message is too old
            let age = chrono::Utc::now()
                .signed_duration_since(msg.received_at)
                .num_seconds();
            if age > super::epoch_buffer::MAX_BUFFER_AGE_SECS {
                self.epoch_buffer
                    .mark_failed(conv_id, &msg.mls_message_b64, "Message expired")
                    .await?;
                failed += 1;
                continue;
            }

            // Try to process the message
            match self.try_process_mls_message(conv_id, &msg.mls_message_b64).await {
                Ok(_) => {
                    self.epoch_buffer
                        .mark_processed(conv_id, &msg.mls_message_b64)
                        .await?;
                    processed += 1;
                    info!(
                        "Successfully processed buffered message from {} in conversation {}",
                        msg.sender, conv_id
                    );
                }
                Err(e) if self.is_epoch_error(&e) => {
                    // Still can't process - increment retry count
                    let new_count = self.epoch_buffer
                        .increment_retry(conv_id, &msg.mls_message_b64)
                        .await?;
                    debug!(
                        "Message still cannot be processed (epoch error), retry count: {}",
                        new_count
                    );
                }
                Err(e) => {
                    // Non-epoch error
                    let new_count = self.epoch_buffer
                        .increment_retry(conv_id, &msg.mls_message_b64)
                        .await?;
                    warn!(
                        "Error processing buffered message (retry {}): {}",
                        new_count, e
                    );

                    if new_count >= super::epoch_buffer::MAX_RETRY_COUNT {
                        self.epoch_buffer
                            .mark_failed(
                                conv_id,
                                &msg.mls_message_b64,
                                &format!("Processing error: {}", e),
                            )
                            .await?;
                        failed += 1;
                    }
                }
            }
        }

        Ok((processed, failed))
    }

    /// Get all conversations that have pending buffered messages
    pub async fn get_conversations_with_pending(&self) -> Result<Vec<String>> {
        self.epoch_buffer.get_conversations_with_pending().await
    }

    /// Cleanup expired buffered messages
    pub async fn cleanup_expired_buffered(&self, max_age_secs: i64) -> Result<u64> {
        self.epoch_buffer.cleanup_expired(max_age_secs).await
    }

    /// Get buffer statistics for monitoring
    pub async fn get_buffer_stats(&self) -> super::epoch_buffer::BufferStats {
        self.epoch_buffer.get_stats().await
    }

    // ========== Phase 3: Welcome Flow Handling ==========

    /// Handle receiving a Welcome message (joining a group)
    ///
    /// This method processes a Welcome message from a group admin and establishes
    /// the user's membership in the group. It also verifies the sender's credential.
    ///
    /// # Arguments
    /// * `welcome` - The MlsWelcome received from the group admin
    /// * `sender_credential` - The credential of the sender for verification
    ///
    /// # Returns
    /// Ok(()) on successful group join
    pub async fn handle_welcome_message(
        &mut self,
        welcome: &MlsWelcome,
        sender_credential: &MlsCredential,
    ) -> Result<()> {
        info!(
            "Handling welcome message for group {} from {}",
            welcome.group_id, welcome.sender
        );

        // Verify the sender's credential is valid
        if !sender_credential.is_valid() {
            return Err(anyhow!(
                "Sender credential is invalid or expired for user: {}",
                sender_credential.username
            ));
        }

        // Verify the sender matches the credential
        if sender_credential.username != welcome.sender {
            return Err(anyhow!(
                "Sender mismatch: welcome from {} but credential for {}",
                welcome.sender,
                sender_credential.username
            ));
        }

        // Create MLS client
        let mls_client = self.create_mls_client().await?;

        // Store the welcome in the database for persistence
        let user = self.current_user.as_deref().unwrap_or("");

        // Create StoredWelcome from MlsWelcome
        let stored_welcome = crate::crypto::mls::types::StoredWelcome {
            id: 0,
            group_id: welcome.group_id.clone(),
            sender: welcome.sender.clone(),
            welcome_bytes: welcome.welcome_bytes.clone(),
            ratchet_tree: welcome.ratchet_tree.clone(),
            cipher_suite: welcome.cipher_suite,
            epoch: welcome.epoch,
            received_at: chrono::Utc::now().to_rfc3339(),
            processed: false,
            processed_at: None,
            error_message: None,
        };

        self.db.store_welcome(user, &stored_welcome).await?;

        // Process the welcome to join the group
        let _mls_group_id = mls_client.process_welcome(welcome).await?;

        // Mark the welcome as processed
        // Get the pending welcomes and find the one we just stored
        let pending = self.db.get_pending_welcomes(user).await?;
        for stored in pending {
            if stored.group_id == welcome.group_id && stored.sender == welcome.sender {
                self.db.mark_welcome_processed(user, stored.id).await?;
                break;
            }
        }

        // Store group membership info
        self.db.add_group_membership(
            user,
            &welcome.group_id,
            &welcome.sender,
            Some(&sender_credential.fingerprint_hex()),
            true, // credential verified
            "admin", // the inviter is admin
        ).await?;

        // Add ourselves as a member
        let own_fingerprint = mls_client.pgp_fingerprint()?;
        self.db.add_group_membership(
            user,
            &welcome.group_id,
            user,
            Some(&hex::encode(&own_fingerprint)),
            true,
            "member",
        ).await?;

        info!(
            "Successfully joined group {} via welcome from {}",
            welcome.group_id, welcome.sender
        );

        Ok(())
    }

    /// Invite a user to a conversation/group
    ///
    /// This method creates a Welcome message to invite a new member to an existing
    /// group or conversation.
    ///
    /// # Arguments
    /// * `conversation_id` - The conversation/group to invite the member to
    /// * `member_username` - The username of the member to invite
    /// * `member_key_package` - Base64-encoded key package of the member
    ///
    /// # Returns
    /// MlsWelcome to be sent to the invited member
    pub async fn invite_member(
        &mut self,
        conversation_id: &str,
        member_username: &str,
        member_key_package: &str,
    ) -> Result<MlsWelcome> {
        info!(
            "Inviting {} to conversation {}",
            member_username, conversation_id
        );

        // Create MLS client
        let mls_client = self.create_mls_client().await?;

        // Decode the key package
        let key_package_bytes = base64::engine::general_purpose::STANDARD
            .decode(member_key_package)
            .map_err(|e| anyhow!("Invalid key package base64: {}", e))?;

        // Add the member to the group and get Welcome + Commit
        let add_result = mls_client.add_member_to_group(conversation_id, &key_package_bytes).await?;

        // Store group membership
        let user = self.current_user.as_deref().unwrap_or("");
        self.db.add_group_membership(
            user,
            conversation_id,
            member_username,
            None, // fingerprint will be updated when they join
            false, // not yet verified
            "member",
        ).await?;

        // Sign the welcome message for authenticity
        if let (Some(secret_key), Some(passphrase)) = (&self.pgp_secret_key, &self.pgp_passphrase) {
            let welcome_bytes = add_result.welcome.to_bytes()?;
            let signature = Crypto::pgp_sign_detached_secure(secret_key, &welcome_bytes, passphrase)?;

            // Send the welcome via mixnet
            self.service.send_mls_welcome(
                user,
                member_username,
                &add_result.welcome,
                &signature,
            ).await?;
        }

        info!(
            "Created welcome for {} to join conversation {}",
            member_username, conversation_id
        );

        Ok(add_result.welcome)
    }

    /// Create a new group and get its public info
    ///
    /// # Arguments
    /// * `group_name` - A name/identifier for the group
    ///
    /// # Returns
    /// MlsGroupInfoPublic containing the group's public information
    pub async fn create_group(&mut self, group_name: &str) -> Result<MlsGroupInfoPublic> {
        info!("Creating new group: {}", group_name);

        let mls_client = self.create_mls_client().await?;
        let group_info = mls_client.create_mls_group(group_name).await?;

        // Store our own membership as creator/admin
        let user = self.current_user.as_deref().unwrap_or("");
        let own_fingerprint = mls_client.pgp_fingerprint()?;

        self.db.add_group_membership(
            user,
            &group_info.group_id,
            user,
            Some(&hex::encode(&own_fingerprint)),
            true,
            "admin",
        ).await?;

        // Store the group info for later reference
        self.db.store_group_info(user, &group_info.group_id, &group_info).await?;

        info!("Created group: {} with id {}", group_name, group_info.group_id);

        Ok(group_info)
    }

    /// Get group information
    ///
    /// # Arguments
    /// * `group_id` - The group identifier
    ///
    /// # Returns
    /// Option<MlsGroupInfoPublic> if the group exists
    pub async fn get_group_info(&self, group_id: &str) -> Result<Option<MlsGroupInfoPublic>> {
        let user = self.current_user.as_deref().unwrap_or("");
        self.db.get_group_info(user, group_id).await
    }

    /// Process pending welcome messages
    ///
    /// This method processes any unprocessed Welcome messages that may have
    /// been received while offline.
    ///
    /// # Returns
    /// Number of welcomes successfully processed
    pub async fn process_pending_welcomes(&mut self) -> Result<usize> {
        let user = self.current_user.as_deref().unwrap_or("");
        let pending = self.db.get_pending_welcomes(user).await?;

        let mut processed_count = 0;

        for stored in pending {
            // Skip already processed
            if stored.processed {
                continue;
            }

            // Convert to MlsWelcome (cipher_suite and epoch are now stored with the welcome)
            let mls_client = self.create_mls_client().await?;
            let welcome = stored.to_mls_welcome();

            match mls_client.process_welcome(&welcome).await {
                Ok(_mls_group_id) => {
                    self.db.mark_welcome_processed(user, stored.id).await?;
                    processed_count += 1;
                    info!("Processed pending welcome for group {}", stored.group_id);
                }
                Err(e) => {
                    warn!("Failed to process welcome for group {}: {}", stored.group_id, e);
                }
            }
        }

        Ok(processed_count)
    }

    /// Get list of groups the user is a member of
    pub async fn get_user_groups(&self) -> Result<Vec<String>> {
        let user = self.current_user.as_deref().unwrap_or("");
        self.db.get_user_groups(user).await
    }

    /// Get members of a group
    pub async fn get_group_members(&self, group_id: &str) -> Result<Vec<crate::core::db::GroupMember>> {
        let user = self.current_user.as_deref().unwrap_or("");
        self.db.get_group_members(user, group_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Note: These would need actual test implementations with mock services

    #[test]
    fn test_conversation_id_generation() {
        // Test that conversation IDs are generated consistently regardless of order
        let user1 = "alice";
        let user2 = "bob";

        let id1 = if user1 < user2 {
            format!("{}-{}", user1, user2)
        } else {
            format!("{}-{}", user2, user1)
        };

        let id2 = if user2 < user1 {
            format!("{}-{}", user2, user1)
        } else {
            format!("{}-{}", user1, user2)
        };

        assert_eq!(id1, id2);
        assert_eq!(id1, "alice-bob");
    }
}