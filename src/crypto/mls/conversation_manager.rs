//! MLS conversation management
//!
//! Handles MLS protocol operations for conversation establishment and group management.

use crate::core::{db::Db, mixnet_client::MixnetService};
use crate::crypto::{Crypto, SecurePassphrase};
use super::MlsClient;
use anyhow::{Result, anyhow};
use base64::Engine;
use log::info;
use pgp::composed::{SignedSecretKey, SignedPublicKey};
use std::sync::Arc;

/// Manages MLS conversations and protocol operations
pub struct MlsConversationManager {
    /// Database for persistence
    pub db: Arc<Db>,
    /// Mixnet service for communication
    pub service: Arc<MixnetService>,
    /// Current user (for conversation IDs)
    pub current_user: Option<String>,
    /// PGP keys for signing
    pub pgp_secret_key: Option<SignedSecretKey>,
    pub pgp_public_key: Option<SignedPublicKey>,
    pub pgp_passphrase: Option<SecurePassphrase>,
    /// MLS storage path
    pub mls_storage_path: Option<String>,
}

impl MlsConversationManager {
    pub fn new(
        db: Arc<Db>,
        service: Arc<MixnetService>,
        current_user: Option<String>,
        pgp_secret_key: Option<SignedSecretKey>,
        pgp_public_key: Option<SignedPublicKey>,
        pgp_passphrase: Option<SecurePassphrase>,
        mls_storage_path: Option<String>,
    ) -> Self {
        Self {
            db,
            service,
            current_user,
            pgp_secret_key,
            pgp_public_key,
            pgp_passphrase,
            mls_storage_path,
        }
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
        let conversation_id = if user < sender {
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

    /// Create an MLS client instance
    async fn create_mls_client(&self) -> Result<MlsClient> {
        let user = self.current_user.as_deref()
            .ok_or_else(|| anyhow!("No current user set"))?;

        let secret_key = self.pgp_secret_key.as_ref()
            .ok_or_else(|| anyhow!("PGP secret key not available"))?;

        let _public_key = self.pgp_public_key.as_ref()
            .ok_or_else(|| anyhow!("PGP public key not available"))?;

        let passphrase = self.pgp_passphrase.as_ref()
            .ok_or_else(|| anyhow!("PGP passphrase not available"))?;

        // Create MLS client with secure key generation
        MlsClient::new_with_generated_keys_secure(user, self.db.clone(), passphrase)
    }

    /// Update manager state
    pub fn update_state(
        &mut self,
        current_user: Option<String>,
        pgp_secret_key: Option<SignedSecretKey>,
        pgp_public_key: Option<SignedPublicKey>,
        pgp_passphrase: Option<SecurePassphrase>,
        mls_storage_path: Option<String>,
    ) {
        self.current_user = current_user;
        self.pgp_secret_key = pgp_secret_key;
        self.pgp_public_key = pgp_public_key;
        self.pgp_passphrase = pgp_passphrase;
        self.mls_storage_path = mls_storage_path;
    }

    /// Check if conversation exists with recipient
    pub async fn conversation_exists(&self, recipient: &str) -> Result<bool> {
        let user = self.current_user.as_deref().unwrap_or("");
        let conversation_id = if user < recipient {
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
                // Handle MLS chat messages
                if let Ok((conversation_id, mls_message)) = crate::crypto::MessageCrypto::extract_mls_message(envelope) {
                    self.handle_mls_chat_message(&envelope.sender, &conversation_id, &mls_message).await
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