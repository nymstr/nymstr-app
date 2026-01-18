//! Direct messaging methods for MessageHandler
//!
//! This module contains methods for sending direct (P2P) encrypted messages.

use super::{MessageHandler, normalize_conversation_id};
use crate::crypto::{Crypto, EncryptedMessage, MlsMessageType};
use anyhow::anyhow;
use chrono::Utc;
use serde_json::json;

impl MessageHandler {
    /// Send a direct (encrypted) message to a contact using MLS
    pub async fn send_direct_message(
        &mut self,
        recipient: &str,
        message_content: &str,
    ) -> anyhow::Result<()> {
        let user = self.current_user.as_deref().unwrap_or("").to_string();

        // Check if we have an established conversation with this recipient
        // Use normalized conversation ID (consistent with handshake)
        let conversation_id = normalize_conversation_id(&user, recipient);
        // Check if MLS group exists for this conversation
        let client = self.create_mls_client().await?;
        let group_id = conversation_id.as_bytes();
        let conversation_exists = client.load_group(group_id).is_ok();

        if !conversation_exists {
            // Need to establish MLS group first
            log::info!("No existing conversation with {}, initiating MLS handshake", recipient);
            self.establish_mls_conversation(recipient).await?;
        }

        // Persist the outgoing plaintext message locally
        self.db
            .save_message(&user, recipient, true, message_content, Utc::now())
            .await?;

        // Load the group for this conversation (reuse group_id from earlier)
        // Note: client was already created above for the existence check
        let mut group = match client.load_group(group_id) {
            Ok(group) => group,
            Err(_) => return Err(anyhow!("No MLS group found for conversation {}", conversation_id)),
        };

        // Wrap plaintext in type/message JSON
        let wrapped = json!({"type": 0, "message": message_content});
        let wrapped_str = wrapped.to_string();

        // Encrypt message using MLS group
        let mls_message = group.encrypt_application_message(wrapped_str.as_bytes(), Default::default())?;

        // Convert to EncryptedMessage format expected by service
        let encrypted_message = EncryptedMessage {
            conversation_id: conversation_id.as_bytes().to_vec(),
            mls_message: mls_message.to_bytes()?,
            message_type: MlsMessageType::Application,
        };

        // Sign the message content for authentication (PGP signature)
        let signature = if let (Some(secret_key), Some(passphrase)) = (&self.pgp_secret_key, &self.pgp_passphrase) {
            Crypto::pgp_sign_detached_secure(secret_key, message_content.as_bytes(), passphrase)?
        } else {
            return Err(anyhow!("PGP secret key or passphrase not available for signing"));
        };

        // Send MLS encrypted message using unified format
        self.service
            .send_mls_message(&user, recipient, &encrypted_message, &signature)
            .await?;

        // Save group state to MLS internal storage after sending message
        group.write_to_storage()?;
        log::info!("Saved MLS group state to persistent storage after sending message");

        Ok(())
    }
}
