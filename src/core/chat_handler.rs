//! Chat message handling
//!
//! Handles regular chat messages and handshakes.

use crate::core::db::Db;
use crate::crypto::{MessageCrypto, Crypto};
use anyhow::{Result, anyhow};
use chrono::Utc;
use log::{info, warn, error};
use std::sync::Arc;

/// Result of processing a chat message
#[derive(Debug)]
#[allow(dead_code)] // Some variants used for future message types
pub enum ChatResult {
    /// Regular text message from sender
    TextMessage { sender: String, content: String },
    /// Handshake with nym address
    Handshake { nym_address: String },
    /// No message to display
    None,
}

/// Handles chat messages and handshakes
pub struct ChatHandler {
    /// Database for lookups and storage
    pub db: Arc<Db>,
    /// Current user (for saving messages)
    pub current_user: Option<String>,
}

impl ChatHandler {
    pub fn new(db: Arc<Db>, current_user: Option<String>) -> Self {
        Self {
            db,
            current_user,
        }
    }

    /// Process a chat message (send/incomingMessage)
    pub async fn handle_chat_message(&self, envelope: &crate::core::messages::MixnetMessage) -> Result<ChatResult> {
        // Look up sender's public key for verification
        let sender_public_key = match self.db.get_user(&envelope.sender).await {
            Ok(Some((_username, public_key_pem))) => {
                match Crypto::parse_pgp_public_key(&public_key_pem) {
                    Ok(pk) => Some(pk),
                    Err(e) => {
                        warn!("Failed to parse public key for {}: {}", envelope.sender, e);
                        None
                    }
                }
            }
            Ok(None) => {
                warn!("No public key found for sender: {}", envelope.sender);
                None
            }
            Err(e) => {
                error!("Database error looking up sender {}: {}", envelope.sender, e);
                None
            }
        };

        // Decrypt and verify the message
        let verified = MessageCrypto::decrypt_and_verify_chat_message(envelope, sender_public_key.as_ref())?;

        // SECURITY: Reject messages with invalid signatures
        if !verified.signature_valid {
            error!("Message from {} rejected: signature verification failed", envelope.sender);
            return Err(anyhow!("Message from {} rejected: signature verification failed", envelope.sender));
        }

        // Save message to database
        if let Some(current_user) = &self.current_user {
            if let Err(e) = self.db.save_message(current_user, &verified.sender, false, &verified.content, Utc::now()).await {
                error!("Failed to save message to database: {}", e);
            }
        }

        Ok(ChatResult::TextMessage {
            sender: verified.sender,
            content: verified.content,
        })
    }

    /// Process a handshake message
    pub async fn handle_handshake(&self, envelope: &crate::core::messages::MixnetMessage) -> Result<ChatResult> {
        let nym_address = MessageCrypto::extract_handshake_info(envelope)?;
        info!("Received handshake with nym address: {}", nym_address);

        Ok(ChatResult::Handshake { nym_address })
    }

    /// Update handler state
    #[allow(dead_code)] // Part of public API for state management
    pub fn update_current_user(&mut self, current_user: Option<String>) {
        self.current_user = current_user;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_test_envelope(action: &str, payload: serde_json::Value) -> crate::core::messages::MixnetMessage {
        crate::core::messages::MixnetMessage {
            message_type: "message".to_string(),
            action: action.to_string(),
            sender: "test_sender".to_string(),
            recipient: "test_recipient".to_string(),
            payload,
            signature: "test_signature".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn test_chat_result_variants() {
        let text_result = ChatResult::TextMessage {
            sender: "alice".to_string(),
            content: "Hello".to_string(),
        };

        let handshake_result = ChatResult::Handshake {
            nym_address: "test_address".to_string(),
        };

        match text_result {
            ChatResult::TextMessage { sender, content } => {
                assert_eq!(sender, "alice");
                assert_eq!(content, "Hello");
            }
            _ => panic!("Expected TextMessage"),
        }

        match handshake_result {
            ChatResult::Handshake { nym_address } => {
                assert_eq!(nym_address, "test_address");
            }
            _ => panic!("Expected Handshake"),
        }
    }
}