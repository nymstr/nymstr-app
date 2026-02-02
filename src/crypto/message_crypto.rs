//! Message cryptography operations
//!
//! Handles encryption, decryption, and signature verification for messages.

use crate::core::messages::MixnetMessage;
use crate::crypto::{Crypto, EncryptedMessage};
use anyhow::{anyhow, Result};
use pgp::composed::SignedPublicKey;

/// Result of message decryption and verification
#[derive(Debug)]
pub struct VerifiedMessage {
    pub sender: String,
    pub content: String,
    pub signature_valid: bool,
}

/// Message cryptography handler
pub struct MessageCrypto;

impl MessageCrypto {
    /// Decrypt and verify a chat message
    pub fn decrypt_and_verify_chat_message(
        envelope: &MixnetMessage,
        sender_public_key: Option<&SignedPublicKey>,
    ) -> Result<VerifiedMessage> {
        // Extract encrypted message from payload
        let encrypted_data = envelope
            .payload
            .get("encrypted")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing encrypted data in message"))?;

        let signature = envelope
            .payload
            .get("signature")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing signature in message"))?;

        // Deserialize the encrypted message
        let _encrypted_message: EncryptedMessage = serde_json::from_str(encrypted_data)
            .map_err(|e| anyhow!("Failed to deserialize encrypted message: {}", e))?;

        // For now, handle as direct message (no MLS decryption)
        // TODO: Implement proper MLS decryption based on message type
        let content = envelope
            .payload
            .get("content")
            .and_then(|v| v.as_str())
            .unwrap_or("(encrypted content)");

        // Verify signature if we have sender's public key
        let signature_valid = if let Some(public_key) = sender_public_key {
            match Crypto::pgp_verify_detached(public_key, content.as_bytes(), signature) {
                Ok(_) => {
                    log::info!("✅ Signature verified for message from {}", envelope.sender);
                    true
                }
                Err(e) => {
                    log::error!(
                        "Signature verification failed from {}: {}",
                        envelope.sender,
                        e
                    );
                    false
                }
            }
        } else {
            log::warn!(
                "No public key available for signature verification from {}",
                envelope.sender
            );
            false
        };

        Ok(VerifiedMessage {
            sender: envelope.sender.clone(),
            content: content.to_string(),
            signature_valid,
        })
    }

    /// Extract handshake information from message
    pub fn extract_handshake_info(envelope: &MixnetMessage) -> Result<String> {
        envelope
            .payload
            .get("nym_address")
            .and_then(|v| v.as_str())
            .map(|addr| addr.to_string())
            .ok_or_else(|| anyhow!("Missing nym_address in handshake message"))
    }

    /// Extract key package from MLS message
    pub fn extract_key_package(envelope: &MixnetMessage) -> Result<String> {
        envelope
            .payload
            .get("senderKeyPackage")
            .and_then(|v| v.as_str())
            .map(|pkg| pkg.to_string())
            .ok_or_else(|| anyhow!("Missing senderKeyPackage in MLS message"))
    }

    /// Extract group welcome information from MLS message
    pub fn extract_group_welcome(envelope: &MixnetMessage) -> Result<(String, String)> {
        let welcome_message = envelope
            .payload
            .get("welcomeMessage")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing welcomeMessage in group welcome"))?;

        let group_id = envelope
            .payload
            .get("groupId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing groupId in group welcome"))?;

        Ok((welcome_message.to_string(), group_id.to_string()))
    }

    /// Extract MLS chat message data from envelope
    pub fn extract_mls_message(envelope: &MixnetMessage) -> Result<(String, String)> {
        let conversation_id = envelope
            .payload
            .get("conversation_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing conversation_id in MLS message"))?;
        let mls_message = envelope
            .payload
            .get("mls_message")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing mls_message in MLS message"))?;
        Ok((conversation_id.to_string(), mls_message.to_string()))
    }

    /// Validate message structure without decrypting
    #[allow(dead_code)] // Part of public API for message validation
    pub fn validate_message_structure(envelope: &MixnetMessage) -> Result<()> {
        if envelope.sender.is_empty() {
            return Err(anyhow!("Message has empty sender"));
        }

        if envelope.action.is_empty() {
            return Err(anyhow!("Message has empty action"));
        }

        // Action-specific validation
        match envelope.action.as_str() {
            "send" | "incomingMessage" => {
                if envelope.payload.get("encrypted").is_none() {
                    return Err(anyhow!("Chat message missing encrypted payload"));
                }
                if envelope.payload.get("signature").is_none() {
                    return Err(anyhow!("Chat message missing signature"));
                }
            }
            "handshake" => {
                if envelope.payload.get("nym_address").is_none() {
                    return Err(anyhow!("Handshake message missing nym_address"));
                }
            }
            "keyPackageRequest" => {
                if envelope.payload.get("senderKeyPackage").is_none() {
                    return Err(anyhow!("Key package request missing senderKeyPackage"));
                }
            }
            "groupWelcome" => {
                if envelope.payload.get("welcomeMessage").is_none() {
                    return Err(anyhow!("Group welcome missing welcomeMessage"));
                }
                if envelope.payload.get("groupId").is_none() {
                    return Err(anyhow!("Group welcome missing groupId"));
                }
            }
            _ => {
                // Other message types don't need specific validation
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_test_envelope(action: &str, payload: serde_json::Value) -> MixnetMessage {
        MixnetMessage {
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
    fn test_validate_chat_message() {
        let envelope = create_test_envelope(
            "send",
            json!({
                "encrypted": "test_encrypted_data",
                "signature": "test_signature"
            }),
        );

        assert!(MessageCrypto::validate_message_structure(&envelope).is_ok());
    }

    #[test]
    fn test_validate_handshake_message() {
        let envelope = create_test_envelope(
            "handshake",
            json!({
                "nym_address": "test_address"
            }),
        );

        assert!(MessageCrypto::validate_message_structure(&envelope).is_ok());
    }

    #[test]
    fn test_validate_invalid_message() {
        let envelope = create_test_envelope("send", json!({})); // Missing required fields

        assert!(MessageCrypto::validate_message_structure(&envelope).is_err());
    }

    #[test]
    fn test_extract_handshake_info() {
        let envelope = create_test_envelope(
            "handshake",
            json!({
                "nym_address": "test_nym_address"
            }),
        );

        let result = MessageCrypto::extract_handshake_info(&envelope);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test_nym_address");
    }

    #[test]
    fn test_extract_key_package() {
        let envelope = create_test_envelope(
            "keyPackageRequest",
            json!({
                "senderKeyPackage": "test_key_package"
            }),
        );

        let result = MessageCrypto::extract_key_package(&envelope);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test_key_package");
    }
}
