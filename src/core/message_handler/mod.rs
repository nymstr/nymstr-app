//! High-level handler for user registration, login, messaging, and queries
//!
//! This module is split into focused submodules:
//! - `auth`: Registration and login flow methods
//! - `mls`: MLS-related methods (client creation, handshake, conversation establishment)
//! - `group`: Group messaging methods (send, fetch, handle responses)
//! - `direct`: Direct messaging methods
//! - `welcome`: Welcome flow handlers (invites, welcomes, join requests)
//! - `buffer`: Background buffer processor for retrying MLS messages

#![allow(dead_code)]

mod auth;
mod mls;
mod group;
mod direct;
mod welcome;
mod buffer;

// Re-export buffer processor types for public API
#[allow(unused_imports)] // Part of public API
pub use buffer::{start_buffer_processor, BufferProcessorHandle};

use crate::crypto::{Crypto, MlsConversationManager, SecurePassphrase};
use crate::crypto::mls::persistence::MlsGroupPersistence;
use crate::core::message_router::{MessageRouter, MessageRoute};
use crate::core::auth_handler::AuthenticationHandler;
use crate::core::chat_handler::{ChatHandler, ChatResult};
use crate::crypto::mls::KeyPackageManager;
use crate::core::db::Db;
use crate::core::mixnet_client::{Incoming, MixnetService};
use tokio::sync::mpsc::Receiver;
use std::sync::Arc;

use pgp::composed::{SignedSecretKey, SignedPublicKey};

/// Type alias for Arc-wrapped PGP secret key to reduce expensive cloning
pub type ArcSecretKey = Arc<SignedSecretKey>;
/// Type alias for Arc-wrapped PGP public key to reduce expensive cloning
pub type ArcPublicKey = Arc<SignedPublicKey>;
/// Type alias for Arc-wrapped secure passphrase to reduce expensive cloning
pub type ArcPassphrase = Arc<SecurePassphrase>;

/// Generate a normalized conversation ID for two users.
///
/// The conversation ID is deterministic regardless of the order of the two usernames,
/// ensuring that both parties in a conversation always use the same ID.
///
/// # Examples
/// ```ignore
/// assert_eq!(normalize_conversation_id("alice", "bob"), "alice-bob");
/// assert_eq!(normalize_conversation_id("bob", "alice"), "alice-bob");
/// ```
pub(crate) fn normalize_conversation_id(user1: &str, user2: &str) -> String {
    let (first, second) = if user1 < user2 {
        (user1, user2)
    } else {
        (user2, user1)
    };
    format!("{}-{}", first, second)
}

/// Handles user state, persistence, and mixnet interactions
pub struct MessageHandler {
    /// Crypto utilities
    pub crypto: Crypto,
    /// Underlying mixnet service client
    pub service: MixnetService,
    /// Incoming message receiver
    pub incoming_rx: Receiver<Incoming>,
    /// Database for persistence
    pub db: std::sync::Arc<Db>,
    /// Currently logged-in username
    pub current_user: Option<String>,
    /// Our own nym address
    pub nym_address: Option<String>,
    /// MLS signing identity and storage path (will create client fresh when needed)
    pub mls_storage_path: Option<String>,
    /// Optional user's PGP public key (Arc-wrapped to avoid expensive cloning)
    pub pgp_public_key: Option<ArcPublicKey>,
    /// Optional user's PGP secret key for signing (Arc-wrapped to avoid expensive cloning)
    pub pgp_secret_key: Option<ArcSecretKey>,
    /// Secure passphrase for PGP operations (Arc-wrapped to avoid expensive cloning)
    pub pgp_passphrase: Option<ArcPassphrase>,
    /// MLS key package manager
    pub key_package_manager: KeyPackageManager,
    /// MLS group state persistence
    pub mls_persistence: Option<MlsGroupPersistence>,
}

impl MessageHandler {
    /// Create a new handler by wrapping the mixnet service and DB
    pub async fn new(
        service: MixnetService,
        incoming_rx: Receiver<Incoming>,
        db_path: &str,
    ) -> anyhow::Result<Self> {
        let db = std::sync::Arc::new(Db::open(db_path).await?);
        db.init_global().await?;
        Ok(Self {
            crypto: Crypto,
            service,
            incoming_rx,
            key_package_manager: KeyPackageManager::new(db.clone()),
            mls_storage_path: None, // Will be set when user logs in
            db,
            current_user: None,
            nym_address: None,
            pgp_public_key: None,
            pgp_secret_key: None,
            pgp_passphrase: None,
            mls_persistence: None, // Will be set when user logs in
        })
    }

    /// Set PGP keys for the current session (called by CLI after key management)
    /// Keys are wrapped in Arc to enable cheap cloning for handlers that need them
    pub fn set_pgp_keys(&mut self, secret_key: SignedSecretKey, public_key: SignedPublicKey, passphrase: SecurePassphrase) {
        self.pgp_secret_key = Some(Arc::new(secret_key));
        self.pgp_public_key = Some(Arc::new(public_key));
        self.pgp_passphrase = Some(Arc::new(passphrase));
    }

    /// Dispatch a single incoming envelope and return decrypted chat messages.
    pub async fn process_received_message(&mut self, incoming: Incoming) -> Vec<(String, String)> {
        // Route the message to appropriate handler
        let route = MessageRouter::route_message(&incoming);

        // Only process messages that should be handled immediately
        if !MessageRouter::should_process_immediately(&route) {
            log::debug!("Message routed to {}, not processing immediately", MessageRouter::route_description(&route));
            return vec![];
        }

        // Create handlers with current state
        let _auth_handler = AuthenticationHandler::new(
            self.db.clone(),
            Arc::new(self.service.clone()),
            self.pgp_secret_key.clone(),
            self.pgp_public_key.clone(),
            self.pgp_passphrase.clone(),
        );

        let mut mls_manager = MlsConversationManager::new(
            self.db.clone(),
            Arc::new(self.service.clone()),
            self.current_user.clone(),
            self.pgp_secret_key.clone(),
            self.pgp_public_key.clone(),
            self.pgp_passphrase.clone(),
            self.mls_storage_path.clone(),
        );

        // Initialize epoch buffer for out-of-order message handling
        if let Err(e) = mls_manager.init_epoch_buffer().await {
            log::warn!("Failed to initialize epoch buffer: {}", e);
        }

        let chat_handler = ChatHandler::new(self.db.clone(), self.current_user.clone());

        // Process based on route
        match route {
            MessageRoute::Chat => {
                match chat_handler.handle_chat_message(&incoming.envelope).await {
                    Ok(ChatResult::TextMessage { sender, content }) => {
                        vec![(sender, content)]
                    }
                    Ok(_) => vec![],
                    Err(e) => {
                        log::error!("Failed to process chat message: {}", e);
                        vec![]
                    }
                }
            }
            MessageRoute::Handshake => {
                match chat_handler.handle_handshake(&incoming.envelope).await {
                    Ok(ChatResult::Handshake { nym_address }) => {
                        self.nym_address = Some(nym_address);
                        vec![]
                    }
                    Ok(_) => vec![],
                    Err(e) => {
                        log::error!("Failed to process handshake: {}", e);
                        vec![]
                    }
                }
            }
            MessageRoute::MlsProtocol => {
                // Handle MLS protocol messages with epoch-aware buffering
                match mls_manager.handle_mls_protocol_message(&incoming.envelope).await {
                    Ok((sender, message)) => {
                        if !sender.is_empty() && !message.is_empty() {
                            vec![(sender, message)]
                        } else {
                            vec![]
                        }
                    }
                    Err(e) => {
                        // Check if this might be an epoch-related error that should be buffered
                        let error_msg = e.to_string().to_lowercase();
                        if error_msg.contains("epoch") || error_msg.contains("stale")
                            || error_msg.contains("generation") || error_msg.contains("cannot decrypt") {
                            log::warn!("MLS message may be out of order (epoch error), buffering: {}", e);
                            // The ConversationManager will handle buffering internally
                        } else {
                            log::error!("Failed to process MLS protocol message: {}", e);
                        }
                        vec![]
                    }
                }
            }
            MessageRoute::WelcomeFlow => {
                // Handle MLS Welcome flow messages (invites, welcomes, join requests)
                match self.handle_welcome_flow_message(&incoming.envelope).await {
                    Ok(notifications) => notifications,
                    Err(e) => {
                        log::error!("Failed to process Welcome flow message: {}", e);
                        vec![]
                    }
                }
            }
            MessageRoute::Group => {
                // Handle group server responses (fetchGroupResponse, etc.) with epoch-aware buffering
                match self.handle_group_response(&incoming.envelope, &mut mls_manager).await {
                    Ok(messages) => messages,
                    Err(e) => {
                        log::error!("Failed to process group response: {}", e);
                        vec![]
                    }
                }
            }
            _ => {
                log::debug!("Unhandled message route: {:?}", route);
                vec![]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{EncryptedMessage, MlsMessageType};
    use serde_json::json;

    #[test]
    fn test_normalize_conversation_id_alphabetical_order() {
        // When user1 < user2, should be "user1-user2"
        assert_eq!(normalize_conversation_id("alice", "bob"), "alice-bob");
    }

    #[test]
    fn test_normalize_conversation_id_reverse_order() {
        // When user1 > user2, should still be "alice-bob" (normalized)
        assert_eq!(normalize_conversation_id("bob", "alice"), "alice-bob");
    }

    #[test]
    fn test_normalize_conversation_id_same_both_ways() {
        // Both orderings should produce the same result
        let id1 = normalize_conversation_id("alice", "bob");
        let id2 = normalize_conversation_id("bob", "alice");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_normalize_conversation_id_same_user() {
        // Edge case: same user on both sides
        assert_eq!(normalize_conversation_id("alice", "alice"), "alice-alice");
    }

    #[test]
    fn test_crypto_struct_creation() {
        let crypto = Crypto;
        assert!(matches!(crypto, Crypto));
    }

    #[test]
    fn test_encrypted_message_serialization() {
        let encrypted = EncryptedMessage {
            conversation_id: b"test_conversation".to_vec(),
            mls_message: b"test_mls_message".to_vec(),
            message_type: MlsMessageType::Application,
        };

        let serialized = serde_json::to_string(&encrypted).unwrap();
        assert!(serialized.contains("conversation_id"));
        assert!(serialized.contains("mls_message"));
        assert!(serialized.contains("Application"));
    }

    #[test]
    fn test_encrypted_message_deserialization() {
        let json = r#"{"conversation_id":[116,101,115,116],"mls_message":[116,101,115,116],"message_type":"Application"}"#;
        let encrypted: EncryptedMessage = serde_json::from_str(json).unwrap();

        assert_eq!(encrypted.conversation_id, b"test");
        assert_eq!(encrypted.mls_message, b"test");
        assert!(matches!(encrypted.message_type, MlsMessageType::Application));
    }


    #[tokio::test]
    async fn test_json_parsing_for_registration() {
        let json = r#"{"nonce":"test_nonce_123"}"#;
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        let nonce = v.get("nonce").and_then(|n| n.as_str());
        assert_eq!(nonce, Some("test_nonce_123"));
    }

    #[tokio::test]
    async fn test_json_parsing_for_query_response() {
        let json = r#"{"username":"alice","publicKey":"pk_alice"}"#;
        let v: serde_json::Value = serde_json::from_str(json).unwrap();

        let username = v.get("username").and_then(|u| u.as_str());
        let public_key = v.get("publicKey").and_then(|k| k.as_str());

        assert_eq!(username, Some("alice"));
        assert_eq!(public_key, Some("pk_alice"));
    }

    #[tokio::test]
    async fn test_message_payload_construction() {
        let payload = json!({
            "type": 0,
            "message": "hello world"
        });

        let payload_str = payload.to_string();
        assert!(payload_str.contains("\"type\":0"));
        assert!(payload_str.contains("hello world"));
    }

    #[tokio::test]
    async fn test_encrypted_body_construction() {
        let encrypted_body = json!({
            "iv": "test_iv",
            "ciphertext": "test_ciphertext",
            "tag": "test_tag"
        });

        assert_eq!(encrypted_body["iv"], "test_iv");
        assert_eq!(encrypted_body["ciphertext"], "test_ciphertext");
        assert_eq!(encrypted_body["tag"], "test_tag");
    }

    #[tokio::test]
    async fn test_nested_payload_construction() {
        let encrypted_body = json!({
            "iv": "test_iv",
            "ciphertext": "test_ciphertext",
            "tag": "test_tag"
        });

        let nested = json!({
            "ephemeralPublicKey": "test_ephemeral_pk",
            "salt": "test_salt",
            "encryptedBody": encrypted_body
        });

        assert_eq!(nested["ephemeralPublicKey"], "test_ephemeral_pk");
        assert_eq!(nested["salt"], "test_salt");
        assert_eq!(nested["encryptedBody"]["iv"], "test_iv");
    }

    #[tokio::test]
    async fn test_full_message_payload_construction() {
        let body = json!({
            "encryptedPayload": {
                "ephemeralPublicKey": "test_pk",
                "salt": "test_salt",
                "encryptedBody": {
                    "iv": "test_iv",
                    "ciphertext": "test_ciphertext",
                    "tag": "test_tag"
                }
            },
            "payloadSignature": "test_signature"
        });

        let payload = json!({
            "sender": "alice",
            "recipient": "bob",
            "body": body,
            "encrypted": true
        });

        assert_eq!(payload["sender"], "alice");
        assert_eq!(payload["recipient"], "bob");
        assert_eq!(payload["encrypted"], true);
        assert_eq!(payload["body"]["payloadSignature"], "test_signature");
    }

    #[tokio::test]
    async fn test_handshake_message_construction() {
        let handshake = json!({
            "type": 1,
            "message": "nym_address_123"
        });

        assert_eq!(handshake["type"], 1);
        assert_eq!(handshake["message"], "nym_address_123");
    }

    #[tokio::test]
    async fn test_group_message_format() {
        let group_msg = json!({
            "action": "sendGroup",
            "ciphertext": "encrypted_group_message"
        });

        assert_eq!(group_msg["action"], "sendGroup");
        assert_eq!(group_msg["ciphertext"], "encrypted_group_message");
    }

    #[tokio::test]
    async fn test_group_registration_format() {
        let register_msg = json!({
            "action": "register",
            "username": "test_user",
            "publicKey": "test_public_key",
            "signature": "test_signature"
        });

        assert_eq!(register_msg["action"], "register");
        assert_eq!(register_msg["username"], "test_user");
        assert_eq!(register_msg["publicKey"], "test_public_key");
        assert_eq!(register_msg["signature"], "test_signature");
    }

    #[tokio::test]
    async fn test_group_connect_format() {
        let connect_msg = json!({
            "action": "connect",
            "username": "test_user",
            "signature": "test_signature"
        });

        assert_eq!(connect_msg["action"], "connect");
        assert_eq!(connect_msg["username"], "test_user");
        assert_eq!(connect_msg["signature"], "test_signature");
    }

    #[tokio::test]
    async fn test_envelope_parsing() {
        let envelope_json = r#"{"action":"incomingMessage","context":"chat","content":"{\"sender\":\"alice\",\"encrypted\":true}"}"#;
        let envelope: serde_json::Value = serde_json::from_str(envelope_json).unwrap();

        assert_eq!(envelope["action"], "incomingMessage");
        assert_eq!(envelope["context"], "chat");

        let content = envelope["content"].as_str().unwrap();
        let content_parsed: serde_json::Value = serde_json::from_str(content).unwrap();
        assert_eq!(content_parsed["sender"], "alice");
        assert_eq!(content_parsed["encrypted"], true);
    }

    #[tokio::test]
    async fn test_message_validation() {
        let valid_msg = json!({
            "sender": "alice",
            "recipient": "bob",
            "body": {
                "encryptedPayload": {},
                "payloadSignature": "sig"
            },
            "encrypted": true
        });

        assert!(valid_msg["sender"].is_string());
        assert!(valid_msg["recipient"].is_string());
        assert!(valid_msg["body"].is_object());
        assert!(valid_msg["encrypted"].is_boolean());
    }

    #[tokio::test]
    async fn test_signature_verification_data_format() {
        let _data_to_sign = "test data for signature verification";
        let signature_hex = "deadbeef";

        let sig_bytes = hex::decode(signature_hex);
        assert!(sig_bytes.is_ok());

        let decoded = sig_bytes.unwrap();
        assert_eq!(decoded, vec![0xde, 0xad, 0xbe, 0xef]);
    }
}
