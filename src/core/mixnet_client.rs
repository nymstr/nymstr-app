//! Mixnet service: wraps nym-sdk client, crypto, and persistence
#![allow(dead_code)]
use crate::core::{db::Db, messages::MixnetMessage};
use crate::crypto::Crypto;
use anyhow::{Context, Result};
use chrono::Utc;
use log::info;
use nym_sdk::mixnet::{
    IncludedSurbs, MixnetClient, MixnetClientBuilder, MixnetClientSender, MixnetMessageSender,
    Recipient,
};
use serde_json;
use std::{collections::HashMap, env, sync::Arc};
use tokio::sync::{Mutex, mpsc};
use tokio_stream::StreamExt;

/// Incoming envelope from mixnet (server or peer)
pub struct Incoming {
    /// Decoded mixnet envelope
    pub envelope: MixnetMessage,
    /// Timestamp when received
    pub ts: chrono::DateTime<Utc>,
}

/// Service holding client, crypto, and DB
pub struct MixnetService {
    client: Arc<Mutex<Option<MixnetClient>>>,
    sender: MixnetClientSender,
    pub crypto: Crypto,
    pub db: Arc<Db>,
    nym_addresses: Arc<Mutex<HashMap<String, String>>>,
    /// Our own Nym address
    our_address: String,
}

impl MixnetService {
    /// Create new service: opens DB, connects client, and spawns receive loop
    pub async fn new(db_path: &str) -> Result<(Self, mpsc::Receiver<Incoming>)> {
        // open database
        let db = Arc::new(Db::open(db_path).await?);
        db.init_global().await?;
        // connect mixnet client
        info!("Building ephemeral mixnet client...");
        let client = MixnetClientBuilder::new_ephemeral()
            .build()
            .context("Failed to build mixnet client")?;
        info!("Connecting to mixnet gateway...");
        let client = client
            .connect_to_mixnet()
            .await
            .context("Failed to connect to mixnet")?;
        let address = client.nym_address().to_string();
        info!("Connected to mixnet; address: {}", address);
        let sender = client.split_sender();
        // wrap client in a mutex for shared access
        let client = Arc::new(Mutex::new(Some(client)));
        let service = Self {
            client: client.clone(),
            sender,
            crypto: Crypto,
            db: db.clone(),
            nym_addresses: Arc::new(Mutex::new(HashMap::new())),
            our_address: address,
        };
        // channel for incoming messages
        let (tx, rx) = mpsc::channel(100);
        // spawn receive loop: forward all envelopes to channel
        {
            let client_ref = client.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut lock = client_ref.lock().await;
                if let Some(client) = lock.as_mut() {
                    while let Some(frame) = client.next().await {
                        log::info!("Received raw message: {} bytes", frame.message.len());

                        if let Ok(text) = String::from_utf8(frame.message.clone()) {
                            log::info!("Parsed message text: {}", text);

                            if let Ok(env) = serde_json::from_str::<MixnetMessage>(&text) {
                                log::info!("Successfully parsed message - type: '{}', action: '{}'", env.message_type, env.action);

                                let incoming = Incoming {
                                    envelope: env,
                                    ts: Utc::now(),
                                };
                                if tx.send(incoming).await.is_err() {
                                    log::error!("Failed to send incoming message to channel");
                                    break;
                                }
                            } else {
                                log::error!("Failed to parse JSON message: {}", text);
                            }
                        } else {
                            log::error!("Failed to parse message as UTF-8");
                        }
                    }
                }
            });
        }
        Ok((service, rx))
    }

    /// Register a new user: generate keys, send registration envelope
    pub async fn register(&self, username: &str) -> Result<()> {
        // generate a new PGP keypair for user registration
        let (_secret_key, public_key) = Crypto::generate_pgp_keypair(username)
            .context("PGP key generation failed")?;
        let public_pem = Crypto::pgp_public_key_armored(&public_key)
            .context("Failed to get armored public key")?;
        // public_pem is already armored PGP public key
        let public_key_str = public_pem.clone();
        // store user in database
        self.db.register_user(username, &public_key_str).await?;
        // build registration envelope
        let env = MixnetMessage::register(username, &public_key_str);
        let inner = env.to_json()?;
        let raw_bytes = inner.into_bytes();
        // send via mixnet to server
        let server_addr = env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
        let recipient: Recipient = server_addr.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        Ok(())
    }

    /// Login existing user: load keys, send login envelope
    pub async fn login(&self, username: &str) -> Result<()> {
        // build login envelope
        let env = MixnetMessage::login(username);
        let inner = env.to_json()?;
        let raw_bytes = inner.into_bytes();
        // send via mixnet to server
        let server_addr = env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
        let recipient: Recipient = server_addr.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        Ok(())
    }

    /// Query for a user's public key via the server
    pub async fn query_user(&self, username: &str) -> Result<Option<(String, String)>> {
        // lookup in local DB
        Ok(self.db.get_user(username).await?)
    }

    /// Send a message via the central server with content and signature
    pub async fn send_message(&self, _to: &str, content: &str, signature: &str) -> Result<()> {
        // Build the envelope exactly as in the Python client
        let current_user = std::env::var("USER").unwrap_or_else(|_| "client".to_string());
        let envelope = MixnetMessage::send(&current_user, _to, content, "conversation_id", signature);
        let payload = envelope.to_json()?;
        let raw_bytes = payload.into_bytes();

        // Send those raw JSON bytes directly to the server
        let server_addr: String =
            std::env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
        let recipient: Recipient = server_addr.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;

        Ok(())
    }

    /// Send a p2p direct chat message with content and signature
    pub async fn send_direct_message(
        &self,
        to: &str,
        content: &str,
        signature: &str,
    ) -> Result<()> {
        // Build the direct message envelope as expected by receiving clients
        let current_user = std::env::var("USER").unwrap_or_else(|_| "client".to_string());
        let env = MixnetMessage::direct_message(&current_user, to, content, "conversation_id", signature);
        let payload = env.to_json()?;
        let raw_bytes = payload.into_bytes();
        // Determine recipient: direct address if known, else central server
        let recipient = if let Some(addr) = self.nym_addresses.lock().await.get(to) {
            addr.parse()? // direct P2P address
        } else {
            let server_addr = env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
            server_addr.parse()? // fallback to central server
        };
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        Ok(())
    }

    /// Send handshake (type=1) to establish anonymous replies
    pub async fn send_handshake(&self, _to: &str) -> Result<()> {
        // send a handshake via server (stub)
        let current_user = std::env::var("USER").unwrap_or_else(|_| "client".to_string());
        let env = MixnetMessage::send(&current_user, _to, "handshake", "handshake_conv", "");
        let inner = env.to_json()?;
        let raw_bytes = inner.into_bytes();
        let server_addr = env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
        let recipient: Recipient = server_addr.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        Ok(())
    }
    /// Send a registration request with username and public key
    pub async fn send_registration_request(&self, username: &str, public_key: &str) -> Result<()> {
        let env = MixnetMessage::register(username, public_key);
        // Note: Signature should be set by caller using proper crypto
        let inner = env.to_json()?;
        let raw_bytes = inner.into_bytes();
        let server_addr = env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
        let recipient: Recipient = server_addr.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        Ok(())
    }
    /// Send registration challenge response
    pub async fn send_registration_response(&self, username: &str, signature: &str) -> Result<()> {
        let env = MixnetMessage::challenge_response(username, "server", signature, "registration");
        let inner = env.to_json()?;
        let raw_bytes = inner.into_bytes();
        let server_addr = env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
        let recipient: Recipient = server_addr.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        Ok(())
    }
    /// Send a login request for a username
    pub async fn send_login_request(&self, username: &str) -> Result<()> {
        let env = MixnetMessage::login(username);
        // Note: Signature should be set by caller using proper crypto
        let inner = env.to_json()?;
        let raw_bytes = inner.into_bytes();
        let server_addr = env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
        let recipient: Recipient = server_addr.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        Ok(())
    }
    /// Send login challenge response
    pub async fn send_login_response(&self, username: &str, signature: &str) -> Result<()> {
        let env = MixnetMessage::challenge_response(username, "server", signature, "login");
        let inner = env.to_json()?;
        let raw_bytes = inner.into_bytes();
        let server_addr = env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
        let recipient: Recipient = server_addr.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        Ok(())
    }
    /// Send a query request for a user's public key
    pub async fn send_query_request(&self, username: &str) -> Result<()> {
        let current_user = std::env::var("USER").unwrap_or_else(|_| "client".to_string());
        let env = MixnetMessage::query(&current_user, username);
        // Note: Signature should be set by caller using proper crypto
        let inner = env.to_json()?;
        let raw_bytes = inner.into_bytes();
        let server_addr = env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
        let recipient: Recipient = server_addr.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        Ok(())
    }

    /// Send a group message to group server
    pub async fn send_group_message(&self, _ciphertext: &str, _group_server_address: &str) -> Result<()> {
        // TODO: Group functionality needs to be redesigned for unified format
        Err(anyhow::anyhow!("Group messaging not yet implemented in unified format"))
    }

    /// Get fanout queue statistics from group server
    pub async fn get_group_stats(&self, _group_server_address: &str) -> Result<()> {
        // This functionality needs to be redesigned for the unified format
        Err(anyhow::anyhow!("get_stats not yet implemented in unified format"))
    }

    /// Send a message via the discovery server for routing
    pub async fn send_message_via_server(
        &self,
        sender: &str,
        recipient: &str,
        content: &str,
        signature: &str,
    ) -> Result<()> {
        let env = MixnetMessage::send_via_server(sender, recipient, content, signature);
        let payload = env.to_json()?;
        log::info!("Sending message via server - payload: {}", payload);
        let raw_bytes = payload.into_bytes();
        let server_addr = env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
        log::info!("Using SERVER_ADDRESS: {}", server_addr);
        let recipient: Recipient = server_addr.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        log::info!("Message sent to server successfully");
        Ok(())
    }

    /// Send MLS encrypted message using unified format
    pub async fn send_mls_message(
        &self,
        sender: &str,
        recipient: &str,
        encrypted_message: &crate::crypto::EncryptedMessage,
        signature: &str,
    ) -> Result<()> {
        let env = MixnetMessage::mls_message(sender, recipient, encrypted_message, signature);
        let payload = env.to_json()?;
        log::info!("Sending MLS message via server - payload: {}", payload);
        let raw_bytes = payload.into_bytes();
        let server_addr = env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
        log::info!("Using SERVER_ADDRESS: {}", server_addr);
        let recipient: Recipient = server_addr.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        log::info!("MLS message sent to server successfully");
        Ok(())
    }

    /// Send key package request for MLS handshake
    pub async fn send_key_package_request(
        &self,
        sender: &str,
        recipient: &str,
        sender_key_package: &str,
        signature: &str,
    ) -> Result<()> {
        let env = MixnetMessage::key_package_request(sender, recipient, sender_key_package, signature);
        let payload = env.to_json()?;
        log::info!("Sending key package request to {} via server", recipient);
        let raw_bytes = payload.into_bytes();
        let server_addr = env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
        let recipient: Recipient = server_addr.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        log::info!("Key package request sent successfully");
        Ok(())
    }

    /// Send key package response for MLS handshake
    pub async fn send_key_package_response(
        &self,
        sender: &str,
        recipient: &str,
        sender_key_package: &str,
        recipient_key_package: &str,
        signature: &str,
    ) -> Result<()> {
        let env = MixnetMessage::key_package_response(sender, recipient, sender_key_package, recipient_key_package, signature);
        let payload = env.to_json()?;
        log::info!("Sending key package response to {} via server", recipient);
        let raw_bytes = payload.into_bytes();
        let server_addr = env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
        let recipient: Recipient = server_addr.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        log::info!("Key package response sent successfully");
        Ok(())
    }

    /// Send group welcome message for MLS handshake
    pub async fn send_group_welcome(
        &self,
        sender: &str,
        recipient: &str,
        welcome_message: &str,
        group_id: &str,
        signature: &str,
    ) -> Result<()> {
        let env = MixnetMessage::group_welcome(sender, recipient, welcome_message, group_id, signature);
        let payload = env.to_json()?;
        log::info!("Sending group welcome to {} via server", recipient);
        let raw_bytes = payload.into_bytes();
        let server_addr = env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
        let recipient: Recipient = server_addr.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        log::info!("Group welcome sent successfully");
        Ok(())
    }

    /// Send group join response for MLS handshake
    pub async fn send_group_join_response(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        success: bool,
        signature: &str,
    ) -> Result<()> {
        let env = MixnetMessage::group_join_response(sender, recipient, group_id, success, signature);
        let payload = env.to_json()?;
        log::info!("Sending group join response to {} via server", recipient);
        let raw_bytes = payload.into_bytes();
        let server_addr = env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
        let recipient: Recipient = server_addr.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        log::info!("Group join response sent successfully");
        Ok(())
    }

    /// Get our own Nym address
    pub fn get_nym_address(&self) -> &str {
        &self.our_address
    }
}

// Allow cloning service for spawn
impl Clone for MixnetService {
    fn clone(&self) -> Self {
        Self {
            client: Arc::clone(&self.client),
            sender: self.sender.clone(),
            crypto: Crypto,
            db: self.db.clone(),
            nym_addresses: Arc::clone(&self.nym_addresses),
            our_address: self.our_address.clone(),
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
// 
//     #[test]
//     fn test_incoming_struct_creation() {
//         let msg = MixnetMessage::query("test_user");
//         let incoming = Incoming {
//             envelope: msg,
//             ts: Utc::now(),
//         };
//         
//         assert_eq!(incoming.envelope.action, "query");
//         assert_eq!(incoming.envelope.username, Some("test_user".to_string()));
//     }
// 
//     #[test]
//     fn test_crypto_struct_instantiation() {
//         let crypto = Crypto;
//         assert!(matches!(crypto, Crypto));
//     }
// 
//     #[tokio::test]
//     async fn test_message_envelope_json_serialization() {
//         let env = MixnetMessage::register("test_user", "test_public_key");
//         let json = env.to_json().unwrap();
//         let raw_bytes = json.into_bytes();
//         
//         assert!(!raw_bytes.is_empty());
//         
//         let restored = String::from_utf8(raw_bytes).unwrap();
//         assert!(restored.contains("\"action\":\"register\""));
//         assert!(restored.contains("\"username\":\"test_user\""));
//         assert!(restored.contains("\"publicKey\":\"test_public_key\""));
//     }
// 
//     #[tokio::test]
//     async fn test_login_envelope_creation() {
//         let env = MixnetMessage::login("test_user");
//         let json = env.to_json().unwrap();
//         
//         assert!(json.contains("\"action\":\"login\""));
//         assert!(json.contains("\"username\":\"test_user\""));
//     }
// 
//     #[tokio::test]
//     async fn test_query_envelope_creation() {
//         let env = MixnetMessage::query("target_user");
//         let json = env.to_json().unwrap();
//         
//         assert!(json.contains("\"action\":\"query\""));
//         assert!(json.contains("\"username\":\"target_user\""));
//     }
// 
//     #[tokio::test]
//     async fn test_send_message_envelope_creation() {
//         let env = MixnetMessage::send("test_content", "test_signature");
//         let json = env.to_json().unwrap();
//         
//         assert!(json.contains("\"action\":\"send\""));
//         assert!(json.contains("\"content\":\"test_content\""));
//         assert!(json.contains("\"signature\":\"test_signature\""));
//     }
// 
//     #[tokio::test]
//     async fn test_direct_message_envelope_creation() {
//         let env = MixnetMessage::direct_message("direct_content", "direct_signature");
//         let json = env.to_json().unwrap();
//         
//         assert!(json.contains("\"action\":\"incomingMessage\""));
//         assert!(json.contains("\"content\":\"direct_content\""));
//         assert!(json.contains("\"context\":\"chat\""));
//         assert!(json.contains("\"signature\":\"direct_signature\""));
//     }
// 
//     #[tokio::test]
//     async fn test_group_message_envelope_creation() {
//         let env = MixnetMessage::send_group("encrypted_group_content");
//         let json = env.to_json().unwrap();
//         
//         assert!(json.contains("\"action\":\"sendGroup\""));
//         assert!(json.contains("\"ciphertext\":\"encrypted_group_content\""));
//     }
// 
//     #[tokio::test]
//     async fn test_registration_response_envelope_creation() {
//         let env = MixnetMessage::registration_response("user", "reg_sig");
//         let json = env.to_json().unwrap();
//         
//         assert!(json.contains("\"action\":\"registrationResponse\""));
//         assert!(json.contains("\"username\":\"user\""));
//         assert!(json.contains("\"signature\":\"reg_sig\""));
//     }
// 
//     #[tokio::test]
//     async fn test_login_response_envelope_creation() {
//         let env = MixnetMessage::login_response("user", "login_sig");
//         let json = env.to_json().unwrap();
//         
//         assert!(json.contains("\"action\":\"loginResponse\""));
//         assert!(json.contains("\"username\":\"user\""));
//         assert!(json.contains("\"signature\":\"login_sig\""));
//     }
// 
// 
//     #[tokio::test]
//     async fn test_connect_group_envelope_creation() {
//         let env = MixnetMessage::connect_group("group_user", "group_sig");
//         let json = env.to_json().unwrap();
//         
//         assert!(json.contains("\"action\":\"connect\""));
//         assert!(json.contains("\"username\":\"group_user\""));
//         assert!(json.contains("\"signature\":\"group_sig\""));
//     }
// 
//     #[tokio::test]
//     async fn test_register_group_envelope_creation() {
//         let env = MixnetMessage::register_group("reg_user", "reg_pk", "reg_sig");
//         let json = env.to_json().unwrap();
//         
//         assert!(json.contains("\"action\":\"register\""));
//         assert!(json.contains("\"username\":\"reg_user\""));
//         assert!(json.contains("\"publicKey\":\"reg_pk\""));
//         assert!(json.contains("\"signature\":\"reg_sig\""));
//     }
// 
//     #[tokio::test]
//     async fn test_envelope_deserialization() {
//         let json = r#"{"action":"query","username":"test_user"}"#;
//         let envelope: MixnetMessage = serde_json::from_str(json).unwrap();
//         
//         assert_eq!(envelope.action, "query");
//         assert_eq!(envelope.username, Some("test_user".to_string()));
//     }
// 
//     #[tokio::test]
//     async fn test_incoming_message_parsing() {
//         let json = r#"{"action":"incomingMessage","context":"chat","content":"hello"}"#;
//         let envelope: MixnetMessage = serde_json::from_str(json).unwrap();
//         
//         assert_eq!(envelope.action, "incomingMessage");
//         assert_eq!(envelope.context, Some("chat".to_string()));
//         assert_eq!(envelope.content, Some("hello".to_string()));
//     }
// 
//     #[tokio::test]
//     async fn test_environment_variable_parsing() {
//         // Test that environment variable parsing would work
//         let test_addr = "test.address.example";
//         unsafe {
//             std::env::set_var("TEST_SERVER_ADDRESS", test_addr);
//         }
//         
//         let addr = std::env::var("TEST_SERVER_ADDRESS").unwrap();
//         assert_eq!(addr, test_addr);
//         
//         // Clean up
//         unsafe {
//             std::env::remove_var("TEST_SERVER_ADDRESS");
//         }
//     }
// 
//     #[tokio::test]
//     async fn test_message_byte_conversion() {
//         let env = MixnetMessage::send("test message", "test sig");
//         let json = env.to_json().unwrap();
//         let bytes = json.into_bytes();
//         
//         assert!(!bytes.is_empty());
//         
//         let restored = String::from_utf8(bytes).unwrap();
//         let restored_env: MixnetMessage = serde_json::from_str(&restored).unwrap();
//         
//         assert_eq!(restored_env.action, "send");
//         assert_eq!(restored_env.content, Some("test message".to_string()));
//         assert_eq!(restored_env.signature, Some("test sig".to_string()));
//     }
// 
//     #[tokio::test]
//     async fn test_handshake_message_format() {
//         let env = MixnetMessage::send("handshake", "");
//         let json = env.to_json().unwrap();
//         
//         assert!(json.contains("\"action\":\"send\""));
//         assert!(json.contains("\"content\":\"handshake\""));
//     }
// 
//     #[tokio::test]
//     async fn test_large_message_handling() {
//         let large_content = "x".repeat(1000);
//         let env = MixnetMessage::send(&large_content, "sig");
//         let json = env.to_json().unwrap();
//         let bytes = json.into_bytes();
//         
//         assert!(bytes.len() > 1000);
//         
//         let restored = String::from_utf8(bytes).unwrap();
//         let restored_env: MixnetMessage = serde_json::from_str(&restored).unwrap();
//         
//         assert_eq!(restored_env.content, Some(large_content));
//     }
// 
//     #[tokio::test]
//     async fn test_unicode_message_handling() {
//         let unicode_content = "Hello 🌍 世界 🦀";
//         let env = MixnetMessage::send(unicode_content, "sig");
//         let json = env.to_json().unwrap();
//         let bytes = json.into_bytes();
//         
//         let restored = String::from_utf8(bytes).unwrap();
//         let restored_env: MixnetMessage = serde_json::from_str(&restored).unwrap();
//         
//         assert_eq!(restored_env.content, Some(unicode_content.to_string()));
//     }
// 
//     #[tokio::test] 
//     async fn test_empty_content_handling() {
//         let env = MixnetMessage::send("", "empty_sig");
//         let json = env.to_json().unwrap();
//         
//         assert!(json.contains("\"content\":\"\""));
//         assert!(json.contains("\"signature\":\"empty_sig\""));
//     }
// 
//     #[tokio::test]
//     async fn test_message_validation() {
//         let env = MixnetMessage::query("valid_user");
//         assert_eq!(env.action, "query");
//         assert!(env.username.is_some());
//         
//         let env2 = MixnetMessage::register("user", "pk");
//         assert_eq!(env2.action, "register");
//         assert!(env2.username.is_some());
//         // assert!(env2.public_key.is_some());
//     // }
// }
