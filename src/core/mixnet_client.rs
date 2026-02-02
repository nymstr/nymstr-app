//! Mixnet service: wraps nym-sdk client, crypto, and persistence
#![allow(dead_code)]
use crate::core::{db::Db, messages::MixnetMessage};
use crate::crypto::mls::types::MlsWelcome;
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
use tokio::sync::{mpsc, Mutex};
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
                                log::info!(
                                    "Successfully parsed message - type: '{}', action: '{}'",
                                    env.message_type,
                                    env.action
                                );

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
        self.db.get_user(username).await
    }

    /// Send a message via the central server with content and signature
    pub async fn send_message(&self, _to: &str, content: &str, signature: &str) -> Result<()> {
        // Build the envelope exactly as in the Python client
        let current_user = std::env::var("USER").unwrap_or_else(|_| "client".to_string());
        let envelope =
            MixnetMessage::send(&current_user, _to, content, "conversation_id", signature);
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
        let env =
            MixnetMessage::direct_message(&current_user, to, content, "conversation_id", signature);
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
    pub async fn send_group_message(
        &self,
        sender: &str,
        ciphertext: &str,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        let env = MixnetMessage::send_group(sender, ciphertext, signature);
        let payload = env.to_json()?;
        log::info!("Sending group message to {}", group_server_address);
        let raw_bytes = payload.into_bytes();
        let recipient: Recipient = group_server_address.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        log::info!("Group message sent successfully");
        Ok(())
    }

    /// Register with a group server using timestamp-based authentication
    /// Signature is over: "register:{username}:{server_address}:{timestamp}"
    pub async fn register_with_group_server(
        &self,
        username: &str,
        public_key: &str,
        signature: &str,
        timestamp: i64,
        group_server_address: &str,
    ) -> Result<()> {
        let env = MixnetMessage::register_with_group_server(
            username,
            public_key,
            signature,
            timestamp,
            group_server_address,
        );
        let payload = env.to_json()?;
        log::info!("Registering with group server {}", group_server_address);
        let raw_bytes = payload.into_bytes();
        let recipient: Recipient = group_server_address.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        log::info!("Group registration request sent");
        Ok(())
    }

    /// Approve a pending group member (admin only)
    pub async fn approve_group_member(
        &self,
        admin: &str,
        username_to_approve: &str,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        let env = MixnetMessage::approve_group_member(admin, username_to_approve, signature);
        let payload = env.to_json()?;
        log::info!(
            "Approving group member {} on server {}",
            username_to_approve,
            group_server_address
        );
        let raw_bytes = payload.into_bytes();
        let recipient: Recipient = group_server_address.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        log::info!("Group approval request sent");
        Ok(())
    }

    /// Fetch group messages from group server since last_seen_id
    pub async fn send_group_fetch_request(
        &self,
        sender: &str,
        last_seen_id: i64,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        let env = MixnetMessage::fetch_group(sender, last_seen_id, signature);
        let payload = env.to_json()?;
        log::info!("Sending fetchGroup request - lastSeenId: {}", last_seen_id);
        let raw_bytes = payload.into_bytes();
        let recipient: Recipient = group_server_address.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        log::info!("fetchGroup request sent successfully");
        Ok(())
    }

    /// Get fanout queue statistics from group server
    pub async fn get_group_stats(&self, _group_server_address: &str) -> Result<()> {
        // This functionality needs to be redesigned for the unified format
        Err(anyhow::anyhow!(
            "get_stats not yet implemented in unified format"
        ))
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
        let env =
            MixnetMessage::key_package_request(sender, recipient, sender_key_package, signature);
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
        let env = MixnetMessage::key_package_response(
            sender,
            recipient,
            sender_key_package,
            recipient_key_package,
            signature,
        );
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
        let env =
            MixnetMessage::group_welcome(sender, recipient, welcome_message, group_id, signature);
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
        let env =
            MixnetMessage::group_join_response(sender, recipient, group_id, success, signature);
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

    // ========== Phase 3: Welcome Flow Methods ==========

    /// Send an MLS Welcome message to invite a user to a group
    ///
    /// This method sends a Welcome message that allows the recipient to join
    /// an MLS group. The Welcome contains all cryptographic material needed
    /// for the recipient to decrypt group messages.
    ///
    /// # Arguments
    /// * `sender` - The username of the group admin sending the welcome
    /// * `recipient` - The username of the user being invited
    /// * `welcome` - The MlsWelcome structure containing the welcome data
    /// * `signature` - PGP signature of the welcome for authenticity
    ///
    /// # Returns
    /// Ok(()) on successful transmission
    pub async fn send_mls_welcome(
        &self,
        sender: &str,
        recipient: &str,
        welcome: &MlsWelcome,
        signature: &str,
    ) -> Result<()> {
        let env = MixnetMessage::mls_welcome(sender, recipient, welcome, signature);
        let payload = env.to_json()?;
        log::info!(
            "Sending MLS welcome for group {} to {} via server",
            welcome.group_id,
            recipient
        );
        let raw_bytes = payload.into_bytes();
        let server_addr = env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
        let recipient_addr: Recipient = server_addr.parse()?;
        self.sender
            .send_message(recipient_addr, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        log::info!(
            "MLS welcome for group {} sent to {} successfully",
            welcome.group_id,
            recipient
        );
        Ok(())
    }

    /// Send a group join request with our KeyPackage
    ///
    /// This is sent when a user wants to join a group and provides their
    /// KeyPackage for the group admin to add them.
    ///
    /// # Arguments
    /// * `sender` - The username requesting to join
    /// * `group_id` - The group identifier
    /// * `key_package` - Base64-encoded KeyPackage
    /// * `signature` - PGP signature of the request
    pub async fn send_group_join_request(
        &self,
        sender: &str,
        group_id: &str,
        key_package: &str,
        signature: &str,
    ) -> Result<()> {
        let env = MixnetMessage::group_join_request(sender, group_id, key_package, signature);
        let payload = env.to_json()?;
        log::info!(
            "Sending group join request for group {} via server",
            group_id
        );
        let raw_bytes = payload.into_bytes();
        let server_addr = env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
        let recipient: Recipient = server_addr.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        log::info!("Group join request sent successfully");
        Ok(())
    }

    /// Send a Welcome acknowledgment after successfully joining a group
    ///
    /// # Arguments
    /// * `sender` - The user who joined
    /// * `recipient` - The group admin who sent the welcome
    /// * `group_id` - The group that was joined
    /// * `success` - Whether joining was successful
    /// * `signature` - PGP signature of the acknowledgment
    pub async fn send_welcome_ack(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        success: bool,
        signature: &str,
    ) -> Result<()> {
        let env = MixnetMessage::welcome_ack(sender, recipient, group_id, success, signature);
        let payload = env.to_json()?;
        log::info!(
            "Sending welcome ack for group {} to {} via server",
            group_id,
            recipient
        );
        let raw_bytes = payload.into_bytes();
        let server_addr = env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
        let recipient_addr: Recipient = server_addr.parse()?;
        self.sender
            .send_message(recipient_addr, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        log::info!("Welcome ack sent successfully");
        Ok(())
    }

    /// Send a group invite notification to a user
    ///
    /// # Arguments
    /// * `sender` - The group admin sending the invite
    /// * `recipient` - The user being invited
    /// * `group_id` - The group identifier
    /// * `group_name` - Optional human-readable group name
    /// * `signature` - PGP signature of the invite
    pub async fn send_group_invite(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        group_name: Option<&str>,
        signature: &str,
    ) -> Result<()> {
        let env = MixnetMessage::group_invite(sender, recipient, group_id, group_name, signature);
        let payload = env.to_json()?;
        log::info!(
            "Sending group invite for {} to {} via server",
            group_id,
            recipient
        );
        let raw_bytes = payload.into_bytes();
        let server_addr = env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
        let recipient_addr: Recipient = server_addr.parse()?;
        self.sender
            .send_message(recipient_addr, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        log::info!("Group invite sent successfully");
        Ok(())
    }

    /// Request a KeyPackage from a user for adding them to a group
    ///
    /// # Arguments
    /// * `sender` - The group admin requesting the KeyPackage
    /// * `recipient` - The user to request from
    /// * `group_id` - The group they'll be added to
    /// * `signature` - PGP signature of the request
    pub async fn send_key_package_for_group_request(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        signature: &str,
    ) -> Result<()> {
        let env = MixnetMessage::key_package_for_group(sender, recipient, group_id, signature);
        let payload = env.to_json()?;
        log::info!(
            "Requesting KeyPackage from {} for group {} via server",
            recipient,
            group_id
        );
        let raw_bytes = payload.into_bytes();
        let server_addr = env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
        let recipient_addr: Recipient = server_addr.parse()?;
        self.sender
            .send_message(recipient_addr, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        log::info!("KeyPackage request sent successfully");
        Ok(())
    }

    /// Send KeyPackage in response to a group join request
    ///
    /// # Arguments
    /// * `sender` - The user providing their KeyPackage
    /// * `recipient` - The group admin who requested it
    /// * `group_id` - The group to join
    /// * `key_package` - Base64-encoded KeyPackage
    /// * `signature` - PGP signature of the response
    pub async fn send_key_package_for_group_response(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        key_package: &str,
        signature: &str,
    ) -> Result<()> {
        let env = MixnetMessage::key_package_for_group_response(
            sender,
            recipient,
            group_id,
            key_package,
            signature,
        );
        let payload = env.to_json()?;
        log::info!(
            "Sending KeyPackage response to {} for group {} via server",
            recipient,
            group_id
        );
        let raw_bytes = payload.into_bytes();
        let server_addr = env::var("SERVER_ADDRESS").context("SERVER_ADDRESS must be set")?;
        let recipient_addr: Recipient = server_addr.parse()?;
        self.sender
            .send_message(recipient_addr, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        log::info!("KeyPackage response sent successfully");
        Ok(())
    }

    // ========== MLS Delivery Service Methods ==========

    /// Register with a group server, optionally including an MLS KeyPackage
    ///
    /// # Arguments
    /// * `username` - The user registering
    /// * `public_key` - The user's PGP public key (armored)
    /// * `signature` - PGP signature over "register:{username}:{server_address}:{timestamp}"
    /// * `timestamp` - Unix timestamp for replay protection
    /// * `group_server_address` - The group server's mixnet address
    /// * `key_package` - Optional base64-encoded MLS KeyPackage
    pub async fn register_with_group_server_and_key_package(
        &self,
        username: &str,
        public_key: &str,
        signature: &str,
        timestamp: i64,
        group_server_address: &str,
        key_package: Option<&str>,
    ) -> Result<()> {
        let env = MixnetMessage::register_with_group_server_and_key_package(
            username,
            public_key,
            signature,
            timestamp,
            group_server_address,
            key_package,
        );
        let payload = env.to_json()?;
        log::info!(
            "Registering with group server {} (with KeyPackage: {})",
            group_server_address,
            key_package.is_some()
        );
        let raw_bytes = payload.into_bytes();
        let recipient: Recipient = group_server_address.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        log::info!("Group registration request sent");
        Ok(())
    }

    /// Store a Welcome message on the group server for a user to fetch later
    ///
    /// # Arguments
    /// * `sender` - The admin/sender storing the welcome
    /// * `group_id` - The MLS group ID
    /// * `target_username` - The user who should receive the Welcome
    /// * `welcome` - Base64-encoded Welcome message
    /// * `signature` - PGP signature over "{group_id}:{target_username}"
    /// * `group_server_address` - The group server's mixnet address
    pub async fn store_welcome_on_server(
        &self,
        sender: &str,
        group_id: &str,
        target_username: &str,
        welcome: &str,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        let env =
            MixnetMessage::store_welcome(sender, group_id, target_username, welcome, signature);
        let payload = env.to_json()?;
        log::info!(
            "Storing Welcome for {} in group {} on server {}",
            target_username,
            group_id,
            group_server_address
        );
        let raw_bytes = payload.into_bytes();
        let recipient: Recipient = group_server_address.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        log::info!("Store Welcome request sent");
        Ok(())
    }

    /// Buffer a commit message on the group server for epoch synchronization
    ///
    /// This allows existing group members who missed the commit (e.g., due to being
    /// offline) to catch up on missed epoch transitions.
    ///
    /// # Arguments
    /// * `sender` - The user who created the commit (admin)
    /// * `group_id` - The MLS group ID (base64 encoded)
    /// * `epoch` - The epoch after applying this commit
    /// * `commit` - Base64-encoded commit message
    /// * `signature` - PGP signature over "{group_id}:{epoch}"
    /// * `group_server_address` - The group server's mixnet address
    pub async fn buffer_commit_on_server(
        &self,
        sender: &str,
        group_id: &str,
        epoch: i64,
        commit: &str,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        let env = MixnetMessage::buffer_commit(sender, group_id, epoch, commit, signature);
        let payload = env.to_json()?;
        log::info!(
            "Buffering commit for group {} at epoch {} on server {}",
            group_id,
            epoch,
            group_server_address
        );
        let raw_bytes = payload.into_bytes();
        let recipient: Recipient = group_server_address.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        log::info!("Buffer commit request sent");
        Ok(())
    }

    /// Fetch pending Welcome messages from the group server
    ///
    /// # Arguments
    /// * `username` - The user fetching their Welcomes
    /// * `group_id` - Optional group ID to filter by
    /// * `signature` - PGP signature over "fetchWelcome:{username}"
    /// * `group_server_address` - The group server's mixnet address
    pub async fn fetch_welcome_from_server(
        &self,
        username: &str,
        group_id: Option<&str>,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        let env = MixnetMessage::fetch_welcome(username, group_id, signature);
        let payload = env.to_json()?;
        log::info!(
            "Fetching Welcomes for {} from server {} (group filter: {:?})",
            username,
            group_server_address,
            group_id
        );
        let raw_bytes = payload.into_bytes();
        let recipient: Recipient = group_server_address.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        log::info!("Fetch Welcome request sent");
        Ok(())
    }

    /// Request epoch sync from the group server
    ///
    /// # Arguments
    /// * `username` - The user requesting sync
    /// * `group_id` - The MLS group ID
    /// * `since_epoch` - The epoch to sync from (exclusive)
    /// * `signature` - PGP signature over "{group_id}:{since_epoch}"
    /// * `group_server_address` - The group server's mixnet address
    pub async fn sync_epoch_from_server(
        &self,
        username: &str,
        group_id: &str,
        since_epoch: i64,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        let env = MixnetMessage::sync_epoch(username, group_id, since_epoch, signature);
        let payload = env.to_json()?;
        log::info!(
            "Requesting epoch sync for group {} since epoch {} from server {}",
            group_id,
            since_epoch,
            group_server_address
        );
        let raw_bytes = payload.into_bytes();
        let recipient: Recipient = group_server_address.parse()?;
        self.sender
            .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
            .await?;
        log::info!("Sync epoch request sent");
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
