//! Mixnet service: wraps nym-sdk client for anonymous messaging
//!
//! This module provides the MixnetService which handles all communication
//! over the Nym mixnet. It wraps the nym-sdk client and provides high-level
//! methods for sending and receiving messages.
#![allow(dead_code)]

use crate::core::messages::MixnetMessage;
use anyhow::{Context, Result};
use chrono::Utc;
use log::info;
use nym_sdk::mixnet::{
    IncludedSurbs, MixnetClient, MixnetClientBuilder, MixnetClientSender, MixnetMessageSender,
    Recipient, StoragePaths,
};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio_stream::StreamExt;

/// Incoming envelope from mixnet (server or peer)
#[derive(Debug)]
pub struct Incoming {
    /// Decoded mixnet envelope
    pub envelope: MixnetMessage,
    /// Timestamp when received
    pub ts: chrono::DateTime<Utc>,
}

/// Configuration for the MixnetService
#[derive(Debug, Clone)]
pub struct MixnetConfig {
    /// Storage path for nym client state (None for ephemeral)
    pub storage_path: Option<PathBuf>,
    /// Server address to use for authentication and routing
    pub server_address: Option<String>,
}

impl Default for MixnetConfig {
    fn default() -> Self {
        Self {
            storage_path: None,
            server_address: None,
        }
    }
}

/// Service holding the mixnet client and related state
pub struct MixnetService {
    /// The actual mixnet client (wrapped in mutex for shared access)
    client: Arc<Mutex<Option<MixnetClient>>>,
    /// Sender half of the client for sending messages
    sender: MixnetClientSender,
    /// Cache of known nym addresses for direct P2P messaging
    nym_addresses: Arc<RwLock<HashMap<String, String>>>,
    /// Our own Nym address
    our_address: String,
    /// Server address for routing through discovery node
    server_address: Arc<RwLock<Option<String>>>,
}

impl MixnetService {
    /// Create a new ephemeral MixnetService and connect to the mixnet
    ///
    /// Returns the service and a receiver channel for incoming messages.
    pub async fn new_ephemeral() -> Result<(Self, mpsc::Receiver<Incoming>)> {
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
        let client = Arc::new(Mutex::new(Some(client)));

        let service = Self {
            client: client.clone(),
            sender,
            nym_addresses: Arc::new(RwLock::new(HashMap::new())),
            our_address: address,
            server_address: Arc::new(RwLock::new(None)),
        };

        // Channel for incoming messages
        let (tx, rx) = mpsc::channel(100);

        // Spawn receive loop: forward all envelopes to channel
        {
            let client_ref = client.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut lock = client_ref.lock().await;
                if let Some(client) = lock.as_mut() {
                    while let Some(frame) = client.next().await {
                        log::info!("Received raw message: {} bytes", frame.message.len());

                        if let Ok(text) = String::from_utf8(frame.message.clone()) {
                            log::debug!("Parsed message text: {}", text);

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

    /// Create a new MixnetService with persistent storage and connect to the mixnet
    ///
    /// Returns the service and a receiver channel for incoming messages.
    pub async fn new_with_storage(storage_dir: PathBuf) -> Result<(Self, mpsc::Receiver<Incoming>)> {
        info!("Building mixnet client with storage at {:?}...", storage_dir);

        // Ensure storage directory exists
        std::fs::create_dir_all(&storage_dir)?;

        // Create StoragePaths from directory
        let storage_paths = StoragePaths::new_from_dir(&storage_dir)
            .context("Failed to create storage paths")?;

        let client = MixnetClientBuilder::new_with_default_storage(storage_paths)
            .await
            .context("Failed to create mixnet client builder")?
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
        let client = Arc::new(Mutex::new(Some(client)));

        let service = Self {
            client: client.clone(),
            sender,
            nym_addresses: Arc::new(RwLock::new(HashMap::new())),
            our_address: address,
            server_address: Arc::new(RwLock::new(None)),
        };

        // Channel for incoming messages
        let (tx, rx) = mpsc::channel(100);

        // Spawn receive loop
        {
            let client_ref = client.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut lock = client_ref.lock().await;
                if let Some(client) = lock.as_mut() {
                    while let Some(frame) = client.next().await {
                        log::info!("Received raw message: {} bytes", frame.message.len());

                        if let Ok(text) = String::from_utf8(frame.message.clone()) {
                            log::debug!("Parsed message text: {}", text);

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

    /// Get our own Nym address
    pub fn our_address(&self) -> &str {
        &self.our_address
    }

    /// Set the server address for routing
    pub async fn set_server_address(&self, address: Option<String>) {
        *self.server_address.write().await = address;
    }

    /// Get the current server address
    pub async fn get_server_address(&self) -> Option<String> {
        self.server_address.read().await.clone()
    }

    /// Register a known Nym address for a username (for direct P2P messaging)
    pub async fn register_peer_address(&self, username: &str, address: &str) {
        self.nym_addresses.write().await.insert(username.to_string(), address.to_string());
    }

    /// Get a peer's Nym address if known
    pub async fn get_peer_address(&self, username: &str) -> Option<String> {
        self.nym_addresses.read().await.get(username).cloned()
    }

    // ========== Low-Level Send Methods ==========

    /// Send raw bytes to a recipient address
    pub async fn send_raw(&self, recipient_address: &str, data: Vec<u8>) -> Result<()> {
        let recipient: Recipient = recipient_address.parse()?;
        self.sender
            .send_message(recipient, data, IncludedSurbs::Amount(10))
            .await?;
        Ok(())
    }

    /// Send a MixnetMessage to a recipient address
    pub async fn send_message_to(&self, recipient_address: &str, message: &MixnetMessage) -> Result<()> {
        let payload = message.to_json()?;
        let raw_bytes = payload.into_bytes();
        self.send_raw(recipient_address, raw_bytes).await
    }

    /// Send a MixnetMessage to the configured server
    pub async fn send_to_server(&self, message: &MixnetMessage) -> Result<()> {
        let server_addr = self.server_address.read().await
            .clone()
            .context("Server address not configured")?;
        self.send_message_to(&server_addr, message).await
    }

    // ========== Authentication Methods ==========

    /// Send a registration request with username and public key
    pub async fn send_registration_request(&self, username: &str, public_key: &str) -> Result<()> {
        let env = MixnetMessage::register(username, public_key);
        self.send_to_server(&env).await
    }

    /// Send registration challenge response
    pub async fn send_registration_response(&self, username: &str, signature: &str) -> Result<()> {
        let env = MixnetMessage::challenge_response(username, "server", signature, "registration");
        self.send_to_server(&env).await
    }

    /// Send a login request for a username
    pub async fn send_login_request(&self, username: &str) -> Result<()> {
        let env = MixnetMessage::login(username);
        self.send_to_server(&env).await
    }

    /// Send login challenge response
    pub async fn send_login_response(&self, username: &str, signature: &str) -> Result<()> {
        let env = MixnetMessage::challenge_response(username, "server", signature, "login");
        self.send_to_server(&env).await
    }

    // ========== Query Methods ==========

    /// Send a query request for a user's public key
    pub async fn send_query_request(&self, sender: &str, username: &str) -> Result<()> {
        let env = MixnetMessage::query(sender, username);
        self.send_to_server(&env).await
    }

    /// Send a fetch pending messages request
    pub async fn send_fetch_pending(&self, username: &str, timestamp: i64, signature: &str) -> Result<()> {
        let env = MixnetMessage::fetch_pending(username, timestamp, signature);
        self.send_to_server(&env).await
    }

    // ========== Direct Messaging Methods ==========

    /// Send a message via the discovery server for routing
    pub async fn send_message_via_server(
        &self,
        sender: &str,
        recipient: &str,
        content: &str,
        signature: &str,
    ) -> Result<()> {
        let env = MixnetMessage::send_via_server(sender, recipient, content, signature);
        log::info!("Sending message via server");
        self.send_to_server(&env).await?;
        log::info!("Message sent to server successfully");
        Ok(())
    }

    /// Send a p2p direct chat message with content and signature
    pub async fn send_direct_message(
        &self,
        sender: &str,
        recipient: &str,
        content: &str,
        conversation_id: &str,
        signature: &str,
    ) -> Result<()> {
        let env = MixnetMessage::direct_message(sender, recipient, content, conversation_id, signature);
        let payload = env.to_json()?;
        let raw_bytes = payload.into_bytes();

        // Determine recipient: direct address if known, else central server
        if let Some(addr) = self.nym_addresses.read().await.get(recipient) {
            let recipient: Recipient = addr.parse()?;
            self.sender
                .send_message(recipient, raw_bytes, IncludedSurbs::Amount(10))
                .await?;
        } else {
            // Fallback to central server
            self.send_to_server(&env).await?;
        }
        Ok(())
    }

    /// Send MLS encrypted message using raw bytes
    pub async fn send_mls_message(
        &self,
        sender: &str,
        recipient: &str,
        conversation_id: &[u8],
        mls_message: &[u8],
        signature: &str,
    ) -> Result<()> {
        let env = MixnetMessage::mls_message_raw(sender, recipient, conversation_id, mls_message, signature);
        log::info!("Sending MLS message via server");
        self.send_to_server(&env).await?;
        log::info!("MLS message sent to server successfully");
        Ok(())
    }

    // ========== MLS Key Exchange Methods ==========

    /// Send key package request for MLS handshake
    pub async fn send_key_package_request(
        &self,
        sender: &str,
        recipient: &str,
        sender_key_package: &str,
        signature: &str,
    ) -> Result<()> {
        let env = MixnetMessage::key_package_request(sender, recipient, sender_key_package, signature);
        log::info!("Sending key package request to {} via server", recipient);
        self.send_to_server(&env).await?;
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
        log::info!("Sending key package response to {} via server", recipient);
        self.send_to_server(&env).await?;
        log::info!("Key package response sent successfully");
        Ok(())
    }

    /// Send P2P MLS welcome message for direct messaging handshake
    ///
    /// This is used for establishing 1:1 encrypted conversations. The welcome
    /// is relayed through the discovery server since users haven't exchanged
    /// direct addresses yet.
    pub async fn send_p2p_welcome(
        &self,
        sender: &str,
        recipient: &str,
        welcome_b64: &str,
        group_id: &str,
        signature: &str,
    ) -> Result<()> {
        // Use a simple payload format for P2P welcome relay
        let payload = serde_json::json!({
            "type": "system",
            "action": "p2pWelcome",
            "sender": sender,
            "recipient": recipient,
            "payload": {
                "welcomeMessage": welcome_b64,
                "groupId": group_id
            },
            "signature": signature,
            "timestamp": chrono::Utc::now().to_rfc3339()
        });
        log::info!("Sending P2P welcome to {} via discovery server", recipient);
        let server_addr = self.server_address.read().await
            .clone()
            .context("Server address not configured")?;
        self.send_raw(&server_addr, payload.to_string().into_bytes()).await?;
        log::info!("P2P welcome sent successfully");
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
        log::info!("Sending group join response to {} via server", recipient);
        self.send_to_server(&env).await?;
        log::info!("Group join response sent successfully");
        Ok(())
    }

    // ========== Group Server Methods ==========

    /// Send a group message to group server
    pub async fn send_group_message(
        &self,
        sender: &str,
        ciphertext: &str,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        let env = MixnetMessage::send_group(sender, ciphertext, signature);
        log::info!("Sending group message to {}", group_server_address);
        self.send_message_to(group_server_address, &env).await?;
        log::info!("Group message sent successfully");
        Ok(())
    }

    /// Register with a group server using timestamp-based authentication
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
        log::info!("Registering with group server {}", group_server_address);
        self.send_message_to(group_server_address, &env).await?;
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
        timestamp: i64,
    ) -> Result<()> {
        let env = MixnetMessage::approve_group_member(
            admin,
            username_to_approve,
            signature,
            group_server_address,
            timestamp,
        );
        log::info!(
            "Approving group member {} on server {}",
            username_to_approve,
            group_server_address
        );
        self.send_message_to(group_server_address, &env).await?;
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
        log::info!("Sending fetchGroup request - lastSeenId: {}", last_seen_id);
        self.send_message_to(group_server_address, &env).await?;
        log::info!("fetchGroup request sent successfully");
        Ok(())
    }

    // ========== Welcome Flow Methods ==========

    /// Send an MLS Welcome message to store on the group server
    ///
    /// This sends a Welcome message to the group server for storage.
    /// The recipient can later fetch it using fetchWelcome.
    pub async fn send_mls_welcome(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        cipher_suite: u16,
        welcome_bytes: &str,
        ratchet_tree: Option<&str>,
        epoch: u64,
        welcome_timestamp: u64,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        let env = MixnetMessage::mls_welcome(
            sender,
            recipient,
            group_id,
            cipher_suite,
            welcome_bytes,
            ratchet_tree,
            epoch,
            welcome_timestamp,
            signature,
        );
        log::info!("Sending MLS welcome for group {} to {} via group server", group_id, recipient);
        self.send_message_to(group_server_address, &env).await?;
        log::info!("MLS welcome for group {} sent to group server for {} successfully", group_id, recipient);
        Ok(())
    }

    /// Send a group join request with our KeyPackage
    pub async fn send_group_join_request(
        &self,
        sender: &str,
        group_id: &str,
        key_package: &str,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        let env = MixnetMessage::group_join_request(sender, group_id, key_package, signature);
        log::info!("Sending group join request for group {} to group server", group_id);
        self.send_message_to(group_server_address, &env).await?;
        log::info!("Group join request sent successfully");
        Ok(())
    }

    /// Send a Welcome acknowledgment after successfully joining a group
    pub async fn send_welcome_ack(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        success: bool,
        signature: &str,
    ) -> Result<()> {
        let env = MixnetMessage::welcome_ack(sender, recipient, group_id, success, signature);
        log::info!("Sending welcome ack for group {} to {} via server", group_id, recipient);
        self.send_to_server(&env).await?;
        log::info!("Welcome ack sent successfully");
        Ok(())
    }

    /// Send a group invite notification to a user
    pub async fn send_group_invite(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        group_name: Option<&str>,
        signature: &str,
    ) -> Result<()> {
        let env = MixnetMessage::group_invite(sender, recipient, group_id, group_name, signature);
        log::info!("Sending group invite for {} to {} via server", group_id, recipient);
        self.send_to_server(&env).await?;
        log::info!("Group invite sent successfully");
        Ok(())
    }

    /// Request a KeyPackage from a user for adding them to a group
    pub async fn send_key_package_for_group_request(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        signature: &str,
    ) -> Result<()> {
        let env = MixnetMessage::key_package_for_group(sender, recipient, group_id, signature);
        log::info!(
            "Requesting KeyPackage from {} for group {} via server",
            recipient,
            group_id
        );
        self.send_to_server(&env).await?;
        log::info!("KeyPackage request sent successfully");
        Ok(())
    }

    /// Send KeyPackage in response to a group join request
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
        log::info!(
            "Sending KeyPackage response to {} for group {} via server",
            recipient,
            group_id
        );
        self.send_to_server(&env).await?;
        log::info!("KeyPackage response sent successfully");
        Ok(())
    }

    // ========== MLS Delivery Service Methods ==========

    /// Register with a group server, optionally including an MLS KeyPackage
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
        log::info!(
            "Registering with group server {} (with KeyPackage: {})",
            group_server_address,
            key_package.is_some()
        );
        self.send_message_to(group_server_address, &env).await?;
        log::info!("Group registration request sent");
        Ok(())
    }

    /// Store a Welcome message on the group server for a user to fetch later
    pub async fn store_welcome_on_server(
        &self,
        sender: &str,
        group_id: &str,
        target_username: &str,
        welcome: &str,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        let env = MixnetMessage::store_welcome(sender, group_id, target_username, welcome, signature);
        log::info!(
            "Storing Welcome for {} in group {} on server {}",
            target_username,
            group_id,
            group_server_address
        );
        self.send_message_to(group_server_address, &env).await?;
        log::info!("Store Welcome request sent");
        Ok(())
    }

    /// Buffer a commit message on the group server for epoch synchronization
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
        log::info!(
            "Buffering commit for group {} at epoch {} on server {}",
            group_id,
            epoch,
            group_server_address
        );
        self.send_message_to(group_server_address, &env).await?;
        log::info!("Buffer commit request sent");
        Ok(())
    }

    /// Fetch pending Welcome messages from the group server
    pub async fn fetch_welcome_from_server(
        &self,
        username: &str,
        group_id: Option<&str>,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        let env = MixnetMessage::fetch_welcome(username, group_id, signature);
        log::info!(
            "Fetching Welcomes for {} from server {} (group filter: {:?})",
            username,
            group_server_address,
            group_id
        );
        self.send_message_to(group_server_address, &env).await?;
        log::info!("Fetch Welcome request sent");
        Ok(())
    }

    /// Request epoch sync from the group server
    pub async fn sync_epoch_from_server(
        &self,
        username: &str,
        group_id: &str,
        since_epoch: i64,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        let env = MixnetMessage::sync_epoch(username, group_id, since_epoch, signature);
        log::info!(
            "Requesting epoch sync for group {} since epoch {} from server {}",
            group_id,
            since_epoch,
            group_server_address
        );
        self.send_message_to(group_server_address, &env).await?;
        log::info!("Sync epoch request sent");
        Ok(())
    }

    /// Query pending users awaiting approval from a group server (admin only)
    pub async fn query_pending_users(
        &self,
        admin: &str,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        let env = MixnetMessage::query_pending_users(admin, signature);
        log::info!(
            "Querying pending users from group server {}",
            group_server_address
        );
        self.send_message_to(group_server_address, &env).await?;
        log::info!("Query pending users request sent");
        Ok(())
    }
}

// Allow cloning service for spawn
impl Clone for MixnetService {
    fn clone(&self) -> Self {
        Self {
            client: Arc::clone(&self.client),
            sender: self.sender.clone(),
            nym_addresses: Arc::clone(&self.nym_addresses),
            our_address: self.our_address.clone(),
            server_address: Arc::clone(&self.server_address),
        }
    }
}

// ========== Trait Implementations ==========

use crate::core::mixnet_traits::{MixnetAddressStore, MixnetSender};
use async_trait::async_trait;

#[async_trait]
impl MixnetSender for MixnetService {
    async fn send_raw(&self, recipient_address: &str, data: Vec<u8>) -> Result<()> {
        MixnetService::send_raw(self, recipient_address, data).await
    }

    async fn send_message_to(&self, recipient_address: &str, message: &MixnetMessage) -> Result<()> {
        MixnetService::send_message_to(self, recipient_address, message).await
    }

    async fn send_to_server(&self, message: &MixnetMessage) -> Result<()> {
        MixnetService::send_to_server(self, message).await
    }

    async fn send_registration_request(&self, username: &str, public_key: &str) -> Result<()> {
        MixnetService::send_registration_request(self, username, public_key).await
    }

    async fn send_registration_response(&self, username: &str, signature: &str) -> Result<()> {
        MixnetService::send_registration_response(self, username, signature).await
    }

    async fn send_login_request(&self, username: &str) -> Result<()> {
        MixnetService::send_login_request(self, username).await
    }

    async fn send_login_response(&self, username: &str, signature: &str) -> Result<()> {
        MixnetService::send_login_response(self, username, signature).await
    }

    async fn send_query_request(&self, sender: &str, username: &str) -> Result<()> {
        MixnetService::send_query_request(self, sender, username).await
    }

    async fn send_fetch_pending(
        &self,
        username: &str,
        timestamp: i64,
        signature: &str,
    ) -> Result<()> {
        MixnetService::send_fetch_pending(self, username, timestamp, signature).await
    }

    async fn send_message_via_server(
        &self,
        sender: &str,
        recipient: &str,
        content: &str,
        signature: &str,
    ) -> Result<()> {
        MixnetService::send_message_via_server(self, sender, recipient, content, signature).await
    }

    async fn send_direct_message(
        &self,
        sender: &str,
        recipient: &str,
        content: &str,
        conversation_id: &str,
        signature: &str,
    ) -> Result<()> {
        MixnetService::send_direct_message(self, sender, recipient, content, conversation_id, signature).await
    }

    async fn send_mls_message(
        &self,
        sender: &str,
        recipient: &str,
        conversation_id: &[u8],
        mls_message: &[u8],
        signature: &str,
    ) -> Result<()> {
        MixnetService::send_mls_message(self, sender, recipient, conversation_id, mls_message, signature).await
    }

    async fn send_key_package_request(
        &self,
        sender: &str,
        recipient: &str,
        sender_key_package: &str,
        signature: &str,
    ) -> Result<()> {
        MixnetService::send_key_package_request(self, sender, recipient, sender_key_package, signature).await
    }

    async fn send_key_package_response(
        &self,
        sender: &str,
        recipient: &str,
        sender_key_package: &str,
        recipient_key_package: &str,
        signature: &str,
    ) -> Result<()> {
        MixnetService::send_key_package_response(
            self,
            sender,
            recipient,
            sender_key_package,
            recipient_key_package,
            signature,
        ).await
    }

    async fn send_p2p_welcome(
        &self,
        sender: &str,
        recipient: &str,
        welcome_b64: &str,
        group_id: &str,
        signature: &str,
    ) -> Result<()> {
        MixnetService::send_p2p_welcome(self, sender, recipient, welcome_b64, group_id, signature).await
    }

    async fn send_group_join_response(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        success: bool,
        signature: &str,
    ) -> Result<()> {
        MixnetService::send_group_join_response(self, sender, recipient, group_id, success, signature).await
    }

    async fn send_group_message(
        &self,
        sender: &str,
        ciphertext: &str,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        MixnetService::send_group_message(self, sender, ciphertext, signature, group_server_address).await
    }

    async fn register_with_group_server(
        &self,
        username: &str,
        public_key: &str,
        signature: &str,
        timestamp: i64,
        group_server_address: &str,
    ) -> Result<()> {
        MixnetService::register_with_group_server(
            self,
            username,
            public_key,
            signature,
            timestamp,
            group_server_address,
        ).await
    }

    async fn approve_group_member(
        &self,
        admin: &str,
        username_to_approve: &str,
        signature: &str,
        group_server_address: &str,
        timestamp: i64,
    ) -> Result<()> {
        MixnetService::approve_group_member(self, admin, username_to_approve, signature, group_server_address, timestamp).await
    }

    async fn send_group_fetch_request(
        &self,
        sender: &str,
        last_seen_id: i64,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        MixnetService::send_group_fetch_request(self, sender, last_seen_id, signature, group_server_address).await
    }

    async fn send_mls_welcome(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        cipher_suite: u16,
        welcome_bytes: &str,
        ratchet_tree: Option<&str>,
        epoch: u64,
        welcome_timestamp: u64,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        MixnetService::send_mls_welcome(
            self,
            sender,
            recipient,
            group_id,
            cipher_suite,
            welcome_bytes,
            ratchet_tree,
            epoch,
            welcome_timestamp,
            signature,
            group_server_address,
        ).await
    }

    async fn send_group_join_request(
        &self,
        sender: &str,
        group_id: &str,
        key_package: &str,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        MixnetService::send_group_join_request(self, sender, group_id, key_package, signature, group_server_address).await
    }

    async fn send_welcome_ack(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        success: bool,
        signature: &str,
    ) -> Result<()> {
        MixnetService::send_welcome_ack(self, sender, recipient, group_id, success, signature).await
    }

    async fn send_group_invite(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        group_name: Option<&str>,
        signature: &str,
    ) -> Result<()> {
        MixnetService::send_group_invite(self, sender, recipient, group_id, group_name, signature).await
    }

    async fn send_key_package_for_group_request(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        signature: &str,
    ) -> Result<()> {
        MixnetService::send_key_package_for_group_request(self, sender, recipient, group_id, signature).await
    }

    async fn send_key_package_for_group_response(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        key_package: &str,
        signature: &str,
    ) -> Result<()> {
        MixnetService::send_key_package_for_group_response(
            self,
            sender,
            recipient,
            group_id,
            key_package,
            signature,
        ).await
    }

    async fn register_with_group_server_and_key_package(
        &self,
        username: &str,
        public_key: &str,
        signature: &str,
        timestamp: i64,
        group_server_address: &str,
        key_package: Option<&str>,
    ) -> Result<()> {
        MixnetService::register_with_group_server_and_key_package(
            self,
            username,
            public_key,
            signature,
            timestamp,
            group_server_address,
            key_package,
        ).await
    }

    async fn store_welcome_on_server(
        &self,
        sender: &str,
        group_id: &str,
        target_username: &str,
        welcome: &str,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        MixnetService::store_welcome_on_server(
            self,
            sender,
            group_id,
            target_username,
            welcome,
            signature,
            group_server_address,
        ).await
    }

    async fn buffer_commit_on_server(
        &self,
        sender: &str,
        group_id: &str,
        epoch: i64,
        commit: &str,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        MixnetService::buffer_commit_on_server(
            self,
            sender,
            group_id,
            epoch,
            commit,
            signature,
            group_server_address,
        ).await
    }

    async fn fetch_welcome_from_server(
        &self,
        username: &str,
        group_id: Option<&str>,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        MixnetService::fetch_welcome_from_server(self, username, group_id, signature, group_server_address).await
    }

    async fn sync_epoch_from_server(
        &self,
        username: &str,
        group_id: &str,
        since_epoch: i64,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        MixnetService::sync_epoch_from_server(
            self,
            username,
            group_id,
            since_epoch,
            signature,
            group_server_address,
        ).await
    }

    async fn query_pending_users(
        &self,
        admin: &str,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        MixnetService::query_pending_users(self, admin, signature, group_server_address).await
    }
}

#[async_trait]
impl MixnetAddressStore for MixnetService {
    fn our_address(&self) -> &str {
        MixnetService::our_address(self)
    }

    async fn set_server_address(&self, address: Option<String>) {
        MixnetService::set_server_address(self, address).await
    }

    async fn get_server_address(&self) -> Option<String> {
        MixnetService::get_server_address(self).await
    }

    async fn register_peer_address(&self, username: &str, address: &str) {
        MixnetService::register_peer_address(self, username, address).await
    }

    async fn get_peer_address(&self, username: &str) -> Option<String> {
        MixnetService::get_peer_address(self, username).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incoming_struct_creation() {
        let msg = MixnetMessage::query("alice", "bob");
        let incoming = Incoming {
            envelope: msg,
            ts: Utc::now(),
        };

        assert_eq!(incoming.envelope.action, "query");
        assert_eq!(incoming.envelope.sender, "alice");
    }

    #[test]
    fn test_mixnet_config_default() {
        let config = MixnetConfig::default();
        assert!(config.storage_path.is_none());
        assert!(config.server_address.is_none());
    }
}
