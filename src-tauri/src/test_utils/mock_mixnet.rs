//! Mock implementation of the mixnet service for testing
//!
//! Provides a `MockMixnetService` that records all sent messages and allows
//! injection of incoming messages for testing message flows without requiring
//! actual network connectivity.

use crate::core::messages::MixnetMessage;
use crate::core::mixnet_traits::{MixnetAddressStore, MixnetSender};
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};

/// Record of a sent message for test verification
#[derive(Debug, Clone)]
pub struct SentMessage {
    /// The recipient address
    pub recipient: String,
    /// The message that was sent
    pub message: MixnetMessage,
    /// When the message was sent
    pub timestamp: DateTime<Utc>,
    /// Raw bytes if sent via send_raw
    pub raw_data: Option<Vec<u8>>,
}

/// Configuration for the mock mixnet behavior
#[derive(Debug, Clone, Default)]
pub struct MockMixnetConfig {
    /// Simulated latency in milliseconds (0 = instant)
    pub latency_ms: u64,
    /// Probability of message loss (0.0 = never, 1.0 = always)
    pub loss_rate: f64,
    /// Whether to reorder messages (simulates mixnet behavior)
    pub reorder_messages: bool,
}

/// Mock implementation of the mixnet service for testing
#[derive(Clone)]
pub struct MockMixnetService {
    /// Our simulated Nym address
    our_address: String,
    /// Server address for routing
    server_address: Arc<RwLock<Option<String>>>,
    /// Peer address cache
    peer_addresses: Arc<RwLock<HashMap<String, String>>>,
    /// Record of all sent messages
    sent_messages: Arc<Mutex<Vec<SentMessage>>>,
    /// Channel to inject incoming messages
    incoming_tx: Arc<Mutex<Option<mpsc::Sender<MixnetMessage>>>>,
    /// Configuration for mock behavior
    #[allow(dead_code)]
    config: MockMixnetConfig,
}

impl MockMixnetService {
    /// Create a new mock mixnet service
    pub fn new() -> Self {
        Self::with_address("mock-nym-address-123")
    }

    /// Create a mock service with a specific address
    pub fn with_address(address: &str) -> Self {
        Self {
            our_address: address.to_string(),
            server_address: Arc::new(RwLock::new(None)),
            peer_addresses: Arc::new(RwLock::new(HashMap::new())),
            sent_messages: Arc::new(Mutex::new(Vec::new())),
            incoming_tx: Arc::new(Mutex::new(None)),
            config: MockMixnetConfig::default(),
        }
    }

    /// Create a mock service with custom configuration
    pub fn with_config(config: MockMixnetConfig) -> Self {
        Self {
            our_address: "mock-nym-address-123".to_string(),
            server_address: Arc::new(RwLock::new(None)),
            peer_addresses: Arc::new(RwLock::new(HashMap::new())),
            sent_messages: Arc::new(Mutex::new(Vec::new())),
            incoming_tx: Arc::new(Mutex::new(None)),
            config,
        }
    }

    /// Set up an incoming message channel for testing message reception
    pub async fn setup_incoming_channel(&self) -> mpsc::Receiver<MixnetMessage> {
        let (tx, rx) = mpsc::channel(100);
        *self.incoming_tx.lock().await = Some(tx);
        rx
    }

    /// Inject an incoming message (simulates receiving from network)
    pub async fn inject_incoming(&self, message: MixnetMessage) -> Result<()> {
        let tx = self.incoming_tx.lock().await;
        if let Some(ref sender) = *tx {
            sender.send(message).await.map_err(|e| anyhow::anyhow!("Failed to inject message: {}", e))?;
        }
        Ok(())
    }

    /// Get all sent messages
    pub async fn get_sent_messages(&self) -> Vec<SentMessage> {
        self.sent_messages.lock().await.clone()
    }

    /// Get sent messages filtered by action type
    pub async fn get_sent_by_action(&self, action: &str) -> Vec<SentMessage> {
        self.sent_messages
            .lock()
            .await
            .iter()
            .filter(|m| m.message.action == action)
            .cloned()
            .collect()
    }

    /// Get sent messages filtered by recipient
    pub async fn get_sent_to(&self, recipient: &str) -> Vec<SentMessage> {
        self.sent_messages
            .lock()
            .await
            .iter()
            .filter(|m| m.recipient == recipient)
            .cloned()
            .collect()
    }

    /// Get the last sent message
    pub async fn last_sent(&self) -> Option<SentMessage> {
        self.sent_messages.lock().await.last().cloned()
    }

    /// Clear all recorded sent messages
    pub async fn clear_sent(&self) {
        self.sent_messages.lock().await.clear();
    }

    /// Get the count of sent messages
    pub async fn sent_count(&self) -> usize {
        self.sent_messages.lock().await.len()
    }

    /// Record a sent message
    async fn record_send(&self, recipient: &str, message: MixnetMessage, raw_data: Option<Vec<u8>>) {
        let sent = SentMessage {
            recipient: recipient.to_string(),
            message,
            timestamp: Utc::now(),
            raw_data,
        };
        self.sent_messages.lock().await.push(sent);
    }
}

impl Default for MockMixnetService {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MixnetSender for MockMixnetService {
    async fn send_raw(&self, recipient_address: &str, data: Vec<u8>) -> Result<()> {
        // Try to parse the raw data as a MixnetMessage for recording
        let message = match String::from_utf8(data.clone()) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|_| {
                MixnetMessage::query("raw", "raw") // Placeholder for unparseable data
            }),
            Err(_) => MixnetMessage::query("raw", "raw"),
        };
        self.record_send(recipient_address, message, Some(data)).await;
        Ok(())
    }

    async fn send_message_to(&self, recipient_address: &str, message: &MixnetMessage) -> Result<()> {
        self.record_send(recipient_address, message.clone(), None).await;
        Ok(())
    }

    async fn send_to_server(&self, message: &MixnetMessage) -> Result<()> {
        let server = self.server_address.read().await;
        let recipient = server.as_deref().unwrap_or("server");
        self.record_send(recipient, message.clone(), None).await;
        Ok(())
    }

    async fn send_registration_request(&self, username: &str, public_key: &str) -> Result<()> {
        let msg = MixnetMessage::register(username, public_key);
        self.send_to_server(&msg).await
    }

    async fn send_registration_response(&self, username: &str, signature: &str) -> Result<()> {
        let msg = MixnetMessage::challenge_response(username, "server", signature, "registration");
        self.send_to_server(&msg).await
    }

    async fn send_login_request(&self, username: &str) -> Result<()> {
        let msg = MixnetMessage::login(username);
        self.send_to_server(&msg).await
    }

    async fn send_login_response(&self, username: &str, signature: &str) -> Result<()> {
        let msg = MixnetMessage::challenge_response(username, "server", signature, "login");
        self.send_to_server(&msg).await
    }

    async fn send_query_request(&self, sender: &str, username: &str) -> Result<()> {
        let msg = MixnetMessage::query(sender, username);
        self.send_to_server(&msg).await
    }

    async fn send_fetch_pending(&self, username: &str, timestamp: i64, signature: &str) -> Result<()> {
        let msg = MixnetMessage::fetch_pending(username, timestamp, signature);
        self.send_to_server(&msg).await
    }

    async fn send_message_via_server(
        &self,
        sender: &str,
        recipient: &str,
        content: &str,
        signature: &str,
    ) -> Result<()> {
        let msg = MixnetMessage::send_via_server(sender, recipient, content, signature);
        self.send_to_server(&msg).await
    }

    async fn send_direct_message(
        &self,
        sender: &str,
        recipient: &str,
        content: &str,
        conversation_id: &str,
        signature: &str,
    ) -> Result<()> {
        let msg = MixnetMessage::direct_message(sender, recipient, content, conversation_id, signature);

        // Check if we have a direct address
        if let Some(addr) = self.peer_addresses.read().await.get(recipient) {
            self.record_send(addr, msg, None).await;
        } else {
            self.send_to_server(&msg).await?;
        }
        Ok(())
    }

    async fn send_mls_message(
        &self,
        sender: &str,
        recipient: &str,
        conversation_id: &[u8],
        mls_message: &[u8],
        signature: &str,
    ) -> Result<()> {
        let msg = MixnetMessage::mls_message_raw(sender, recipient, conversation_id, mls_message, signature);
        self.send_to_server(&msg).await
    }

    async fn send_key_package_request(
        &self,
        sender: &str,
        recipient: &str,
        sender_key_package: &str,
        signature: &str,
    ) -> Result<()> {
        let msg = MixnetMessage::key_package_request(sender, recipient, sender_key_package, signature);
        self.send_to_server(&msg).await
    }

    async fn send_key_package_response(
        &self,
        sender: &str,
        recipient: &str,
        sender_key_package: &str,
        recipient_key_package: &str,
        signature: &str,
    ) -> Result<()> {
        let msg = MixnetMessage::key_package_response(
            sender,
            recipient,
            sender_key_package,
            recipient_key_package,
            signature,
        );
        self.send_to_server(&msg).await
    }

    async fn send_p2p_welcome(
        &self,
        sender: &str,
        recipient: &str,
        welcome_b64: &str,
        group_id: &str,
        signature: &str,
    ) -> Result<()> {
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
        let server = self.server_address.read().await;
        let server_addr = server.as_deref().unwrap_or("server");

        // Create a message for recording
        let msg = MixnetMessage {
            message_type: "system".into(),
            action: "p2pWelcome".into(),
            sender: sender.into(),
            recipient: recipient.into(),
            payload: payload["payload"].clone(),
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        self.record_send(server_addr, msg, None).await;
        Ok(())
    }

    async fn send_group_join_response(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        success: bool,
        signature: &str,
    ) -> Result<()> {
        let msg = MixnetMessage::group_join_response(sender, recipient, group_id, success, signature);
        self.send_to_server(&msg).await
    }

    async fn send_group_message(
        &self,
        sender: &str,
        ciphertext: &str,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        let msg = MixnetMessage::send_group(sender, ciphertext, signature);
        self.record_send(group_server_address, msg, None).await;
        Ok(())
    }

    async fn register_with_group_server(
        &self,
        username: &str,
        public_key: &str,
        signature: &str,
        timestamp: i64,
        group_server_address: &str,
    ) -> Result<()> {
        let msg = MixnetMessage::register_with_group_server(
            username,
            public_key,
            signature,
            timestamp,
            group_server_address,
        );
        self.record_send(group_server_address, msg, None).await;
        Ok(())
    }

    async fn approve_group_member(
        &self,
        admin: &str,
        username_to_approve: &str,
        signature: &str,
        group_server_address: &str,
        timestamp: i64,
    ) -> Result<()> {
        let msg = MixnetMessage::approve_group_member(admin, username_to_approve, signature, group_server_address, timestamp);
        self.record_send(group_server_address, msg, None).await;
        Ok(())
    }

    async fn send_group_fetch_request(
        &self,
        sender: &str,
        last_seen_id: i64,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        let msg = MixnetMessage::fetch_group(sender, last_seen_id, signature);
        self.record_send(group_server_address, msg, None).await;
        Ok(())
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
        let msg = MixnetMessage::mls_welcome(
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
        self.record_send(group_server_address, msg, None).await;
        Ok(())
    }

    async fn send_group_join_request(
        &self,
        sender: &str,
        group_id: &str,
        key_package: &str,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        let msg = MixnetMessage::group_join_request(sender, group_id, key_package, signature);
        self.record_send(group_server_address, msg, None).await;
        Ok(())
    }

    async fn send_welcome_ack(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        success: bool,
        signature: &str,
    ) -> Result<()> {
        let msg = MixnetMessage::welcome_ack(sender, recipient, group_id, success, signature);
        self.send_to_server(&msg).await
    }

    async fn send_group_invite(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        group_name: Option<&str>,
        signature: &str,
    ) -> Result<()> {
        let msg = MixnetMessage::group_invite(sender, recipient, group_id, group_name, signature);
        self.send_to_server(&msg).await
    }

    async fn send_key_package_for_group_request(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        signature: &str,
    ) -> Result<()> {
        let msg = MixnetMessage::key_package_for_group(sender, recipient, group_id, signature);
        self.send_to_server(&msg).await
    }

    async fn send_key_package_for_group_response(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        key_package: &str,
        signature: &str,
    ) -> Result<()> {
        let msg = MixnetMessage::key_package_for_group_response(
            sender,
            recipient,
            group_id,
            key_package,
            signature,
        );
        self.send_to_server(&msg).await
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
        let msg = MixnetMessage::register_with_group_server_and_key_package(
            username,
            public_key,
            signature,
            timestamp,
            group_server_address,
            key_package,
        );
        self.record_send(group_server_address, msg, None).await;
        Ok(())
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
        let msg = MixnetMessage::store_welcome(sender, group_id, target_username, welcome, signature);
        self.record_send(group_server_address, msg, None).await;
        Ok(())
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
        let msg = MixnetMessage::buffer_commit(sender, group_id, epoch, commit, signature);
        self.record_send(group_server_address, msg, None).await;
        Ok(())
    }

    async fn fetch_welcome_from_server(
        &self,
        username: &str,
        group_id: Option<&str>,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        let msg = MixnetMessage::fetch_welcome(username, group_id, signature);
        self.record_send(group_server_address, msg, None).await;
        Ok(())
    }

    async fn sync_epoch_from_server(
        &self,
        username: &str,
        group_id: &str,
        since_epoch: i64,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        let msg = MixnetMessage::sync_epoch(username, group_id, since_epoch, signature);
        self.record_send(group_server_address, msg, None).await;
        Ok(())
    }

    async fn query_pending_users(
        &self,
        admin: &str,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()> {
        let msg = MixnetMessage::query_pending_users(admin, signature);
        self.record_send(group_server_address, msg, None).await;
        Ok(())
    }
}

#[async_trait]
impl MixnetAddressStore for MockMixnetService {
    fn our_address(&self) -> &str {
        &self.our_address
    }

    async fn set_server_address(&self, address: Option<String>) {
        *self.server_address.write().await = address;
    }

    async fn get_server_address(&self) -> Option<String> {
        self.server_address.read().await.clone()
    }

    async fn register_peer_address(&self, username: &str, address: &str) {
        self.peer_addresses.write().await.insert(username.to_string(), address.to_string());
    }

    async fn get_peer_address(&self, username: &str) -> Option<String> {
        self.peer_addresses.read().await.get(username).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_mixnet_records_sent_messages() {
        let mock = MockMixnetService::new();
        mock.set_server_address(Some("test-server".to_string())).await;

        mock.send_registration_request("alice", "pubkey123").await.unwrap();

        let sent = mock.get_sent_messages().await;
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].message.action, "register");
        assert_eq!(sent[0].message.sender, "alice");
    }

    #[tokio::test]
    async fn test_mock_mixnet_filter_by_action() {
        let mock = MockMixnetService::new();
        mock.set_server_address(Some("test-server".to_string())).await;

        mock.send_registration_request("alice", "pubkey").await.unwrap();
        mock.send_login_request("alice").await.unwrap();
        mock.send_query_request("alice", "bob").await.unwrap();

        let login_msgs = mock.get_sent_by_action("login").await;
        assert_eq!(login_msgs.len(), 1);
        assert_eq!(login_msgs[0].message.sender, "alice");
    }

    #[tokio::test]
    async fn test_mock_mixnet_peer_addresses() {
        let mock = MockMixnetService::new();

        mock.register_peer_address("bob", "bob-nym-address").await;

        let addr = mock.get_peer_address("bob").await;
        assert_eq!(addr, Some("bob-nym-address".to_string()));

        let unknown = mock.get_peer_address("unknown").await;
        assert!(unknown.is_none());
    }

    #[tokio::test]
    async fn test_mock_mixnet_incoming_channel() {
        let mock = MockMixnetService::new();
        let mut rx = mock.setup_incoming_channel().await;

        let msg = MixnetMessage::query("server", "alice");
        mock.inject_incoming(msg.clone()).await.unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.action, "query");
        assert_eq!(received.sender, "server");
    }
}
