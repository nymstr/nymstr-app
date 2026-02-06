//! Trait abstractions for mixnet operations
//!
//! This module defines traits that abstract the mixnet communication layer,
//! enabling testability through mock implementations without requiring actual
//! Nym SDK connectivity.

use anyhow::Result;
use async_trait::async_trait;

use crate::core::messages::MixnetMessage;

/// Trait for sending messages over the mixnet
///
/// All methods that send messages through the mixnet are defined here.
/// This enables mock implementations for testing.
#[async_trait]
pub trait MixnetSender: Send + Sync {
    // ========== Low-Level Send Methods ==========

    /// Send raw bytes to a recipient address
    async fn send_raw(&self, recipient_address: &str, data: Vec<u8>) -> Result<()>;

    /// Send a MixnetMessage to a recipient address
    async fn send_message_to(&self, recipient_address: &str, message: &MixnetMessage) -> Result<()>;

    /// Send a MixnetMessage to the configured server
    async fn send_to_server(&self, message: &MixnetMessage) -> Result<()>;

    // ========== Authentication Methods ==========

    /// Send a registration request with username and public key
    async fn send_registration_request(&self, username: &str, public_key: &str) -> Result<()>;

    /// Send registration challenge response
    async fn send_registration_response(&self, username: &str, signature: &str) -> Result<()>;

    /// Send a login request for a username
    async fn send_login_request(&self, username: &str) -> Result<()>;

    /// Send login challenge response
    async fn send_login_response(&self, username: &str, signature: &str) -> Result<()>;

    // ========== Query Methods ==========

    /// Send a query request for a user's public key
    async fn send_query_request(&self, sender: &str, username: &str) -> Result<()>;

    /// Send a fetch pending messages request
    async fn send_fetch_pending(&self, username: &str, timestamp: i64, signature: &str)
        -> Result<()>;

    // ========== Direct Messaging Methods ==========

    /// Send a message via the discovery server for routing
    async fn send_message_via_server(
        &self,
        sender: &str,
        recipient: &str,
        content: &str,
        signature: &str,
    ) -> Result<()>;

    /// Send a p2p direct chat message with content and signature
    async fn send_direct_message(
        &self,
        sender: &str,
        recipient: &str,
        content: &str,
        conversation_id: &str,
        signature: &str,
    ) -> Result<()>;

    /// Send MLS encrypted message using raw bytes
    async fn send_mls_message(
        &self,
        sender: &str,
        recipient: &str,
        conversation_id: &[u8],
        mls_message: &[u8],
        signature: &str,
    ) -> Result<()>;

    // ========== MLS Key Exchange Methods ==========

    /// Send key package request for MLS handshake
    async fn send_key_package_request(
        &self,
        sender: &str,
        recipient: &str,
        sender_key_package: &str,
        signature: &str,
    ) -> Result<()>;

    /// Send key package response for MLS handshake
    async fn send_key_package_response(
        &self,
        sender: &str,
        recipient: &str,
        sender_key_package: &str,
        recipient_key_package: &str,
        signature: &str,
    ) -> Result<()>;

    /// Send P2P MLS welcome message for direct messaging handshake
    async fn send_p2p_welcome(
        &self,
        sender: &str,
        recipient: &str,
        welcome_b64: &str,
        group_id: &str,
        signature: &str,
    ) -> Result<()>;

    /// Send group join response for MLS handshake
    async fn send_group_join_response(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        success: bool,
        signature: &str,
    ) -> Result<()>;

    // ========== Group Server Methods ==========

    /// Send a group message to group server
    async fn send_group_message(
        &self,
        sender: &str,
        ciphertext: &str,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()>;

    /// Register with a group server using timestamp-based authentication
    async fn register_with_group_server(
        &self,
        username: &str,
        public_key: &str,
        signature: &str,
        timestamp: i64,
        group_server_address: &str,
    ) -> Result<()>;

    /// Approve a pending group member (admin only)
    async fn approve_group_member(
        &self,
        admin: &str,
        username_to_approve: &str,
        signature: &str,
        group_server_address: &str,
        timestamp: i64,
    ) -> Result<()>;

    /// Fetch group messages from group server since last_seen_id
    async fn send_group_fetch_request(
        &self,
        sender: &str,
        last_seen_id: i64,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()>;

    // ========== Welcome Flow Methods ==========

    /// Send an MLS Welcome message to store on the group server
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
    ) -> Result<()>;

    /// Send a group join request with our KeyPackage
    async fn send_group_join_request(
        &self,
        sender: &str,
        group_id: &str,
        key_package: &str,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()>;

    /// Send a Welcome acknowledgment after successfully joining a group
    async fn send_welcome_ack(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        success: bool,
        signature: &str,
    ) -> Result<()>;

    /// Send a group invite notification to a user
    async fn send_group_invite(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        group_name: Option<&str>,
        signature: &str,
    ) -> Result<()>;

    /// Request a KeyPackage from a user for adding them to a group
    async fn send_key_package_for_group_request(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        signature: &str,
    ) -> Result<()>;

    /// Send KeyPackage in response to a group join request
    async fn send_key_package_for_group_response(
        &self,
        sender: &str,
        recipient: &str,
        group_id: &str,
        key_package: &str,
        signature: &str,
    ) -> Result<()>;

    // ========== MLS Delivery Service Methods ==========

    /// Register with a group server, optionally including an MLS KeyPackage
    async fn register_with_group_server_and_key_package(
        &self,
        username: &str,
        public_key: &str,
        signature: &str,
        timestamp: i64,
        group_server_address: &str,
        key_package: Option<&str>,
    ) -> Result<()>;

    /// Store a Welcome message on the group server for a user to fetch later
    async fn store_welcome_on_server(
        &self,
        sender: &str,
        group_id: &str,
        target_username: &str,
        welcome: &str,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()>;

    /// Buffer a commit message on the group server for epoch synchronization
    async fn buffer_commit_on_server(
        &self,
        sender: &str,
        group_id: &str,
        epoch: i64,
        commit: &str,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()>;

    /// Fetch pending Welcome messages from the group server
    async fn fetch_welcome_from_server(
        &self,
        username: &str,
        group_id: Option<&str>,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()>;

    /// Request epoch sync from the group server
    async fn sync_epoch_from_server(
        &self,
        username: &str,
        group_id: &str,
        since_epoch: i64,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()>;

    /// Query pending users awaiting approval from a group server (admin only)
    async fn query_pending_users(
        &self,
        admin: &str,
        signature: &str,
        group_server_address: &str,
    ) -> Result<()>;
}

/// Trait for managing peer addresses
#[async_trait]
pub trait MixnetAddressStore: Send + Sync {
    /// Get our own Nym address
    fn our_address(&self) -> &str;

    /// Set the server address for routing
    async fn set_server_address(&self, address: Option<String>);

    /// Get the current server address
    async fn get_server_address(&self) -> Option<String>;

    /// Register a known Nym address for a username (for direct P2P messaging)
    async fn register_peer_address(&self, username: &str, address: &str);

    /// Get a peer's Nym address if known
    async fn get_peer_address(&self, username: &str) -> Option<String>;
}

/// Combined trait for full mixnet functionality
pub trait MixnetClient: MixnetSender + MixnetAddressStore + Clone {}

// Blanket implementation for any type that implements all required traits
impl<T: MixnetSender + MixnetAddressStore + Clone> MixnetClient for T {}

#[cfg(test)]
mod tests {
    use super::*;

    // Test that the traits compile and can be used
    fn _assert_traits_are_object_safe(_: &dyn MixnetSender) {}
    fn _assert_address_store_is_object_safe(_: &dyn MixnetAddressStore) {}
}
