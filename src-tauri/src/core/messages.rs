//! Definition and serialization of mixnet envelope messages
//!
//! This module provides the unified message format for all Nymstr communications.
//! All messages follow the same structure with type, action, sender, recipient,
//! payload, signature, and timestamp fields.
#![allow(dead_code)]

use anyhow::Result;
use chrono;
use serde::{Deserialize, Serialize};

/// Unified message format for all Nymstr communications
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MixnetMessage {
    /// Message category: "message", "response", or "system"
    #[serde(rename = "type")]
    pub message_type: String,
    /// Specific action being performed
    pub action: String,
    /// Who sent the message
    pub sender: String,
    /// Who should receive the message
    pub recipient: String,
    /// Type-specific content as JSON object
    pub payload: serde_json::Value,
    /// Cryptographic signature of the payload
    pub signature: String,
    /// ISO-8601 timestamp when message was created
    pub timestamp: String,
}

impl MixnetMessage {
    /// Create a query message for a given username
    pub fn query(sender: &str, username: &str) -> Self {
        let payload = serde_json::json!({
            "username": username
        });
        Self {
            message_type: "system".into(),
            action: "query".into(),
            sender: sender.into(),
            recipient: "server".into(),
            payload,
            signature: "placeholder".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Register a new user with public key
    pub fn register(username: &str, public_key: &str) -> Self {
        let payload = serde_json::json!({
            "username": username,
            "publicKey": public_key
        });
        Self {
            message_type: "system".into(),
            action: "register".into(),
            sender: username.into(),
            recipient: "server".into(),
            payload,
            signature: "placeholder".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Login an existing username
    pub fn login(username: &str) -> Self {
        let payload = serde_json::json!({
            "username": username
        });
        Self {
            message_type: "system".into(),
            action: "login".into(),
            sender: username.into(),
            recipient: "server".into(),
            payload,
            signature: "placeholder".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Fetch pending messages for offline delivery
    pub fn fetch_pending(username: &str, timestamp: i64, signature: &str) -> Self {
        let payload = serde_json::json!({
            "timestamp": timestamp,
            "signature": signature
        });
        Self {
            message_type: "message".into(),
            action: "fetchPending".into(),
            sender: username.into(),
            recipient: "server".into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Challenge message from server
    pub fn challenge(sender: &str, recipient: &str, nonce: &str, context: &str) -> Self {
        let payload = serde_json::json!({
            "nonce": nonce,
            "context": context
        });
        Self {
            message_type: "system".into(),
            action: "challenge".into(),
            sender: sender.into(),
            recipient: recipient.into(),
            payload,
            signature: "placeholder".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Send a message via the central mixnet server
    pub fn send(
        sender: &str,
        recipient: &str,
        mls_message: &str,
        conversation_id: &str,
        signature: &str,
    ) -> Self {
        let payload = serde_json::json!({
            "conversation_id": conversation_id,
            "mls_message": mls_message
        });
        Self {
            message_type: "message".into(),
            action: "send".into(),
            sender: sender.into(),
            recipient: recipient.into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Send a message via the discovery server for routing
    pub fn send_via_server(sender: &str, recipient: &str, content: &str, signature: &str) -> Self {
        let payload = serde_json::json!({
            "recipient": recipient,
            "content": content
        });
        Self {
            message_type: "system".into(),
            action: "send".into(),
            sender: sender.into(),
            recipient: "server".into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Create a direct p2p message envelope
    pub fn direct_message(
        sender: &str,
        recipient: &str,
        mls_message: &str,
        conversation_id: &str,
        signature: &str,
    ) -> Self {
        let payload = serde_json::json!({
            "conversation_id": conversation_id,
            "mls_message": mls_message
        });
        Self {
            message_type: "message".into(),
            action: "send".into(),
            sender: sender.into(),
            recipient: recipient.into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Response to challenge
    pub fn challenge_response(
        sender: &str,
        recipient: &str,
        signed_nonce: &str,
        context: &str,
    ) -> Self {
        let payload = serde_json::json!({
            "signature": signed_nonce,
            "context": context
        });

        // Use the appropriate action based on context
        let action = match context {
            "login" => "loginResponse",
            "registration" => "registrationResponse",
            _ => "registrationResponse", // default fallback
        };

        Self {
            message_type: "system".into(),
            action: action.into(),
            sender: sender.into(),
            recipient: recipient.into(),
            payload,
            signature: "placeholder".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Query response from server
    pub fn query_response(
        sender: &str,
        recipient: &str,
        username: &str,
        public_key: &str,
    ) -> Self {
        let payload = serde_json::json!({
            "username": username,
            "publicKey": public_key
        });
        Self {
            message_type: "response".into(),
            action: "queryResponse".into(),
            sender: sender.into(),
            recipient: recipient.into(),
            payload,
            signature: "placeholder".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Send response (acknowledgment) from server
    pub fn send_response(sender: &str, recipient: &str, status: &str) -> Self {
        let payload = serde_json::json!({
            "status": status
        });
        Self {
            message_type: "response".into(),
            action: "sendResponse".into(),
            sender: sender.into(),
            recipient: recipient.into(),
            payload,
            signature: "placeholder".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Registration challenge response from server
    pub fn registration_response(
        sender: &str,
        recipient: &str,
        result: &str,
        context: &str,
    ) -> Self {
        let payload = serde_json::json!({
            "result": result,
            "context": context
        });
        Self {
            message_type: "response".into(),
            action: "challengeResponse".into(),
            sender: sender.into(),
            recipient: recipient.into(),
            payload,
            signature: "placeholder".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Login response from server
    pub fn login_response(sender: &str, recipient: &str, result: &str, context: &str) -> Self {
        let payload = serde_json::json!({
            "result": result,
            "context": context
        });
        Self {
            message_type: "response".into(),
            action: "loginResponse".into(),
            sender: sender.into(),
            recipient: recipient.into(),
            payload,
            signature: "placeholder".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Request key package from another user for MLS group establishment
    pub fn key_package_request(
        sender: &str,
        recipient: &str,
        sender_key_package: &str,
        signature: &str,
    ) -> Self {
        let payload = serde_json::json!({
            "senderKeyPackage": sender_key_package
        });
        Self {
            message_type: "system".into(),
            action: "keyPackageRequest".into(),
            sender: sender.into(),
            recipient: recipient.into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Response with key package for MLS group establishment
    pub fn key_package_response(
        sender: &str,
        recipient: &str,
        sender_key_package: &str,
        recipient_key_package: &str,
        signature: &str,
    ) -> Self {
        let payload = serde_json::json!({
            "senderKeyPackage": sender_key_package,
            "recipientKeyPackage": recipient_key_package
        });
        Self {
            message_type: "system".into(),
            action: "keyPackageResponse".into(),
            sender: sender.into(),
            recipient: recipient.into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Confirm joining MLS group
    pub fn group_join_response(
        sender: &str,
        recipient: &str,
        group_id: &str,
        success: bool,
        signature: &str,
    ) -> Self {
        let payload = serde_json::json!({
            "groupId": group_id,
            "success": success
        });
        Self {
            message_type: "system".into(),
            action: "groupJoinResponse".into(),
            sender: sender.into(),
            recipient: recipient.into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Fetch messages from group server since a cursor
    pub fn fetch_group(sender: &str, last_seen_id: i64, signature: &str) -> Self {
        let payload = serde_json::json!({
            "lastSeenId": last_seen_id
        });
        Self {
            message_type: "system".into(),
            action: "fetchGroup".into(),
            sender: sender.into(),
            recipient: "group-server".into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Send a message to a group server
    pub fn send_group(sender: &str, ciphertext: &str, signature: &str) -> Self {
        let payload = serde_json::json!({
            "ciphertext": ciphertext
        });
        Self {
            message_type: "message".into(),
            action: "sendGroup".into(),
            sender: sender.into(),
            recipient: "group-server".into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Register with a group server using timestamp-based authentication
    /// The signature should be over: "register:{username}:{server_address}:{timestamp}"
    pub fn register_with_group_server(
        username: &str,
        public_key: &str,
        signature: &str,
        timestamp: i64,
        server_address: &str,
    ) -> Self {
        let payload = serde_json::json!({
            "username": username,
            "publicKey": public_key,
            "timestamp": timestamp,
            "serverAddress": server_address
        });
        Self {
            message_type: "system".into(),
            action: "register".into(),
            sender: username.into(),
            recipient: "group-server".into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Create approveGroup message for admin to approve a pending user
    pub fn approve_group_member(
        admin: &str,
        username_to_approve: &str,
        signature: &str,
        group_id: &str,
        timestamp: i64,
    ) -> Self {
        let payload = serde_json::json!({
            "username": username_to_approve,
            "groupId": group_id,
            "timestamp": timestamp
        });
        Self {
            message_type: "system".into(),
            action: "approveGroup".into(),
            sender: admin.into(),
            recipient: "group-server".into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Create MLS encrypted message using unified format
    ///
    /// This version accepts raw bytes for conversation_id and mls_message,
    /// encoding them as base64 in the payload.
    pub fn mls_message_raw(
        sender: &str,
        recipient: &str,
        conversation_id: &[u8],
        mls_message: &[u8],
        signature: &str,
    ) -> Self {
        use base64::Engine;
        let payload = serde_json::json!({
            "conversation_id": base64::engine::general_purpose::STANDARD.encode(conversation_id),
            "mls_message": base64::engine::general_purpose::STANDARD.encode(mls_message)
        });
        Self {
            message_type: "message".into(),
            action: "send".into(),
            sender: sender.into(),
            recipient: recipient.into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Update signature for a message
    pub fn set_signature(&mut self, signature: &str) {
        self.signature = signature.into();
    }

    /// Get payload as JSON string for signing
    pub fn payload_for_signing(&self) -> Result<String> {
        Ok(serde_json::to_string(&self.payload)?)
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    // ========== Welcome Flow Message Builders ==========

    /// Send a Welcome message to invite a user to a group
    ///
    /// This creates a message containing the MLS Welcome that allows the
    /// recipient to join the group.
    ///
    /// # Arguments
    /// * `sender` - The user sending the welcome (group admin)
    /// * `recipient` - The user being invited
    /// * `group_id` - The group identifier
    /// * `cipher_suite` - The cipher suite ID
    /// * `welcome_bytes` - Base64-encoded welcome bytes
    /// * `ratchet_tree` - Optional base64-encoded ratchet tree
    /// * `epoch` - Current epoch
    /// * `welcome_timestamp` - Unix timestamp of welcome creation
    /// * `signature` - PGP signature of the welcome
    pub fn mls_welcome(
        sender: &str,
        recipient: &str,
        group_id: &str,
        cipher_suite: u16,
        welcome_bytes: &str,
        ratchet_tree: Option<&str>,
        epoch: u64,
        welcome_timestamp: u64,
        signature: &str,
    ) -> Self {
        let payload = serde_json::json!({
            "group_id": group_id,
            "cipher_suite": cipher_suite,
            "welcome_bytes": welcome_bytes,
            "ratchet_tree": ratchet_tree,
            "epoch": epoch,
            "timestamp": welcome_timestamp
        });
        Self {
            message_type: "system".into(),
            action: "mlsWelcome".into(),
            sender: sender.into(),
            recipient: recipient.into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Request to join a group (with our KeyPackage)
    ///
    /// This is sent when a user wants to join a group and provides their
    /// KeyPackage for the group admin to add them.
    ///
    /// # Arguments
    /// * `sender` - The user requesting to join
    /// * `group_id` - The group they want to join
    /// * `key_package` - Base64-encoded KeyPackage
    /// * `signature` - PGP signature of the request
    pub fn group_join_request(
        sender: &str,
        group_id: &str,
        key_package: &str,
        signature: &str,
    ) -> Self {
        let payload = serde_json::json!({
            "groupId": group_id,
            "keyPackage": key_package
        });
        Self {
            message_type: "system".into(),
            action: "groupJoinRequest".into(),
            sender: sender.into(),
            recipient: "server".into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Acknowledge receipt of a Welcome message
    ///
    /// Sent after successfully processing a Welcome to confirm group membership.
    ///
    /// # Arguments
    /// * `sender` - The user who joined
    /// * `recipient` - The group admin who sent the welcome
    /// * `group_id` - The group that was joined
    /// * `success` - Whether joining was successful
    /// * `signature` - PGP signature of the acknowledgment
    pub fn welcome_ack(
        sender: &str,
        recipient: &str,
        group_id: &str,
        success: bool,
        signature: &str,
    ) -> Self {
        let payload = serde_json::json!({
            "groupId": group_id,
            "success": success
        });
        Self {
            message_type: "system".into(),
            action: "welcomeAck".into(),
            sender: sender.into(),
            recipient: recipient.into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Invite a user to a group by sending them a notification
    ///
    /// This is used to notify a user that they have been invited and should
    /// provide their KeyPackage to join.
    ///
    /// # Arguments
    /// * `sender` - The group admin sending the invite
    /// * `recipient` - The user being invited
    /// * `group_id` - The group they're being invited to
    /// * `group_name` - Optional human-readable group name
    /// * `signature` - PGP signature of the invite
    pub fn group_invite(
        sender: &str,
        recipient: &str,
        group_id: &str,
        group_name: Option<&str>,
        signature: &str,
    ) -> Self {
        let payload = serde_json::json!({
            "groupId": group_id,
            "groupName": group_name.unwrap_or(group_id)
        });
        Self {
            message_type: "system".into(),
            action: "groupInvite".into(),
            sender: sender.into(),
            recipient: recipient.into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Request a KeyPackage from a user (for adding them to a group)
    ///
    /// # Arguments
    /// * `sender` - The group admin requesting the KeyPackage
    /// * `recipient` - The user to request the KeyPackage from
    /// * `group_id` - The group they'll be added to
    /// * `signature` - PGP signature of the request
    pub fn key_package_for_group(
        sender: &str,
        recipient: &str,
        group_id: &str,
        signature: &str,
    ) -> Self {
        let payload = serde_json::json!({
            "groupId": group_id,
            "purpose": "groupJoin"
        });
        Self {
            message_type: "system".into(),
            action: "keyPackageForGroup".into(),
            sender: sender.into(),
            recipient: recipient.into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Provide a KeyPackage in response to a request (for group joining)
    ///
    /// # Arguments
    /// * `sender` - The user providing their KeyPackage
    /// * `recipient` - The group admin who requested it
    /// * `group_id` - The group to join
    /// * `key_package` - Base64-encoded KeyPackage
    /// * `signature` - PGP signature of the response
    pub fn key_package_for_group_response(
        sender: &str,
        recipient: &str,
        group_id: &str,
        key_package: &str,
        signature: &str,
    ) -> Self {
        let payload = serde_json::json!({
            "groupId": group_id,
            "keyPackage": key_package
        });
        Self {
            message_type: "system".into(),
            action: "keyPackageForGroupResponse".into(),
            sender: sender.into(),
            recipient: recipient.into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ========== MLS Delivery Service Message Builders ==========

    /// Register with a group server including an MLS KeyPackage
    /// This allows the server to store the KeyPackage for later use when
    /// the user is added to groups.
    ///
    /// # Arguments
    /// * `username` - The user registering
    /// * `public_key` - The user's PGP public key (armored)
    /// * `signature` - PGP signature over "register:{username}:{server_address}:{timestamp}"
    /// * `timestamp` - Unix timestamp for replay protection
    /// * `server_address` - The group server's mixnet address
    /// * `key_package` - Optional base64-encoded MLS KeyPackage
    pub fn register_with_group_server_and_key_package(
        username: &str,
        public_key: &str,
        signature: &str,
        timestamp: i64,
        server_address: &str,
        key_package: Option<&str>,
    ) -> Self {
        let mut payload = serde_json::json!({
            "username": username,
            "publicKey": public_key,
            "timestamp": timestamp,
            "serverAddress": server_address
        });
        if let Some(kp) = key_package {
            payload["keyPackage"] = serde_json::json!(kp);
        }
        Self {
            message_type: "system".into(),
            action: "register".into(),
            sender: username.into(),
            recipient: "group-server".into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Store a Welcome message on the group server for a user to fetch later
    ///
    /// # Arguments
    /// * `sender` - The admin/sender storing the welcome
    /// * `group_id` - The MLS group ID
    /// * `target_username` - The user who should receive the Welcome
    /// * `welcome` - Base64-encoded Welcome message
    /// * `signature` - PGP signature over "{group_id}:{target_username}"
    pub fn store_welcome(
        sender: &str,
        group_id: &str,
        target_username: &str,
        welcome: &str,
        signature: &str,
    ) -> Self {
        let payload = serde_json::json!({
            "groupId": group_id,
            "targetUsername": target_username,
            "welcome": welcome
        });
        Self {
            message_type: "system".into(),
            action: "storeWelcome".into(),
            sender: sender.into(),
            recipient: "group-server".into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Fetch pending Welcome messages from the group server
    ///
    /// # Arguments
    /// * `username` - The user fetching their Welcomes
    /// * `group_id` - Optional group ID to filter by
    /// * `signature` - PGP signature over "fetchWelcome:{username}"
    pub fn fetch_welcome(username: &str, group_id: Option<&str>, signature: &str) -> Self {
        let mut payload = serde_json::json!({});
        if let Some(gid) = group_id {
            payload["groupId"] = serde_json::json!(gid);
        }
        Self {
            message_type: "system".into(),
            action: "fetchWelcome".into(),
            sender: username.into(),
            recipient: "group-server".into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Request epoch sync from the group server
    /// Returns all commits since the given epoch for catch-up
    ///
    /// # Arguments
    /// * `username` - The user requesting sync
    /// * `group_id` - The MLS group ID
    /// * `since_epoch` - The epoch to sync from (exclusive)
    /// * `signature` - PGP signature over "{group_id}:{since_epoch}"
    pub fn sync_epoch(
        username: &str,
        group_id: &str,
        since_epoch: i64,
        signature: &str,
    ) -> Self {
        let payload = serde_json::json!({
            "groupId": group_id,
            "sinceEpoch": since_epoch
        });
        Self {
            message_type: "system".into(),
            action: "syncEpoch".into(),
            sender: username.into(),
            recipient: "group-server".into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Buffer a commit message on the group server for epoch sync
    /// This allows late joiners to catch up on missed commits
    ///
    /// # Arguments
    /// * `username` - The user buffering the commit
    /// * `group_id` - The MLS group ID
    /// * `epoch` - The epoch of this commit
    /// * `commit` - Base64-encoded commit message
    /// * `signature` - PGP signature over "{group_id}:{epoch}"
    pub fn buffer_commit(
        username: &str,
        group_id: &str,
        epoch: i64,
        commit: &str,
        signature: &str,
    ) -> Self {
        let payload = serde_json::json!({
            "groupId": group_id,
            "epoch": epoch,
            "commit": commit
        });
        Self {
            message_type: "system".into(),
            action: "bufferCommit".into(),
            sender: username.into(),
            recipient: "group-server".into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Query pending users awaiting approval from the group server (admin only)
    ///
    /// # Arguments
    /// * `admin` - The admin username making the query
    /// * `signature` - PGP signature over "queryPendingUsers"
    pub fn query_pending_users(admin: &str, signature: &str) -> Self {
        let payload = serde_json::json!({});
        Self {
            message_type: "system".into(),
            action: "queryPendingUsers".into(),
            sender: admin.into(),
            recipient: "group-server".into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_message() {
        let msg = MixnetMessage::query("alice", "bob");
        assert_eq!(msg.message_type, "system");
        assert_eq!(msg.action, "query");
        assert_eq!(msg.sender, "alice");
        assert_eq!(msg.recipient, "server");
        assert_eq!(msg.payload["username"], "bob");
    }

    #[test]
    fn test_register_message() {
        let msg = MixnetMessage::register("bob", "pk_bob");
        assert_eq!(msg.message_type, "system");
        assert_eq!(msg.action, "register");
        assert_eq!(msg.sender, "bob");
        assert_eq!(msg.recipient, "server");
        assert_eq!(msg.payload["username"], "bob");
        assert_eq!(msg.payload["publicKey"], "pk_bob");
    }

    #[test]
    fn test_login_message() {
        let msg = MixnetMessage::login("charlie");
        assert_eq!(msg.message_type, "system");
        assert_eq!(msg.action, "login");
        assert_eq!(msg.sender, "charlie");
        assert_eq!(msg.recipient, "server");
        assert_eq!(msg.payload["username"], "charlie");
    }

    #[test]
    fn test_send_message() {
        let msg = MixnetMessage::send("alice", "bob", "encrypted_content", "conv123", "sig456");
        assert_eq!(msg.message_type, "message");
        assert_eq!(msg.action, "send");
        assert_eq!(msg.sender, "alice");
        assert_eq!(msg.recipient, "bob");
        assert_eq!(msg.payload["conversation_id"], "conv123");
        assert_eq!(msg.payload["mls_message"], "encrypted_content");
        assert_eq!(msg.signature, "sig456");
    }

    #[test]
    fn test_challenge_message() {
        let msg = MixnetMessage::challenge("server", "alice", "nonce123", "registration");
        assert_eq!(msg.message_type, "system");
        assert_eq!(msg.action, "challenge");
        assert_eq!(msg.sender, "server");
        assert_eq!(msg.recipient, "alice");
        assert_eq!(msg.payload["nonce"], "nonce123");
        assert_eq!(msg.payload["context"], "registration");
    }

    #[test]
    fn test_challenge_response_message() {
        let msg =
            MixnetMessage::challenge_response("alice", "server", "signed_nonce", "registration");
        assert_eq!(msg.message_type, "system");
        assert_eq!(msg.action, "registrationResponse");
        assert_eq!(msg.sender, "alice");
        assert_eq!(msg.recipient, "server");
        assert_eq!(msg.payload["signature"], "signed_nonce");
        assert_eq!(msg.payload["context"], "registration");
    }

    #[test]
    fn test_query_response_message() {
        let msg = MixnetMessage::query_response("server", "alice", "bob", "pk_bob");
        assert_eq!(msg.message_type, "response");
        assert_eq!(msg.action, "queryResponse");
        assert_eq!(msg.sender, "server");
        assert_eq!(msg.recipient, "alice");
        assert_eq!(msg.payload["username"], "bob");
        assert_eq!(msg.payload["publicKey"], "pk_bob");
    }

    #[test]
    fn test_registration_response_message() {
        let msg =
            MixnetMessage::registration_response("server", "alice", "success", "registration");
        assert_eq!(msg.message_type, "response");
        assert_eq!(msg.action, "challengeResponse");
        assert_eq!(msg.sender, "server");
        assert_eq!(msg.recipient, "alice");
        assert_eq!(msg.payload["result"], "success");
        assert_eq!(msg.payload["context"], "registration");
    }

    #[test]
    fn test_set_signature() {
        let mut msg = MixnetMessage::query("alice", "bob");
        assert_eq!(msg.signature, "placeholder");
        msg.set_signature("real_signature");
        assert_eq!(msg.signature, "real_signature");
    }

    #[test]
    fn test_payload_for_signing() {
        let msg = MixnetMessage::query("alice", "bob");
        let payload_str = msg.payload_for_signing().unwrap();
        assert!(payload_str.contains("\"username\":\"bob\""));
    }

    #[test]
    fn test_unified_format_serialization() {
        let msg = MixnetMessage::send("alice", "bob", "encrypted_content", "conv123", "sig456");
        let json = msg.to_json().unwrap();

        assert!(json.contains("\"type\":\"message\""));
        assert!(json.contains("\"action\":\"send\""));
        assert!(json.contains("\"sender\":\"alice\""));
        assert!(json.contains("\"recipient\":\"bob\""));
        assert!(json.contains("\"payload\""));
        assert!(json.contains("\"signature\":\"sig456\""));
        assert!(json.contains("\"timestamp\""));
    }

    #[test]
    fn test_unified_format_deserialization() {
        let json = r#"{"type":"system","action":"query","sender":"alice","recipient":"server","payload":{"username":"bob"},"signature":"sig","timestamp":"2025-09-14T22:30:00Z"}"#;
        let msg: MixnetMessage = serde_json::from_str(json).unwrap();

        assert_eq!(msg.message_type, "system");
        assert_eq!(msg.action, "query");
        assert_eq!(msg.sender, "alice");
        assert_eq!(msg.recipient, "server");
        assert_eq!(msg.payload["username"], "bob");
        assert_eq!(msg.signature, "sig");
    }
}
