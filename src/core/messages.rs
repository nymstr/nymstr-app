//! Definition and serialization of mixnet envelope messages
#![allow(dead_code)]
use anyhow::Result;
use serde::{Deserialize, Serialize};
use chrono;
use base64;

/// Unified message format for all Nymstr communications
#[derive(Serialize, Deserialize, Debug)]
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
    pub fn send(sender: &str, recipient: &str, mls_message: &str, conversation_id: &str, signature: &str) -> Self {
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
    pub fn direct_message(sender: &str, recipient: &str, mls_message: &str, conversation_id: &str, signature: &str) -> Self {
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
    pub fn challenge_response(sender: &str, recipient: &str, signed_nonce: &str, context: &str) -> Self {
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
    pub fn query_response(sender: &str, recipient: &str, username: &str, public_key: &str) -> Self {
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
    pub fn registration_response(sender: &str, recipient: &str, result: &str, context: &str) -> Self {
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
    pub fn key_package_request(sender: &str, recipient: &str, sender_key_package: &str, signature: &str) -> Self {
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
    pub fn key_package_response(sender: &str, recipient: &str, sender_key_package: &str, recipient_key_package: &str, signature: &str) -> Self {
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

    /// Send MLS group welcome message to establish shared group
    pub fn group_welcome(sender: &str, recipient: &str, welcome_message: &str, group_id: &str, signature: &str) -> Self {
        let payload = serde_json::json!({
            "welcomeMessage": welcome_message,
            "groupId": group_id
        });
        Self {
            message_type: "system".into(),
            action: "groupWelcome".into(),
            sender: sender.into(),
            recipient: recipient.into(),
            payload,
            signature: signature.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Confirm joining MLS group
    pub fn group_join_response(sender: &str, recipient: &str, group_id: &str, success: bool, signature: &str) -> Self {
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

    /// Create MLS encrypted message using unified format
    pub fn mls_message(sender: &str, recipient: &str, encrypted_message: &crate::crypto::EncryptedMessage, signature: &str) -> Self {
        let payload = serde_json::json!({
            "conversation_id": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encrypted_message.conversation_id),
            "mls_message": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encrypted_message.mls_message)
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
        let msg = MixnetMessage::challenge_response("alice", "server", "signed_nonce", "registration");
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
        let msg = MixnetMessage::registration_response("server", "alice", "success", "registration");
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
