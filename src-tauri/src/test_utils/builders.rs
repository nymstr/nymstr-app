//! Builder patterns for constructing test data
//!
//! Provides fluent builder APIs for creating test objects with sensible defaults.

use crate::core::messages::MixnetMessage;
use crate::types::{MessageDTO, MessageStatus};

/// Builder for creating test MixnetMessage objects
#[derive(Debug, Clone)]
pub struct MixnetMessageBuilder {
    message_type: String,
    action: String,
    sender: String,
    recipient: String,
    payload: serde_json::Value,
    signature: String,
    timestamp: String,
}

impl MixnetMessageBuilder {
    /// Create a new builder with default values
    pub fn new() -> Self {
        Self {
            message_type: "message".into(),
            action: "send".into(),
            sender: "test_sender".into(),
            recipient: "test_recipient".into(),
            payload: serde_json::json!({}),
            signature: "test_signature".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Create a system message builder
    pub fn system() -> Self {
        Self::new().message_type("system")
    }

    /// Create a response message builder
    pub fn response() -> Self {
        Self::new().message_type("response")
    }

    /// Set the message type
    pub fn message_type(mut self, message_type: &str) -> Self {
        self.message_type = message_type.into();
        self
    }

    /// Set the action
    pub fn action(mut self, action: &str) -> Self {
        self.action = action.into();
        self
    }

    /// Set the sender
    pub fn sender(mut self, sender: &str) -> Self {
        self.sender = sender.into();
        self
    }

    /// Set the recipient
    pub fn recipient(mut self, recipient: &str) -> Self {
        self.recipient = recipient.into();
        self
    }

    /// Set the payload
    pub fn payload(mut self, payload: serde_json::Value) -> Self {
        self.payload = payload;
        self
    }

    /// Set a payload field
    pub fn payload_field(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        if let serde_json::Value::Object(ref mut map) = self.payload {
            map.insert(key.to_string(), value.into());
        }
        self
    }

    /// Set the signature
    pub fn signature(mut self, signature: &str) -> Self {
        self.signature = signature.into();
        self
    }

    /// Set the timestamp
    pub fn timestamp(mut self, timestamp: &str) -> Self {
        self.timestamp = timestamp.into();
        self
    }

    /// Build the MixnetMessage
    pub fn build(self) -> MixnetMessage {
        MixnetMessage {
            message_type: self.message_type,
            action: self.action,
            sender: self.sender,
            recipient: self.recipient,
            payload: self.payload,
            signature: self.signature,
            timestamp: self.timestamp,
        }
    }
}

impl Default for MixnetMessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating test MessageDTO objects
#[derive(Debug, Clone)]
pub struct MessageDTOBuilder {
    id: String,
    sender: String,
    content: String,
    timestamp: String,
    status: MessageStatus,
    is_own: bool,
}

impl MessageDTOBuilder {
    /// Create a new builder with default values
    pub fn new() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            sender: "test_sender".into(),
            content: "Test message content".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            status: MessageStatus::Delivered,
            is_own: false,
        }
    }

    /// Create an outgoing message builder
    pub fn outgoing() -> Self {
        Self::new().is_own(true).status(MessageStatus::Sent)
    }

    /// Create an incoming message builder
    pub fn incoming() -> Self {
        Self::new().is_own(false).status(MessageStatus::Delivered)
    }

    /// Set the message ID
    pub fn id(mut self, id: &str) -> Self {
        self.id = id.into();
        self
    }

    /// Set the sender
    pub fn sender(mut self, sender: &str) -> Self {
        self.sender = sender.into();
        self
    }

    /// Set the content
    pub fn content(mut self, content: &str) -> Self {
        self.content = content.into();
        self
    }

    /// Set the timestamp
    pub fn timestamp(mut self, timestamp: &str) -> Self {
        self.timestamp = timestamp.into();
        self
    }

    /// Set the status
    pub fn status(mut self, status: MessageStatus) -> Self {
        self.status = status;
        self
    }

    /// Set whether this is an own message
    pub fn is_own(mut self, is_own: bool) -> Self {
        self.is_own = is_own;
        self
    }

    /// Build the MessageDTO
    pub fn build(self) -> MessageDTO {
        MessageDTO {
            id: self.id,
            sender: self.sender,
            content: self.content,
            timestamp: self.timestamp,
            status: self.status,
            is_own: self.is_own,
        }
    }
}

impl Default for MessageDTOBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating test user tuples
#[derive(Debug, Clone)]
pub struct UserBuilder {
    username: String,
    display_name: Option<String>,
    public_key: String,
}

impl UserBuilder {
    /// Create a new builder with default values
    pub fn new(username: &str) -> Self {
        Self {
            username: username.into(),
            display_name: None,
            public_key: format!("pk_{}", username),
        }
    }

    /// Set the display name
    pub fn display_name(mut self, name: &str) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Set the public key
    pub fn public_key(mut self, key: &str) -> Self {
        self.public_key = key.into();
        self
    }

    /// Build as a tuple (username, public_key)
    pub fn build_tuple(&self) -> (String, String) {
        (self.username.clone(), self.public_key.clone())
    }

    /// Build as a triple (username, display_name, public_key)
    pub fn build_triple(&self) -> (String, String, String) {
        (
            self.username.clone(),
            self.display_name
                .clone()
                .unwrap_or_else(|| self.username.clone()),
            self.public_key.clone(),
        )
    }
}

/// Builder for creating test group data
#[derive(Debug, Clone)]
pub struct GroupBuilder {
    id: String,
    name: String,
    address: String,
    member_count: i32,
    is_public: bool,
    description: Option<String>,
}

impl GroupBuilder {
    /// Create a new builder with default values
    pub fn new(name: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.into(),
            address: format!("group-server-{}", uuid::Uuid::new_v4()),
            member_count: 1,
            is_public: true,
            description: None,
        }
    }

    /// Set the group ID
    pub fn id(mut self, id: &str) -> Self {
        self.id = id.into();
        self
    }

    /// Set the server address
    pub fn address(mut self, address: &str) -> Self {
        self.address = address.into();
        self
    }

    /// Set the member count
    pub fn member_count(mut self, count: i32) -> Self {
        self.member_count = count;
        self
    }

    /// Set whether the group is public
    pub fn public(mut self, is_public: bool) -> Self {
        self.is_public = is_public;
        self
    }

    /// Set the description
    pub fn description(mut self, desc: &str) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Get the group ID
    pub fn get_id(&self) -> &str {
        &self.id
    }

    /// Get the server address
    pub fn get_address(&self) -> &str {
        &self.address
    }

    /// Get the name
    pub fn get_name(&self) -> &str {
        &self.name
    }
}

/// Builder for creating challenge messages
pub struct ChallengeBuilder {
    sender: String,
    recipient: String,
    nonce: String,
    context: String,
}

impl ChallengeBuilder {
    /// Create a new challenge builder
    pub fn new() -> Self {
        Self {
            sender: "server".into(),
            recipient: "test_user".into(),
            nonce: uuid::Uuid::new_v4().to_string(),
            context: "registration".into(),
        }
    }

    /// Create for registration context
    pub fn registration(recipient: &str) -> Self {
        Self::new().recipient(recipient).context("registration")
    }

    /// Create for login context
    pub fn login(recipient: &str) -> Self {
        Self::new().recipient(recipient).context("login")
    }

    /// Set the sender
    pub fn sender(mut self, sender: &str) -> Self {
        self.sender = sender.into();
        self
    }

    /// Set the recipient
    pub fn recipient(mut self, recipient: &str) -> Self {
        self.recipient = recipient.into();
        self
    }

    /// Set the nonce
    pub fn nonce(mut self, nonce: &str) -> Self {
        self.nonce = nonce.into();
        self
    }

    /// Set the context
    pub fn context(mut self, context: &str) -> Self {
        self.context = context.into();
        self
    }

    /// Build the challenge message
    pub fn build(self) -> MixnetMessage {
        MixnetMessage::challenge(&self.sender, &self.recipient, &self.nonce, &self.context)
    }

    /// Get the nonce for signing
    pub fn get_nonce(&self) -> &str {
        &self.nonce
    }
}

impl Default for ChallengeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mixnet_message_builder() {
        let msg = MixnetMessageBuilder::new()
            .action("test_action")
            .sender("alice")
            .recipient("bob")
            .payload_field("key", "value")
            .build();

        assert_eq!(msg.action, "test_action");
        assert_eq!(msg.sender, "alice");
        assert_eq!(msg.recipient, "bob");
        assert_eq!(msg.payload["key"], "value");
    }

    #[test]
    fn test_message_dto_builder() {
        let msg = MessageDTOBuilder::outgoing()
            .sender("alice")
            .content("Hello!")
            .build();

        assert_eq!(msg.sender, "alice");
        assert_eq!(msg.content, "Hello!");
        assert!(msg.is_own);
    }

    #[test]
    fn test_user_builder() {
        let user = UserBuilder::new("alice")
            .display_name("Alice")
            .public_key("custom_pk");

        let (username, pk) = user.build_tuple();
        assert_eq!(username, "alice");
        assert_eq!(pk, "custom_pk");
    }

    #[test]
    fn test_group_builder() {
        let group = GroupBuilder::new("Test Group")
            .member_count(5)
            .public(true)
            .description("A test group");

        assert_eq!(group.get_name(), "Test Group");
        assert!(!group.get_id().is_empty());
        assert!(!group.get_address().is_empty());
    }

    #[test]
    fn test_challenge_builder() {
        let challenge = ChallengeBuilder::registration("alice");
        let nonce = challenge.get_nonce().to_string();
        let msg = challenge.build();

        assert_eq!(msg.action, "challenge");
        assert_eq!(msg.recipient, "alice");
        assert_eq!(msg.payload["context"], "registration");
        assert_eq!(msg.payload["nonce"], nonce);
    }
}
