use crate::model::Id;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub sender: Id,
    pub content: String,
    pub timestamp: DateTime<Utc>,
}

impl Message {
    pub fn new(sender: &str, content: &str) -> Self {
        Self {
            sender: sender.to_string(),
            content: content.to_string(),
            timestamp: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_message_new() {
        let message = Message::new("alice", "Hello world!");
        assert_eq!(message.sender, "alice");
        assert_eq!(message.content, "Hello world!");
        assert!(message.timestamp <= Utc::now());
    }

    #[test]
    fn test_message_fields() {
        let mut message = Message::new("bob", "Initial message");
        assert_eq!(message.sender, "bob");
        assert_eq!(message.content, "Initial message");

        message.content = "Updated message".to_string();
        assert_eq!(message.content, "Updated message");
        assert_eq!(message.sender, "bob");
    }

    #[test]
    fn test_message_clone() {
        let message1 = Message::new("charlie", "Test message");
        let message2 = message1.clone();

        assert_eq!(message1, message2);
        assert_eq!(message1.sender, message2.sender);
        assert_eq!(message1.content, message2.content);
        assert_eq!(message1.timestamp, message2.timestamp);
    }

    #[test]
    fn test_message_equality() {
        let timestamp = Utc::now();
        let message1 = Message {
            sender: "dave".to_string(),
            content: "Same content".to_string(),
            timestamp,
        };
        let message2 = Message {
            sender: "dave".to_string(),
            content: "Same content".to_string(),
            timestamp,
        };
        let message3 = Message {
            sender: "eve".to_string(),
            content: "Different content".to_string(),
            timestamp,
        };

        assert_eq!(message1, message2);
        assert_ne!(message1, message3);
    }

    #[test]
    fn test_message_debug() {
        let message = Message::new("frank", "Debug test");
        let debug_str = format!("{:?}", message);
        assert!(debug_str.contains("Message"));
        assert!(debug_str.contains("frank"));
        assert!(debug_str.contains("Debug test"));
    }

    #[test]
    fn test_message_with_empty_content() {
        let message = Message::new("user", "");
        assert_eq!(message.sender, "user");
        assert_eq!(message.content, "");
        assert!(message.timestamp <= Utc::now());
    }

    #[test]
    fn test_message_with_empty_sender() {
        let message = Message::new("", "Message content");
        assert_eq!(message.sender, "");
        assert_eq!(message.content, "Message content");
        assert!(message.timestamp <= Utc::now());
    }

    #[test]
    fn test_message_with_special_characters() {
        let message = Message::new("user@example.com", "Message with @#$%^&*()");
        assert_eq!(message.sender, "user@example.com");
        assert_eq!(message.content, "Message with @#$%^&*()");
    }

    #[test]
    fn test_message_with_unicode() {
        let message = Message::new("用户", "消息内容 🦀 Rust");
        assert_eq!(message.sender, "用户");
        assert_eq!(message.content, "消息内容 🦀 Rust");
    }

    #[test]
    fn test_message_with_long_content() {
        let long_content = "x".repeat(1000);
        let message = Message::new("sender", &long_content);
        assert_eq!(message.sender, "sender");
        assert_eq!(message.content, long_content);
        assert_eq!(message.content.len(), 1000);
    }

    #[test]
    fn test_message_timestamp_ordering() {
        let message1 = Message::new("user1", "First message");
        std::thread::sleep(std::time::Duration::from_millis(1));
        let message2 = Message::new("user2", "Second message");

        assert!(message1.timestamp < message2.timestamp);
    }

    #[test]
    fn test_message_modification() {
        let mut message = Message {
            sender: "original_sender".to_string(),
            content: "original_content".to_string(),
            timestamp: Utc::now(),
        };

        message.sender = "modified_sender".to_string();
        message.content = "modified_content".to_string();

        assert_eq!(message.sender, "modified_sender");
        assert_eq!(message.content, "modified_content");
    }

    #[test]
    fn test_message_partial_eq() {
        let timestamp = Utc::now();
        let message1 = Message {
            sender: "test".to_string(),
            content: "content".to_string(),
            timestamp,
        };

        let message2 = Message {
            sender: "test".to_string(),
            content: "content".to_string(),
            timestamp,
        };

        let message3 = Message {
            sender: "test".to_string(),
            content: "different".to_string(),
            timestamp,
        };

        assert_eq!(message1, message2);
        assert_ne!(message1, message3);
    }
}
