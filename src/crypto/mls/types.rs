//! MLS message types and data structures

use serde::{Deserialize, Serialize};

/// MLS encrypted message format
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedMessage {
    pub conversation_id: Vec<u8>, // Group ID for both 1:1 and group chats
    pub mls_message: Vec<u8>,
    pub message_type: MlsMessageType,
}

/// MLS group message format
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MlsGroupMessage {
    pub group_id: Vec<u8>,
    pub mls_message: Vec<u8>,
    pub message_type: MlsMessageType,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum MlsMessageType {
    Commit,
    Application,
    Welcome,
    KeyPackage,
}

/// MLS group information
#[derive(Debug, Clone)]
pub struct MlsGroupInfo {
    pub group_id: Vec<u8>,
    pub client_identity: String,
}

/// Conversation information for both 1:1 and group chats
#[derive(Debug, Clone)]
pub struct ConversationInfo {
    pub conversation_id: Vec<u8>,
    pub conversation_type: ConversationType,
    pub participants: u32,
    pub welcome_message: Option<Vec<u8>>, // For inviting others
    pub group_info: MlsGroupInfo,
}

/// Type of conversation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConversationType {
    OneToOne,
    Group,
}