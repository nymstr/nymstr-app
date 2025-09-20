//! MLS message types and data structures

use serde::{Deserialize, Serialize};

/// MLS encrypted message format
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedMessage {
    pub conversation_id: Vec<u8>, // Group ID for both 1:1 and group chats
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

