//! Type definitions for the Tauri IPC layer
//!
//! These types are serialized/deserialized for communication between
//! the Rust backend and TypeScript frontend.

use serde::{Deserialize, Serialize};

/// User data transfer object
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserDTO {
    pub username: String,
    pub display_name: String,
    pub public_key: String,
    pub online: bool,
}

/// Contact data transfer object
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactDTO {
    pub username: String,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub last_seen: Option<String>,
    pub unread_count: u32,
    pub online: bool,
}

/// Message status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageStatus {
    Pending,
    Sent,
    Delivered,
    Read,
    Failed,
}

/// Message data transfer object
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageDTO {
    pub id: String,
    pub sender: String,
    pub content: String,
    pub timestamp: String,
    pub status: MessageStatus,
    pub is_own: bool,
}

/// Group data transfer object
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupDTO {
    pub id: String,
    pub name: String,
    pub address: String,
    pub member_count: u32,
    pub is_public: bool,
    pub description: Option<String>,
}

/// Connection status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionStatus {
    pub connected: bool,
    pub mixnet_address: Option<String>,
}

/// Initialize response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResponse {
    pub has_user: bool,
    pub username: Option<String>,
}

/// API error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

impl ApiError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new("INTERNAL_ERROR", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new("NOT_FOUND", message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new("UNAUTHORIZED", message)
    }

    pub fn validation(message: impl Into<String>) -> Self {
        Self::new("VALIDATION_ERROR", message)
    }

    pub fn authentication(message: impl Into<String>) -> Self {
        Self::new("AUTHENTICATION_ERROR", message)
    }

    pub fn not_connected(message: impl Into<String>) -> Self {
        Self::new("NOT_CONNECTED", message)
    }

    pub fn timeout(message: impl Into<String>) -> Self {
        Self::new("TIMEOUT", message)
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        Self::internal(err.to_string())
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
