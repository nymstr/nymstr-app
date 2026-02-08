//! Event system for real-time updates from Rust to frontend
//!
//! This module handles emitting events to the frontend for
//! incoming messages, connection status changes, and other
//! real-time updates.

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

use crate::types::MessageDTO;

/// All possible events that can be emitted to the frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum AppEvent {
    /// Mixnet connection established
    MixnetConnected { address: String },

    /// Mixnet connection lost
    MixnetDisconnected { reason: String },

    /// New message received
    MessageReceived {
        #[serde(flatten)]
        message: MessageDTO,
        #[serde(rename = "conversationId")]
        conversation_id: String,
    },

    /// Message sent successfully
    MessageSent { id: String },

    /// Message delivered to recipient
    MessageDelivered { id: String },

    /// Message failed to send
    MessageFailed { id: String, error: String },

    /// Contact came online
    ContactOnline { username: String, online: bool },

    // ========== Authentication Events ==========

    /// Server sent a challenge for authentication
    AuthChallenge {
        /// The username being authenticated
        username: String,
        /// Context: "registration" or "login"
        context: String,
    },

    /// Registration completed successfully
    RegistrationSuccess {
        /// The registered username
        username: String,
    },

    /// Registration failed
    RegistrationFailed {
        /// The username that failed to register
        username: String,
        /// Error message
        error: String,
    },

    /// Login completed successfully
    LoginSuccess {
        /// The logged-in username
        username: String,
    },

    /// Login failed
    LoginFailed {
        /// The username that failed to login
        username: String,
        /// Error message
        error: String,
    },

    // ========== Group Events ==========

    /// Group messages received from server
    GroupMessagesReceived {
        /// Number of messages received
        count: u32,
    },

    /// Group registration is pending admin approval
    GroupRegistrationPending,

    /// Group registration succeeded
    GroupRegistrationSuccess,

    /// Group registration failed
    GroupRegistrationFailed {
        /// Error message
        error: String,
    },

    // ========== Welcome/Invite Events ==========

    /// Welcome message received for joining a group
    WelcomeReceived {
        /// The group ID
        group_id: String,
        /// Who sent the welcome
        sender: String,
    },

    /// Group invite received
    GroupInviteReceived {
        /// The group ID
        group_id: String,
        /// Optional group name
        group_name: Option<String>,
        /// Who sent the invite
        sender: String,
    },

    /// Successfully joined a group via Welcome message
    GroupJoined {
        /// The group ID from the welcome
        group_id: String,
        /// The MLS group ID (used for encryption)
        mls_group_id: String,
        /// Who sent the welcome
        sender: String,
    },

    /// Contact request received (someone wants to DM us)
    ContactRequestReceived {
        /// The username of the requester
        username: String,
    },

    /// 1:1 DM conversation fully established (both sides ready)
    ConversationEstablished {
        /// The normalized conversation ID (dm:alice:bob)
        conversation_id: String,
        /// The peer username
        peer: String,
    },

    // ========== System Events ==========

    /// System notification message
    SystemNotification {
        /// The notification message
        message: String,
    },

    /// Background tasks started
    BackgroundTasksStarted,

    /// Background tasks stopped
    BackgroundTasksStopped,

    /// Pending messages delivered from offline queue
    PendingMessagesDelivered {
        /// Number of messages delivered
        count: u32,
    },
}

/// Event emitter helper
pub struct EventEmitter {
    app_handle: AppHandle,
}

impl EventEmitter {
    pub fn new(app_handle: AppHandle) -> Self {
        Self { app_handle }
    }

    /// Emit an event to all windows
    pub fn emit(&self, event: AppEvent) {
        if let Err(e) = self.app_handle.emit("app-event", &event) {
            tracing::error!("Failed to emit event: {}", e);
        }
    }

    /// Emit a connection established event
    pub fn connected(&self, address: String) {
        self.emit(AppEvent::MixnetConnected { address });
    }

    /// Emit a connection lost event
    pub fn disconnected(&self, reason: String) {
        self.emit(AppEvent::MixnetDisconnected { reason });
    }

    /// Emit a message received event
    pub fn message_received(&self, message: MessageDTO, conversation_id: String) {
        self.emit(AppEvent::MessageReceived {
            message,
            conversation_id,
        });
    }

    /// Emit a message sent event
    pub fn message_sent(&self, id: String) {
        self.emit(AppEvent::MessageSent { id });
    }

    /// Emit a message delivered event
    pub fn message_delivered(&self, id: String) {
        self.emit(AppEvent::MessageDelivered { id });
    }

    /// Emit a message failed event
    pub fn message_failed(&self, id: String, error: String) {
        self.emit(AppEvent::MessageFailed { id, error });
    }

    /// Emit a contact online status event
    pub fn contact_online(&self, username: String, online: bool) {
        self.emit(AppEvent::ContactOnline { username, online });
    }

    // ========== Authentication Event Helpers ==========

    /// Emit an authentication challenge event
    pub fn auth_challenge(&self, username: String, context: String) {
        self.emit(AppEvent::AuthChallenge { username, context });
    }

    /// Emit a registration success event
    pub fn registration_success(&self, username: String) {
        self.emit(AppEvent::RegistrationSuccess { username });
    }

    /// Emit a registration failed event
    pub fn registration_failed(&self, username: String, error: String) {
        self.emit(AppEvent::RegistrationFailed { username, error });
    }

    /// Emit a login success event
    pub fn login_success(&self, username: String) {
        self.emit(AppEvent::LoginSuccess { username });
    }

    /// Emit a login failed event
    pub fn login_failed(&self, username: String, error: String) {
        self.emit(AppEvent::LoginFailed { username, error });
    }

    // ========== Group Event Helpers ==========

    /// Emit a group messages received event
    pub fn group_messages_received(&self, count: u32) {
        self.emit(AppEvent::GroupMessagesReceived { count });
    }

    /// Emit a group registration pending event
    pub fn group_registration_pending(&self) {
        self.emit(AppEvent::GroupRegistrationPending);
    }

    /// Emit a group registration success event
    pub fn group_registration_success(&self) {
        self.emit(AppEvent::GroupRegistrationSuccess);
    }

    /// Emit a group registration failed event
    pub fn group_registration_failed(&self, error: String) {
        self.emit(AppEvent::GroupRegistrationFailed { error });
    }

    // ========== Welcome/Invite Event Helpers ==========

    /// Emit a welcome received event
    pub fn welcome_received(&self, group_id: String, sender: String) {
        self.emit(AppEvent::WelcomeReceived { group_id, sender });
    }

    /// Emit a group invite received event
    pub fn group_invite_received(&self, group_id: String, group_name: Option<String>, sender: String) {
        self.emit(AppEvent::GroupInviteReceived {
            group_id,
            group_name,
            sender,
        });
    }

    /// Emit a group joined event (after processing Welcome)
    pub fn group_joined(&self, group_id: String, mls_group_id: String, sender: String) {
        self.emit(AppEvent::GroupJoined {
            group_id,
            mls_group_id,
            sender,
        });
    }

    /// Emit a contact request received event
    pub fn contact_request_received(&self, username: String) {
        self.emit(AppEvent::ContactRequestReceived { username });
    }

    // ========== System Event Helpers ==========

    /// Emit a system notification event
    pub fn system_notification(&self, message: String) {
        self.emit(AppEvent::SystemNotification { message });
    }

    /// Emit a background tasks started event
    pub fn background_tasks_started(&self) {
        self.emit(AppEvent::BackgroundTasksStarted);
    }

    /// Emit a background tasks stopped event
    pub fn background_tasks_stopped(&self) {
        self.emit(AppEvent::BackgroundTasksStopped);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::MessageStatus;

    #[test]
    fn test_message_received_serialization() {
        let event = AppEvent::MessageReceived {
            message: MessageDTO {
                id: "test-id".to_string(),
                sender: "terry10".to_string(),
                content: "yoooo".to_string(),
                timestamp: "2026-02-07T00:00:00Z".to_string(),
                status: MessageStatus::Delivered,
                is_own: false,
                is_read: false,
            },
            conversation_id: "dm:raider:terry10".to_string(),
        };

        let json = serde_json::to_value(&event).unwrap();

        // Check adjacently-tagged envelope
        assert_eq!(json["type"], "MessageReceived");

        // Check payload has flattened MessageDTO fields + conversationId
        let payload = &json["payload"];
        assert_eq!(payload["id"], "test-id");
        assert_eq!(payload["sender"], "terry10");
        assert_eq!(payload["content"], "yoooo");
        assert_eq!(payload["status"], "delivered");
        assert_eq!(payload["isOwn"], false);
        assert_eq!(payload["isRead"], false);
        assert_eq!(payload["conversationId"], "dm:raider:terry10");
    }
}
