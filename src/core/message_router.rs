//! Message routing logic - pure routing with no dependencies
//!
//! Routes incoming messages to appropriate handlers based on action type.

use crate::core::mixnet_client::Incoming;

/// Different types of messages that can be routed
#[derive(Debug, PartialEq)]
#[allow(dead_code)] // Some variants used for future routing
pub enum MessageRoute {
    /// Authentication-related messages (challenge, loginResponse, etc.)
    Authentication,
    /// MLS protocol messages (keyPackageRequest, groupWelcome, etc.)
    MlsProtocol,
    /// Regular chat messages (send, incomingMessage)
    Chat,
    /// Handshake establishment messages
    Handshake,
    /// Query/lookup operations
    Query,
    /// Group server operations (fetchGroupResponse, sendGroupResponse, etc.)
    Group,
    /// MLS Welcome flow messages (mlsWelcome, groupInvite, groupJoinRequest, etc.)
    WelcomeFlow,
    /// Unknown or unsupported message types
    Unknown,
}

/// Pure message router - no side effects, just determines routing
pub struct MessageRouter;

impl MessageRouter {
    /// Route an incoming message to determine which handler should process it
    pub fn route_message(incoming: &Incoming) -> MessageRoute {
        match incoming.envelope.action.as_str() {
            // Authentication flow messages
            "challenge" | "challengeResponse" | "loginResponse" | "sendResponse" => {
                MessageRoute::Authentication
            }

            // MLS protocol messages (key package exchange)
            "keyPackageRequest" | "groupWelcome" => {
                MessageRoute::MlsProtocol
            }

            // MLS Welcome flow messages (group invitation and joining)
            "mlsWelcome" | "groupInvite" | "groupJoinRequest" | "welcomeAck"
            | "keyPackageForGroup" | "keyPackageForGroupResponse" => {
                MessageRoute::WelcomeFlow
            }

            // MLS chat messages (all messages use MLS now)
            "send" | "incomingMessage" => {
                MessageRoute::MlsProtocol
            }

            // Handshake for P2P discovery
            "handshake" => {
                MessageRoute::Handshake
            }

            // Query operations
            "queryResponse" => {
                MessageRoute::Query
            }

            // Group server responses
            "fetchGroupResponse" | "sendGroupResponse" | "registerResponse" | "approveGroupResponse" => {
                MessageRoute::Group
            }

            // Unknown message type
            _ => MessageRoute::Unknown,
        }
    }

    /// Check if a message should be processed immediately or queued
    pub fn should_process_immediately(route: &MessageRoute) -> bool {
        match route {
            MessageRoute::Authentication => false, // These go through incoming_rx channel
            MessageRoute::Query => false,          // These go through incoming_rx channel
            MessageRoute::MlsProtocol => true,     // Handle immediately
            MessageRoute::Chat => true,            // Handle immediately
            MessageRoute::Handshake => true,       // Handle immediately
            MessageRoute::Group => true,           // Handle group responses immediately
            MessageRoute::WelcomeFlow => true,     // Handle Welcome flow immediately
            MessageRoute::Unknown => false,        // Ignore
        }
    }

    /// Get a human-readable description of the route
    pub fn route_description(route: &MessageRoute) -> &'static str {
        match route {
            MessageRoute::Authentication => "Authentication protocol message",
            MessageRoute::MlsProtocol => "MLS protocol message",
            MessageRoute::Chat => "Chat message",
            MessageRoute::Handshake => "Handshake message",
            MessageRoute::Query => "Query response",
            MessageRoute::Group => "Group server message",
            MessageRoute::WelcomeFlow => "MLS Welcome flow message",
            MessageRoute::Unknown => "Unknown message type",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::messages::MixnetMessage;
    use chrono::Utc;
    use serde_json::json;

    fn create_test_incoming(action: &str) -> Incoming {
        let envelope = MixnetMessage {
            message_type: "message".to_string(),
            action: action.to_string(),
            sender: "test_sender".to_string(),
            recipient: "test_recipient".to_string(),
            payload: json!({}),
            signature: "test_signature".to_string(),
            timestamp: Utc::now().to_rfc3339(),
        };

        Incoming {
            envelope,
            ts: Utc::now(),
        }
    }

    #[test]
    fn test_authentication_routing() {
        let messages = ["challenge", "challengeResponse", "loginResponse", "sendResponse"];

        for action in messages {
            let incoming = create_test_incoming(action);
            assert_eq!(MessageRouter::route_message(&incoming), MessageRoute::Authentication);
        }
    }

    #[test]
    fn test_mls_protocol_routing() {
        let messages = ["keyPackageRequest", "groupWelcome"];

        for action in messages {
            let incoming = create_test_incoming(action);
            assert_eq!(MessageRouter::route_message(&incoming), MessageRoute::MlsProtocol);
        }
    }

    #[test]
    fn test_chat_routing() {
        // Note: "send" and "incomingMessage" now route to MlsProtocol since all messages use MLS
        let messages = ["send", "incomingMessage"];

        for action in messages {
            let incoming = create_test_incoming(action);
            // All chat messages now go through MLS
            assert_eq!(MessageRouter::route_message(&incoming), MessageRoute::MlsProtocol);
        }
    }

    #[test]
    fn test_handshake_routing() {
        let incoming = create_test_incoming("handshake");
        assert_eq!(MessageRouter::route_message(&incoming), MessageRoute::Handshake);
    }

    #[test]
    fn test_query_routing() {
        let incoming = create_test_incoming("queryResponse");
        assert_eq!(MessageRouter::route_message(&incoming), MessageRoute::Query);
    }

    #[test]
    fn test_unknown_routing() {
        let incoming = create_test_incoming("unknownAction");
        assert_eq!(MessageRouter::route_message(&incoming), MessageRoute::Unknown);
    }

    #[test]
    fn test_welcome_flow_routing() {
        let messages = [
            "mlsWelcome",
            "groupInvite",
            "groupJoinRequest",
            "welcomeAck",
            "keyPackageForGroup",
            "keyPackageForGroupResponse",
        ];

        for action in messages {
            let incoming = create_test_incoming(action);
            assert_eq!(MessageRouter::route_message(&incoming), MessageRoute::WelcomeFlow);
        }
    }

    #[test]
    fn test_should_process_immediately() {
        assert!(!MessageRouter::should_process_immediately(&MessageRoute::Authentication));
        assert!(!MessageRouter::should_process_immediately(&MessageRoute::Query));
        assert!(MessageRouter::should_process_immediately(&MessageRoute::MlsProtocol));
        assert!(MessageRouter::should_process_immediately(&MessageRoute::Chat));
        assert!(MessageRouter::should_process_immediately(&MessageRoute::Handshake));
        assert!(MessageRouter::should_process_immediately(&MessageRoute::WelcomeFlow));
        assert!(!MessageRouter::should_process_immediately(&MessageRoute::Unknown));
    }
}