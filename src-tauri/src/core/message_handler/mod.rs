//! Message handler module for processing incoming and outgoing messages.
//!
//! This module contains:
//! - MessageHandler struct: Central orchestrator for message processing
//! - Authentication flows (registration, login)
//! - MLS operations (key packages, welcomes, conversations)
//! - Group messaging (send, fetch, responses)
//! - Direct messaging methods
//! - Welcome/invite flow handlers
//! - Background buffer processor for MLS retries

pub mod auth;
pub mod direct;
pub mod group;
pub mod welcome;

// Re-export commonly used types
pub use auth::{AuthResult, AuthenticationHandler};
pub use direct::{DirectMessageHandler, DirectMessageHandlerBuilder, normalize_conversation_id};
pub use group::GroupMessageHandler;
pub use welcome::{WelcomeFlowHandler, WelcomeFlowResult, WelcomeProcessResult};
