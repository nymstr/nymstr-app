//! Core module for Nymstr backend functionality.
//!
//! This module contains the core components for the Nymstr messaging system:
//! - Mixnet client wrapper for Nym SDK connectivity
//! - Message handling and routing
//! - Database operations
//! - Message type definitions

pub mod db;
pub mod message_handler;
pub mod message_router;
pub mod messages;
pub mod mixnet_client;
pub mod mixnet_traits;

// Re-export commonly used types
pub use message_router::{MessageRoute, MessageRouter};
pub use messages::MixnetMessage;
pub use mixnet_client::{Incoming, MixnetConfig, MixnetService};
pub use mixnet_traits::{MixnetAddressStore, MixnetClient, MixnetSender};

// TODO: Add these modules in subsequent phases:
// pub mod auth_handler;     // Phase 4: Authentication flows
// pub mod chat_handler;     // Phase 5: Direct messaging
