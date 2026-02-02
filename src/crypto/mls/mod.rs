//! MLS (Message Layer Security) implementation
//!
//! This module provides:
//! - End-to-end encrypted messaging
//! - Group conversation management
//! - Key package exchange protocols
//! - Secure group establishment
//! - Epoch-aware message buffering for mixnet delivery

pub mod client;
// Groups now managed by MlsClient directly
pub mod key_packages;
// Removed custom storage - now using official mls-rs-provider-sqlite
pub mod conversation_manager;
pub mod epoch_buffer;
pub mod persistence;
pub mod types;

#[cfg(test)]
mod basic_test;
#[cfg(test)]
mod integration_test;
#[cfg(test)]
pub mod test_client;
#[cfg(test)]
pub mod test_storage;

#[allow(unused_imports)] // Part of public API
pub use client::MlsClient;
// GroupManager removed - groups handled by MlsClient
#[allow(unused_imports)] // Part of public API
pub use key_packages::{KeyPackageManager, KeyPackageValidationResult};
// Storage now handled by official mls-rs-provider-sqlite
pub use conversation_manager::MlsConversationManager;
#[allow(unused_imports)] // Part of public API
pub use epoch_buffer::{BufferStats, BufferedMessage, EpochAwareBuffer};
#[allow(unused_imports)] // Part of public API
pub use types::{
    CredentialValidationResult,
    EncryptedMessage,
    MlsAddMemberResult,
    MlsCredential,
    MlsGroupInfoPublic,
    MlsMessageType,
    // Phase 3: Welcome Flow types
    MlsWelcome,
    StoredWelcome,
};
