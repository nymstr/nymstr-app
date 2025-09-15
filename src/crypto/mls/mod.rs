//! MLS (Message Layer Security) implementation
//!
//! This module provides:
//! - End-to-end encrypted messaging
//! - Group conversation management
//! - Key package exchange protocols
//! - Secure group establishment

pub mod client;
// Groups now managed by MlsClient directly
pub mod key_packages;
// Removed custom storage - now using official mls-rs-provider-sqlite
pub mod types;

#[cfg(test)]
mod basic_test;
#[cfg(test)]
mod integration_test;
#[cfg(test)]
pub mod test_storage;
#[cfg(test)]
pub mod test_client;

pub use client::MlsClient;
// GroupManager removed - groups handled by MlsClient
pub use key_packages::KeyPackageManager;
// Storage now handled by official mls-rs-provider-sqlite
pub use types::{EncryptedMessage, MlsMessageType};