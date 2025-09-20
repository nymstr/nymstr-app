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
pub mod persistence;


pub use client::{PgpCredential, PgpIdentityProvider};
pub use key_packages::KeyPackageManager;
// Storage now handled by official mls-rs-provider-sqlite
pub use types::{EncryptedMessage, MlsMessageType};