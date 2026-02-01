//! Cryptography module for Nymstr.
//!
//! This module provides cryptographic operations:
//! - PGP key management and signing
//! - MLS (Message Layer Security) for end-to-end encryption
//! - Utility functions for encryption/decryption

pub mod mls;
pub mod pgp;
pub mod utils;

// Re-export commonly used types for convenience
pub use pgp::{
    ArcPassphrase, ArcPublicKey, ArcSecretKey, PgpKeyManager, PgpSigner, SecurePassphrase,
    VerifiedSignature,
};
pub use utils::Crypto;

// Re-export MLS types
pub use mls::{
    EncryptedMessage, MlsClient, MlsCredential, MlsMessageType, KeyPackageManager,
    ConversationInfo, ConversationType,
};
