//! Cryptographic operations for Nymstr
//!
//! This module provides all cryptographic functionality including:
//! - MLS (Message Layer Security) for end-to-end encryption
//! - PGP for identity and signing
//! - Conversation establishment protocols

pub mod message_crypto;
pub mod mls;
pub mod pgp;
pub mod utils;

// Re-export main types
#[allow(unused_imports)] // Part of public API
pub use message_crypto::{MessageCrypto, VerifiedMessage};
#[allow(unused_imports)] // Part of public API
pub use mls::{EncryptedMessage, MlsClient, MlsConversationManager, MlsMessageType};
#[allow(unused_imports)] // Part of public API
pub use pgp::{PgpKeyManager, PgpSigner, SecurePassphrase, VerifiedSignature};
pub use utils::Crypto;
