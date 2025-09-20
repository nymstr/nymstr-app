//! Cryptographic operations for Nymstr
//!
//! This module provides all cryptographic functionality including:
//! - MLS (Message Layer Security) for end-to-end encryption
//! - PGP for identity and signing
//! - Conversation establishment protocols

pub mod mls;
pub mod pgp;
pub mod utils;
pub mod message_crypto;

// Re-export main types
pub use mls::{MlsClient, EncryptedMessage, MlsMessageType, MlsConversationManager};
pub use pgp::{PgpKeyManager, PgpSigner, SecurePassphrase, VerifiedSignature};
pub use utils::Crypto;
pub use message_crypto::{MessageCrypto, VerifiedMessage};