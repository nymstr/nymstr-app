//! MLS (Message Layer Security) implementation
//!
//! This module provides:
//! - End-to-end encrypted messaging using MLS protocol (RFC 9420)
//! - Group conversation management
//! - Key package generation and exchange
//! - Secure group establishment
//! - PGP-based identity credentials
//! - Epoch-aware message buffering for out-of-order delivery

pub mod client;
pub mod conversation_manager;
pub mod epoch_buffer;
pub mod key_packages;
pub mod types;

// Re-export commonly used types for convenience
pub use client::{
    ArcPassphrase, ArcPublicKey, ArcSecretKey, MlsClient, MlsKeyManager, PgpCredential,
    PgpIdentityProvider,
};
pub use conversation_manager::MlsConversationManager;
pub use epoch_buffer::{BufferStats, BufferedMessage, EpochAwareBuffer, PendingMlsMessage};
pub use key_packages::{KeyPackageManager, KeyPackageValidationResult};
pub use types::{
    ConversationInfo, ConversationType, CredentialValidationResult, EncryptedMessage,
    MlsAddMemberResult, MlsCredential, MlsGroupInfo, MlsGroupInfoPublic, MlsMessageType,
    MlsWelcome, StoredWelcome,
};
