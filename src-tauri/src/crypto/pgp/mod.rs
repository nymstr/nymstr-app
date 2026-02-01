//! PGP cryptographic operations.
//!
//! This module handles:
//! - PGP key generation and management (Ed25519 and RSA)
//! - Secure key storage with HMAC integrity verification
//! - Digital signatures for authentication
//! - Identity verification

pub mod keypair;
pub mod signing;

pub use keypair::{PgpKeyManager, SecurePassphrase};
pub use signing::{PgpSigner, VerifiedSignature};

use pgp::composed::{SignedPublicKey, SignedSecretKey};
use std::sync::Arc;

/// Arc-wrapped secret key for efficient sharing across async tasks.
///
/// Using Arc avoids expensive deep cloning of cryptographic keys.
pub type ArcSecretKey = Arc<SignedSecretKey>;

/// Arc-wrapped public key for efficient sharing across async tasks.
pub type ArcPublicKey = Arc<SignedPublicKey>;

/// Arc-wrapped passphrase for efficient sharing across async tasks.
pub type ArcPassphrase = Arc<SecurePassphrase>;
