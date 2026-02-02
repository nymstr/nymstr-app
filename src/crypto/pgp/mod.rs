//! PGP cryptographic operations
//!
//! This module handles:
//! - PGP key generation and management
//! - Digital signatures for authentication
//! - Identity verification

pub mod keypair;
pub mod signing;

pub use keypair::{PgpKeyManager, SecurePassphrase};
pub use signing::{PgpSigner, VerifiedSignature};
