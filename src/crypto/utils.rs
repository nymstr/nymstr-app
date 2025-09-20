//! Basic cryptographic utilities

use anyhow::Result;
use pgp::composed::{SignedSecretKey, SignedPublicKey};

/// Basic crypto utilities: file operations and key management
#[derive(Clone, Copy)]
pub struct Crypto;

impl Crypto {
    /// Generate PGP keypair for given user ID (backward compatibility)
    pub fn generate_pgp_keypair(user_id: &str) -> Result<(SignedSecretKey, SignedPublicKey)> {
        crate::crypto::pgp::PgpKeyManager::generate_keypair(user_id)
    }

    /// Get armored public key from PGP certificate (backward compatibility)
    pub fn pgp_public_key_armored(public_key: &SignedPublicKey) -> Result<String> {
        crate::crypto::pgp::PgpKeyManager::public_key_armored(public_key)
    }

    /// Create detached PGP signature (backward compatibility)
    pub fn pgp_sign_detached(secret_key: &SignedSecretKey, data: &[u8]) -> Result<String> {
        crate::crypto::pgp::PgpSigner::sign_detached(secret_key, data)
    }
}