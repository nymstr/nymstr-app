//! Cryptographic utilities.
//!
//! This module provides convenience wrappers for common cryptographic operations,
//! including PGP key management and signing.

#![allow(dead_code)]

use anyhow::Result;
use pgp::composed::{SignedPublicKey, SignedSecretKey};

use crate::crypto::pgp::{PgpKeyManager, PgpSigner, SecurePassphrase, VerifiedSignature};

/// Cryptographic utilities struct.
///
/// Provides a unified interface for common cryptographic operations.
#[derive(Clone, Copy)]
pub struct Crypto;

impl Crypto {
    /// Save private and public key PEM files for the given username.
    pub fn save_keys(
        &self,
        storage_dir: &str,
        username: &str,
        private_pem: &[u8],
        public_pem: &[u8],
    ) -> Result<()> {
        use std::{fs, path::Path};
        let user_dir = Path::new(storage_dir).join(username);
        fs::create_dir_all(&user_dir)?;
        fs::write(
            user_dir.join(format!("{}_private_key.pem", username)),
            private_pem,
        )?;
        fs::write(
            user_dir.join(format!("{}_public_key.pem", username)),
            public_pem,
        )?;
        Ok(())
    }

    /// Load the private key PEM bytes for the given username.
    pub fn load_private_key_from_file(&self, storage_dir: &str, username: &str) -> Result<Vec<u8>> {
        use std::{fs, path::Path};
        let path = Path::new(storage_dir)
            .join(username)
            .join(format!("{}_private_key.pem", username));
        let data = fs::read(path)?;
        Ok(data)
    }

    /// Load the public key PEM bytes for the given username.
    pub fn load_public_key_from_file(&self, storage_dir: &str, username: &str) -> Result<Vec<u8>> {
        use std::{fs, path::Path};
        let path = Path::new(storage_dir)
            .join(username)
            .join(format!("{}_public_key.pem", username));
        let data = fs::read(path)?;
        Ok(data)
    }

    /// Generate secure PGP keypair with Ed25519 keys.
    pub fn generate_pgp_keypair_secure(
        user_id: &str,
        passphrase: &SecurePassphrase,
    ) -> Result<(SignedSecretKey, SignedPublicKey)> {
        PgpKeyManager::generate_keypair_secure(user_id, passphrase)
    }

    /// Generate secure PGP keypair with RSA-3072 keys (fallback).
    pub fn generate_pgp_keypair_rsa_secure(
        user_id: &str,
        passphrase: &SecurePassphrase,
    ) -> Result<(SignedSecretKey, SignedPublicKey)> {
        PgpKeyManager::generate_keypair_rsa_secure(user_id, passphrase)
    }

    /// Get armored public key from PGP certificate.
    pub fn pgp_public_key_armored(public_key: &SignedPublicKey) -> Result<String> {
        PgpKeyManager::public_key_armored(public_key)
    }

    /// Create secure detached PGP signature.
    pub fn pgp_sign_detached_secure(
        secret_key: &SignedSecretKey,
        data: &[u8],
        passphrase: &SecurePassphrase,
    ) -> Result<String> {
        PgpSigner::sign_detached_secure(secret_key, data, passphrase)
    }

    /// Verify detached PGP signature.
    pub fn pgp_verify_detached(
        public_key: &SignedPublicKey,
        data: &[u8],
        signature: &str,
    ) -> Result<VerifiedSignature> {
        PgpSigner::verify_detached(public_key, data, signature)
    }

    /// Create a secure passphrase from user input.
    pub fn create_secure_passphrase() -> Result<SecurePassphrase> {
        SecurePassphrase::from_user_input()
    }

    /// Generate a strong random passphrase.
    pub fn generate_strong_passphrase() -> SecurePassphrase {
        SecurePassphrase::generate_strong()
    }

    /// Parse and validate a PGP public key from armored string.
    pub fn parse_pgp_public_key(public_key_armored: &str) -> Result<SignedPublicKey> {
        PgpKeyManager::parse_public_key(public_key_armored)
    }
}
