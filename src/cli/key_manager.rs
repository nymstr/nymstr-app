//! CLI Key Management - handles password prompting and key operations

use anyhow::{Result, anyhow};
use pgp::composed::{SignedSecretKey, SignedPublicKey};
use crate::crypto::pgp::{PgpKeyManager, SecurePassphrase};
use crate::crypto::Crypto;

/// Handles PGP key management at the CLI level with proper user interaction
pub struct KeyManager;

impl KeyManager {
    /// Load existing keys or create new ones with user password prompting
    /// This is the main entry point for CLI key management
    pub fn load_or_create_keys(username: &str) -> Result<(SignedSecretKey, SignedPublicKey, SecurePassphrase)> {
        if PgpKeyManager::keys_exist(username) {
            Self::load_existing_keys(username)
        } else {
            Self::create_new_keys(username)
        }
    }

    /// Create new keys for a user (called during registration)
    pub fn create_new_keys(username: &str) -> Result<(SignedSecretKey, SignedPublicKey, SecurePassphrase)> {
        println!("Creating new PGP keys for user: {}", username);

        // Prompt user for a secure passphrase
        let passphrase = SecurePassphrase::from_user_input_with_prompt(
            "Create a secure passphrase for your PGP keys (min 12 characters)"
        )?;

        // Generate Ed25519 keys with the user's passphrase
        let (secret_key, public_key) = Crypto::generate_pgp_keypair_secure(username, &passphrase)?;

        // Save keys securely with HMAC integrity protection
        PgpKeyManager::save_keypair_secure(username, &secret_key, &public_key, &passphrase)?;

        println!("✅ New PGP keys created and saved securely for: {}", username);
        Ok((secret_key, public_key, passphrase))
    }

    /// Load existing keys for a user (called during login)
    pub fn load_existing_keys(username: &str) -> Result<(SignedSecretKey, SignedPublicKey, SecurePassphrase)> {
        println!("Loading existing PGP keys for user: {}", username);

        // Prompt user for their passphrase
        let passphrase = SecurePassphrase::from_user_input_with_prompt(
            "Enter your passphrase to unlock PGP keys"
        )?;

        // Try to load keys with secure verification
        if let Some((secret_key, public_key)) = PgpKeyManager::load_keypair_secure(username, &passphrase)? {
            println!("✅ PGP keys loaded successfully for: {}", username);
            Ok((secret_key, public_key, passphrase))
        } else {
            // No secure keys found
            Err(anyhow!("Could not load PGP keys for user: {}. Check your passphrase or re-register.", username))
        }
    }

    /// Verify that keys are valid for signing operations
    pub fn verify_keys(secret_key: &SignedSecretKey, public_key: &SignedPublicKey) -> Result<()> {
        use crate::crypto::pgp::PgpSigner;

        // Validate the public key
        PgpSigner::validate_signing_key(public_key)?;

        // Verify key integrity
        PgpSigner::verify_key_integrity(public_key)?;

        // Check signing capability
        if !PgpSigner::has_signing_capability(public_key) {
            return Err(anyhow!("PGP key does not have signing capability"));
        }

        Ok(())
    }

    /// Get armored public key for sharing/registration
    pub fn get_public_key_armored(public_key: &SignedPublicKey) -> Result<String> {
        Crypto::pgp_public_key_armored(public_key)
    }
}