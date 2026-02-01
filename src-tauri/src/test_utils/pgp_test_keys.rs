//! PGP key generation utilities for testing
//!
//! Provides helpers for generating PGP keypairs without requiring user interaction.

use crate::crypto::pgp::keypair::{PgpKeyManager, SecurePassphrase};
use anyhow::Result;
use pgp::composed::{SignedPublicKey, SignedSecretKey};
use std::sync::Arc;

/// Type alias for Arc-wrapped secret key
pub type ArcSecretKey = Arc<SignedSecretKey>;
/// Type alias for Arc-wrapped public key
pub type ArcPublicKey = Arc<SignedPublicKey>;
/// Type alias for Arc-wrapped passphrase
pub type ArcPassphrase = Arc<SecurePassphrase>;

/// Test user credentials with PGP keys
#[derive(Clone)]
pub struct TestUser {
    pub username: String,
    pub secret_key: ArcSecretKey,
    pub public_key: ArcPublicKey,
    pub passphrase: ArcPassphrase,
    pub public_key_armored: String,
}

impl TestUser {
    /// Create a new test user with generated PGP keys
    pub fn new(username: &str) -> Result<Self> {
        let passphrase = SecurePassphrase::generate_strong();
        let (secret_key, public_key) =
            PgpKeyManager::generate_keypair_secure(username, &passphrase)?;

        let public_key_armored = PgpKeyManager::public_key_armored(&public_key)?;

        Ok(Self {
            username: username.to_string(),
            secret_key: Arc::new(secret_key),
            public_key: Arc::new(public_key),
            passphrase: Arc::new(passphrase),
            public_key_armored,
        })
    }

    /// Create a test user with a specific passphrase
    pub fn with_passphrase(username: &str, passphrase: &str) -> Result<Self> {
        let passphrase = SecurePassphrase::new(passphrase.to_string());
        let (secret_key, public_key) =
            PgpKeyManager::generate_keypair_secure(username, &passphrase)?;

        let public_key_armored = PgpKeyManager::public_key_armored(&public_key)?;

        Ok(Self {
            username: username.to_string(),
            secret_key: Arc::new(secret_key),
            public_key: Arc::new(public_key),
            passphrase: Arc::new(passphrase),
            public_key_armored,
        })
    }

    /// Get the username
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Get the Arc-wrapped secret key
    pub fn secret_key(&self) -> ArcSecretKey {
        Arc::clone(&self.secret_key)
    }

    /// Get the Arc-wrapped public key
    pub fn public_key(&self) -> ArcPublicKey {
        Arc::clone(&self.public_key)
    }

    /// Get the Arc-wrapped passphrase
    pub fn passphrase(&self) -> ArcPassphrase {
        Arc::clone(&self.passphrase)
    }

    /// Get the armored public key string
    pub fn public_key_armored(&self) -> &str {
        &self.public_key_armored
    }
}

/// Generate a test keypair for a given username
pub fn generate_test_keypair(username: &str) -> Result<(SignedSecretKey, SignedPublicKey, SecurePassphrase)> {
    let passphrase = SecurePassphrase::generate_strong();
    let (secret_key, public_key) = PgpKeyManager::generate_keypair_secure(username, &passphrase)?;
    Ok((secret_key, public_key, passphrase))
}

/// Generate multiple test users
pub fn generate_test_users(usernames: &[&str]) -> Result<Vec<TestUser>> {
    usernames.iter().map(|name| TestUser::new(name)).collect()
}

/// Generate Alice, Bob, and Charlie test users (common test scenario)
pub fn generate_abc_users() -> Result<(TestUser, TestUser, TestUser)> {
    let alice = TestUser::new("alice")?;
    let bob = TestUser::new("bob")?;
    let charlie = TestUser::new("charlie")?;
    Ok((alice, bob, charlie))
}

/// Generate a pair of users for direct messaging tests
pub fn generate_dm_pair() -> Result<(TestUser, TestUser)> {
    let sender = TestUser::new("sender")?;
    let recipient = TestUser::new("recipient")?;
    Ok((sender, recipient))
}

/// Sign a message using a test user's key
pub fn sign_message(user: &TestUser, message: &str) -> Result<String> {
    use crate::crypto::pgp::signing::PgpSigner;
    PgpSigner::sign_detached_secure(&user.secret_key, message.as_bytes(), &user.passphrase)
}

/// Verify a signature using a test user's public key
pub fn verify_signature(user: &TestUser, message: &str, signature: &str) -> Result<bool> {
    use crate::crypto::pgp::signing::PgpSigner;
    let result = PgpSigner::verify_detached(&user.public_key, message.as_bytes(), signature)?;
    Ok(result.is_valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::types::KeyDetails;

    #[test]
    fn test_generate_test_keypair() {
        let (secret, public, _passphrase) = generate_test_keypair("test_user").unwrap();

        // Verify keys are valid
        assert!(!secret.public_key().fingerprint().to_string().is_empty());
        assert!(!public.fingerprint().to_string().is_empty());
    }

    #[test]
    fn test_test_user_creation() {
        let user = TestUser::new("alice").unwrap();

        assert_eq!(user.username(), "alice");
        assert!(!user.public_key_armored().is_empty());
        assert!(user.public_key_armored().contains("BEGIN PGP PUBLIC KEY"));
    }

    #[test]
    fn test_generate_test_users() {
        let users = generate_test_users(&["alice", "bob", "charlie"]).unwrap();

        assert_eq!(users.len(), 3);
        assert_eq!(users[0].username(), "alice");
        assert_eq!(users[1].username(), "bob");
        assert_eq!(users[2].username(), "charlie");
    }

    #[test]
    fn test_abc_users() {
        let (alice, bob, charlie) = generate_abc_users().unwrap();

        assert_eq!(alice.username(), "alice");
        assert_eq!(bob.username(), "bob");
        assert_eq!(charlie.username(), "charlie");
    }

    #[test]
    fn test_sign_and_verify() {
        let user = TestUser::new("signer").unwrap();
        let message = "Hello, World!";

        let signature = sign_message(&user, message).unwrap();
        let valid = verify_signature(&user, message, &signature).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_signature_verification_fails_for_wrong_message() {
        let user = TestUser::new("signer").unwrap();
        let message = "Hello, World!";
        let wrong_message = "Goodbye, World!";

        let signature = sign_message(&user, message).unwrap();
        let valid = verify_signature(&user, wrong_message, &signature).unwrap();

        assert!(!valid);
    }
}
