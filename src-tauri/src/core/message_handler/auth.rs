//! Authentication handler for challenge/response protocols
//!
//! This module handles registration and login challenge/response flows
//! for the Nymstr discovery server.

use crate::core::mixnet_client::MixnetService;
use crate::crypto::pgp::{ArcPassphrase, ArcPublicKey, ArcSecretKey, PgpSigner};
use anyhow::Result;
use std::sync::Arc;

/// Handles authentication challenge/response protocols
pub struct AuthenticationHandler {
    /// Mixnet service for sending responses
    service: Arc<MixnetService>,
    /// PGP secret key for signing challenges (Arc-wrapped to avoid expensive cloning)
    pgp_secret_key: ArcSecretKey,
    /// PGP public key for identity
    pgp_public_key: ArcPublicKey,
    /// PGP passphrase for signing operations
    pgp_passphrase: ArcPassphrase,
}

impl AuthenticationHandler {
    /// Create a new authentication handler with PGP keys
    pub fn new(
        service: Arc<MixnetService>,
        pgp_secret_key: ArcSecretKey,
        pgp_public_key: ArcPublicKey,
        pgp_passphrase: ArcPassphrase,
    ) -> Self {
        Self {
            service,
            pgp_secret_key,
            pgp_public_key,
            pgp_passphrase,
        }
    }

    /// Handle registration challenge from server
    ///
    /// Signs the nonce with our PGP key and sends the response back to the server.
    /// PGP handles hashing internally - we sign the raw nonce.
    pub async fn process_register_challenge(&self, username: &str, nonce: &str) -> Result<()> {
        tracing::info!("Processing registration challenge for user: {}", username);

        // Sign the raw nonce with our PGP key (PGP handles hashing internally)
        let signature =
            PgpSigner::sign_detached_secure(&self.pgp_secret_key, nonce.as_bytes(), &self.pgp_passphrase)?;

        // Send signed response back to server
        self.service
            .send_registration_response(username, &signature)
            .await?;

        tracing::info!(
            "Sent registration challenge response for user: {}",
            username
        );
        Ok(())
    }

    /// Handle registration response from server
    ///
    /// Returns true if registration was successful, false otherwise.
    pub fn process_register_response(&self, username: &str, result: &str) -> Result<bool> {
        match result {
            "success" => {
                tracing::info!("Registration successful for user: {}", username);
                Ok(true)
            }
            error_msg => {
                tracing::error!(
                    "Registration failed for user {}: {}",
                    username,
                    error_msg
                );
                Ok(false)
            }
        }
    }

    /// Handle login challenge from server
    ///
    /// Signs the nonce with our PGP key and sends the response back to the server.
    /// PGP handles hashing internally - we sign the raw nonce.
    pub async fn process_login_challenge(&self, username: &str, nonce: &str) -> Result<()> {
        tracing::info!("Processing login challenge for user: {}", username);

        // Sign the raw nonce with our PGP key (PGP handles hashing internally)
        let signature =
            PgpSigner::sign_detached_secure(&self.pgp_secret_key, nonce.as_bytes(), &self.pgp_passphrase)?;

        // Send login challenge response
        self.service
            .send_login_response(username, &signature)
            .await?;

        tracing::info!("Sent login challenge response for user: {}", username);
        Ok(())
    }

    /// Handle login response from server
    ///
    /// Returns true if login was successful, false otherwise.
    pub fn process_login_response(&self, username: &str, result: &str) -> Result<bool> {
        match result {
            "success" => {
                tracing::info!("Login successful for user: {}", username);
                Ok(true)
            }
            error_msg => {
                tracing::error!("Login failed for user {}: {}", username, error_msg);
                Ok(false)
            }
        }
    }

    /// Get reference to the public key
    pub fn public_key(&self) -> &ArcPublicKey {
        &self.pgp_public_key
    }
}

/// Result of an authentication flow (registration or login)
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// Authentication succeeded
    Success {
        /// The authenticated username
        username: String,
    },
    /// Authentication failed
    Failed {
        /// The username that failed to authenticate
        username: String,
        /// Error message from the server
        error: String,
    },
    /// Authentication timed out waiting for server response
    Timeout {
        /// The username that timed out
        username: String,
    },
}

impl AuthResult {
    /// Check if authentication was successful
    pub fn is_success(&self) -> bool {
        matches!(self, AuthResult::Success { .. })
    }

    /// Get the username from the result
    pub fn username(&self) -> &str {
        match self {
            AuthResult::Success { username } => username,
            AuthResult::Failed { username, .. } => username,
            AuthResult::Timeout { username } => username,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_result_success() {
        let result = AuthResult::Success {
            username: "alice".to_string(),
        };
        assert!(result.is_success());
        assert_eq!(result.username(), "alice");
    }

    #[test]
    fn test_auth_result_failed() {
        let result = AuthResult::Failed {
            username: "bob".to_string(),
            error: "Invalid signature".to_string(),
        };
        assert!(!result.is_success());
        assert_eq!(result.username(), "bob");
    }

    #[test]
    fn test_auth_result_timeout() {
        let result = AuthResult::Timeout {
            username: "charlie".to_string(),
        };
        assert!(!result.is_success());
        assert_eq!(result.username(), "charlie");
    }
}
