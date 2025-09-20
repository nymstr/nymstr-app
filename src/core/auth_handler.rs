//! Authentication handler for challenge/response protocols
//!
//! Handles registration and login challenge/response flows.

use crate::core::{db::Db, mixnet_client::MixnetService};
use crate::crypto::{Crypto, SecurePassphrase};
use anyhow::{Result, anyhow};
use log::{info, error};
use pgp::composed::{SignedSecretKey, SignedPublicKey};
use std::sync::Arc;

/// Handles authentication challenge/response protocols
pub struct AuthenticationHandler {
    /// Database for persistence
    pub db: Arc<Db>,
    /// Mixnet service for sending responses
    pub service: Arc<MixnetService>,
    /// PGP keys for signing challenges
    pub pgp_secret_key: Option<SignedSecretKey>,
    pub pgp_public_key: Option<SignedPublicKey>,
    pub pgp_passphrase: Option<SecurePassphrase>,
}

impl AuthenticationHandler {
    pub fn new(
        db: Arc<Db>,
        service: Arc<MixnetService>,
        pgp_secret_key: Option<SignedSecretKey>,
        pgp_public_key: Option<SignedPublicKey>,
        pgp_passphrase: Option<SecurePassphrase>,
    ) -> Self {
        Self {
            db,
            service,
            pgp_secret_key,
            pgp_public_key,
            pgp_passphrase,
        }
    }

    /// Handle registration challenge from server
    pub async fn process_register_challenge(&self, username: &str, nonce: &str) -> Result<()> {
        info!("Processing registration challenge for user: {}", username);

        // Sign the nonce with our PGP key
        let signature = if let (Some(secret_key), Some(passphrase)) = (&self.pgp_secret_key, &self.pgp_passphrase) {
            Crypto::pgp_sign_detached_secure(secret_key, nonce.as_bytes(), passphrase)?
        } else {
            return Err(anyhow!("PGP secret key or passphrase not available for signing"));
        };

        // Send signed response back to server
        self.service.send_registration_response(username, &signature).await?;
        info!("Sent registration challenge response for user: {}", username);
        Ok(())
    }

    /// Handle registration response from server
    pub async fn process_register_response(&self, username: &str, result: &str) -> Result<bool> {
        match result {
            "success" => {
                info!("✅ Registration successful for user: {}", username);
                Ok(true)
            }
            error_msg => {
                error!("❌ Registration failed for user {}: {}", username, error_msg);
                Ok(false)
            }
        }
    }

    /// Handle login challenge from server
    pub async fn process_login_challenge(&self, username: &str, nonce: &str) -> Result<()> {
        info!("Processing login challenge for user: {}", username);

        // Sign the nonce with our PGP key
        let signature = if let (Some(secret_key), Some(passphrase)) = (&self.pgp_secret_key, &self.pgp_passphrase) {
            Crypto::pgp_sign_detached_secure(secret_key, nonce.as_bytes(), passphrase)?
        } else {
            return Err(anyhow!("PGP secret key or passphrase not available for signing"));
        };

        // Send login challenge response
        self.service.send_login_response(username, &signature).await?;
        info!("Sent login challenge response for user: {}", username);
        Ok(())
    }

    /// Handle login response from server
    pub async fn process_login_response(&self, username: &str, result: &str) -> Result<bool> {
        match result {
            "success" => {
                info!("✅ Login successful for user: {}", username);
                Ok(true)
            }
            error_msg => {
                error!("❌ Login failed for user {}: {}", username, error_msg);
                Ok(false)
            }
        }
    }

    /// Handle query response from server
    pub async fn process_query_response(&self, username: &str, public_key: &str) -> Result<(String, String)> {
        info!("Received query response for user: {}", username);

        // Validate the public key format
        if let Err(e) = Crypto::parse_pgp_public_key(public_key) {
            error!("Invalid public key format in query response: {}", e);
            return Err(anyhow!("Invalid public key format received"));
        }

        // Store the user and public key in database
        self.db.register_user(username, public_key).await?;
        info!("Stored public key for user: {}", username);

        Ok((username.to_string(), public_key.to_string()))
    }

    /// Update handler state when PGP keys change
    pub fn update_pgp_keys(
        &mut self,
        secret_key: Option<SignedSecretKey>,
        public_key: Option<SignedPublicKey>,
        passphrase: Option<SecurePassphrase>,
    ) {
        self.pgp_secret_key = secret_key;
        self.pgp_public_key = public_key;
        self.pgp_passphrase = passphrase;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Note: These would need actual test implementations with mock services

    #[test]
    fn test_process_register_response_success() {
        // Test would create handler and call process_register_response with "success"
        // Should return Ok(true)
    }

    #[test]
    fn test_process_register_response_failure() {
        // Test would create handler and call process_register_response with error message
        // Should return Ok(false)
    }

    #[test]
    fn test_process_login_response_success() {
        // Test would create handler and call process_login_response with "success"
        // Should return Ok(true)
    }

    #[test]
    fn test_process_login_response_failure() {
        // Test would create handler and call process_login_response with error message
        // Should return Ok(false)
    }
}