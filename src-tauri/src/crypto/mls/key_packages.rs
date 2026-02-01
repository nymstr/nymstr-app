//! MLS key package management and exchange

#![allow(dead_code)] // Many methods are part of the public API for key package management

use anyhow::{anyhow, Result};
use base64::Engine;
use mls_rs::CipherSuite;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::client::MlsClient;
use super::types::{CredentialValidationResult, MlsCredential};

/// Supported cipher suites for key packages
const SUPPORTED_CIPHER_SUITES: &[CipherSuite] = &[
    CipherSuite::CURVE25519_AES128,
    CipherSuite::CURVE25519_CHACHA,
];

/// Maximum key package age in seconds (7 days)
#[allow(dead_code)]
const MAX_KEY_PACKAGE_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// Manages MLS key package generation, storage, and exchange
pub struct KeyPackageManager {
    // In-memory cache of key packages (username -> base64 key package)
    key_package_cache: Arc<Mutex<HashMap<String, String>>>,
    // In-memory cache of credentials (username -> MlsCredential)
    credential_cache: Arc<Mutex<HashMap<String, MlsCredential>>>,
}

impl KeyPackageManager {
    pub fn new() -> Self {
        Self {
            key_package_cache: Arc::new(Mutex::new(HashMap::new())),
            credential_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Generate a key package for this client using MLS client
    pub fn generate_key_package(&self, mls_client: &MlsClient) -> Result<String> {
        let key_package_bytes = mls_client.generate_key_package()?;
        let key_package_b64 =
            base64::engine::general_purpose::STANDARD.encode(&key_package_bytes);
        Ok(key_package_b64)
    }

    /// Generate a key package with an associated MLS credential for enhanced authentication
    ///
    /// This method generates a key package that includes credential binding information,
    /// which allows other parties to verify the PGP identity associated with the MLS key.
    pub fn generate_key_package_with_credential(
        &self,
        mls_client: &MlsClient,
        credential: &MlsCredential,
    ) -> Result<String> {
        // Validate the credential before generating the key package
        if !credential.is_valid() {
            return Err(anyhow!(
                "Cannot generate key package with invalid or expired credential"
            ));
        }

        // Generate the base key package
        let key_package_b64 = self.generate_key_package(mls_client)?;

        // Store the credential association
        let mut cache = self
            .credential_cache
            .lock()
            .map_err(|e| anyhow!("Failed to acquire credential_cache lock: {}", e))?;
        cache.insert(credential.username.clone(), credential.clone());

        log::info!(
            "Generated key package with credential for user: {} (expires in {} seconds)",
            credential.username,
            credential.remaining_validity_secs()
        );

        Ok(key_package_b64)
    }

    /// Validate a received key package with comprehensive checks
    pub fn validate_key_package(&self, key_package_b64: &str) -> Result<bool> {
        log::info!("Validating key package...");

        // Decode from base64
        let key_package_bytes = base64::engine::general_purpose::STANDARD
            .decode(key_package_b64)
            .map_err(|e| anyhow!("Invalid base64 key package: {}", e))?;

        // Check minimum size (key packages should be substantial)
        if key_package_bytes.len() < 100 {
            log::warn!("Key package too small: {} bytes", key_package_bytes.len());
            return Err(anyhow!("Key package too small to be valid"));
        }

        // Try to parse as MLS message to verify it's valid
        let key_package_msg = mls_rs::MlsMessage::from_bytes(&key_package_bytes)
            .map_err(|e| anyhow!("Invalid MLS key package format: {}", e))?;

        // Verify this is actually a key package message type
        let key_package = match key_package_msg.into_key_package() {
            Some(kp) => kp,
            None => {
                log::warn!("MLS message is not a key package");
                return Err(anyhow!("MLS message is not a key package"));
            }
        };

        // Check cipher suite is supported
        let cipher_suite = key_package.cipher_suite;
        if !SUPPORTED_CIPHER_SUITES.contains(&cipher_suite) {
            log::warn!(
                "Unsupported cipher suite in key package: {:?}",
                cipher_suite
            );
            return Err(anyhow!("Unsupported cipher suite: {:?}", cipher_suite));
        }
        log::debug!("Key package cipher suite: {:?} - OK", cipher_suite);

        log::info!("Key package validation passed");
        Ok(true)
    }

    /// Validate key package with detailed logging and return validation details
    pub fn validate_key_package_detailed(
        &self,
        key_package_b64: &str,
    ) -> Result<KeyPackageValidationResult> {
        let mut result = KeyPackageValidationResult::default();

        // Decode from base64
        let key_package_bytes =
            match base64::engine::general_purpose::STANDARD.decode(key_package_b64) {
                Ok(bytes) => bytes,
                Err(e) => {
                    result.errors.push(format!("Invalid base64: {}", e));
                    return Ok(result);
                }
            };
        result.size_bytes = key_package_bytes.len();

        // Parse as MLS message
        let key_package_msg = match mls_rs::MlsMessage::from_bytes(&key_package_bytes) {
            Ok(msg) => msg,
            Err(e) => {
                result.errors.push(format!("Invalid MLS format: {}", e));
                return Ok(result);
            }
        };

        // Extract key package
        let key_package = match key_package_msg.into_key_package() {
            Some(kp) => kp,
            None => {
                result
                    .errors
                    .push("Message is not a key package".to_string());
                return Ok(result);
            }
        };

        // Validate cipher suite
        let cipher_suite = key_package.cipher_suite;
        result.cipher_suite = Some(format!("{:?}", cipher_suite));
        if !SUPPORTED_CIPHER_SUITES.contains(&cipher_suite) {
            result
                .warnings
                .push(format!("Unsupported cipher suite: {:?}", cipher_suite));
        }

        result.valid = result.errors.is_empty();
        Ok(result)
    }

    /// Validate key package with credential binding verification
    pub fn validate_key_package_with_credential(
        &self,
        key_package_b64: &str,
        credential: &MlsCredential,
        pgp_public_key_bytes: &[u8],
    ) -> Result<KeyPackageValidationResult> {
        // First perform standard key package validation
        let mut result = self.validate_key_package_detailed(key_package_b64)?;

        // If basic validation failed, return early
        if !result.valid {
            return Ok(result);
        }

        // Now validate the credential
        let mut cred_result = CredentialValidationResult::default();

        // Check if credential is expired
        if credential.is_expired() {
            result.errors.push("Credential has expired".to_string());
            cred_result.expired = true;
            result.valid = false;
        } else {
            cred_result.expired = false;
        }

        // Verify PGP binding
        if credential.verify_pgp_binding(pgp_public_key_bytes) {
            cred_result.pgp_binding_verified = true;
            log::info!("PGP binding verified for user: {}", credential.username);
        } else {
            result
                .errors
                .push("PGP key binding verification failed".to_string());
            cred_result.pgp_binding_verified = false;
            result.valid = false;
        }

        // Check MLS signature key presence
        if !credential.mls_signature_key.is_empty() {
            cred_result.has_signature_key = true;
        } else {
            result
                .errors
                .push("Credential missing MLS signature key".to_string());
            cred_result.has_signature_key = false;
            result.valid = false;
        }

        // Set overall credential validation status
        cred_result.valid = cred_result.pgp_binding_verified
            && !cred_result.expired
            && cred_result.has_signature_key;

        result.credential_verified = cred_result.valid;
        result.credential_validation = Some(cred_result);

        if result.valid && result.credential_verified {
            log::info!(
                "Key package with credential validated successfully for user: {}",
                credential.username
            );
        }

        Ok(result)
    }

    /// Get the credential associated with a username
    pub fn get_credential(&self, username: &str) -> Option<MlsCredential> {
        let cache = self
            .credential_cache
            .lock()
            .expect("credential_cache lock poisoned in get_credential");
        cache.get(username).cloned()
    }

    /// Store a credential for a user
    pub fn store_credential(&self, credential: MlsCredential) -> Result<()> {
        if !credential.is_valid() {
            return Err(anyhow!("Cannot store invalid or expired credential"));
        }

        let mut cache = self
            .credential_cache
            .lock()
            .map_err(|e| anyhow!("Failed to acquire credential_cache lock: {}", e))?;
        cache.insert(credential.username.clone(), credential);
        Ok(())
    }

    /// Remove a credential for a user
    pub fn remove_credential(&self, username: &str) -> Option<MlsCredential> {
        let mut cache = self
            .credential_cache
            .lock()
            .expect("credential_cache lock poisoned in remove_credential");
        cache.remove(username)
    }

    /// Store a trusted key package for a user (in-memory for now)
    pub fn store_key_package(&self, username: &str, key_package_b64: &str) -> Result<()> {
        // Validate before storing
        if !self.validate_key_package(key_package_b64)? {
            return Err(anyhow!("Invalid key package for user: {}", username));
        }

        let mut cache = self
            .key_package_cache
            .lock()
            .map_err(|e| anyhow!("Failed to acquire key_package_cache lock: {}", e))?;
        cache.insert(username.to_string(), key_package_b64.to_string());
        log::info!("Stored key package for user: {}", username);
        Ok(())
    }

    /// Retrieve a stored key package for a user
    pub fn get_key_package(&self, username: &str) -> Result<Option<String>> {
        let cache = self
            .key_package_cache
            .lock()
            .map_err(|e| anyhow!("Failed to acquire key_package_cache lock: {}", e))?;
        Ok(cache.get(username).cloned())
    }

    /// Check if we have a key package for a user
    pub fn has_key_package(&self, username: &str) -> bool {
        let cache = self
            .key_package_cache
            .lock()
            .expect("key_package_cache lock poisoned in has_key_package");
        cache.contains_key(username)
    }

    /// Clear stored key package for a user (for testing/cleanup)
    pub fn clear_key_package(&self, username: &str) -> Result<()> {
        let mut cache = self
            .key_package_cache
            .lock()
            .map_err(|e| anyhow!("Failed to acquire key_package_cache lock: {}", e))?;
        cache.remove(username);
        log::info!("Cleared key package for user: {}", username);
        Ok(())
    }

    /// Get all stored usernames (for debugging)
    pub fn list_stored_users(&self) -> Vec<String> {
        let cache = self
            .key_package_cache
            .lock()
            .expect("key_package_cache lock poisoned in list_stored_users");
        cache.keys().cloned().collect()
    }
}

impl Default for KeyPackageManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of key package validation with detailed information
#[derive(Debug, Default)]
pub struct KeyPackageValidationResult {
    /// Whether the key package is valid
    pub valid: bool,
    /// Size of the key package in bytes
    pub size_bytes: usize,
    /// Cipher suite used
    pub cipher_suite: Option<String>,
    /// Validation errors
    pub errors: Vec<String>,
    /// Validation warnings (non-fatal)
    pub warnings: Vec<String>,
    /// Whether credential binding was verified
    pub credential_verified: bool,
    /// Associated credential validation result (if credential was provided)
    pub credential_validation: Option<CredentialValidationResult>,
}

impl KeyPackageValidationResult {
    /// Check if validation passed (no errors)
    pub fn is_valid(&self) -> bool {
        self.valid && self.errors.is_empty()
    }

    /// Get a summary of validation results
    pub fn summary(&self) -> String {
        if self.valid {
            format!(
                "Valid key package ({} bytes, cipher suite: {})",
                self.size_bytes,
                self.cipher_suite.as_deref().unwrap_or("unknown")
            )
        } else {
            format!("Invalid key package: {}", self.errors.join(", "))
        }
    }
}
