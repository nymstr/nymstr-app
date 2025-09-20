//! MLS key package management and exchange

use anyhow::{Result, anyhow};
use base64::Engine;
use std::collections::HashMap;
use crate::core::db::Db;

/// Manages MLS key package generation, storage, and exchange
pub struct KeyPackageManager {
    // In-memory cache of key packages (username -> base64 key package)
    key_package_cache: std::sync::Arc<std::sync::Mutex<HashMap<String, String>>>,
    db: std::sync::Arc<Db>,
}

impl KeyPackageManager {
    pub fn new(db: std::sync::Arc<Db>) -> Self {
        Self {
            key_package_cache: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
            db,
        }
    }

    /// Validate a received key package (basic validation)
    pub fn validate_key_package(&self, key_package_b64: &str) -> Result<bool> {
        // Decode from base64
        let key_package_bytes = base64::engine::general_purpose::STANDARD.decode(key_package_b64)
            .map_err(|_| anyhow!("Invalid base64 key package"))?;

        // Try to parse as MLS message to verify it's valid
        let _key_package_msg = mls_rs::MlsMessage::from_bytes(&key_package_bytes)
            .map_err(|_| anyhow!("Invalid MLS key package format"))?;

        // Additional validation could check:
        // - Key package expiry
        // - Signature validity
        // - Supported cipher suites

        Ok(true)
    }

    /// Store a trusted key package for a user (in-memory for now)
    pub fn store_key_package(&self, username: &str, key_package_b64: &str) -> Result<()> {
        // Validate before storing
        if !self.validate_key_package(key_package_b64)? {
            return Err(anyhow!("Invalid key package for user: {}", username));
        }

        let mut cache = self.key_package_cache.lock().unwrap();
        cache.insert(username.to_string(), key_package_b64.to_string());
        log::info!("Stored key package for user: {}", username);
        Ok(())
    }

}