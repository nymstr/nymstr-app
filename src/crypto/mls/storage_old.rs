//! MLS-RS storage provider implementation for persistent group state
//!
//! This module implements the MLS-RS storage traits to provide proper
//! group state persistence using the database backend.

use mls_rs::{
    GroupStateStorage, KeyPackageStorage, PreSharedKeyStorage,
    psk::{PreSharedKey, ExternalPskId},
    storage_provider::KeyPackageData,
};
use mls_rs_core::group::{GroupState, EpochRecord};
use mls_rs_core::error::IntoAnyError;
use std::sync::Arc;
use std::collections::HashMap;
use base64::Engine;

use crate::core::db::Db;

/// Error type for storage operations
#[derive(Debug)]
pub struct StorageError(String);

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Storage error: {}", self.0)
    }
}

impl std::error::Error for StorageError {}

impl IntoAnyError for StorageError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

impl From<anyhow::Error> for StorageError {
    fn from(e: anyhow::Error) -> Self {
        StorageError(e.to_string())
    }
}

/// MLS storage provider that uses the Nymstr database for persistence
#[derive(Clone)]
pub struct NymstrStorageProvider {
    username: String,
    db: Arc<Db>,
    /// In-memory cache for frequently accessed data
    group_cache: Arc<tokio::sync::Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
    key_package_cache: Arc<tokio::sync::Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
}

impl NymstrStorageProvider {
    pub fn new(username: String, db: Arc<Db>) -> Self {
        Self {
            username,
            db,
            group_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            key_package_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Convert group ID to base64 string for database storage
    fn group_id_to_string(&self, group_id: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(group_id)
    }

    /// Convert key package ID to base64 string for database storage
    fn key_package_id_to_string(&self, key_package_id: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(key_package_id)
    }
}

impl GroupStateStorage for NymstrStorageProvider {
    type Error = StorageError;

    /// Fetch a group state from storage
    fn state(&self, group_id: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        let group_id_str = self.group_id_to_string(group_id);

        let rt = tokio::runtime::Handle::current();
        let result = rt.block_on(async {
            self.db.load_mls_group_state(&self.username, &group_id_str).await
        })?;

        log::debug!("Loaded group state for {}: {}", group_id_str, result.is_some());
        Ok(result)
    }

    /// Lazy loads cached epoch data from a particular group
    fn epoch(&self, group_id: &[u8], epoch_id: u64) -> Result<Option<Vec<u8>>, Self::Error> {
        let group_id_str = self.group_id_to_string(group_id);
        let epoch_key = format!("{}_{}", group_id_str, epoch_id);

        let rt = tokio::runtime::Handle::current();
        let result = rt.block_on(async {
            self.db.load_mls_group_state(&self.username, &epoch_key).await
        })?;

        log::debug!("Loaded epoch {} for group {}: {}", epoch_id, group_id_str, result.is_some());
        Ok(result)
    }

    /// Writes pending state updates
    fn write(&mut self, state: GroupState, _epoch_inserts: Vec<EpochRecord>, _epoch_updates: Vec<EpochRecord>) -> Result<(), Self::Error> {
        let group_id_str = self.group_id_to_string(&state.id);

        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            self.db.save_mls_group_state(&self.username, &group_id_str, &state.data).await
        })?;

        log::info!("Wrote group state for {}", group_id_str);
        Ok(())
    }

    /// Retrieves the maximum epoch ID for a group
    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        // For this implementation, we'll return 0 for now
        // In a full implementation, you'd track epoch IDs in the database
        let group_id_str = self.group_id_to_string(group_id);
        log::debug!("Max epoch ID for {}: 0 (placeholder)", group_id_str);
        Ok(Some(0))
    }
}

impl KeyPackageStorage for NymstrStorageProvider {
    type Error = StorageError;

    /// Delete a KeyPackageData referenced by the given ID
    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        let key_id_str = self.key_package_id_to_string(id);
        let storage_key = format!("keypackage_{}", key_id_str);

        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            self.db.delete_mls_group_state(&self.username, &storage_key).await
        })?;

        log::info!("Deleted key package for ID {}", key_id_str);
        Ok(())
    }

    /// Store a KeyPackageData that can be accessed by the provided ID
    fn insert(&mut self, id: Vec<u8>, _pkg: KeyPackageData) -> Result<(), Self::Error> {
        let key_id_str = self.key_package_id_to_string(&id);
        let storage_key = format!("keypackage_{}", key_id_str);

        // For now, store as binary data (KeyPackageData might not be serializable)
        // This is a simplified implementation - a full one would need proper serialization
        let serialized = vec![]; // Placeholder

        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            self.db.save_mls_group_state(&self.username, &storage_key, &serialized).await
        })?;

        log::info!("Inserted key package for ID {}", key_id_str);
        Ok(())
    }

    /// Retrieve a KeyPackageData by its ID
    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        let key_id_str = self.key_package_id_to_string(id);
        let storage_key = format!("keypackage_{}", key_id_str);

        let rt = tokio::runtime::Handle::current();
        let result = rt.block_on(async {
            self.db.load_mls_group_state(&self.username, &storage_key).await
        })?;

        match result {
            Some(_data) => {
                // For now, return None since we can't deserialize properly
                // This is a placeholder implementation
                log::debug!("Key package data found for ID {} but can't deserialize yet", key_id_str);
                Ok(None)
            }
            None => {
                log::debug!("No key package found for ID {}", key_id_str);
                Ok(None)
            }
        }
    }
}

impl PreSharedKeyStorage for NymstrStorageProvider {
    type Error = StorageError;

    /// Retrieve a pre-shared key by its external ID
    fn get(&self, id: &ExternalPskId) -> Result<Option<PreSharedKey>, Self::Error> {
        // For now, use a simplified approach for PSK ID
        let psk_id_bytes = format!("{:?}", id).into_bytes();
        let psk_id_str = base64::engine::general_purpose::STANDARD.encode(&psk_id_bytes);
        let storage_key = format!("psk_{}", psk_id_str);

        let rt = tokio::runtime::Handle::current();
        let result = rt.block_on(async {
            self.db.load_mls_group_state(&self.username, &storage_key).await
        })?;

        match result {
            Some(_data) => {
                // For now, return None since we can't deserialize PreSharedKey properly
                // This is a placeholder implementation
                log::debug!("PSK data found for ID {} but can't deserialize yet", psk_id_str);
                Ok(None)
            }
            None => {
                log::debug!("No pre-shared key found for ID {}", psk_id_str);
                Ok(None)
            }
        }
    }
}


/// Helper struct for managing MLS groups with proper persistence
pub struct PersistentMlsGroup {
    storage: NymstrStorageProvider,
}

impl PersistentMlsGroup {
    pub fn new(username: String, db: Arc<Db>) -> Self {
        Self {
            storage: NymstrStorageProvider::new(username, db),
        }
    }

    pub fn storage_provider(&self) -> &NymstrStorageProvider {
        &self.storage
    }
}