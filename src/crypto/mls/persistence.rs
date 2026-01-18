//! Simple MLS group state persistence for Nymstr
//!
//! This module provides basic group state persistence functionality
//! that works with the existing database structure.

#![allow(dead_code)] // Methods are part of the public API for MLS persistence

use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use base64::Engine;

use crate::core::db::Db;

/// Simple persistence manager for MLS groups
#[derive(Clone)]
pub struct MlsGroupPersistence {
    username: String,
    db: Arc<Db>,
    /// In-memory cache for frequently accessed group state
    cache: Arc<tokio::sync::Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
}

impl MlsGroupPersistence {
    pub fn new(username: String, db: Arc<Db>) -> Self {
        Self {
            username,
            db,
            cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Convert group ID to base64 string for database storage
    fn group_id_to_string(&self, group_id: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(group_id)
    }

    /// Save group state to persistent storage
    pub async fn save_group_state(&self, group_id: &[u8], group_state: &[u8]) -> Result<()> {
        let group_id_str = self.group_id_to_string(group_id);

        log::debug!("Saving MLS group state for conversation {} (size: {} bytes)",
                   group_id_str, group_state.len());

        // Save to database
        self.db.save_mls_group_state(&self.username, &group_id_str, group_state).await?;

        // Update cache
        self.cache.lock().await.insert(group_id.to_vec(), group_state.to_vec());

        log::info!("Successfully saved MLS group state for conversation {}", group_id_str);
        Ok(())
    }

    /// Load group state from persistent storage
    pub async fn load_group_state(&self, group_id: &[u8]) -> Result<Option<Vec<u8>>> {
        let group_id_str = self.group_id_to_string(group_id);

        // Check cache first
        if let Some(state) = self.cache.lock().await.get(group_id).cloned() {
            log::debug!("Found MLS group state in cache for conversation {}", group_id_str);
            return Ok(Some(state));
        }

        // Load from database
        match self.db.load_mls_group_state(&self.username, &group_id_str).await? {
            Some(state) => {
                log::debug!("Loaded MLS group state from database for conversation {} (size: {} bytes)",
                           group_id_str, state.len());
                // Cache for next time
                self.cache.lock().await.insert(group_id.to_vec(), state.clone());
                Ok(Some(state))
            }
            None => {
                log::debug!("No MLS group state found for conversation {}", group_id_str);
                Ok(None)
            }
        }
    }

    /// Delete group state from persistent storage
    pub async fn delete_group_state(&self, group_id: &[u8]) -> Result<()> {
        let group_id_str = self.group_id_to_string(group_id);

        log::debug!("Deleting MLS group state for conversation {}", group_id_str);

        // Remove from database
        self.db.delete_mls_group_state(&self.username, &group_id_str).await?;

        // Remove from cache
        self.cache.lock().await.remove(group_id);

        log::info!("Successfully deleted MLS group state for conversation {}", group_id_str);
        Ok(())
    }

    /// Check if group state exists
    pub async fn group_exists(&self, group_id: &[u8]) -> Result<bool> {
        let group_id_str = self.group_id_to_string(group_id);

        // Check cache first
        if self.cache.lock().await.contains_key(group_id) {
            return Ok(true);
        }

        // Check database
        let state = self.db.load_mls_group_state(&self.username, &group_id_str).await?;
        Ok(state.is_some())
    }

    /// Clear all cached group states
    pub async fn clear_cache(&self) {
        self.cache.lock().await.clear();
        log::info!("Cleared MLS group state cache for user {}", self.username);
    }

    /// Get the username
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Export all group states for backup
    pub async fn export_all_groups(&self) -> Result<HashMap<String, Vec<u8>>> {
        // This would require a new DB method to list all group IDs
        // For now, return empty map
        Ok(HashMap::new())
    }
}