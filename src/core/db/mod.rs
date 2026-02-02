//! SQLite persistence using the schema from dbUtils.py
//!
//! This module is split into focused submodules:
//! - `user`: User registration and management operations
//! - `contacts`: Contact management operations
//! - `messages`: Message storage and retrieval
//! - `mls`: MLS state and credential operations
//! - `group`: Group membership and server operations

mod contacts;
mod group;
mod messages;
mod mls;
mod user;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use std::{fs, path::Path};

/// Represents a pending MLS message waiting for epoch sync
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used in database operations
pub struct PendingMlsMessage {
    pub id: i64,
    pub conversation_id: String,
    pub sender: String,
    pub mls_message_b64: String,
    pub received_at: String,
    pub retry_count: i32,
    pub last_retry_at: Option<String>,
    pub status: String,
    pub error_message: Option<String>,
}

/// Represents a fetched group message
#[derive(Debug, Clone)]
#[allow(dead_code)] // Part of public API for group messaging
pub struct GroupMessage {
    pub id: i64,
    pub sender: String,
    pub ciphertext: String,
    pub timestamp: String,
    pub fetched_at: DateTime<Utc>,
}

/// Represents a stored MLS credential
#[derive(Debug, Clone)]
#[allow(dead_code)] // Part of public API for credential management
pub struct StoredCredential {
    pub username: String,
    pub pgp_key_fingerprint: Vec<u8>,
    pub mls_signature_key: Vec<u8>,
    pub credential_type: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub credential_data: Vec<u8>,
}

/// Represents a stored key package
#[derive(Debug, Clone)]
#[allow(dead_code)] // Part of public API for key package management
pub struct StoredKeyPackage {
    pub id: i64,
    pub key_package_b64: String,
    pub credential_username: Option<String>,
    pub cipher_suite: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Represents a group member with verification status
#[derive(Debug, Clone)]
#[allow(dead_code)] // Part of public API for group membership
pub struct GroupMember {
    pub username: String,
    pub credential_fingerprint: Option<String>,
    pub credential_verified: bool,
    pub verified_at: Option<DateTime<Utc>>,
    pub joined_at: DateTime<Utc>,
    pub role: String,
}

/// Re-export StoredWelcome from types for convenience
pub use crate::crypto::mls::types::StoredWelcome;

/// Re-export MlsGroupInfoPublic for convenience
pub use crate::crypto::mls::types::MlsGroupInfoPublic;

/// Get the full path for an MLS database file in the storage directory
pub fn get_mls_db_path(username: &str) -> String {
    format!("storage/nymstr_mls_{}.db", username)
}

/// Sanitize username for use in table names to prevent SQL injection
/// Only allows alphanumeric characters and underscores
pub(crate) fn sanitize_table_name(username: &str) -> Result<String> {
    // Check for empty username
    if username.is_empty() {
        return Err(anyhow!("Username cannot be empty"));
    }

    // Check for maximum length (prevent overly long table names)
    if username.len() > 64 {
        return Err(anyhow!("Username too long (max 64 characters)"));
    }

    // Only allow alphanumeric characters and underscores
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(anyhow!(
            "Invalid characters in username. Only alphanumeric characters and underscores allowed."
        ));
    }

    // Ensure it doesn't start with a number (SQLite table name restriction)
    if username.chars().next().is_some_and(|c| c.is_numeric()) {
        return Err(anyhow!("Username cannot start with a number"));
    }

    Ok(format!("user_{}", username))
}

/// SQLite-backed database.
#[derive(Debug)]
pub struct Db {
    pub(crate) pool: SqlitePool,
}

impl Db {
    /// Open or create a database at the given path.
    pub async fn open(path: &str) -> Result<Self> {
        // ensure parent directories exist so SQLite can create/open the file
        if let Some(dir) = Path::new(path).parent() {
            fs::create_dir_all(dir)?;
        }
        let url = format!("sqlite://{}?mode=rwc", path);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await?;
        Ok(Db { pool })
    }

    /// Create global tables (users).
    pub async fn init_global(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                public_key TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[tokio::test]
    async fn test_register_and_get_user() -> Result<()> {
        let db = Db::open(":memory:").await?;
        db.init_global().await?;
        db.register_user("alice", "pk_alice").await?;
        let user = db.get_user("alice").await?;
        assert_eq!(user, Some(("alice".to_string(), "pk_alice".to_string())));
        Ok(())
    }

    #[tokio::test]
    async fn test_contact_and_messages_flow() -> Result<()> {
        let db = Db::open(":memory:").await?;
        db.init_global().await?;
        db.init_user("bob").await?;
        db.add_contact("bob", "alice", "pk1").await?;
        let ct = db.get_contact("bob", "alice").await?;
        assert_eq!(ct, Some(("alice".to_string(), "pk1".to_string())));

        let ts = Utc::now();
        db.save_message("bob", "alice", true, "hello", ts).await?;
        let msgs = db.load_messages("bob", "alice").await?;
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].0);
        assert_eq!(msgs[0].1, "hello".to_string());
        Ok(())
    }

    #[tokio::test]
    async fn test_delete_contact_and_messages() -> Result<()> {
        let db = Db::open(":memory:").await?;
        db.init_global().await?;
        db.init_user("bob").await?;
        db.add_contact("bob", "alice", "pk1").await?;
        db.delete_contact("bob", "alice").await?;
        assert!(db.get_contact("bob", "alice").await?.is_none());

        let ts = Utc::now();
        db.save_message("bob", "alice", false, "hey", ts).await?;
        db.delete_all_messages("bob").await?;
        let msgs = db.load_messages("bob", "alice").await?;
        assert!(msgs.is_empty());
        Ok(())
    }
}
