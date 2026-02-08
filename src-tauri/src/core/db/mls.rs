//! MLS state and credential operations
//!
//! This module contains methods for managing MLS group state, credentials,
//! key packages, and welcome messages.

use anyhow::Result;
use sqlx::{Row, SqlitePool};

use crate::crypto::mls::types::StoredWelcome;

/// Represents a stored MLS credential
#[derive(Debug, Clone)]
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
pub struct StoredKeyPackage {
    pub id: i64,
    pub key_package_b64: String,
    pub credential_username: Option<String>,
    pub cipher_suite: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

/// MLS database operations
pub struct MlsDb;

impl MlsDb {
    // ========== MLS Group State ==========

    /// Save MLS group state for a conversation
    pub async fn save_group_state(
        pool: &SqlitePool,
        conversation_id: &str,
        group_state: &[u8],
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO mls_groups (conversation_id, group_state, updated_at)
            VALUES (?, ?, datetime('now'))
            "#,
        )
        .bind(conversation_id)
        .bind(group_state)
        .execute(pool)
        .await?;

        tracing::debug!("Saved MLS group state for conversation {}", conversation_id);
        Ok(())
    }

    /// Load MLS group state for a conversation
    pub async fn load_group_state(
        pool: &SqlitePool,
        conversation_id: &str,
    ) -> Result<Option<Vec<u8>>> {
        let row = sqlx::query("SELECT group_state FROM mls_groups WHERE conversation_id = ?")
            .bind(conversation_id)
            .fetch_optional(pool)
            .await?;

        match row {
            Some(r) => Ok(Some(r.try_get("group_state")?)),
            None => Ok(None),
        }
    }

    /// Delete MLS group state for a conversation
    #[allow(dead_code)]
    pub async fn delete_group_state(pool: &SqlitePool, conversation_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM mls_groups WHERE conversation_id = ?")
            .bind(conversation_id)
            .execute(pool)
            .await?;

        Ok(())
    }

    /// List all MLS conversations
    #[allow(dead_code)]
    pub async fn list_conversations(pool: &SqlitePool) -> Result<Vec<String>> {
        let rows =
            sqlx::query("SELECT conversation_id FROM mls_groups ORDER BY updated_at DESC")
                .fetch_all(pool)
                .await?;

        Ok(rows
            .into_iter()
            .map(|r| r.try_get("conversation_id").unwrap())
            .collect())
    }

    // ========== MLS Credential Storage ==========

    /// Store an MLS credential
    pub async fn store_credential(pool: &SqlitePool, credential: &StoredCredential) -> Result<()> {
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO mls_credentials
            (username, pgp_key_fingerprint, mls_signature_key, credential_type, issued_at, expires_at, credential_data, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
            "#,
        )
        .bind(&credential.username)
        .bind(&credential.pgp_key_fingerprint)
        .bind(&credential.mls_signature_key)
        .bind(&credential.credential_type)
        .bind(credential.issued_at)
        .bind(credential.expires_at)
        .bind(&credential.credential_data)
        .execute(pool)
        .await?;

        tracing::debug!("Stored MLS credential for user {}", credential.username);
        Ok(())
    }

    /// Get an MLS credential for a user
    pub async fn get_credential(
        pool: &SqlitePool,
        username: &str,
    ) -> Result<Option<StoredCredential>> {
        let row = sqlx::query(
            r#"
            SELECT username, pgp_key_fingerprint, mls_signature_key, credential_type, issued_at, expires_at, credential_data
            FROM mls_credentials
            WHERE username = ?
            "#,
        )
        .bind(username)
        .fetch_optional(pool)
        .await?;

        match row {
            Some(r) => Ok(Some(StoredCredential {
                username: r.try_get("username")?,
                pgp_key_fingerprint: r.try_get("pgp_key_fingerprint")?,
                mls_signature_key: r.try_get("mls_signature_key")?,
                credential_type: r.try_get("credential_type")?,
                issued_at: r.try_get("issued_at")?,
                expires_at: r.try_get("expires_at")?,
                credential_data: r.try_get("credential_data")?,
            })),
            None => Ok(None),
        }
    }

    /// Delete an MLS credential
    #[allow(dead_code)]
    pub async fn delete_credential(pool: &SqlitePool, username: &str) -> Result<()> {
        sqlx::query("DELETE FROM mls_credentials WHERE username = ?")
            .bind(username)
            .execute(pool)
            .await?;

        Ok(())
    }

    // ========== Key Package Storage ==========

    /// Store a key package
    pub async fn store_key_package(
        pool: &SqlitePool,
        key_package_b64: &str,
        credential_username: Option<&str>,
        cipher_suite: &str,
        expires_at: Option<&str>,
    ) -> Result<i64> {
        let result = sqlx::query(
            r#"
            INSERT INTO key_packages (key_package_b64, credential_username, cipher_suite, expires_at)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(key_package_b64)
        .bind(credential_username)
        .bind(cipher_suite)
        .bind(expires_at)
        .execute(pool)
        .await?;

        let id = result.last_insert_rowid();
        tracing::debug!("Stored key package {}", id);
        Ok(id)
    }

    /// Get an unused key package
    pub async fn get_key_package(pool: &SqlitePool) -> Result<Option<StoredKeyPackage>> {
        let row = sqlx::query(
            r#"
            SELECT id, key_package_b64, credential_username, cipher_suite, created_at, expires_at
            FROM key_packages
            WHERE used = 0 AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
            ORDER BY created_at ASC
            LIMIT 1
            "#,
        )
        .fetch_optional(pool)
        .await?;

        match row {
            Some(r) => Ok(Some(StoredKeyPackage {
                id: r.try_get("id")?,
                key_package_b64: r.try_get("key_package_b64")?,
                credential_username: r.try_get("credential_username")?,
                cipher_suite: r.try_get("cipher_suite")?,
                created_at: r.try_get("created_at")?,
                expires_at: r.try_get("expires_at")?,
            })),
            None => Ok(None),
        }
    }

    /// Mark a key package as used
    pub async fn mark_key_package_used(pool: &SqlitePool, id: i64) -> Result<()> {
        sqlx::query("UPDATE key_packages SET used = 1 WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        Ok(())
    }

    /// Delete expired or used key packages
    #[allow(dead_code)]
    pub async fn cleanup_key_packages(pool: &SqlitePool) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM key_packages WHERE used = 1 OR (expires_at IS NOT NULL AND datetime(expires_at) < datetime('now'))",
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count available key packages
    #[allow(dead_code)]
    pub async fn count_available_key_packages(pool: &SqlitePool) -> Result<i64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM key_packages WHERE used = 0 AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))",
        )
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    // ========== Welcome Message Storage ==========

    /// Store a received Welcome message
    pub async fn save_welcome(pool: &SqlitePool, welcome: &StoredWelcome) -> Result<i64> {
        let result = sqlx::query(
            r#"
            INSERT INTO pending_welcomes (group_id, sender, welcome_bytes, ratchet_tree, cipher_suite, epoch, received_at, processed)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0)
            "#,
        )
        .bind(&welcome.group_id)
        .bind(&welcome.sender)
        .bind(&welcome.welcome_bytes)
        .bind(&welcome.ratchet_tree)
        .bind(welcome.cipher_suite as i64)
        .bind(welcome.epoch as i64)
        .bind(&welcome.received_at)
        .execute(pool)
        .await?;

        let id = result.last_insert_rowid();
        tracing::debug!(
            "Stored welcome {} for group {} from {}",
            id,
            welcome.group_id,
            welcome.sender
        );
        Ok(id)
    }

    /// Get pending Welcome messages that haven't been processed
    pub async fn get_pending_welcomes(pool: &SqlitePool) -> Result<Vec<StoredWelcome>> {
        let rows = sqlx::query(
            r#"
            SELECT id, group_id, sender, welcome_bytes, ratchet_tree, cipher_suite, epoch, received_at, processed, processed_at, error_message
            FROM pending_welcomes
            WHERE processed = 0
            ORDER BY received_at ASC
            "#,
        )
        .fetch_all(pool)
        .await?;

        let mut welcomes = Vec::new();
        for row in rows {
            welcomes.push(StoredWelcome {
                id: row.try_get("id")?,
                group_id: row.try_get("group_id")?,
                sender: row.try_get("sender")?,
                welcome_bytes: row.try_get("welcome_bytes")?,
                ratchet_tree: row.try_get("ratchet_tree")?,
                cipher_suite: row.try_get::<i64, _>("cipher_suite")? as u16,
                epoch: row.try_get::<i64, _>("epoch")? as u64,
                received_at: row.try_get("received_at")?,
                processed: row.try_get("processed")?,
                processed_at: row.try_get("processed_at")?,
                error_message: row.try_get("error_message")?,
            });
        }
        Ok(welcomes)
    }

    /// Mark a Welcome as processed
    pub async fn mark_welcome_processed(pool: &SqlitePool, id: i64) -> Result<()> {
        sqlx::query(
            "UPDATE pending_welcomes SET processed = 1, processed_at = datetime('now') WHERE id = ?",
        )
        .bind(id)
        .execute(pool)
        .await?;

        tracing::debug!("Marked welcome {} as processed", id);
        Ok(())
    }

    /// Mark a Welcome as failed with error message
    #[allow(dead_code)]
    pub async fn mark_welcome_failed(pool: &SqlitePool, id: i64, error: &str) -> Result<()> {
        sqlx::query(
            "UPDATE pending_welcomes SET processed = 1, error_message = ?, processed_at = datetime('now') WHERE id = ?",
        )
        .bind(error)
        .bind(id)
        .execute(pool)
        .await?;

        tracing::warn!("Marked welcome {} as failed: {}", id, error);
        Ok(())
    }

    /// Cleanup old processed welcomes
    #[allow(dead_code)]
    pub async fn cleanup_old_welcomes(pool: &SqlitePool, max_age_secs: i64) -> Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM pending_welcomes
            WHERE processed = 1 AND datetime(processed_at) < datetime('now', ? || ' seconds')
            "#,
        )
        .bind(-max_age_secs)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    async fn setup_test_db() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();

        // Create required tables
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS mls_groups (
                conversation_id TEXT PRIMARY KEY,
                group_state BLOB NOT NULL,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS mls_credentials (
                username TEXT PRIMARY KEY,
                pgp_key_fingerprint BLOB,
                mls_signature_key BLOB,
                credential_type TEXT,
                issued_at INTEGER,
                expires_at INTEGER,
                credential_data BLOB,
                updated_at TEXT DEFAULT (datetime('now'))
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS key_packages (
                id INTEGER PRIMARY KEY,
                key_package_b64 TEXT,
                credential_username TEXT,
                cipher_suite TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                expires_at TEXT,
                used INTEGER DEFAULT 0
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        pool
    }

    #[tokio::test]
    async fn test_save_and_load_group_state() {
        let pool = setup_test_db().await;
        let state = vec![1, 2, 3, 4, 5];

        MlsDb::save_group_state(&pool, "conv1", &state).await.unwrap();
        let loaded = MlsDb::load_group_state(&pool, "conv1").await.unwrap();

        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap(), state);
    }

    #[tokio::test]
    async fn test_key_package_operations() {
        let pool = setup_test_db().await;

        let id = MlsDb::store_key_package(&pool, "base64data", Some("alice"), "X25519-SHA256", None)
            .await
            .unwrap();

        let pkg = MlsDb::get_key_package(&pool).await.unwrap();
        assert!(pkg.is_some());
        let pkg = pkg.unwrap();
        assert_eq!(pkg.key_package_b64, "base64data");

        MlsDb::mark_key_package_used(&pool, id).await.unwrap();

        // Should not get used package
        let pkg = MlsDb::get_key_package(&pool).await.unwrap();
        assert!(pkg.is_none());
    }
}
