//! MLS state and credential operations
//!
//! This module contains methods for managing MLS group state, credentials, key packages,
//! welcomes, and GroupInfo.

use super::{
    sanitize_table_name, Db, MlsGroupInfoPublic, StoredCredential, StoredKeyPackage, StoredWelcome,
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::Row;

impl Db {
    // ========== MLS Group State ==========

    /// Save MLS group state for a conversation.
    pub async fn save_mls_group_state(
        &self,
        me: &str,
        conversation_id: &str,
        group_state: &[u8],
    ) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("mls_groups_{}", safe_name);
        sqlx::query(&format!(
            r#"
            INSERT OR REPLACE INTO {table} (conversation_id, group_state, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            "#,
            table = table
        ))
        .bind(conversation_id)
        .bind(group_state)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Load MLS group state for a conversation.
    #[allow(dead_code)] // Part of public API for MLS state management
    pub async fn load_mls_group_state(
        &self,
        me: &str,
        conversation_id: &str,
    ) -> Result<Option<Vec<u8>>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("mls_groups_{}", safe_name);
        if let Some(row) = sqlx::query(&format!(
            r#"SELECT group_state FROM {table} WHERE conversation_id = ?"#,
            table = table
        ))
        .bind(conversation_id)
        .fetch_optional(&self.pool)
        .await?
        {
            let state: Vec<u8> = row.try_get("group_state")?;
            Ok(Some(state))
        } else {
            Ok(None)
        }
    }

    /// Delete MLS group state for a conversation.
    #[allow(dead_code)] // Part of public API for MLS state management
    pub async fn delete_mls_group_state(&self, me: &str, conversation_id: &str) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("mls_groups_{}", safe_name);
        sqlx::query(&format!(
            "DELETE FROM {table} WHERE conversation_id = ?",
            table = table
        ))
        .bind(conversation_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// List all MLS conversations for a user.
    #[allow(dead_code)] // Part of public API for MLS state management
    pub async fn list_mls_conversations(&self, me: &str) -> Result<Vec<String>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("mls_groups_{}", safe_name);
        let rows = sqlx::query(&format!(
            r#"SELECT conversation_id FROM {table} ORDER BY updated_at DESC"#,
            table = table
        ))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| r.try_get("conversation_id").unwrap())
            .collect())
    }

    // ========== MLS Credential Storage ==========

    /// Store an MLS credential for a user
    #[allow(dead_code)] // Part of public API for MLS credential management
    #[allow(clippy::too_many_arguments)]
    pub async fn store_credential(
        &self,
        me: &str,
        username: &str,
        pgp_key_fingerprint: &[u8],
        mls_signature_key: &[u8],
        credential_type: &str,
        issued_at: i64,
        expires_at: i64,
        credential_data: &[u8],
    ) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("mls_credentials_{}", safe_name);

        sqlx::query(&format!(
            r#"
            INSERT OR REPLACE INTO {table}
            (username, pgp_key_fingerprint, mls_signature_key, credential_type, issued_at, expires_at, credential_data, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            "#,
            table = table
        ))
        .bind(username)
        .bind(pgp_key_fingerprint)
        .bind(mls_signature_key)
        .bind(credential_type)
        .bind(issued_at)
        .bind(expires_at)
        .bind(credential_data)
        .execute(&self.pool)
        .await?;

        log::info!(
            "Stored MLS credential for user {} (owner: {})",
            username,
            me
        );
        Ok(())
    }

    /// Get an MLS credential for a user
    #[allow(dead_code)] // Part of public API for MLS credential management
    pub async fn get_credential(
        &self,
        me: &str,
        username: &str,
    ) -> Result<Option<StoredCredential>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("mls_credentials_{}", safe_name);

        let row = sqlx::query(&format!(
            r#"
            SELECT username, pgp_key_fingerprint, mls_signature_key, credential_type, issued_at, expires_at, credential_data
            FROM {table}
            WHERE username = ?
            "#,
            table = table
        ))
        .bind(username)
        .fetch_optional(&self.pool)
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
    #[allow(dead_code)] // Part of public API for MLS credential management
    pub async fn delete_credential(&self, me: &str, username: &str) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("mls_credentials_{}", safe_name);

        sqlx::query(&format!(
            "DELETE FROM {table} WHERE username = ?",
            table = table
        ))
        .bind(username)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// List all stored credentials
    #[allow(dead_code)] // Part of public API for MLS credential management
    pub async fn list_credentials(&self, me: &str) -> Result<Vec<StoredCredential>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("mls_credentials_{}", safe_name);

        let rows = sqlx::query(&format!(
            r#"
            SELECT username, pgp_key_fingerprint, mls_signature_key, credential_type, issued_at, expires_at, credential_data
            FROM {table}
            ORDER BY username
            "#,
            table = table
        ))
        .fetch_all(&self.pool)
        .await?;

        let mut credentials = Vec::new();
        for r in rows {
            credentials.push(StoredCredential {
                username: r.try_get("username")?,
                pgp_key_fingerprint: r.try_get("pgp_key_fingerprint")?,
                mls_signature_key: r.try_get("mls_signature_key")?,
                credential_type: r.try_get("credential_type")?,
                issued_at: r.try_get("issued_at")?,
                expires_at: r.try_get("expires_at")?,
                credential_data: r.try_get("credential_data")?,
            });
        }
        Ok(credentials)
    }

    // ========== Key Package Storage ==========

    /// Store a key package
    #[allow(dead_code)] // Part of public API for key package management
    pub async fn store_key_package(
        &self,
        me: &str,
        key_package_b64: &str,
        credential_username: Option<&str>,
        cipher_suite: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<i64> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("key_packages_{}", safe_name);

        let result = sqlx::query(&format!(
            r#"
            INSERT INTO {table} (key_package_b64, credential_username, cipher_suite, expires_at)
            VALUES (?, ?, ?, ?)
            "#,
            table = table
        ))
        .bind(key_package_b64)
        .bind(credential_username)
        .bind(cipher_suite)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        let id = result.last_insert_rowid();
        log::info!("Stored key package {} for user {}", id, me);
        Ok(id)
    }

    /// Get an unused key package
    #[allow(dead_code)] // Part of public API for key package management
    pub async fn get_key_package(&self, me: &str) -> Result<Option<StoredKeyPackage>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("key_packages_{}", safe_name);

        let row = sqlx::query(&format!(
            r#"
            SELECT id, key_package_b64, credential_username, cipher_suite, created_at, expires_at
            FROM {table}
            WHERE used = FALSE AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
            ORDER BY created_at ASC
            LIMIT 1
            "#,
            table = table
        ))
        .fetch_optional(&self.pool)
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
    #[allow(dead_code)] // Part of public API for key package management
    pub async fn mark_key_package_used(&self, me: &str, key_package_id: i64) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("key_packages_{}", safe_name);

        sqlx::query(&format!(
            "UPDATE {table} SET used = TRUE WHERE id = ?",
            table = table
        ))
        .bind(key_package_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Delete expired or used key packages
    #[allow(dead_code)] // Part of public API for key package management
    pub async fn cleanup_key_packages(&self, me: &str) -> Result<u64> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("key_packages_{}", safe_name);

        let result = sqlx::query(&format!(
            "DELETE FROM {table} WHERE used = TRUE OR (expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP)",
            table = table
        ))
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count available key packages
    #[allow(dead_code)] // Part of public API for key package management
    pub async fn count_available_key_packages(&self, me: &str) -> Result<i64> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("key_packages_{}", safe_name);

        let row = sqlx::query(&format!(
            "SELECT COUNT(*) as count FROM {table} WHERE used = FALSE AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)",
            table = table
        ))
        .fetch_one(&self.pool)
        .await?;

        Ok(row.try_get("count")?)
    }

    // ========== Welcome Message Storage ==========

    /// Store a received Welcome message
    ///
    /// # Arguments
    /// * `me` - The current user
    /// * `welcome` - The StoredWelcome struct containing all fields
    ///
    /// # Returns
    /// The ID of the stored welcome
    pub async fn store_welcome(&self, me: &str, welcome: &StoredWelcome) -> Result<i64> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_welcomes_{}", safe_name);

        use base64::Engine;
        let welcome_bytes = base64::engine::general_purpose::STANDARD
            .decode(&welcome.welcome_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to decode welcome_bytes: {}", e))?;
        let ratchet_tree = welcome
            .ratchet_tree
            .as_ref()
            .map(|rt| base64::engine::general_purpose::STANDARD.decode(rt))
            .transpose()
            .map_err(|e| anyhow::anyhow!("Failed to decode ratchet_tree: {}", e))?;

        let result = sqlx::query(&format!(
            r#"
            INSERT INTO {table} (group_id, sender, welcome_bytes, ratchet_tree, cipher_suite, epoch, received_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
            table = table
        ))
        .bind(&welcome.group_id)
        .bind(&welcome.sender)
        .bind(&welcome_bytes)
        .bind(&ratchet_tree)
        .bind(welcome.cipher_suite as i64)
        .bind(welcome.epoch as i64)
        .bind(&welcome.received_at)
        .execute(&self.pool)
        .await?;

        let id = result.last_insert_rowid();
        log::info!(
            "Stored welcome {} for group {} from {} (user: {})",
            id,
            &welcome.group_id,
            &welcome.sender,
            me
        );
        Ok(id)
    }

    /// Get pending Welcome messages that haven't been processed
    #[allow(dead_code)] // Part of public API for welcome management
    pub async fn get_pending_welcomes(&self, me: &str) -> Result<Vec<StoredWelcome>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_welcomes_{}", safe_name);

        let rows = sqlx::query(&format!(
            r#"
            SELECT id, group_id, sender, welcome_bytes, ratchet_tree, cipher_suite, epoch, received_at, processed, processed_at, error_message
            FROM {table}
            WHERE processed = FALSE
            ORDER BY received_at ASC
            "#,
            table = table
        ))
        .fetch_all(&self.pool)
        .await?;

        use base64::Engine;
        let mut welcomes = Vec::new();
        for row in rows {
            let welcome_bytes_raw: Vec<u8> = row.try_get("welcome_bytes")?;
            let ratchet_tree_raw: Option<Vec<u8>> = row.try_get("ratchet_tree")?;

            welcomes.push(StoredWelcome {
                id: row.try_get("id")?,
                group_id: row.try_get("group_id")?,
                sender: row.try_get("sender")?,
                welcome_bytes: base64::engine::general_purpose::STANDARD.encode(&welcome_bytes_raw),
                ratchet_tree: ratchet_tree_raw
                    .map(|rt| base64::engine::general_purpose::STANDARD.encode(&rt)),
                cipher_suite: row.try_get::<i64, _>("cipher_suite")? as u16,
                epoch: row.try_get::<i64, _>("epoch")? as u64,
                received_at: row.try_get::<String, _>("received_at")?,
                processed: row.try_get("processed")?,
                processed_at: row.try_get("processed_at")?,
                error_message: row.try_get("error_message")?,
            });
        }
        Ok(welcomes)
    }

    /// Mark a Welcome as processed
    pub async fn mark_welcome_processed(&self, me: &str, welcome_id: i64) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_welcomes_{}", safe_name);

        sqlx::query(&format!(
            r#"UPDATE {table} SET processed = TRUE, processed_at = CURRENT_TIMESTAMP WHERE id = ?"#,
            table = table
        ))
        .bind(welcome_id)
        .execute(&self.pool)
        .await?;

        log::info!("Marked welcome {} as processed for user {}", welcome_id, me);
        Ok(())
    }

    /// Mark a Welcome as failed with error message
    #[allow(dead_code)] // Part of public API for welcome management
    pub async fn mark_welcome_failed(&self, me: &str, welcome_id: i64, error: &str) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_welcomes_{}", safe_name);

        sqlx::query(&format!(
            r#"UPDATE {table} SET processed = TRUE, error_message = ?, processed_at = CURRENT_TIMESTAMP WHERE id = ?"#,
            table = table
        ))
        .bind(error)
        .bind(welcome_id)
        .execute(&self.pool)
        .await?;

        log::warn!(
            "Marked welcome {} as failed for user {}: {}",
            welcome_id,
            me,
            error
        );
        Ok(())
    }

    /// Cleanup old processed welcomes
    #[allow(dead_code)] // Part of public API for welcome management
    pub async fn cleanup_old_welcomes(&self, me: &str, max_age_secs: i64) -> Result<u64> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_welcomes_{}", safe_name);

        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64 - max_age_secs)
            .unwrap_or(0);

        let result = sqlx::query(&format!(
            "DELETE FROM {table} WHERE processed = TRUE AND received_at < ?",
            table = table
        ))
        .bind(cutoff)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    // ========== GroupInfo Storage ==========

    /// Store published GroupInfo
    #[allow(dead_code)] // Part of public API for group info management
    pub async fn store_group_info(
        &self,
        me: &str,
        group_id: &str,
        group_info: &MlsGroupInfoPublic,
    ) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_info_{}", safe_name);

        // Decode the base64-encoded fields
        let group_info_bytes = group_info.decode_group_info_bytes()?;
        let external_pub = group_info.decode_external_pub()?;

        sqlx::query(&format!(
            r#"
            INSERT OR REPLACE INTO {table}
            (group_id, mls_group_id, epoch, tree_hash, group_info_bytes, external_pub, created_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            "#,
            table = table
        ))
        .bind(group_id)
        .bind(&group_info.mls_group_id)
        .bind(group_info.epoch as i64)
        .bind(&group_info.tree_hash)
        .bind(&group_info_bytes)
        .bind(external_pub.as_deref())
        .bind(&group_info.created_by)
        .bind(group_info.created_at as i64)
        .execute(&self.pool)
        .await?;

        log::info!(
            "Stored group info for {} at epoch {} (user: {})",
            group_id,
            group_info.epoch,
            me
        );
        Ok(())
    }

    /// Get GroupInfo for a group
    #[allow(dead_code)] // Part of public API for group info management
    pub async fn get_group_info(
        &self,
        me: &str,
        group_id: &str,
    ) -> Result<Option<MlsGroupInfoPublic>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_info_{}", safe_name);

        let row = sqlx::query(&format!(
            r#"
            SELECT group_id, mls_group_id, epoch, tree_hash, group_info_bytes, external_pub, created_by, created_at
            FROM {table}
            WHERE group_id = ?
            "#,
            table = table
        ))
        .bind(group_id)
        .fetch_optional(&self.pool)
        .await?;

        use base64::Engine;
        match row {
            Some(r) => {
                let group_info_bytes_raw: Vec<u8> = r.try_get("group_info_bytes")?;
                let external_pub_raw: Option<Vec<u8>> = r.try_get("external_pub")?;

                Ok(Some(MlsGroupInfoPublic {
                    group_id: r.try_get("group_id")?,
                    mls_group_id: r
                        .try_get::<Option<String>, _>("mls_group_id")?
                        .unwrap_or_default(),
                    epoch: r.try_get::<i64, _>("epoch")? as u64,
                    tree_hash: r.try_get("tree_hash")?,
                    group_info_bytes: base64::engine::general_purpose::STANDARD
                        .encode(&group_info_bytes_raw),
                    external_pub: external_pub_raw
                        .map(|ep| base64::engine::general_purpose::STANDARD.encode(&ep)),
                    created_by: r.try_get("created_by")?,
                    created_at: r.try_get::<i64, _>("created_at")? as u64,
                }))
            }
            None => Ok(None),
        }
    }

    /// Update GroupInfo for a group (when epoch changes)
    #[allow(dead_code)] // Part of public API for group info management
    pub async fn update_group_info(
        &self,
        me: &str,
        group_id: &str,
        epoch: u64,
        tree_hash: &[u8],
        group_info_bytes: &[u8],
    ) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_info_{}", safe_name);

        sqlx::query(&format!(
            r#"
            UPDATE {table}
            SET epoch = ?, tree_hash = ?, group_info_bytes = ?, updated_at = CURRENT_TIMESTAMP
            WHERE group_id = ?
            "#,
            table = table
        ))
        .bind(epoch as i64)
        .bind(tree_hash)
        .bind(group_info_bytes)
        .bind(group_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Delete GroupInfo for a group
    #[allow(dead_code)] // Part of public API for group info management
    pub async fn delete_group_info(&self, me: &str, group_id: &str) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_info_{}", safe_name);

        sqlx::query(&format!(
            "DELETE FROM {table} WHERE group_id = ?",
            table = table
        ))
        .bind(group_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// List all stored GroupInfo
    #[allow(dead_code)] // Part of public API for group info management
    pub async fn list_group_info(&self, me: &str) -> Result<Vec<MlsGroupInfoPublic>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_info_{}", safe_name);

        let rows = sqlx::query(&format!(
            r#"
            SELECT group_id, mls_group_id, epoch, tree_hash, group_info_bytes, external_pub, created_by, created_at
            FROM {table}
            ORDER BY created_at DESC
            "#,
            table = table
        ))
        .fetch_all(&self.pool)
        .await?;

        use base64::Engine;
        let mut groups = Vec::new();
        for r in rows {
            let group_info_bytes_raw: Vec<u8> = r.try_get("group_info_bytes")?;
            let external_pub_raw: Option<Vec<u8>> = r.try_get("external_pub")?;

            groups.push(MlsGroupInfoPublic {
                group_id: r.try_get("group_id")?,
                mls_group_id: r
                    .try_get::<Option<String>, _>("mls_group_id")?
                    .unwrap_or_default(),
                epoch: r.try_get::<i64, _>("epoch")? as u64,
                tree_hash: r.try_get("tree_hash")?,
                group_info_bytes: base64::engine::general_purpose::STANDARD
                    .encode(&group_info_bytes_raw),
                external_pub: external_pub_raw
                    .map(|ep| base64::engine::general_purpose::STANDARD.encode(&ep)),
                created_by: r.try_get("created_by")?,
                created_at: r.try_get::<i64, _>("created_at")? as u64,
            });
        }
        Ok(groups)
    }
}
