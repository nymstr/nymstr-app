//! Message storage operations
//!
//! This module contains methods for saving, loading, and managing messages
//! including pending MLS messages for epoch-aware buffering.

use super::{sanitize_table_name, Db, GroupMessage, PendingMlsMessage};
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::Row;

impl Db {
    /// Save a message (to/from) for the given user.
    pub async fn save_message(
        &self,
        me: &str,
        contact: &str,
        sent: bool,
        text: &str,
        ts: DateTime<Utc>,
    ) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("messages_{}", safe_name);
        let msg_type = if sent { "to" } else { "from" };
        sqlx::query(&format!(
            r#"
            INSERT INTO {table} (username, type, message, timestamp)
            VALUES (?, ?, ?, ?)
            "#,
            table = table
        ))
        .bind(contact)
        .bind(msg_type)
        .bind(text)
        .bind(ts)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Load all messages exchanged with a contact for the given user.
    pub async fn load_messages(
        &self,
        me: &str,
        contact: &str,
    ) -> Result<Vec<(bool, String, DateTime<Utc>)>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("messages_{}", safe_name);
        let rows = sqlx::query(&format!(
            r#"
            SELECT type, message, timestamp
            FROM {table}
            WHERE username = ?
            ORDER BY timestamp ASC
            "#,
            table = table
        ))
        .bind(contact)
        .fetch_all(&self.pool)
        .await?;
        let mut msgs = Vec::new();
        for row in rows {
            let t: String = row.try_get("type")?;
            let sent = t == "to";
            let msg: String = row.try_get("message")?;
            let ts: DateTime<Utc> = row.try_get("timestamp")?;
            msgs.push((sent, msg, ts));
        }
        Ok(msgs)
    }

    /// Delete all messages for the specified user.
    #[allow(dead_code)] // Part of public API for message management
    pub async fn delete_all_messages(&self, me: &str) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("messages_{}", safe_name);
        sqlx::query(&format!("DELETE FROM {table}", table = table))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Retrieve all messages for the specified user.
    #[allow(dead_code)] // Part of public API for message management
    pub async fn get_all_messages(
        &self,
        me: &str,
    ) -> Result<Vec<(String, String, String, DateTime<Utc>)>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("messages_{}", safe_name);
        let query = format!(
            "SELECT username, type, message, timestamp FROM {table} ORDER BY username, timestamp ASC",
            table = table
        );
        let rows = sqlx::query(&query).fetch_all(&self.pool).await?;
        let mut msgs = Vec::new();
        for row in rows {
            let username: String = row.try_get("username")?;
            let msg_type: String = row.try_get("type")?;
            let message: String = row.try_get("message")?;
            let ts: DateTime<Utc> = row.try_get("timestamp")?;
            msgs.push((username, msg_type, message, ts));
        }
        Ok(msgs)
    }

    /// Load complete chat history for a user (all contacts and their messages)
    pub async fn load_chat_history(
        &self,
        user: &str,
    ) -> Result<Vec<(String, Vec<(bool, String, chrono::DateTime<chrono::Utc>)>)>> {
        // Get all contacts for this user
        let contacts = self.load_contacts(user).await?;

        let mut chat_history = Vec::new();

        for (contact_name, _contact_pk) in contacts {
            // Load messages for each contact
            let messages = self.load_messages(user, &contact_name).await?;
            chat_history.push((contact_name, messages));
        }

        Ok(chat_history)
    }

    // ========== Pending MLS Messages (Epoch-Aware Buffering) ==========

    /// Store a pending MLS message for later retry
    pub async fn store_pending_message(
        &self,
        me: &str,
        conversation_id: &str,
        sender: &str,
        mls_message_b64: &str,
    ) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("pending_mls_messages_{}", safe_name);
        let received_at = Utc::now().to_rfc3339();

        sqlx::query(&format!(
            r#"
            INSERT OR IGNORE INTO {table} (conversation_id, sender, mls_message_b64, received_at, status)
            VALUES (?, ?, ?, ?, 'pending')
            "#,
            table = table
        ))
        .bind(conversation_id)
        .bind(sender)
        .bind(mls_message_b64)
        .bind(&received_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Get pending messages for a conversation
    pub async fn get_pending_messages(
        &self,
        me: &str,
        conversation_id: &str,
    ) -> Result<Vec<PendingMlsMessage>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("pending_mls_messages_{}", safe_name);

        let rows = sqlx::query(&format!(
            r#"
            SELECT id, conversation_id, sender, mls_message_b64, received_at, retry_count, last_retry_at, status, error_message
            FROM {table}
            WHERE conversation_id = ? AND status = 'pending'
            ORDER BY received_at ASC
            "#,
            table = table
        ))
        .bind(conversation_id)
        .fetch_all(&self.pool)
        .await?;

        let mut messages = Vec::new();
        for row in rows {
            messages.push(PendingMlsMessage {
                id: row.try_get("id")?,
                conversation_id: row.try_get("conversation_id")?,
                sender: row.try_get("sender")?,
                mls_message_b64: row.try_get("mls_message_b64")?,
                received_at: row.try_get("received_at")?,
                retry_count: row.try_get("retry_count")?,
                last_retry_at: row.try_get::<Option<String>, _>("last_retry_at")?,
                status: row.try_get("status")?,
                error_message: row.try_get::<Option<String>, _>("error_message")?,
            });
        }
        Ok(messages)
    }

    /// Get all conversations with pending messages
    pub async fn get_conversations_with_pending(&self, me: &str) -> Result<Vec<String>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("pending_mls_messages_{}", safe_name);

        let rows = sqlx::query(&format!(
            r#"
            SELECT DISTINCT conversation_id
            FROM {table}
            WHERE status = 'pending'
            "#,
            table = table
        ))
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| r.try_get("conversation_id").unwrap())
            .collect())
    }

    /// Mark a pending message as processed
    pub async fn mark_message_processed(&self, me: &str, message_id: i64) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("pending_mls_messages_{}", safe_name);

        sqlx::query(&format!(
            r#"UPDATE {table} SET status = 'processed' WHERE id = ?"#,
            table = table
        ))
        .bind(message_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Mark a pending message as failed with error message
    pub async fn mark_message_failed(&self, me: &str, message_id: i64, error: &str) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("pending_mls_messages_{}", safe_name);

        sqlx::query(&format!(
            r#"UPDATE {table} SET status = 'failed', error_message = ? WHERE id = ?"#,
            table = table
        ))
        .bind(error)
        .bind(message_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Increment retry count for a pending message
    pub async fn increment_retry_count(&self, me: &str, message_id: i64) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("pending_mls_messages_{}", safe_name);
        let last_retry_at = Utc::now().to_rfc3339();

        sqlx::query(&format!(
            r#"UPDATE {table} SET retry_count = retry_count + 1, last_retry_at = ? WHERE id = ?"#,
            table = table
        ))
        .bind(&last_retry_at)
        .bind(message_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Cleanup expired pending messages (older than max_age_secs)
    pub async fn cleanup_expired_messages(&self, me: &str, max_age_secs: i64) -> Result<u64> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("pending_mls_messages_{}", safe_name);
        let cutoff = (Utc::now() - chrono::Duration::seconds(max_age_secs)).to_rfc3339();

        let result = sqlx::query(&format!(
            r#"DELETE FROM {table} WHERE received_at < ? OR status IN ('processed', 'failed')"#,
            table = table
        ))
        .bind(&cutoff)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    // ========== Group Message Storage ==========

    /// Get the last seen message ID for a group server
    pub async fn get_group_cursor(&self, me: &str, group_server: &str) -> Result<i64> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_cursor_{}", safe_name);

        let row = sqlx::query(&format!(
            "SELECT last_seen_id FROM {table} WHERE group_server = ?",
            table = table
        ))
        .bind(group_server)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row
            .map(|r| r.try_get::<i64, _>("last_seen_id").unwrap_or(0))
            .unwrap_or(0))
    }

    /// Update the group cursor after fetching messages
    #[allow(dead_code)] // Part of public API for group message management
    pub async fn update_group_cursor(
        &self,
        me: &str,
        group_server: &str,
        last_seen_id: i64,
    ) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_cursor_{}", safe_name);

        sqlx::query(&format!(
            r#"INSERT OR REPLACE INTO {table} (group_server, last_seen_id, last_fetch_at)
               VALUES (?, ?, CURRENT_TIMESTAMP)"#,
            table = table
        ))
        .bind(group_server)
        .bind(last_seen_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Store fetched group messages
    #[allow(dead_code)] // Part of public API for group message management
    pub async fn store_group_messages(
        &self,
        me: &str,
        group_server: &str,
        messages: Vec<GroupMessage>,
    ) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_messages_{}", safe_name);

        for msg in messages {
            sqlx::query(&format!(
                r#"INSERT OR IGNORE INTO {table}
                   (id, group_server, sender, ciphertext, message_timestamp, fetched_at)
                   VALUES (?, ?, ?, ?, ?, ?)"#,
                table = table
            ))
            .bind(msg.id)
            .bind(group_server)
            .bind(&msg.sender)
            .bind(&msg.ciphertext)
            .bind(&msg.timestamp)
            .bind(msg.fetched_at)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    /// Load group messages for display
    #[allow(dead_code)] // Part of public API for group message management
    pub async fn load_group_messages(
        &self,
        me: &str,
        group_server: &str,
    ) -> Result<Vec<GroupMessage>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_messages_{}", safe_name);

        let rows = sqlx::query(&format!(
            r#"SELECT id, sender, ciphertext, message_timestamp, fetched_at
               FROM {table}
               WHERE group_server = ?
               ORDER BY id ASC"#,
            table = table
        ))
        .bind(group_server)
        .fetch_all(&self.pool)
        .await?;

        let mut messages = Vec::new();
        for row in rows {
            messages.push(GroupMessage {
                id: row.try_get("id")?,
                sender: row.try_get("sender")?,
                ciphertext: row.try_get("ciphertext")?,
                timestamp: row.try_get("message_timestamp")?,
                fetched_at: row.try_get("fetched_at")?,
            });
        }
        Ok(messages)
    }
}
