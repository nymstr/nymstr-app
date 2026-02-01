//! Message storage operations
//!
//! This module contains methods for saving, loading, and managing messages
//! including pending MLS messages for epoch-aware buffering.

use anyhow::Result;
use sqlx::{Row, SqlitePool};

use crate::types::{MessageDTO, MessageStatus};

/// Represents a pending MLS message waiting for epoch sync
#[derive(Debug, Clone)]
pub struct BufferedMessage {
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

/// Message database operations
pub struct MessageDb;

impl MessageDb {
    /// Save a message to a conversation
    pub async fn save_message(pool: &SqlitePool, conv_id: &str, msg: &MessageDTO) -> Result<()> {
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO messages (id, conversation_id, sender, content, timestamp, status, is_own)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&msg.id)
        .bind(conv_id)
        .bind(&msg.sender)
        .bind(&msg.content)
        .bind(&msg.timestamp)
        .bind(status_to_string(&msg.status))
        .bind(msg.is_own)
        .execute(pool)
        .await?;

        tracing::debug!("Saved message {} to conversation {}", msg.id, conv_id);
        Ok(())
    }

    /// Get messages for a conversation with pagination
    pub async fn get_messages(
        pool: &SqlitePool,
        conv_id: &str,
        limit: u32,
    ) -> Result<Vec<MessageDTO>> {
        let rows = sqlx::query(
            r#"
            SELECT id, sender, content, timestamp, status, is_own
            FROM messages
            WHERE conversation_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
            "#,
        )
        .bind(conv_id)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        let mut messages = Vec::new();
        for r in rows {
            messages.push(MessageDTO {
                id: r.try_get("id")?,
                sender: r.try_get("sender")?,
                content: r.try_get("content")?,
                timestamp: r.try_get("timestamp")?,
                status: string_to_status(&r.try_get::<String, _>("status")?),
                is_own: r.try_get("is_own")?,
            });
        }

        // Reverse to get chronological order
        messages.reverse();
        Ok(messages)
    }

    /// Get all messages for a conversation (no limit)
    pub async fn get_all_messages(pool: &SqlitePool, conv_id: &str) -> Result<Vec<MessageDTO>> {
        let rows = sqlx::query(
            r#"
            SELECT id, sender, content, timestamp, status, is_own
            FROM messages
            WHERE conversation_id = ?
            ORDER BY timestamp ASC
            "#,
        )
        .bind(conv_id)
        .fetch_all(pool)
        .await?;

        let mut messages = Vec::new();
        for r in rows {
            messages.push(MessageDTO {
                id: r.try_get("id")?,
                sender: r.try_get("sender")?,
                content: r.try_get("content")?,
                timestamp: r.try_get("timestamp")?,
                status: string_to_status(&r.try_get::<String, _>("status")?),
                is_own: r.try_get("is_own")?,
            });
        }
        Ok(messages)
    }

    /// Update message status
    pub async fn update_status(pool: &SqlitePool, msg_id: &str, status: &MessageStatus) -> Result<()> {
        sqlx::query("UPDATE messages SET status = ? WHERE id = ?")
            .bind(status_to_string(status))
            .bind(msg_id)
            .execute(pool)
            .await?;

        Ok(())
    }

    /// Delete a message
    #[allow(dead_code)]
    pub async fn delete_message(pool: &SqlitePool, msg_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM messages WHERE id = ?")
            .bind(msg_id)
            .execute(pool)
            .await?;

        Ok(())
    }

    /// Delete all messages for a conversation
    #[allow(dead_code)]
    pub async fn delete_conversation_messages(pool: &SqlitePool, conv_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM messages WHERE conversation_id = ?")
            .bind(conv_id)
            .execute(pool)
            .await?;

        Ok(())
    }

    /// Get message count for a conversation
    #[allow(dead_code)]
    pub async fn get_message_count(pool: &SqlitePool, conv_id: &str) -> Result<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM messages WHERE conversation_id = ?")
            .bind(conv_id)
            .fetch_one(pool)
            .await?;

        Ok(row.0)
    }

    // ========== Pending MLS Messages (Epoch Buffer) ==========

    /// Store a pending MLS message for later retry
    pub async fn buffer_message(pool: &SqlitePool, msg: &BufferedMessage) -> Result<()> {
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO pending_mls_messages
            (conversation_id, sender, mls_message_b64, received_at, status)
            VALUES (?, ?, ?, ?, 'pending')
            "#,
        )
        .bind(&msg.conversation_id)
        .bind(&msg.sender)
        .bind(&msg.mls_message_b64)
        .bind(&msg.received_at)
        .execute(pool)
        .await?;

        tracing::debug!(
            "Buffered MLS message for conversation {}",
            msg.conversation_id
        );
        Ok(())
    }

    /// Get buffered messages for a conversation
    pub async fn get_buffered_messages(
        pool: &SqlitePool,
        conv_id: &str,
    ) -> Result<Vec<BufferedMessage>> {
        let rows = sqlx::query(
            r#"
            SELECT id, conversation_id, sender, mls_message_b64, received_at, retry_count, last_retry_at, status, error_message
            FROM pending_mls_messages
            WHERE conversation_id = ? AND status = 'pending'
            ORDER BY received_at ASC
            "#,
        )
        .bind(conv_id)
        .fetch_all(pool)
        .await?;

        let mut messages = Vec::new();
        for r in rows {
            messages.push(BufferedMessage {
                id: r.try_get("id")?,
                conversation_id: r.try_get("conversation_id")?,
                sender: r.try_get("sender")?,
                mls_message_b64: r.try_get("mls_message_b64")?,
                received_at: r.try_get("received_at")?,
                retry_count: r.try_get("retry_count")?,
                last_retry_at: r.try_get("last_retry_at")?,
                status: r.try_get("status")?,
                error_message: r.try_get("error_message")?,
            });
        }
        Ok(messages)
    }

    /// Get all conversations with pending messages
    pub async fn get_conversations_with_pending(pool: &SqlitePool) -> Result<Vec<String>> {
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT conversation_id
            FROM pending_mls_messages
            WHERE status = 'pending'
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| r.try_get("conversation_id").unwrap())
            .collect())
    }

    /// Remove a buffered message by ID
    pub async fn remove_buffered_message(pool: &SqlitePool, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM pending_mls_messages WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        Ok(())
    }

    /// Mark a buffered message as processed
    pub async fn mark_buffered_processed(pool: &SqlitePool, id: i64) -> Result<()> {
        sqlx::query("UPDATE pending_mls_messages SET status = 'processed' WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        Ok(())
    }

    /// Mark a buffered message as failed with error
    pub async fn mark_buffered_failed(pool: &SqlitePool, id: i64, error: &str) -> Result<()> {
        sqlx::query(
            "UPDATE pending_mls_messages SET status = 'failed', error_message = ? WHERE id = ?",
        )
        .bind(error)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Increment retry count for a buffered message
    pub async fn increment_retry_count(pool: &SqlitePool, id: i64) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE pending_mls_messages
            SET retry_count = retry_count + 1, last_retry_at = datetime('now')
            WHERE id = ?
            "#,
        )
        .bind(id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Cleanup expired buffered messages
    pub async fn cleanup_expired_buffered(pool: &SqlitePool, max_age_secs: i64) -> Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM pending_mls_messages
            WHERE datetime(received_at) < datetime('now', ? || ' seconds')
               OR status IN ('processed', 'failed')
            "#,
        )
        .bind(-max_age_secs)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

/// Convert MessageStatus to string for database storage
fn status_to_string(status: &MessageStatus) -> &'static str {
    match status {
        MessageStatus::Pending => "pending",
        MessageStatus::Sent => "sent",
        MessageStatus::Delivered => "delivered",
        MessageStatus::Read => "read",
        MessageStatus::Failed => "failed",
    }
}

/// Convert string from database to MessageStatus
fn string_to_status(s: &str) -> MessageStatus {
    match s {
        "pending" => MessageStatus::Pending,
        "sent" => MessageStatus::Sent,
        "delivered" => MessageStatus::Delivered,
        "read" => MessageStatus::Read,
        "failed" => MessageStatus::Failed,
        _ => MessageStatus::Pending,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    async fn setup_test_db() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                is_own INTEGER NOT NULL DEFAULT 0
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS pending_mls_messages (
                id INTEGER PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                mls_message_b64 TEXT NOT NULL,
                received_at TEXT DEFAULT (datetime('now')),
                retry_count INTEGER DEFAULT 0,
                last_retry_at TEXT,
                status TEXT DEFAULT 'pending',
                error_message TEXT
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        pool
    }

    #[tokio::test]
    async fn test_save_and_get_message() {
        let pool = setup_test_db().await;
        let msg = MessageDTO {
            id: "msg1".to_string(),
            sender: "alice".to_string(),
            content: "Hello!".to_string(),
            timestamp: "2026-01-18T12:00:00Z".to_string(),
            status: MessageStatus::Sent,
            is_own: true,
        };

        MessageDb::save_message(&pool, "conv1", &msg).await.unwrap();
        let messages = MessageDb::get_messages(&pool, "conv1", 10).await.unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, "msg1");
        assert_eq!(messages[0].content, "Hello!");
    }

    #[tokio::test]
    async fn test_buffer_message() {
        let pool = setup_test_db().await;
        let buffered = BufferedMessage {
            id: 0,
            conversation_id: "conv1".to_string(),
            sender: "alice".to_string(),
            mls_message_b64: "base64data".to_string(),
            received_at: "2026-01-18T12:00:00Z".to_string(),
            retry_count: 0,
            last_retry_at: None,
            status: "pending".to_string(),
            error_message: None,
        };

        MessageDb::buffer_message(&pool, &buffered).await.unwrap();
        let messages = MessageDb::get_buffered_messages(&pool, "conv1")
            .await
            .unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].mls_message_b64, "base64data");
    }
}
