//! Epoch-aware message buffer for MLS protocol
//!
//! This module handles out-of-order message delivery from the Nym mixnet by buffering
//! messages that arrive before their epoch can be processed. The MLS protocol requires
//! strict message ordering within epochs - messages encrypted under epoch N cannot be
//! decrypted if the client is at epoch N-1 (missing a Commit) or has already advanced to N+1.

#![allow(dead_code)] // Methods are part of the public API for epoch buffering

use anyhow::{anyhow, Result};
use log::{debug, info, warn};
use sqlx::SqlitePool;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Maximum time (in seconds) to keep a message in the buffer before expiring
pub const MAX_BUFFER_AGE_SECS: i64 = 300; // 5 minutes

/// Maximum number of pending messages per conversation in memory
pub const MAX_BUFFER_SIZE: usize = 100;

/// Maximum retry attempts before marking a message as failed
pub const MAX_RETRY_COUNT: i32 = 10;

/// Pending MLS message from the database
#[derive(Debug, Clone)]
pub struct PendingMlsMessage {
    pub id: i64,
    pub conversation_id: String,
    pub sender: String,
    pub mls_message_b64: String,
    pub received_at: String,
    pub retry_count: i32,
}

/// In-memory pending message for fast access
#[derive(Debug, Clone)]
pub struct BufferedMessage {
    pub sender: String,
    pub mls_message_b64: String,
    pub received_at: chrono::DateTime<chrono::Utc>,
    pub retry_count: i32,
    pub db_id: Option<i64>,
}

/// Epoch-aware message buffer that handles out-of-order MLS messages
///
/// Messages that cannot be processed due to epoch mismatch are queued here
/// and retried when the epoch advances (e.g., after receiving a Commit).
pub struct EpochAwareBuffer {
    /// In-memory buffer for fast access (conversation_id -> pending messages)
    memory_buffer: Arc<Mutex<HashMap<String, VecDeque<BufferedMessage>>>>,
    /// Track known epochs per conversation for optimization
    known_epochs: Arc<Mutex<HashMap<String, u64>>>,
    /// Database connection pool for persistence
    db: SqlitePool,
    /// Current username for database operations
    username: Arc<Mutex<Option<String>>>,
}

impl EpochAwareBuffer {
    /// Create a new epoch-aware buffer with database persistence
    pub fn new(db: SqlitePool) -> Self {
        Self {
            memory_buffer: Arc::new(Mutex::new(HashMap::new())),
            known_epochs: Arc::new(Mutex::new(HashMap::new())),
            db,
            username: Arc::new(Mutex::new(None)),
        }
    }

    /// Set the current username for database operations
    pub async fn set_username(&self, username: &str) {
        let mut user = self.username.lock().await;
        *user = Some(username.to_string());
    }

    /// Get the current username
    async fn get_username(&self) -> Result<String> {
        let user = self.username.lock().await;
        user.clone()
            .ok_or_else(|| anyhow!("Username not set in epoch buffer"))
    }

    /// Ensure the pending_mls_messages table exists
    async fn ensure_table(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS pending_mls_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                mls_message_b64 TEXT NOT NULL,
                received_at TEXT NOT NULL,
                retry_count INTEGER NOT NULL DEFAULT 0,
                processed INTEGER NOT NULL DEFAULT 0,
                failed INTEGER NOT NULL DEFAULT 0,
                error_message TEXT
            )
            "#,
        )
        .execute(&self.db)
        .await
        .map_err(|e| anyhow!("Failed to create pending_mls_messages table: {}", e))?;

        // Create index for faster queries
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_pending_mls_conversation
            ON pending_mls_messages (conversation_id, processed)
            "#,
        )
        .execute(&self.db)
        .await
        .ok(); // Ignore errors on index creation

        Ok(())
    }

    /// Queue a message that couldn't be processed due to epoch mismatch
    pub async fn queue_message(
        &self,
        conv_id: &str,
        sender: &str,
        mls_message_b64: &str,
    ) -> Result<()> {
        self.ensure_table().await?;

        let received_at = chrono::Utc::now().to_rfc3339();

        // Store in database for persistence
        sqlx::query(
            r#"
            INSERT INTO pending_mls_messages (conversation_id, sender, mls_message_b64, received_at)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(conv_id)
        .bind(sender)
        .bind(mls_message_b64)
        .bind(&received_at)
        .execute(&self.db)
        .await
        .map_err(|e| anyhow!("Failed to store pending message: {}", e))?;

        // Also buffer in memory for fast retry
        let buffered = BufferedMessage {
            sender: sender.to_string(),
            mls_message_b64: mls_message_b64.to_string(),
            received_at: chrono::Utc::now(),
            retry_count: 0,
            db_id: None, // Will be set on reload from DB
        };

        let mut buffer = self.memory_buffer.lock().await;
        let queue = buffer
            .entry(conv_id.to_string())
            .or_insert_with(VecDeque::new);

        // Enforce memory limit - overflow to DB only
        if queue.len() >= MAX_BUFFER_SIZE {
            warn!(
                "Memory buffer full for conversation {}, message stored in DB only",
                conv_id
            );
        } else {
            queue.push_back(buffered);
        }

        info!(
            "Queued message for conversation {} (sender: {}, buffer size: {})",
            conv_id,
            sender,
            queue.len()
        );

        Ok(())
    }

    /// Update the known epoch for a conversation
    ///
    /// Called after successfully processing a Commit message
    pub async fn update_epoch(&self, conv_id: &str, epoch: u64) {
        let mut epochs = self.known_epochs.lock().await;
        let previous = epochs.insert(conv_id.to_string(), epoch);

        if let Some(prev) = previous {
            if epoch > prev {
                info!(
                    "Epoch advanced for conversation {}: {} -> {}",
                    conv_id, prev, epoch
                );
            }
        } else {
            info!("Initial epoch set for conversation {}: {}", conv_id, epoch);
        }
    }

    /// Get the known epoch for a conversation
    pub async fn get_known_epoch(&self, conv_id: &str) -> Option<u64> {
        let epochs = self.known_epochs.lock().await;
        epochs.get(conv_id).copied()
    }

    /// Get pending messages from memory buffer for retry
    pub async fn get_memory_pending(&self, conv_id: &str) -> Vec<BufferedMessage> {
        let buffer = self.memory_buffer.lock().await;
        buffer
            .get(conv_id)
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get pending messages from database for retry
    pub async fn get_db_pending(&self, conv_id: &str) -> Result<Vec<PendingMlsMessage>> {
        self.ensure_table().await?;

        let messages: Vec<(i64, String, String, String, String, i32)> = sqlx::query_as(
            r#"
            SELECT id, conversation_id, sender, mls_message_b64, received_at, retry_count
            FROM pending_mls_messages
            WHERE conversation_id = ? AND processed = 0 AND failed = 0
            ORDER BY received_at ASC
            "#,
        )
        .bind(conv_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| anyhow!("Failed to fetch pending messages: {}", e))?;

        Ok(messages
            .into_iter()
            .map(
                |(id, conversation_id, sender, mls_message_b64, received_at, retry_count)| {
                    PendingMlsMessage {
                        id,
                        conversation_id,
                        sender,
                        mls_message_b64,
                        received_at,
                        retry_count,
                    }
                },
            )
            .collect())
    }

    /// Get all retry candidates for a conversation (combines memory and DB)
    pub async fn get_retry_candidates(&self, conv_id: &str) -> Result<Vec<BufferedMessage>> {
        // First get from memory
        let memory_pending = self.get_memory_pending(conv_id).await;

        // Then get from DB and merge (avoiding duplicates based on message content)
        let db_pending = self.get_db_pending(conv_id).await?;

        let mut candidates: HashMap<String, BufferedMessage> = HashMap::new();

        // Add memory messages first
        for msg in memory_pending {
            candidates.insert(msg.mls_message_b64.clone(), msg);
        }

        // Add DB messages (will update with DB ID if exists)
        for db_msg in db_pending {
            let entry = candidates
                .entry(db_msg.mls_message_b64.clone())
                .or_insert_with(|| BufferedMessage {
                    sender: db_msg.sender.clone(),
                    mls_message_b64: db_msg.mls_message_b64.clone(),
                    received_at: chrono::DateTime::parse_from_rfc3339(&db_msg.received_at)
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                        .unwrap_or_else(|_| chrono::Utc::now()),
                    retry_count: db_msg.retry_count,
                    db_id: Some(db_msg.id),
                });
            entry.db_id = Some(db_msg.id);
            entry.retry_count = db_msg.retry_count;
        }

        Ok(candidates.into_values().collect())
    }

    /// Mark a message as successfully processed
    pub async fn mark_processed(&self, conv_id: &str, mls_message_b64: &str) -> Result<()> {
        // Remove from memory buffer
        {
            let mut buffer = self.memory_buffer.lock().await;
            if let Some(queue) = buffer.get_mut(conv_id) {
                queue.retain(|m| m.mls_message_b64 != mls_message_b64);
            }
        }

        // Mark as processed in database
        sqlx::query(
            r#"
            UPDATE pending_mls_messages
            SET processed = 1
            WHERE conversation_id = ? AND mls_message_b64 = ? AND processed = 0
            "#,
        )
        .bind(conv_id)
        .bind(mls_message_b64)
        .execute(&self.db)
        .await
        .map_err(|e| anyhow!("Failed to mark message as processed: {}", e))?;

        debug!("Marked message as processed in conversation {}", conv_id);

        Ok(())
    }

    /// Mark a message as failed after exceeding retry limit
    pub async fn mark_failed(
        &self,
        conv_id: &str,
        mls_message_b64: &str,
        error: &str,
    ) -> Result<()> {
        // Remove from memory buffer
        {
            let mut buffer = self.memory_buffer.lock().await;
            if let Some(queue) = buffer.get_mut(conv_id) {
                queue.retain(|m| m.mls_message_b64 != mls_message_b64);
            }
        }

        // Mark as failed in database
        sqlx::query(
            r#"
            UPDATE pending_mls_messages
            SET failed = 1, error_message = ?
            WHERE conversation_id = ? AND mls_message_b64 = ?
            "#,
        )
        .bind(error)
        .bind(conv_id)
        .bind(mls_message_b64)
        .execute(&self.db)
        .await
        .map_err(|e| anyhow!("Failed to mark message as failed: {}", e))?;

        warn!(
            "Marked message as failed in conversation {}: {}",
            conv_id, error
        );

        Ok(())
    }

    /// Increment retry count for a message
    pub async fn increment_retry(&self, conv_id: &str, mls_message_b64: &str) -> Result<i32> {
        let mut new_count = 0;

        // Update in memory buffer
        {
            let mut buffer = self.memory_buffer.lock().await;
            if let Some(queue) = buffer.get_mut(conv_id) {
                for msg in queue.iter_mut() {
                    if msg.mls_message_b64 == mls_message_b64 {
                        msg.retry_count += 1;
                        new_count = msg.retry_count;
                        break;
                    }
                }
            }
        }

        // Update in database
        sqlx::query(
            r#"
            UPDATE pending_mls_messages
            SET retry_count = retry_count + 1
            WHERE conversation_id = ? AND mls_message_b64 = ?
            "#,
        )
        .bind(conv_id)
        .bind(mls_message_b64)
        .execute(&self.db)
        .await
        .map_err(|e| anyhow!("Failed to increment retry count: {}", e))?;

        // Get actual count from DB
        let result: Option<(i32,)> = sqlx::query_as(
            "SELECT retry_count FROM pending_mls_messages WHERE conversation_id = ? AND mls_message_b64 = ?",
        )
        .bind(conv_id)
        .bind(mls_message_b64)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| anyhow!("Failed to get retry count: {}", e))?;

        if let Some((count,)) = result {
            new_count = count;
        }

        Ok(new_count)
    }

    /// Get all conversations that have pending messages
    pub async fn get_conversations_with_pending(&self) -> Result<Vec<String>> {
        self.ensure_table().await?;

        // Get from DB
        let db_convs: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT DISTINCT conversation_id
            FROM pending_mls_messages
            WHERE processed = 0 AND failed = 0
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| anyhow!("Failed to fetch conversations with pending: {}", e))?;

        // Also check memory buffer
        let buffer = self.memory_buffer.lock().await;
        let memory_convs: Vec<String> = buffer
            .iter()
            .filter(|(_, q)| !q.is_empty())
            .map(|(k, _)| k.clone())
            .collect();

        // Merge and dedupe
        let mut all_convs: HashSet<String> = db_convs.into_iter().map(|(c,)| c).collect();
        all_convs.extend(memory_convs);

        Ok(all_convs.into_iter().collect())
    }

    /// Cleanup expired messages
    pub async fn cleanup_expired(&self, max_age_secs: i64) -> Result<u64> {
        self.ensure_table().await?;

        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(max_age_secs);
        let cutoff_str = cutoff.to_rfc3339();

        // Clean DB
        let result = sqlx::query(
            r#"
            DELETE FROM pending_mls_messages
            WHERE received_at < ? AND processed = 0
            "#,
        )
        .bind(&cutoff_str)
        .execute(&self.db)
        .await
        .map_err(|e| anyhow!("Failed to cleanup expired messages: {}", e))?;

        let deleted = result.rows_affected();

        // Clean memory buffer
        {
            let mut buffer = self.memory_buffer.lock().await;
            for queue in buffer.values_mut() {
                queue.retain(|m| m.received_at > cutoff);
            }
            // Remove empty queues
            buffer.retain(|_, q| !q.is_empty());
        }

        if deleted > 0 {
            info!("Cleaned up {} expired pending messages", deleted);
        }

        Ok(deleted)
    }

    /// Reload pending messages from database into memory buffer
    ///
    /// Call this after app restart to recover buffered messages
    pub async fn reload_from_db(&self) -> Result<usize> {
        self.ensure_table().await?;

        let conversations = self.get_conversations_with_pending().await?;
        let mut total_loaded = 0;

        let mut buffer = self.memory_buffer.lock().await;

        for conv_id in conversations {
            let db_pending: Vec<(i64, String, String, String, String, i32)> = sqlx::query_as(
                r#"
                SELECT id, conversation_id, sender, mls_message_b64, received_at, retry_count
                FROM pending_mls_messages
                WHERE conversation_id = ? AND processed = 0 AND failed = 0
                ORDER BY received_at ASC
                "#,
            )
            .bind(&conv_id)
            .fetch_all(&self.db)
            .await
            .map_err(|e| anyhow!("Failed to reload pending messages: {}", e))?;

            let queue = buffer
                .entry(conv_id.clone())
                .or_insert_with(VecDeque::new);

            for (id, _, sender, mls_message_b64, received_at, retry_count) in db_pending {
                // Only load up to MAX_BUFFER_SIZE per conversation
                if queue.len() >= MAX_BUFFER_SIZE {
                    break;
                }

                let buffered = BufferedMessage {
                    sender,
                    mls_message_b64,
                    received_at: chrono::DateTime::parse_from_rfc3339(&received_at)
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                        .unwrap_or_else(|_| chrono::Utc::now()),
                    retry_count,
                    db_id: Some(id),
                };

                queue.push_back(buffered);
                total_loaded += 1;
            }
        }

        if total_loaded > 0 {
            info!("Reloaded {} pending messages from database", total_loaded);
        }

        Ok(total_loaded)
    }

    /// Get buffer statistics for monitoring
    pub async fn get_stats(&self) -> BufferStats {
        let buffer = self.memory_buffer.lock().await;
        let epochs = self.known_epochs.lock().await;

        let total_memory = buffer.values().map(|q| q.len()).sum();
        let conversations = buffer.len();
        let tracked_epochs = epochs.len();

        BufferStats {
            total_memory_messages: total_memory,
            conversations_with_pending: conversations,
            tracked_epochs,
        }
    }
}

/// Statistics about the epoch buffer
#[derive(Debug, Clone)]
pub struct BufferStats {
    pub total_memory_messages: usize,
    pub conversations_with_pending: usize,
    pub tracked_epochs: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_constants() {
        assert_eq!(MAX_BUFFER_AGE_SECS, 300);
        assert_eq!(MAX_BUFFER_SIZE, 100);
        assert_eq!(MAX_RETRY_COUNT, 10);
    }

    #[test]
    fn test_buffered_message() {
        let msg = BufferedMessage {
            sender: "alice".to_string(),
            mls_message_b64: "dGVzdA==".to_string(),
            received_at: chrono::Utc::now(),
            retry_count: 0,
            db_id: None,
        };

        assert_eq!(msg.sender, "alice");
        assert_eq!(msg.retry_count, 0);
    }

    #[test]
    fn test_buffer_stats() {
        let stats = BufferStats {
            total_memory_messages: 10,
            conversations_with_pending: 3,
            tracked_epochs: 5,
        };

        assert_eq!(stats.total_memory_messages, 10);
        assert_eq!(stats.conversations_with_pending, 3);
        assert_eq!(stats.tracked_epochs, 5);
    }
}
