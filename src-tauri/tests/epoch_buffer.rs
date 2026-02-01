//! Integration tests for the epoch-aware message buffer
//!
//! Tests the critical functionality of buffering out-of-order MLS messages
//! due to mixnet latency and retrying them when epochs advance.

mod common;

use anyhow::Result;
use chrono::{Duration, Utc};
use nymstr_app_v2_lib::crypto::mls::epoch_buffer::{
    EpochAwareBuffer, BufferedMessage, MAX_BUFFER_AGE_SECS, MAX_BUFFER_SIZE, MAX_RETRY_COUNT,
};
use common::TestContext;

/// Test that messages are correctly queued when they can't be processed
#[tokio::test]
async fn test_message_buffering_basic() -> Result<()> {
    let ctx = TestContext::new().await?;
    let buffer = EpochAwareBuffer::new(ctx.db.clone());
    buffer.set_username("alice").await;

    // Queue a message
    buffer.queue_message("conv1", "bob", "encrypted_message_b64").await?;

    // Verify it's in the buffer
    let pending = buffer.get_retry_candidates("conv1").await?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].sender, "bob");
    assert_eq!(pending[0].mls_message_b64, "encrypted_message_b64");

    Ok(())
}

/// Test that multiple messages for the same conversation are queued in order
#[tokio::test]
async fn test_message_buffering_multiple() -> Result<()> {
    let ctx = TestContext::new().await?;
    let buffer = EpochAwareBuffer::new(ctx.db.clone());
    buffer.set_username("alice").await;

    // Queue multiple messages
    buffer.queue_message("conv1", "bob", "msg1").await?;
    buffer.queue_message("conv1", "charlie", "msg2").await?;
    buffer.queue_message("conv1", "bob", "msg3").await?;

    let pending = buffer.get_retry_candidates("conv1").await?;
    assert_eq!(pending.len(), 3);

    Ok(())
}

/// Test that marking a message as processed removes it from the buffer
#[tokio::test]
async fn test_mark_processed_removes_from_buffer() -> Result<()> {
    let ctx = TestContext::new().await?;
    let buffer = EpochAwareBuffer::new(ctx.db.clone());
    buffer.set_username("alice").await;

    buffer.queue_message("conv1", "bob", "msg1").await?;
    buffer.queue_message("conv1", "bob", "msg2").await?;

    // Mark first message as processed
    buffer.mark_processed("conv1", "msg1").await?;

    let pending = buffer.get_retry_candidates("conv1").await?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].mls_message_b64, "msg2");

    Ok(())
}

/// Test that retry count is properly incremented
#[tokio::test]
async fn test_retry_count_increment() -> Result<()> {
    let ctx = TestContext::new().await?;
    let buffer = EpochAwareBuffer::new(ctx.db.clone());
    buffer.set_username("alice").await;

    buffer.queue_message("conv1", "bob", "msg1").await?;

    // Increment retry count multiple times
    let count1 = buffer.increment_retry("conv1", "msg1").await?;
    let count2 = buffer.increment_retry("conv1", "msg1").await?;
    let count3 = buffer.increment_retry("conv1", "msg1").await?;

    assert_eq!(count1, 1);
    assert_eq!(count2, 2);
    assert_eq!(count3, 3);

    Ok(())
}

/// Test that the maximum retry count constant is correctly set
#[tokio::test]
async fn test_max_retry_count_constant() {
    assert_eq!(MAX_RETRY_COUNT, 10);
}

/// Test that marking a message as failed removes it from retry candidates
#[tokio::test]
async fn test_mark_failed_removes_from_candidates() -> Result<()> {
    let ctx = TestContext::new().await?;
    let buffer = EpochAwareBuffer::new(ctx.db.clone());
    buffer.set_username("alice").await;

    buffer.queue_message("conv1", "bob", "msg1").await?;

    // Mark as failed
    buffer.mark_failed("conv1", "msg1", "Exceeded max retries").await?;

    // Should no longer appear in retry candidates
    let pending = buffer.get_retry_candidates("conv1").await?;
    assert!(pending.is_empty());

    Ok(())
}

/// Test that TTL expiration constant is correctly set (5 minutes = 300 seconds)
#[tokio::test]
async fn test_ttl_constant() {
    assert_eq!(MAX_BUFFER_AGE_SECS, 300);
}

/// Test buffer size limit constant
#[tokio::test]
async fn test_buffer_size_limit_constant() {
    assert_eq!(MAX_BUFFER_SIZE, 100);
}

/// Test that expired messages are cleaned up
#[tokio::test]
async fn test_cleanup_expired_messages() -> Result<()> {
    let ctx = TestContext::new().await?;
    let buffer = EpochAwareBuffer::new(ctx.db.clone());
    buffer.set_username("alice").await;

    // Queue a message
    buffer.queue_message("conv1", "bob", "msg1").await?;

    // Cleanup with very short max age (0 seconds - everything should be expired immediately after)
    // Wait a tiny bit to ensure timestamp is in the past
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    let deleted = buffer.cleanup_expired(0).await?;

    // Should have deleted the message
    assert_eq!(deleted, 1);

    let pending = buffer.get_retry_candidates("conv1").await?;
    assert!(pending.is_empty());

    Ok(())
}

/// Test that non-expired messages are not cleaned up
#[tokio::test]
async fn test_cleanup_keeps_valid_messages() -> Result<()> {
    let ctx = TestContext::new().await?;
    let buffer = EpochAwareBuffer::new(ctx.db.clone());
    buffer.set_username("alice").await;

    buffer.queue_message("conv1", "bob", "msg1").await?;

    // Cleanup with very long max age (should keep everything)
    let deleted = buffer.cleanup_expired(86400).await?; // 24 hours

    assert_eq!(deleted, 0);

    let pending = buffer.get_retry_candidates("conv1").await?;
    assert_eq!(pending.len(), 1);

    Ok(())
}

/// Test epoch tracking
#[tokio::test]
async fn test_epoch_tracking() -> Result<()> {
    let ctx = TestContext::new().await?;
    let buffer = EpochAwareBuffer::new(ctx.db.clone());
    buffer.set_username("alice").await;

    // Initially no epoch
    assert!(buffer.get_known_epoch("conv1").await.is_none());

    // Set epoch
    buffer.update_epoch("conv1", 5).await;
    assert_eq!(buffer.get_known_epoch("conv1").await, Some(5));

    // Update epoch
    buffer.update_epoch("conv1", 10).await;
    assert_eq!(buffer.get_known_epoch("conv1").await, Some(10));

    Ok(())
}

/// Test getting conversations with pending messages
#[tokio::test]
async fn test_get_conversations_with_pending() -> Result<()> {
    let ctx = TestContext::new().await?;
    let buffer = EpochAwareBuffer::new(ctx.db.clone());
    buffer.set_username("alice").await;

    // Initially no conversations
    let convs = buffer.get_conversations_with_pending().await?;
    assert!(convs.is_empty());

    // Add messages to different conversations
    buffer.queue_message("conv1", "bob", "msg1").await?;
    buffer.queue_message("conv2", "charlie", "msg2").await?;
    buffer.queue_message("conv1", "bob", "msg3").await?;

    let convs = buffer.get_conversations_with_pending().await?;
    assert_eq!(convs.len(), 2);
    assert!(convs.contains(&"conv1".to_string()));
    assert!(convs.contains(&"conv2".to_string()));

    Ok(())
}

/// Test buffer statistics
#[tokio::test]
async fn test_buffer_stats() -> Result<()> {
    let ctx = TestContext::new().await?;
    let buffer = EpochAwareBuffer::new(ctx.db.clone());
    buffer.set_username("alice").await;

    // Initial stats
    let stats = buffer.get_stats().await;
    assert_eq!(stats.total_memory_messages, 0);
    assert_eq!(stats.conversations_with_pending, 0);

    // Add messages
    buffer.queue_message("conv1", "bob", "msg1").await?;
    buffer.queue_message("conv1", "bob", "msg2").await?;
    buffer.queue_message("conv2", "charlie", "msg3").await?;

    let stats = buffer.get_stats().await;
    assert_eq!(stats.total_memory_messages, 3);
    assert_eq!(stats.conversations_with_pending, 2);

    Ok(())
}

/// Test reload from database after restart simulation
#[tokio::test]
async fn test_reload_from_db() -> Result<()> {
    let ctx = TestContext::new().await?;

    // First buffer instance - queue messages
    {
        let buffer = EpochAwareBuffer::new(ctx.db.clone());
        buffer.set_username("alice").await;
        buffer.queue_message("conv1", "bob", "msg1").await?;
        buffer.queue_message("conv1", "bob", "msg2").await?;
    }

    // Second buffer instance - reload from DB
    let buffer2 = EpochAwareBuffer::new(ctx.db.clone());
    buffer2.set_username("alice").await;
    let loaded = buffer2.reload_from_db().await?;

    assert_eq!(loaded, 2);

    let pending = buffer2.get_retry_candidates("conv1").await?;
    assert_eq!(pending.len(), 2);

    Ok(())
}

/// Test that memory and database stay in sync
#[tokio::test]
async fn test_memory_db_sync() -> Result<()> {
    let ctx = TestContext::new().await?;
    let buffer = EpochAwareBuffer::new(ctx.db.clone());
    buffer.set_username("alice").await;

    // Queue message
    buffer.queue_message("conv1", "bob", "msg1").await?;

    // Check both memory and DB
    let memory_pending = buffer.get_memory_pending("conv1").await;
    let db_pending = buffer.get_db_pending("conv1").await?;

    assert_eq!(memory_pending.len(), 1);
    assert_eq!(db_pending.len(), 1);

    // Mark processed
    buffer.mark_processed("conv1", "msg1").await?;

    // Both should be empty now
    let memory_pending = buffer.get_memory_pending("conv1").await;
    let db_pending = buffer.get_db_pending("conv1").await?;

    assert!(memory_pending.is_empty());
    assert!(db_pending.is_empty());

    Ok(())
}

/// Test buffered message structure
#[test]
fn test_buffered_message_structure() {
    let msg = BufferedMessage {
        sender: "alice".to_string(),
        mls_message_b64: "base64data".to_string(),
        received_at: Utc::now(),
        retry_count: 3,
        db_id: Some(42),
    };

    assert_eq!(msg.sender, "alice");
    assert_eq!(msg.mls_message_b64, "base64data");
    assert_eq!(msg.retry_count, 3);
    assert_eq!(msg.db_id, Some(42));
}

/// Test messages for different conversations are isolated
#[tokio::test]
async fn test_conversation_isolation() -> Result<()> {
    let ctx = TestContext::new().await?;
    let buffer = EpochAwareBuffer::new(ctx.db.clone());
    buffer.set_username("alice").await;

    buffer.queue_message("conv1", "bob", "msg1").await?;
    buffer.queue_message("conv2", "charlie", "msg2").await?;

    // Get pending for conv1 only
    let conv1_pending = buffer.get_retry_candidates("conv1").await?;
    assert_eq!(conv1_pending.len(), 1);
    assert_eq!(conv1_pending[0].sender, "bob");

    // Get pending for conv2 only
    let conv2_pending = buffer.get_retry_candidates("conv2").await?;
    assert_eq!(conv2_pending.len(), 1);
    assert_eq!(conv2_pending[0].sender, "charlie");

    Ok(())
}
