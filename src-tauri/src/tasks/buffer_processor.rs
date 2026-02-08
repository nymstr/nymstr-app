//! Epoch buffer processor task
//!
//! This module handles retry processing of buffered MLS messages that couldn't
//! be decrypted due to epoch mismatches. The mixnet's variable latency can cause
//! messages to arrive out of order, requiring buffering and retry logic.

use std::sync::Arc;
use std::time::Duration;

use tauri::AppHandle;
use tokio::task::JoinHandle;

use crate::core::db::{Db, MessageDb};
use crate::core::message_handler::DirectMessageHandlerBuilder;
use crate::crypto::mls::MlsMessageType;
use crate::events::EventEmitter;
use crate::state::AppState;
use crate::types::{MessageDTO, MessageStatus};

/// Maximum age for buffered messages before they are considered expired (5 minutes)
const MAX_MESSAGE_AGE_SECS: i64 = 300;

/// Maximum number of retry attempts before marking as failed
const MAX_RETRY_COUNT: i32 = 10;

/// Interval between buffer processing runs (5 seconds)
const BUFFER_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Start the buffer processor task
///
/// This spawns a background task that:
/// - Runs every 5 seconds
/// - Gets buffered messages from database
/// - Retries decryption with current MLS state
/// - Processes successful decryptions
/// - Removes expired messages (> 5 minutes old)
/// - Tracks retry counts
pub fn start_buffer_processor(
    app_handle: AppHandle,
    state: Arc<AppState>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!("Buffer processor started");
        let emitter = EventEmitter::new(app_handle.clone());

        let mut interval = tokio::time::interval(BUFFER_CHECK_INTERVAL);

        loop {
            interval.tick().await;

            // Check if we're logged in before processing
            let current_user = match state.get_current_user().await {
                Some(user) => user,
                None => {
                    tracing::debug!("Buffer processor: no user logged in, skipping");
                    continue;
                }
            };

            // Process buffered messages
            if let Err(e) = process_buffered_messages(&emitter, &state, &current_user.username).await {
                tracing::error!("Error processing buffered messages: {}", e);
            }

            // Cleanup expired messages
            if let Err(e) = cleanup_expired_messages(&state).await {
                tracing::error!("Error cleaning up expired messages: {}", e);
            }
        }
    })
}

/// Process all buffered messages
async fn process_buffered_messages(
    emitter: &EventEmitter,
    state: &Arc<AppState>,
    username: &str,
) -> anyhow::Result<()> {
    // Get all conversations with pending messages
    let conversations = MessageDb::get_conversations_with_pending(&state.db).await?;

    if conversations.is_empty() {
        return Ok(());
    }

    tracing::debug!("Processing buffered messages for {} conversations", conversations.len());

    // Get required state
    let mls_client = match state.get_mls_client().await {
        Some(client) => client,
        None => {
            tracing::debug!("MLS client not initialized, skipping buffer processing");
            return Ok(());
        }
    };

    let mixnet_service = match state.get_mixnet_service().await {
        Some(service) => service,
        None => {
            tracing::debug!("Mixnet not connected, skipping buffer processing");
            return Ok(());
        }
    };

    let (pgp_secret_key, pgp_passphrase) = match state.get_pgp_signing_keys().await {
        Some(keys) => keys,
        None => {
            tracing::debug!("PGP keys not available, skipping buffer processing");
            return Ok(());
        }
    };

    // Create handler
    let handler = DirectMessageHandlerBuilder::new()
        .mls_client(mls_client)
        .mixnet_service(mixnet_service)
        .pgp_keys(pgp_secret_key, pgp_passphrase)
        .current_user(username.to_string())
        .db(state.db.clone())
        .build()?;

    // Process each conversation
    for conv_id in conversations {
        if let Err(e) = process_conversation_buffer(emitter, state, &handler, &conv_id).await {
            tracing::warn!("Error processing buffer for conversation {}: {}", conv_id, e);
        }
    }

    Ok(())
}

/// Process buffered messages for a single conversation
async fn process_conversation_buffer(
    emitter: &EventEmitter,
    state: &Arc<AppState>,
    handler: &crate::core::message_handler::DirectMessageHandler,
    conv_id: &str,
) -> anyhow::Result<()> {
    let messages = MessageDb::get_buffered_messages(&state.db, conv_id).await?;

    if messages.is_empty() {
        return Ok(());
    }

    tracing::debug!("Processing {} buffered messages for conversation {}", messages.len(), conv_id);

    for msg in messages {
        // Check retry count
        if msg.retry_count >= MAX_RETRY_COUNT {
            tracing::warn!(
                "Message {} exceeded max retries, marking as failed",
                msg.id
            );
            MessageDb::mark_buffered_failed(
                &state.db,
                msg.id,
                "Exceeded maximum retry attempts",
            ).await?;
            continue;
        }

        // Increment retry count
        MessageDb::increment_retry_count(&state.db, msg.id).await?;

        // Try to decrypt
        match handler
            .process_incoming_message(&msg.sender, &msg.mls_message_b64, MlsMessageType::Application)
            .await
        {
            Ok(Some(content)) => {
                tracing::info!(
                    "Successfully decrypted buffered message {} from {}",
                    msg.id,
                    msg.sender
                );

                // Create message DTO
                let message = MessageDTO {
                    id: uuid::Uuid::new_v4().to_string(),
                    sender: msg.sender.clone(),
                    content,
                    timestamp: msg.received_at.clone(),
                    status: MessageStatus::Delivered,
                    is_own: false,
                    is_read: false,
                };

                // Store in database
                Db::save_message(&state.db, conv_id, &message).await?;

                // Mark buffered message as processed
                MessageDb::mark_buffered_processed(&state.db, msg.id).await?;

                // Emit event to frontend
                emitter.message_received(message, conv_id.to_string());
            }
            Ok(None) => {
                // Non-application message (commit, etc.), mark as processed
                tracing::debug!(
                    "Buffered message {} was non-application MLS message",
                    msg.id
                );
                MessageDb::mark_buffered_processed(&state.db, msg.id).await?;
            }
            Err(e) => {
                // Still can't decrypt - check if it's still an epoch issue
                let error_msg = e.to_string();
                if error_msg.contains("epoch") || error_msg.contains("Epoch") {
                    tracing::debug!(
                        "Buffered message {} still has epoch mismatch, will retry later",
                        msg.id
                    );
                } else {
                    tracing::warn!(
                        "Buffered message {} failed with non-epoch error: {}",
                        msg.id,
                        error_msg
                    );
                    // Mark as failed for non-epoch errors
                    MessageDb::mark_buffered_failed(&state.db, msg.id, &error_msg).await?;
                }
            }
        }
    }

    Ok(())
}

/// Cleanup expired buffered messages
async fn cleanup_expired_messages(state: &Arc<AppState>) -> anyhow::Result<()> {
    let deleted = MessageDb::cleanup_expired_buffered(&state.db, MAX_MESSAGE_AGE_SECS).await?;

    if deleted > 0 {
        tracing::info!("Cleaned up {} expired/processed buffered messages", deleted);
    }

    Ok(())
}
