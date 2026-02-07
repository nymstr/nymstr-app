//! Messaging commands with MLS encryption
//!
//! This module provides Tauri commands for:
//! - Sending MLS-encrypted direct messages
//! - Retrieving conversation history
//! - Managing message read status
//! - Handling MLS key package exchange

use chrono::Utc;
use tauri::State;
use uuid::Uuid;

use crate::core::message_handler::{DirectMessageHandler, normalize_conversation_id};
use crate::state::AppState;
use crate::types::{ApiError, MessageDTO, MessageStatus};

/// Send a direct message to a contact with MLS encryption
#[tauri::command]
pub async fn send_message(
    recipient: String,
    content: String,
    state: State<'_, AppState>,
) -> Result<MessageDTO, ApiError> {
    tracing::info!("Sending message to: {}", recipient);

    // Validate content
    if content.is_empty() {
        return Err(ApiError::validation("Message content cannot be empty"));
    }

    if content.len() > 10000 {
        return Err(ApiError::validation("Message too long (max 10000 characters)"));
    }

    // Get current user
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    // Get MLS client
    let mls_client = state
        .get_mls_client()
        .await
        .ok_or_else(|| ApiError::internal("MLS client not initialized".to_string()))?;

    // Get mixnet service
    let mixnet_service = state
        .get_mixnet_service()
        .await
        .ok_or_else(|| ApiError::internal("Mixnet not connected".to_string()))?;

    // Get PGP signing keys
    let (secret_key, passphrase) = state
        .get_pgp_signing_keys()
        .await
        .ok_or_else(|| ApiError::internal("PGP keys not available".to_string()))?;

    // Create message DTO first (for storage)
    let message = MessageDTO {
        id: Uuid::new_v4().to_string(),
        sender: current_user.username.clone(),
        content: content.clone(),
        timestamp: Utc::now().to_rfc3339(),
        status: MessageStatus::Pending,
        is_own: true,
    };

    // Store message locally with pending status
    let conversation_id = normalize_conversation_id(&current_user.username, &recipient);
    sqlx::query(
        r#"
        INSERT INTO messages (id, conversation_id, sender, content, timestamp, status, is_own)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#
    )
    .bind(&message.id)
    .bind(&conversation_id)
    .bind(&message.sender)
    .bind(&message.content)
    .bind(&message.timestamp)
    .bind("pending")
    .bind(true)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to store message: {}", e)))?;

    // Create direct message handler
    let dm_handler = DirectMessageHandler::new(
        mls_client,
        mixnet_service,
        secret_key,
        passphrase,
        current_user.username.clone(),
        state.db.clone(),
    );

    // Check if MLS conversation exists
    if !dm_handler.conversation_exists(&recipient).await {
        tracing::info!("No MLS conversation with {}, initiating key package exchange", recipient);

        // Initiate key package request for handshake
        dm_handler.request_key_package(&recipient).await
            .map_err(|e| ApiError::internal(format!("Failed to request key package: {}", e)))?;

        // Update message status to pending (waiting for handshake)
        sqlx::query("UPDATE messages SET status = 'pending' WHERE id = ?")
            .bind(&message.id)
            .execute(&state.db)
            .await
            .map_err(|e| ApiError::internal(format!("Failed to update message status: {}", e)))?;

        tracing::info!("Key package request sent, message queued pending handshake");

        // Return message with pending status
        return Ok(MessageDTO {
            status: MessageStatus::Pending,
            ..message
        });
    }

    // Send the encrypted message
    match dm_handler.send_message(&recipient, &content).await {
        Ok(_) => {
            // Update message status to sent
            sqlx::query("UPDATE messages SET status = 'sent' WHERE id = ?")
                .bind(&message.id)
                .execute(&state.db)
                .await
                .map_err(|e| ApiError::internal(format!("Failed to update message status: {}", e)))?;

            tracing::info!("Message sent: {} -> {}", current_user.username, recipient);

            Ok(MessageDTO {
                status: MessageStatus::Sent,
                ..message
            })
        }
        Err(e) => {
            // Update message status to failed
            sqlx::query("UPDATE messages SET status = 'failed' WHERE id = ?")
                .bind(&message.id)
                .execute(&state.db)
                .await
                .ok(); // Ignore error here

            tracing::error!("Failed to send message: {}", e);
            Err(ApiError::internal(format!("Failed to send message: {}", e)))
        }
    }
}

/// Initiate MLS handshake with a contact
/// Call this before sending the first message to a new contact
#[tauri::command]
pub async fn initiate_conversation(
    recipient: String,
    state: State<'_, AppState>,
) -> Result<bool, ApiError> {
    tracing::info!("Initiating MLS conversation with: {}", recipient);

    // Get current user
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    // Get required components
    let mls_client = state
        .get_mls_client()
        .await
        .ok_or_else(|| ApiError::internal("MLS client not initialized".to_string()))?;

    let mixnet_service = state
        .get_mixnet_service()
        .await
        .ok_or_else(|| ApiError::internal("Mixnet not connected".to_string()))?;

    let (secret_key, passphrase) = state
        .get_pgp_signing_keys()
        .await
        .ok_or_else(|| ApiError::internal("PGP keys not available".to_string()))?;

    // Create handler
    let dm_handler = DirectMessageHandler::new(
        mls_client,
        mixnet_service,
        secret_key,
        passphrase,
        current_user.username.clone(),
        state.db.clone(),
    );

    // Check if conversation already exists
    if dm_handler.conversation_exists(&recipient).await {
        tracing::info!("MLS conversation already exists with {}", recipient);
        return Ok(true);
    }

    // Send key package request
    dm_handler.request_key_package(&recipient).await
        .map_err(|e| ApiError::internal(format!("Failed to request key package: {}", e)))?;

    tracing::info!("Key package request sent to {}", recipient);
    Ok(false)
}

/// Generate a key package for MLS handshakes
#[tauri::command]
pub async fn generate_key_package(
    state: State<'_, AppState>,
) -> Result<String, ApiError> {
    tracing::info!("Generating key package");

    // Get MLS client
    let mls_client = state
        .get_mls_client()
        .await
        .ok_or_else(|| ApiError::internal("MLS client not initialized".to_string()))?;

    // Generate key package
    let key_package = mls_client.generate_key_package()
        .map_err(|e| ApiError::internal(format!("Failed to generate key package: {}", e)))?;

    use base64::Engine;
    let key_package_b64 = base64::engine::general_purpose::STANDARD.encode(&key_package);

    tracing::info!("Key package generated successfully");
    Ok(key_package_b64)
}

/// Get conversation history with a contact
#[tauri::command]
pub async fn get_conversation(
    contact: String,
    limit: Option<i64>,
    before_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<MessageDTO>, ApiError> {
    tracing::debug!("Fetching conversation with: {}", contact);

    // Get current user for normalized conversation ID
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    let conversation_id = normalize_conversation_id(&current_user.username, &contact);
    let limit = limit.unwrap_or(50).min(100);

    let messages: Vec<(String, String, String, String, String, bool)> = if let Some(before) = before_id {
        sqlx::query_as(
            r#"
            SELECT id, sender, content, timestamp, status, is_own
            FROM messages
            WHERE conversation_id = ? AND id < ?
            ORDER BY timestamp DESC
            LIMIT ?
            "#
        )
        .bind(&conversation_id)
        .bind(&before)
        .bind(limit)
        .fetch_all(&state.db)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    } else {
        sqlx::query_as(
            r#"
            SELECT id, sender, content, timestamp, status, is_own
            FROM messages
            WHERE conversation_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
            "#
        )
        .bind(&conversation_id)
        .bind(limit)
        .fetch_all(&state.db)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    };

    // Convert to DTOs and reverse to get chronological order
    let mut result: Vec<MessageDTO> = messages
        .into_iter()
        .map(|(id, sender, content, timestamp, status, is_own)| {
            MessageDTO {
                id,
                sender,
                content,
                timestamp,
                status: match status.as_str() {
                    "pending" => MessageStatus::Pending,
                    "sent" => MessageStatus::Sent,
                    "delivered" => MessageStatus::Delivered,
                    "read" => MessageStatus::Read,
                    _ => MessageStatus::Failed,
                },
                is_own,
            }
        })
        .collect();

    result.reverse();
    Ok(result)
}

/// Mark messages as read
#[tauri::command]
pub async fn mark_as_read(
    contact: String,
    message_id: String,
    state: State<'_, AppState>,
) -> Result<(), ApiError> {
    // Get current user for normalized conversation ID
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    let conversation_id = normalize_conversation_id(&current_user.username, &contact);

    // Update all messages up to and including this one as read
    sqlx::query(
        r#"
        UPDATE messages
        SET status = 'read'
        WHERE conversation_id = ? AND timestamp <= (
            SELECT timestamp FROM messages WHERE id = ?
        ) AND is_own = 0
        "#
    )
    .bind(&conversation_id)
    .bind(&message_id)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(())
}

/// Check if MLS conversation exists with a contact
#[tauri::command]
pub async fn check_conversation_exists(
    contact: String,
    state: State<'_, AppState>,
) -> Result<bool, ApiError> {
    // Get current user
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    // Get MLS client
    let mls_client = state
        .get_mls_client()
        .await
        .ok_or_else(|| ApiError::internal("MLS client not initialized".to_string()))?;

    // Look up the real MLS group ID from the database
    let conversation_id = normalize_conversation_id(&current_user.username, &contact);
    let result: Option<(String,)> = sqlx::query_as(
        "SELECT mls_group_id FROM conversations WHERE id = ?"
    )
    .bind(&conversation_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to query conversation: {}", e)))?;

    let exists = if let Some((mls_group_id_b64,)) = result {
        use base64::Engine;
        match base64::engine::general_purpose::STANDARD.decode(&mls_group_id_b64) {
            Ok(mls_group_id) => mls_client.group_exists(&mls_group_id),
            Err(_) => false,
        }
    } else {
        false
    };

    Ok(exists)
}

/// Get pending messages (messages waiting for MLS handshake to complete)
#[tauri::command]
pub async fn get_pending_messages(
    state: State<'_, AppState>,
) -> Result<Vec<MessageDTO>, ApiError> {
    let messages: Vec<(String, String, String, String, String, bool)> = sqlx::query_as(
        r#"
        SELECT id, sender, content, timestamp, status, is_own
        FROM messages
        WHERE status = 'pending' AND is_own = 1
        ORDER BY timestamp ASC
        "#
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let result: Vec<MessageDTO> = messages
        .into_iter()
        .map(|(id, sender, content, timestamp, _status, is_own)| {
            MessageDTO {
                id,
                sender,
                content,
                timestamp,
                status: MessageStatus::Pending,
                is_own,
            }
        })
        .collect();

    Ok(result)
}
