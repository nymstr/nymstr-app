//! Invite management commands (DM contact requests + group invite denial)

use tauri::State;

use crate::core::message_handler::{normalize_conversation_id, DirectMessageHandlerBuilder};
use crate::state::AppState;
use crate::types::ApiError;

/// Get all pending contact requests (DM invites)
#[tauri::command]
pub async fn get_contact_requests(
    state: State<'_, AppState>,
) -> Result<Vec<serde_json::Value>, ApiError> {
    let requests: Vec<(i64, String, String)> = sqlx::query_as(
        r#"
        SELECT id, from_username, received_at
        FROM contact_requests
        WHERE status = 'pending'
        ORDER BY received_at ASC
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let result: Vec<serde_json::Value> = requests
        .into_iter()
        .map(|(id, from_username, received_at)| {
            serde_json::json!({
                "id": id,
                "fromUsername": from_username,
                "receivedAt": received_at,
            })
        })
        .collect();

    Ok(result)
}

/// Accept a contact request: respond with our key package to complete the handshake.
/// Returns `{ conversationId, fromUsername }` so the frontend can create the conversation.
#[tauri::command]
pub async fn accept_contact_request(
    from_username: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, ApiError> {
    // Verify the request exists
    let exists: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM contact_requests WHERE from_username = ? AND status = 'pending'",
    )
    .bind(&from_username)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    if exists.is_none() {
        return Err(ApiError::not_found("Contact request not found or already handled"));
    }

    tracing::info!("Accepting contact request from {}", from_username);

    // Get required state for building the handler
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;
    let mls_client = state
        .get_mls_client()
        .await
        .ok_or_else(|| ApiError::internal("MLS client not initialized"))?;
    let mixnet_service = state
        .get_mixnet_service()
        .await
        .ok_or_else(|| ApiError::not_connected("Not connected to mixnet"))?;
    let (pgp_secret_key, pgp_passphrase) = state
        .get_pgp_signing_keys()
        .await
        .ok_or_else(|| ApiError::internal("PGP keys not available"))?;

    // Build the handler and respond to the key package request
    let handler = DirectMessageHandlerBuilder::new()
        .mls_client(mls_client)
        .mixnet_service(mixnet_service)
        .pgp_keys(pgp_secret_key, pgp_passphrase)
        .current_user(current_user.username.clone())
        .db(state.db.clone())
        .build()
        .map_err(|e| ApiError::internal(format!("Failed to build handler: {}", e)))?;

    // Respond with our key package — the initiator's KP is no longer sent in the request
    handler
        .respond_to_key_package_request(&from_username, "")
        .await
        .map_err(|e| ApiError::internal(format!("Failed to respond to key package: {}", e)))?;

    // Compute conversation ID
    let conversation_id = normalize_conversation_id(&current_user.username, &from_username);

    // Create the conversation entry in the DB so it persists
    sqlx::query(
        r#"
        INSERT OR IGNORE INTO conversations (id, type, participant, created_at, last_message_at)
        VALUES (?, 'direct', ?, datetime('now'), datetime('now'))
        "#,
    )
    .bind(&conversation_id)
    .bind(&from_username)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    // Add the user as a contact so they appear in the contacts list
    sqlx::query(
        r#"
        INSERT OR IGNORE INTO contacts (owner_username, username, display_name, public_key, created_at)
        VALUES (?, ?, ?, '', datetime('now'))
        "#,
    )
    .bind(&current_user.username)
    .bind(&from_username)
    .bind(&from_username)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    // Mark the request as accepted
    sqlx::query("UPDATE contact_requests SET status = 'accepted' WHERE from_username = ?")
        .bind(&from_username)
        .execute(&state.db)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    tracing::info!("Contact request from {} accepted, conversation: {}", from_username, conversation_id);

    Ok(serde_json::json!({
        "conversationId": conversation_id,
        "fromUsername": from_username,
    }))
}

/// Deny a contact request (silently ignore it)
#[tauri::command]
pub async fn deny_contact_request(
    from_username: String,
    state: State<'_, AppState>,
) -> Result<(), ApiError> {
    let rows_affected = sqlx::query(
        "UPDATE contact_requests SET status = 'denied' WHERE from_username = ? AND status = 'pending'",
    )
    .bind(&from_username)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .rows_affected();

    if rows_affected == 0 {
        return Err(ApiError::not_found(
            "Contact request not found or already handled",
        ));
    }

    tracing::info!("Contact request from {} denied", from_username);

    Ok(())
}

/// Deny a group welcome/invite (mark as processed with denial)
#[tauri::command]
pub async fn deny_welcome(
    welcome_id: i64,
    state: State<'_, AppState>,
) -> Result<(), ApiError> {
    let rows_affected = sqlx::query(
        r#"
        UPDATE pending_welcomes
        SET processed = 1, processed_at = datetime('now'), error_message = 'denied_by_user'
        WHERE id = ? AND processed = 0
        "#,
    )
    .bind(welcome_id)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .rows_affected();

    if rows_affected == 0 {
        return Err(ApiError::not_found(
            "Welcome not found or already processed",
        ));
    }

    tracing::info!("Welcome {} denied by user", welcome_id);

    Ok(())
}
