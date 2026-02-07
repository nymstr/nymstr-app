//! Contact management commands

use tauri::State;

use std::collections::HashMap;

use crate::core::message_handler::normalize_conversation_id;
use crate::state::AppState;
use crate::types::{ApiError, ContactDTO};

/// Get all contacts for the current user
#[tauri::command]
pub async fn get_contacts(
    state: State<'_, AppState>,
) -> Result<Vec<ContactDTO>, ApiError> {
    // Get current user to scope contacts
    let current_user = state.get_current_user().await
        .ok_or_else(|| ApiError::authentication("Not logged in"))?;

    tracing::debug!("Fetching contacts for user: {}", current_user.username);

    let contacts: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT username, display_name, public_key, last_seen FROM contacts WHERE owner_username = ? ORDER BY display_name"
    )
    .bind(&current_user.username)
    .fetch_all(&state.db)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    // Count unread incoming messages per conversation in one query
    let unread_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT conversation_id, COUNT(*) FROM messages WHERE is_own = 0 AND status != 'read' GROUP BY conversation_id"
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let unread_map: HashMap<String, i64> = unread_rows.into_iter().collect();

    let result: Vec<ContactDTO> = contacts
        .into_iter()
        .map(|(username, display_name, _public_key, last_seen)| {
            let conversation_id = normalize_conversation_id(&current_user.username, &username);
            let unread_count = unread_map.get(&conversation_id).copied().unwrap_or(0) as u32;
            ContactDTO {
                username,
                display_name,
                avatar_url: None,
                last_seen,
                unread_count,
                online: false, // TODO: Track online status
            }
        })
        .collect();

    Ok(result)
}

/// Add a new contact for the current user
#[tauri::command]
pub async fn add_contact(
    username: String,
    display_name: Option<String>,
    state: State<'_, AppState>,
) -> Result<ContactDTO, ApiError> {
    // Get current user to scope contact ownership
    let current_user = state.get_current_user().await
        .ok_or_else(|| ApiError::authentication("Not logged in"))?;

    tracing::info!("User {} adding contact: {}", current_user.username, username);

    // Validate username
    if username.is_empty() || username.len() > 64 {
        return Err(ApiError::validation("Username must be 1-64 characters"));
    }

    // Prevent adding yourself as a contact
    if username == current_user.username {
        return Err(ApiError::validation("Cannot add yourself as a contact"));
    }

    // TODO: Integrate with nymstr-app core
    // - Query discovery server for user's public key
    // - Verify user exists

    let display_name = display_name.unwrap_or_else(|| username.clone());
    let mock_public_key = format!("mock_key_{}", username);

    // Store in database with owner_username
    sqlx::query(
        "INSERT OR REPLACE INTO contacts (owner_username, username, display_name, public_key) VALUES (?, ?, ?, ?)"
    )
    .bind(&current_user.username)
    .bind(&username)
    .bind(&display_name)
    .bind(&mock_public_key)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to add contact: {}", e)))?;

    let contact = ContactDTO {
        username,
        display_name,
        avatar_url: None,
        last_seen: None,
        unread_count: 0,
        online: false,
    };

    Ok(contact)
}

/// Remove a contact for the current user
#[tauri::command]
pub async fn remove_contact(
    username: String,
    state: State<'_, AppState>,
) -> Result<(), ApiError> {
    // Get current user to scope deletion
    let current_user = state.get_current_user().await
        .ok_or_else(|| ApiError::authentication("Not logged in"))?;

    tracing::info!("User {} removing contact: {}", current_user.username, username);

    sqlx::query("DELETE FROM contacts WHERE owner_username = ? AND username = ?")
        .bind(&current_user.username)
        .bind(&username)
        .execute(&state.db)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(())
}

/// Query a user on the discovery server
#[tauri::command]
pub async fn query_user(
    username: String,
    state: State<'_, AppState>,
) -> Result<Option<serde_json::Value>, ApiError> {
    tracing::info!("Querying user: {}", username);

    // Get current user and mixnet service
    let current_user = state.get_current_user().await
        .ok_or_else(|| ApiError::authentication("Not logged in"))?;
    let mixnet_service = state.get_mixnet_service().await
        .ok_or_else(|| ApiError::not_connected("Mixnet not connected"))?;

    // Register pending query to receive the response
    let rx = state.register_pending_query(&username).await;

    // Send query request to server
    mixnet_service
        .send_query_request(&current_user.username, &username)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to send query: {}", e)))?;

    // Wait for response with timeout (15 seconds)
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        rx,
    )
    .await;

    match result {
        Ok(Ok(Some(query_result))) => {
            tracing::info!("Query successful for user: {}", username);
            Ok(Some(serde_json::json!({
                "username": query_result.username,
                "publicKey": query_result.public_key
            })))
        }
        Ok(Ok(None)) => {
            tracing::info!("User not found: {}", username);
            Ok(None)
        }
        Ok(Err(_)) => {
            // Channel was dropped (canceled)
            state.cancel_pending_query(&username).await;
            Err(ApiError::internal("Query was canceled"))
        }
        Err(_) => {
            // Timeout
            state.cancel_pending_query(&username).await;
            tracing::warn!("Query timed out for user: {}", username);
            Err(ApiError::timeout("Query timed out waiting for server response"))
        }
    }
}
