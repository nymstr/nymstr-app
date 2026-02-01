//! Connection management commands
//!
//! This module handles mixnet connectivity and server address configuration.

use std::sync::Arc;

use tauri::State;

use crate::core::mixnet_client::MixnetService;
use crate::state::AppState;
use crate::types::{ApiError, ConnectionStatus};

/// Set the Nym server address (nymstr-server discovery node)
#[tauri::command]
pub async fn set_server_address(
    state: State<'_, AppState>,
    address: String,
) -> Result<(), ApiError> {
    tracing::info!("Setting server address: {}", address);

    state
        .set_server_address(Some(address.clone()))
        .await
        .map_err(|e| ApiError::internal(format!("Failed to save settings: {}", e)))?;

    // If mixnet is already connected, update the server address there too
    if let Some(service) = state.get_mixnet_service().await {
        service.set_server_address(Some(address)).await;
    }

    Ok(())
}

/// Get the current server address
#[tauri::command]
pub async fn get_server_address(state: State<'_, AppState>) -> Result<Option<String>, ApiError> {
    Ok(state.get_server_address().await)
}

/// Connect to the Nym mixnet
///
/// This creates a new MixnetService and connects to the network.
/// For persistent storage, provide a username via `connect_to_mixnet_for_user`.
#[tauri::command]
pub async fn connect_to_mixnet(state: State<'_, AppState>) -> Result<String, ApiError> {
    tracing::info!("Connecting to mixnet (ephemeral mode)...");

    // Check if already connected
    if state.get_mixnet_service().await.is_some() {
        let status = state.get_connection_status().await;
        if let Some(addr) = status.mixnet_address {
            tracing::info!("Already connected to mixnet: {}", addr);
            return Ok(addr);
        }
    }

    // Create ephemeral mixnet client
    let (service, incoming_rx) = MixnetService::new_ephemeral()
        .await
        .map_err(|e| ApiError::internal(format!("Failed to connect to mixnet: {}", e)))?;

    let address = service.our_address().to_string();
    tracing::info!("Connected to mixnet: {}", address);

    // Set server address if configured
    if let Some(server_addr) = state.get_server_address().await {
        service.set_server_address(Some(server_addr)).await;
    }

    // Store in state
    let service = Arc::new(service);
    state.set_mixnet_service(service, incoming_rx).await;
    state
        .set_connection_status(true, Some(address.clone()))
        .await;

    Ok(address)
}

/// Connect to the Nym mixnet with persistent storage for a specific user
///
/// This creates a new MixnetService with storage in the user's directory.
#[tauri::command]
pub async fn connect_to_mixnet_for_user(
    state: State<'_, AppState>,
    username: String,
) -> Result<String, ApiError> {
    tracing::info!(
        "Connecting to mixnet with persistent storage for user: {}",
        username
    );

    // Check if already connected
    if state.get_mixnet_service().await.is_some() {
        let status = state.get_connection_status().await;
        if let Some(addr) = status.mixnet_address {
            tracing::info!("Already connected to mixnet: {}", addr);
            return Ok(addr);
        }
    }

    // Get storage path for this user
    let storage_dir = state.get_mixnet_storage_dir(&username);
    tracing::info!("Mixnet storage directory: {:?}", storage_dir);

    // Create mixnet client with persistent storage
    let (service, incoming_rx) = MixnetService::new_with_storage(storage_dir)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to connect to mixnet: {}", e)))?;

    let address = service.our_address().to_string();
    tracing::info!("Connected to mixnet: {}", address);

    // Set server address if configured
    if let Some(server_addr) = state.get_server_address().await {
        service.set_server_address(Some(server_addr)).await;
    }

    // Store in state
    let service = Arc::new(service);
    state.set_mixnet_service(service, incoming_rx).await;
    state
        .set_connection_status(true, Some(address.clone()))
        .await;

    Ok(address)
}

/// Disconnect from the Nym mixnet
#[tauri::command]
pub async fn disconnect_from_mixnet(state: State<'_, AppState>) -> Result<(), ApiError> {
    tracing::info!("Disconnecting from mixnet");

    // Clear the mixnet service (this will drop the client)
    state.clear_mixnet_service().await;

    // Update connection status
    state.set_connection_status(false, None).await;

    tracing::info!("Disconnected from mixnet");
    Ok(())
}

/// Get current connection status
#[tauri::command]
pub async fn get_connection_status(
    state: State<'_, AppState>,
) -> Result<ConnectionStatus, ApiError> {
    Ok(state.get_connection_status().await)
}
