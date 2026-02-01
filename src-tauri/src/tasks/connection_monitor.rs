//! Connection monitoring task
//!
//! This module monitors the mixnet connection health and attempts
//! reconnection if the connection is lost.

use std::sync::Arc;
use std::time::Duration;

use tauri::AppHandle;
use tokio::task::JoinHandle;

use crate::events::EventEmitter;
use crate::state::AppState;

/// Interval between connection health checks (30 seconds)
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Start the connection monitor task
///
/// This spawns a background task that:
/// - Runs every 30 seconds
/// - Checks if mixnet connection is healthy
/// - Emits connection status events
/// - Attempts reconnection if disconnected
pub fn start_connection_monitor(
    app_handle: AppHandle,
    state: Arc<AppState>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!("Connection monitor started");
        let emitter = EventEmitter::new(app_handle.clone());

        let mut interval = tokio::time::interval(HEALTH_CHECK_INTERVAL);
        let mut was_connected = false;

        loop {
            interval.tick().await;

            // Check connection status
            let is_connected = check_connection_health(&state).await;

            // Detect connection state changes
            if is_connected && !was_connected {
                tracing::info!("Mixnet connection restored");
                let address = state.get_connection_status().await.mixnet_address;
                emitter.connected(address.unwrap_or_else(|| "unknown".to_string()));
            } else if !is_connected && was_connected {
                tracing::warn!("Mixnet connection lost");
                emitter.disconnected("Connection lost".to_string());
            }

            was_connected = is_connected;

            // If disconnected, attempt reconnection
            if !is_connected {
                if let Err(e) = attempt_reconnection(&state).await {
                    tracing::debug!("Reconnection attempt failed: {}", e);
                }
            }
        }
    })
}

/// Check if the mixnet connection is healthy
async fn check_connection_health(state: &Arc<AppState>) -> bool {
    // Check if we have a mixnet service
    let _mixnet_service = match state.get_mixnet_service().await {
        Some(service) => service,
        None => return false,
    };

    // The service exists, check the connection status
    let status = state.get_connection_status().await;
    status.connected
}

/// Attempt to reconnect to the mixnet
async fn attempt_reconnection(state: &Arc<AppState>) -> anyhow::Result<()> {
    // Only attempt reconnection if we have a user logged in
    let current_user = match state.get_current_user().await {
        Some(user) => user,
        None => {
            tracing::debug!("No user logged in, skipping reconnection attempt");
            return Ok(());
        }
    };

    // Check if we already have a mixnet service
    if state.get_mixnet_service().await.is_some() {
        // Service exists but might be unhealthy - for now we don't force reconnect
        // This could be extended to check actual connection health
        return Ok(());
    }

    tracing::info!("Attempting to reconnect to mixnet for user {}", current_user.username);

    // Get storage directory for the user
    let storage_dir = state.get_mixnet_storage_dir(&current_user.username);

    // Create new mixnet connection
    let (service, rx) = crate::core::mixnet_client::MixnetService::new_with_storage(storage_dir)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create mixnet service: {}", e))?;

    let address = service.our_address().to_string();

    // Set server address if configured
    if let Some(server_addr) = state.get_server_address().await {
        service.set_server_address(Some(server_addr)).await;
    }

    // Update state
    state.set_mixnet_service(Arc::new(service), rx).await;
    state.set_connection_status(true, Some(address.clone())).await;

    tracing::info!("Reconnected to mixnet with address: {}", address);

    // Note: The message receive loop needs to be restarted with the new rx
    // This is handled by BackgroundTasks which will detect the new rx

    Ok(())
}
