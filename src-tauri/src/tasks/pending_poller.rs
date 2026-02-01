//! Pending message poller task
//!
//! This module handles periodic polling for offline-queued messages.
//! When the user is online, it periodically fetches pending messages
//! from the discovery server that were queued while they were offline.

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::time::interval;

use crate::crypto::pgp::PgpSigner;
use crate::state::AppState;

/// Poll interval for fetching pending messages (30 seconds)
const POLL_INTERVAL_SECS: u64 = 30;

/// Start the pending message poller
///
/// This spawns a background task that:
/// - Periodically sends fetchPending requests to the discovery server
/// - Signs requests with the user's PGP key for authentication
/// - Responses are handled by the message receive loop
pub fn start_pending_poller(state: Arc<AppState>) -> JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!("Pending message poller started (interval: {}s)", POLL_INTERVAL_SECS);

        let mut poll_interval = interval(Duration::from_secs(POLL_INTERVAL_SECS));

        // Wait for initial interval before first poll (let the app settle)
        poll_interval.tick().await;

        loop {
            poll_interval.tick().await;

            // Check if we have the required state to poll
            let current_user = match state.get_current_user().await {
                Some(user) => user,
                None => {
                    tracing::debug!("Pending poller: no user logged in, skipping");
                    continue;
                }
            };

            let mixnet_service = match state.get_mixnet_service().await {
                Some(service) => service,
                None => {
                    tracing::debug!("Pending poller: mixnet not connected, skipping");
                    continue;
                }
            };

            let (pgp_secret_key, pgp_passphrase) = match state.get_pgp_signing_keys().await {
                Some(keys) => keys,
                None => {
                    tracing::debug!("Pending poller: PGP keys not available, skipping");
                    continue;
                }
            };

            // Create timestamp for signature
            let timestamp = chrono::Utc::now().timestamp();

            // Sign the request: "fetchPending:{username}:{timestamp}"
            // PGP handles hashing internally - sign raw message
            let message_to_sign = format!("fetchPending:{}:{}", current_user.username, timestamp);
            let signature = match PgpSigner::sign_detached_secure(
                &pgp_secret_key,
                message_to_sign.as_bytes(),
                &pgp_passphrase,
            ) {
                Ok(sig) => sig,
                Err(e) => {
                    tracing::warn!("Pending poller: failed to sign request: {}", e);
                    continue;
                }
            };

            // Send the fetchPending request
            tracing::debug!("Pending poller: fetching pending messages for {}", current_user.username);
            if let Err(e) = mixnet_service
                .send_fetch_pending(&current_user.username, timestamp, &signature)
                .await
            {
                tracing::warn!("Pending poller: failed to send fetchPending: {}", e);
            }
        }
    })
}
