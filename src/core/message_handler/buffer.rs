//! Background buffer processor for MLS message retries
//!
//! This module contains the background task that periodically retries buffered MLS messages
//! that couldn't be decrypted due to epoch mismatches.

use crate::crypto::{MlsConversationManager, SecurePassphrase};
use crate::core::db::Db;
use crate::core::mixnet_client::MixnetService;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

use pgp::composed::{SignedSecretKey, SignedPublicKey};

/// Type alias for Arc-wrapped PGP secret key to reduce expensive cloning
pub type ArcSecretKey = Arc<SignedSecretKey>;
/// Type alias for Arc-wrapped PGP public key to reduce expensive cloning
pub type ArcPublicKey = Arc<SignedPublicKey>;
/// Type alias for Arc-wrapped secure passphrase to reduce expensive cloning
pub type ArcPassphrase = Arc<SecurePassphrase>;

/// Interval for background buffer processing (in seconds)
const BUFFER_RETRY_INTERVAL_SECS: u64 = 5;

/// Maximum age for expired messages cleanup (in seconds) - 1 hour
const MESSAGE_EXPIRY_SECS: i64 = 3600;

/// Background task that periodically retries buffered MLS messages
///
/// This task runs in the background and:
/// 1. Checks for pending buffered messages every BUFFER_RETRY_INTERVAL_SECS
/// 2. Attempts to process buffered messages for each conversation
/// 3. Cleans up expired messages older than MESSAGE_EXPIRY_SECS
///
/// # Arguments
/// * `db` - Database connection for persistence
/// * `service` - Mixnet service for communication
/// * `current_user` - Current logged-in user
/// * `pgp_secret_key` - Optional Arc-wrapped PGP secret key for signing (cheap to clone)
/// * `pgp_public_key` - Optional Arc-wrapped PGP public key (cheap to clone)
/// * `pgp_passphrase` - Optional Arc-wrapped secure passphrase (cheap to clone)
/// * `mls_storage_path` - Optional MLS storage path
/// * `shutdown_rx` - Broadcast receiver for shutdown signal
pub async fn start_buffer_processor(
    db: Arc<Db>,
    service: Arc<MixnetService>,
    current_user: String,
    pgp_secret_key: Option<ArcSecretKey>,
    pgp_public_key: Option<ArcPublicKey>,
    pgp_passphrase: Option<ArcPassphrase>,
    mls_storage_path: Option<String>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    log::info!("Starting background buffer processor for user: {}", current_user);

    let mut interval = tokio::time::interval(Duration::from_secs(BUFFER_RETRY_INTERVAL_SECS));
    let mut cleanup_counter: u64 = 0;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Create a fresh MLS conversation manager for each iteration
                let mls_manager = MlsConversationManager::new(
                    db.clone(),
                    service.clone(),
                    Some(current_user.clone()),
                    pgp_secret_key.clone(),
                    pgp_public_key.clone(),
                    pgp_passphrase.clone(),
                    mls_storage_path.clone(),
                );

                // Initialize the epoch buffer
                if let Err(e) = mls_manager.init_epoch_buffer().await {
                    log::error!("Failed to initialize epoch buffer: {}", e);
                    continue;
                }

                // Get conversations with pending messages
                let conversations = match mls_manager.get_conversations_with_pending().await {
                    Ok(convs) => convs,
                    Err(e) => {
                        log::error!("Failed to get conversations with pending messages: {}", e);
                        continue;
                    }
                };

                // Process buffered messages for each conversation
                for conv_id in conversations {
                    match mls_manager.process_buffered_messages(&conv_id).await {
                        Ok((processed, failed)) => {
                            if processed > 0 || failed > 0 {
                                log::info!(
                                    "Buffer processor: conversation {} - processed: {}, failed: {}",
                                    conv_id, processed, failed
                                );
                            }
                        }
                        Err(e) => {
                            log::error!(
                                "Failed to process buffered messages for conversation {}: {}",
                                conv_id, e
                            );
                        }
                    }
                }

                // Periodic cleanup (every ~12 intervals = ~1 minute)
                cleanup_counter += 1;
                if cleanup_counter >= 12 {
                    cleanup_counter = 0;
                    match mls_manager.cleanup_expired_buffered(MESSAGE_EXPIRY_SECS).await {
                        Ok(deleted) => {
                            if deleted > 0 {
                                log::info!("Cleaned up {} expired buffered messages", deleted);
                            }
                        }
                        Err(e) => {
                            log::error!("Failed to cleanup expired messages: {}", e);
                        }
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                log::info!("Buffer processor received shutdown signal, stopping...");
                break;
            }
        }
    }

    log::info!("Background buffer processor stopped");
}

/// Helper struct for managing the buffer processor lifecycle
pub struct BufferProcessorHandle {
    shutdown_tx: broadcast::Sender<()>,
}

impl BufferProcessorHandle {
    /// Create a new buffer processor handle
    pub fn new() -> (Self, broadcast::Receiver<()>) {
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        (Self { shutdown_tx }, shutdown_rx)
    }

    /// Send shutdown signal to stop the buffer processor
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

impl Default for BufferProcessorHandle {
    fn default() -> Self {
        Self::new().0
    }
}
