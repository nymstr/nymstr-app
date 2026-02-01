//! Background tasks module.
//!
//! This module contains long-running background tasks:
//! - Message receive loop (processing incoming mixnet messages)
//! - Connection monitoring and reconnection
//! - Epoch buffer retry processing
//! - Pending message polling (offline queue)

pub mod buffer_processor;
pub mod connection_monitor;
pub mod message_loop;
pub mod pending_poller;

use std::sync::Arc;

use tauri::AppHandle;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::core::mixnet_client::Incoming;
use crate::state::AppState;

/// Manager for background tasks
///
/// This struct holds handles to all background tasks and provides
/// methods for starting and stopping them.
pub struct BackgroundTasks {
    /// Handle to the message receive loop task
    pub message_loop: Option<JoinHandle<()>>,
    /// Handle to the epoch buffer processor task
    pub buffer_processor: Option<JoinHandle<()>>,
    /// Handle to the connection monitor task
    pub connection_monitor: Option<JoinHandle<()>>,
    /// Handle to the pending message poller task
    pub pending_poller: Option<JoinHandle<()>>,
}

impl BackgroundTasks {
    /// Create a new BackgroundTasks manager (all tasks stopped)
    pub fn new() -> Self {
        Self {
            message_loop: None,
            buffer_processor: None,
            connection_monitor: None,
            pending_poller: None,
        }
    }

    /// Start all background tasks
    ///
    /// This starts:
    /// - Message receive loop (processes incoming mixnet messages)
    /// - Buffer processor (retries epoch-buffered MLS messages)
    /// - Connection monitor (checks connection health)
    /// - Pending message poller (fetches offline-queued messages)
    ///
    /// # Arguments
    /// * `app_handle` - Tauri app handle for event emission
    /// * `state` - Application state
    /// * `rx` - Receiver for incoming mixnet messages
    pub async fn start(
        app_handle: AppHandle,
        state: Arc<AppState>,
        rx: mpsc::Receiver<Incoming>,
    ) -> Self {
        tracing::info!("Starting background tasks");

        // Start message receive loop
        let message_loop = message_loop::start_message_receive_loop(
            app_handle.clone(),
            Arc::clone(&state),
            rx,
        );

        // Start buffer processor
        let buffer_processor = buffer_processor::start_buffer_processor(
            app_handle.clone(),
            Arc::clone(&state),
        );

        // Start connection monitor
        let connection_monitor = connection_monitor::start_connection_monitor(
            app_handle,
            Arc::clone(&state),
        );

        // Start pending message poller
        let pending_poller = pending_poller::start_pending_poller(Arc::clone(&state));

        tracing::info!("All background tasks started");

        Self {
            message_loop: Some(message_loop),
            buffer_processor: Some(buffer_processor),
            connection_monitor: Some(connection_monitor),
            pending_poller: Some(pending_poller),
        }
    }

    /// Start tasks without the message loop (for when rx is not available yet)
    ///
    /// This starts only:
    /// - Buffer processor (retries epoch-buffered MLS messages)
    /// - Connection monitor (checks connection health)
    /// - Pending message poller (fetches offline-queued messages)
    pub fn start_without_message_loop(
        app_handle: AppHandle,
        state: Arc<AppState>,
    ) -> Self {
        tracing::info!("Starting background tasks (without message loop)");

        // Start buffer processor
        let buffer_processor = buffer_processor::start_buffer_processor(
            app_handle.clone(),
            Arc::clone(&state),
        );

        // Start connection monitor
        let connection_monitor = connection_monitor::start_connection_monitor(
            app_handle,
            Arc::clone(&state),
        );

        // Start pending message poller
        let pending_poller = pending_poller::start_pending_poller(Arc::clone(&state));

        tracing::info!("Background tasks started (message loop pending)");

        Self {
            message_loop: None,
            buffer_processor: Some(buffer_processor),
            connection_monitor: Some(connection_monitor),
            pending_poller: Some(pending_poller),
        }
    }

    /// Start the message loop task
    ///
    /// Call this after the mixnet connection is established and rx is available.
    pub fn start_message_loop(
        &mut self,
        app_handle: AppHandle,
        state: Arc<AppState>,
        rx: mpsc::Receiver<Incoming>,
    ) {
        // Stop existing message loop if running
        if let Some(handle) = self.message_loop.take() {
            handle.abort();
        }

        // Start new message loop
        self.message_loop = Some(message_loop::start_message_receive_loop(
            app_handle,
            state,
            rx,
        ));

        tracing::info!("Message receive loop started");
    }

    /// Stop all background tasks
    pub fn stop(&mut self) {
        tracing::info!("Stopping background tasks");

        if let Some(handle) = self.message_loop.take() {
            handle.abort();
            tracing::debug!("Message loop stopped");
        }

        if let Some(handle) = self.buffer_processor.take() {
            handle.abort();
            tracing::debug!("Buffer processor stopped");
        }

        if let Some(handle) = self.connection_monitor.take() {
            handle.abort();
            tracing::debug!("Connection monitor stopped");
        }

        if let Some(handle) = self.pending_poller.take() {
            handle.abort();
            tracing::debug!("Pending poller stopped");
        }

        tracing::info!("All background tasks stopped");
    }

    /// Stop only the message loop (useful for reconnection scenarios)
    pub fn stop_message_loop(&mut self) {
        if let Some(handle) = self.message_loop.take() {
            handle.abort();
            tracing::debug!("Message loop stopped");
        }
    }

    /// Check if the message loop is running
    pub fn is_message_loop_running(&self) -> bool {
        self.message_loop.as_ref().map(|h| !h.is_finished()).unwrap_or(false)
    }

    /// Check if any tasks are running
    pub fn is_running(&self) -> bool {
        self.message_loop.as_ref().map(|h| !h.is_finished()).unwrap_or(false)
            || self.buffer_processor.as_ref().map(|h| !h.is_finished()).unwrap_or(false)
            || self.connection_monitor.as_ref().map(|h| !h.is_finished()).unwrap_or(false)
            || self.pending_poller.as_ref().map(|h| !h.is_finished()).unwrap_or(false)
    }
}

impl Default for BackgroundTasks {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BackgroundTasks {
    fn drop(&mut self) {
        self.stop();
    }
}
