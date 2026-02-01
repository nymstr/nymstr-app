//! Application state management for Tauri
//!
//! This module manages the shared state between all Tauri commands,
//! including the mixnet client, database connections, and user session.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use sqlx::SqlitePool;
use tauri::{AppHandle, Manager};
use tokio::sync::{mpsc, oneshot, RwLock};

use crate::core::db::schema;
use crate::core::mixnet_client::{Incoming, MixnetService};
use crate::crypto::mls::{KeyPackageManager, MlsClient};
use crate::crypto::pgp::{ArcPassphrase, ArcPublicKey, ArcSecretKey};
use crate::tasks::BackgroundTasks;
use crate::types::{ConnectionStatus, UserDTO};

/// Result of a user query
#[derive(Debug, Clone)]
pub struct QueryResult {
    pub username: String,
    pub public_key: String,
}

/// Main application state shared across all Tauri commands
///
/// All mutable state is wrapped in Arc<RwLock<T>> to enable safe sharing
/// between the main thread and background tasks without breaking cloning.
#[derive(Clone)]
pub struct AppState {
    /// SQLite database connection pool
    pub db: SqlitePool,

    /// Application data directory
    pub app_dir: PathBuf,

    /// Currently logged in user (Arc-wrapped for safe sharing across tasks)
    pub current_user: Arc<RwLock<Option<UserDTO>>>,

    /// Connection status (Arc-wrapped for safe sharing across tasks)
    pub connection_status: Arc<RwLock<ConnectionStatus>>,

    /// Nym server address (nymstr-server discovery node)
    pub server_address: Arc<RwLock<Option<String>>>,

    /// Mixnet service for anonymous messaging (initialized on connect)
    pub mixnet_service: Arc<RwLock<Option<Arc<MixnetService>>>>,

    /// Receiver for incoming mixnet messages (held to keep receive loop alive)
    pub incoming_rx: Arc<RwLock<Option<mpsc::Receiver<Incoming>>>>,

    /// PGP secret key for signing (Arc-wrapped to avoid expensive cloning)
    pub pgp_secret_key: Arc<RwLock<Option<ArcSecretKey>>>,

    /// PGP public key for identity (Arc-wrapped to avoid expensive cloning)
    pub pgp_public_key: Arc<RwLock<Option<ArcPublicKey>>>,

    /// PGP passphrase for decrypting the secret key (Arc-wrapped for secure sharing)
    pub pgp_passphrase: Arc<RwLock<Option<ArcPassphrase>>>,

    /// MLS client for end-to-end encrypted messaging (initialized after login)
    pub mls_client: Arc<RwLock<Option<Arc<MlsClient>>>>,

    /// Key package manager for MLS handshakes
    pub key_package_manager: Arc<KeyPackageManager>,

    /// Background tasks (message loop, buffer processor, connection monitor)
    pub background_tasks: Arc<RwLock<Option<BackgroundTasks>>>,

    /// Pending user queries awaiting responses
    pub pending_queries: Arc<RwLock<HashMap<String, oneshot::Sender<Option<QueryResult>>>>>,
}

impl AppState {
    /// Create a new AppState instance
    pub async fn new(app_handle: &AppHandle) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Get app data directory
        let app_dir = app_handle
            .path()
            .app_data_dir()
            .expect("Failed to get app data dir");

        std::fs::create_dir_all(&app_dir)?;

        // Initialize database
        let db_path = app_dir.join("nymstr.db");
        let db_url = format!("sqlite:{}?mode=rwc", db_path.display());

        tracing::info!("Initializing database at: {}", db_path.display());

        let db = SqlitePool::connect(&db_url).await?;

        // Run migrations from centralized schema module
        schema::run_migrations(&db).await?;

        // Load server address from settings file if it exists
        let settings_path = app_dir.join("settings.json");
        let server_address = if settings_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&settings_path) {
                serde_json::from_str::<serde_json::Value>(&content)
                    .ok()
                    .and_then(|v| v.get("server_address").and_then(|s| s.as_str().map(String::from)))
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            db,
            app_dir,
            current_user: Arc::new(RwLock::new(None)),
            connection_status: Arc::new(RwLock::new(ConnectionStatus {
                connected: false,
                mixnet_address: None,
            })),
            server_address: Arc::new(RwLock::new(server_address)),
            mixnet_service: Arc::new(RwLock::new(None)),
            incoming_rx: Arc::new(RwLock::new(None)),
            pgp_secret_key: Arc::new(RwLock::new(None)),
            pgp_public_key: Arc::new(RwLock::new(None)),
            pgp_passphrase: Arc::new(RwLock::new(None)),
            mls_client: Arc::new(RwLock::new(None)),
            key_package_manager: Arc::new(KeyPackageManager::new()),
            background_tasks: Arc::new(RwLock::new(None)),
            pending_queries: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Check if a user exists locally
    pub async fn has_local_user(&self) -> Result<Option<String>, sqlx::Error> {
        let result: Option<(String,)> = sqlx::query_as(
            "SELECT username FROM users LIMIT 1"
        )
        .fetch_optional(&self.db)
        .await?;

        Ok(result.map(|(username,)| username))
    }

    /// Get the current logged in user
    pub async fn get_current_user(&self) -> Option<UserDTO> {
        self.current_user.read().await.clone()
    }

    /// Set the current logged in user
    pub async fn set_current_user(&self, user: Option<UserDTO>) {
        *self.current_user.write().await = user;
    }

    /// Update connection status
    pub async fn set_connection_status(&self, connected: bool, address: Option<String>) {
        *self.connection_status.write().await = ConnectionStatus {
            connected,
            mixnet_address: address,
        };
    }

    /// Get connection status
    pub async fn get_connection_status(&self) -> ConnectionStatus {
        self.connection_status.read().await.clone()
    }

    /// Set the server address
    pub async fn set_server_address(&self, address: Option<String>) -> Result<(), std::io::Error> {
        *self.server_address.write().await = address.clone();

        // Persist to settings file
        let settings_path = self.app_dir.join("settings.json");
        let settings = serde_json::json!({
            "server_address": address
        });
        std::fs::write(settings_path, serde_json::to_string_pretty(&settings)?)?;
        Ok(())
    }

    /// Get the server address
    pub async fn get_server_address(&self) -> Option<String> {
        self.server_address.read().await.clone()
    }
}

// Clone is automatically derived - all Arc<RwLock<T>> fields share the same underlying data

impl AppState {
    /// Set the mixnet service (called after successful connection)
    pub async fn set_mixnet_service(
        &self,
        service: Arc<MixnetService>,
        rx: mpsc::Receiver<Incoming>,
    ) {
        *self.mixnet_service.write().await = Some(service);
        *self.incoming_rx.write().await = Some(rx);
    }

    /// Get the mixnet service if connected
    pub async fn get_mixnet_service(&self) -> Option<Arc<MixnetService>> {
        self.mixnet_service.read().await.clone()
    }

    /// Clear the mixnet service (called on disconnect)
    pub async fn clear_mixnet_service(&self) {
        *self.mixnet_service.write().await = None;
        *self.incoming_rx.write().await = None;
    }

    /// Take the incoming message receiver (transfers ownership)
    pub async fn take_incoming_rx(&self) -> Option<mpsc::Receiver<Incoming>> {
        self.incoming_rx.write().await.take()
    }

    /// Set PGP keys (called after successful key generation or loading)
    pub async fn set_pgp_keys(
        &self,
        secret_key: ArcSecretKey,
        public_key: ArcPublicKey,
        passphrase: ArcPassphrase,
    ) {
        *self.pgp_secret_key.write().await = Some(secret_key);
        *self.pgp_public_key.write().await = Some(public_key);
        *self.pgp_passphrase.write().await = Some(passphrase);
    }

    /// Get PGP keys if available (returns cloned Arc references)
    pub async fn get_pgp_keys(
        &self,
    ) -> Option<(ArcSecretKey, ArcPublicKey, ArcPassphrase)> {
        let secret = self.pgp_secret_key.read().await.clone()?;
        let public = self.pgp_public_key.read().await.clone()?;
        let passphrase = self.pgp_passphrase.read().await.clone()?;
        Some((secret, public, passphrase))
    }

    /// Get just the PGP public key if available
    pub async fn get_pgp_public_key(&self) -> Option<ArcPublicKey> {
        self.pgp_public_key.read().await.clone()
    }

    /// Get PGP secret key and passphrase for signing operations
    pub async fn get_pgp_signing_keys(&self) -> Option<(ArcSecretKey, ArcPassphrase)> {
        let secret = self.pgp_secret_key.read().await.clone()?;
        let passphrase = self.pgp_passphrase.read().await.clone()?;
        Some((secret, passphrase))
    }

    /// Clear PGP keys (called on logout)
    pub async fn clear_pgp_keys(&self) {
        *self.pgp_secret_key.write().await = None;
        *self.pgp_public_key.write().await = None;
        *self.pgp_passphrase.write().await = None;
    }

    /// Check if PGP keys are loaded
    pub async fn has_pgp_keys(&self) -> bool {
        self.pgp_secret_key.read().await.is_some()
            && self.pgp_public_key.read().await.is_some()
            && self.pgp_passphrase.read().await.is_some()
    }

    /// Get the user's PGP key storage directory
    pub fn get_pgp_key_dir(&self, username: &str) -> PathBuf {
        self.app_dir.join(username).join("pgp_keys")
    }

    /// Get the user's mixnet storage directory
    pub fn get_mixnet_storage_dir(&self, username: &str) -> PathBuf {
        self.app_dir.join(username).join("mixnet")
    }

    /// Get the user's MLS storage directory
    pub fn get_mls_storage_dir(&self, username: &str) -> PathBuf {
        self.app_dir.join(username).join("mls")
    }

    /// Set the MLS client (called after successful login)
    pub async fn set_mls_client(&self, client: Arc<MlsClient>) {
        *self.mls_client.write().await = Some(client);
    }

    /// Get the MLS client if initialized
    pub async fn get_mls_client(&self) -> Option<Arc<MlsClient>> {
        self.mls_client.read().await.clone()
    }

    /// Clear the MLS client (called on logout)
    pub async fn clear_mls_client(&self) {
        *self.mls_client.write().await = None;
    }

    /// Check if MLS client is initialized
    pub async fn has_mls_client(&self) -> bool {
        self.mls_client.read().await.is_some()
    }

    /// Get the key package manager
    pub fn get_key_package_manager(&self) -> Arc<KeyPackageManager> {
        Arc::clone(&self.key_package_manager)
    }

    /// Initialize MLS client for the current user
    /// This should be called after PGP keys are loaded
    pub async fn initialize_mls_client(&self, username: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use crate::crypto::mls::MlsClient;

        // Check if already initialized
        if self.has_mls_client().await {
            tracing::info!("MLS client already initialized");
            return Ok(());
        }

        // Get PGP keys
        let (secret_key, public_key, passphrase) = self
            .get_pgp_keys()
            .await
            .ok_or_else(|| "PGP keys not available - cannot initialize MLS client")?;

        // Create MLS client with persistent storage
        let mls_client = MlsClient::new(
            username,
            secret_key,
            public_key,
            &passphrase,
            self.app_dir.clone(),
        ).map_err(|e| format!("Failed to create MLS client: {}", e))?;

        // Store the client in state
        self.set_mls_client(Arc::new(mls_client)).await;
        tracing::info!("MLS client initialized for user: {}", username);

        Ok(())
    }

    // ========== Background Task Management ==========

    /// Start background tasks with the given message receiver
    pub async fn start_background_tasks(
        &self,
        app_handle: tauri::AppHandle,
        rx: mpsc::Receiver<crate::core::mixnet_client::Incoming>,
    ) {
        let state_arc = Arc::new(self.clone());
        let tasks = BackgroundTasks::start(app_handle, state_arc, rx).await;
        *self.background_tasks.write().await = Some(tasks);
        tracing::info!("Background tasks started");
    }

    /// Start background tasks without the message loop
    /// (useful when mixnet is not yet connected)
    pub async fn start_background_tasks_without_message_loop(&self, app_handle: tauri::AppHandle) {
        let state_arc = Arc::new(self.clone());
        let tasks = BackgroundTasks::start_without_message_loop(app_handle, state_arc);
        *self.background_tasks.write().await = Some(tasks);
        tracing::info!("Background tasks started (without message loop)");
    }

    /// Start the message receive loop
    /// Call this after mixnet connection is established
    pub async fn start_message_loop(
        &self,
        app_handle: tauri::AppHandle,
        rx: mpsc::Receiver<crate::core::mixnet_client::Incoming>,
    ) {
        let mut tasks = self.background_tasks.write().await;
        if let Some(ref mut t) = *tasks {
            let state_arc = Arc::new(self.clone());
            t.start_message_loop(app_handle, state_arc, rx);
        } else {
            tracing::warn!("Cannot start message loop: background tasks not initialized");
        }
    }

    /// Stop all background tasks
    pub async fn stop_background_tasks(&self) {
        let mut tasks = self.background_tasks.write().await;
        if let Some(ref mut t) = *tasks {
            t.stop();
        }
        *tasks = None;
        tracing::info!("Background tasks stopped");
    }

    /// Check if background tasks are running
    pub async fn are_background_tasks_running(&self) -> bool {
        self.background_tasks.read().await.as_ref().map(|t| t.is_running()).unwrap_or(false)
    }

    /// Check if message loop is running
    pub async fn is_message_loop_running(&self) -> bool {
        self.background_tasks.read().await.as_ref().map(|t| t.is_message_loop_running()).unwrap_or(false)
    }

    // ========== Query Management ==========

    /// Register a pending query and return a receiver for the result
    pub async fn register_pending_query(&self, username: &str) -> oneshot::Receiver<Option<QueryResult>> {
        let (tx, rx) = oneshot::channel();
        self.pending_queries.write().await.insert(username.to_string(), tx);
        rx
    }

    /// Resolve a pending query with the result
    pub async fn resolve_pending_query(&self, username: &str, result: Option<QueryResult>) {
        if let Some(tx) = self.pending_queries.write().await.remove(username) {
            let _ = tx.send(result);
        }
    }

    /// Cancel a pending query
    pub async fn cancel_pending_query(&self, username: &str) {
        self.pending_queries.write().await.remove(username);
    }
}
