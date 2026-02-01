//! Authentication commands
//!
//! This module handles user registration and login flows with the Nymstr
//! discovery server, including PGP key generation and nonce-challenge authentication.

use std::sync::Arc;
use std::time::Duration;

use tauri::{AppHandle, State};

use crate::core::message_handler::AuthenticationHandler;
use crate::crypto::pgp::{PgpKeyManager, SecurePassphrase};
use crate::state::AppState;
use crate::types::{ApiError, InitializeResponse, UserDTO};

/// Timeout for authentication flows (30 seconds)
const AUTH_TIMEOUT: Duration = Duration::from_secs(30);

/// Validate username format.
///
/// Rules:
/// - 1-64 characters
/// - Alphanumeric, underscore, or hyphen only
fn validate_username(username: &str) -> Result<(), ApiError> {
    if username.is_empty() || username.len() > 64 {
        return Err(ApiError::validation("Username must be 1-64 characters"));
    }

    if !username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ApiError::validation(
            "Username can only contain letters, numbers, underscores, and hyphens",
        ));
    }

    Ok(())
}

/// Initialize the application and check for existing users
#[tauri::command]
pub async fn initialize(state: State<'_, AppState>) -> Result<InitializeResponse, ApiError> {
    tracing::info!("Initializing application");

    // Check if we have a local user
    let username = state
        .has_local_user()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(InitializeResponse {
        has_user: username.is_some(),
        username,
    })
}

/// Register a new user
///
/// This performs the full registration flow:
/// 1. Validate username
/// 2. Generate PGP keypair
/// 3. Store encrypted keys locally
/// 4. Connect to mixnet if not connected
/// 5. Send registration request
/// 6. Handle challenge-response authentication
/// 7. Store user in database on success
#[tauri::command]
pub async fn register_user(
    app_handle: AppHandle,
    username: String,
    passphrase: String,
    state: State<'_, AppState>,
) -> Result<UserDTO, ApiError> {
    tracing::info!("Registering user: {}", username);

    // 1. Validate username
    validate_username(&username)?;

    // Validate passphrase
    if passphrase.len() < 12 {
        return Err(ApiError::validation(
            "Passphrase must be at least 12 characters",
        ));
    }

    // 2. Generate PGP keypair
    let secure_passphrase = SecurePassphrase::new(passphrase);

    let (secret_key, public_key) =
        PgpKeyManager::generate_keypair_secure(&username, &secure_passphrase)
            .map_err(|e| ApiError::internal(format!("Failed to generate PGP keypair: {}", e)))?;

    // Get armored public key for registration
    let public_key_armored = PgpKeyManager::public_key_armored(&public_key)
        .map_err(|e| ApiError::internal(format!("Failed to armor public key: {}", e)))?;

    // 3. Store encrypted keys locally
    let key_dir = state.get_pgp_key_dir(&username);
    std::fs::create_dir_all(&key_dir)
        .map_err(|e| ApiError::internal(format!("Failed to create key directory: {}", e)))?;

    // Save keys using PgpKeyManager (saves to storage/{username}/pgp_keys/)
    // We need to temporarily change directory or modify the save path
    // For now, we'll save directly to the app directory
    save_keys_to_app_dir(
        &key_dir,
        &username,
        &secret_key,
        &public_key,
        &secure_passphrase,
    )?;

    // Wrap keys in Arc for state storage
    let arc_secret_key = Arc::new(secret_key);
    let arc_public_key = Arc::new(public_key);
    let arc_passphrase = Arc::new(secure_passphrase);

    // 4. Check if mixnet is connected
    let mixnet_service = state.get_mixnet_service().await.ok_or_else(|| {
        ApiError::not_connected("Mixnet not connected. Please connect first.")
    })?;

    // 5. Check server address
    let server_address = state.get_server_address().await.ok_or_else(|| {
        ApiError::validation("Server address not configured")
    })?;

    // Ensure mixnet service has server address
    mixnet_service.set_server_address(Some(server_address.clone())).await;

    // 6. Send registration request
    mixnet_service
        .send_registration_request(&username, &public_key_armored)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to send registration request: {}", e)))?;

    tracing::info!("Registration request sent for user: {}", username);

    // 7. Wait for challenge and handle response
    // Take the incoming receiver to process messages
    let mut incoming_rx = state.take_incoming_rx().await.ok_or_else(|| {
        ApiError::internal("Message receiver not available")
    })?;

    // Create auth handler for processing challenge
    let auth_handler = AuthenticationHandler::new(
        mixnet_service.clone(),
        arc_secret_key.clone(),
        arc_public_key.clone(),
        arc_passphrase.clone(),
    );

    // Wait for server response with timeout
    let result = tokio::time::timeout(AUTH_TIMEOUT, async {
        loop {
            match incoming_rx.recv().await {
                Some(incoming) => {
                    let env = &incoming.envelope;
                    let action = env.action.as_str();

                    match action {
                        "challenge" => {
                            // Check if this is a registration challenge
                            if let Some(context) = env.payload.get("context").and_then(|v| v.as_str()) {
                                if context == "registration" {
                                    if let Some(nonce) = env.payload.get("nonce").and_then(|v| v.as_str()) {
                                        tracing::info!("Received registration challenge");

                                        if let Err(e) = auth_handler.process_register_challenge(&username, nonce).await {
                                            return Err(format!("Failed to process challenge: {}", e));
                                        }
                                    }
                                }
                            }
                        }
                        "challengeResponse" => {
                            // Check if this is a registration response
                            if let Some(context) = env.payload.get("context").and_then(|v| v.as_str()) {
                                if context == "registration" {
                                    if let Some(result) = env.payload.get("result").and_then(|v| v.as_str()) {
                                        match auth_handler.process_register_response(&username, result) {
                                            Ok(true) => return Ok(()),
                                            Ok(false) => return Err(format!("Registration failed: {}", result)),
                                            Err(e) => return Err(format!("Error processing response: {}", e)),
                                        }
                                    }
                                }
                            }
                        }
                        _ => {
                            tracing::debug!("Ignoring message with action: {}", action);
                        }
                    }
                }
                None => {
                    return Err("Message channel closed".to_string());
                }
            }
        }
    })
    .await;

    // Handle result
    match result {
        Ok(Ok(())) => {
            tracing::info!("Registration successful for user: {}", username);
        }
        Ok(Err(e)) => {
            // Put the receiver back on failure
            *state.incoming_rx.write().await = Some(incoming_rx);
            return Err(ApiError::authentication(format!("Registration failed: {}", e)));
        }
        Err(_) => {
            // Put the receiver back on timeout
            *state.incoming_rx.write().await = Some(incoming_rx);
            return Err(ApiError::timeout("Registration timed out waiting for server response"));
        }
    }

    // 8. Store user in database
    sqlx::query(
        "INSERT INTO users (username, display_name, public_key) VALUES (?, ?, ?)",
    )
    .bind(&username)
    .bind(&username)
    .bind(&public_key_armored)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to store user: {}", e)))?;

    // 9. Set current user and keys in state
    let user = UserDTO {
        username: username.clone(),
        display_name: username.clone(),
        public_key: public_key_armored.clone(),
        online: true,
    };

    state.set_current_user(Some(user.clone())).await;
    state.set_pgp_keys(arc_secret_key, arc_public_key, arc_passphrase).await;

    // 10. Initialize MLS client for encrypted messaging
    if let Err(e) = state.initialize_mls_client(&user.username).await {
        tracing::warn!("Failed to initialize MLS client: {}", e);
        // Continue - MLS can be initialized later if needed
    }

    // 11. Start background tasks with the message loop
    state.start_background_tasks(app_handle, incoming_rx).await;

    tracing::info!("User registered successfully: {}", username);
    Ok(user)
}

/// Login an existing user
///
/// This performs the full login flow:
/// 1. Load user from database
/// 2. Load PGP keys from disk
/// 3. Connect to mixnet if not connected
/// 4. Send login request
/// 5. Handle challenge-response authentication
/// 6. Set current user on success
#[tauri::command]
pub async fn login_user(
    app_handle: AppHandle,
    username: String,
    passphrase: String,
    state: State<'_, AppState>,
) -> Result<UserDTO, ApiError> {
    tracing::info!("Logging in user: {}", username);

    // 1. Check if user exists in database
    let result: Option<(String, String, String)> = sqlx::query_as(
        "SELECT username, display_name, public_key FROM users WHERE username = ?",
    )
    .bind(&username)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let (db_username, display_name, public_key_armored) =
        result.ok_or_else(|| ApiError::not_found("User not found"))?;

    // 2. Load PGP keys from disk
    let secure_passphrase = SecurePassphrase::new(passphrase);
    let key_dir = state.get_pgp_key_dir(&username);

    let (secret_key, public_key) = load_keys_from_app_dir(&key_dir, &secure_passphrase)?;

    // Wrap keys in Arc
    let arc_secret_key = Arc::new(secret_key);
    let arc_public_key = Arc::new(public_key);
    let arc_passphrase = Arc::new(secure_passphrase);

    // Store keys in state
    state.set_pgp_keys(
        arc_secret_key.clone(),
        arc_public_key.clone(),
        arc_passphrase.clone(),
    ).await;

    // 3. Check if mixnet is connected
    let mixnet_service = state.get_mixnet_service().await.ok_or_else(|| {
        ApiError::not_connected("Mixnet not connected. Please connect first.")
    })?;

    // 4. Check server address
    let server_address = state.get_server_address().await.ok_or_else(|| {
        ApiError::validation("Server address not configured")
    })?;

    // Ensure mixnet service has server address
    mixnet_service.set_server_address(Some(server_address.clone())).await;

    // 5. Send login request
    mixnet_service
        .send_login_request(&username)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to send login request: {}", e)))?;

    tracing::info!("Login request sent for user: {}", username);

    // 6. Wait for challenge and handle response
    let mut incoming_rx = state.take_incoming_rx().await.ok_or_else(|| {
        ApiError::internal("Message receiver not available")
    })?;

    let auth_handler = AuthenticationHandler::new(
        mixnet_service.clone(),
        arc_secret_key.clone(),
        arc_public_key.clone(),
        arc_passphrase.clone(),
    );

    let result = tokio::time::timeout(AUTH_TIMEOUT, async {
        loop {
            match incoming_rx.recv().await {
                Some(incoming) => {
                    let env = &incoming.envelope;
                    let action = env.action.as_str();

                    match action {
                        "challenge" => {
                            if let Some(context) = env.payload.get("context").and_then(|v| v.as_str()) {
                                if context == "login" {
                                    if let Some(nonce) = env.payload.get("nonce").and_then(|v| v.as_str()) {
                                        tracing::info!("Received login challenge");

                                        if let Err(e) = auth_handler.process_login_challenge(&username, nonce).await {
                                            return Err(format!("Failed to process challenge: {}", e));
                                        }
                                    }
                                }
                            }
                        }
                        "challengeResponse" => {
                            if let Some(context) = env.payload.get("context").and_then(|v| v.as_str()) {
                                if context == "login" {
                                    if let Some(result) = env.payload.get("result").and_then(|v| v.as_str()) {
                                        match auth_handler.process_login_response(&username, result) {
                                            Ok(true) => return Ok(()),
                                            Ok(false) => return Err(format!("Login failed: {}", result)),
                                            Err(e) => return Err(format!("Error processing response: {}", e)),
                                        }
                                    }
                                }
                            }
                        }
                        _ => {
                            tracing::debug!("Ignoring message with action: {}", action);
                        }
                    }
                }
                None => {
                    return Err("Message channel closed".to_string());
                }
            }
        }
    })
    .await;

    // Handle result
    match result {
        Ok(Ok(())) => {
            tracing::info!("Login successful for user: {}", username);
        }
        Ok(Err(e)) => {
            // Put the receiver back on failure
            *state.incoming_rx.write().await = Some(incoming_rx);
            // Clear keys on failure
            state.clear_pgp_keys().await;
            return Err(ApiError::authentication(format!("Login failed: {}", e)));
        }
        Err(_) => {
            // Put the receiver back on timeout
            *state.incoming_rx.write().await = Some(incoming_rx);
            // Clear keys on timeout
            state.clear_pgp_keys().await;
            return Err(ApiError::timeout("Login timed out waiting for server response"));
        }
    }

    // 7. Set current user
    let user = UserDTO {
        username: db_username.clone(),
        display_name,
        public_key: public_key_armored,
        online: true,
    };

    state.set_current_user(Some(user.clone())).await;

    // 8. Initialize MLS client for encrypted messaging
    if let Err(e) = state.initialize_mls_client(&user.username).await {
        tracing::warn!("Failed to initialize MLS client: {}", e);
        // Continue - MLS can be initialized later if needed
    }

    // 9. Start background tasks with the message loop
    // The rx is now owned by the background task system
    state.start_background_tasks(app_handle, incoming_rx).await;

    tracing::info!("User logged in successfully: {}", user.username);
    Ok(user)
}

/// Logout the current user
#[tauri::command]
pub async fn logout(state: State<'_, AppState>) -> Result<(), ApiError> {
    tracing::info!("Logging out user");

    // Stop background tasks first (they depend on mixnet)
    state.stop_background_tasks().await;

    // Disconnect from mixnet (this drops the channel which is now broken)
    // User will need to reconnect before logging in again
    state.clear_mixnet_service().await;
    state.set_connection_status(false, None).await;

    // Clear MLS client
    state.clear_mls_client().await;

    // Clear current user
    state.set_current_user(None).await;

    // Clear PGP keys from memory
    state.clear_pgp_keys().await;

    tracing::info!("User logged out, mixnet disconnected");
    Ok(())
}

/// Get the current logged in user
#[tauri::command]
pub async fn get_current_user(state: State<'_, AppState>) -> Result<Option<UserDTO>, ApiError> {
    Ok(state.get_current_user().await)
}

// ========== Helper Functions ==========

/// Save PGP keys to the app data directory
fn save_keys_to_app_dir(
    key_dir: &std::path::Path,
    _username: &str,
    secret_key: &pgp::composed::SignedSecretKey,
    public_key: &pgp::composed::SignedPublicKey,
    passphrase: &SecurePassphrase,
) -> Result<(), ApiError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use std::fs;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    type HmacSha256 = Hmac<Sha256>;

    // Ensure directory exists with secure permissions
    fs::create_dir_all(key_dir)
        .map_err(|e| ApiError::internal(format!("Failed to create key directory: {}", e)))?;

    #[cfg(unix)]
    {
        let mut dir_perms = fs::metadata(key_dir)
            .map_err(|e| ApiError::internal(format!("Failed to read directory metadata: {}", e)))?
            .permissions();
        dir_perms.set_mode(0o700);
        fs::set_permissions(key_dir, dir_perms)
            .map_err(|e| ApiError::internal(format!("Failed to set directory permissions: {}", e)))?;
    }

    // Armor and save secret key
    let secret_armored = secret_key
        .to_armored_string(Default::default())
        .map_err(|e| ApiError::internal(format!("Failed to armor secret key: {}", e)))?;

    let secret_path = key_dir.join("secret.asc");

    // Compute HMAC for integrity
    let mut mac = HmacSha256::new_from_slice(passphrase.as_str().as_bytes())
        .map_err(|e| ApiError::internal(format!("Failed to create HMAC: {}", e)))?;
    mac.update(secret_armored.as_bytes());
    let secret_hmac = hex::encode(mac.finalize().into_bytes());

    fs::write(&secret_path, &secret_armored)
        .map_err(|e| ApiError::internal(format!("Failed to write secret key: {}", e)))?;
    fs::write(secret_path.with_extension("hmac"), &secret_hmac)
        .map_err(|e| ApiError::internal(format!("Failed to write secret key HMAC: {}", e)))?;

    #[cfg(unix)]
    {
        let mut secret_perms = fs::metadata(&secret_path)
            .map_err(|e| ApiError::internal(format!("Failed to read secret key metadata: {}", e)))?
            .permissions();
        secret_perms.set_mode(0o600);
        fs::set_permissions(&secret_path, secret_perms)
            .map_err(|e| ApiError::internal(format!("Failed to set secret key permissions: {}", e)))?;
    }

    // Armor and save public key
    let public_armored = public_key
        .to_armored_string(Default::default())
        .map_err(|e| ApiError::internal(format!("Failed to armor public key: {}", e)))?;

    let public_path = key_dir.join("public.asc");

    let mut mac = HmacSha256::new_from_slice(passphrase.as_str().as_bytes())
        .map_err(|e| ApiError::internal(format!("Failed to create HMAC: {}", e)))?;
    mac.update(public_armored.as_bytes());
    let public_hmac = hex::encode(mac.finalize().into_bytes());

    fs::write(&public_path, &public_armored)
        .map_err(|e| ApiError::internal(format!("Failed to write public key: {}", e)))?;
    fs::write(public_path.with_extension("hmac"), &public_hmac)
        .map_err(|e| ApiError::internal(format!("Failed to write public key HMAC: {}", e)))?;

    tracing::info!("Saved PGP keys to {:?}", key_dir);
    Ok(())
}

/// Load PGP keys from the app data directory
fn load_keys_from_app_dir(
    key_dir: &std::path::Path,
    passphrase: &SecurePassphrase,
) -> Result<(pgp::composed::SignedSecretKey, pgp::composed::SignedPublicKey), ApiError> {
    use hmac::{Hmac, Mac};
    use pgp::composed::Deserializable;
    use sha2::Sha256;
    use std::fs;
    use subtle::ConstantTimeEq;

    type HmacSha256 = Hmac<Sha256>;

    let secret_path = key_dir.join("secret.asc");
    let public_path = key_dir.join("public.asc");
    let secret_hmac_path = secret_path.with_extension("hmac");
    let public_hmac_path = public_path.with_extension("hmac");

    if !secret_path.exists() || !public_path.exists() {
        return Err(ApiError::not_found("PGP keys not found"));
    }

    // Load and verify secret key
    let secret_armored = fs::read_to_string(&secret_path)
        .map_err(|e| ApiError::internal(format!("Failed to read secret key: {}", e)))?;

    if secret_hmac_path.exists() {
        let stored_hmac = fs::read_to_string(&secret_hmac_path)
            .map_err(|e| ApiError::internal(format!("Failed to read secret key HMAC: {}", e)))?;

        let mut mac = HmacSha256::new_from_slice(passphrase.as_str().as_bytes())
            .map_err(|e| ApiError::internal(format!("Failed to create HMAC: {}", e)))?;
        mac.update(secret_armored.as_bytes());
        let computed_hmac = hex::encode(mac.finalize().into_bytes());

        if !bool::from(
            stored_hmac
                .trim()
                .as_bytes()
                .ct_eq(computed_hmac.as_bytes()),
        ) {
            return Err(ApiError::authentication(
                "Secret key integrity verification failed (incorrect passphrase?)",
            ));
        }
    } else {
        tracing::warn!("No HMAC file found for secret key - skipping integrity verification");
    }

    let (secret_key, _) = pgp::composed::SignedSecretKey::from_string(&secret_armored)
        .map_err(|e| ApiError::internal(format!("Failed to parse secret key: {}", e)))?;

    // Load and verify public key
    let public_armored = fs::read_to_string(&public_path)
        .map_err(|e| ApiError::internal(format!("Failed to read public key: {}", e)))?;

    if public_hmac_path.exists() {
        let stored_hmac = fs::read_to_string(&public_hmac_path)
            .map_err(|e| ApiError::internal(format!("Failed to read public key HMAC: {}", e)))?;

        let mut mac = HmacSha256::new_from_slice(passphrase.as_str().as_bytes())
            .map_err(|e| ApiError::internal(format!("Failed to create HMAC: {}", e)))?;
        mac.update(public_armored.as_bytes());
        let computed_hmac = hex::encode(mac.finalize().into_bytes());

        if !bool::from(
            stored_hmac
                .trim()
                .as_bytes()
                .ct_eq(computed_hmac.as_bytes()),
        ) {
            return Err(ApiError::authentication(
                "Public key integrity verification failed",
            ));
        }
    }

    let (public_key, _) = pgp::composed::SignedPublicKey::from_string(&public_armored)
        .map_err(|e| ApiError::internal(format!("Failed to parse public key: {}", e)))?;

    tracing::info!("Loaded PGP keys from {:?}", key_dir);
    Ok((secret_key, public_key))
}
