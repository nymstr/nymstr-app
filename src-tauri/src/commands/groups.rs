//! Group management commands with MLS encryption

use base64::Engine;
use chrono::Utc;
use tauri::State;
use uuid::Uuid;

use crate::crypto::mls::MlsClient;
use crate::crypto::pgp::PgpSigner;
use crate::state::AppState;
use crate::types::{ApiError, GroupDTO, MessageDTO, MessageStatus};

/// Discover public groups from the discovery server
#[tauri::command]
pub async fn discover_groups(state: State<'_, AppState>) -> Result<Vec<GroupDTO>, ApiError> {
    tracing::info!("Discovering public groups");

    // Get mixnet service
    let service = state
        .get_mixnet_service()
        .await
        .ok_or_else(|| ApiError::not_connected("Not connected to mixnet"))?;

    // Get current user for signing
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    // Get PGP keys for signing
    let (secret_key, passphrase) = state
        .get_pgp_signing_keys()
        .await
        .ok_or_else(|| ApiError::internal("PGP keys not available"))?;

    // Sign the query request
    let timestamp = Utc::now().timestamp();
    let sign_content = format!("queryGroups:{}:{}", current_user.username, timestamp);
    let _signature = PgpSigner::sign_detached_secure(&secret_key, sign_content.as_bytes(), &passphrase)
        .map_err(|e| ApiError::internal(format!("Failed to sign request: {}", e)))?;

    // Send query request to server (the response will come async via mixnet)
    // For now, we return groups from local database
    // TODO: Implement async response handling via events using the signature

    // Fetch from local database (groups we've discovered before)
    let groups: Vec<(String, String, String, i64, bool, Option<String>)> = sqlx::query_as(
        "SELECT id, name, address, member_count, is_public, description FROM groups WHERE is_public = 1",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let result: Vec<GroupDTO> = groups
        .into_iter()
        .map(
            |(id, name, address, member_count, is_public, description)| GroupDTO {
                id,
                name,
                address,
                member_count: member_count as u32,
                is_public,
                description,
            },
        )
        .collect();

    // Also try to send a discovery query (fire and forget)
    let _ = service.set_server_address(state.get_server_address().await).await;
    // Note: The actual discovery response will be handled via the message router

    Ok(result)
}

/// Join a group
#[tauri::command]
pub async fn join_group(
    group_address: String,
    state: State<'_, AppState>,
) -> Result<GroupDTO, ApiError> {
    tracing::info!("Joining group: {}", group_address);

    // Get current user
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    // Get mixnet service
    let service = state
        .get_mixnet_service()
        .await
        .ok_or_else(|| ApiError::not_connected("Not connected to mixnet"))?;

    // Get PGP keys
    let (secret_key, public_key, passphrase) = state
        .get_pgp_keys()
        .await
        .ok_or_else(|| ApiError::internal("PGP keys not available"))?;

    let public_key_armored = crate::crypto::pgp::PgpKeyManager::public_key_armored(&public_key)
        .map_err(|e| ApiError::internal(format!("Failed to export public key: {}", e)))?;

    // Create timestamp-based signature for authentication
    let timestamp = Utc::now().timestamp();
    let sign_content = format!(
        "register:{}:{}:{}",
        current_user.username, group_address, timestamp
    );
    let signature = PgpSigner::sign_detached_secure(&secret_key, sign_content.as_bytes(), &passphrase)
        .map_err(|e| ApiError::internal(format!("Failed to sign request: {}", e)))?;

    // Generate MLS KeyPackage for joining
    let mls_client = MlsClient::new(
        &current_user.username,
        secret_key.clone(),
        public_key.clone(),
        &passphrase,
        state.app_dir.clone(),
    )
    .map_err(|e| ApiError::internal(format!("Failed to create MLS client: {}", e)))?;

    let key_package = mls_client
        .generate_key_package()
        .map_err(|e| ApiError::internal(format!("Failed to generate KeyPackage: {}", e)))?;
    let key_package_b64 = base64::engine::general_purpose::STANDARD.encode(&key_package);

    // Register with the group server (includes KeyPackage)
    service
        .register_with_group_server_and_key_package(
            &current_user.username,
            &public_key_armored,
            &signature,
            timestamp,
            &group_address,
            Some(&key_package_b64),
        )
        .await
        .map_err(|e| ApiError::internal(format!("Failed to register with group: {}", e)))?;

    // Create the group entry locally (will be updated when we receive confirmation)
    let group = GroupDTO {
        id: Uuid::new_v4().to_string(),
        name: format!("Group {}", &group_address[..8.min(group_address.len())]),
        address: group_address.clone(),
        member_count: 1,
        is_public: true,
        description: None,
    };

    // Store in database
    sqlx::query(
        r#"
        INSERT OR REPLACE INTO groups (id, name, address, member_count, is_public)
        VALUES (?, ?, ?, ?, ?)
        "#,
    )
    .bind(&group.id)
    .bind(&group.name)
    .bind(&group.address)
    .bind(group.member_count as i64)
    .bind(group.is_public)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to store group: {}", e)))?;

    // Tables are created by schema::run_migrations() on app startup
    // Store initial membership
    sqlx::query(
        r#"
        INSERT OR REPLACE INTO group_memberships (server_address, username, role)
        VALUES (?, ?, 'member')
        "#,
    )
    .bind(&group_address)
    .bind(&current_user.username)
    .execute(&state.db)
    .await
    .ok();

    tracing::info!(
        "Sent join request to group {} for user {}",
        group_address,
        current_user.username
    );

    Ok(group)
}

/// Leave a group
#[tauri::command]
pub async fn leave_group(
    group_address: String,
    state: State<'_, AppState>,
) -> Result<(), ApiError> {
    tracing::info!("Leaving group: {}", group_address);

    // Remove from local database
    sqlx::query("DELETE FROM groups WHERE address = ?")
        .bind(&group_address)
        .execute(&state.db)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // Get current user for scoped delete
    let current_user = state.get_current_user().await;

    // Remove membership (scoped to current user)
    if let Some(user) = current_user {
        sqlx::query("DELETE FROM group_memberships WHERE server_address = ? AND username = ?")
            .bind(&group_address)
            .bind(&user.username)
            .execute(&state.db)
            .await
            .ok();
    }

    // Remove cursor
    sqlx::query("DELETE FROM group_cursors WHERE server_address = ?")
        .bind(&group_address)
        .execute(&state.db)
        .await
        .ok();

    // TODO: Optionally notify group server that we're leaving

    Ok(())
}

/// Send a message to a group with MLS encryption
#[tauri::command]
pub async fn send_group_message(
    group_address: String,
    content: String,
    state: State<'_, AppState>,
) -> Result<MessageDTO, ApiError> {
    tracing::info!("Sending group message to: {}", group_address);

    // Validate content
    if content.is_empty() {
        return Err(ApiError::validation("Message content cannot be empty"));
    }

    // Get current user
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    // Get mixnet service
    let service = state
        .get_mixnet_service()
        .await
        .ok_or_else(|| ApiError::not_connected("Not connected to mixnet"))?;

    // Get PGP keys
    let (secret_key, public_key, passphrase) = state
        .get_pgp_keys()
        .await
        .ok_or_else(|| ApiError::internal("PGP keys not available"))?;

    // Look up the MLS group ID for this server address (scoped to current user)
    let mls_group_id: Option<(String,)> =
        sqlx::query_as("SELECT mls_group_id FROM group_memberships WHERE server_address = ? AND username = ?")
            .bind(&group_address)
            .bind(&current_user.username)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| ApiError::internal(format!("Failed to query MLS group: {}", e)))?;

    let mls_group_id = mls_group_id
        .and_then(|(id,)| if id.is_empty() { None } else { Some(id) })
        .ok_or_else(|| {
            ApiError::internal(format!(
                "MLS group not initialized for {}. Wait for welcome message after joining.",
                group_address
            ))
        })?;

    // Create MLS client
    let mls_client = MlsClient::new(
        &current_user.username,
        secret_key.clone(),
        public_key.clone(),
        &passphrase,
        state.app_dir.clone(),
    )
    .map_err(|e| ApiError::internal(format!("Failed to create MLS client: {}", e)))?;

    // Decode the MLS group ID from base64 to bytes
    let conversation_id = base64::engine::general_purpose::STANDARD
        .decode(&mls_group_id)
        .map_err(|e| ApiError::internal(format!("Invalid MLS group ID: {}", e)))?;

    // Encrypt the message with MLS
    let encrypted = mls_client
        .encrypt_message(&conversation_id, content.as_bytes())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to encrypt message: {}", e)))?;

    // Encode as base64 for transport
    let ciphertext = base64::engine::general_purpose::STANDARD.encode(&encrypted.mls_message);

    // Sign the ciphertext
    let signature = PgpSigner::sign_detached_secure(&secret_key, ciphertext.as_bytes(), &passphrase)
        .map_err(|e| ApiError::internal(format!("Failed to sign message: {}", e)))?;

    // Send to group server
    service
        .send_group_message(&current_user.username, &ciphertext, &signature, &group_address)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to send message: {}", e)))?;

    // Create message DTO
    let message = MessageDTO {
        id: Uuid::new_v4().to_string(),
        sender: current_user.username.clone(),
        content: content.clone(),
        timestamp: Utc::now().to_rfc3339(),
        status: MessageStatus::Sent,
        is_own: true,
        is_read: true,
    };

    // Store locally
    sqlx::query(
        r#"
        INSERT INTO messages (id, conversation_id, sender, content, timestamp, status, is_own, is_read)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&message.id)
    .bind(&group_address)
    .bind(&message.sender)
    .bind(&message.content)
    .bind(&message.timestamp)
    .bind("sent")
    .bind(true)
    .bind(true)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to store message: {}", e)))?;

    tracing::info!("Sent MLS-encrypted message to group {}", group_address);

    Ok(message)
}

/// Fetch messages from a group server
#[tauri::command]
pub async fn fetch_group_messages(
    group_address: String,
    limit: Option<i64>,
    before_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<MessageDTO>, ApiError> {
    tracing::debug!("Fetching group messages from: {}", group_address);

    // Get current user
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    // Get mixnet service
    let service = state
        .get_mixnet_service()
        .await
        .ok_or_else(|| ApiError::not_connected("Not connected to mixnet"))?;

    // Get PGP keys for signing
    let (secret_key, passphrase) = state
        .get_pgp_signing_keys()
        .await
        .ok_or_else(|| ApiError::internal("PGP keys not available"))?;

    // Get current cursor from database
    let cursor: Option<(i64,)> =
        sqlx::query_as("SELECT last_message_id FROM group_cursors WHERE server_address = ?")
            .bind(&group_address)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| ApiError::internal(format!("Failed to query cursor: {}", e)))?;

    let last_seen_id = cursor.map(|(id,)| id).unwrap_or(0);

    // Try to sync epoch before fetching (best effort, non-blocking)
    // This helps catch up on any missed commits when group membership changed
    let mls_group_id: Option<(String,)> =
        sqlx::query_as("SELECT mls_group_id FROM group_memberships WHERE server_address = ? AND username = ?")
            .bind(&group_address)
            .bind(&current_user.username)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

    if let Some((mls_group_id,)) = mls_group_id {
        if !mls_group_id.is_empty() {
            // Get PGP keys for full key access (needed for MLS client)
            if let Some((_, public_key, _)) = state.get_pgp_keys().await {
                // Create MLS client to get current epoch
                if let Ok(mls_client) = MlsClient::new(
                    &current_user.username,
                    secret_key.clone(),
                    public_key,
                    &passphrase,
                    state.app_dir.clone(),
                ) {
                    // Decode MLS group ID to bytes to check if group exists
                    if let Ok(group_id_bytes) = base64::engine::general_purpose::STANDARD.decode(&mls_group_id) {
                        if mls_client.group_exists(&group_id_bytes) {
                            // Sign epoch sync request: "groupId:epoch"
                            // We request sync from epoch 0 to get all commits, MLS will handle deduplication
                            let epoch = 0i64; // Request all commits, let server filter
                            let sign_content = format!("{}:{}", mls_group_id, epoch);
                            if let Ok(sync_sig) = PgpSigner::sign_detached_secure(&secret_key, sign_content.as_bytes(), &passphrase) {
                                tracing::debug!("Sending epoch sync request for group {} before fetch", group_address);
                                let _ = service
                                    .sync_epoch_from_server(
                                        &current_user.username,
                                        &mls_group_id,
                                        epoch,
                                        &sync_sig,
                                        &group_address,
                                    )
                                    .await;
                            }
                        }
                    }
                }
            }
        }
    }

    // Sign the fetch request
    let signature = PgpSigner::sign_detached_secure(
        &secret_key,
        last_seen_id.to_string().as_bytes(),
        &passphrase,
    )
    .map_err(|e| ApiError::internal(format!("Failed to sign request: {}", e)))?;

    // Send fetch request (fire and forget - response comes async)
    let _ = service
        .send_group_fetch_request(
            &current_user.username,
            last_seen_id,
            &signature,
            &group_address,
        )
        .await;

    // Return messages from local database for now
    // The new messages will be received via the message router and stored
    let limit = limit.unwrap_or(50).min(100);

    let messages: Vec<(String, String, String, String, String, bool, bool)> = if let Some(before) =
        before_id
    {
        sqlx::query_as(
            r#"
            SELECT id, sender, content, timestamp, status, is_own, is_read
            FROM messages
            WHERE conversation_id = ? AND id < ?
            ORDER BY timestamp DESC
            LIMIT ?
            "#,
        )
        .bind(&group_address)
        .bind(&before)
        .bind(limit)
        .fetch_all(&state.db)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    } else {
        sqlx::query_as(
            r#"
            SELECT id, sender, content, timestamp, status, is_own, is_read
            FROM messages
            WHERE conversation_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
            "#,
        )
        .bind(&group_address)
        .bind(limit)
        .fetch_all(&state.db)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    };

    let mut result: Vec<MessageDTO> = messages
        .into_iter()
        .map(|(id, sender, content, timestamp, status, is_own, is_read)| MessageDTO {
            id,
            sender,
            content,
            timestamp,
            status: match status.as_str() {
                "pending" => MessageStatus::Pending,
                "sent" => MessageStatus::Sent,
                "delivered" => MessageStatus::Delivered,
                _ => MessageStatus::Failed,
            },
            is_own,
            is_read,
        })
        .collect();

    result.reverse();
    Ok(result)
}

/// Initialize a group as admin/creator (creates MLS group locally first)
/// This is for the first member/admin who creates the group.
/// Other members should use `join_group` and wait for a Welcome message.
#[tauri::command]
pub async fn init_group(
    group_address: String,
    group_name: Option<String>,
    state: State<'_, AppState>,
) -> Result<GroupDTO, ApiError> {
    tracing::info!("Initializing group as admin: {}", group_address);

    // Get current user
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    // Get mixnet service
    let service = state
        .get_mixnet_service()
        .await
        .ok_or_else(|| ApiError::not_connected("Not connected to mixnet"))?;

    // Get PGP keys
    let (secret_key, public_key, passphrase) = state
        .get_pgp_keys()
        .await
        .ok_or_else(|| ApiError::internal("PGP keys not available"))?;

    let public_key_armored = crate::crypto::pgp::PgpKeyManager::public_key_armored(&public_key)
        .map_err(|e| ApiError::internal(format!("Failed to export public key: {}", e)))?;

    // Create MLS client
    let mls_client = MlsClient::new(
        &current_user.username,
        secret_key.clone(),
        public_key.clone(),
        &passphrase,
        state.app_dir.clone(),
    )
    .map_err(|e| ApiError::internal(format!("Failed to create MLS client: {}", e)))?;

    // Create the MLS group locally using server address as identifier
    // This ensures all members use the same group_id for this server
    let group_info = mls_client
        .create_mls_group(&group_address)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to create MLS group: {}", e)))?;

    // Store the MLS group ID (base64 encoded)
    let mls_group_id_b64 = group_info.mls_group_id.clone();
    tracing::info!(
        "Created MLS group for server {} with MLS ID: {}",
        group_address,
        mls_group_id_b64
    );

    // Create timestamp-based signature for authentication
    let timestamp = Utc::now().timestamp();
    let sign_content = format!(
        "register:{}:{}:{}",
        current_user.username, group_address, timestamp
    );
    let signature = PgpSigner::sign_detached_secure(&secret_key, sign_content.as_bytes(), &passphrase)
        .map_err(|e| ApiError::internal(format!("Failed to sign request: {}", e)))?;

    // Register with the group server (without KeyPackage since admin creates the group)
    service
        .register_with_group_server_and_key_package(
            &current_user.username,
            &public_key_armored,
            &signature,
            timestamp,
            &group_address,
            None, // No KeyPackage needed - admin is creating the group
        )
        .await
        .map_err(|e| ApiError::internal(format!("Failed to register with group: {}", e)))?;

    // Generate display name
    let display_name = group_name
        .unwrap_or_else(|| format!("Group {}", &group_address[..8.min(group_address.len())]));

    // Check if group with this address already exists
    let existing_group: Option<(String, String, String, i64, bool, Option<String>)> = sqlx::query_as(
        "SELECT id, name, address, member_count, is_public, description FROM groups WHERE address = ?",
    )
    .bind(&group_address)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to check existing group: {}", e)))?;

    let group = if let Some((id, name, address, member_count, is_public, description)) = existing_group {
        // Group already exists, use existing entry
        tracing::info!("Group {} already exists with id {}", group_address, id);
        GroupDTO {
            id,
            name,
            address,
            member_count: member_count as u32,
            is_public,
            description,
        }
    } else {
        // Create new group entry
        let new_group = GroupDTO {
            id: Uuid::new_v4().to_string(),
            name: display_name.clone(),
            address: group_address.clone(),
            member_count: 1,
            is_public: true,
            description: None,
        };

        // Store in groups table
        sqlx::query(
            r#"
            INSERT INTO groups (id, name, address, member_count, is_public)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(&new_group.id)
        .bind(&new_group.name)
        .bind(&new_group.address)
        .bind(new_group.member_count as i64)
        .bind(new_group.is_public)
        .execute(&state.db)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to store group: {}", e)))?;

        new_group
    };

    // Tables are created by schema::run_migrations() on app startup
    // Store membership with MLS group ID and admin role
    sqlx::query(
        r#"
        INSERT OR REPLACE INTO group_memberships (server_address, username, mls_group_id, role)
        VALUES (?, ?, ?, 'admin')
        "#,
    )
    .bind(&group_address)
    .bind(&current_user.username)
    .bind(&mls_group_id_b64)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to store membership: {}", e)))?;

    tracing::info!(
        "Initialized group {} as admin {} with MLS ID {}",
        group_address,
        current_user.username,
        mls_group_id_b64
    );

    Ok(group)
}

/// Get all joined groups
#[tauri::command]
pub async fn get_joined_groups(state: State<'_, AppState>) -> Result<Vec<GroupDTO>, ApiError> {
    tracing::debug!("Fetching joined groups");

    // Get current user to filter memberships
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    // Only return groups that the current user has actually joined
    // Use DISTINCT to prevent duplicates if any exist in the database
    let groups: Vec<(String, String, String, i64, bool, Option<String>)> = sqlx::query_as(
        r#"
        SELECT DISTINCT g.id, g.name, g.address, g.member_count, g.is_public, g.description
        FROM groups g
        INNER JOIN group_memberships gm ON gm.server_address = g.address AND gm.username = ?
        "#,
    )
    .bind(&current_user.username)
    .fetch_all(&state.db)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let result: Vec<GroupDTO> = groups
        .into_iter()
        .map(
            |(id, name, address, member_count, is_public, description)| GroupDTO {
                id,
                name,
                address,
                member_count: member_count as u32,
                is_public,
                description,
            },
        )
        .collect();

    Ok(result)
}

/// Store MLS group ID for a server address (called after receiving welcome)
#[tauri::command]
pub async fn set_mls_group_id(
    group_address: String,
    mls_group_id: String,
    state: State<'_, AppState>,
) -> Result<(), ApiError> {
    tracing::info!(
        "Setting MLS group ID for {}: {}",
        group_address,
        mls_group_id
    );

    // Get current user to scope the update
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    sqlx::query(
        r#"
        UPDATE group_memberships
        SET mls_group_id = ?
        WHERE server_address = ? AND username = ?
        "#,
    )
    .bind(&mls_group_id)
    .bind(&group_address)
    .bind(&current_user.username)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to update MLS group ID: {}", e)))?;

    Ok(())
}

/// Get pending welcomes that need to be processed
#[tauri::command]
pub async fn get_pending_welcomes(
    state: State<'_, AppState>,
) -> Result<Vec<serde_json::Value>, ApiError> {
    let welcomes = crate::core::db::MlsDb::get_pending_welcomes(&state.db)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let result: Vec<serde_json::Value> = welcomes
        .into_iter()
        .map(|w| {
            serde_json::json!({
                "id": w.id,
                "groupId": w.group_id,
                "sender": w.sender,
                "welcomeBytes": w.welcome_bytes,
                "cipherSuite": w.cipher_suite,
                "epoch": w.epoch,
                "receivedAt": w.received_at
            })
        })
        .collect();

    Ok(result)
}

/// Process a pending welcome message
#[tauri::command]
pub async fn process_welcome(welcome_id: i64, state: State<'_, AppState>) -> Result<(), ApiError> {
    tracing::info!("Processing welcome: {}", welcome_id);

    // Get current user
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    // Get PGP keys
    let (secret_key, public_key, passphrase) = state
        .get_pgp_keys()
        .await
        .ok_or_else(|| ApiError::internal("PGP keys not available"))?;

    // Get pending welcomes and find the one we need
    let welcomes = crate::core::db::MlsDb::get_pending_welcomes(&state.db)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let stored_welcome = welcomes
        .into_iter()
        .find(|w| w.id == welcome_id)
        .ok_or_else(|| ApiError::not_found("Welcome not found or already processed"))?;

    let group_id = stored_welcome.group_id;
    let sender = stored_welcome.sender;
    let welcome_bytes = stored_welcome.welcome_bytes;
    let ratchet_tree = stored_welcome.ratchet_tree;
    let cipher_suite = stored_welcome.cipher_suite;
    let epoch = stored_welcome.epoch;

    // Create MLS client
    let mls_client = MlsClient::new(
        &current_user.username,
        secret_key.clone(),
        public_key.clone(),
        &passphrase,
        state.app_dir.clone(),
    )
    .map_err(|e| ApiError::internal(format!("Failed to create MLS client: {}", e)))?;

    // Decode the welcome bytes from base64 (stored as b64 in DB)
    let welcome_bytes_decoded = base64::engine::general_purpose::STANDARD
        .decode(&welcome_bytes)
        .map_err(|e| ApiError::internal(format!("Failed to decode welcome bytes: {}", e)))?;

    // Decode ratchet tree if present
    let ratchet_tree_decoded = ratchet_tree
        .as_ref()
        .map(|rt| base64::engine::general_purpose::STANDARD.decode(rt))
        .transpose()
        .map_err(|e| ApiError::internal(format!("Failed to decode ratchet tree: {}", e)))?;

    // Create MlsWelcome struct
    let mls_welcome = crate::crypto::mls::MlsWelcome::new(
        &group_id,
        cipher_suite,
        &welcome_bytes_decoded,
        ratchet_tree_decoded.as_deref(),
        epoch,
        &sender,
    );

    // Process the welcome
    let mls_group_id = mls_client
        .process_welcome(&mls_welcome)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to process welcome: {}", e)))?;

    // Mark as processed
    crate::core::db::MlsDb::mark_welcome_processed(&state.db, welcome_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // Find the group server address (try to find by group_id match)
    // This assumes the group_id in the welcome corresponds to a known server
    let server_address: Option<(String,)> =
        sqlx::query_as("SELECT address FROM groups WHERE id = ? OR address LIKE ?")
            .bind(&group_id)
            .bind(format!("%{}%", &group_id[..8.min(group_id.len())]))
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

    if let Some((addr,)) = server_address {
        // Update the MLS group ID in memberships (scoped to current user)
        sqlx::query(
            "UPDATE group_memberships SET mls_group_id = ? WHERE server_address = ? AND username = ?",
        )
        .bind(&mls_group_id)
        .bind(&addr)
        .bind(&current_user.username)
        .execute(&state.db)
        .await
        .ok();
    }

    tracing::info!(
        "Successfully processed welcome for group {} (MLS ID: {}) for user {}",
        group_id,
        mls_group_id,
        current_user.username
    );

    Ok(())
}

/// Approve a pending member to join a group (admin only)
///
/// This command:
/// 1. Sends approval to group server and receives user's KeyPackage in response
/// 2. Adds the user to the local MLS group (generates Welcome + Commit)
/// 3. Stores the Welcome on the server for the user to fetch
/// 4. Buffers the Commit on the server for epoch synchronization
#[tauri::command]
pub async fn approve_member(
    group_address: String,
    member_username: String,
    state: State<'_, AppState>,
) -> Result<(), ApiError> {
    tracing::info!(
        "Approving member {} for group {}",
        member_username,
        group_address
    );

    // Get current user (must be admin)
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    // Get mixnet service
    let service = state
        .get_mixnet_service()
        .await
        .ok_or_else(|| ApiError::not_connected("Not connected to mixnet"))?;

    // Get PGP keys for signing
    let (secret_key, public_key, passphrase) = state
        .get_pgp_keys()
        .await
        .ok_or_else(|| ApiError::internal("PGP keys not available"))?;

    // Sign structured content: "approveGroup:{username}:{group_id}:{timestamp}"
    let timestamp = Utc::now().timestamp();
    let sign_content = format!(
        "approveGroup:{}:{}:{}",
        member_username, group_address, timestamp
    );
    let signature =
        PgpSigner::sign_detached_secure(&secret_key, sign_content.as_bytes(), &passphrase)
            .map_err(|e| ApiError::internal(format!("Failed to sign approval: {}", e)))?;

    // Send approval request to group server
    tracing::info!(
        "Sending approval request for {} to server {}",
        member_username,
        group_address
    );
    service
        .approve_group_member(
            &current_user.username,
            &member_username,
            &signature,
            &group_address,
            timestamp,
        )
        .await
        .map_err(|e| ApiError::internal(format!("Failed to send approval request: {}", e)))?;

    // Take the incoming message receiver to wait for response
    let rx = state.take_incoming_rx().await;
    let rx = rx.ok_or_else(|| ApiError::internal("Message receiver not available"))?;

    // Wait for approveGroupResponse with timeout
    let timeout = std::time::Duration::from_secs(30);
    let result = wait_for_approval_response(
        rx,
        &state,
        &current_user.username,
        &group_address,
        &member_username,
        secret_key,
        public_key,
        passphrase,
        &service,
        timeout,
    )
    .await;

    result
}

/// Wait for the approveGroupResponse and process the KeyPackage
async fn wait_for_approval_response(
    mut rx: tokio::sync::mpsc::Receiver<crate::core::mixnet_client::Incoming>,
    state: &AppState,
    admin_username: &str,
    group_address: &str,
    member_username: &str,
    secret_key: crate::crypto::pgp::ArcSecretKey,
    public_key: crate::crypto::pgp::ArcPublicKey,
    passphrase: crate::crypto::pgp::ArcPassphrase,
    service: &std::sync::Arc<crate::core::mixnet_client::MixnetService>,
    timeout: std::time::Duration,
) -> Result<(), ApiError> {
    use tokio::time::timeout as tokio_timeout;

    let start = std::time::Instant::now();

    loop {
        if start.elapsed() >= timeout {
            // Put the receiver back before returning error
            *state.incoming_rx.write().await = Some(rx);
            return Err(ApiError::internal(
                "Timeout waiting for approveGroupResponse",
            ));
        }

        let remaining = timeout - start.elapsed();
        let recv_result = tokio_timeout(remaining, rx.recv()).await;

        match recv_result {
            Ok(Some(incoming)) => {
                if incoming.envelope.action == "approveGroupResponse" {
                    // Parse the response to get the KeyPackage
                    let content = incoming
                        .envelope
                        .payload
                        .get("content")
                        .and_then(|v| v.as_str());

                    if let Some(content) = content {
                        // Try to parse as JSON
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(content) {
                            // Check for success status
                            if parsed.get("status").and_then(|v| v.as_str()) == Some("success") {
                                // Get the KeyPackage if present
                                if let Some(key_package_b64) =
                                    parsed.get("keyPackage").and_then(|v| v.as_str())
                                {
                                    tracing::info!(
                                        "Received KeyPackage for {}",
                                        member_username
                                    );

                                    // Process the KeyPackage and add member to MLS group
                                    let result = process_key_package_and_add_member(
                                        state,
                                        admin_username,
                                        group_address,
                                        member_username,
                                        key_package_b64,
                                        &secret_key,
                                        &public_key,
                                        &passphrase,
                                        service,
                                    )
                                    .await;

                                    // Put the receiver back
                                    *state.incoming_rx.write().await = Some(rx);
                                    return result;
                                } else {
                                    // No KeyPackage in response
                                    tracing::info!(
                                        "User {} was approved but no KeyPackage available",
                                        member_username
                                    );
                                    *state.incoming_rx.write().await = Some(rx);
                                    return Ok(());
                                }
                            } else if let Some(error) = parsed
                                .get("error")
                                .or(parsed.get("status"))
                                .and_then(|v| v.as_str())
                            {
                                *state.incoming_rx.write().await = Some(rx);
                                return Err(ApiError::internal(format!(
                                    "Approval failed: {}",
                                    error
                                )));
                            }
                        } else if content == "success" {
                            // Legacy response without KeyPackage
                            tracing::info!(
                                "Approved {} (legacy response, no KeyPackage)",
                                member_username
                            );
                            *state.incoming_rx.write().await = Some(rx);
                            return Ok(());
                        }
                    }

                    // Default: put receiver back and return success
                    tracing::info!(
                        "Received approveGroupResponse: {:?}",
                        incoming.envelope.payload
                    );
                    *state.incoming_rx.write().await = Some(rx);
                    return Ok(());
                }
                // Not the message we're waiting for, continue
            }
            Ok(None) => {
                // Channel closed
                return Err(ApiError::internal("Message channel closed"));
            }
            Err(_) => {
                // Timeout on this recv, continue loop (will check overall timeout)
            }
        }
    }
}

/// Get pending join requests for a group (admin only)
///
/// This command:
/// 1. Sends a query to the group server for pending users
/// 2. Waits for queryPendingUsersResponse with a timeout
/// 3. Returns the list of pending usernames
#[tauri::command]
pub async fn get_pending_join_requests(
    group_address: String,
    state: State<'_, AppState>,
) -> Result<Vec<String>, ApiError> {
    tracing::info!(
        "Getting pending join requests for group {}",
        group_address
    );

    // Get current user (must be admin)
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    // Get mixnet service
    let service = state
        .get_mixnet_service()
        .await
        .ok_or_else(|| ApiError::not_connected("Not connected to mixnet"))?;

    // Get PGP keys for signing
    let (secret_key, passphrase) = state
        .get_pgp_signing_keys()
        .await
        .ok_or_else(|| ApiError::internal("PGP keys not available"))?;

    // Sign the query request: "queryPendingUsers"
    let sign_content = "queryPendingUsers";
    let signature = PgpSigner::sign_detached_secure(&secret_key, sign_content.as_bytes(), &passphrase)
        .map_err(|e| ApiError::internal(format!("Failed to sign request: {}", e)))?;

    // Send query request to group server
    tracing::info!(
        "Sending queryPendingUsers request to server {}",
        group_address
    );
    service
        .query_pending_users(
            &current_user.username,
            &signature,
            &group_address,
        )
        .await
        .map_err(|e| ApiError::internal(format!("Failed to send query request: {}", e)))?;

    // Take the incoming message receiver to wait for response
    let rx = state.take_incoming_rx().await;
    let rx = rx.ok_or_else(|| ApiError::internal("Message receiver not available"))?;

    // Wait for queryPendingUsersResponse with timeout
    let timeout = std::time::Duration::from_secs(30);
    let result = wait_for_pending_users_response(rx, &state, timeout).await;

    result
}

/// Wait for the queryPendingUsersResponse
async fn wait_for_pending_users_response(
    mut rx: tokio::sync::mpsc::Receiver<crate::core::mixnet_client::Incoming>,
    state: &AppState,
    timeout: std::time::Duration,
) -> Result<Vec<String>, ApiError> {
    use tokio::time::timeout as tokio_timeout;

    let start = std::time::Instant::now();

    loop {
        if start.elapsed() >= timeout {
            // Put the receiver back before returning error
            *state.incoming_rx.write().await = Some(rx);
            return Err(ApiError::internal(
                "Timeout waiting for queryPendingUsersResponse",
            ));
        }

        let remaining = timeout - start.elapsed();
        let recv_result = tokio_timeout(remaining, rx.recv()).await;

        match recv_result {
            Ok(Some(incoming)) => {
                if incoming.envelope.action == "queryPendingUsersResponse" {
                    // Parse the response to get the pending users list
                    let content = incoming
                        .envelope
                        .payload
                        .get("content")
                        .and_then(|v| v.as_str());

                    if let Some(content) = content {
                        // Try to parse as JSON
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(content) {
                            // Check for success status
                            if parsed.get("status").and_then(|v| v.as_str()) == Some("success") {
                                // Get the pending users list
                                let pending_users = parsed
                                    .get("pendingUsers")
                                    .and_then(|v| v.as_array())
                                    .map(|arr| {
                                        arr.iter()
                                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                            .collect::<Vec<String>>()
                                    })
                                    .unwrap_or_default();

                                tracing::info!(
                                    "Received {} pending users",
                                    pending_users.len()
                                );
                                *state.incoming_rx.write().await = Some(rx);
                                return Ok(pending_users);
                            } else if let Some(error) = parsed
                                .get("error")
                                .or(parsed.get("status"))
                                .and_then(|v| v.as_str())
                            {
                                *state.incoming_rx.write().await = Some(rx);
                                return Err(ApiError::internal(format!(
                                    "Query failed: {}",
                                    error
                                )));
                            }
                        } else {
                            // Try parsing content directly as array
                            if let Ok(users) = serde_json::from_str::<Vec<String>>(content) {
                                tracing::info!("Received {} pending users (array format)", users.len());
                                *state.incoming_rx.write().await = Some(rx);
                                return Ok(users);
                            }
                        }
                    }

                    // Also try direct payload parsing
                    if let Some(pending_users) = incoming
                        .envelope
                        .payload
                        .get("pendingUsers")
                        .and_then(|v| v.as_array())
                    {
                        let users: Vec<String> = pending_users
                            .iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect();
                        tracing::info!("Received {} pending users (direct payload)", users.len());
                        *state.incoming_rx.write().await = Some(rx);
                        return Ok(users);
                    }

                    // Default: empty list
                    tracing::info!(
                        "Received queryPendingUsersResponse: {:?}",
                        incoming.envelope.payload
                    );
                    *state.incoming_rx.write().await = Some(rx);
                    return Ok(Vec::new());
                }
                // Not the message we're waiting for, continue
            }
            Ok(None) => {
                // Channel closed
                return Err(ApiError::internal("Message channel closed"));
            }
            Err(_) => {
                // Timeout on this recv, continue loop (will check overall timeout)
            }
        }
    }
}

/// Process the received KeyPackage and add member to the MLS group
async fn process_key_package_and_add_member(
    state: &AppState,
    admin_username: &str,
    group_address: &str,
    member_username: &str,
    key_package_b64: &str,
    secret_key: &crate::crypto::pgp::ArcSecretKey,
    public_key: &crate::crypto::pgp::ArcPublicKey,
    passphrase: &crate::crypto::pgp::ArcPassphrase,
    service: &std::sync::Arc<crate::core::mixnet_client::MixnetService>,
) -> Result<(), ApiError> {
    // Decode the KeyPackage
    let key_package_bytes = base64::engine::general_purpose::STANDARD
        .decode(key_package_b64)
        .map_err(|e| ApiError::internal(format!("Failed to decode KeyPackage: {}", e)))?;

    // Get the MLS group ID from the database (scoped to admin user)
    let mls_group_id: Option<(String,)> =
        sqlx::query_as("SELECT mls_group_id FROM group_memberships WHERE server_address = ? AND username = ?")
            .bind(group_address)
            .bind(admin_username)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| ApiError::internal(format!("Failed to query MLS group: {}", e)))?;

    let mls_group_id = mls_group_id
        .and_then(|(id,)| if id.is_empty() { None } else { Some(id) })
        .ok_or_else(|| {
            ApiError::internal(format!(
                "MLS group not found for server {}. Did you run 'init_group' first?",
                group_address
            ))
        })?;

    // Create MLS client and add member
    let mls_client = MlsClient::new(
        admin_username,
        secret_key.clone(),
        public_key.clone(),
        passphrase,
        state.app_dir.clone(),
    )
    .map_err(|e| ApiError::internal(format!("Failed to create MLS client: {}", e)))?;

    let add_result = mls_client
        .add_member_to_group(&mls_group_id, &key_package_bytes)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to add member to MLS group: {}", e)))?;

    tracing::info!(
        "Generated Welcome for {} at epoch {}",
        member_username,
        add_result.new_epoch
    );

    // Encode the Welcome bytes as base64 for transport
    let welcome_b64 =
        base64::engine::general_purpose::STANDARD.encode(&add_result.welcome.welcome_bytes);

    // Sign the store welcome request: "groupId:targetUsername"
    let sign_content = format!("{}:{}", group_address, member_username);
    let welcome_sig = PgpSigner::sign_detached_secure(secret_key, sign_content.as_bytes(), passphrase)
        .map_err(|e| ApiError::internal(format!("Failed to sign welcome: {}", e)))?;

    // Store the Welcome on the server for the user to fetch
    service
        .store_welcome_on_server(
            admin_username,
            group_address, // group_id is the server address
            member_username,
            &welcome_b64,
            &welcome_sig,
            group_address,
        )
        .await
        .map_err(|e| ApiError::internal(format!("Failed to store welcome on server: {}", e)))?;

    tracing::info!("Stored Welcome on server for {}", member_username);

    // Buffer the Commit on the server for existing members to sync
    // Sign: "groupId:epoch"
    let commit_sign_content = format!("{}:{}", mls_group_id, add_result.new_epoch);
    let commit_sig =
        PgpSigner::sign_detached_secure(secret_key, commit_sign_content.as_bytes(), passphrase)
            .map_err(|e| ApiError::internal(format!("Failed to sign commit: {}", e)))?;

    // Encode commit bytes as base64
    let commit_b64 = base64::engine::general_purpose::STANDARD.encode(&add_result.commit_bytes);

    service
        .buffer_commit_on_server(
            admin_username,
            &mls_group_id,
            add_result.new_epoch as i64,
            &commit_b64,
            &commit_sig,
            group_address,
        )
        .await
        .map_err(|e| ApiError::internal(format!("Failed to buffer commit on server: {}", e)))?;

    tracing::info!(
        "Buffered Commit on server for epoch {}",
        add_result.new_epoch
    );

    // Wait for mixnet to transmit the messages
    tracing::info!("Waiting for mixnet to transmit Welcome and Commit...");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    tracing::info!(
        "Approved {} and stored Welcome on server",
        member_username
    );

    Ok(())
}

// ============================================================================
// Group Member Management Commands
// ============================================================================

/// DTO for group member information
#[derive(Debug, Clone, serde::Serialize)]
pub struct GroupMemberDTO {
    pub username: String,
    pub role: String,
    pub joined_at: String,
    pub credential_verified: bool,
}

/// Get all members of a group
#[tauri::command]
pub async fn get_group_members(
    group_address: String,
    state: State<'_, AppState>,
) -> Result<Vec<GroupMemberDTO>, ApiError> {
    tracing::debug!("Getting members for group: {}", group_address);

    // Get current user
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    // Get the MLS group ID for this server address
    let mls_group_id: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT mls_group_id FROM group_memberships WHERE server_address = ? AND username = ?",
    )
    .bind(&group_address)
    .bind(&current_user.username)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to query group membership: {}", e)))?;

    let conversation_id = match mls_group_id {
        Some((Some(id),)) if !id.is_empty() => id,
        _ => {
            // Fall back to using group_address as conversation_id
            group_address.clone()
        }
    };

    // Query group members from the database
    let rows: Vec<(String, String, String, bool)> = sqlx::query_as(
        r#"
        SELECT member_username, role, joined_at, credential_verified
        FROM group_members
        WHERE conversation_id = ?
        ORDER BY
            CASE WHEN role = 'admin' THEN 0 ELSE 1 END,
            joined_at ASC
        "#,
    )
    .bind(&conversation_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch group members: {}", e)))?;

    let members: Vec<GroupMemberDTO> = rows
        .into_iter()
        .map(|(username, role, joined_at, credential_verified)| GroupMemberDTO {
            username,
            role,
            joined_at,
            credential_verified,
        })
        .collect();

    tracing::debug!("Found {} members for group {}", members.len(), group_address);
    Ok(members)
}

/// Get the current user's role in a group (admin/member/none)
#[tauri::command]
pub async fn get_current_user_role(
    group_address: String,
    state: State<'_, AppState>,
) -> Result<Option<String>, ApiError> {
    tracing::debug!("Getting current user role for group: {}", group_address);

    // Get current user
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    // First check group_memberships table (per-user scoped)
    let membership_role: Option<(String,)> = sqlx::query_as(
        "SELECT role FROM group_memberships WHERE server_address = ? AND username = ?",
    )
    .bind(&group_address)
    .bind(&current_user.username)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to query membership: {}", e)))?;

    if let Some((role,)) = membership_role {
        tracing::debug!(
            "User {} has role '{}' in group {}",
            current_user.username,
            role,
            group_address
        );
        return Ok(Some(role));
    }

    // Also check group_members table via MLS group ID
    let mls_group_id: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT mls_group_id FROM group_memberships WHERE server_address = ? AND username = ?",
    )
    .bind(&group_address)
    .bind(&current_user.username)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to query MLS group: {}", e)))?;

    if let Some((Some(mls_id),)) = mls_group_id {
        let member_role: Option<(String,)> = sqlx::query_as(
            "SELECT role FROM group_members WHERE conversation_id = ? AND member_username = ?",
        )
        .bind(&mls_id)
        .bind(&current_user.username)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to query member role: {}", e)))?;

        if let Some((role,)) = member_role {
            return Ok(Some(role));
        }
    }

    tracing::debug!(
        "User {} is not a member of group {}",
        current_user.username,
        group_address
    );
    Ok(None)
}
