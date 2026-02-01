//! Message receive loop task
//!
//! This module handles the continuous processing of incoming mixnet messages.
//! It receives messages from the mixnet client, routes them to appropriate handlers,
//! and emits events to the frontend for real-time updates.

use std::sync::Arc;

use tauri::AppHandle;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use base64::Engine;

use crate::core::db::{BufferedMessage, Db};
use crate::core::message_handler::{DirectMessageHandlerBuilder, WelcomeFlowHandler};
use crate::core::message_router::{MessageRoute, MessageRouter};
use crate::core::mixnet_client::Incoming;
use crate::crypto::mls::{MlsClient, MlsMessageType};
use crate::events::{AppEvent, EventEmitter};
use crate::state::{AppState, QueryResult};
use crate::types::{MessageDTO, MessageStatus};

/// Start the message receive loop
///
/// This spawns a background task that:
/// - Receives messages from the mixnet
/// - Routes them using MessageRouter
/// - Handles each message type appropriately
/// - Emits events to the frontend for real-time updates
pub fn start_message_receive_loop(
    app_handle: AppHandle,
    state: Arc<AppState>,
    mut rx: mpsc::Receiver<Incoming>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!("Message receive loop started");
        let emitter = EventEmitter::new(app_handle.clone());

        while let Some(incoming) = rx.recv().await {
            // Route the message to determine handling
            let route = MessageRouter::route_message(&incoming);
            let description = MessageRouter::route_description(&route);

            tracing::debug!(
                "Received message: action={}, route={}",
                incoming.envelope.action,
                description
            );

            // Process based on route
            if let Err(e) = process_message(&emitter, &state, &incoming, route).await {
                tracing::error!(
                    "Error processing message (action={}): {}",
                    incoming.envelope.action,
                    e
                );
            }
        }

        tracing::info!("Message receive loop ended");
    })
}

/// Process a single incoming message based on its route
async fn process_message(
    emitter: &EventEmitter,
    state: &Arc<AppState>,
    incoming: &Incoming,
    route: MessageRoute,
) -> anyhow::Result<()> {
    match route {
        MessageRoute::Authentication => {
            // Authentication messages are handled by the auth command flow
            // They are consumed during register_user and login_user
            tracing::debug!(
                "Authentication message received (action={}), should be handled by auth flow",
                incoming.envelope.action
            );
        }

        MessageRoute::Query => {
            // Handle query responses by resolving pending queries
            handle_query_response(state, incoming).await?;
        }

        MessageRoute::MlsProtocol => {
            handle_mls_message(emitter, state, incoming).await?;
        }

        MessageRoute::Chat => {
            // All chat messages go through MLS now
            handle_mls_message(emitter, state, incoming).await?;
        }

        MessageRoute::Handshake => {
            handle_handshake_message(emitter, state, incoming).await?;
        }

        MessageRoute::Group => {
            handle_group_message(emitter, state, incoming).await?;
        }

        MessageRoute::WelcomeFlow => {
            handle_welcome_flow_message(emitter, state, incoming).await?;
        }

        MessageRoute::PendingDelivery => {
            handle_pending_delivery(emitter, state, incoming).await?;
        }

        MessageRoute::Unknown => {
            tracing::warn!(
                "Unknown message type received: action={}",
                incoming.envelope.action
            );
        }
    }

    Ok(())
}

/// Handle query responses from the discovery server
async fn handle_query_response(
    state: &Arc<AppState>,
    incoming: &Incoming,
) -> anyhow::Result<()> {
    let payload = &incoming.envelope.payload;

    // Extract username and public key from response
    let username = payload.get("username").and_then(|v| v.as_str());
    let public_key = payload.get("publicKey").and_then(|v| v.as_str());

    if let (Some(username), Some(public_key)) = (username, public_key) {
        tracing::info!("Received query response for user: {}", username);

        let result = QueryResult {
            username: username.to_string(),
            public_key: public_key.to_string(),
        };

        // Resolve the pending query
        state.resolve_pending_query(username, Some(result)).await;
    } else {
        // User not found - the payload might contain the queried username
        // Try to extract from different field names
        let queried_username = payload.get("identifier")
            .or_else(|| payload.get("username"))
            .and_then(|v| v.as_str());

        if let Some(username) = queried_username {
            tracing::info!("User not found: {}", username);
            state.resolve_pending_query(username, None).await;
        } else {
            tracing::warn!("Query response received but couldn't determine username");
        }
    }

    Ok(())
}

/// Handle MLS protocol messages (key packages, welcomes, encrypted messages)
async fn handle_mls_message(
    emitter: &EventEmitter,
    state: &Arc<AppState>,
    incoming: &Incoming,
) -> anyhow::Result<()> {
    let action = incoming.envelope.action.as_str();
    let sender = &incoming.envelope.sender;
    let payload = &incoming.envelope.payload;

    match action {
        "keyPackageRequest" => {
            // Someone wants to establish a conversation with us
            tracing::info!("Received key package request from {}", sender);

            // Get required state
            let current_user = state.get_current_user().await
                .ok_or_else(|| anyhow::anyhow!("No user logged in"))?;
            let mls_client = state.get_mls_client().await
                .ok_or_else(|| anyhow::anyhow!("MLS client not initialized"))?;
            let mixnet_service = state.get_mixnet_service().await
                .ok_or_else(|| anyhow::anyhow!("Mixnet not connected"))?;
            let (pgp_secret_key, pgp_passphrase) = state.get_pgp_signing_keys().await
                .ok_or_else(|| anyhow::anyhow!("PGP keys not available"))?;

            // Create direct message handler
            let handler = DirectMessageHandlerBuilder::new()
                .mls_client(mls_client)
                .mixnet_service(mixnet_service)
                .pgp_keys(pgp_secret_key, pgp_passphrase)
                .current_user(current_user.username.clone())
                .build()?;

            // Get their key package from payload
            let their_key_package = payload
                .get("senderKeyPackage")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing senderKeyPackage in request"))?;

            // Respond with our key package
            handler.respond_to_key_package_request(sender, their_key_package).await?;

            tracing::info!("Sent key package response to {}", sender);

            // Notify the UI that someone wants to establish a conversation
            emitter.conversation_request_received(
                sender.clone(),
                incoming.ts.to_rfc3339(),
            );
            tracing::info!("Emitted ConversationRequestReceived event for {}", sender);
        }

        "keyPackageResponse" => {
            // Received key package from someone we requested
            tracing::info!("Received key package response from {}", sender);

            let current_user = state.get_current_user().await
                .ok_or_else(|| anyhow::anyhow!("No user logged in"))?;
            let mls_client = state.get_mls_client().await
                .ok_or_else(|| anyhow::anyhow!("MLS client not initialized"))?;
            let mixnet_service = state.get_mixnet_service().await
                .ok_or_else(|| anyhow::anyhow!("Mixnet not connected"))?;
            let (pgp_secret_key, pgp_passphrase) = state.get_pgp_signing_keys().await
                .ok_or_else(|| anyhow::anyhow!("PGP keys not available"))?;

            let handler = DirectMessageHandlerBuilder::new()
                .mls_client(mls_client)
                .mixnet_service(mixnet_service)
                .pgp_keys(pgp_secret_key, pgp_passphrase)
                .current_user(current_user.username.clone())
                .build()?;

            // Get their key package
            let recipient_key_package = payload
                .get("senderKeyPackage")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing senderKeyPackage in response"))?;

            // Complete the handshake (establish conversation and send welcome)
            handler.complete_handshake(sender, recipient_key_package).await?;

            tracing::info!("MLS handshake completed with {}", sender);
        }

        "p2pWelcome" => {
            // Received P2P welcome to join a 1:1 conversation
            tracing::info!("Received P2P welcome from {}", sender);

            let current_user = state.get_current_user().await
                .ok_or_else(|| anyhow::anyhow!("No user logged in"))?;
            let mls_client = state.get_mls_client().await
                .ok_or_else(|| anyhow::anyhow!("MLS client not initialized"))?;
            let mixnet_service = state.get_mixnet_service().await
                .ok_or_else(|| anyhow::anyhow!("Mixnet not connected"))?;
            let (pgp_secret_key, pgp_passphrase) = state.get_pgp_signing_keys().await
                .ok_or_else(|| anyhow::anyhow!("PGP keys not available"))?;

            let handler = DirectMessageHandlerBuilder::new()
                .mls_client(mls_client)
                .mixnet_service(mixnet_service)
                .pgp_keys(pgp_secret_key, pgp_passphrase)
                .current_user(current_user.username.clone())
                .build()?;

            // Get welcome message from payload
            let welcome_message = payload
                .get("welcomeMessage")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing welcomeMessage in payload"))?;

            // Join the conversation
            handler.process_incoming_message(sender, welcome_message, MlsMessageType::Welcome).await?;

            tracing::info!("Joined conversation with {}", sender);
        }

        "send" | "incomingMessage" => {
            // Encrypted message received
            handle_encrypted_message(emitter, state, incoming).await?;
        }

        _ => {
            tracing::debug!("Unhandled MLS action: {}", action);
        }
    }

    Ok(())
}

/// Handle encrypted incoming messages
async fn handle_encrypted_message(
    emitter: &EventEmitter,
    state: &Arc<AppState>,
    incoming: &Incoming,
) -> anyhow::Result<()> {
    let sender = &incoming.envelope.sender;
    let payload = &incoming.envelope.payload;

    let current_user = state.get_current_user().await
        .ok_or_else(|| anyhow::anyhow!("No user logged in"))?;
    let mls_client = state.get_mls_client().await
        .ok_or_else(|| anyhow::anyhow!("MLS client not initialized"))?;
    let mixnet_service = state.get_mixnet_service().await
        .ok_or_else(|| anyhow::anyhow!("Mixnet not connected"))?;
    let (pgp_secret_key, pgp_passphrase) = state.get_pgp_signing_keys().await
        .ok_or_else(|| anyhow::anyhow!("PGP keys not available"))?;

    let handler = DirectMessageHandlerBuilder::new()
        .mls_client(mls_client)
        .mixnet_service(mixnet_service)
        .pgp_keys(pgp_secret_key, pgp_passphrase)
        .current_user(current_user.username.clone())
        .build()?;

    // Get the MLS message from payload
    let mls_message = payload
        .get("mls_message")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing mls_message in payload"))?;

    let _conversation_id_b64 = payload
        .get("conversation_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Try to decrypt the message
    match handler.process_incoming_message(sender, mls_message, MlsMessageType::Application).await {
        Ok(Some(content)) => {
            tracing::info!("Decrypted message from {}", sender);

            // Create message DTO
            let conversation_id = handler.get_conversation_id(sender);
            let message = MessageDTO {
                id: uuid::Uuid::new_v4().to_string(),
                sender: sender.clone(),
                content,
                timestamp: incoming.ts.to_rfc3339(),
                status: MessageStatus::Delivered,
                is_own: false,
            };

            // Store in database
            Db::save_message(&state.db, &conversation_id, &message).await?;

            // Emit event to frontend
            emitter.message_received(message, conversation_id);
        }
        Ok(None) => {
            // Message was a commit or other non-application message
            tracing::debug!("Processed non-application MLS message from {}", sender);
        }
        Err(e) => {
            // Check if this is an epoch mismatch - buffer for later
            let error_msg = e.to_string();
            if error_msg.contains("epoch") || error_msg.contains("Epoch") {
                tracing::info!("Message from {} has epoch mismatch, buffering", sender);

                let conversation_id = handler.get_conversation_id(sender);
                let buffered = BufferedMessage {
                    id: 0,
                    conversation_id: conversation_id.clone(),
                    sender: sender.clone(),
                    mls_message_b64: mls_message.to_string(),
                    received_at: incoming.ts.to_rfc3339(),
                    retry_count: 0,
                    last_retry_at: None,
                    status: "pending".to_string(),
                    error_message: Some(error_msg),
                };

                Db::buffer_message(&state.db, &buffered).await?;
            } else {
                return Err(e);
            }
        }
    }

    Ok(())
}

/// Handle handshake messages for P2P discovery
async fn handle_handshake_message(
    _emitter: &EventEmitter,
    _state: &Arc<AppState>,
    incoming: &Incoming,
) -> anyhow::Result<()> {
    tracing::info!("Received handshake message from {}", incoming.envelope.sender);
    // Handshake handling can be extended as needed
    Ok(())
}

/// Handle group server response messages
async fn handle_group_message(
    emitter: &EventEmitter,
    state: &Arc<AppState>,
    incoming: &Incoming,
) -> anyhow::Result<()> {
    let action = incoming.envelope.action.as_str();
    let payload = &incoming.envelope.payload;

    match action {
        "fetchGroupResponse" => {
            tracing::info!("Received group fetch response");

            // Extract the server address from the sender field
            let server_address = &incoming.envelope.sender;

            // Extract messages from payload
            let content = payload
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("{}");

            if content.starts_with("error:") {
                tracing::error!("Group fetch failed: {}", content);
                return Ok(());
            }

            // Parse the content
            if let Ok(content_json) = serde_json::from_str::<serde_json::Value>(content) {
                if let Some(messages) = content_json.get("messages").and_then(|v| v.as_array()) {
                    tracing::info!("Received {} messages from group server", messages.len());

                    // Find the maximum message ID for cursor update
                    let max_message_id = messages
                        .iter()
                        .filter_map(|msg| msg.get("id").and_then(|v| v.as_i64()))
                        .max();

                    // Update cursor if we received messages
                    if let Some(max_id) = max_message_id {
                        // Update the cursor in the database
                        if let Err(e) = sqlx::query(
                            r#"
                            INSERT OR REPLACE INTO group_cursors (server_address, last_message_id, updated_at)
                            VALUES (?, ?, datetime('now'))
                            "#,
                        )
                        .bind(server_address)
                        .bind(max_id)
                        .execute(&state.db)
                        .await
                        {
                            tracing::warn!("Failed to update group cursor: {}", e);
                        } else {
                            tracing::debug!(
                                "Updated group cursor for {} to {}",
                                server_address,
                                max_id
                            );
                        }
                    }

                    // Messages need to be decrypted with MLS - this requires group context
                    // For now, emit a raw event and let the command layer handle decryption
                    emitter.emit(AppEvent::GroupMessagesReceived {
                        count: messages.len() as u32,
                    });
                }
            }
        }

        "sendGroupResponse" => {
            let content = payload
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("sent");
            tracing::info!("Group message send response: {}", content);
        }

        "registerResponse" => {
            let content = payload
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            tracing::info!("Group registration response: {}", content);

            if content == "pending" {
                emitter.emit(AppEvent::GroupRegistrationPending);
            } else if content.starts_with("error:") {
                emitter.emit(AppEvent::GroupRegistrationFailed {
                    error: content.to_string(),
                });
            } else {
                emitter.emit(AppEvent::GroupRegistrationSuccess);
            }
        }

        "approveGroupResponse" => {
            let content = payload
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("approved");
            tracing::info!("Group approval response: {}", content);
        }

        "syncEpochResponse" => {
            tracing::info!("Received epoch sync response");

            let content = payload
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("{}");

            if content.starts_with("error:") {
                tracing::warn!("Epoch sync failed: {}", content);
                return Ok(());
            }

            // Parse the sync response
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(content) {
                let current_epoch = parsed.get("currentEpoch").and_then(|v| v.as_i64());
                let group_id = parsed.get("groupId").and_then(|v| v.as_str());

                if let Some(epoch) = current_epoch {
                    tracing::info!("Server current epoch: {}", epoch);
                }

                // Process any buffered commits
                if let Some(commits) = parsed.get("commits").and_then(|v| v.as_array()) {
                    if commits.is_empty() {
                        tracing::debug!("No commits to process in epoch sync");
                        return Ok(());
                    }

                    tracing::info!("Processing {} buffered commits for epoch catch-up", commits.len());

                    // Get MLS client to process commits
                    let current_user = match state.get_current_user().await {
                        Some(u) => u,
                        None => {
                            tracing::warn!("Cannot process epoch sync: no user logged in");
                            return Ok(());
                        }
                    };

                    let (secret_key, public_key, passphrase) = match state.get_pgp_keys().await {
                        Some(keys) => keys,
                        None => {
                            tracing::warn!("Cannot process epoch sync: PGP keys not available");
                            return Ok(());
                        }
                    };

                    let mls_client = match MlsClient::new(
                        &current_user.username,
                        secret_key,
                        public_key,
                        &passphrase,
                        state.app_dir.clone(),
                    ) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!("Cannot process epoch sync: failed to create MLS client: {}", e);
                            return Ok(());
                        }
                    };

                    // Use the group_id from the response
                    let mls_group_id = match group_id {
                        Some(id) => id.to_string(),
                        None => {
                            tracing::warn!("Cannot process epoch sync: no group ID in response");
                            return Ok(());
                        }
                    };

                    // Process each commit in order
                    for commit_obj in commits {
                        let commit_epoch = commit_obj.get("epoch").and_then(|v| v.as_i64());
                        let commit_b64 = commit_obj.get("commit").and_then(|v| v.as_str());

                        if let (Some(epoch), Some(commit_data)) = (commit_epoch, commit_b64) {
                            tracing::debug!("Processing commit for epoch {}", epoch);

                            match base64::engine::general_purpose::STANDARD.decode(commit_data) {
                                Ok(commit_bytes) => {
                                    match mls_client.process_commit(&mls_group_id, &commit_bytes) {
                                        Ok(new_epoch) => {
                                            tracing::info!(
                                                "Advanced to epoch {} after processing commit",
                                                new_epoch
                                            );
                                        }
                                        Err(e) => {
                                            // This might happen if we already processed this commit
                                            tracing::debug!(
                                                "Failed to process commit for epoch {}: {} (may already be processed)",
                                                epoch,
                                                e
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("Failed to decode commit base64: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }

        _ => {
            tracing::debug!("Unhandled group action: {}", action);
        }
    }

    Ok(())
}

/// Handle Welcome flow messages (invites, welcomes, join requests)
///
/// Uses the shared MLS client from AppState to ensure conversation state
/// persists across messages. When a Welcome is successfully processed,
/// emits a GroupJoined event to the frontend.
async fn handle_welcome_flow_message(
    emitter: &EventEmitter,
    state: &Arc<AppState>,
    incoming: &Incoming,
) -> anyhow::Result<()> {
    let current_user = state.get_current_user().await;
    let mixnet_service = state.get_mixnet_service().await;
    let pgp_keys = state.get_pgp_keys().await;
    let mls_client = state.get_mls_client().await;

    // Create welcome flow handler with shared MLS client
    // The MLS client is obtained from AppState to ensure state persists across messages
    let mut handler = WelcomeFlowHandler::new(
        state.db.clone(),
        mixnet_service.unwrap_or_else(|| panic!("Mixnet service not available")),
        current_user.as_ref().map(|u| u.username.clone()),
        pgp_keys.as_ref().map(|(sk, _, _)| sk.clone()),
        pgp_keys.as_ref().map(|(_, pk, _)| pk.clone()),
        pgp_keys.as_ref().map(|(_, _, pp)| pp.clone()),
        mls_client, // Shared MLS client maintains conversation state
    );

    // Process the message
    let result = handler.handle_welcome_flow_message(&incoming.envelope).await?;

    // Emit events for any notifications
    for (sender, notification) in result.notifications {
        if sender == "SYSTEM" {
            emitter.emit(AppEvent::SystemNotification {
                message: notification,
            });
        }
    }

    // If a Welcome was successfully processed, emit the GroupJoined event
    if let Some(welcome_result) = result.welcome_processed {
        emitter.group_joined(
            welcome_result.group_id,
            welcome_result.mls_group_id,
            welcome_result.sender,
        );
        tracing::info!("Emitted GroupJoined event for automatic Welcome processing");
    }

    Ok(())
}

/// Handle pending message delivery (offline queue)
///
/// Processes messages that were queued on the server while we were offline.
/// Each message is re-processed as if it just arrived fresh from the mixnet.
async fn handle_pending_delivery(
    emitter: &EventEmitter,
    state: &Arc<AppState>,
    incoming: &Incoming,
) -> anyhow::Result<()> {
    let payload = &incoming.envelope.payload;

    // Check for error status
    let status = payload.get("status").and_then(|v| v.as_str());
    if status == Some("error") {
        let error_msg = payload.get("message").and_then(|v| v.as_str()).unwrap_or("unknown");
        tracing::warn!("fetchPending error: {}", error_msg);
        return Ok(());
    }

    // Get the messages array
    let messages = match payload.get("messages").and_then(|v| v.as_array()) {
        Some(msgs) => msgs,
        None => {
            tracing::debug!("No pending messages in response");
            return Ok(());
        }
    };

    let count = payload.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
    tracing::info!("Processing {} pending messages from offline queue", count);

    // Process each queued message
    for msg in messages {
        let sender = msg.get("sender").and_then(|v| v.as_str()).unwrap_or("unknown");
        let action = msg.get("action").and_then(|v| v.as_str()).unwrap_or("send");
        let msg_payload = msg.get("payload").cloned().unwrap_or_else(|| serde_json::json!({}));
        let timestamp = msg.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);

        tracing::debug!(
            "Processing queued message from {} (action={}, ts={})",
            sender, action, timestamp
        );

        // Create a synthetic incoming message to process
        let synthetic_envelope = crate::core::messages::MixnetMessage {
            message_type: "message".to_string(),
            action: action.to_string(),
            sender: sender.to_string(),
            recipient: state.get_current_user().await
                .map(|u| u.username.clone())
                .unwrap_or_default(),
            payload: msg_payload,
            signature: "from_queue".to_string(),
            timestamp: chrono::DateTime::from_timestamp(timestamp, 0)
                .unwrap_or_else(chrono::Utc::now)
                .to_rfc3339(),
        };

        let synthetic_incoming = Incoming {
            envelope: synthetic_envelope,
            ts: chrono::DateTime::from_timestamp(timestamp, 0)
                .unwrap_or_else(chrono::Utc::now),
        };

        // Route and process the synthetic message
        let route = MessageRouter::route_message(&synthetic_incoming);

        // Skip PendingDelivery routes to prevent recursion - pending messages
        // can never contain more fetchPendingResponse messages
        if matches!(route, MessageRoute::PendingDelivery) {
            tracing::warn!("Skipping invalid fetchPendingResponse in pending queue");
            continue;
        }

        // Use Box::pin to break the async recursion cycle
        let result = Box::pin(process_message(emitter, state, &synthetic_incoming, route)).await;
        if let Err(e) = result {
            tracing::error!(
                "Error processing queued message from {} (action={}): {}",
                sender, action, e
            );
        }
    }

    if count > 0 {
        emitter.emit(AppEvent::PendingMessagesDelivered { count: count as u32 });
    }

    Ok(())
}
