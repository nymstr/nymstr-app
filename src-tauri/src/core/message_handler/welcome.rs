//! Welcome flow handlers for MessageHandler
//!
//! This module contains methods for handling MLS Welcome flow messages:
//! invites, welcomes, join requests, key package exchanges, etc.

use crate::core::messages::MixnetMessage;
use crate::core::mixnet_client::MixnetService;
use crate::crypto::mls::{MlsClient, StoredWelcome};
use crate::crypto::pgp::{ArcPassphrase, ArcPublicKey, ArcSecretKey, PgpSigner};
use anyhow::{anyhow, Result};
use base64::Engine;
use sqlx::SqlitePool;
use std::sync::Arc;

/// Result of successfully processing a Welcome message
#[derive(Debug, Clone)]
pub struct WelcomeProcessResult {
    /// The group ID from the welcome
    pub group_id: String,
    /// The MLS group ID returned after joining
    pub mls_group_id: String,
    /// Who sent the welcome
    pub sender: String,
}

/// Result of handling a welcome flow message
#[derive(Debug, Clone)]
pub struct WelcomeFlowResult {
    /// Notifications to emit (sender, message)
    pub notifications: Vec<(String, String)>,
    /// If a Welcome was successfully processed, contains the result
    pub welcome_processed: Option<WelcomeProcessResult>,
}

/// Welcome flow handler for processing MLS welcome messages and group invites
///
/// This handler uses a shared MLS client from AppState to ensure MLS state
/// (groups, epochs, conversations) persists across messages.
pub struct WelcomeFlowHandler {
    /// Database connection pool
    pub db: SqlitePool,
    /// Mixnet service for communication
    pub service: Arc<MixnetService>,
    /// Current user
    pub current_user: Option<String>,
    /// PGP keys for signing (Arc-wrapped to avoid expensive cloning)
    pub pgp_secret_key: Option<ArcSecretKey>,
    pub pgp_public_key: Option<ArcPublicKey>,
    pub pgp_passphrase: Option<ArcPassphrase>,
    /// Shared MLS client from AppState (maintains state across messages)
    pub mls_client: Option<Arc<MlsClient>>,
}

impl WelcomeFlowHandler {
    /// Create a new WelcomeFlowHandler with shared MLS client
    ///
    /// The MLS client should be obtained from AppState to ensure conversation
    /// state persists across messages.
    pub fn new(
        db: SqlitePool,
        service: Arc<MixnetService>,
        current_user: Option<String>,
        pgp_secret_key: Option<ArcSecretKey>,
        pgp_public_key: Option<ArcPublicKey>,
        pgp_passphrase: Option<ArcPassphrase>,
        mls_client: Option<Arc<MlsClient>>,
    ) -> Self {
        Self {
            db,
            service,
            current_user,
            pgp_secret_key,
            pgp_public_key,
            pgp_passphrase,
            mls_client,
        }
    }

    /// Handle Welcome flow messages (invites, welcomes, join requests, etc.)
    ///
    /// Returns a `WelcomeFlowResult` containing notifications and optionally
    /// the result of processing a Welcome message (for event emission).
    pub async fn handle_welcome_flow_message(
        &mut self,
        envelope: &MixnetMessage,
    ) -> Result<WelcomeFlowResult> {
        let user = self
            .current_user
            .as_deref()
            .ok_or_else(|| anyhow!("No user logged in"))?;

        let action = envelope.action.as_str();
        let sender = &envelope.sender;
        let payload = &envelope.payload;

        log::info!(
            "Processing Welcome flow message: action={}, from={}",
            action,
            sender
        );

        match action {
            "groupInvite" => {
                // Someone invited us to join a group
                let group_id = payload
                    .get("groupId")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("Missing groupId in groupInvite"))?;
                let group_name = payload.get("groupName").and_then(|v| v.as_str());

                // Store the invite in the database
                self.store_group_invite(user, group_id, group_name, sender)
                    .await?;

                log::info!(
                    "Received group invite from {} for group {} ({})",
                    sender,
                    group_id,
                    group_name.unwrap_or("unnamed")
                );

                // Return notification to UI
                let notification = format!(
                    "Group invite from {} for {}",
                    sender,
                    group_name.unwrap_or(group_id)
                );
                Ok(WelcomeFlowResult {
                    notifications: vec![("SYSTEM".to_string(), notification)],
                    welcome_processed: None,
                })
            }

            "mlsWelcome" => {
                // Someone sent us a Welcome message to join a group
                let group_id = payload
                    .get("groupId")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("Missing groupId in mlsWelcome"))?;
                let welcome_bytes = payload
                    .get("welcome")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("Missing welcome bytes"))?;
                let cipher_suite = payload
                    .get("cipherSuite")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1) as u16;
                let epoch = payload.get("epoch").and_then(|v| v.as_u64()).unwrap_or(0);
                let ratchet_tree = payload
                    .get("ratchetTree")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                // Create StoredWelcome and save it
                let stored_welcome = StoredWelcome {
                    id: 0, // Will be set by database
                    group_id: group_id.to_string(),
                    sender: sender.clone(),
                    welcome_bytes: welcome_bytes.to_string(),
                    ratchet_tree,
                    cipher_suite,
                    epoch,
                    received_at: chrono::Utc::now().to_rfc3339(),
                    processed: false,
                    processed_at: None,
                    error_message: None,
                };

                self.store_welcome(user, &stored_welcome).await?;

                log::info!(
                    "Received MLS Welcome from {} for group {} at epoch {}",
                    sender,
                    group_id,
                    epoch
                );

                // Try to process the Welcome immediately using the shared MLS client
                if self.mls_client.is_some() {
                    match self.process_pending_welcome(user, &stored_welcome).await {
                        Ok(result) => {
                            let notification =
                                format!("Joined group {} via Welcome from {}", group_id, sender);
                            return Ok(WelcomeFlowResult {
                                notifications: vec![("SYSTEM".to_string(), notification)],
                                welcome_processed: Some(result),
                            });
                        }
                        Err(e) => {
                            log::warn!("Failed to process Welcome immediately: {}", e);
                            // It will be retried later
                        }
                    }
                } else {
                    log::warn!("MLS client not available, Welcome will be processed later");
                }

                let notification = format!(
                    "Received Welcome for group {} from {} (pending processing)",
                    group_id, sender
                );
                Ok(WelcomeFlowResult {
                    notifications: vec![("SYSTEM".to_string(), notification)],
                    welcome_processed: None,
                })
            }

            "groupJoinRequest" => {
                // Someone wants to join a group we manage
                let group_id = payload
                    .get("groupId")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("Missing groupId in groupJoinRequest"))?;
                let key_package = payload
                    .get("keyPackage")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("Missing keyPackage in groupJoinRequest"))?;

                // Store the join request
                self.store_join_request(user, group_id, sender, key_package)
                    .await?;

                log::info!(
                    "Received join request from {} for group {}",
                    sender,
                    group_id
                );

                let notification = format!("Join request from {} for group {}", sender, group_id);
                Ok(WelcomeFlowResult {
                    notifications: vec![("SYSTEM".to_string(), notification)],
                    welcome_processed: None,
                })
            }

            "welcomeAck" => {
                // Acknowledgment that someone processed our Welcome
                let group_id = payload
                    .get("groupId")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("Missing groupId in welcomeAck"))?;
                let success = payload
                    .get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);

                let notification = if success {
                    log::info!("{} successfully joined group {}", sender, group_id);
                    format!("{} joined group {}", sender, group_id)
                } else {
                    let error = payload
                        .get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown error");
                    log::warn!("{} failed to join group {}: {}", sender, group_id, error);
                    format!("{} failed to join group {}: {}", sender, group_id, error)
                };

                Ok(WelcomeFlowResult {
                    notifications: vec![("SYSTEM".to_string(), notification)],
                    welcome_processed: None,
                })
            }

            "keyPackageForGroup" => {
                // Request for our KeyPackage to be added to a specific group
                let group_id = payload
                    .get("groupId")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("Missing groupId in keyPackageForGroup"))?;

                log::info!(
                    "Received KeyPackage request from {} for group {}",
                    sender,
                    group_id
                );

                // Generate and send KeyPackage response using shared MLS client
                if self.mls_client.is_some() {
                    match self.generate_and_send_key_package(user, sender, group_id).await {
                        Ok(_) => {
                            log::info!(
                                "Sent KeyPackage response to {} for group {}",
                                sender,
                                group_id
                            );
                        }
                        Err(e) => {
                            log::error!("Failed to send KeyPackage response: {}", e);
                        }
                    }
                } else {
                    log::error!("MLS client not available, cannot send KeyPackage response");
                }

                Ok(WelcomeFlowResult {
                    notifications: vec![],
                    welcome_processed: None,
                })
            }

            "keyPackageForGroupResponse" => {
                // Received a KeyPackage in response to our request
                let group_id = payload
                    .get("groupId")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("Missing groupId in keyPackageForGroupResponse"))?;
                let key_package = payload
                    .get("keyPackage")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("Missing keyPackage"))?;

                log::info!(
                    "Received KeyPackage from {} for group {}",
                    sender,
                    group_id
                );

                // Add the member to the group using their KeyPackage and shared MLS client
                if self.mls_client.is_some() {
                    match self
                        .add_member_with_key_package(user, sender, group_id, key_package)
                        .await
                    {
                        Ok(_) => {
                            let notification = format!("Added {} to group {}", sender, group_id);
                            return Ok(WelcomeFlowResult {
                                notifications: vec![("SYSTEM".to_string(), notification)],
                                welcome_processed: None,
                            });
                        }
                        Err(e) => {
                            log::error!("Failed to add member to group: {}", e);
                        }
                    }
                } else {
                    log::error!("MLS client not available, cannot add member to group");
                }

                Ok(WelcomeFlowResult {
                    notifications: vec![],
                    welcome_processed: None,
                })
            }

            _ => {
                log::warn!("Unknown Welcome flow action: {}", action);
                Ok(WelcomeFlowResult {
                    notifications: vec![],
                    welcome_processed: None,
                })
            }
        }
    }

    /// Store a group invite in the database
    async fn store_group_invite(
        &self,
        _user: &str,
        group_id: &str,
        group_name: Option<&str>,
        sender: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO group_invites (group_id, group_name, sender, received_at, status)
            VALUES (?, ?, ?, datetime('now'), 'pending')
            "#,
        )
        .bind(group_id)
        .bind(group_name)
        .bind(sender)
        .execute(&self.db)
        .await
        .map_err(|e| anyhow!("Failed to store group invite: {}", e))?;

        Ok(())
    }

    /// Store a welcome message in the database
    async fn store_welcome(&self, _user: &str, welcome: &StoredWelcome) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO pending_welcomes (group_id, sender, welcome_bytes, ratchet_tree, cipher_suite, epoch, received_at, processed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&welcome.group_id)
        .bind(&welcome.sender)
        .bind(&welcome.welcome_bytes)
        .bind(&welcome.ratchet_tree)
        .bind(welcome.cipher_suite as i64)
        .bind(welcome.epoch as i64)
        .bind(&welcome.received_at)
        .bind(welcome.processed)
        .execute(&self.db)
        .await
        .map_err(|e| anyhow!("Failed to store welcome: {}", e))?;

        Ok(())
    }

    /// Store a join request in the database
    async fn store_join_request(
        &self,
        _user: &str,
        group_id: &str,
        sender: &str,
        key_package: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO join_requests (group_id, sender, key_package, received_at, status)
            VALUES (?, ?, ?, datetime('now'), 'pending')
            "#,
        )
        .bind(group_id)
        .bind(sender)
        .bind(key_package)
        .execute(&self.db)
        .await
        .map_err(|e| anyhow!("Failed to store join request: {}", e))?;

        Ok(())
    }

    /// Process a pending Welcome message to join a group
    ///
    /// Uses the shared MLS client from AppState to maintain state across messages.
    /// Returns the processing result containing group info for event emission.
    async fn process_pending_welcome(&self, user: &str, welcome: &StoredWelcome) -> Result<WelcomeProcessResult> {
        // Get shared MLS client
        let mls_client = self
            .mls_client
            .as_ref()
            .ok_or_else(|| anyhow!("MLS client not available"))?;

        // Get PGP keys for signing acknowledgment
        let (secret_key, passphrase) =
            match (&self.pgp_secret_key, &self.pgp_passphrase) {
                (Some(sk), Some(pp)) => (Arc::clone(sk), Arc::clone(pp)),
                _ => return Err(anyhow!("PGP keys not available")),
            };

        // Convert StoredWelcome to MlsWelcome using the built-in method
        let mls_welcome = welcome.to_mls_welcome();

        // Process the Welcome using the shared MLS client - this returns the mls_group_id
        let mls_group_id = mls_client.process_welcome(&mls_welcome).await?;

        // Mark as processed in database
        sqlx::query(
            "UPDATE pending_welcomes SET processed = 1, processed_at = datetime('now') WHERE group_id = ? AND sender = ?",
        )
        .bind(&welcome.group_id)
        .bind(&welcome.sender)
        .execute(&self.db)
        .await
        .map_err(|e| anyhow!("Failed to mark welcome as processed: {}", e))?;

        // Update group_memberships table with the MLS group ID
        // First, try to find a matching group server by group_id
        let server_address: Option<(String,)> = sqlx::query_as(
            "SELECT address FROM groups WHERE id = ? OR address LIKE ?"
        )
        .bind(&welcome.group_id)
        .bind(format!("%{}%", &welcome.group_id[..8.min(welcome.group_id.len())]))
        .fetch_optional(&self.db)
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
            .bind(user)
            .execute(&self.db)
            .await
            .ok(); // Non-fatal if this fails

            log::info!(
                "Updated group_memberships for server {} with MLS group ID {} for user {}",
                addr,
                mls_group_id,
                user
            );
        } else {
            log::warn!(
                "Could not find group server for group_id {}, membership MLS ID not updated",
                welcome.group_id
            );
        }

        // Send acknowledgment
        let signature = PgpSigner::sign_detached_secure(
            &secret_key,
            format!("welcomeAck:{}:{}", welcome.group_id, user).as_bytes(),
            &passphrase,
        )?;

        self.service
            .send_welcome_ack(user, &welcome.sender, &welcome.group_id, true, &signature)
            .await?;

        log::info!(
            "Successfully processed Welcome and joined group {} (MLS ID: {})",
            welcome.group_id,
            mls_group_id
        );

        Ok(WelcomeProcessResult {
            group_id: welcome.group_id.clone(),
            mls_group_id,
            sender: welcome.sender.clone(),
        })
    }

    /// Generate a KeyPackage and send it in response to a request
    ///
    /// Uses the shared MLS client from AppState to maintain state across messages.
    async fn generate_and_send_key_package(
        &self,
        user: &str,
        requester: &str,
        group_id: &str,
    ) -> Result<()> {
        // Get shared MLS client
        let mls_client = self
            .mls_client
            .as_ref()
            .ok_or_else(|| anyhow!("MLS client not available"))?;

        // Get PGP keys for signing
        let (secret_key, passphrase) = match (&self.pgp_secret_key, &self.pgp_passphrase) {
            (Some(sk), Some(pp)) => (Arc::clone(sk), Arc::clone(pp)),
            _ => return Err(anyhow!("PGP keys not available")),
        };

        // Generate a KeyPackage using the shared MLS client
        let key_package_bytes = mls_client.generate_key_package()?;
        let key_package_b64 =
            base64::engine::general_purpose::STANDARD.encode(&key_package_bytes);

        // Sign and send
        let signature = PgpSigner::sign_detached_secure(
            &secret_key,
            key_package_bytes.as_slice(),
            &passphrase,
        )?;

        self.service
            .send_key_package_for_group_response(user, requester, group_id, &key_package_b64, &signature)
            .await?;

        Ok(())
    }

    /// Add a member to a group using their KeyPackage and send them a Welcome
    ///
    /// Uses the shared MLS client from AppState to maintain state across messages.
    async fn add_member_with_key_package(
        &self,
        user: &str,
        new_member: &str,
        group_id: &str,
        key_package_b64: &str,
    ) -> Result<()> {
        use crate::core::db::group::GroupDb;

        // Get shared MLS client
        let mls_client = self
            .mls_client
            .as_ref()
            .ok_or_else(|| anyhow!("MLS client not available"))?;

        // Get PGP keys for signing
        let (secret_key, passphrase) = match (&self.pgp_secret_key, &self.pgp_passphrase) {
            (Some(sk), Some(pp)) => (Arc::clone(sk), Arc::clone(pp)),
            _ => return Err(anyhow!("PGP keys not available")),
        };

        // Look up the group server address for this group
        let group_server_address = GroupDb::get_server_address_by_group_id(&self.db, group_id)
            .await?
            .ok_or_else(|| anyhow!("No group server found for group {}", group_id))?;

        // Decode KeyPackage
        let key_package_bytes = base64::engine::general_purpose::STANDARD.decode(key_package_b64)?;

        // Add member and generate Welcome + Commit using the shared MLS client
        let add_result = mls_client
            .add_member_to_group(group_id, &key_package_bytes)
            .await?;

        // Send Welcome to new member via the group server
        let signature = PgpSigner::sign_detached_secure(
            &secret_key,
            add_result.welcome.welcome_bytes.as_bytes(),
            &passphrase,
        )?;

        self.service
            .send_mls_welcome(
                user,
                new_member,
                &add_result.welcome.group_id,
                add_result.welcome.cipher_suite,
                &add_result.welcome.welcome_bytes,
                add_result.welcome.ratchet_tree.as_deref(),
                add_result.welcome.epoch,
                chrono::Utc::now().timestamp() as u64,
                &signature,
                &group_server_address,
            )
            .await?;

        // Update join request status if one exists
        sqlx::query("UPDATE join_requests SET status = 'approved' WHERE group_id = ? AND sender = ?")
            .bind(group_id)
            .bind(new_member)
            .execute(&self.db)
            .await
            .ok(); // Ignore errors if no request exists

        log::info!(
            "Added {} to group {} and sent Welcome via group server {}",
            new_member,
            group_id,
            group_server_address
        );
        Ok(())
    }
}
