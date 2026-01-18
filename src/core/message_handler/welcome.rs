//! Welcome flow handlers for MessageHandler
//!
//! This module contains methods for handling MLS Welcome flow messages:
//! invites, welcomes, join requests, key package exchanges, etc.

use super::MessageHandler;
use crate::core::messages::MixnetMessage;
use std::sync::Arc;

impl MessageHandler {
    /// Handle Welcome flow messages (invites, welcomes, join requests, etc.)
    pub(crate) async fn handle_welcome_flow_message(&mut self, envelope: &MixnetMessage) -> anyhow::Result<Vec<(String, String)>> {
        let user = self.current_user.as_deref()
            .ok_or_else(|| anyhow::anyhow!("No user logged in"))?;

        let action = envelope.action.as_str();
        let sender = &envelope.sender;
        let payload = &envelope.payload;

        log::info!("Processing Welcome flow message: action={}, from={}", action, sender);

        match action {
            "groupInvite" => {
                // Someone invited us to join a group
                let group_id = payload.get("groupId")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing groupId in groupInvite"))?;
                let group_name = payload.get("groupName")
                    .and_then(|v| v.as_str());

                // Store the invite in the database
                self.db.store_group_invite(user, group_id, group_name, sender).await?;

                log::info!("Received group invite from {} for group {} ({})",
                    sender, group_id, group_name.unwrap_or("unnamed"));

                // Return notification to UI
                let notification = format!("Group invite from {} for {}",
                    sender, group_name.unwrap_or(group_id));
                Ok(vec![("SYSTEM".to_string(), notification)])
            }

            "mlsWelcome" => {
                // Someone sent us a Welcome message to join a group
                let group_id = payload.get("groupId")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing groupId in mlsWelcome"))?;
                let welcome_bytes = payload.get("welcome")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing welcome bytes"))?;
                let cipher_suite = payload.get("cipherSuite")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1) as u16;
                let epoch = payload.get("epoch")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let ratchet_tree = payload.get("ratchetTree")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                // Create StoredWelcome and save it
                let stored_welcome = crate::core::db::StoredWelcome {
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

                self.db.store_welcome(user, &stored_welcome).await?;

                log::info!("Received MLS Welcome from {} for group {} at epoch {}",
                    sender, group_id, epoch);

                // Try to process the Welcome immediately
                if let Some(mls_storage_path) = &self.mls_storage_path {
                    match self.process_pending_welcome(user, &stored_welcome, mls_storage_path).await {
                        Ok(_) => {
                            let notification = format!("Joined group {} via Welcome from {}", group_id, sender);
                            return Ok(vec![("SYSTEM".to_string(), notification)]);
                        }
                        Err(e) => {
                            log::warn!("Failed to process Welcome immediately: {}", e);
                            // It will be retried later
                        }
                    }
                }

                let notification = format!("Received Welcome for group {} from {} (pending processing)",
                    group_id, sender);
                Ok(vec![("SYSTEM".to_string(), notification)])
            }

            "groupJoinRequest" => {
                // Someone wants to join a group we manage
                let group_id = payload.get("groupId")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing groupId in groupJoinRequest"))?;
                let key_package = payload.get("keyPackage")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing keyPackage in groupJoinRequest"))?;

                // Store the join request
                self.db.store_join_request(user, group_id, sender, key_package).await?;

                log::info!("Received join request from {} for group {}", sender, group_id);

                let notification = format!("Join request from {} for group {}", sender, group_id);
                Ok(vec![("SYSTEM".to_string(), notification)])
            }

            "welcomeAck" => {
                // Acknowledgment that someone processed our Welcome
                let group_id = payload.get("groupId")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing groupId in welcomeAck"))?;
                let success = payload.get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);

                if success {
                    log::info!("{} successfully joined group {}", sender, group_id);
                    let notification = format!("{} joined group {}", sender, group_id);
                    Ok(vec![("SYSTEM".to_string(), notification)])
                } else {
                    let error = payload.get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown error");
                    log::warn!("{} failed to join group {}: {}", sender, group_id, error);
                    let notification = format!("{} failed to join group {}: {}", sender, group_id, error);
                    Ok(vec![("SYSTEM".to_string(), notification)])
                }
            }

            "keyPackageForGroup" => {
                // Request for our KeyPackage to be added to a specific group
                let group_id = payload.get("groupId")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing groupId in keyPackageForGroup"))?;

                log::info!("Received KeyPackage request from {} for group {}", sender, group_id);

                // Generate and send KeyPackage response
                if let Some(mls_storage_path) = &self.mls_storage_path {
                    match self.generate_and_send_key_package(user, sender, group_id, mls_storage_path).await {
                        Ok(_) => {
                            log::info!("Sent KeyPackage response to {} for group {}", sender, group_id);
                        }
                        Err(e) => {
                            log::error!("Failed to send KeyPackage response: {}", e);
                        }
                    }
                }

                Ok(vec![])
            }

            "keyPackageForGroupResponse" => {
                // Received a KeyPackage in response to our request
                let group_id = payload.get("groupId")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing groupId in keyPackageForGroupResponse"))?;
                let key_package = payload.get("keyPackage")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing keyPackage"))?;

                log::info!("Received KeyPackage from {} for group {}", sender, group_id);

                // Add the member to the group using their KeyPackage
                if let Some(mls_storage_path) = &self.mls_storage_path {
                    match self.add_member_with_key_package(user, sender, group_id, key_package, mls_storage_path).await {
                        Ok(_) => {
                            let notification = format!("Added {} to group {}", sender, group_id);
                            return Ok(vec![("SYSTEM".to_string(), notification)]);
                        }
                        Err(e) => {
                            log::error!("Failed to add member to group: {}", e);
                        }
                    }
                }

                Ok(vec![])
            }

            _ => {
                log::warn!("Unknown Welcome flow action: {}", action);
                Ok(vec![])
            }
        }
    }

    /// Process a pending Welcome message to join a group
    async fn process_pending_welcome(
        &self,
        user: &str,
        welcome: &crate::core::db::StoredWelcome,
        _mls_storage_path: &str,
    ) -> anyhow::Result<()> {
        use crate::crypto::mls::MlsClient;

        // Get required keys (Arc::clone is cheap - just increments reference count)
        let (secret_key, public_key, passphrase) = match (&self.pgp_secret_key, &self.pgp_public_key, &self.pgp_passphrase) {
            (Some(sk), Some(pk), Some(pp)) => (Arc::clone(sk), Arc::clone(pk), Arc::clone(pp)),
            _ => return Err(anyhow::anyhow!("PGP keys not available")),
        };

        // Create MLS client using Arc-wrapped keys
        let mls_client = MlsClient::new(user, Arc::clone(&secret_key), Arc::clone(&public_key), self.db.clone(), &passphrase)?;

        // Convert StoredWelcome to MlsWelcome using the built-in method
        let mls_welcome = welcome.to_mls_welcome();

        // Process the Welcome
        mls_client.process_welcome(&mls_welcome).await?;

        // Mark as processed in database
        self.db.mark_welcome_processed(user, welcome.id).await?;

        // Add group membership (me, conversation_id, member_username, credential_fingerprint, credential_verified, role)
        self.db.add_group_membership(
            user,
            &welcome.group_id,
            user,
            None, // credential_fingerprint
            true, // credential_verified
            "member",
        ).await?;

        // Send acknowledgment
        let signature = crate::crypto::Crypto::pgp_sign_detached_secure(
            &secret_key,
            format!("welcomeAck:{}:{}", welcome.group_id, user).as_bytes(),
            &passphrase,
        )?;

        self.service.send_welcome_ack(user, &welcome.sender, &welcome.group_id, true, &signature).await?;

        log::info!("Successfully processed Welcome and joined group {}", welcome.group_id);
        Ok(())
    }

    /// Generate a KeyPackage and send it in response to a request
    async fn generate_and_send_key_package(
        &self,
        user: &str,
        requester: &str,
        group_id: &str,
        _mls_storage_path: &str,
    ) -> anyhow::Result<()> {
        use crate::crypto::mls::MlsClient;
        use base64::Engine;

        // Get required keys (Arc::clone is cheap - just increments reference count)
        let (secret_key, public_key, passphrase) = match (&self.pgp_secret_key, &self.pgp_public_key, &self.pgp_passphrase) {
            (Some(sk), Some(pk), Some(pp)) => (Arc::clone(sk), Arc::clone(pk), Arc::clone(pp)),
            _ => return Err(anyhow::anyhow!("PGP keys not available")),
        };

        // Create MLS client using Arc-wrapped keys
        let mls_client = MlsClient::new(user, Arc::clone(&secret_key), Arc::clone(&public_key), self.db.clone(), &passphrase)?;

        // Generate a KeyPackage
        let key_package_bytes = mls_client.generate_key_package()?;
        let key_package_b64 = base64::engine::general_purpose::STANDARD.encode(&key_package_bytes);

        // Sign and send
        let signature = crate::crypto::Crypto::pgp_sign_detached_secure(
            &secret_key,
            key_package_bytes.as_slice(),
            &passphrase,
        )?;

        self.service.send_key_package_for_group_response(
            user,
            requester,
            group_id,
            &key_package_b64,
            &signature,
        ).await?;

        Ok(())
    }

    /// Add a member to a group using their KeyPackage and send them a Welcome
    async fn add_member_with_key_package(
        &self,
        user: &str,
        new_member: &str,
        group_id: &str,
        key_package_b64: &str,
        _mls_storage_path: &str,
    ) -> anyhow::Result<()> {
        use crate::crypto::mls::MlsClient;
        use base64::Engine;

        // Get required keys (Arc::clone is cheap - just increments reference count)
        let (secret_key, public_key, passphrase) = match (&self.pgp_secret_key, &self.pgp_public_key, &self.pgp_passphrase) {
            (Some(sk), Some(pk), Some(pp)) => (Arc::clone(sk), Arc::clone(pk), Arc::clone(pp)),
            _ => return Err(anyhow::anyhow!("PGP keys not available")),
        };

        // Decode KeyPackage
        let key_package_bytes = base64::engine::general_purpose::STANDARD.decode(key_package_b64)?;

        // Create MLS client using Arc-wrapped keys
        let mls_client = MlsClient::new(user, Arc::clone(&secret_key), Arc::clone(&public_key), self.db.clone(), &passphrase)?;

        // Add member and generate Welcome + Commit
        let add_result = mls_client.add_member_to_group(group_id, &key_package_bytes).await?;

        // Send Welcome to new member
        let signature = crate::crypto::Crypto::pgp_sign_detached_secure(
            &secret_key,
            add_result.welcome.welcome_bytes.as_bytes(),
            &passphrase,
        )?;

        self.service.send_mls_welcome(user, new_member, &add_result.welcome, &signature).await?;

        // Update group membership in database (me, conversation_id, member_username, credential_fingerprint, credential_verified, role)
        self.db.add_group_membership(
            user,
            group_id,
            new_member,
            None, // credential_fingerprint
            true, // credential_verified
            "member",
        ).await?;

        // Update join request status if one exists
        let requests = self.db.get_pending_join_requests(user, group_id).await?;
        for (request_id, requester, _, _) in requests {
            if requester == new_member {
                self.db.update_join_request_status(user, request_id, "approved").await?;
                break;
            }
        }

        log::info!("Added {} to group {} and sent Welcome", new_member, group_id);
        Ok(())
    }
}
