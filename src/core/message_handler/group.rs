//! Group messaging methods for MessageHandler
//!
//! This module contains methods for group authentication, sending/fetching group messages,
//! and handling group server responses.

use super::MessageHandler;
use crate::core::messages::MixnetMessage;
use crate::crypto::{Crypto, MlsConversationManager};
use std::sync::Arc;

impl MessageHandler {
    /// Authenticate with group server (register + connect)
    pub async fn authenticate_group(
        &mut self,
        username: &str,
        group_server_address: &str,
    ) -> anyhow::Result<bool> {
        // Get user's PGP keys
        let public_key = match &self.pgp_public_key {
            Some(pk) => pk,
            None => {
                log::error!("No PGP public key available for group authentication");
                return Ok(false);
            }
        };

        let secret_key = match &self.pgp_secret_key {
            Some(sk) => sk,
            None => {
                log::error!("No PGP secret key available for group authentication");
                return Ok(false);
            }
        };

        let passphrase = match &self.pgp_passphrase {
            Some(pp) => pp.clone(),
            None => {
                log::error!("No PGP passphrase available for group authentication");
                return Ok(false);
            }
        };

        let public_key_armored = Crypto::pgp_public_key_armored(public_key)?;

        // Register with the group server using timestamp-based authentication
        let timestamp = chrono::Utc::now().timestamp();
        let sign_content = format!(
            "register:{}:{}:{}",
            username, group_server_address, timestamp
        );
        let signature =
            Crypto::pgp_sign_detached_secure(secret_key, sign_content.as_bytes(), &passphrase)?;

        self.service
            .register_with_group_server(
                username,
                &public_key_armored,
                &signature,
                timestamp,
                group_server_address,
            )
            .await?;

        // Wait for mixnet to forward the message
        log::info!("Waiting for mixnet to forward registration message...");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        Ok(true)
    }

    /// Send an MLS-encrypted message to a group server.
    ///
    /// Note: Regular application messages don't advance the MLS epoch - only
    /// commits (adding/removing members) do. Commit buffering happens in
    /// group_approve when members are added.
    pub async fn send_group_message(
        &mut self,
        message: &str,
        group_server_address: &str,
    ) -> anyhow::Result<()> {
        use crate::crypto::mls::MlsClient;
        use base64::Engine;

        let sender = self
            .current_user
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("No user logged in"))?;

        // Get PGP keys for MLS client and signing (Arc::clone is cheap - just increments reference count)
        let (secret_key, public_key, passphrase) = match (
            &self.pgp_secret_key,
            &self.pgp_public_key,
            &self.pgp_passphrase,
        ) {
            (Some(sk), Some(pk), Some(pp)) => (Arc::clone(sk), Arc::clone(pk), Arc::clone(pp)),
            _ => return Err(anyhow::anyhow!("PGP keys not available")),
        };

        // Create MLS client and encrypt the message using Arc-wrapped keys
        let mls_client = MlsClient::new(
            sender,
            Arc::clone(&secret_key),
            Arc::clone(&public_key),
            self.db.clone(),
            &passphrase,
        )?;

        // Look up the actual MLS group ID from the database
        let mls_group_id = self.db.get_mls_group_id_by_server(sender, group_server_address).await?
            .ok_or_else(|| anyhow::anyhow!("MLS group not found for server {}. Did you run 'group init' or 'group join' first?", group_server_address))?;

        // Decode the MLS group ID from base64 to bytes
        let conversation_id = base64::engine::general_purpose::STANDARD
            .decode(&mls_group_id)
            .map_err(|e| anyhow::anyhow!("Invalid MLS group ID: {}", e))?;
        let encrypted = mls_client
            .encrypt_message(&conversation_id, message.as_bytes())
            .await?;

        // Encode the encrypted MLS message as base64 for transport
        let ciphertext = base64::engine::general_purpose::STANDARD.encode(&encrypted.mls_message);

        // Sign the ciphertext with PGP key
        let signature = crate::crypto::Crypto::pgp_sign_detached_secure(
            &secret_key,
            ciphertext.as_bytes(),
            &passphrase,
        )?;

        // Send the encrypted message to the group server
        self.service
            .send_group_message(sender, &ciphertext, &signature, group_server_address)
            .await?;
        log::info!(
            "Sent MLS-encrypted message to group {}",
            group_server_address
        );
        Ok(())
    }

    /// Fetch messages from a group server
    pub async fn fetch_group_messages(&mut self, group_server_address: &str) -> anyhow::Result<()> {
        let user = self
            .current_user
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("No user logged in"))?;

        // Get current cursor from database
        let last_seen_id = self.db.get_group_cursor(user, group_server_address).await?;

        // Sign the lastSeenId for authentication
        let signature = if let (Some(secret_key), Some(passphrase)) =
            (&self.pgp_secret_key, &self.pgp_passphrase)
        {
            crate::crypto::Crypto::pgp_sign_detached_secure(
                secret_key,
                last_seen_id.to_string().as_bytes(),
                passphrase,
            )?
        } else {
            return Err(anyhow::anyhow!("PGP keys not available for signing"));
        };

        // Send fetch request
        self.service
            .send_group_fetch_request(user, last_seen_id, &signature, group_server_address)
            .await?;
        log::info!(
            "Sent fetchGroup request to {} with cursor {}",
            group_server_address,
            last_seen_id
        );

        Ok(())
    }

    /// Attempts to decrypt a message using any of the user's known groups.
    ///
    /// Returns:
    /// - `Ok(Some((sender, text)))` if decryption succeeded
    /// - `Ok(None)` if the message was buffered due to epoch mismatch
    /// - `Err(())` if decryption failed with all groups
    async fn try_decrypt_with_any_group(
        mls_manager: &mut MlsConversationManager,
        groups: &[String],
        sender: &str,
        ciphertext: &str,
    ) -> Result<Option<(String, String)>, ()> {
        for group_id in groups {
            match mls_manager
                .process_incoming_message_buffered(group_id, sender, ciphertext)
                .await
            {
                Ok(Some((_, text))) => {
                    return Ok(Some((sender.to_string(), text)));
                }
                Ok(None) => {
                    // Message was buffered for later - epoch mismatch
                    log::info!(
                        "Group message from {} buffered for group {} (epoch mismatch)",
                        sender,
                        group_id
                    );
                    return Ok(None); // Consider it handled (buffered)
                }
                Err(e) => {
                    // Try next group - this one didn't work
                    log::debug!("Failed to decrypt with group {}: {}", group_id, e);
                }
            }
        }
        Err(())
    }

    /// Handle group server responses (fetchGroupResponse, etc.) with epoch-aware MLS decryption
    ///
    /// Uses MlsConversationManager for proper epoch buffering - messages that can't be
    /// decrypted due to epoch mismatch are queued and retried when the epoch advances.
    pub(crate) async fn handle_group_response(
        &mut self,
        envelope: &MixnetMessage,
        mls_manager: &mut MlsConversationManager,
    ) -> anyhow::Result<Vec<(String, String)>> {
        let user = self
            .current_user
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("No user logged in"))?;

        let action = envelope.action.as_str();
        log::info!("Processing group response: action={}", action);

        match action {
            "fetchGroupResponse" => {
                // Parse the content from payload
                let content = envelope
                    .payload
                    .get("content")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing content in fetchGroupResponse"))?;

                // Check for error response
                if content.starts_with("error:") {
                    return Err(anyhow::anyhow!("Group fetch failed: {}", content));
                }

                // Parse the JSON content
                let content_json: serde_json::Value =
                    serde_json::from_str(content).map_err(|e| {
                        anyhow::anyhow!("Failed to parse fetchGroupResponse content: {}", e)
                    })?;

                let messages = content_json
                    .get("messages")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| {
                        anyhow::anyhow!("Missing messages array in fetchGroupResponse")
                    })?;

                if messages.is_empty() {
                    return Ok(vec![]);
                }

                // Get all groups the user is a member of
                let groups = self.db.get_user_groups(user).await.unwrap_or_default();
                if groups.is_empty() {
                    log::warn!("No groups found for user {}, cannot decrypt messages", user);
                    return Ok(vec![]);
                }

                let mut decrypted_messages = Vec::new();

                for msg in messages {
                    let sender = msg
                        .get("sender")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let ciphertext = msg.get("ciphertext").and_then(|v| v.as_str()).unwrap_or("");

                    if ciphertext.is_empty() {
                        continue;
                    }

                    match Self::try_decrypt_with_any_group(mls_manager, &groups, sender, ciphertext)
                        .await
                    {
                        Ok(Some((sender, text))) => {
                            decrypted_messages.push((sender, text));
                        }
                        Ok(None) => {
                            // Message was buffered - already logged in helper
                        }
                        Err(()) => {
                            log::warn!(
                                "Could not decrypt message from {} with any known group",
                                sender
                            );
                        }
                    }
                }

                Ok(decrypted_messages)
            }
            "sendGroupResponse" => {
                // Message was sent successfully
                let content = envelope
                    .payload
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("sent");
                log::info!("Group message send response: {}", content);
                Ok(vec![])
            }
            "registerResponse" => {
                // Registration response
                let content = envelope
                    .payload
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                log::info!("Group registration response: {}", content);
                if content == "pending" {
                    Ok(vec![(
                        "SYSTEM".to_string(),
                        "Registration pending admin approval".to_string(),
                    )])
                } else if content.starts_with("error:") {
                    Ok(vec![(
                        "SYSTEM".to_string(),
                        format!("Registration failed: {}", content),
                    )])
                } else {
                    Ok(vec![])
                }
            }
            _ => {
                log::debug!("Unknown group response action: {}", action);
                Ok(vec![])
            }
        }
    }
}
