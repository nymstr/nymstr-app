use crate::core::message_handler::MessageHandler;
use crate::core::mixnet_client::MixnetService;
use crate::core::KeyManager;
use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;

#[derive(Parser)]
#[command(name = "nymstr")]
#[command(about = "Nymstr - Anonymous messaging over the Nym mixnet")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Username for operations
    #[arg(short, long)]
    pub username: Option<String>,

    /// Enable verbose logging
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Register a new user
    Register {
        /// Username to register
        username: String,
    },
    /// Login with existing user
    Login {
        /// Username to login with
        username: String,
    },
    /// Send a message to a recipient
    Send {
        /// Sender username (must be logged in)
        from: String,
        /// Recipient username
        recipient: String,
        /// Message content
        message: String,
    },
    /// Query for a user's public key
    Query {
        /// Username to query
        username: String,
    },
    /// Listen for incoming messages
    Listen {
        /// Username to listen as (must be logged in)
        username: String,
        /// Duration to listen in seconds (0 = indefinite)
        #[arg(short, long, default_value = "0")]
        duration: u64,
    },
    /// Send a handshake to establish p2p routing
    Handshake {
        /// Sender username (must be logged in)
        from: String,
        /// Recipient username
        recipient: String,
    },
    /// Group operations
    Group {
        #[command(subcommand)]
        action: GroupCommands,
    },
}

#[derive(Subcommand)]
pub enum GroupCommands {
    /// Register with a group server (request to join)
    Register {
        /// Group server address
        server: String,
        /// Your username
        user: String,
    },
    /// Send a message to the group
    Send {
        /// Group server address
        server: String,
        /// Your username
        user: String,
        /// Message content
        message: String,
    },
    /// Fetch messages from the group server
    Fetch {
        /// Group server address
        server: String,
        /// Your username
        user: String,
    },
    /// Get group statistics
    Stats {
        /// Group server address
        server: String,
        /// Your username
        user: String,
    },
    /// Initialize MLS group tied to a group server (admin only)
    Init {
        /// Group server Nym address
        server: String,
        /// Admin username (must match server's configured admin)
        user: String,
    },
    /// Approve a pending user's registration (admin only)
    Approve {
        /// Group server address
        server: String,
        /// Your username (must be admin)
        user: String,
        /// Username to approve
        username_to_approve: String,
    },
    /// Invite a user to join a group
    Invite {
        /// Group ID (server address)
        group_id: String,
        /// Your username (must be admin)
        user: String,
        /// Username to invite
        recipient: String,
    },
    /// List pending group invites received
    ListInvites {
        /// Your username
        user: String,
    },
    /// Accept a group invite
    AcceptInvite {
        /// Your username
        user: String,
        /// Invite ID
        invite_id: i64,
    },
    /// List groups you're a member of
    ListGroups {
        /// Your username
        user: String,
    },
    /// List pending join requests for your groups
    ListJoinRequests {
        /// Your username (must be admin)
        user: String,
        /// Optional group ID to filter by
        group_id: Option<String>,
    },
    /// Approve a join request
    ApproveJoinRequest {
        /// Your username (must be admin)
        user: String,
        /// Request ID
        request_id: i64,
    },
    /// Join a group by fetching Welcome message from server (after being approved)
    Join {
        /// Group server address
        server: String,
        /// Your username
        user: String,
    },
    /// Interactive group chat mode
    Chat {
        /// Group server address
        server: String,
        /// Your username
        user: String,
    },
}

pub struct CliApp {
    handler: Option<MessageHandler>,
}

impl Default for CliApp {
    fn default() -> Self {
        Self::new()
    }
}

impl CliApp {
    pub fn new() -> Self {
        Self { handler: None }
    }

    pub async fn connect(&mut self) -> Result<()> {
        info!("Connecting to mixnet...");

        // Initialize mixnet service
        let (service, incoming_rx) = MixnetService::new("nymstr.db").await?;

        // Initialize message handler
        let mut handler = MessageHandler::new(service, incoming_rx, "nymstr.db").await?;

        // Store the nym address for later use
        handler.nym_address = Some(handler.service.get_nym_address().to_string());

        self.handler = Some(handler);
        info!("Connected to mixnet successfully");
        Ok(())
    }

    /// Load user keys and set up user context locally (no discovery server contact).
    /// Used for group operations that don't require central authentication.
    fn load_user(&mut self, username: &str) -> Result<()> {
        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        if handler.current_user.as_deref() == Some(username) {
            return Ok(());
        }

        info!("Loading local keys for user: {}", username);
        let (secret_key, public_key, passphrase) = KeyManager::load_existing_keys(username)?;
        KeyManager::verify_keys(&secret_key, &public_key)?;
        handler.set_pgp_keys(secret_key, public_key, passphrase);
        handler.current_user = Some(username.to_string());
        handler.mls_storage_path = Some(crate::core::db::get_mls_db_path(username));
        Ok(())
    }

    pub async fn login(&mut self, username: &str) -> Result<bool> {
        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        info!("Logging in user: {}", username);

        // Use KeyManager to load existing keys with password prompting
        let (secret_key, public_key, passphrase) = KeyManager::load_existing_keys(username)?;

        // Verify keys are valid
        KeyManager::verify_keys(&secret_key, &public_key)?;

        // Set the keys in the message handler
        handler.set_pgp_keys(secret_key, public_key, passphrase);

        // Now login with the server
        let success = handler.login_user(username).await?;

        if success {
            info!("Login successful for user: {}", username);
        } else {
            info!("Login failed for user: {}", username);
        }

        Ok(success)
    }

    pub async fn send_message(&mut self, from: &str, recipient: &str, message: &str) -> Result<()> {
        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        // Ensure user is logged in first
        if handler.current_user.as_deref() != Some(from) {
            info!("Logging in user {} before sending message", from);
            let login_success = handler.login_user(from).await?;
            if !login_success {
                return Err(anyhow::anyhow!("Failed to login user: {}", from));
            }
        }

        info!(
            "Sending message from {} to {}: {}",
            from, recipient, message
        );
        handler.send_direct_message(recipient, message).await?;
        info!("Message sent successfully");
        Ok(())
    }

    pub async fn query_user(&mut self, username: &str) -> Result<Option<(String, String)>> {
        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        info!("Querying user: {}", username);
        let result = handler.query_user(username).await?;

        match &result {
            Some((user, pk)) => {
                info!("Query successful - User: {}, Public Key: {}", user, pk);
                println!("User: {}\nPublic Key: {}", user, pk);
            }
            None => {
                info!("User not found: {}", username);
                println!("User not found: {}", username);
            }
        }

        Ok(result)
    }

    pub async fn send_handshake(&mut self, from: &str, recipient: &str) -> Result<()> {
        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        // Ensure user is logged in first
        if handler.current_user.as_deref() != Some(from) {
            info!("Logging in user {} before sending handshake", from);
            let login_success = handler.login_user(from).await?;
            if !login_success {
                return Err(anyhow::anyhow!("Failed to login user: {}", from));
            }
        }

        info!("Sending handshake from {} to: {}", from, recipient);
        handler.send_handshake(recipient).await?;
        info!("Handshake sent successfully");
        Ok(())
    }

    pub async fn listen(&mut self, username: &str, duration: u64) -> Result<()> {
        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        // Ensure user is logged in first
        if handler.current_user.as_deref() != Some(username) {
            info!("Logging in user {} before listening", username);
            let login_success = handler.login_user(username).await?;
            if !login_success {
                return Err(anyhow::anyhow!("Failed to login user: {}", username));
            }
        }

        info!(
            "Listening for messages as {}{}...",
            username,
            if duration > 0 {
                format!(" for {} seconds", duration)
            } else {
                String::new()
            }
        );

        let timeout = if duration > 0 {
            Some(std::time::Duration::from_secs(duration))
        } else {
            None
        };

        let start_time = std::time::Instant::now();

        loop {
            // Check timeout
            if let Some(timeout_duration) = timeout {
                if start_time.elapsed() >= timeout_duration {
                    info!("Listen timeout reached");
                    break;
                }
            }

            // Listen for incoming messages with a reasonable timeout
            tokio::select! {
                incoming = handler.incoming_rx.recv() => {
                    if let Some(incoming) = incoming {
                        let messages = handler.process_received_message(incoming).await;
                        for (sender, message) in messages {
                            println!("Message from {}: {}", sender, message);
                            info!("Received message from {}: {}", sender, message);
                        }
                    } else {
                        info!("Message channel closed");
                        break;
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                    // Continue listening
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Listen cancelled by user");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Register with a group server, including an MLS KeyPackage for future group joining.
    /// The KeyPackage is stored on the server and used when the admin approves the user.
    pub async fn group_register(&mut self, server: &str, user: &str) -> Result<bool> {
        use crate::crypto::mls::MlsClient;
        use crate::crypto::Crypto;
        use base64::Engine;

        self.load_user(user)?;

        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        // Get required keys
        let (secret_key, public_key, passphrase) = match (
            &handler.pgp_secret_key,
            &handler.pgp_public_key,
            &handler.pgp_passphrase,
        ) {
            (Some(sk), Some(pk), Some(pp)) => (sk.clone(), pk.clone(), pp.clone()),
            _ => return Err(anyhow::anyhow!("PGP keys not available")),
        };

        // Generate MLS KeyPackage for future group membership
        info!("Generating MLS KeyPackage for user {}", user);
        let mls_client = MlsClient::new(
            user,
            secret_key.clone(),
            public_key.clone(),
            handler.db.clone(),
            &passphrase,
        )?;
        let key_package_bytes = mls_client.generate_key_package()?;
        let key_package_b64 = base64::engine::general_purpose::STANDARD.encode(&key_package_bytes);
        info!("Generated KeyPackage ({} bytes)", key_package_bytes.len());

        // Prepare registration with timestamp-based authentication
        let public_key_armored = Crypto::pgp_public_key_armored(&public_key)?;
        let timestamp = chrono::Utc::now().timestamp();
        let sign_content = format!("register:{}:{}:{}", user, server, timestamp);
        let signature =
            Crypto::pgp_sign_detached_secure(&secret_key, sign_content.as_bytes(), &passphrase)?;

        // Send registration with KeyPackage
        info!("Registering with group server {} (with KeyPackage)", server);
        handler
            .service
            .register_with_group_server_and_key_package(
                user,
                &public_key_armored,
                &signature,
                timestamp,
                server,
                Some(&key_package_b64),
            )
            .await?;

        // Wait for mixnet to forward the message
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        info!("Group registration request sent with KeyPackage");
        Ok(true)
    }

    pub async fn group_send(&mut self, server: &str, user: &str, message: &str) -> Result<()> {
        self.load_user(user)?;

        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        info!("Sending group message to {}: {}", server, message);
        handler.send_group_message(message, server).await?;

        // Wait for mixnet to transmit the message before exiting
        info!("Waiting for mixnet to transmit message...");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        info!("Group message sent successfully");
        Ok(())
    }

    pub async fn group_stats(&mut self, server: &str, user: &str) -> Result<()> {
        self.load_user(user)?;

        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        info!("Getting group stats from {}", server);
        handler.service.get_group_stats(server).await?;
        info!("Group stats request sent");
        Ok(())
    }

    /// Fetch group messages, with optional epoch sync for late joiners.
    ///
    /// This command:
    /// 1. (Optional) Syncs MLS epoch to catch up on any missed commits
    /// 2. Fetches messages from the group server
    /// 3. Decrypts messages using the MLS group state
    pub async fn group_fetch(&mut self, server: &str, user: &str) -> Result<()> {
        use crate::crypto::mls::MlsClient;
        use crate::crypto::Crypto;
        use base64::Engine;

        self.load_user(user)?;

        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        // Get required keys
        let (secret_key, public_key, passphrase) = match (
            &handler.pgp_secret_key,
            &handler.pgp_public_key,
            &handler.pgp_passphrase,
        ) {
            (Some(sk), Some(pk), Some(pp)) => (sk.clone(), pk.clone(), pp.clone()),
            _ => return Err(anyhow::anyhow!("PGP keys not available")),
        };

        // Try to get current MLS epoch for this group (if we have joined it)
        let mls_client = MlsClient::new(
            user,
            secret_key.clone(),
            public_key.clone(),
            handler.db.clone(),
            &passphrase,
        )?;

        // Look up the actual MLS group ID from the database
        let mls_group_id = handler.db.get_mls_group_id_by_server(user, server).await?;

        // Only attempt epoch sync if we have an MLS group state
        if let Some(ref group_id) = mls_group_id {
            if let Ok(local_epoch) = mls_client.get_group_epoch(group_id) {
                info!("Local MLS epoch for group: {}", local_epoch);

                // Request epoch sync to catch up on any missed commits
                // Server expects signature over "groupId:epoch" where groupId is the MLS group ID
                let sign_content = format!("{}:{}", group_id, local_epoch);
                let sync_sig = Crypto::pgp_sign_detached_secure(
                    &secret_key,
                    sign_content.as_bytes(),
                    &passphrase,
                )?;

                info!(
                    "Requesting epoch sync from server (since epoch {})",
                    local_epoch
                );
                if let Err(e) = handler
                    .service
                    .sync_epoch_from_server(user, group_id, local_epoch as i64, &sync_sig, server)
                    .await
                {
                    info!("Epoch sync request failed (non-fatal): {}", e);
                }

                // Brief wait for sync response (non-blocking, best effort)
                let sync_timeout = std::time::Duration::from_secs(5);
                let sync_start = std::time::Instant::now();

                while sync_start.elapsed() < sync_timeout {
                    tokio::select! {
                        incoming = handler.incoming_rx.recv() => {
                            if let Some(incoming) = incoming {
                                if incoming.envelope.action == "syncEpochResponse" {
                                    info!("Received epoch sync response");
                                    // Process the sync response (commits would be processed here)
                                    // For now, just log it - commit processing would require extending MlsClient
                                    if let Some(content) = incoming.envelope.payload.get("content").and_then(|v| v.as_str()) {
                                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(content) {
                                            if let Some(current_epoch) = parsed.get("currentEpoch").and_then(|v| v.as_i64()) {
                                                info!("Server current epoch: {}", current_epoch);
                                            }
                                            if let Some(commits) = parsed.get("commits").and_then(|v| v.as_array()) {
                                                info!("Received {} buffered commits for catch-up", commits.len());
                                                // Process each commit to advance our epoch
                                                for commit_obj in commits {
                                                    if let (Some(epoch), Some(commit_b64)) = (
                                                        commit_obj.get("epoch").and_then(|v| v.as_i64()),
                                                        commit_obj.get("commit").and_then(|v| v.as_str())
                                                    ) {
                                                        info!("Processing commit for epoch {}", epoch);
                                                        match base64::engine::general_purpose::STANDARD.decode(commit_b64) {
                                                            Ok(commit_bytes) => {
                                                                match mls_client.process_commit(group_id, &commit_bytes) {
                                                                    Ok(new_epoch) => {
                                                                        info!("Advanced to epoch {} after processing commit", new_epoch);
                                                                    }
                                                                    Err(e) => {
                                                                        info!("Failed to process commit for epoch {}: {}", epoch, e);
                                                                    }
                                                                }
                                                            }
                                                            Err(e) => {
                                                                info!("Failed to decode commit: {}", e);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    break;
                                } else {
                                    handler.process_received_message(incoming).await;
                                }
                            }
                        }
                        _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
                    }
                }
            } else {
                info!("No local MLS group state found for this server - skipping epoch sync");
            }
        } else {
            info!("MLS group ID not found in database - skipping epoch sync");
        }

        // Now fetch messages
        info!("Fetching group messages from {}", server);
        handler.fetch_group_messages(server).await?;

        // Wait for response with timeout
        let timeout_duration = std::time::Duration::from_secs(30);
        let start = std::time::Instant::now();

        while start.elapsed() < timeout_duration {
            tokio::select! {
                incoming = handler.incoming_rx.recv() => {
                    if let Some(incoming) = incoming {
                        if incoming.envelope.action == "fetchGroupResponse" {
                            let messages = handler.process_received_message(incoming).await;
                            println!("Fetched messages from group server");
                            for (sender, message) in messages {
                                println!("  [{}]: {}", sender, message);
                            }
                            return Ok(());
                        } else {
                            handler.process_received_message(incoming).await;
                        }
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
            }
        }

        Err(anyhow::anyhow!("Timeout waiting for fetchGroupResponse"))
    }

    // ==================== MLS Group Commands ====================

    /// Initialize MLS group tied to a group server
    ///
    /// This creates the local MLS group state for a specific group server,
    /// then registers the user with the group server using timestamp-based auth.
    /// The server address is used as the group identifier to ensure consistency
    /// across all members.
    pub async fn group_init(&mut self, server: &str, user: &str) -> Result<String> {
        use crate::crypto::mls::MlsClient;
        use crate::crypto::Crypto;

        self.load_user(user)?;

        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        // Get required keys
        let (secret_key, public_key, passphrase) = match (
            &handler.pgp_secret_key,
            &handler.pgp_public_key,
            &handler.pgp_passphrase,
        ) {
            (Some(sk), Some(pk), Some(pp)) => (sk.clone(), pk.clone(), pp.clone()),
            _ => return Err(anyhow::anyhow!("PGP keys not available")),
        };

        // Use server address as the group identifier for consistency
        // This ensures all members use the same group_id
        let group_id = server.to_string();

        // Create MLS client and group
        let mls_client = MlsClient::new(
            user,
            secret_key.clone(),
            public_key.clone(),
            handler.db.clone(),
            &passphrase,
        )?;
        let group_info = mls_client.create_mls_group(&group_id).await?;

        // Store group server association with the actual MLS group ID
        // The mls_group_id is the internally-generated ID used by MLS for group lookup
        handler
            .db
            .store_group_server(
                user,
                &group_id,
                server,
                user,
                Some(&group_info.mls_group_id),
            )
            .await?;

        // Store group membership using the actual MLS group ID as conversation_id
        // This ensures decryption can find the group by the same ID used by MLS
        handler
            .db
            .add_group_membership(user, &group_info.mls_group_id, user, None, true, "admin")
            .await?;

        // Register with the group server using timestamp-based authentication
        // Sign: "register:{username}:{server_address}:{unix_timestamp}"
        let timestamp = chrono::Utc::now().timestamp();
        let sign_content = format!("register:{}:{}:{}", user, server, timestamp);
        let public_key_armored = Crypto::pgp_public_key_armored(&public_key)?;
        let signature =
            Crypto::pgp_sign_detached_secure(&secret_key, sign_content.as_bytes(), &passphrase)?;

        handler
            .service
            .register_with_group_server(user, &public_key_armored, &signature, timestamp, server)
            .await?;

        // Wait for mixnet to forward the message before disconnecting
        // The mixnet has latency due to multiple hops, so we need to keep the client alive
        info!("Waiting for mixnet to forward registration message...");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        info!(
            "Initialized MLS group for server {} as admin {} and sent registration",
            server, user
        );
        Ok(group_id)
    }

    /// Approve a user's registration and add them to the MLS group.
    /// This command:
    /// 1. Sends approval to server
    /// 2. Receives the user's KeyPackage in response
    /// 3. Adds them to the local MLS group (generates Welcome)
    /// 4. Stores the Welcome on the server for the user to fetch
    pub async fn group_approve(
        &mut self,
        server: &str,
        user: &str,
        username_to_approve: &str,
    ) -> Result<()> {
        use crate::crypto::mls::MlsClient;
        use crate::crypto::Crypto;
        use base64::Engine;

        self.load_user(user)?;

        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        // Get required keys
        let (secret_key, public_key, passphrase) = match (
            &handler.pgp_secret_key,
            &handler.pgp_public_key,
            &handler.pgp_passphrase,
        ) {
            (Some(sk), Some(pk), Some(pp)) => (sk.clone(), pk.clone(), pp.clone()),
            _ => return Err(anyhow::anyhow!("PGP keys not available")),
        };

        // Sign the username to approve (server verifies against admin public key)
        let signature = Crypto::pgp_sign_detached_secure(
            &secret_key,
            username_to_approve.as_bytes(),
            &passphrase,
        )?;

        info!(
            "Sending approval request for {} to server {}",
            username_to_approve, server
        );
        handler
            .service
            .approve_group_member(user, username_to_approve, &signature, server)
            .await?;

        // Wait for approveGroupResponse containing the user's KeyPackage
        let timeout = std::time::Duration::from_secs(30);
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            tokio::select! {
                incoming = handler.incoming_rx.recv() => {
                    if let Some(incoming) = incoming {
                        if incoming.envelope.action == "approveGroupResponse" {
                            // Parse the response to get the KeyPackage
                            if let Some(content) = incoming.envelope.payload.get("content").and_then(|v| v.as_str()) {
                                // Try to parse as JSON
                                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(content) {
                                    // Check for success status
                                    if parsed.get("status").and_then(|v| v.as_str()) == Some("success") {
                                        // Get the KeyPackage if present
                                        if let Some(key_package_b64) = parsed.get("keyPackage").and_then(|v| v.as_str()) {
                                            info!("Received KeyPackage for {}", username_to_approve);

                                            // Decode the KeyPackage
                                            let key_package_bytes = base64::engine::general_purpose::STANDARD.decode(key_package_b64)?;

                                            // Get the MLS group ID from the database
                                            // The server address is used as the group_id key in the database
                                            let mls_group_id = handler.db.get_mls_group_id_by_server(user, server).await?
                                                .ok_or_else(|| anyhow::anyhow!("MLS group not found for server {}. Did you run 'group init' first?", server))?;

                                            // Add the user to the MLS group and get the Welcome + Commit
                                            let mls_client = MlsClient::new(user, secret_key.clone(), public_key.clone(), handler.db.clone(), &passphrase)?;
                                            let add_result = mls_client.add_member_to_group(&mls_group_id, &key_package_bytes).await?;

                                            info!("Generated Welcome for {} at epoch {}", username_to_approve, add_result.welcome.epoch);

                                            // Store the Welcome on the server for the user to fetch
                                            let sign_content = format!("{}:{}", server, username_to_approve);
                                            let welcome_sig = Crypto::pgp_sign_detached_secure(&secret_key, sign_content.as_bytes(), &passphrase)?;

                                            handler.service.store_welcome_on_server(
                                                user,
                                                server, // group_id is the server address
                                                username_to_approve,
                                                &add_result.welcome.welcome_bytes,
                                                &welcome_sig,
                                                server,
                                            ).await?;

                                            info!("Stored Welcome on server for {}", username_to_approve);

                                            // Buffer the Commit on the server for existing members to sync
                                            // Server expects signature over "groupId:epoch"
                                            let commit_sign_content = format!("{}:{}", mls_group_id, add_result.new_epoch);
                                            let commit_sig = Crypto::pgp_sign_detached_secure(&secret_key, commit_sign_content.as_bytes(), &passphrase)?;

                                            handler.service.buffer_commit_on_server(
                                                user,
                                                &mls_group_id,
                                                add_result.new_epoch as i64,
                                                &add_result.commit_bytes,
                                                &commit_sig,
                                                server,
                                            ).await?;

                                            info!("Buffered Commit on server for epoch {}", add_result.new_epoch);

                                            // Wait for mixnet to transmit the storeWelcome and bufferCommit messages
                                            info!("Waiting for mixnet to transmit Welcome and Commit...");
                                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;

                                            println!("Approved {} and stored Welcome on server", username_to_approve);
                                            return Ok(());
                                        } else {
                                            // No KeyPackage in response - user didn't provide one during registration
                                            info!("User {} was approved but no KeyPackage available", username_to_approve);
                                            info!("The user will need to re-register with a KeyPackage to join the MLS group");
                                            return Ok(());
                                        }
                                    } else if let Some(error) = parsed.get("error").or(parsed.get("status")).and_then(|v| v.as_str()) {
                                        return Err(anyhow::anyhow!("Approval failed: {}", error));
                                    }
                                } else if content == "success" {
                                    // Legacy response without KeyPackage
                                    info!("Approved {} (legacy response, no KeyPackage)", username_to_approve);
                                    return Ok(());
                                }
                            }
                            info!("Received approveGroupResponse: {:?}", incoming.envelope.payload);
                            return Ok(());
                        } else {
                            // Process other messages
                            handler.process_received_message(incoming).await;
                        }
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
            }
        }

        Err(anyhow::anyhow!("Timeout waiting for approveGroupResponse"))
    }

    /// Join a group by fetching the Welcome message from the server.
    /// This is called after the admin has approved the user's registration.
    /// The server stores the Welcome message when the admin approves, and
    /// this command fetches it to complete the MLS group join process.
    pub async fn group_join(&mut self, server: &str, user: &str) -> Result<()> {
        use crate::crypto::mls::MlsClient;
        use crate::crypto::Crypto;
        use base64::Engine;

        self.load_user(user)?;

        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        // Get required keys
        let (secret_key, public_key, passphrase) = match (
            &handler.pgp_secret_key,
            &handler.pgp_public_key,
            &handler.pgp_passphrase,
        ) {
            (Some(sk), Some(pk), Some(pp)) => (sk.clone(), pk.clone(), pp.clone()),
            _ => return Err(anyhow::anyhow!("PGP keys not available")),
        };

        // Sign the fetch request
        let sign_content = format!("fetchWelcome:{}", user);
        let signature =
            Crypto::pgp_sign_detached_secure(&secret_key, sign_content.as_bytes(), &passphrase)?;

        // Request Welcome from server
        info!("Fetching Welcome message from server {}", server);
        handler
            .service
            .fetch_welcome_from_server(user, Some(server), &signature, server)
            .await?;

        // Wait for fetchWelcomeResponse
        let timeout = std::time::Duration::from_secs(30);
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            tokio::select! {
                incoming = handler.incoming_rx.recv() => {
                    if let Some(incoming) = incoming {
                        if incoming.envelope.action == "fetchWelcomeResponse" {
                            // Parse the response
                            if let Some(content) = incoming.envelope.payload.get("content").and_then(|v| v.as_str()) {
                                // Try to parse as JSON
                                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(content) {
                                    if let Some(welcomes) = parsed.get("welcomes").and_then(|v| v.as_array()) {
                                        if welcomes.is_empty() {
                                            info!("No pending Welcome messages found. You may not have been approved yet.");
                                            return Ok(());
                                        }

                                        for welcome_json in welcomes {
                                            let group_id = welcome_json.get("groupId")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or(server);
                                            let welcome_b64 = welcome_json.get("welcome")
                                                .and_then(|v| v.as_str())
                                                .ok_or_else(|| anyhow::anyhow!("Missing welcome in response"))?;

                                            // Decode Welcome
                                            let welcome_bytes = base64::engine::general_purpose::STANDARD.decode(welcome_b64)?;
                                            info!("Received Welcome for group {} ({} bytes)", group_id, welcome_bytes.len());

                                            // Process Welcome with MLS client
                                            let mls_client = MlsClient::new(user, secret_key.clone(), public_key.clone(), handler.db.clone(), &passphrase)?;

                                            // Create MlsWelcome structure
                                            let mls_welcome = crate::crypto::mls::types::MlsWelcome {
                                                group_id: group_id.to_string(),
                                                cipher_suite: 1, // MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
                                                welcome_bytes: welcome_b64.to_string(),
                                                ratchet_tree: None,
                                                epoch: 0,
                                                sender: "admin".to_string(),
                                                timestamp: chrono::Utc::now().timestamp() as u64,
                                            };

                                            let mls_group_id = mls_client.process_welcome(&mls_welcome).await?;
                                            info!("Successfully joined group {} via Welcome message (mls_group_id: {})", group_id, mls_group_id);

                                            // Store the server -> mls_group_id mapping so we can send/receive messages
                                            handler.db.store_group_server(user, server, server, "unknown", Some(&mls_group_id)).await?;
                                            info!("Stored group server mapping for {}", server);

                                            // Store group membership using the MLS group ID as conversation_id
                                            // This ensures decryption can find the group
                                            handler.db.add_group_membership(
                                                user,
                                                &mls_group_id,
                                                user,
                                                None,
                                                true,
                                                "member",
                                            ).await?;
                                            info!("Stored group membership for {}", user);
                                        }
                                        return Ok(());
                                    }
                                }
                            }
                            // If we couldn't parse welcomes, it might be an error message
                            info!("Received fetchWelcomeResponse: {:?}", incoming.envelope.payload);
                            return Ok(());
                        } else {
                            // Process other messages
                            handler.process_received_message(incoming).await;
                        }
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
            }
        }

        Err(anyhow::anyhow!("Timeout waiting for fetchWelcomeResponse"))
    }

    /// Interactive group chat mode
    pub async fn group_chat_interactive(&mut self, server: &str, user: &str) -> Result<()> {
        use crate::crypto::mls::MlsClient;
        use std::io::{self, BufRead, Write};

        self.load_user(user)?;

        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        // Get required keys
        let (secret_key, public_key, passphrase) = match (
            &handler.pgp_secret_key,
            &handler.pgp_public_key,
            &handler.pgp_passphrase,
        ) {
            (Some(sk), Some(pk), Some(pp)) => (sk.clone(), pk.clone(), pp.clone()),
            _ => return Err(anyhow::anyhow!("PGP keys not available")),
        };

        // Check if we're a member of this group
        let mls_group_id = handler
            .db
            .get_mls_group_id_by_server(user, server)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Not a member of group at {}. Run 'group join' first.",
                    server
                )
            })?;

        let mls_client = MlsClient::new(
            user,
            secret_key.clone(),
            public_key.clone(),
            handler.db.clone(),
            &passphrase,
        )?;
        let current_epoch = mls_client.get_group_epoch(&mls_group_id).unwrap_or(0);

        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║           NYMSTR GROUP CHAT - Interactive Mode               ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║  User: {:<54} ║", user);
        println!(
            "║  Group: {:<53} ║",
            &server[..std::cmp::min(53, server.len())]
        );
        println!("║  Epoch: {:<53} ║", current_epoch);
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║  Commands:                                                   ║");
        println!("║    /fetch  - Fetch new messages                              ║");
        println!("║    /sync   - Sync epoch (fetch missed commits)               ║");
        println!("║    /epoch  - Show current epoch                              ║");
        println!("║    /quit   - Exit chat                                       ║");
        println!("║                                                              ║");
        println!("║  Type a message and press Enter to send                      ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");

        let stdin = io::stdin();
        let mut stdout = io::stdout();

        loop {
            // Print prompt
            print!("[{}] > ", user);
            stdout.flush()?;

            // Read input
            let mut input = String::new();
            if stdin.lock().read_line(&mut input)? == 0 {
                // EOF
                break;
            }

            let input = input.trim();
            if input.is_empty() {
                continue;
            }

            // Handle commands
            if input.starts_with('/') {
                match input {
                    "/quit" | "/exit" | "/q" => {
                        println!("Goodbye!");
                        break;
                    }
                    "/fetch" => {
                        println!("Fetching messages...");
                        // Do epoch sync first
                        self.do_epoch_sync(server, user).await;
                        // Then fetch messages
                        match self.do_fetch_messages(server, user).await {
                            Ok(messages) => {
                                if messages.is_empty() {
                                    println!("  (no new messages)");
                                } else {
                                    for (sender, msg) in messages {
                                        println!("  [{}]: {}", sender, msg);
                                    }
                                }
                            }
                            Err(e) => println!("  Error fetching: {}", e),
                        }
                    }
                    "/sync" => {
                        println!("Syncing epoch...");
                        self.do_epoch_sync(server, user).await;
                        // Show new epoch
                        let handler = self.handler.as_ref().unwrap();
                        let mls_client = MlsClient::new(
                            user,
                            secret_key.clone(),
                            public_key.clone(),
                            handler.db.clone(),
                            &passphrase,
                        )
                        .ok();
                        if let Some(client) = mls_client {
                            if let Ok(epoch) = client.get_group_epoch(&mls_group_id) {
                                println!("  Current epoch: {}", epoch);
                            }
                        }
                    }
                    "/epoch" => {
                        let handler = self.handler.as_ref().unwrap();
                        let mls_client = MlsClient::new(
                            user,
                            secret_key.clone(),
                            public_key.clone(),
                            handler.db.clone(),
                            &passphrase,
                        )
                        .ok();
                        if let Some(client) = mls_client {
                            match client.get_group_epoch(&mls_group_id) {
                                Ok(epoch) => println!("  Current epoch: {}", epoch),
                                Err(e) => println!("  Error getting epoch: {}", e),
                            }
                        }
                    }
                    "/help" => {
                        println!("  /fetch  - Fetch new messages");
                        println!("  /sync   - Sync epoch");
                        println!("  /epoch  - Show current epoch");
                        println!("  /quit   - Exit chat");
                    }
                    _ => {
                        println!("  Unknown command. Type /help for commands.");
                    }
                }
                continue;
            }

            // Send message
            println!("  Sending...");
            match self.do_send_message(server, user, input).await {
                Ok(()) => println!("  Sent!"),
                Err(e) => println!("  Error: {}", e),
            }
        }

        Ok(())
    }

    /// Helper: sync epoch before operations
    async fn do_epoch_sync(&mut self, server: &str, user: &str) {
        use crate::crypto::mls::MlsClient;
        use crate::crypto::Crypto;
        use base64::Engine;

        let handler = match self.handler.as_mut() {
            Some(h) => h,
            None => return,
        };

        let (secret_key, public_key, passphrase) = match (
            &handler.pgp_secret_key,
            &handler.pgp_public_key,
            &handler.pgp_passphrase,
        ) {
            (Some(sk), Some(pk), Some(pp)) => (sk.clone(), pk.clone(), pp.clone()),
            _ => return,
        };

        let mls_group_id = match handler.db.get_mls_group_id_by_server(user, server).await {
            Ok(Some(id)) => id,
            _ => return,
        };

        let mls_client = match MlsClient::new(
            user,
            secret_key.clone(),
            public_key.clone(),
            handler.db.clone(),
            &passphrase,
        ) {
            Ok(c) => c,
            Err(_) => return,
        };

        let local_epoch = mls_client.get_group_epoch(&mls_group_id).unwrap_or(0);

        // Sign and send sync request
        let sign_content = format!("{}:{}", mls_group_id, local_epoch);
        let sync_sig = match Crypto::pgp_sign_detached_secure(
            &secret_key,
            sign_content.as_bytes(),
            &passphrase,
        ) {
            Ok(s) => s,
            Err(_) => return,
        };

        if handler
            .service
            .sync_epoch_from_server(user, &mls_group_id, local_epoch as i64, &sync_sig, server)
            .await
            .is_err()
        {
            return;
        }

        // Wait briefly for response
        let timeout = std::time::Duration::from_secs(5);
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            tokio::select! {
                incoming = handler.incoming_rx.recv() => {
                    if let Some(incoming) = incoming {
                        if incoming.envelope.action == "syncEpochResponse" {
                            if let Some(content) = incoming.envelope.payload.get("content").and_then(|v| v.as_str()) {
                                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(content) {
                                    if let Some(commits) = parsed.get("commits").and_then(|v| v.as_array()) {
                                        for commit_obj in commits {
                                            if let (Some(_epoch), Some(commit_b64)) = (
                                                commit_obj.get("epoch").and_then(|v| v.as_i64()),
                                                commit_obj.get("commit").and_then(|v| v.as_str())
                                            ) {
                                                if let Ok(commit_bytes) = base64::engine::general_purpose::STANDARD.decode(commit_b64) {
                                                    if let Ok(new_epoch) = mls_client.process_commit(&mls_group_id, &commit_bytes) {
                                                        println!("  Synced to epoch {}", new_epoch);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            return;
                        } else {
                            handler.process_received_message(incoming).await;
                        }
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
            }
        }
    }

    /// Helper: fetch messages
    async fn do_fetch_messages(
        &mut self,
        server: &str,
        _user: &str,
    ) -> Result<Vec<(String, String)>> {
        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected"))?;

        handler.fetch_group_messages(server).await?;

        let timeout = std::time::Duration::from_secs(10);
        let start = std::time::Instant::now();
        let mut messages = Vec::new();

        while start.elapsed() < timeout {
            tokio::select! {
                incoming = handler.incoming_rx.recv() => {
                    if let Some(incoming) = incoming {
                        if incoming.envelope.action == "fetchGroupResponse" {
                            let msgs = handler.process_received_message(incoming).await;
                            messages.extend(msgs);
                            return Ok(messages);
                        } else {
                            handler.process_received_message(incoming).await;
                        }
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
            }
        }

        Ok(messages)
    }

    /// Helper: send a message
    async fn do_send_message(&mut self, server: &str, user: &str, message: &str) -> Result<()> {
        use crate::crypto::mls::MlsClient;
        use crate::crypto::Crypto;
        use base64::Engine;

        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected"))?;

        let (secret_key, public_key, passphrase) = match (
            &handler.pgp_secret_key,
            &handler.pgp_public_key,
            &handler.pgp_passphrase,
        ) {
            (Some(sk), Some(pk), Some(pp)) => (sk.clone(), pk.clone(), pp.clone()),
            _ => return Err(anyhow::anyhow!("PGP keys not available")),
        };

        let mls_group_id = handler
            .db
            .get_mls_group_id_by_server(user, server)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Not a member of this group"))?;

        let mls_client = MlsClient::new(
            user,
            secret_key.clone(),
            public_key.clone(),
            handler.db.clone(),
            &passphrase,
        )?;

        // Decode the group ID for MLS encryption
        let group_id_bytes = base64::engine::general_purpose::STANDARD.decode(&mls_group_id)?;

        // Encrypt message with MLS
        let encrypted = mls_client
            .encrypt_message(&group_id_bytes, message.as_bytes())
            .await?;
        let mls_ciphertext =
            base64::engine::general_purpose::STANDARD.encode(&encrypted.mls_message);

        // Sign and send - server expects signature over just ciphertext
        let signature =
            Crypto::pgp_sign_detached_secure(&secret_key, mls_ciphertext.as_bytes(), &passphrase)?;

        handler
            .service
            .send_group_message(user, &mls_ciphertext, &signature, server)
            .await?;

        // Wait briefly for confirmation
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        Ok(())
    }

    /// Invite a user to join a group
    pub async fn group_invite(
        &mut self,
        group_id: &str,
        user: &str,
        recipient: &str,
    ) -> Result<()> {
        self.load_user(user)?;

        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        // Get required keys
        let (secret_key, passphrase) = match (&handler.pgp_secret_key, &handler.pgp_passphrase) {
            (Some(sk), Some(pp)) => (sk.clone(), pp.clone()),
            _ => return Err(anyhow::anyhow!("PGP keys not available")),
        };

        // Sign the invite
        let signature = crate::crypto::Crypto::pgp_sign_detached_secure(
            &secret_key,
            format!("groupInvite:{}:{}:{}", group_id, user, recipient).as_bytes(),
            &passphrase,
        )?;

        // Send the invite
        handler
            .service
            .send_group_invite(user, recipient, group_id, Some(group_id), &signature)
            .await?;

        info!("Sent group invite to {} for group {}", recipient, group_id);
        Ok(())
    }

    /// List pending group invites
    pub async fn group_list_invites(
        &mut self,
        user: &str,
    ) -> Result<Vec<(i64, String, Option<String>, String, String)>> {
        self.load_user(user)?;

        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        let invites = handler.db.get_pending_invites(user).await?;
        Ok(invites)
    }

    /// Accept a group invite
    pub async fn group_accept_invite(&mut self, user: &str, invite_id: i64) -> Result<()> {
        use crate::crypto::mls::MlsClient;
        use base64::Engine;

        self.load_user(user)?;

        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        // Get the invite details
        let invites = handler.db.get_pending_invites(user).await?;
        let invite = invites
            .iter()
            .find(|(id, _, _, _, _)| *id == invite_id)
            .ok_or_else(|| anyhow::anyhow!("Invite not found"))?;

        let (_id, group_id, _group_name, sender, _received_at) = invite;

        // Get required keys
        let (secret_key, public_key, passphrase) = match (
            &handler.pgp_secret_key,
            &handler.pgp_public_key,
            &handler.pgp_passphrase,
        ) {
            (Some(sk), Some(pk), Some(pp)) => (sk.clone(), pk.clone(), pp.clone()),
            _ => return Err(anyhow::anyhow!("PGP keys not available")),
        };

        // Create MLS client and generate KeyPackage
        let mls_client = MlsClient::new(
            user,
            secret_key.clone(),
            public_key,
            handler.db.clone(),
            &passphrase,
        )?;
        let key_package_bytes = mls_client.generate_key_package()?;
        let key_package_b64 = base64::engine::general_purpose::STANDARD.encode(&key_package_bytes);

        // Sign the join request
        let signature = crate::crypto::Crypto::pgp_sign_detached_secure(
            &secret_key,
            key_package_bytes.as_slice(),
            &passphrase,
        )?;

        // Send join request with our KeyPackage
        handler
            .service
            .send_group_join_request(user, group_id, &key_package_b64, &signature)
            .await?;

        // Mark invite as accepted
        handler
            .db
            .update_invite_status(user, invite_id, "accepted")
            .await?;

        info!(
            "Accepted invite {} and sent join request to {} for group {}",
            invite_id, sender, group_id
        );
        Ok(())
    }

    /// List groups user is a member of
    pub async fn group_list_groups(&mut self, user: &str) -> Result<Vec<String>> {
        self.load_user(user)?;

        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        let groups = handler.db.get_user_groups(user).await?;
        Ok(groups)
    }

    /// List pending join requests
    pub async fn group_list_join_requests(
        &mut self,
        user: &str,
        group_id: Option<&str>,
    ) -> Result<Vec<(i64, String, String, String, String)>> {
        self.load_user(user)?;

        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        let requests = if let Some(gid) = group_id {
            let reqs = handler.db.get_pending_join_requests(user, gid).await?;
            reqs.into_iter()
                .map(|(id, req, kp, ts)| (id, gid.to_string(), req, kp, ts))
                .collect()
        } else {
            handler.db.get_all_pending_join_requests(user).await?
        };

        Ok(requests)
    }

    /// Approve a join request
    pub async fn group_approve_join_request(&mut self, user: &str, request_id: i64) -> Result<()> {
        use crate::crypto::mls::MlsClient;
        use base64::Engine;

        self.load_user(user)?;

        let handler = self
            .handler
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        // Get all pending requests to find the one we want
        let requests = handler.db.get_all_pending_join_requests(user).await?;
        let request = requests
            .iter()
            .find(|(id, _, _, _, _)| *id == request_id)
            .ok_or_else(|| anyhow::anyhow!("Join request not found"))?;

        let (_id, group_id, requester, key_package_b64, _requested_at) = request;

        // Get required keys
        let (secret_key, public_key, passphrase) = match (
            &handler.pgp_secret_key,
            &handler.pgp_public_key,
            &handler.pgp_passphrase,
        ) {
            (Some(sk), Some(pk), Some(pp)) => (sk.clone(), pk.clone(), pp.clone()),
            _ => return Err(anyhow::anyhow!("PGP keys not available")),
        };

        // Decode KeyPackage
        let key_package_bytes =
            base64::engine::general_purpose::STANDARD.decode(key_package_b64)?;

        // Create MLS client and add member
        let mls_client = MlsClient::new(
            user,
            secret_key.clone(),
            public_key,
            handler.db.clone(),
            &passphrase,
        )?;
        let add_result = mls_client
            .add_member_to_group(group_id, &key_package_bytes)
            .await?;

        // Sign and send Welcome
        let signature = crate::crypto::Crypto::pgp_sign_detached_secure(
            &secret_key,
            add_result.welcome.welcome_bytes.as_bytes(),
            &passphrase,
        )?;

        handler
            .service
            .send_mls_welcome(user, requester, &add_result.welcome, &signature)
            .await?;

        // Update request status and add membership
        handler
            .db
            .update_join_request_status(user, request_id, "approved")
            .await?;
        handler
            .db
            .add_group_membership(user, group_id, requester, None, true, "member")
            .await?;

        info!(
            "Approved join request {} from {} for group {}",
            request_id, requester, group_id
        );
        Ok(())
    }
}

pub async fn run_cli(cli: Cli) -> Result<()> {
    let mut app = CliApp::new();

    // Connect to mixnet first
    app.connect().await?;

    match cli.command {
        Commands::Register { username } => {
            let handler = app
                .handler
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;
            handler.register_user(&username).await?;
        }

        Commands::Login { username } => {
            app.login(&username).await?;
        }

        Commands::Send {
            from,
            recipient,
            message,
        } => {
            app.send_message(&from, &recipient, &message).await?;
            // Wait for message to be transmitted through mixnet before shutting down
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        }

        Commands::Query { username } => {
            app.query_user(&username).await?;
        }

        Commands::Listen { username, duration } => {
            app.listen(&username, duration).await?;
        }

        Commands::Handshake { from, recipient } => {
            app.send_handshake(&from, &recipient).await?;
        }

        Commands::Group { action } => match action {
            GroupCommands::Register { server, user } => {
                app.group_register(&server, &user).await?;
            }
            GroupCommands::Send {
                server,
                user,
                message,
            } => {
                app.group_send(&server, &user, &message).await?;
            }
            GroupCommands::Fetch { server, user } => {
                app.group_fetch(&server, &user).await?;
            }
            GroupCommands::Stats { server, user } => {
                app.group_stats(&server, &user).await?;
            }
            GroupCommands::Init { server, user } => {
                let group_id = app.group_init(&server, &user).await?;
                println!(
                    "Initialized MLS group for server {} as admin {}",
                    server, user
                );
                println!("Group ID: {}", group_id);
            }
            GroupCommands::Approve {
                server,
                user,
                username_to_approve,
            } => {
                app.group_approve(&server, &user, &username_to_approve)
                    .await?;
                println!(
                    "Approved {} for group server {}",
                    username_to_approve, server
                );
            }
            GroupCommands::Invite {
                group_id,
                user,
                recipient,
            } => {
                app.group_invite(&group_id, &user, &recipient).await?;
                println!("Sent invite to {} for group {}", recipient, group_id);
            }
            GroupCommands::ListInvites { user } => {
                let invites = app.group_list_invites(&user).await?;
                if invites.is_empty() {
                    println!("No pending invites");
                } else {
                    println!("Pending invites:");
                    for (id, group_id, group_name, sender, received_at) in invites {
                        println!(
                            "  [{}] From: {}, Group: {} ({}), Received: {}",
                            id,
                            sender,
                            group_name.as_deref().unwrap_or("unnamed"),
                            group_id,
                            received_at
                        );
                    }
                }
            }
            GroupCommands::AcceptInvite { user, invite_id } => {
                app.group_accept_invite(&user, invite_id).await?;
                println!("Accepted invite {} and sent join request", invite_id);
            }
            GroupCommands::ListGroups { user } => {
                let groups = app.group_list_groups(&user).await?;
                if groups.is_empty() {
                    println!("Not a member of any groups");
                } else {
                    println!("Your groups:");
                    for group_id in groups {
                        println!("  {}", group_id);
                    }
                }
            }
            GroupCommands::ListJoinRequests { user, group_id } => {
                let requests = app
                    .group_list_join_requests(&user, group_id.as_deref())
                    .await?;
                if requests.is_empty() {
                    println!("No pending join requests");
                } else {
                    println!("Pending join requests:");
                    for (id, gid, requester, _, requested_at) in requests {
                        println!(
                            "  [{}] From: {}, Group: {}, Requested: {}",
                            id, requester, gid, requested_at
                        );
                    }
                }
            }
            GroupCommands::ApproveJoinRequest { user, request_id } => {
                app.group_approve_join_request(&user, request_id).await?;
                println!("Approved join request {} and sent Welcome", request_id);
            }
            GroupCommands::Join { server, user } => {
                app.group_join(&server, &user).await?;
                println!("Successfully joined group at server {}", server);
            }
            GroupCommands::Chat { server, user } => {
                app.group_chat_interactive(&server, &user).await?;
            }
        },
    }

    Ok(())
}
