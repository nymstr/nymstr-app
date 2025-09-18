//! High-level handler for user registration, login, messaging, and queries
#![allow(dead_code)]
use crate::crypto::{Crypto, EncryptedMessage};
use mls_rs::{Client, ExtensionList, MlsMessage, CipherSuite, CryptoProvider, CipherSuiteProvider};
use mls_rs::client_builder::MlsConfig;
use mls_rs::identity::MlsCredential;
use mls_rs::group::ReceivedMessage;
use mls_rs_crypto_openssl::OpensslCryptoProvider;
use mls_rs_provider_sqlite::{SqLiteDataStorageEngine, connection_strategy::FileConnectionStrategy};
use crate::crypto::mls::KeyPackageManager;
// TODO: Update message handler to use MlsClient instead of removed GroupManager
use crate::core::db::Db;
use crate::core::mixnet_client::{Incoming, MixnetService};
use anyhow::{Result, anyhow};
use chrono::Utc;
use serde_json::{Value, json};
use tokio::sync::mpsc::Receiver;

use pgp::composed::{SignedSecretKey, SignedPublicKey};

/// Handles user state, persistence, and mixnet interactions
pub struct MessageHandler {
    /// Crypto utilities
    pub crypto: Crypto,
    /// Underlying mixnet service client
    pub service: MixnetService,
    /// Incoming message receiver
    pub incoming_rx: Receiver<Incoming>,
    /// Database for persistence
    pub db: std::sync::Arc<Db>,
    /// Currently logged-in username
    pub current_user: Option<String>,
    /// Our own nym address
    pub nym_address: Option<String>,
    /// MLS signing identity and storage path (will create client fresh when needed)
    pub mls_storage_path: Option<String>,
    /// Optional user's PGP public key
    pub pgp_public_key: Option<SignedPublicKey>,
    /// Optional user's PGP secret key for signing
    pub pgp_secret_key: Option<SignedSecretKey>,
    /// MLS key package manager
    pub key_package_manager: KeyPackageManager,
}

impl MessageHandler {
    /// Create a new handler by wrapping the mixnet service and DB
    pub async fn new(
        service: MixnetService,
        incoming_rx: Receiver<Incoming>,
        db_path: &str,
    ) -> anyhow::Result<Self> {
        let db = std::sync::Arc::new(Db::open(db_path).await?);
        db.init_global().await?;
        Ok(Self {
            crypto: Crypto,
            service,
            incoming_rx,
            key_package_manager: KeyPackageManager::new(db.clone()),
            mls_storage_path: None, // Will be set when user logs in
            db,
            current_user: None,
            nym_address: None,
            pgp_public_key: None,
            pgp_secret_key: None,
        })
    }

    /// Create an MLS client following the official mls-rs pattern
    async fn create_mls_client(&self) -> anyhow::Result<Client<impl MlsConfig + use<>>> {
        let username = self.current_user.as_ref()
            .ok_or_else(|| anyhow!("No user logged in"))?;
        let storage_path = self.mls_storage_path.as_ref()
            .ok_or_else(|| anyhow!("MLS storage not initialized"))?;
        let pgp_secret_key = self.pgp_secret_key.as_ref()
            .ok_or_else(|| anyhow!("PGP key not available"))?;
        let pgp_public_key = self.pgp_public_key.as_ref()
            .ok_or_else(|| anyhow!("PGP public key not available"))?;

        let crypto_provider = OpensslCryptoProvider::default();
        let cipher_suite = CipherSuite::CURVE25519_AES128;
        let cipher_suite_provider = crypto_provider.cipher_suite_provider(cipher_suite)
            .ok_or_else(|| anyhow!("Cipher suite not supported"))?;

        // Generate MLS signature keys
        let (secret_key, public_key) = cipher_suite_provider.signature_key_generate()
            .map_err(|e| anyhow!("Failed to generate MLS signature keys: {}", e))?;

        // Create PGP credential for MLS (reusing the credential creation from our wrapper)
        let pgp_credential = crate::crypto::mls::client::PgpCredential::new(username.clone(), pgp_public_key)?;
        let credential = pgp_credential.into_credential()?;
        let signing_identity = mls_rs::identity::SigningIdentity::new(credential, public_key);

        // Create storage engine
        let connection_strategy = FileConnectionStrategy::new(std::path::Path::new(storage_path));
        let storage_engine = SqLiteDataStorageEngine::new(connection_strategy)
            .map_err(|e| anyhow!("Failed to create MLS storage engine: {}", e))?;

        // Build the official mls-rs client
        Ok(Client::builder()
            .group_state_storage(storage_engine.group_state_storage()
                .map_err(|e| anyhow!("Failed to create group storage: {}", e))?)
            .key_package_repo(storage_engine.key_package_storage()
                .map_err(|e| anyhow!("Failed to create key package storage: {}", e))?)
            .psk_store(storage_engine.pre_shared_key_storage()
                .map_err(|e| anyhow!("Failed to create PSK storage: {}", e))?)
            .identity_provider(crate::crypto::mls::client::PgpIdentityProvider)
            .crypto_provider(crypto_provider)
            .signing_identity(signing_identity, secret_key, cipher_suite)
            .build())
    }

    /// Register a new user via the mixnet service, awaiting server responses
    pub async fn register_user(&mut self, username: &str) -> anyhow::Result<bool> {
        // Generate PGP keypair and initialize MLS crypto
        let (secret_key, public_key) = Crypto::generate_pgp_keypair(username)?;
        // Store keys in handler for signing
        self.pgp_public_key = Some(public_key.clone());
        self.pgp_secret_key = Some(secret_key.clone());
        // Initialize MLS storage path for client creation
        self.mls_storage_path = Some(crate::core::db::get_mls_db_path(username));
        // Get armored public key
        let public_key_armored = Crypto::pgp_public_key_armored(&public_key)?;
        // Persist and send the public key in armored format
        self.db.register_user(username, &public_key_armored).await?;
        self.service
            .send_registration_request(username, &public_key_armored)
            .await?;
        // Await server challenge and responses with timeout and Ctrl+C handling
        let timeout_duration = std::time::Duration::from_secs(30);
        loop {
            tokio::select! {
                incoming = self.incoming_rx.recv() => {
                    if let Some(incoming) = incoming {
                        let env = incoming.envelope;
                        let action = env.action.as_str();
                        match action {
                            "challenge" => {
                                if let Some(context) = env.payload.get("context").and_then(|v| v.as_str()) {
                                    if context == "registration" {
                                        if let Some(nonce) = env.payload.get("nonce").and_then(|v| v.as_str()) {
                                            self.process_register_challenge(username, nonce).await?;
                                        }
                                    }
                                }
                            }
                            "challengeResponse" => {
                                if let Some(context) = env.payload.get("context").and_then(|v| v.as_str()) {
                                    if context == "registration" {
                                        if let Some(result) = env.payload.get("result").and_then(|v| v.as_str()) {
                                            return self.process_register_response(username, result).await;
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    } else {
                        // Channel closed
                        return Ok(false);
                    }
                }
                _ = tokio::time::sleep(timeout_duration) => {
                    println!("Registration timed out after 30 seconds");
                    return Ok(false);
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("Registration cancelled by user");
                    return Ok(false);
                }
            }
        }
    }

    /// Login an existing user via the mixnet service, awaiting server response
    pub async fn login_user(&mut self, username: &str) -> anyhow::Result<bool> {
        // Ensure current user is set and generate PGP keys for this session
        self.current_user = Some(username.to_string());
        // Generate PGP keypair for this session
        let (secret_key, public_key) = Crypto::generate_pgp_keypair(username)?;
        self.pgp_public_key = Some(public_key.clone());
        self.pgp_secret_key = Some(secret_key.clone());
        // Initialize MLS storage path for client creation
        self.mls_storage_path = Some(crate::core::db::get_mls_db_path(username));

        // Send initial login request
        self.service.send_login_request(username).await?;
        // Await server challenge and responses with timeout and Ctrl+C handling
        let timeout_duration = std::time::Duration::from_secs(30);
        loop {
            tokio::select! {
                incoming = self.incoming_rx.recv() => {
                    if let Some(incoming) = incoming {
                        let env = incoming.envelope;
                        let action = env.action.as_str();
                        match action {
                            "challenge" => {
                                if let Some(context) = env.payload.get("context").and_then(|v| v.as_str()) {
                                    if context == "login" {
                                        if let Some(nonce) = env.payload.get("nonce").and_then(|v| v.as_str()) {
                                            self.process_login_challenge(nonce).await?;
                                        }
                                    }
                                }
                            }
                            "challengeResponse" => {
                                if let Some(context) = env.payload.get("context").and_then(|v| v.as_str()) {
                                    if context == "login" {
                                        if let Some(result) = env.payload.get("result").and_then(|v| v.as_str()) {
                                            return self.process_login_response(username, result).await;
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    } else {
                        // Channel closed
                        return Ok(false);
                    }
                }
                _ = tokio::time::sleep(timeout_duration) => {
                    println!("Login timed out after 30 seconds");
                    return Ok(false);
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("Login cancelled by user");
                    return Ok(false);
                }
            }
        }
    }

    /// Query for a user's public key via the mixnet service, awaiting server response
    pub async fn query_user(&mut self, username: &str) -> anyhow::Result<Option<(String, String)>> {
        // Send query request
        self.service.send_query_request(username).await?;
        // Await server's query response with timeout and Ctrl+C handling
        let timeout_duration = std::time::Duration::from_secs(15);
        loop {
            tokio::select! {
                incoming = self.incoming_rx.recv() => {
                    if let Some(incoming) = incoming {
                        let env = incoming.envelope;
                        let action = env.action.as_str();
                        match action {
                            "queryResponse" => {
                                if let (Some(user), Some(pk)) = (
                                    env.payload.get("username").and_then(|u| u.as_str()),
                                    env.payload.get("publicKey").and_then(|k| k.as_str()),
                                ) {
                                    let res = (user.to_string(), pk.to_string());
                                    if let Some(me) = &self.current_user {
                                        let _ = self.db.add_contact(me, user, pk).await;
                                    }
                                    return Ok(Some(res));
                                }
                                return Ok(None);
                            }
                            _ => {}
                        }
                    } else {
                        // Channel closed
                        return Ok(None);
                    }
                }
                _ = tokio::time::sleep(timeout_duration) => {
                    println!("User query timed out after 15 seconds");
                    return Ok(None);
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("User query cancelled by user");
                    return Ok(None);
                }
            }
        }
    }

    /// Send a direct (encrypted) message to a contact using MLS
    pub async fn send_direct_message(
        &mut self,
        recipient: &str,
        message_content: &str,
    ) -> anyhow::Result<()> {
        let user = self.current_user.as_deref().unwrap_or("").to_string();

        // Check if we have an established conversation with this recipient
        // Use normalized conversation ID (consistent with handshake)
        let conversation_id = if user.as_str() < recipient {
            format!("{}-{}", user, recipient)
        } else {
            format!("{}-{}", recipient, user)
        };
        // Check if MLS group exists for this conversation
        let client = self.create_mls_client().await?;
        let group_id = conversation_id.as_bytes();
        let conversation_exists = client.load_group(group_id).is_ok();

        if !conversation_exists {
            // Need to establish MLS group first
            log::info!("No existing conversation with {}, initiating MLS handshake", recipient);
            self.establish_mls_conversation(recipient).await?;
        }

        // Persist the outgoing plaintext message locally
        self.db
            .save_message(&user, recipient, true, message_content, Utc::now())
            .await?;

        // Load the group for this conversation (reuse group_id from earlier)
        // Note: client was already created above for the existence check
        let mut group = match client.load_group(group_id) {
            Ok(group) => group,
            Err(_) => return Err(anyhow!("No MLS group found for conversation {}", conversation_id)),
        };

        // Wrap plaintext in type/message JSON
        let wrapped = json!({"type": 0, "message": message_content});
        let wrapped_str = wrapped.to_string();

        // Encrypt message using MLS group
        let mls_message = group.encrypt_application_message(wrapped_str.as_bytes(), Default::default())?;

        // Convert to EncryptedMessage format expected by service
        let encrypted_message = EncryptedMessage {
            conversation_id: conversation_id.as_bytes().to_vec(),
            mls_message: mls_message.to_bytes()?,
            message_type: crate::crypto::MlsMessageType::Application,
        };

        // Sign the message content for authentication (PGP signature)
        let signature = if let Some(secret_key) = &self.pgp_secret_key {
            Crypto::pgp_sign_detached(secret_key, message_content.as_bytes())?
        } else {
            return Err(anyhow!("PGP secret key not available for signing"));
        };

        // Send MLS encrypted message using unified format
        self.service
            .send_mls_message(&user, recipient, &encrypted_message, &signature)
            .await?;
        Ok(())
    }

    /// Send a handshake (type=1) encrypted message to establish p2p routing using MLS
    pub async fn send_handshake(&self, recipient: &str) -> anyhow::Result<()> {
        let user = self.current_user.as_deref().unwrap_or("");
        // Ensure our own nym address is set
        let nym_addr = self.nym_address.clone().unwrap_or_default();
        
        // Create MLS client
        let client = self.create_mls_client().await?;

        // Use conversation ID based on user pair (normalized for consistency)
        let conversation_id = if user < recipient {
            format!("{}-{}", user, recipient)
        } else {
            format!("{}-{}", recipient, user)
        };
        let group_id = conversation_id.as_bytes();

        // Load or create group for this conversation
        let mut group = match client.load_group(group_id) {
            Ok(group) => group,
            Err(_) => {
                // Create new group for this conversation with our conversation ID
                client.create_group_with_id(
                    conversation_id.as_bytes().to_vec(),
                    ExtensionList::default(),
                    Default::default(),
                    None
                )?
            }
        };

        // Construct inner handshake payload with type=1
        let handshake = json!({"type": 1, "message": nym_addr});
        let handshake_str = handshake.to_string();

        // Encrypt using MLS
        let encrypted_message = group.encrypt_application_message(handshake_str.as_bytes(), Default::default())?;
        
        // Build payload with MLS message
        let mls_message_bytes = encrypted_message.to_bytes()?;
        let payload = json!({
            "sender": user,
            "recipient": recipient,
            "body": {
                "conversation_id": conversation_id,
                "mls_message": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &mls_message_bytes),
                "message_type": "handshake"
            },
            "encrypted": true,
            "mls": true
        });

        // Save group state after encryption
        group.write_to_storage()?;

        // Sign with PGP
        let payload_str = payload.to_string();
        let signature = if let Some(secret_key) = &self.pgp_secret_key {
            Crypto::pgp_sign_detached(secret_key, payload_str.as_bytes())?
        } else {
            return Err(anyhow!("PGP secret key not available for signing"));
        };
        
        // Send encrypted handshake
        self.service
            .send_direct_message(recipient, &payload_str, &signature)
            .await?;
        Ok(())
    }

    /// Establish MLS conversation with recipient through key package exchange
    async fn establish_mls_conversation(&mut self, recipient: &str) -> anyhow::Result<()> {
        let user = self.current_user.as_deref().unwrap_or("");

        // Create MLS client
        let client = self.create_mls_client().await?;

        // Generate our key package
        let our_key_package = client.generate_key_package_message(Default::default(), Default::default(), None)?;

        // Sign the key package request
        let signature = if let Some(secret_key) = &self.pgp_secret_key {
            Crypto::pgp_sign_detached(secret_key, &our_key_package.to_bytes()?)?
        } else {
            return Err(anyhow!("PGP secret key not available for signing"));
        };

        // Send key package request to recipient
        let key_package_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &our_key_package.to_bytes()?);
        self.service.send_key_package_request(user, recipient, &key_package_b64, &signature).await?;

        // Wait for key package response
        let timeout_duration = std::time::Duration::from_secs(30);
        loop {
            tokio::select! {
                incoming = self.incoming_rx.recv() => {
                    if let Some(incoming) = incoming {
                        let env = incoming.envelope;

                        if env.action == "keyPackageResponse" && env.sender == recipient {
                            if let Some(recipient_key_package) = env.payload.get("recipientKeyPackage")
                                .and_then(|v| v.as_str()) {

                                // Validate the received key package
                                if !self.key_package_manager.validate_key_package(recipient_key_package)? {
                                    return Err(anyhow!("Invalid key package from {}", recipient));
                                }

                                // Store the recipient's key package
                                self.key_package_manager.store_key_package(recipient, recipient_key_package)?;

                                // Parse recipient's key package
                                let key_package_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, recipient_key_package)
                                    .map_err(|e| anyhow!("Failed to decode key package: {}", e))?;
                                let recipient_key_package = mls_rs::MlsMessage::from_bytes(&key_package_bytes)?;

                                // Create new MLS group with our conversation ID
                                let conversation_id = if user < recipient {
                                    format!("{}-{}", user, recipient)
                                } else {
                                    format!("{}-{}", recipient, user)
                                };
                                let mut group = client.create_group_with_id(
                                    conversation_id.as_bytes().to_vec(),
                                    ExtensionList::default(),
                                    Default::default(),
                                    None
                                )?;

                                // Add recipient to the group
                                let commit = group
                                    .commit_builder()
                                    .add_member(recipient_key_package)?
                                    .build()?;

                                // Apply the commit
                                group.apply_pending_commit()?;

                                // Save group state
                                group.write_to_storage()?;

                                // Send welcome message to recipient
                                if let Some(welcome_message) = commit.welcome_messages.first() {
                                    let welcome_bytes = welcome_message.to_bytes()?;
                                    let welcome_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &welcome_bytes);
                                    let group_id = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, group.group_id());

                                    let welcome_signature = if let Some(secret_key) = &self.pgp_secret_key {
                                        Crypto::pgp_sign_detached(secret_key, &welcome_bytes)?
                                    } else {
                                        return Err(anyhow!("PGP secret key not available for signing"));
                                    };

                                    self.service.send_group_welcome(
                                        user, recipient, &welcome_b64, &group_id, &welcome_signature
                                    ).await?;
                                }

                                log::info!("Sent welcome message to {}, waiting for join confirmation", recipient);
                                // Continue waiting for groupJoinResponse - don't return here
                            }
                        }
                        else if env.action == "groupJoinResponse" && env.sender == recipient {
                            if let Some(success) = env.payload.get("success").and_then(|v| v.as_bool()) {
                                if success {
                                    log::info!("Received join confirmation from {}, MLS handshake complete", recipient);
                                    return Ok(());
                                } else {
                                    return Err(anyhow!("Recipient {} failed to join MLS group", recipient));
                                }
                            }
                        }
                    }
                }
                _ = tokio::time::sleep(timeout_duration) => {
                    return Err(anyhow!("MLS handshake timed out with {}", recipient));
                }
                _ = tokio::signal::ctrl_c() => {
                    return Err(anyhow!("MLS handshake cancelled by user"));
                }
            }
        }
    }

    /// Handle incoming key package request
    async fn handle_key_package_request(&mut self, sender: &str, sender_key_package: &str) -> anyhow::Result<()> {
        let user = self.current_user.as_deref().unwrap_or("");

        // Create MLS client
        let client = self.create_mls_client().await?;

        // Validate the sender's key package
        if !self.key_package_manager.validate_key_package(sender_key_package)? {
            return Err(anyhow!("Invalid key package from {}", sender));
        }

        // Store the sender's key package
        self.key_package_manager.store_key_package(sender, sender_key_package)?;

        // Generate our key package
        let our_key_package = client.generate_key_package_message(Default::default(), Default::default(), None)?;

        // Sign the response
        let signature = if let Some(secret_key) = &self.pgp_secret_key {
            Crypto::pgp_sign_detached(secret_key, &our_key_package.to_bytes()?)?
        } else {
            return Err(anyhow!("PGP secret key not available for signing"));
        };

        // Send key package response
        let our_key_package_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &our_key_package.to_bytes()?);
        self.service.send_key_package_response(
            user, sender, sender_key_package, &our_key_package_b64, &signature
        ).await?;

        log::info!("Sent key package response to {}", sender);
        Ok(())
    }

    /// Handle incoming group welcome message
    async fn handle_group_welcome(&mut self, sender: &str, welcome_message: &str, group_id: &str) -> anyhow::Result<()> {
        let user = self.current_user.as_deref().unwrap_or("");

        // Create MLS client
        let client = self.create_mls_client().await?;

        // Decode welcome message
        let welcome_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, welcome_message)
            .map_err(|e| anyhow!("Failed to decode welcome message: {}", e))?;
        let welcome_msg = mls_rs::MlsMessage::from_bytes(&welcome_bytes)?;

        // Join the group with the welcome message
        let (mut group, _) = client.join_group(None, &welcome_msg, None)?;

        // Save group state
        group.write_to_storage()?;

        // Store conversation state
        // TODO: Use MlsClient to store conversation state
        // self.group_manager.store_conversation_state(
        //     user, &conversation_info, &group_state
        // ).await?;

        // Send confirmation
        let signature = if let Some(secret_key) = &self.pgp_secret_key {
            Crypto::pgp_sign_detached(secret_key, group_id.as_bytes())?
        } else {
            return Err(anyhow!("PGP secret key not available for signing"));
        };
        self.service.send_group_join_response(user, sender, group_id, true, &signature).await?;

        log::info!("Successfully joined MLS conversation with {}", sender);
        Ok(())
    }

    // Helpers to keep the match arms clean:
    async fn process_register_challenge(
        &mut self,
        username: &str,
        nonce: &str,
    ) -> anyhow::Result<()> {
        let secret_key = self.pgp_secret_key.as_ref().unwrap();
        let signature = Crypto::pgp_sign_detached(secret_key, nonce.as_bytes())?;
        self.service
            .send_registration_response(username, &signature)
            .await?;
        Ok(())
    }

    async fn process_register_response(
        &mut self,
        username: &str,
        result: &str,
    ) -> anyhow::Result<bool> {
        if result == "success" {
            // MLS crypto is already initialized during registration
            self.db.init_user(username).await?;
            self.current_user = Some(username.to_string());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn process_login_challenge(&mut self, nonce: &str) -> anyhow::Result<()> {
        let secret_key = self.pgp_secret_key.as_ref().unwrap();
        let signature = Crypto::pgp_sign_detached(secret_key, nonce.as_bytes())?;
        self.service
            .send_login_response(self.current_user.as_deref().unwrap(), &signature)
            .await?;
        Ok(())
    }

    async fn process_login_response(
        &mut self,
        username: &str,
        result: &str,
    ) -> anyhow::Result<bool> {
        if result == "success" {
            self.db.init_user(username).await?;
            self.current_user = Some(username.to_string());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Handle the queryResponse "action" from the server (context = "query").
    async fn process_query_response(
        &mut self,
        content: &str,
    ) -> anyhow::Result<Option<(String, String)>> {
        if let Ok(v) = serde_json::from_str::<Value>(content) {
            if let (Some(user), Some(pk)) = (
                v.get("username").and_then(|u| u.as_str()),
                v.get("publicKey").and_then(|k| k.as_str()),
            ) {
                if let Some(me) = &self.current_user {
                    let _ = self.db.add_contact(me, user, pk).await;
                }
                return Ok(Some((user.to_string(), pk.to_string())));
            }
        }
        Ok(None)
    }

    /// Dispatch a single incoming envelope and return decrypted chat messages.
    pub async fn process_received_message(&mut self, incoming: Incoming) -> Vec<(String, String)> {
        let ts = incoming.ts;
        match self.decrypt_and_verify(incoming).await {
            Ok(Some((sender, ChatMsg::Text(msg)))) => {
                let user = self.current_user.as_deref().unwrap_or("");
                let _ = self.db.save_message(user, &sender, false, &msg, ts).await;
                vec![(sender, msg)]
            }
            Ok(Some((_sender, ChatMsg::Handshake(addr)))) => {
                self.nym_address = Some(addr);
                vec![]
            }
            _ => vec![],
        }
    }

    async fn decrypt_and_verify(
        &mut self,
        incoming: Incoming,
    ) -> Result<Option<(String, ChatMsg)>> {
        let env = incoming.envelope;
        // Handle server responses (these are processed elsewhere via incoming_rx channel)
        match env.action.as_str() {
            "challenge" | "challengeResponse" | "queryResponse" | "loginResponse" | "sendResponse" => {
                log::debug!("Received server response action: {}", env.action);
                return Ok(None);
            }
            "keyPackageRequest" => {
                // Handle incoming key package request for MLS handshake
                if let Some(sender_key_package) = env.payload.get("senderKeyPackage").and_then(|v| v.as_str()) {
                    if let Err(e) = self.handle_key_package_request(&env.sender, sender_key_package).await {
                        log::error!("Failed to handle key package request from {}: {}", env.sender, e);
                    }
                }
                return Ok(None);
            }
            "groupWelcome" => {
                // Handle incoming group welcome message
                if let (Some(welcome_message), Some(group_id)) = (
                    env.payload.get("welcomeMessage").and_then(|v| v.as_str()),
                    env.payload.get("groupId").and_then(|v| v.as_str())
                ) {
                    if let Err(e) = self.handle_group_welcome(&env.sender, welcome_message, group_id).await {
                        log::error!("Failed to handle group welcome from {}: {}", env.sender, e);
                    }
                }
                return Ok(None);
            }
            "send" | "incomingMessage" => {
                // Continue processing as chat message
            }
            _ => {
                log::warn!("Unknown action received: {}", env.action);
                return Ok(None);
            }
        }
        
        // Check if this is a message type in the unified format
        if env.message_type != "message" {
            return Ok(None);
        }

        // Extract MLS message from payload
        let conversation_id = env.payload.get("conversation_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing conversation_id in message payload"))?;

        let mls_message = env.payload.get("mls_message")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing mls_message in message payload"))?;

        // For unified format, sender information is in the envelope
        let sender = env.sender.clone();

        // Try to decrypt the MLS message
        // Create a payload for MLS decryption that matches expected format
        let mls_payload = json!({
            "body": {
                "conversation_id": conversation_id,
                "mls_message": mls_message
            },
            "sender": sender
        });

        return self.decrypt_mls_message(mls_payload, sender).await;
    }
    
    async fn decrypt_mls_message(
        &self,
        payload: Value,
        sender: String,
    ) -> Result<Option<(String, ChatMsg)>> {
        let body = &payload["body"];
        
        // Extract MLS message components
        let conversation_id_b64 = body["conversation_id"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing conversation_id"))?;
        let mls_message_b64 = body["mls_message"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing mls_message"))?;
        
        let conversation_id = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, conversation_id_b64)?;
        let mls_message = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, mls_message_b64)?;
        
        // Create MLS client
        let client = self.create_mls_client().await?;

        // Parse MLS message
        let mls_msg = mls_rs::MlsMessage::from_bytes(&mls_message)?;

        // Load the group for this conversation
        let mut group = match client.load_group(&conversation_id) {
            Ok(group) => group,
            Err(_) => return Err(anyhow!("No MLS group found for conversation")),
        };

        // Process the incoming message
        let processed = group.process_incoming_message(mls_msg)?;

        // Save group state after processing
        group.write_to_storage()?;

        // Extract decrypted content if it's an application message
        let decrypted = match processed {
            ReceivedMessage::ApplicationMessage(app_msg) => app_msg.data().to_vec(),
            _ => return Ok(None), // Not an application message
        };
        let text = String::from_utf8(decrypted)?;
        let msg_val: Value = serde_json::from_str(&text)?;

        if let Some(msg_type) = msg_val["type"].as_i64() {
            let content = msg_val["message"].as_str().unwrap_or("").to_string();
            let chat_msg = match msg_type {
                0 => ChatMsg::Text(content),
                1 => ChatMsg::Handshake(content),
                _ => return Ok(None),
            };
            Ok(Some((sender, chat_msg)))
        } else {
            Ok(None)
        }
    }

    /// Authenticate with group server (register + connect)
    pub async fn authenticate_group(&mut self, username: &str, group_server_address: &str) -> anyhow::Result<bool> {
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

        let public_key_armored = Crypto::pgp_public_key_armored(public_key)?;

        // TODO: Group functionality needs to be redesigned for unified format
        log::warn!("Group functionality not yet implemented in unified format");

        Ok(true)
    }

    /// Send a message to the group
    pub async fn send_group_message(&mut self, message: &str, group_server_address: &str) -> anyhow::Result<()> {
        // For now, send the message as plaintext ciphertext
        // In a real implementation, this would be encrypted
        self.service.send_group_message(message, group_server_address).await?;
        Ok(())
    }

    /// Get group server fanout statistics
    pub async fn get_group_stats(&mut self, group_server_address: &str) -> anyhow::Result<()> {
        self.service.get_group_stats(group_server_address).await?;
        Ok(())
    }
}

enum ChatMsg {
    Text(String),
    Handshake(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_struct_creation() {
        let crypto = Crypto;
        assert!(matches!(crypto, Crypto));
    }

    #[test]
    fn test_encrypted_message_serialization() {
        let encrypted = EncryptedMessage {
            conversation_id: b"test_conversation".to_vec(),
            mls_message: b"test_mls_message".to_vec(),
            message_type: crate::crypto::MlsMessageType::Application,
        };
        
        let serialized = serde_json::to_string(&encrypted).unwrap();
        assert!(serialized.contains("conversation_id"));
        assert!(serialized.contains("mls_message"));
        assert!(serialized.contains("Application"));
    }

    #[test]
    fn test_encrypted_message_deserialization() {
        let json = r#"{"conversation_id":[116,101,115,116],"mls_message":[116,101,115,116],"message_type":"Application"}"#;
        let encrypted: EncryptedMessage = serde_json::from_str(json).unwrap();
        
        assert_eq!(encrypted.conversation_id, b"test");
        assert_eq!(encrypted.mls_message, b"test");
        assert!(matches!(encrypted.message_type, crate::crypto::MlsMessageType::Application));
    }

    #[test]
    fn test_chat_msg_enum() {
        let text_msg = ChatMsg::Text("hello".to_string());
        let handshake_msg = ChatMsg::Handshake("handshake_data".to_string());
        
        match text_msg {
            ChatMsg::Text(ref content) => assert_eq!(content, "hello"),
            _ => panic!("Expected text message"),
        }
        
        match handshake_msg {
            ChatMsg::Handshake(ref content) => assert_eq!(content, "handshake_data"),
            _ => panic!("Expected handshake message"),
        }
    }

    #[tokio::test]
    async fn test_json_parsing_for_registration() {
        let json = r#"{"nonce":"test_nonce_123"}"#;
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        let nonce = v.get("nonce").and_then(|n| n.as_str());
        assert_eq!(nonce, Some("test_nonce_123"));
    }

    #[tokio::test]
    async fn test_json_parsing_for_query_response() {
        let json = r#"{"username":"alice","publicKey":"pk_alice"}"#;
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        
        let username = v.get("username").and_then(|u| u.as_str());
        let public_key = v.get("publicKey").and_then(|k| k.as_str());
        
        assert_eq!(username, Some("alice"));
        assert_eq!(public_key, Some("pk_alice"));
    }

    #[tokio::test]
    async fn test_message_payload_construction() {
        let payload = json!({
            "type": 0,
            "message": "hello world"
        });
        
        let payload_str = payload.to_string();
        assert!(payload_str.contains("\"type\":0"));
        assert!(payload_str.contains("hello world"));
    }

    #[tokio::test]
    async fn test_encrypted_body_construction() {
        let encrypted_body = json!({
            "iv": "test_iv",
            "ciphertext": "test_ciphertext",
            "tag": "test_tag"
        });
        
        assert_eq!(encrypted_body["iv"], "test_iv");
        assert_eq!(encrypted_body["ciphertext"], "test_ciphertext");
        assert_eq!(encrypted_body["tag"], "test_tag");
    }

    #[tokio::test]
    async fn test_nested_payload_construction() {
        let encrypted_body = json!({
            "iv": "test_iv",
            "ciphertext": "test_ciphertext",
            "tag": "test_tag"
        });
        
        let nested = json!({
            "ephemeralPublicKey": "test_ephemeral_pk",
            "salt": "test_salt",
            "encryptedBody": encrypted_body
        });
        
        assert_eq!(nested["ephemeralPublicKey"], "test_ephemeral_pk");
        assert_eq!(nested["salt"], "test_salt");
        assert_eq!(nested["encryptedBody"]["iv"], "test_iv");
    }

    #[tokio::test]
    async fn test_full_message_payload_construction() {
        let body = json!({
            "encryptedPayload": {
                "ephemeralPublicKey": "test_pk",
                "salt": "test_salt",
                "encryptedBody": {
                    "iv": "test_iv",
                    "ciphertext": "test_ciphertext",
                    "tag": "test_tag"
                }
            },
            "payloadSignature": "test_signature"
        });
        
        let payload = json!({
            "sender": "alice",
            "recipient": "bob",
            "body": body,
            "encrypted": true
        });
        
        assert_eq!(payload["sender"], "alice");
        assert_eq!(payload["recipient"], "bob");
        assert_eq!(payload["encrypted"], true);
        assert_eq!(payload["body"]["payloadSignature"], "test_signature");
    }

    #[tokio::test]
    async fn test_handshake_message_construction() {
        let handshake = json!({
            "type": 1,
            "message": "nym_address_123"
        });
        
        assert_eq!(handshake["type"], 1);
        assert_eq!(handshake["message"], "nym_address_123");
    }

    #[tokio::test]
    async fn test_group_message_format() {
        let group_msg = json!({
            "action": "sendGroup",
            "ciphertext": "encrypted_group_message"
        });
        
        assert_eq!(group_msg["action"], "sendGroup");
        assert_eq!(group_msg["ciphertext"], "encrypted_group_message");
    }

    #[tokio::test]
    async fn test_group_registration_format() {
        let register_msg = json!({
            "action": "register",
            "username": "test_user",
            "publicKey": "test_public_key",
            "signature": "test_signature"
        });
        
        assert_eq!(register_msg["action"], "register");
        assert_eq!(register_msg["username"], "test_user");
        assert_eq!(register_msg["publicKey"], "test_public_key");
        assert_eq!(register_msg["signature"], "test_signature");
    }

    #[tokio::test]
    async fn test_group_connect_format() {
        let connect_msg = json!({
            "action": "connect",
            "username": "test_user",
            "signature": "test_signature"
        });
        
        assert_eq!(connect_msg["action"], "connect");
        assert_eq!(connect_msg["username"], "test_user");
        assert_eq!(connect_msg["signature"], "test_signature");
    }

    #[tokio::test]
    async fn test_envelope_parsing() {
        let envelope_json = r#"{"action":"incomingMessage","context":"chat","content":"{\"sender\":\"alice\",\"encrypted\":true}"}"#;
        let envelope: serde_json::Value = serde_json::from_str(envelope_json).unwrap();
        
        assert_eq!(envelope["action"], "incomingMessage");
        assert_eq!(envelope["context"], "chat");
        
        let content = envelope["content"].as_str().unwrap();
        let content_parsed: serde_json::Value = serde_json::from_str(content).unwrap();
        assert_eq!(content_parsed["sender"], "alice");
        assert_eq!(content_parsed["encrypted"], true);
    }

    #[tokio::test]
    async fn test_message_validation() {
        let valid_msg = json!({
            "sender": "alice",
            "recipient": "bob",
            "body": {
                "encryptedPayload": {},
                "payloadSignature": "sig"
            },
            "encrypted": true
        });
        
        assert!(valid_msg["sender"].is_string());
        assert!(valid_msg["recipient"].is_string());
        assert!(valid_msg["body"].is_object());
        assert!(valid_msg["encrypted"].is_boolean());
    }

    #[tokio::test]
    async fn test_signature_verification_data_format() {
        let _data_to_sign = "test data for signature verification";
        let signature_hex = "deadbeef";
        
        let sig_bytes = hex::decode(signature_hex);
        assert!(sig_bytes.is_ok());
        
        let decoded = sig_bytes.unwrap();
        assert_eq!(decoded, vec![0xde, 0xad, 0xbe, 0xef]);
    }
}
