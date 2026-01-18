//! Authentication methods for MessageHandler
//!
//! This module contains registration, login, and user query methods.

use super::{MessageHandler, ArcSecretKey, ArcPublicKey, ArcPassphrase};
use crate::crypto::{Crypto, SecurePassphrase, PgpKeyManager};
use crate::crypto::mls::persistence::MlsGroupPersistence;
use crate::core::auth_handler::AuthenticationHandler;
use std::sync::Arc;

impl MessageHandler {
    /// Register a new user via the mixnet service, awaiting server responses
    pub async fn register_user(&mut self, username: &str) -> anyhow::Result<bool> {
        // Set current user
        self.current_user = Some(username.to_string());

        // Get passphrase from environment variable or generate one
        let passphrase = if let Ok(env_passphrase) = std::env::var("NYMSTR_PGP_PASSPHRASE") {
            SecurePassphrase::new(env_passphrase)
        } else {
            log::warn!("NYMSTR_PGP_PASSPHRASE not set, generating random passphrase");
            SecurePassphrase::generate_strong()
        };

        // Generate new PGP keys for registration (or load existing if they exist)
        let (secret_key, public_key) = if PgpKeyManager::keys_exist(username) {
            log::info!("Loading existing PGP keys for user: {}", username);
            match PgpKeyManager::load_keypair_secure(username, &passphrase)? {
                Some((secret, public)) => {
                    log::info!("Successfully loaded existing PGP keys for user: {}", username);
                    (secret, public)
                }
                None => {
                    log::info!("Generating new PGP keys for registration: {}", username);
                    let (new_secret, new_public) = Crypto::generate_pgp_keypair_secure(username, &passphrase)?;
                    PgpKeyManager::save_keypair_secure(username, &new_secret, &new_public, &passphrase)?;
                    (new_secret, new_public)
                }
            }
        } else {
            log::info!("Generating new PGP keys for registration: {}", username);
            let (new_secret, new_public) = Crypto::generate_pgp_keypair_secure(username, &passphrase)?;
            PgpKeyManager::save_keypair_secure(username, &new_secret, &new_public, &passphrase)?;
            (new_secret, new_public)
        };

        // Wrap keys in Arc to avoid expensive cloning
        let arc_public_key: ArcPublicKey = Arc::new(public_key);
        let arc_secret_key: ArcSecretKey = Arc::new(secret_key);
        let arc_passphrase: ArcPassphrase = Arc::new(passphrase);

        self.pgp_public_key = Some(Arc::clone(&arc_public_key));
        self.pgp_secret_key = Some(Arc::clone(&arc_secret_key));
        self.pgp_passphrase = Some(Arc::clone(&arc_passphrase));

        // Initialize MLS storage path for client creation
        self.mls_storage_path = Some(crate::core::db::get_mls_db_path(username));

        // Get armored public key (dereference Arc to get reference)
        let public_key_armored = Crypto::pgp_public_key_armored(&*arc_public_key)?;

        // Persist and send the public key in armored format
        self.db.register_user(username, &public_key_armored).await?;
        self.service
            .send_registration_request(username, &public_key_armored)
            .await?;

        // Create authentication handler for processing responses
        // Arc::clone is cheap - just increments reference count
        let auth_handler = AuthenticationHandler::new(
            self.db.clone(),
            Arc::new(self.service.clone()),
            self.pgp_secret_key.clone(), // Arc::clone
            self.pgp_public_key.clone(), // Arc::clone
            self.pgp_passphrase.clone(), // Arc::clone
        );

        // Await server challenge and responses using modular message processing
        let timeout_duration = std::time::Duration::from_secs(30);
        loop {
            tokio::select! {
                incoming = self.incoming_rx.recv() => {
                    if let Some(incoming) = incoming {
                        let env = &incoming.envelope;
                        let action = env.action.as_str();

                        match action {
                            "challenge" => {
                                if let Some(context) = env.payload.get("context").and_then(|v| v.as_str()) {
                                    if context == "registration" {
                                        if let Some(nonce) = env.payload.get("nonce").and_then(|v| v.as_str()) {
                                            if let Err(e) = auth_handler.process_register_challenge(username, nonce).await {
                                                log::error!("Registration challenge failed: {}", e);
                                                return Ok(false);
                                            }
                                        }
                                    }
                                }
                            }
                            "challengeResponse" => {
                                if let Some(context) = env.payload.get("context").and_then(|v| v.as_str()) {
                                    if context == "registration" {
                                        if let Some(result) = env.payload.get("result").and_then(|v| v.as_str()) {
                                            match auth_handler.process_register_response(username, result).await {
                                                Ok(success) => {
                                                    if success {
                                                        self.db.init_user(username).await?;
                                                        self.current_user = Some(username.to_string());
                                                    }
                                                    return Ok(success);
                                                }
                                                Err(e) => {
                                                    log::error!("Registration response failed: {}", e);
                                                    return Ok(false);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {
                                // Process other messages normally through the modular system
                                self.process_received_message(incoming).await;
                            }
                        }
                    } else {
                        // Channel closed
                        return Ok(false);
                    }
                }
                _ = tokio::time::sleep(timeout_duration) => {
                    log::warn!("Registration timed out after 30 seconds");
                    return Ok(false);
                }
                _ = tokio::signal::ctrl_c() => {
                    log::warn!("Registration cancelled by user");
                    return Ok(false);
                }
            }
        }
    }

    /// Login an existing user via the mixnet service, awaiting server response.
    ///
    /// IMPORTANT: PGP keys must be set via `set_pgp_keys()` before calling this function.
    /// The caller is responsible for key management (loading keys with proper passphrase).
    pub async fn login_user(&mut self, username: &str) -> anyhow::Result<bool> {
        // Verify that PGP keys have been set
        // Note: .clone() on Arc<T> is cheap - just increments reference count
        let (secret_key, public_key, passphrase) = match (
            &self.pgp_secret_key,
            &self.pgp_public_key,
            &self.pgp_passphrase,
        ) {
            (Some(sk), Some(pk), Some(pp)) => (Arc::clone(sk), Arc::clone(pk), Arc::clone(pp)),
            _ => {
                log::error!("login_user called without PGP keys set. Call set_pgp_keys() first.");
                return Err(anyhow::anyhow!(
                    "PGP keys not set. Use set_pgp_keys() before calling login_user()"
                ));
            }
        };

        self.current_user = Some(username.to_string());

        // Initialize MLS storage path for client creation
        self.mls_storage_path = Some(crate::core::db::get_mls_db_path(username));
        // Initialize MLS group persistence
        self.mls_persistence = Some(MlsGroupPersistence::new(username.to_string(), self.db.clone()));

        // Create authentication handler for processing responses
        // Arc::clone is cheap - just increments reference count
        let auth_handler = AuthenticationHandler::new(
            self.db.clone(),
            Arc::new(self.service.clone()),
            Some(secret_key),
            Some(public_key),
            Some(passphrase),
        );

        // Send initial login request
        self.service.send_login_request(username).await?;

        // Await server challenge and responses using modular message processing
        let timeout_duration = std::time::Duration::from_secs(30);
        loop {
            tokio::select! {
                incoming = self.incoming_rx.recv() => {
                    if let Some(incoming) = incoming {
                        let env = &incoming.envelope;
                        let action = env.action.as_str();

                        match action {
                            "challenge" => {
                                if let Some(context) = env.payload.get("context").and_then(|v| v.as_str()) {
                                    if context == "login" {
                                        if let Some(nonce) = env.payload.get("nonce").and_then(|v| v.as_str()) {
                                            if let Err(e) = auth_handler.process_login_challenge(username, nonce).await {
                                                log::error!("Login challenge failed: {}", e);
                                                return Ok(false);
                                            }
                                        }
                                    }
                                }
                            }
                            "challengeResponse" => {
                                if let Some(context) = env.payload.get("context").and_then(|v| v.as_str()) {
                                    if context == "login" {
                                        if let Some(result) = env.payload.get("result").and_then(|v| v.as_str()) {
                                            match auth_handler.process_login_response(username, result).await {
                                                Ok(success) => {
                                                    if success {
                                                        self.db.init_user(username).await?;
                                                        self.current_user = Some(username.to_string());
                                                    }
                                                    return Ok(success);
                                                }
                                                Err(e) => {
                                                    log::error!("Login response failed: {}", e);
                                                    return Ok(false);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {
                                // Process other messages normally through the modular system
                                self.process_received_message(incoming).await;
                            }
                        }
                    } else {
                        // Channel closed
                        return Ok(false);
                    }
                }
                _ = tokio::time::sleep(timeout_duration) => {
                    log::warn!("Login timed out after 30 seconds");
                    return Ok(false);
                }
                _ = tokio::signal::ctrl_c() => {
                    log::warn!("Login cancelled by user");
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
                    log::warn!("User query timed out after 15 seconds");
                    return Ok(None);
                }
                _ = tokio::signal::ctrl_c() => {
                    log::warn!("User query cancelled by user");
                    return Ok(None);
                }
            }
        }
    }
}
