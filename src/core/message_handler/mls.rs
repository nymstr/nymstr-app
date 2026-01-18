//! MLS-related methods for MessageHandler
//!
//! This module contains methods for MLS client creation, handshake, and conversation establishment.

use super::{MessageHandler, normalize_conversation_id};
use crate::crypto::Crypto;
use anyhow::anyhow;
use mls_rs::{Client, ExtensionList, CipherSuite, CryptoProvider};
use mls_rs::client_builder::MlsConfig;
use mls_rs::identity::MlsCredential;
use mls_rs_crypto_openssl::OpensslCryptoProvider;
use mls_rs_provider_sqlite::{SqLiteDataStorageEngine, connection_strategy::FileConnectionStrategy};
use serde_json::json;

impl MessageHandler {
    /// Create an MLS client following the official mls-rs pattern
    /// Uses MlsKeyManager for persistent, encrypted key storage
    pub(crate) async fn create_mls_client(&self) -> anyhow::Result<Client<impl MlsConfig + use<>>> {
        let username = self.current_user.as_ref()
            .ok_or_else(|| anyhow!("No user logged in"))?;
        let storage_path = self.mls_storage_path.as_ref()
            .ok_or_else(|| anyhow!("MLS storage not initialized"))?;
        let pgp_public_key = self.pgp_public_key.as_ref()
            .ok_or_else(|| anyhow!("PGP public key not available"))?;
        let passphrase = self.pgp_passphrase.as_ref()
            .ok_or_else(|| anyhow!("PGP passphrase not available"))?;

        let crypto_provider = OpensslCryptoProvider::default();
        let cipher_suite = CipherSuite::CURVE25519_AES128;
        let cipher_suite_provider = crypto_provider.cipher_suite_provider(cipher_suite)
            .ok_or_else(|| anyhow!("Cipher suite not supported"))?;

        // Load or generate persistent MLS signature keys using MlsKeyManager
        let (secret_key, public_key) = crate::crypto::mls::client::MlsKeyManager::load_or_generate_keys(
            &cipher_suite_provider,
            username,
            passphrase,
        ).map_err(|e| anyhow!("Failed to get MLS signature keys: {}", e))?;

        // Create PGP credential for MLS (reusing the credential creation from our wrapper)
        // Dereference Arc to get &SignedPublicKey
        let pgp_credential = crate::crypto::mls::client::PgpCredential::new(username.clone(), &**pgp_public_key)?;
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

    /// Send a handshake (type=1) encrypted message to establish p2p routing using MLS
    pub async fn send_handshake(&self, recipient: &str) -> anyhow::Result<()> {
        let user = self.current_user.as_deref().unwrap_or("");
        // Ensure our own nym address is set
        let nym_addr = self.nym_address.clone().unwrap_or_default();

        // Create MLS client
        let client = self.create_mls_client().await?;

        // Use conversation ID based on user pair (normalized for consistency)
        let conversation_id = normalize_conversation_id(user, recipient);
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
        let signature = if let (Some(secret_key), Some(passphrase)) = (&self.pgp_secret_key, &self.pgp_passphrase) {
            Crypto::pgp_sign_detached_secure(secret_key, payload_str.as_bytes(), passphrase)?
        } else {
            return Err(anyhow!("PGP secret key or passphrase not available for signing"));
        };

        // Send encrypted handshake
        self.service
            .send_direct_message(recipient, &payload_str, &signature)
            .await?;
        Ok(())
    }

    /// Establish MLS conversation with recipient through key package exchange
    pub(crate) async fn establish_mls_conversation(&mut self, recipient: &str) -> anyhow::Result<()> {
        let user = self.current_user.as_deref().unwrap_or("");

        // Create MLS client
        let client = self.create_mls_client().await?;

        // Generate our key package
        let our_key_package = client.generate_key_package_message(Default::default(), Default::default(), None)?;

        // Sign the key package request
        let signature = if let (Some(secret_key), Some(passphrase)) = (&self.pgp_secret_key, &self.pgp_passphrase) {
            Crypto::pgp_sign_detached_secure(secret_key, &our_key_package.to_bytes()?, passphrase)?
        } else {
            return Err(anyhow!("PGP secret key or passphrase not available for signing"));
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
                                let conversation_id = normalize_conversation_id(user, recipient);
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

                                    let welcome_signature = if let (Some(secret_key), Some(passphrase)) = (&self.pgp_secret_key, &self.pgp_passphrase) {
                                        Crypto::pgp_sign_detached_secure(secret_key, &welcome_bytes, passphrase)?
                                    } else {
                                        return Err(anyhow!("PGP secret key or passphrase not available for signing"));
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
}
