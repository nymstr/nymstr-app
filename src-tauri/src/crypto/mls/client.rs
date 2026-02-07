//! MLS client wrapper with proper group state persistence using MLS-RS 0.51.0
//!
//! This implementation uses the correct MLS-RS ClientBuilder API with proper
//! storage providers for maintaining group state consistency.

#![allow(dead_code)] // Many methods are part of the public API for MLS operations

use aes_gcm::{aead::KeyInit as AesKeyInit, Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, Result};
use base64::Engine;
use hmac::{Hmac, Mac};
use mls_rs::{
    client_builder::MlsConfig,
    crypto::{SignaturePublicKey, SignatureSecretKey},
    group::{ExportedTree, ReceivedMessage},
    identity::SigningIdentity,
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, IdentityProvider,
    MlsMessage,
};
use mls_rs_core::error::IntoAnyError;
use mls_rs_core::identity::{
    Credential, CredentialType, CustomCredential, MemberValidationContext, MlsCredential,
};
use mls_rs_core::time::MlsTime;
use mls_rs_crypto_openssl::OpensslCryptoProvider;
use mls_rs_provider_sqlite::{connection_strategy::FileConnectionStrategy, SqLiteDataStorageEngine};
use pgp::composed::{SignedPublicKey, SignedSecretKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;
use std::sync::Arc;
use std::{fs, path::PathBuf};

use super::types::{
    ConversationInfo, ConversationType,
    MlsAddMemberResult, MlsCredential as NymstrMlsCredential, MlsGroupInfo, MlsGroupInfoPublic,
    MlsRemoveMemberResult, MlsWelcome,
};
use crate::crypto::pgp::{PgpKeyManager, PgpSigner, SecurePassphrase};

type HmacSha256 = Hmac<Sha256>;

/// Type alias for Arc-wrapped PGP secret key to reduce expensive cloning
pub type ArcSecretKey = Arc<SignedSecretKey>;
/// Type alias for Arc-wrapped PGP public key to reduce expensive cloning
pub type ArcPublicKey = Arc<SignedPublicKey>;
/// Type alias for Arc-wrapped secure passphrase to reduce expensive cloning
#[allow(dead_code)] // Part of public API for type aliases
pub type ArcPassphrase = Arc<SecurePassphrase>;

/// MLS Key Manager for secure persistence of MLS signature keys
/// Modeled after PgpKeyManager with encrypted storage
pub struct MlsKeyManager;

impl MlsKeyManager {
    /// Get the MLS keys directory for a user
    fn get_keys_dir(username: &str, base_dir: Option<&Path>) -> PathBuf {
        match base_dir {
            Some(dir) => dir.join(username).join("mls_keys"),
            None => Path::new("storage").join(username).join("mls_keys"),
        }
    }

    /// Check if MLS keys exist for a user
    pub fn keys_exist(username: &str, base_dir: Option<&Path>) -> bool {
        let keys_dir = Self::get_keys_dir(username, base_dir);
        keys_dir.join("secret.bin.enc").exists() && keys_dir.join("public.bin").exists()
    }

    /// Derive an AES-256 key from passphrase using HKDF
    fn derive_key(passphrase: &SecurePassphrase) -> [u8; 32] {
        use hkdf::Hkdf;
        let salt = b"nymstr-mls-key-encryption-v1";
        let hk = Hkdf::<Sha256>::new(Some(salt), passphrase.as_str().as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(b"mls-secret-key", &mut okm)
            .expect("HKDF expand failed");
        okm
    }

    /// Compute HMAC-SHA256 for integrity verification
    fn compute_hmac(data: &[u8], passphrase: &SecurePassphrase) -> Result<Vec<u8>> {
        use hmac::digest::KeyInit;
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(passphrase.as_str().as_bytes())
            .map_err(|e| anyhow!("Failed to create HMAC: {}", e))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    /// Verify HMAC-SHA256
    fn verify_hmac(
        data: &[u8],
        expected_hmac: &[u8],
        passphrase: &SecurePassphrase,
    ) -> Result<bool> {
        use hmac::digest::KeyInit;
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(passphrase.as_str().as_bytes())
            .map_err(|e| anyhow!("Failed to create HMAC: {}", e))?;
        mac.update(data);
        Ok(mac.verify_slice(expected_hmac).is_ok())
    }

    /// Encrypt data with AES-256-GCM
    fn encrypt_data(data: &[u8], passphrase: &SecurePassphrase) -> Result<Vec<u8>> {
        use aes_gcm::aead::Aead;
        let key_bytes = Self::derive_key(passphrase);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = <Aes256Gcm as AesKeyInit>::new(key);

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }

    /// Decrypt data with AES-256-GCM
    fn decrypt_data(encrypted: &[u8], passphrase: &SecurePassphrase) -> Result<Vec<u8>> {
        use aes_gcm::aead::Aead;
        if encrypted.len() < 12 {
            return Err(anyhow!("Encrypted data too short"));
        }

        let key_bytes = Self::derive_key(passphrase);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = <Aes256Gcm as AesKeyInit>::new(key);

        let nonce = Nonce::from_slice(&encrypted[..12]);
        let ciphertext = &encrypted[12..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {}", e))
    }

    /// Load or generate MLS signature keys for a user
    pub fn load_or_generate_keys<T: CipherSuiteProvider>(
        cipher_suite_provider: &T,
        username: &str,
        passphrase: &SecurePassphrase,
        base_dir: Option<&Path>,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey)> {
        // Try to load existing keys first
        if Self::keys_exist(username, base_dir) {
            log::info!(
                "Loading existing MLS signature keys for user: {}",
                username
            );
            if let Ok(keys) = Self::load_keys_secure(username, passphrase, base_dir) {
                return Ok(keys);
            }
            log::warn!(
                "Failed to load MLS keys, generating new ones for user: {}",
                username
            );
        }

        // Generate new keys
        log::info!(
            "Generating new MLS signature keys for user: {}",
            username
        );
        let (secret_key, public_key) = cipher_suite_provider
            .signature_key_generate()
            .map_err(|e| anyhow!("Failed to generate MLS signature keys: {:?}", e))?;

        // Save the keys securely
        Self::save_keys_secure(username, &secret_key, &public_key, passphrase, base_dir)?;

        Ok((secret_key, public_key))
    }

    /// Save MLS keys securely with encryption and HMAC
    pub fn save_keys_secure(
        username: &str,
        secret_key: &SignatureSecretKey,
        public_key: &SignaturePublicKey,
        passphrase: &SecurePassphrase,
        base_dir: Option<&Path>,
    ) -> Result<()> {
        let keys_dir = Self::get_keys_dir(username, base_dir);
        fs::create_dir_all(&keys_dir)?;

        // Set strict directory permissions (owner read/write/execute only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut dir_perms = fs::metadata(&keys_dir)?.permissions();
            dir_perms.set_mode(0o700);
            fs::set_permissions(&keys_dir, dir_perms)?;
        }

        // Encrypt and save secret key
        let secret_bytes = secret_key.as_bytes();
        let encrypted_secret = Self::encrypt_data(secret_bytes, passphrase)?;
        let secret_path = keys_dir.join("secret.bin.enc");
        fs::write(&secret_path, &encrypted_secret)?;

        // Compute and save HMAC for secret key
        let secret_hmac = Self::compute_hmac(&encrypted_secret, passphrase)?;
        fs::write(keys_dir.join("secret.bin.hmac"), &secret_hmac)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut secret_perms = fs::metadata(&secret_path)?.permissions();
            secret_perms.set_mode(0o600);
            fs::set_permissions(&secret_path, secret_perms)?;
        }

        // Save public key (not encrypted, but with HMAC)
        let public_bytes = public_key.as_bytes();
        let public_path = keys_dir.join("public.bin");
        fs::write(&public_path, public_bytes)?;

        let public_hmac = Self::compute_hmac(public_bytes, passphrase)?;
        fs::write(keys_dir.join("public.bin.hmac"), &public_hmac)?;

        // Save metadata
        let metadata = serde_json::json!({
            "version": 1,
            "created_at": chrono::Utc::now().to_rfc3339(),
            "cipher_suite": "CURVE25519_AES128",
        });
        fs::write(
            keys_dir.join("metadata.json"),
            serde_json::to_string_pretty(&metadata)?,
        )?;

        log::info!(
            "Successfully saved MLS keys securely for user: {}",
            username
        );
        Ok(())
    }

    /// Load MLS keys securely with decryption and HMAC verification
    pub fn load_keys_secure(
        username: &str,
        passphrase: &SecurePassphrase,
        base_dir: Option<&Path>,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey)> {
        let keys_dir = Self::get_keys_dir(username, base_dir);

        // Load and verify encrypted secret key
        let encrypted_secret = fs::read(keys_dir.join("secret.bin.enc"))?;
        let stored_secret_hmac = fs::read(keys_dir.join("secret.bin.hmac"))?;

        if !Self::verify_hmac(&encrypted_secret, &stored_secret_hmac, passphrase)? {
            return Err(anyhow!("Secret key integrity verification failed"));
        }

        let secret_bytes = Self::decrypt_data(&encrypted_secret, passphrase)?;
        let secret_key = SignatureSecretKey::new_slice(&secret_bytes);

        // Load and verify public key
        let public_bytes = fs::read(keys_dir.join("public.bin"))?;
        let stored_public_hmac = fs::read(keys_dir.join("public.bin.hmac"))?;

        if !Self::verify_hmac(&public_bytes, &stored_public_hmac, passphrase)? {
            return Err(anyhow!("Public key integrity verification failed"));
        }

        let public_key = SignaturePublicKey::new_slice(&public_bytes);

        log::info!(
            "Successfully loaded MLS keys securely for user: {}",
            username
        );
        Ok((secret_key, public_key))
    }
}

/// MLS client wrapper with proper group state persistence
/// This wraps a single mls-rs Client that manages multiple conversations
#[allow(dead_code)] // Fields used in MLS operations
pub struct MlsClient {
    identity: String,
    /// PGP secret key (Arc-wrapped to avoid expensive cloning)
    pgp_secret_key: ArcSecretKey,
    /// PGP public key (Arc-wrapped to avoid expensive cloning)
    pgp_public_key: ArcPublicKey,
    /// Storage engine for MLS state
    storage_engine: SqLiteDataStorageEngine<FileConnectionStrategy>,
    signing_identity: SigningIdentity,
    secret_key: SignatureSecretKey,
    cipher_suite: CipherSuite,
    /// Base directory for storage
    base_dir: PathBuf,
}

impl MlsClient {
    /// Get the MLS database path for a user
    pub fn get_mls_db_path(username: &str, base_dir: &Path) -> PathBuf {
        base_dir.join(username).join("mls_state.db")
    }

    /// Create a new MLS client with persistent storage and persistent MLS keys
    /// Keys are Arc-wrapped to avoid expensive cloning of cryptographic objects
    pub fn new(
        identity: &str,
        pgp_secret_key: ArcSecretKey,
        pgp_public_key: ArcPublicKey,
        passphrase: &SecurePassphrase,
        base_dir: PathBuf,
    ) -> Result<Self> {
        // Create MLS database path
        let mls_db_path = Self::get_mls_db_path(identity, &base_dir);

        // Ensure the directory exists
        if let Some(parent) = mls_db_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let connection_strategy = FileConnectionStrategy::new(&mls_db_path);
        let storage_engine = SqLiteDataStorageEngine::new(connection_strategy)
            .map_err(|e| anyhow!("Failed to create MLS storage engine: {}", e))?;

        // Create PGP credential for MLS (dereference Arc to get reference)
        let pgp_credential = PgpCredential::new(identity.to_string(), &*pgp_public_key)?;
        let credential = pgp_credential.into_credential()?;

        // Load or generate persistent MLS signature keys
        let crypto_provider = OpensslCryptoProvider::default();
        let cipher_suite = CipherSuite::CURVE25519_AES128;
        let cipher_suite_provider = crypto_provider
            .cipher_suite_provider(cipher_suite)
            .ok_or_else(|| anyhow!("Cipher suite not supported"))?;

        let (secret_key, public_key) = MlsKeyManager::load_or_generate_keys(
            &cipher_suite_provider,
            identity,
            passphrase,
            Some(&base_dir),
        )?;

        let signing_identity = SigningIdentity::new(credential, public_key);

        Ok(Self {
            identity: identity.to_string(),
            pgp_secret_key,
            pgp_public_key,
            storage_engine,
            signing_identity,
            secret_key,
            cipher_suite,
            base_dir,
        })
    }

    /// Create an MLS client with the configured storage
    pub fn create_client(&self) -> Result<Client<impl MlsConfig>> {
        let crypto_provider = OpensslCryptoProvider::default();

        let client = Client::builder()
            .group_state_storage(
                self.storage_engine
                    .group_state_storage()
                    .map_err(|e| anyhow!("Failed to create group storage: {}", e))?,
            )
            .key_package_repo(
                self.storage_engine
                    .key_package_storage()
                    .map_err(|e| anyhow!("Failed to create key package storage: {}", e))?,
            )
            .psk_store(
                self.storage_engine
                    .pre_shared_key_storage()
                    .map_err(|e| anyhow!("Failed to create PSK storage: {}", e))?,
            )
            .identity_provider(PgpIdentityProvider)
            .crypto_provider(crypto_provider)
            .signing_identity(
                self.signing_identity.clone(),
                self.secret_key.clone(),
                self.cipher_suite,
            )
            .build();

        Ok(client)
    }

    /// Create a new MLS group
    pub async fn create_group(&self) -> Result<MlsGroupInfo> {
        log::info!("Creating MLS group for user {}", self.identity);

        let client = self.create_client()?;
        let mut group = client
            .create_group(ExtensionList::default(), ExtensionList::default(), None)
            .map_err(|e| anyhow!("Failed to create group: {}", e))?;

        let group_id = group.group_id().to_vec();

        // Save the group (it will persist via our storage provider)
        group
            .write_to_storage()
            .map_err(|e| anyhow!("Failed to save group: {}", e))?;

        Ok(MlsGroupInfo {
            group_id,
            client_identity: self.identity.clone(),
        })
    }

    /// Generate a key package for joining groups
    pub fn generate_key_package(&self) -> Result<Vec<u8>> {
        log::info!("Generating key package for user {}", self.identity);

        let client = self.create_client()?;
        let key_package = client
            .generate_key_package_message(ExtensionList::default(), ExtensionList::default(), None)
            .map_err(|e| anyhow!("Failed to generate key package: {}", e))?;

        key_package
            .to_bytes()
            .map_err(|e| anyhow!("Failed to serialize key package: {}", e))
    }

    /// Start a 1:1 conversation (creates a 2-person MLS group)
    pub async fn start_conversation(&self, recipient_key_package: &[u8]) -> Result<ConversationInfo> {
        log::info!("Starting conversation for user {}", self.identity);

        // Parse recipient's key package
        let key_package_msg = MlsMessage::from_bytes(recipient_key_package)
            .map_err(|e| anyhow!("Failed to parse recipient key package: {}", e))?;

        // Create a new MLS group
        let client = self.create_client()?;
        let mut group = client
            .create_group(ExtensionList::default(), ExtensionList::default(), None)
            .map_err(|e| anyhow!("Failed to create MLS group: {}", e))?;

        let group_id = group.group_id().to_vec();
        let conversation_id_str = base64::engine::general_purpose::STANDARD.encode(&group_id);

        // Add the recipient to the group
        log::info!(
            "Adding member to group for conversation {} (user: {})",
            conversation_id_str,
            self.identity
        );
        let commit_result = group
            .commit_builder()
            .add_member(key_package_msg)
            .map_err(|e| anyhow!("Failed to add member to group: {}", e))?
            .build()
            .map_err(|e| anyhow!("Failed to build commit: {}", e))?;

        // Do NOT apply the pending commit yet — wait for the other party's ack.
        // The group is saved with the pending commit so it survives restarts.
        group
            .write_to_storage()
            .map_err(|e| anyhow!("Failed to save group state: {}", e))?;

        // Export ratchet tree for the welcome recipient
        let exported_tree = group.export_tree().to_bytes()
            .map_err(|e| anyhow!("Failed to export ratchet tree: {}", e))?;

        // Serialize commit message for deferred application
        let commit_bytes = commit_result
            .commit_message
            .to_bytes()
            .map_err(|e| anyhow!("Failed to serialize commit message: {}", e))?;

        // Extract welcome message for the recipient
        let welcome_message = if !commit_result.welcome_messages.is_empty() {
            Some(
                commit_result.welcome_messages[0]
                    .to_bytes()
                    .map_err(|e| anyhow!("Failed to serialize welcome message: {}", e))?,
            )
        } else {
            None
        };

        log::info!(
            "Successfully created MLS conversation {} with recipient (commit deferred)",
            conversation_id_str
        );

        Ok(ConversationInfo {
            conversation_id: group_id.clone(),
            conversation_type: ConversationType::OneToOne,
            participants: 2,
            welcome_message,
            commit_message: Some(commit_bytes),
            group_info: MlsGroupInfo {
                group_id,
                client_identity: self.identity.clone(),
            },
            ratchet_tree: Some(exported_tree),
        })
    }

    /// Join a 1:1 conversation using a welcome message
    pub async fn join_conversation(&self, welcome_bytes: &[u8]) -> Result<ConversationInfo> {
        log::info!("Joining conversation for user {}", self.identity);

        // Parse welcome message
        let welcome_message = MlsMessage::from_bytes(welcome_bytes)
            .map_err(|e| anyhow!("Failed to parse welcome message: {}", e))?;

        // Join the group using the welcome message
        let client = self.create_client()?;
        let (mut group, _roster_update) = client
            .join_group(None, &welcome_message, None)
            .map_err(|e| anyhow!("Failed to join MLS group: {}", e))?;

        let group_id = group.group_id().to_vec();
        let conversation_id_str = base64::engine::general_purpose::STANDARD.encode(&group_id);

        // Save the joined group state
        group
            .write_to_storage()
            .map_err(|e| anyhow!("Failed to save joined group state: {}", e))?;

        let participant_count = 2; // Placeholder - in reality we'd check the roster

        log::info!(
            "Successfully joined MLS conversation {}",
            conversation_id_str
        );

        Ok(ConversationInfo {
            conversation_id: group_id.clone(),
            conversation_type: ConversationType::OneToOne,
            participants: participant_count,
            welcome_message: None,
            commit_message: None,
            group_info: MlsGroupInfo {
                group_id,
                client_identity: self.identity.clone(),
            },
            ratchet_tree: None,
        })
    }

    /// Apply a previously-built pending commit after the other party confirms.
    /// Call this after receiving p2pWelcomeAck.
    pub fn apply_pending_commit_for_group(&self, group_id: &[u8]) -> Result<u64> {
        let group_id_str = base64::engine::general_purpose::STANDARD.encode(group_id);
        log::info!(
            "Applying deferred pending commit for group {} (user: {})",
            group_id_str,
            self.identity
        );

        let client = self.create_client()?;
        let mut group = client.load_group(group_id).map_err(|e| {
            anyhow!(
                "Failed to load MLS group {} for pending commit: {}",
                group_id_str,
                e
            )
        })?;

        group.apply_pending_commit().map_err(|e| {
            anyhow!(
                "Failed to apply pending commit for group {}: {}",
                group_id_str,
                e
            )
        })?;

        group
            .write_to_storage()
            .map_err(|e| anyhow!("Failed to save group state after applying pending commit: {}", e))?;

        let epoch = group.current_epoch();
        log::info!(
            "Pending commit applied for group {}, now at epoch {}",
            group_id_str,
            epoch
        );

        Ok(epoch)
    }

    /// Encrypt message for any conversation using persistent group state
    pub async fn encrypt_message(
        &self,
        conversation_id: &[u8],
        plaintext: &[u8],
    ) -> Result<super::types::EncryptedMessage> {
        let conversation_id_str =
            base64::engine::general_purpose::STANDARD.encode(conversation_id);
        log::info!(
            "Encrypting message for user {} in conversation {}",
            self.identity,
            conversation_id_str
        );

        // Load the group from storage
        let client = self.create_client()?;
        let mut group = client.load_group(conversation_id).map_err(|e| {
            anyhow!(
                "Failed to load MLS group for conversation {}: {}",
                conversation_id_str,
                e
            )
        })?;

        // Encrypt the message using MLS
        let application_message = group
            .encrypt_application_message(plaintext, Default::default())
            .map_err(|e| anyhow!("Failed to encrypt MLS message: {}", e))?;

        // Serialize the MLS message
        let mls_message_bytes = application_message
            .to_bytes()
            .map_err(|e| anyhow!("Failed to serialize MLS message: {}", e))?;

        // Save the group state after encryption
        group
            .write_to_storage()
            .map_err(|e| anyhow!("Failed to save group state after encryption: {}", e))?;

        log::info!(
            "Successfully encrypted message using MLS group for conversation {}",
            conversation_id_str
        );

        Ok(super::types::EncryptedMessage {
            conversation_id: conversation_id.to_vec(),
            mls_message: mls_message_bytes,
            message_type: super::types::MlsMessageType::Application,
        })
    }

    /// Decrypt message from any conversation using persistent group state
    pub async fn decrypt_message(
        &self,
        encrypted: &super::types::EncryptedMessage,
    ) -> Result<Vec<u8>> {
        let conversation_id_str =
            base64::engine::general_purpose::STANDARD.encode(&encrypted.conversation_id);
        log::info!(
            "Decrypting message for user {} in conversation {}",
            self.identity,
            conversation_id_str
        );

        // Load the group from storage
        let client = self.create_client()?;
        let mut group = client.load_group(&encrypted.conversation_id).map_err(|e| {
            anyhow!(
                "Failed to load MLS group for conversation {}: {}",
                conversation_id_str,
                e
            )
        })?;

        // Parse the MLS message
        let mls_message = MlsMessage::from_bytes(&encrypted.mls_message)
            .map_err(|e| anyhow!("Failed to parse MLS message: {}", e))?;

        // Process the incoming message and decrypt using MLS
        let received_message = group
            .process_incoming_message(mls_message)
            .map_err(|e| anyhow!("Failed to process incoming MLS message: {}", e))?;

        // Save the group state after processing
        group
            .write_to_storage()
            .map_err(|e| anyhow!("Failed to save group state after decryption: {}", e))?;

        // Extract the plaintext from the processed message
        match received_message {
            ReceivedMessage::ApplicationMessage(app_msg) => {
                log::info!(
                    "Successfully decrypted application message for conversation {}",
                    conversation_id_str
                );
                Ok(app_msg.data().to_vec())
            }
            _ => {
                log::warn!(
                    "Received non-application message in conversation {}",
                    conversation_id_str
                );
                Err(anyhow!(
                    "Expected application message, got different message type"
                ))
            }
        }
    }

    /// Process an incoming commit message to advance the group epoch
    pub fn process_commit(&self, group_id: &str, commit_bytes: &[u8]) -> Result<u64> {
        log::info!(
            "Processing commit for user {} in group {}",
            self.identity,
            group_id
        );

        let group_id_bytes = base64::engine::general_purpose::STANDARD
            .decode(group_id)
            .map_err(|e| anyhow!("Failed to decode group ID: {}", e))?;

        let client = self.create_client()?;
        let mut group = client
            .load_group(&group_id_bytes)
            .map_err(|e| anyhow!("Failed to load MLS group {}: {}", group_id, e))?;

        let old_epoch = group.current_epoch();
        log::info!("Current epoch before commit: {}", old_epoch);

        let mls_message = MlsMessage::from_bytes(commit_bytes)
            .map_err(|e| anyhow!("Failed to parse commit message: {}", e))?;

        let received_message = group
            .process_incoming_message(mls_message)
            .map_err(|e| anyhow!("Failed to process incoming commit: {}", e))?;

        group
            .write_to_storage()
            .map_err(|e| anyhow!("Failed to save group state after commit: {}", e))?;

        let new_epoch = group.current_epoch();
        log::info!(
            "Epoch advanced from {} to {} after processing commit",
            old_epoch,
            new_epoch
        );

        match received_message {
            ReceivedMessage::Commit(_) => {
                log::info!("Successfully processed Commit message");
            }
            other => {
                log::warn!(
                    "Expected Commit but got: {:?}",
                    std::mem::discriminant(&other)
                );
            }
        }

        Ok(new_epoch)
    }

    /// Add member to existing conversation
    pub async fn add_member(
        &self,
        conversation_id: &[u8],
        key_package_bytes: &[u8],
    ) -> Result<super::types::EncryptedMessage> {
        let conversation_id_str =
            base64::engine::general_purpose::STANDARD.encode(conversation_id);
        log::info!(
            "Adding member for user {} in conversation {}",
            self.identity,
            conversation_id_str
        );

        let client = self.create_client()?;
        let mut group = client.load_group(conversation_id).map_err(|e| {
            anyhow!(
                "Failed to load MLS group for conversation {}: {}",
                conversation_id_str,
                e
            )
        })?;

        let key_package = MlsMessage::from_bytes(key_package_bytes)
            .map_err(|e| anyhow!("Failed to parse key package: {}", e))?;

        let commit_result = group
            .commit_builder()
            .add_member(key_package)
            .map_err(|e| anyhow!("Failed to add member to group: {}", e))?
            .build()
            .map_err(|e| anyhow!("Failed to build add member commit: {}", e))?;

        group
            .apply_pending_commit()
            .map_err(|e| anyhow!("Failed to apply pending commit: {}", e))?;

        group
            .write_to_storage()
            .map_err(|e| anyhow!("Failed to save updated group state: {}", e))?;

        let commit_bytes = commit_result
            .commit_message
            .to_bytes()
            .map_err(|e| anyhow!("Failed to serialize commit message: {}", e))?;

        log::info!(
            "Successfully added member to conversation {}",
            conversation_id_str
        );

        Ok(super::types::EncryptedMessage {
            conversation_id: conversation_id.to_vec(),
            mls_message: commit_bytes,
            message_type: super::types::MlsMessageType::Commit,
        })
    }

    /// Get identity
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Get PGP public key
    pub fn pgp_public_key(&self) -> &SignedPublicKey {
        &self.pgp_public_key
    }

    /// Get PGP secret key
    pub fn pgp_secret_key(&self) -> &SignedSecretKey {
        &self.pgp_secret_key
    }

    /// Sign data with PGP key using secure method
    pub fn pgp_sign_secure(&self, data: &[u8], passphrase: &SecurePassphrase) -> Result<String> {
        PgpSigner::sign_detached_secure(&self.pgp_secret_key, data, passphrase)
    }

    /// Export group state for backup/migration purposes
    pub async fn export_group_state(&self, conversation_id: &[u8]) -> Result<Vec<u8>> {
        let group_id_str = base64::engine::general_purpose::STANDARD.encode(conversation_id);

        let client = self.create_client()?;
        let group = client.load_group(conversation_id).map_err(|e| {
            anyhow!(
                "Failed to load MLS group for conversation {}: {}",
                group_id_str,
                e
            )
        })?;

        let export_data = serde_json::json!({
            "group_id": base64::engine::general_purpose::STANDARD.encode(group.group_id()),
            "epoch": group.current_epoch(),
            "member_count": group.roster().members().len(),
            "exported_at": chrono::Utc::now().to_rfc3339(),
            "client_identity": self.identity,
        });

        let state = serde_json::to_vec(&export_data)
            .map_err(|e| anyhow!("Failed to serialize group state: {}", e))?;

        log::info!(
            "Exported group state for conversation {} (size: {} bytes, epoch: {})",
            group_id_str,
            state.len(),
            group.current_epoch()
        );
        Ok(state)
    }

    /// Create welcome message for a conversation
    pub fn create_welcome_message(&self, conversation_info: &ConversationInfo) -> Result<String> {
        if let Some(welcome_bytes) = &conversation_info.welcome_message {
            return Ok(base64::engine::general_purpose::STANDARD.encode(welcome_bytes));
        }

        Err(anyhow!("No welcome message available in conversation info"))
    }

    /// Create an MLS credential that binds the PGP identity to the MLS signature key
    pub fn create_credential(&self) -> Result<NymstrMlsCredential> {
        log::info!("Creating MLS credential for user: {}", self.identity);

        let pgp_public_key_armored = PgpKeyManager::public_key_armored(&self.pgp_public_key)?;
        let pgp_public_key_bytes = pgp_public_key_armored.as_bytes();
        let mls_signature_key = self.signing_identity.signature_key.as_bytes().to_vec();

        let credential = NymstrMlsCredential::new(
            &self.identity,
            pgp_public_key_bytes,
            mls_signature_key,
        )?;

        log::info!(
            "Created MLS credential for user: {} (fingerprint: {}, expires in {} seconds)",
            self.identity,
            credential.fingerprint_hex(),
            credential.remaining_validity_secs()
        );

        Ok(credential)
    }

    /// Get the MLS signature public key bytes
    pub fn mls_signature_key(&self) -> Vec<u8> {
        self.signing_identity.signature_key.as_bytes().to_vec()
    }

    /// Get the PGP public key fingerprint (SHA-256 hash of armored key)
    pub fn pgp_fingerprint(&self) -> Result<Vec<u8>> {
        use sha2::{Digest, Sha256};

        let pgp_public_key_armored = PgpKeyManager::public_key_armored(&self.pgp_public_key)?;
        let mut hasher = Sha256::new();
        hasher.update(pgp_public_key_armored.as_bytes());
        Ok(hasher.finalize().to_vec())
    }

    /// Create a new MLS group (as creator/admin)
    pub async fn create_mls_group(&self, group_id: &str) -> Result<MlsGroupInfoPublic> {
        log::info!(
            "Creating new MLS group: {} for user {}",
            group_id,
            self.identity
        );

        let client = self.create_client()?;
        let mut group = client
            .create_group(ExtensionList::default(), ExtensionList::default(), None)
            .map_err(|e| anyhow!("Failed to create MLS group: {}", e))?;

        let mls_group_id = group.group_id().to_vec();
        let epoch = group.current_epoch();

        let tree_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&mls_group_id);
            hasher.update(&epoch.to_le_bytes());
            hasher.finalize().to_vec()
        };

        let group_info_bytes = serde_json::to_vec(&serde_json::json!({
            "group_id": base64::engine::general_purpose::STANDARD.encode(&mls_group_id),
            "epoch": epoch,
            "cipher_suite": format!("{:?}", self.cipher_suite),
            "member_count": group.roster().members().len(),
        }))
        .map_err(|e| anyhow!("Failed to serialize group info: {}", e))?;

        group
            .write_to_storage()
            .map_err(|e| anyhow!("Failed to save group state: {}", e))?;

        let group_info = MlsGroupInfoPublic::new(
            group_id,
            &mls_group_id,
            epoch,
            tree_hash,
            &group_info_bytes,
            None,
            &self.identity,
        );

        log::info!(
            "Created MLS group: {} at epoch {} for user {}",
            group_id,
            epoch,
            self.identity
        );

        Ok(group_info)
    }

    /// Add a member to the group using their KeyPackage
    pub async fn add_member_to_group(
        &self,
        group_id: &str,
        member_key_package: &[u8],
    ) -> Result<MlsAddMemberResult> {
        log::info!(
            "Adding member to group {} for user {}",
            group_id,
            self.identity
        );

        let group_id_bytes = base64::engine::general_purpose::STANDARD
            .decode(group_id)
            .map_err(|e| anyhow!("Invalid group_id base64: {}", e))?;

        let client = self.create_client()?;
        let mut group = client
            .load_group(&group_id_bytes)
            .map_err(|e| anyhow!("Failed to load group {}: {}", group_id, e))?;

        let key_package_msg = MlsMessage::from_bytes(member_key_package)
            .map_err(|e| anyhow!("Failed to parse member key package: {}", e))?;

        let commit_result = group
            .commit_builder()
            .add_member(key_package_msg)
            .map_err(|e| anyhow!("Failed to add member: {}", e))?
            .build()
            .map_err(|e| anyhow!("Failed to build commit: {}", e))?;

        let commit_bytes = commit_result
            .commit_message
            .to_bytes()
            .map_err(|e| anyhow!("Failed to serialize commit: {}", e))?;

        group
            .apply_pending_commit()
            .map_err(|e| anyhow!("Failed to apply pending commit: {}", e))?;

        group
            .write_to_storage()
            .map_err(|e| anyhow!("Failed to save group state: {}", e))?;

        // Export ratchet tree for the welcome recipient
        let exported_tree_bytes = group.export_tree().to_bytes()
            .map_err(|e| anyhow!("Failed to export ratchet tree: {}", e))?;

        if commit_result.welcome_messages.is_empty() {
            return Err(anyhow!("No welcome message generated for new member"));
        }

        let welcome_bytes = commit_result.welcome_messages[0]
            .to_bytes()
            .map_err(|e| anyhow!("Failed to serialize welcome: {}", e))?;

        let epoch = group.current_epoch();
        let cipher_suite_value: u16 = self.cipher_suite.into();

        let welcome = MlsWelcome::new(
            group_id,
            cipher_suite_value,
            &welcome_bytes,
            Some(&exported_tree_bytes),
            epoch,
            &self.identity,
        );

        log::info!(
            "Generated welcome for group {} at epoch {} from {}",
            group_id,
            epoch,
            self.identity
        );

        Ok(MlsAddMemberResult::new(welcome, &commit_bytes, epoch))
    }

    /// Remove a member from the group by their leaf index
    ///
    /// The removed member must be identified by their leaf index in the group tree.
    /// Use `get_member_leaf_index` to find the index for a given username.
    pub async fn remove_member_from_group(
        &self,
        group_id: &str,
        member_username: &str,
    ) -> Result<MlsRemoveMemberResult> {
        log::info!(
            "Removing member {} from group {} for user {}",
            member_username,
            group_id,
            self.identity
        );

        let group_id_bytes = base64::engine::general_purpose::STANDARD
            .decode(group_id)
            .map_err(|e| anyhow!("Invalid group_id base64: {}", e))?;

        let client = self.create_client()?;
        let mut group = client
            .load_group(&group_id_bytes)
            .map_err(|e| anyhow!("Failed to load group {}: {}", group_id, e))?;

        // Find the member's leaf index by matching their identity
        let roster = group.roster();
        let members = roster.members();

        let mut member_index: Option<u32> = None;
        for member in members {
            // Get the identity from the signing identity credential
            let credential = &member.signing_identity.credential;
            if let Some(custom_cred) = credential.as_custom() {
                if custom_cred.credential_type == PgpCredential::credential_type() {
                    if let Ok(pgp_cred) = serde_json::from_slice::<PgpCredential>(&custom_cred.data) {
                        if pgp_cred.user_id == member_username {
                            member_index = Some(member.index);
                            break;
                        }
                    }
                }
            }
        }

        let leaf_index = member_index
            .ok_or_else(|| anyhow!("Member {} not found in group {}", member_username, group_id))?;

        log::info!(
            "Found member {} at leaf index {} in group {}",
            member_username,
            leaf_index,
            group_id
        );

        // Build and apply the remove commit
        let commit_result = group
            .commit_builder()
            .remove_member(leaf_index)
            .map_err(|e| anyhow!("Failed to remove member: {}", e))?
            .build()
            .map_err(|e| anyhow!("Failed to build remove commit: {}", e))?;

        let commit_bytes = commit_result
            .commit_message
            .to_bytes()
            .map_err(|e| anyhow!("Failed to serialize commit: {}", e))?;

        group
            .apply_pending_commit()
            .map_err(|e| anyhow!("Failed to apply pending commit: {}", e))?;

        group
            .write_to_storage()
            .map_err(|e| anyhow!("Failed to save group state: {}", e))?;

        let epoch = group.current_epoch();

        log::info!(
            "Removed member {} from group {} at epoch {} by {}",
            member_username,
            group_id,
            epoch,
            self.identity
        );

        Ok(MlsRemoveMemberResult::new(&commit_bytes, epoch, member_username))
    }

    /// Get the current epoch of a group
    pub fn get_group_epoch(&self, group_id: &str) -> Result<u64> {
        let group_id_bytes = base64::engine::general_purpose::STANDARD
            .decode(group_id)
            .map_err(|e| anyhow!("Invalid group_id base64: {}", e))?;

        let client = self.create_client()?;
        let group = client
            .load_group(&group_id_bytes)
            .map_err(|e| anyhow!("Failed to load group {}: {}", group_id, e))?;

        Ok(group.current_epoch())
    }

    /// Get the member count of a group
    pub fn get_group_member_count(&self, group_id: &str) -> Result<usize> {
        let group_id_bytes = base64::engine::general_purpose::STANDARD
            .decode(group_id)
            .map_err(|e| anyhow!("Invalid group_id base64: {}", e))?;

        let client = self.create_client()?;
        let group = client
            .load_group(&group_id_bytes)
            .map_err(|e| anyhow!("Failed to load group {}: {}", group_id, e))?;

        Ok(group.roster().members().len())
    }

    /// Process a Welcome message to join a group
    pub async fn process_welcome(&self, welcome: &MlsWelcome) -> Result<String> {
        log::info!(
            "Processing welcome for group {} from {} for user {}",
            welcome.group_id,
            welcome.sender,
            self.identity
        );

        let welcome_bytes = welcome.decode_welcome_bytes()?;

        let welcome_msg = MlsMessage::from_bytes(&welcome_bytes)
            .map_err(|e| anyhow!("Failed to parse welcome message: {}", e))?;

        let client = self.create_client()?;

        let ratchet_tree_bytes = welcome.decode_ratchet_tree()?;
        let exported_tree = ratchet_tree_bytes
            .map(|bytes| ExportedTree::from_bytes(&bytes))
            .transpose()
            .map_err(|e| anyhow!("Failed to parse ratchet tree: {}", e))?;

        let (mut group, _roster_update) = client
            .join_group(exported_tree, &welcome_msg, None)
            .map_err(|e| anyhow!("Failed to join group: {}", e))?;

        let joined_group_id = base64::engine::general_purpose::STANDARD.encode(group.group_id());

        group
            .write_to_storage()
            .map_err(|e| anyhow!("Failed to save joined group state: {}", e))?;

        log::info!(
            "Successfully joined group {} (id: {}) at epoch {} for user {}",
            welcome.group_id,
            joined_group_id,
            group.current_epoch(),
            self.identity
        );

        Ok(joined_group_id)
    }

    /// Get the cipher suite value used by this client
    pub fn cipher_suite_value(&self) -> u16 {
        self.cipher_suite.into()
    }

    /// Check if a group/conversation exists
    pub fn group_exists(&self, conversation_id: &[u8]) -> bool {
        let client = match self.create_client() {
            Ok(c) => c,
            Err(_) => return false,
        };
        client.load_group(conversation_id).is_ok()
    }
}

// ========== PGP Credential and Identity Provider ==========

/// PGP-based credential for MLS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgpCredential {
    pub user_id: String,
    pub public_key_armored: String,
}

impl PgpCredential {
    pub fn new(user_id: String, public_key: &SignedPublicKey) -> Result<Self> {
        let public_key_armored = PgpKeyManager::public_key_armored(public_key)?;
        Ok(Self {
            user_id,
            public_key_armored,
        })
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    pub fn public_key_armored(&self) -> &str {
        &self.public_key_armored
    }
}

impl MlsCredential for PgpCredential {
    type Error = anyhow::Error;

    fn credential_type() -> CredentialType {
        CredentialType::new(0x1000) // Custom PGP credential type
    }

    fn into_credential(self) -> Result<Credential, Self::Error> {
        let serialized = serde_json::to_vec(&self)
            .map_err(|e| anyhow!("Failed to serialize PGP credential: {}", e))?;

        let custom_cred = CustomCredential::new(Self::credential_type(), serialized);
        Ok(Credential::Custom(custom_cred))
    }
}

/// PGP Identity Provider for MLS
#[derive(Debug, Clone)]
pub struct PgpIdentityProvider;

/// Error type for PGP identity validation
#[derive(Debug)]
pub struct PgpIdentityError(String);

impl std::fmt::Display for PgpIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PGP identity error: {}", self.0)
    }
}

impl std::error::Error for PgpIdentityError {}

impl IntoAnyError for PgpIdentityError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

impl PgpIdentityProvider {
    /// Validate a PGP credential thoroughly
    fn validate_pgp_credential(pgp_cred: &PgpCredential) -> Result<(), String> {
        use pgp::composed::Deserializable;

        if pgp_cred.user_id.is_empty() {
            return Err("Empty user ID in PGP credential".to_string());
        }

        if pgp_cred.public_key_armored.is_empty() {
            return Err("Empty public key in PGP credential".to_string());
        }

        // Parse and validate the PGP public key
        let (public_key, _) =
            pgp::composed::SignedPublicKey::from_string(&pgp_cred.public_key_armored)
                .map_err(|e| format!("Invalid PGP key format: {}", e))?;

        // Validate that the key is suitable for signing
        if let Err(e) = PgpSigner::validate_signing_key(&public_key) {
            return Err(format!("PGP key validation failed: {}", e));
        }

        // Verify the user ID matches the key
        let key_user_ids: Vec<String> = public_key
            .details
            .users
            .iter()
            .map(|user| String::from_utf8_lossy(user.id.id()).to_string())
            .collect();

        if !key_user_ids
            .iter()
            .any(|uid| uid.contains(&pgp_cred.user_id))
        {
            return Err(format!(
                "User ID '{}' not found in PGP key. Available user IDs: {:?}",
                pgp_cred.user_id, key_user_ids
            ));
        }

        log::info!(
            "PGP credential validation passed for user: {}",
            pgp_cred.user_id
        );
        Ok(())
    }
}

impl IdentityProvider for PgpIdentityProvider {
    type Error = PgpIdentityError;

    fn validate_member(
        &self,
        signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _context: MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        let credential = &signing_identity.credential;
        if let Some(custom_cred) = credential.as_custom() {
            if custom_cred.credential_type == PgpCredential::credential_type() {
                let pgp_cred: PgpCredential =
                    serde_json::from_slice(&custom_cred.data).map_err(|e| {
                        PgpIdentityError(format!("Failed to deserialize PGP credential: {}", e))
                    })?;

                if pgp_cred.user_id.is_empty() {
                    return Err(PgpIdentityError(
                        "Empty user ID in PGP credential".to_string(),
                    ));
                }

                if pgp_cred.public_key_armored.is_empty() {
                    return Err(PgpIdentityError(
                        "Empty public key in PGP credential".to_string(),
                    ));
                }

                if let Err(e) = Self::validate_pgp_credential(&pgp_cred) {
                    return Err(PgpIdentityError(format!(
                        "PGP credential validation failed: {}",
                        e
                    )));
                }
                return Ok(());
            }
        }

        Err(PgpIdentityError(
            "Invalid or missing PGP credential".to_string(),
        ))
    }

    fn validate_external_sender(
        &self,
        signing_identity: &SigningIdentity,
        timestamp: Option<MlsTime>,
        _extensions: Option<&mls_rs_core::extension::ExtensionList>,
    ) -> Result<(), Self::Error> {
        self.validate_member(signing_identity, timestamp, MemberValidationContext::None)
    }

    fn identity(
        &self,
        signing_identity: &SigningIdentity,
        _extensions: &mls_rs_core::extension::ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        let credential = &signing_identity.credential;
        if let Some(custom_cred) = credential.as_custom() {
            if custom_cred.credential_type == PgpCredential::credential_type() {
                let pgp_cred: PgpCredential =
                    serde_json::from_slice(&custom_cred.data).map_err(|e| {
                        PgpIdentityError(format!("Failed to deserialize PGP credential: {}", e))
                    })?;
                return Ok(pgp_cred.user_id.into_bytes());
            }
        }
        Err(PgpIdentityError(
            "Invalid or missing PGP credential".to_string(),
        ))
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
        extensions: &mls_rs_core::extension::ExtensionList,
    ) -> Result<bool, Self::Error> {
        let pred_id = self.identity(predecessor, extensions)?;
        let succ_id = self.identity(successor, extensions)?;
        Ok(pred_id == succ_id)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![PgpCredential::credential_type()]
    }
}
