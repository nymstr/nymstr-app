//! MLS client wrapper with proper group state persistence using MLS-RS 0.49.0
//!
//! This implementation uses the correct MLS-RS ClientBuilder API with proper
//! storage providers for maintaining group state consistency.

#![allow(dead_code)] // Many methods are part of the public API for MLS operations

use aes_gcm::{
    aead::{Aead, KeyInit as AesKeyInit},
    Aes256Gcm, Key, Nonce,
};
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
use mls_rs_crypto_openssl::OpensslCryptoProvider;
use pgp::composed::{SignedPublicKey, SignedSecretKey};
use pgp::types::PublicKeyTrait;
use sha2::Sha256;
use std::sync::Arc;
use std::{fs, path::Path};

use super::types::{
    ConversationInfo, ConversationType, CredentialValidationResult, EncryptedMessage,
    MlsAddMemberResult, MlsCredential as NymstrMlsCredential, MlsGroupInfo, MlsGroupInfoPublic,
    MlsMessageType, MlsWelcome,
};
use crate::core::db::Db;
use crate::crypto::pgp::{PgpKeyManager, PgpSigner, SecurePassphrase};
use mls_rs_provider_sqlite::{
    connection_strategy::FileConnectionStrategy, SqLiteDataStorageEngine,
};

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
    fn get_keys_dir(username: &str) -> std::path::PathBuf {
        Path::new("storage").join(username).join("mls_keys")
    }

    /// Check if MLS keys exist for a user
    pub fn keys_exist(username: &str) -> bool {
        let keys_dir = Self::get_keys_dir(username);
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
    ) -> Result<(SignatureSecretKey, SignaturePublicKey)> {
        // Try to load existing keys first
        if Self::keys_exist(username) {
            log::info!("Loading existing MLS signature keys for user: {}", username);
            if let Ok(keys) = Self::load_keys_secure(username, passphrase) {
                return Ok(keys);
            }
            log::warn!(
                "Failed to load MLS keys, generating new ones for user: {}",
                username
            );
        }

        // Generate new keys
        log::info!("Generating new MLS signature keys for user: {}", username);
        let (secret_key, public_key) = cipher_suite_provider
            .signature_key_generate()
            .map_err(|e| anyhow!("Failed to generate MLS signature keys: {:?}", e))?;

        // Save the keys securely
        Self::save_keys_secure(username, &secret_key, &public_key, passphrase)?;

        Ok((secret_key, public_key))
    }

    /// Save MLS keys securely with encryption and HMAC
    pub fn save_keys_secure(
        username: &str,
        secret_key: &SignatureSecretKey,
        public_key: &SignaturePublicKey,
        passphrase: &SecurePassphrase,
    ) -> Result<()> {
        let keys_dir = Self::get_keys_dir(username);
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
    ) -> Result<(SignatureSecretKey, SignaturePublicKey)> {
        let keys_dir = Self::get_keys_dir(username);

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

    /// Migrate old unencrypted MLS keys to new encrypted format
    pub fn migrate_legacy_keys(username: &str, passphrase: &SecurePassphrase) -> Result<bool> {
        let legacy_keys_dir = Path::new("storage/mls_keys");
        let secret_key_path = legacy_keys_dir.join(format!("{}_secret.key", username));
        let public_key_path = legacy_keys_dir.join(format!("{}_public.key", username));

        if !secret_key_path.exists() || !public_key_path.exists() {
            return Ok(false); // No legacy keys to migrate
        }

        log::info!("Migrating legacy MLS keys for user: {}", username);

        // Load legacy keys
        let secret_bytes = fs::read(&secret_key_path)?;
        let public_bytes = fs::read(&public_key_path)?;

        let secret_key = SignatureSecretKey::new_slice(&secret_bytes);
        let public_key = SignaturePublicKey::new_slice(&public_bytes);

        // Save with new secure format
        Self::save_keys_secure(username, &secret_key, &public_key, passphrase)?;

        // Delete legacy keys after successful migration
        fs::remove_file(&secret_key_path)?;
        fs::remove_file(&public_key_path)?;

        log::info!(
            "Successfully migrated legacy MLS keys for user: {}",
            username
        );
        Ok(true)
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
    db: Arc<Db>,
    // We'll store the client components and create it lazily
    storage_engine: SqLiteDataStorageEngine<FileConnectionStrategy>,
    signing_identity: SigningIdentity,
    secret_key: SignatureSecretKey,
    cipher_suite: CipherSuite,
    // Note: We create clients fresh each time since it's cheap and avoids type complexity
}

impl MlsClient {
    /// Create a new MLS client with persistent storage and persistent MLS keys
    /// Keys are Arc-wrapped to avoid expensive cloning of cryptographic objects
    pub fn new(
        identity: &str,
        pgp_secret_key: ArcSecretKey,
        pgp_public_key: ArcPublicKey,
        db: Arc<Db>,
        passphrase: &SecurePassphrase,
    ) -> Result<Self> {
        // Migrate any legacy MLS keys first
        let _ = MlsKeyManager::migrate_legacy_keys(identity, passphrase);

        // Create MLS database path (separate from main app database)
        let mls_db_path = crate::core::db::get_mls_db_path(identity);
        let connection_strategy = FileConnectionStrategy::new(std::path::Path::new(&mls_db_path));
        let storage_engine = SqLiteDataStorageEngine::new(connection_strategy)
            .map_err(|e| anyhow!("Failed to create MLS storage engine: {}", e))?;

        // Create PGP credential for MLS (dereference Arc to get reference)
        let pgp_credential = PgpCredential::new(identity.to_string(), &pgp_public_key)?;
        let credential = pgp_credential.into_credential()?;

        // Load or generate persistent MLS signature keys
        let crypto_provider = OpensslCryptoProvider::default();
        let cipher_suite = CipherSuite::CURVE25519_AES128;
        let cipher_suite_provider = crypto_provider
            .cipher_suite_provider(cipher_suite)
            .ok_or_else(|| anyhow!("Cipher suite not supported"))?;

        let (secret_key, public_key) =
            MlsKeyManager::load_or_generate_keys(&cipher_suite_provider, identity, passphrase)?;

        let signing_identity = SigningIdentity::new(credential, public_key);

        Ok(Self {
            identity: identity.to_string(),
            pgp_secret_key,
            pgp_public_key,
            db,
            storage_engine,
            signing_identity,
            secret_key,
            cipher_suite,
        })
    }

    /// Create a new MLS client and generate secure PGP keys
    /// Keys are wrapped in Arc for efficient sharing
    pub fn new_with_generated_keys_secure(
        identity: &str,
        db: Arc<Db>,
        passphrase: &SecurePassphrase,
    ) -> Result<Self> {
        // Load or generate PGP keys
        let (pgp_secret_key, pgp_public_key) = if PgpKeyManager::keys_exist(identity) {
            match PgpKeyManager::load_keypair_secure(identity, passphrase)? {
                Some((secret, public)) => (secret, public),
                None => PgpKeyManager::generate_keypair_secure(identity, passphrase)?,
            }
        } else {
            let (secret, public) = PgpKeyManager::generate_keypair_secure(identity, passphrase)?;
            PgpKeyManager::save_keypair_secure(identity, &secret, &public, passphrase)?;
            (secret, public)
        };

        // Wrap in Arc for efficient sharing
        Self::new(
            identity,
            Arc::new(pgp_secret_key),
            Arc::new(pgp_public_key),
            db,
            passphrase,
        )
    }

    /// Create an MLS client with the configured storage
    pub fn create_client(&self) -> Result<Client<impl MlsConfig>> {
        let crypto_provider = OpensslCryptoProvider::default();

        // Note: build() returns Client directly, no Result wrapping
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
    pub async fn start_conversation(
        &self,
        recipient_key_package: &[u8],
    ) -> Result<ConversationInfo> {
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
        log::info!(
            "Built commit for conversation {} (user: {})",
            conversation_id_str,
            self.identity
        );

        // Apply the pending commit locally
        log::info!(
            "Applying pending commit for conversation {} (user: {})",
            conversation_id_str,
            self.identity
        );
        group.apply_pending_commit().map_err(|e| {
            anyhow!(
                "Failed to apply pending commit for user {} in conversation {}: {}",
                self.identity,
                conversation_id_str,
                e
            )
        })?;
        log::info!(
            "Successfully applied pending commit for conversation {} (user: {})",
            conversation_id_str,
            self.identity
        );

        // Save the group state
        group
            .write_to_storage()
            .map_err(|e| anyhow!("Failed to save group state: {}", e))?;

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
            "Successfully created MLS conversation {} with recipient",
            conversation_id_str
        );

        Ok(ConversationInfo {
            conversation_id: group_id.clone(),
            conversation_type: ConversationType::OneToOne,
            participants: 2,
            welcome_message,
            group_info: MlsGroupInfo {
                group_id,
                client_identity: self.identity.clone(),
            },
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

        // TODO: Get actual participant count from roster
        let participant_count = 2; // Placeholder - in reality we'd check the roster

        log::info!(
            "Successfully joined MLS conversation {}",
            conversation_id_str
        );

        Ok(ConversationInfo {
            conversation_id: group_id.clone(),
            conversation_type: ConversationType::OneToOne,
            participants: participant_count,
            welcome_message: None, // Joiners don't need to send welcome messages
            group_info: MlsGroupInfo {
                group_id,
                client_identity: self.identity.clone(),
            },
        })
    }

    /// Encrypt message for any conversation using persistent group state
    pub async fn encrypt_message(
        &self,
        conversation_id: &[u8],
        plaintext: &[u8],
    ) -> Result<EncryptedMessage> {
        let conversation_id_str = base64::engine::general_purpose::STANDARD.encode(conversation_id);
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

        // Save the group state after encryption (epoch might have advanced)
        group
            .write_to_storage()
            .map_err(|e| anyhow!("Failed to save group state after encryption: {}", e))?;

        log::info!(
            "Successfully encrypted message using MLS group for conversation {}",
            conversation_id_str
        );

        Ok(EncryptedMessage {
            conversation_id: conversation_id.to_vec(),
            mls_message: mls_message_bytes,
            message_type: MlsMessageType::Application,
        })
    }

    /// Decrypt message from any conversation using persistent group state
    pub async fn decrypt_message(&self, encrypted: &EncryptedMessage) -> Result<Vec<u8>> {
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

        // Save the group state after processing (epoch might have advanced)
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
    ///
    /// This is used for epoch synchronization when existing members receive
    /// commits from the server (e.g., when a new member is added by another admin).
    ///
    /// # Arguments
    /// * `group_id` - The MLS group ID (base64 encoded)
    /// * `commit_bytes` - The raw commit message bytes
    ///
    /// # Returns
    /// The new epoch number after processing the commit
    pub fn process_commit(&self, group_id: &str, commit_bytes: &[u8]) -> Result<u64> {
        log::info!(
            "Processing commit for user {} in group {}",
            self.identity,
            group_id
        );

        // Decode the group ID
        let group_id_bytes = base64::engine::general_purpose::STANDARD
            .decode(group_id)
            .map_err(|e| anyhow!("Failed to decode group ID: {}", e))?;

        // Load the group from storage
        let client = self.create_client()?;
        let mut group = client
            .load_group(&group_id_bytes)
            .map_err(|e| anyhow!("Failed to load MLS group {}: {}", group_id, e))?;

        let old_epoch = group.current_epoch();
        log::info!("Current epoch before commit: {}", old_epoch);

        // Parse the MLS message (commit)
        let mls_message = MlsMessage::from_bytes(commit_bytes)
            .map_err(|e| anyhow!("Failed to parse commit message: {}", e))?;

        // Process the incoming commit - this advances the epoch
        let received_message = group
            .process_incoming_message(mls_message)
            .map_err(|e| anyhow!("Failed to process incoming commit: {}", e))?;

        // Save the group state after processing
        group
            .write_to_storage()
            .map_err(|e| anyhow!("Failed to save group state after commit: {}", e))?;

        let new_epoch = group.current_epoch();
        log::info!(
            "Epoch advanced from {} to {} after processing commit",
            old_epoch,
            new_epoch
        );

        // Log the message type for debugging
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

    /// Add member to existing conversation (converts 1:1 to group)
    pub async fn add_member(
        &self,
        conversation_id: &[u8],
        key_package_bytes: &[u8],
    ) -> Result<EncryptedMessage> {
        let conversation_id_str = base64::engine::general_purpose::STANDARD.encode(conversation_id);
        log::info!(
            "Adding member for user {} in conversation {}",
            self.identity,
            conversation_id_str
        );

        // Load the existing group
        let client = self.create_client()?;
        let mut group = client.load_group(conversation_id).map_err(|e| {
            anyhow!(
                "Failed to load MLS group for conversation {}: {}",
                conversation_id_str,
                e
            )
        })?;

        // Parse the new member's key package
        let key_package = MlsMessage::from_bytes(key_package_bytes)
            .map_err(|e| anyhow!("Failed to parse key package: {}", e))?;

        // Create a commit that adds the new member
        let commit_result = group
            .commit_builder()
            .add_member(key_package)
            .map_err(|e| anyhow!("Failed to add member to group: {}", e))?
            .build()
            .map_err(|e| anyhow!("Failed to build add member commit: {}", e))?;

        // Apply the pending commit locally
        group
            .apply_pending_commit()
            .map_err(|e| anyhow!("Failed to apply pending commit: {}", e))?;

        // Save the updated group state
        group
            .write_to_storage()
            .map_err(|e| anyhow!("Failed to save updated group state: {}", e))?;

        // Convert the commit to bytes for sending to other members
        let commit_bytes = commit_result
            .commit_message
            .to_bytes()
            .map_err(|e| anyhow!("Failed to serialize commit message: {}", e))?;

        log::info!(
            "Successfully added member to conversation {}",
            conversation_id_str
        );

        Ok(EncryptedMessage {
            conversation_id: conversation_id.to_vec(),
            mls_message: commit_bytes,
            message_type: MlsMessageType::Commit,
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

        // Load the group from the MLS client and export its state
        let client = self.create_client()?;
        let group = client.load_group(conversation_id).map_err(|e| {
            anyhow!(
                "Failed to load MLS group for conversation {}: {}",
                group_id_str,
                e
            )
        })?;

        // Export comprehensive group state for backup/migration
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
        // Use the actual welcome message from the conversation info if available
        if let Some(welcome_bytes) = &conversation_info.welcome_message {
            return Ok(base64::engine::general_purpose::STANDARD.encode(welcome_bytes));
        }

        // If no welcome message, this is an error since all conversations should have welcome messages
        Err(anyhow!("No welcome message available in conversation info"))
    }

    /// Create an MLS credential that binds the PGP identity to the MLS signature key
    ///
    /// This method creates a credential per RFC 9420 that establishes a cryptographic
    /// binding between the user's PGP identity and their MLS signing key.
    ///
    /// # Returns
    /// An NymstrMlsCredential containing the PGP fingerprint and MLS signature key
    pub fn create_credential(&self) -> Result<NymstrMlsCredential> {
        log::info!("Creating MLS credential for user: {}", self.identity);

        // Get PGP public key bytes for fingerprint computation
        let pgp_public_key_armored = PgpKeyManager::public_key_armored(&self.pgp_public_key)?;
        let pgp_public_key_bytes = pgp_public_key_armored.as_bytes();

        // Get MLS signature public key
        let mls_signature_key = self.signing_identity.signature_key.as_bytes().to_vec();

        // Create the credential
        let credential =
            NymstrMlsCredential::new(&self.identity, pgp_public_key_bytes, mls_signature_key)?;

        log::info!(
            "Created MLS credential for user: {} (fingerprint: {}, expires in {} seconds)",
            self.identity,
            credential.fingerprint_hex(),
            credential.remaining_validity_secs()
        );

        Ok(credential)
    }

    /// Create an MLS credential with a custom validity period
    ///
    /// # Arguments
    /// * `validity_secs` - The validity period in seconds
    ///
    /// # Returns
    /// An NymstrMlsCredential with the specified validity period
    pub fn create_credential_with_validity(
        &self,
        validity_secs: u64,
    ) -> Result<NymstrMlsCredential> {
        log::info!(
            "Creating MLS credential for user: {} with {} second validity",
            self.identity,
            validity_secs
        );

        let pgp_public_key_armored = PgpKeyManager::public_key_armored(&self.pgp_public_key)?;
        let pgp_public_key_bytes = pgp_public_key_armored.as_bytes();
        let mls_signature_key = self.signing_identity.signature_key.as_bytes().to_vec();

        let credential = NymstrMlsCredential::new_with_validity(
            &self.identity,
            pgp_public_key_bytes,
            mls_signature_key,
            validity_secs,
        )?;

        Ok(credential)
    }

    /// Verify that a credential is valid and bound to the provided PGP public key
    ///
    /// This method performs comprehensive validation of a credential including:
    /// - Checking that the credential hasn't expired
    /// - Verifying the PGP key fingerprint binding
    /// - Ensuring the MLS signature key is present
    ///
    /// # Arguments
    /// * `credential` - The MLS credential to verify
    /// * `pgp_public_key_armored` - The armored PGP public key to verify against
    ///
    /// # Returns
    /// A CredentialValidationResult with detailed validation status
    pub fn verify_credential_binding(
        &self,
        credential: &NymstrMlsCredential,
        pgp_public_key_armored: &str,
    ) -> CredentialValidationResult {
        let mut result = CredentialValidationResult::default();

        // Check expiration
        if credential.is_expired() {
            result.expired = true;
            result.errors.push("Credential has expired".to_string());
            log::warn!(
                "Credential verification failed: expired for user {}",
                credential.username
            );
            return result;
        }
        result.expired = false;

        // Verify PGP binding
        let pgp_key_bytes = pgp_public_key_armored.as_bytes();
        if credential.verify_pgp_binding(pgp_key_bytes) {
            result.pgp_binding_verified = true;
            log::debug!("PGP binding verified for user: {}", credential.username);
        } else {
            result.pgp_binding_verified = false;
            result
                .errors
                .push("PGP key fingerprint does not match credential".to_string());
            log::warn!(
                "Credential verification failed: PGP binding mismatch for user {}",
                credential.username
            );
            return result;
        }

        // Check MLS signature key presence
        if !credential.mls_signature_key.is_empty() {
            result.has_signature_key = true;
        } else {
            result.has_signature_key = false;
            result
                .errors
                .push("Credential missing MLS signature key".to_string());
            log::warn!(
                "Credential verification failed: missing signature key for user {}",
                credential.username
            );
            return result;
        }

        // All checks passed
        result.valid = true;
        log::info!(
            "Credential verification successful for user: {} (fingerprint: {})",
            credential.username,
            credential.fingerprint_hex()
        );

        result
    }

    /// Verify that our own credential is valid
    ///
    /// This is useful for checking if our credential needs to be renewed.
    ///
    /// # Arguments
    /// * `credential` - Our own MLS credential
    ///
    /// # Returns
    /// A CredentialValidationResult
    pub fn verify_own_credential(
        &self,
        credential: &NymstrMlsCredential,
    ) -> CredentialValidationResult {
        let pgp_public_key_armored = match PgpKeyManager::public_key_armored(&self.pgp_public_key) {
            Ok(armored) => armored,
            Err(e) => {
                return CredentialValidationResult::failure(&format!(
                    "Failed to get own PGP public key: {}",
                    e
                ));
            }
        };

        self.verify_credential_binding(credential, &pgp_public_key_armored)
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

    // ========== Phase 3: Welcome Flow Methods ==========

    /// Create a new MLS group (as creator/admin)
    ///
    /// This creates a fresh MLS group and returns public group information
    /// that can be shared with potential members.
    ///
    /// # Arguments
    /// * `group_id` - A unique identifier for the group
    ///
    /// # Returns
    /// MlsGroupInfoPublic containing group metadata for publishing
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

        // Compute tree hash for the group
        let tree_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&mls_group_id);
            hasher.update(epoch.to_le_bytes());
            hasher.finalize().to_vec()
        };

        // Export group info for external access
        // Note: The actual group info serialization depends on mls-rs version
        // For now, we create a placeholder that includes essential info
        let group_info_bytes = serde_json::to_vec(&serde_json::json!({
            "group_id": base64::engine::general_purpose::STANDARD.encode(&mls_group_id),
            "epoch": epoch,
            "cipher_suite": format!("{:?}", self.cipher_suite),
            "member_count": group.roster().members().len(),
        }))
        .map_err(|e| anyhow!("Failed to serialize group info: {}", e))?;

        // Save the group state
        group
            .write_to_storage()
            .map_err(|e| anyhow!("Failed to save group state: {}", e))?;

        let group_info = MlsGroupInfoPublic::new(
            group_id,
            &mls_group_id, // Pass the actual MLS-generated group ID
            epoch,
            tree_hash,
            &group_info_bytes,
            None, // No external pub for now
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
    ///
    /// This adds a new member to an existing group and generates both a Welcome
    /// message (for the new member) and a Commit message (for existing members).
    ///
    /// # Arguments
    /// * `group_id` - The group to add the member to
    /// * `member_key_package` - The raw bytes of the member's KeyPackage
    ///
    /// # Returns
    /// MlsAddMemberResult containing both the Welcome and Commit messages
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

        // Decode group_id to bytes for lookup
        let group_id_bytes = base64::engine::general_purpose::STANDARD
            .decode(group_id)
            .map_err(|e| anyhow!("Invalid group_id base64: {}", e))?;

        // Load the existing group
        let client = self.create_client()?;
        let mut group = client
            .load_group(&group_id_bytes)
            .map_err(|e| anyhow!("Failed to load group {}: {}", group_id, e))?;

        // Parse the member's key package
        let key_package_msg = MlsMessage::from_bytes(member_key_package)
            .map_err(|e| anyhow!("Failed to parse member key package: {}", e))?;

        // Add the member to the group
        let commit_result = group
            .commit_builder()
            .add_member(key_package_msg)
            .map_err(|e| anyhow!("Failed to add member: {}", e))?
            .build()
            .map_err(|e| anyhow!("Failed to build commit: {}", e))?;

        // Extract the commit message bytes BEFORE applying (we need to send this to existing members)
        let commit_bytes = commit_result
            .commit_message
            .to_bytes()
            .map_err(|e| anyhow!("Failed to serialize commit: {}", e))?;

        // Apply the pending commit
        group
            .apply_pending_commit()
            .map_err(|e| anyhow!("Failed to apply pending commit: {}", e))?;

        // Save the updated group state
        group
            .write_to_storage()
            .map_err(|e| anyhow!("Failed to save group state: {}", e))?;

        // Extract the welcome message
        if commit_result.welcome_messages.is_empty() {
            return Err(anyhow!("No welcome message generated for new member"));
        }

        let welcome_bytes = commit_result.welcome_messages[0]
            .to_bytes()
            .map_err(|e| anyhow!("Failed to serialize welcome: {}", e))?;

        // Get current epoch and cipher suite
        let epoch = group.current_epoch();
        let cipher_suite_value: u16 = self.cipher_suite.into();

        // Create the MlsWelcome
        let welcome = MlsWelcome::new(
            group_id,
            cipher_suite_value,
            &welcome_bytes,
            None, // ratchet_tree - can be included if needed
            epoch,
            &self.identity,
        );

        log::info!(
            "Generated welcome for group {} at epoch {} from {}",
            group_id,
            epoch,
            self.identity
        );

        // Return both the welcome and the commit
        Ok(MlsAddMemberResult::new(welcome, &commit_bytes, epoch))
    }

    /// Process a Welcome message to join a group
    ///
    /// This processes a received Welcome message and establishes membership
    /// in the group.
    ///
    /// # Arguments
    /// * `welcome` - The MlsWelcome received from the group creator/admin
    ///
    /// # Returns
    /// The base64-encoded MLS group ID that was joined
    pub async fn process_welcome(&self, welcome: &MlsWelcome) -> Result<String> {
        log::info!(
            "Processing welcome for group {} from {} for user {}",
            welcome.group_id,
            welcome.sender,
            self.identity
        );

        // Decode the welcome bytes
        let welcome_bytes = welcome.decode_welcome_bytes()?;

        // Parse as MLS message
        let welcome_msg = MlsMessage::from_bytes(&welcome_bytes)
            .map_err(|e| anyhow!("Failed to parse welcome message: {}", e))?;

        // Join the group
        let client = self.create_client()?;

        // Handle ratchet tree if present
        let ratchet_tree_bytes = welcome.decode_ratchet_tree()?;
        let exported_tree = ratchet_tree_bytes
            .map(|bytes| ExportedTree::from_bytes(&bytes))
            .transpose()
            .map_err(|e| anyhow!("Failed to parse ratchet tree: {}", e))?;

        let (mut group, _roster_update) = client
            .join_group(exported_tree, &welcome_msg, None)
            .map_err(|e| anyhow!("Failed to join group: {}", e))?;

        let joined_group_id = base64::engine::general_purpose::STANDARD.encode(group.group_id());

        // Save the joined group state
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

    /// Get the current GroupInfo for publishing
    ///
    /// This retrieves the current group state information that can be
    /// shared with potential external joiners.
    ///
    /// # Arguments
    /// * `group_id` - The group identifier
    ///
    /// # Returns
    /// MlsGroupInfoPublic with current group metadata
    pub fn get_group_info(&self, group_id: &str) -> Result<MlsGroupInfoPublic> {
        log::info!(
            "Getting group info for {} for user {}",
            group_id,
            self.identity
        );

        // Decode group_id to bytes
        let group_id_bytes = base64::engine::general_purpose::STANDARD
            .decode(group_id)
            .map_err(|e| anyhow!("Invalid group_id base64: {}", e))?;

        // Load the group
        let client = self.create_client()?;
        let group = client
            .load_group(&group_id_bytes)
            .map_err(|e| anyhow!("Failed to load group {}: {}", group_id, e))?;

        let epoch = group.current_epoch();

        // Compute tree hash
        let tree_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&group_id_bytes);
            hasher.update(epoch.to_le_bytes());
            hasher.finalize().to_vec()
        };

        // Create group info bytes
        let group_info_bytes = serde_json::to_vec(&serde_json::json!({
            "group_id": group_id,
            "epoch": epoch,
            "cipher_suite": format!("{:?}", self.cipher_suite),
            "member_count": group.roster().members().len(),
        }))
        .map_err(|e| anyhow!("Failed to serialize group info: {}", e))?;

        // Determine who created the group (we don't have this info, use current user)
        // In a real implementation, this would be stored when the group is created
        let created_by = &self.identity;

        let group_info = MlsGroupInfoPublic::new(
            group_id,
            &group_id_bytes, // The actual MLS group ID bytes
            epoch,
            tree_hash,
            &group_info_bytes,
            None,
            created_by,
        );

        Ok(group_info)
    }

    /// Get a list of members in a group
    ///
    /// # Arguments
    /// * `group_id` - The group identifier
    ///
    /// # Returns
    /// Vector of member identities
    pub fn get_group_members(&self, group_id: &str) -> Result<Vec<String>> {
        let group_id_bytes = base64::engine::general_purpose::STANDARD
            .decode(group_id)
            .map_err(|e| anyhow!("Invalid group_id base64: {}", e))?;

        let client = self.create_client()?;
        let group = client
            .load_group(&group_id_bytes)
            .map_err(|e| anyhow!("Failed to load group {}: {}", group_id, e))?;

        let members: Vec<String> = group
            .roster()
            .members()
            .iter()
            .filter_map(|member| {
                // Try to extract identity from credential
                let credential = &member.signing_identity.credential;
                if let Some(custom_cred) = credential.as_custom() {
                    if let Ok(pgp_cred) = serde_json::from_slice::<PgpCredential>(&custom_cred.data)
                    {
                        return Some(pgp_cred.user_id);
                    }
                }
                None
            })
            .collect();

        Ok(members)
    }

    /// Remove a member from the group
    ///
    /// # Arguments
    /// * `group_id` - The group to remove the member from
    /// * `member_index` - The leaf index of the member to remove
    ///
    /// # Returns
    /// Ok(()) on successful removal
    pub async fn remove_member_from_group(&self, group_id: &str, member_index: u32) -> Result<()> {
        log::info!(
            "Removing member {} from group {} for user {}",
            member_index,
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

        // Build commit to remove member
        let _commit_result = group
            .commit_builder()
            .remove_member(member_index)
            .map_err(|e| anyhow!("Failed to remove member: {}", e))?
            .build()
            .map_err(|e| anyhow!("Failed to build commit: {}", e))?;

        // Apply the pending commit
        group
            .apply_pending_commit()
            .map_err(|e| anyhow!("Failed to apply pending commit: {}", e))?;

        // Save the updated group state
        group
            .write_to_storage()
            .map_err(|e| anyhow!("Failed to save group state: {}", e))?;

        log::info!(
            "Successfully removed member {} from group {}",
            member_index,
            group_id
        );

        Ok(())
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

    /// Get the cipher suite value used by this client
    pub fn cipher_suite_value(&self) -> u16 {
        self.cipher_suite.into()
    }
}

// Import the PGP credential and identity provider types
use mls_rs_core::error::IntoAnyError;
use mls_rs_core::identity::{
    Credential, CredentialType, CustomCredential, MemberValidationContext, MlsCredential,
};
use mls_rs_core::time::MlsTime;
use serde::{Deserialize, Serialize};

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
        use crate::crypto::pgp::PgpSigner;
        use pgp::composed::Deserializable;

        // Check basic fields
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

        // Additional security checks
        let key_created = public_key.primary_key.created_at().timestamp() as u32;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        // Check if key is too old (more than 10 years)
        if now.saturating_sub(key_created) > (10 * 365 * 24 * 60 * 60) {
            return Err("PGP key is older than 10 years, consider renewal".to_string());
        }

        // Check if key was created in the future (clock skew protection)
        if key_created > now + (24 * 60 * 60) {
            // Allow 1 day clock skew
            return Err("PGP key has invalid creation time (future)".to_string());
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
        // Extract and validate PGP credential
        let credential = &signing_identity.credential;
        if let Some(custom_cred) = credential.as_custom() {
            if custom_cred.credential_type == PgpCredential::credential_type() {
                let pgp_cred: PgpCredential =
                    serde_json::from_slice(&custom_cred.data).map_err(|e| {
                        PgpIdentityError(format!("Failed to deserialize PGP credential: {}", e))
                    })?;

                // Validate PGP credential
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

                // Validate PGP credential properly
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
        // For now, use same validation as member
        self.validate_member(signing_identity, timestamp, MemberValidationContext::None)
    }

    fn identity(
        &self,
        signing_identity: &SigningIdentity,
        _extensions: &mls_rs_core::extension::ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        // Extract user ID as identity
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
        _extensions: &mls_rs_core::extension::ExtensionList,
    ) -> Result<bool, Self::Error> {
        // Check if both have the same user ID
        let pred_id = self.identity(predecessor, _extensions)?;
        let succ_id = self.identity(successor, _extensions)?;
        Ok(pred_id == succ_id)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![PgpCredential::credential_type()]
    }
}
