//! PGP key generation and management using rPGP 0.16 (based on source analysis)

use anyhow::{Result, anyhow};
use pgp::composed::{
    KeyType, SecretKeyParamsBuilder, SignedSecretKey, SignedPublicKey, SubkeyParamsBuilder
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::types::Password;
use pgp::composed::Deserializable;
use std::{fs, path::Path};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use zeroize::ZeroizeOnDrop;
use subtle::ConstantTimeEq;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use rand::thread_rng;

type HmacSha256 = Hmac<Sha256>;

/// Secure passphrase for PGP operations
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecurePassphrase {
    passphrase: String,
}

impl SecurePassphrase {
    pub fn new(passphrase: String) -> Self {
        Self { passphrase }
    }

    #[allow(dead_code)] // Part of public API for user interaction
    pub fn from_user_input() -> Result<Self> {
        Self::from_user_input_with_prompt("Enter passphrase for PGP key")
    }

    pub fn from_user_input_with_prompt(prompt: &str) -> Result<Self> {
        use std::io::{self, Write};

        print!("{}: ", prompt);
        io::stdout().flush()?;

        // Try to read password securely (without echo)
        let passphrase = Self::read_password_secure()?;

        if passphrase.len() < 12 {
            return Err(anyhow!("Passphrase must be at least 12 characters long"));
        }

        Ok(Self::new(passphrase))
    }

    #[cfg(unix)]
    fn read_password_secure() -> Result<String> {
        use std::io;
        use std::os::unix::io::AsRawFd;

        // Disable echo on terminal
        let stdin_fd = io::stdin().as_raw_fd();
        let mut termios = unsafe { std::mem::zeroed() };

        unsafe {
            if libc::tcgetattr(stdin_fd, &mut termios) != 0 {
                // Fallback to visible input if we can't disable echo
                log::warn!("Could not disable password echo");
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                return Ok(input.trim().to_string());
            }

            let original_flags = termios.c_lflag;
            termios.c_lflag &= !libc::ECHO;

            if libc::tcsetattr(stdin_fd, libc::TCSANOW, &termios) != 0 {
                // Fallback to visible input
                log::warn!("Could not disable password echo");
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                return Ok(input.trim().to_string());
            }

            // Read password
            let mut input = String::new();
            let result = io::stdin().read_line(&mut input);

            // Restore echo
            termios.c_lflag = original_flags;
            libc::tcsetattr(stdin_fd, libc::TCSANOW, &termios);

            log::debug!("Password input completed"); // New line after hidden input

            match result {
                Ok(_) => Ok(input.trim().to_string()),
                Err(e) => Err(anyhow!("Failed to read password: {}", e)),
            }
        }
    }

    #[cfg(not(unix))]
    fn read_password_secure() -> Result<String> {
        use std::io::{self, Write};
        log::warn!("Secure password input not available on this platform");
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        Ok(input.trim().to_string())
    }

    pub fn generate_strong() -> Self {
        use rand::distributions::{Alphanumeric, DistString};
        let passphrase = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
        Self::new(passphrase)
    }

    pub fn as_str(&self) -> &str {
        &self.passphrase
    }

    /// Convert to PGP Password type
    pub fn to_pgp_password(&self) -> Password {
        Password::from(self.passphrase.as_str())
    }
}

/// PGP key management utilities using rPGP 0.16
pub struct PgpKeyManager;

impl PgpKeyManager {

    /// Generate secure PGP keypair with Ed25519 keys and proper passphrase
    pub fn generate_keypair_secure(user_id: &str, passphrase: &SecurePassphrase) -> Result<(SignedSecretKey, SignedPublicKey)> {
        log::info!("Generating Ed25519 PGP keypair for user: {}", user_id);

        // Set up builders for subkeys (for rPGP 0.16)
        let mut signkey = SubkeyParamsBuilder::default();
        signkey
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .can_encrypt(false)
            .can_authenticate(false);

        let mut encryptkey = SubkeyParamsBuilder::default();
        encryptkey
            .key_type(KeyType::ECDH(ECCCurve::Curve25519))
            .can_sign(false)
            .can_encrypt(true)
            .can_authenticate(false);

        // Set up parameter builder for the full private key
        let mut key_params = SecretKeyParamsBuilder::default();
        key_params
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(false) // Primary key is for certification only
            .can_encrypt(false)
            .primary_user_id(user_id.into())
            .subkeys(vec![
                signkey.build().map_err(|e| anyhow!("Failed to build signing subkey: {}", e))?,
                encryptkey.build().map_err(|e| anyhow!("Failed to build encryption subkey: {}", e))?,
            ]);

        // Generate the components of the private key
        let secret_key_params = key_params.build()
            .map_err(|e| anyhow!("Failed to build secret key params: {}", e))?;
        let secret_key = secret_key_params
            .generate(thread_rng())
            .map_err(|e| anyhow!("Failed to generate secret key: {}", e))?;

        // SECURITY FIX: Use proper passphrase instead of hardcoded "password"
        let signed_secret_key = secret_key
            .sign(&mut thread_rng(), &passphrase.to_pgp_password())
            .map_err(|e| anyhow!("Failed to sign secret key: {}", e))?;

        // Derive the public key
        let signed_public_key = SignedPublicKey::from(signed_secret_key.clone());

        log::info!("Successfully generated Ed25519 PGP keypair for user: {}", user_id);
        Ok((signed_secret_key, signed_public_key))
    }

    /// Generate RSA keypair with stronger 3072-bit keys (fallback option)
    #[allow(dead_code)] // Part of public API as fallback key generation
    pub fn generate_keypair_rsa_secure(user_id: &str, passphrase: &SecurePassphrase) -> Result<(SignedSecretKey, SignedPublicKey)> {
        log::info!("Generating RSA-3072 PGP keypair for user: {}", user_id);

        // Set up builders for subkeys
        let mut signkey = SubkeyParamsBuilder::default();
        signkey
            .key_type(KeyType::Rsa(3072))
            .can_sign(true)
            .can_encrypt(false)
            .can_authenticate(false);

        let mut encryptkey = SubkeyParamsBuilder::default();
        encryptkey
            .key_type(KeyType::Rsa(3072))
            .can_sign(false)
            .can_encrypt(true)
            .can_authenticate(false);

        // Set up parameter builder for the full private key
        let mut key_params = SecretKeyParamsBuilder::default();
        key_params
            .key_type(KeyType::Rsa(3072))
            .can_certify(true)
            .can_sign(false)
            .can_encrypt(false)
            .primary_user_id(user_id.into())
            .subkeys(vec![
                signkey.build().map_err(|e| anyhow!("Failed to build signing subkey: {}", e))?,
                encryptkey.build().map_err(|e| anyhow!("Failed to build encryption subkey: {}", e))?,
            ]);

        // Generate the components of the private key
        let secret_key_params = key_params.build()
            .map_err(|e| anyhow!("Failed to build secret key params: {}", e))?;
        let secret_key = secret_key_params
            .generate(thread_rng())
            .map_err(|e| anyhow!("Failed to generate secret key: {}", e))?;

        // Use proper passphrase
        let signed_secret_key = secret_key
            .sign(&mut thread_rng(), &passphrase.to_pgp_password())
            .map_err(|e| anyhow!("Failed to sign secret key: {}", e))?;

        // Derive the public key
        let signed_public_key = SignedPublicKey::from(signed_secret_key.clone());

        log::info!("Successfully generated RSA-3072 PGP keypair for user: {}", user_id);
        Ok((signed_secret_key, signed_public_key))
    }

    /// Get armored public key from PGP certificate
    pub fn public_key_armored(public_key: &SignedPublicKey) -> Result<String> {
        public_key.to_armored_string(Default::default())
            .map_err(|e| anyhow!("Failed to armor public key: {}", e))
    }


    /// Save PGP keypair to storage directory with proper security
    pub fn save_keypair_secure(username: &str, secret_key: &SignedSecretKey, public_key: &SignedPublicKey, passphrase: &SecurePassphrase) -> Result<()> {
        log::info!("Saving PGP keypair securely for user: {}", username);

        let user_dir = Path::new("storage").join(username).join("pgp_keys");
        fs::create_dir_all(&user_dir)?;

        // Set strict directory permissions (owner read/write/execute only)
        let mut dir_perms = fs::metadata(&user_dir)?.permissions();
        dir_perms.set_mode(0o700);
        fs::set_permissions(&user_dir, dir_perms)?;

        // Save secret key with integrity protection
        let secret_armored = secret_key.to_armored_string(Default::default())
            .map_err(|e| anyhow!("Failed to armor secret key: {}", e))?;
        let secret_path = user_dir.join("secret.asc");

        // Compute HMAC for integrity verification
        let secret_hmac = Self::compute_file_hmac(&secret_armored, passphrase)?;

        fs::write(&secret_path, &secret_armored)?;
        fs::write(secret_path.with_extension("hmac"), secret_hmac)?;

        // Set strict file permissions (owner read/write only)
        let mut secret_perms = fs::metadata(&secret_path)?.permissions();
        secret_perms.set_mode(0o600);
        fs::set_permissions(&secret_path, secret_perms)?;

        // Save public key (can be world-readable)
        let public_armored = public_key.to_armored_string(Default::default())
            .map_err(|e| anyhow!("Failed to armor public key: {}", e))?;
        let public_path = user_dir.join("public.asc");

        let public_hmac = Self::compute_file_hmac(&public_armored, passphrase)?;

        fs::write(&public_path, &public_armored)?;
        fs::write(public_path.with_extension("hmac"), public_hmac)?;

        // Public key can be readable by others
        let mut public_perms = fs::metadata(&public_path)?.permissions();
        public_perms.set_mode(0o644);
        fs::set_permissions(&public_path, public_perms)?;

        log::info!("Successfully saved PGP keypair securely for user: {}", username);
        Ok(())
    }

    /// Compute HMAC-SHA256 for file integrity verification
    /// Uses proper HMAC construction to prevent length extension attacks
    fn compute_file_hmac(content: &str, passphrase: &SecurePassphrase) -> Result<String> {
        let mut mac = HmacSha256::new_from_slice(passphrase.as_str().as_bytes())
            .map_err(|e| anyhow!("Failed to create HMAC: {}", e))?;
        mac.update(content.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    /// Compute legacy HMAC (SHA256 concatenation) for migration
    fn compute_legacy_hmac(content: &str, passphrase: &SecurePassphrase) -> Result<String> {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hasher.update(passphrase.as_str().as_bytes());
        let hash = hasher.finalize();
        Ok(hex::encode(hash))
    }

    /// Migrate old HMACs to new proper HMAC format
    fn migrate_hmac_if_needed(
        file_path: &Path,
        hmac_path: &Path,
        passphrase: &SecurePassphrase,
    ) -> Result<bool> {
        if !hmac_path.exists() {
            return Ok(false);
        }

        let content = fs::read_to_string(file_path)?;
        let stored_hmac = fs::read_to_string(hmac_path)?;

        // Check if stored HMAC matches legacy format
        let legacy_hmac = Self::compute_legacy_hmac(&content, passphrase)?;
        if stored_hmac.trim() == legacy_hmac {
            // Migrate to new proper HMAC format
            log::info!("Migrating HMAC from legacy format: {:?}", hmac_path);
            let new_hmac = Self::compute_file_hmac(&content, passphrase)?;
            fs::write(hmac_path, new_hmac)?;
            return Ok(true);
        }

        Ok(false)
    }


    /// Load PGP keypair from storage directory with integrity verification
    pub fn load_keypair_secure(username: &str, passphrase: &SecurePassphrase) -> Result<Option<(SignedSecretKey, SignedPublicKey)>> {
        log::info!("Loading PGP keypair securely for user: {}", username);

        let user_dir = Path::new("storage").join(username).join("pgp_keys");
        let secret_path = user_dir.join("secret.asc");
        let public_path = user_dir.join("public.asc");
        let secret_hmac_path = secret_path.with_extension("hmac");
        let public_hmac_path = public_path.with_extension("hmac");

        // Check if all required files exist
        if !secret_path.exists() || !public_path.exists() {
            return Ok(None);
        }

        // Migrate legacy HMACs to proper format if needed
        if let Ok(migrated) = Self::migrate_hmac_if_needed(&secret_path, &secret_hmac_path, passphrase) {
            if migrated {
                log::info!("Migrated secret key HMAC for user: {}", username);
            }
        }
        if let Ok(migrated) = Self::migrate_hmac_if_needed(&public_path, &public_hmac_path, passphrase) {
            if migrated {
                log::info!("Migrated public key HMAC for user: {}", username);
            }
        }

        // Load and verify secret key
        let secret_armored = fs::read_to_string(&secret_path)?;
        if secret_hmac_path.exists() {
            let stored_hmac = fs::read_to_string(&secret_hmac_path)?;
            let computed_hmac = Self::compute_file_hmac(&secret_armored, passphrase)?;

            if !bool::from(stored_hmac.trim().as_bytes().ct_eq(computed_hmac.as_bytes())) {
                return Err(anyhow!("Secret key integrity verification failed for user: {}", username));
            }
        } else {
            log::warn!("No HMAC file found for secret key - integrity verification skipped");
        }

        let (secret_key, _) = SignedSecretKey::from_string(&secret_armored)
            .map_err(|e| anyhow!("Failed to parse secret key: {}", e))?;

        // Load and verify public key
        let public_armored = fs::read_to_string(&public_path)?;
        if public_hmac_path.exists() {
            let stored_hmac = fs::read_to_string(&public_hmac_path)?;
            let computed_hmac = Self::compute_file_hmac(&public_armored, passphrase)?;

            if !bool::from(stored_hmac.trim().as_bytes().ct_eq(computed_hmac.as_bytes())) {
                return Err(anyhow!("Public key integrity verification failed for user: {}", username));
            }
        } else {
            log::warn!("No HMAC file found for public key - integrity verification skipped");
        }

        let (public_key, _) = SignedPublicKey::from_string(&public_armored)
            .map_err(|e| anyhow!("Failed to parse public key: {}", e))?;

        log::info!("Successfully loaded and verified PGP keypair for user: {}", username);
        Ok(Some((secret_key, public_key)))
    }

    /// Check if PGP keys exist for user
    pub fn keys_exist(username: &str) -> bool {
        let user_dir = Path::new("storage").join(username).join("pgp_keys");
        user_dir.join("secret.asc").exists() && user_dir.join("public.asc").exists()
    }

    /// Parse and validate a PGP public key from armored string
    pub fn parse_public_key(public_key_armored: &str) -> Result<SignedPublicKey> {
        let (public_key, _) = SignedPublicKey::from_string(public_key_armored)
            .map_err(|e| anyhow!("Failed to parse PGP public key: {}", e))?;
        Ok(public_key)
    }
}