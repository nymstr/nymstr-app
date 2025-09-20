//! PGP key generation and management

use anyhow::Result;
use pgp::composed::{KeyType, SecretKeyParamsBuilder, SignedSecretKey, SignedPublicKey};
use pgp::types::SecretKeyTrait;
use pgp::Deserializable;
use std::{fs, path::Path};

/// PGP key management utilities
pub struct PgpKeyManager;

impl PgpKeyManager {
    /// Generate PGP keypair for given user ID
    pub fn generate_keypair(user_id: &str) -> Result<(SignedSecretKey, SignedPublicKey)> {
        let key_params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Rsa(2048))
            .can_sign(true)
            .can_certify(true)
            .primary_user_id(user_id.to_string())
            .build()?;

        let secret_key = key_params.generate()?;
        let signed_secret_key = secret_key.sign(|| "password".to_string())?;
        let public_key = signed_secret_key.public_key().sign(&signed_secret_key, || "password".to_string())?;

        Ok((signed_secret_key, public_key))
    }

    /// Get armored public key from PGP certificate
    pub fn public_key_armored(public_key: &SignedPublicKey) -> Result<String> {
        let armored = public_key.to_armored_string(Default::default())?;
        Ok(armored)
    }

    /// Save PGP keypair to storage directory
    pub fn save_keypair(username: &str, secret_key: &SignedSecretKey, public_key: &SignedPublicKey) -> Result<()> {
        let user_dir = Path::new("storage").join(username).join("pgp_keys");
        fs::create_dir_all(&user_dir)?;

        // Save secret key
        let secret_armored = secret_key.to_armored_string(Default::default())?;
        fs::write(user_dir.join("secret.asc"), secret_armored)?;

        // Save public key
        let public_armored = public_key.to_armored_string(Default::default())?;
        fs::write(user_dir.join("public.asc"), public_armored)?;

        Ok(())
    }

    /// Load PGP keypair from storage directory
    pub fn load_keypair(username: &str) -> Result<Option<(SignedSecretKey, SignedPublicKey)>> {
        let user_dir = Path::new("storage").join(username).join("pgp_keys");
        let secret_path = user_dir.join("secret.asc");
        let public_path = user_dir.join("public.asc");

        // Check if both files exist
        if !secret_path.exists() || !public_path.exists() {
            return Ok(None);
        }

        // Load secret key
        let secret_armored = fs::read_to_string(&secret_path)?;
        let (secret_key, _) = SignedSecretKey::from_string(&secret_armored)?;

        // Load public key
        let public_armored = fs::read_to_string(&public_path)?;
        let (public_key, _) = SignedPublicKey::from_string(&public_armored)?;

        Ok(Some((secret_key, public_key)))
    }

}