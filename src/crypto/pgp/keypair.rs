//! PGP key generation and management

use anyhow::Result;
use pgp::composed::{KeyType, SecretKeyParamsBuilder, SignedSecretKey, SignedPublicKey};
use pgp::types::SecretKeyTrait;

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
}