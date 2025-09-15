//! PGP digital signatures

use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use pgp::composed::SignedSecretKey;
use pgp::crypto::hash::HashAlgorithm;
use pgp::ser::Serialize as PgpSerialize;
use pgp::types::SecretKeyTrait;

/// PGP signing operations
pub struct PgpSigner;

impl PgpSigner {
    /// Create detached PGP signature
    pub fn sign_detached(
        secret_key: &SignedSecretKey,
        data: &[u8],
    ) -> Result<String> {
        // Always hash the message before signing for consistent behavior
        log::info!("Hashing message ({} bytes) before signing", data.len());
        use openssl::sha::Sha256;
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finish();
        let message_to_sign = hex::encode(hash);

        let signature = secret_key.create_signature(|| "password".to_string(), HashAlgorithm::default(), message_to_sign.as_bytes())?;
        // Return signature as base64 for now - in a real implementation we'd use proper PGP armoring
        let signature_bytes = PgpSerialize::to_bytes(&signature)?;
        Ok(base64::Engine::encode(&STANDARD, &signature_bytes))
    }
}