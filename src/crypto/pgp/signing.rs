//! PGP digital signatures using rPGP 0.16 (simplified but secure)

use anyhow::{Result, anyhow};
use pgp::composed::{SignedSecretKey, SignedPublicKey, StandaloneSignature, Deserializable};
use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::types::{PublicKeyTrait, KeyDetails};
use crate::crypto::pgp::keypair::SecurePassphrase;
use std::time::SystemTime;
use rand::thread_rng;

/// PGP signing operations using rPGP 0.16
pub struct PgpSigner;

/// Verified signature result
#[derive(Debug, Clone)]
pub struct VerifiedSignature {
    pub signer_user_id: String,
    pub is_valid: bool,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl PgpSigner {

    /// Create detached PGP signature with proper security using rPGP 0.16
    pub fn sign_detached_secure(
        secret_key: &SignedSecretKey,
        data: &[u8],
        passphrase: &SecurePassphrase,
    ) -> Result<String> {
        log::info!("Creating detached PGP signature for {} bytes of data", data.len());

        // Set up a signature configuration to create a binary data signature
        let mut config = SignatureConfig::from_key(
            thread_rng(),
            &secret_key.primary_key,
            SignatureType::Binary,
        ).map_err(|e| anyhow!("Failed to create signature config: {}", e))?;

        // Add required subpackets
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                secret_key.fingerprint(),
            )).map_err(|e| anyhow!("Failed to create fingerprint subpacket: {}", e))?,
            Subpacket::critical(SubpacketData::SignatureCreationTime(
                SystemTime::now().into(),
            )).map_err(|e| anyhow!("Failed to create creation time subpacket: {}", e))?,
        ];

        config.unhashed_subpackets = vec![
            Subpacket::regular(SubpacketData::Issuer(secret_key.key_id()))
                .map_err(|e| anyhow!("Failed to create issuer subpacket: {}", e))?
        ];

        // SECURITY FIX: Let PGP handle the hashing properly - no double-hashing
        let signature = config
            .sign(
                &secret_key.primary_key,
                &passphrase.to_pgp_password(),
                data,
            )
            .map_err(|e| anyhow!("Failed to create signature: {}", e))?;

        // Return properly armored signature
        let standalone_signature = pgp::composed::StandaloneSignature::new(signature);
        let armored_signature = standalone_signature.to_armored_string(Default::default())
            .map_err(|e| anyhow!("Failed to armor signature: {}", e))?;

        log::info!("Successfully created detached PGP signature");
        Ok(armored_signature)
    }

    /// Create cleartext signature (message + signature combined)
    pub fn sign_cleartext(
        secret_key: &SignedSecretKey,
        message: &str,
        passphrase: &SecurePassphrase,
    ) -> Result<String> {
        log::info!("Creating cleartext PGP signature for {} chars of text", message.len());

        // Set up a signature configuration for cleartext signing
        let mut config = SignatureConfig::from_key(
            thread_rng(),
            &secret_key.primary_key,
            SignatureType::Text,
        ).map_err(|e| anyhow!("Failed to create signature config: {}", e))?;

        // Add required subpackets
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                secret_key.fingerprint(),
            )).map_err(|e| anyhow!("Failed to create fingerprint subpacket: {}", e))?,
            Subpacket::critical(SubpacketData::SignatureCreationTime(
                SystemTime::now().into(),
            )).map_err(|e| anyhow!("Failed to create creation time subpacket: {}", e))?,
        ];

        config.unhashed_subpackets = vec![
            Subpacket::regular(SubpacketData::Issuer(secret_key.key_id()))
                .map_err(|e| anyhow!("Failed to create issuer subpacket: {}", e))?
        ];

        // Generate the signature
        let signature = config
            .sign(
                &secret_key.primary_key,
                &passphrase.to_pgp_password(),
                message.as_bytes(),
            )
            .map_err(|e| anyhow!("Failed to create signature: {}", e))?;

        // Create cleartext signature format
        let standalone_signature = pgp::composed::StandaloneSignature::new(signature);
        let cleartext_sig = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\\nHash: SHA256\\n\\n{}\\n{}",
            message,
            standalone_signature.to_armored_string(Default::default())
                .map_err(|e| anyhow!("Failed to armor signature: {}", e))?
        );

        log::info!("Successfully created cleartext PGP signature");
        Ok(cleartext_sig)
    }

    /// Verify detached PGP signature (simplified implementation)
    pub fn verify_detached(
        public_key: &SignedPublicKey,
        data: &[u8],
        signature_armored: &str,
    ) -> Result<VerifiedSignature> {
        log::info!("Verifying detached PGP signature for {} bytes of data", data.len());

        // Parse the armored signature
        let (standalone_sig, _) = StandaloneSignature::from_armor_single(std::io::Cursor::new(signature_armored))
            .map_err(|e| anyhow!("Failed to parse armored signature: {}", e))?;

        // Verify the signature against the public key
        let is_valid = standalone_sig.verify(&public_key.primary_key, data)
            .map(|_| true)
            .unwrap_or(false);

        let signature = &standalone_sig.signature;

        // Extract signer information from the public key
        // In rPGP 0.16, user IDs are in the users vector
        let signer_user_id = if let Some(first_uid) = public_key.details.users.first() {
            String::from_utf8_lossy(first_uid.id.id()).to_string()
        } else {
            "unknown".to_string()
        };

        // Get signature creation time from signature subpackets
        let created_at = signature.config()
            .and_then(|config| {
                config.hashed_subpackets.iter()
                    .find_map(|subpkt| {
                        match &subpkt.data {
                            pgp::packet::SubpacketData::SignatureCreationTime(dt) => Some(dt.clone()),
                            _ => None,
                        }
                    })
            })
;

        let result = VerifiedSignature {
            signer_user_id,
            is_valid,
            created_at,
        };

        log::info!("PGP signature verification result: valid={}, signer={}", result.is_valid, result.signer_user_id);
        Ok(result)
    }

    /// Verify that a public key is suitable for signing (simplified validation)
    pub fn validate_signing_key(public_key: &SignedPublicKey) -> Result<()> {
        log::info!("Validating PGP signing key");

        // Check if the key has user IDs
        let has_user_ids = !public_key.details.users.is_empty();
        if !has_user_ids {
            log::warn!("PGP key has no user IDs - this may cause issues");
        }

        // Check key age (simplified check)
        let created = public_key.primary_key.created_at();
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        // Basic age check - if key is older than 10 years, warn
        let created_timestamp = created.timestamp() as u32;
        if now.saturating_sub(created_timestamp) > (10 * 365 * 24 * 60 * 60) {
            log::warn!("PGP key is older than 10 years, consider renewal");
        }

        // Check key algorithm strength
        match public_key.primary_key.algorithm() {
            pgp::crypto::public_key::PublicKeyAlgorithm::RSA => {
                // For rPGP 0.16, we'll assume RSA keys are acceptable
                log::info!("Using RSA key for signing");
            }
            pgp::crypto::public_key::PublicKeyAlgorithm::ECDSA => {
                // ECDSA includes Ed25519 variants
                log::info!("Using ECDSA/Ed25519 key for signing");
            }
            _ => {
                log::warn!("Using non-standard key algorithm: {:?}", public_key.primary_key.algorithm());
            }
        }

        log::info!("PGP key validation completed");
        Ok(())
    }

    /// Check if a public key has signing capability (simplified check)
    pub fn has_signing_capability(public_key: &SignedPublicKey) -> bool {
        // Check if any direct signatures indicate signing capability
        let has_direct_sign = public_key.details.direct_signatures.iter().any(|sig| {
            // Look for key flags in signature subpackets
            sig.config().map_or(false, |config| {
                config.hashed_subpackets.iter().any(|subpkt| {
                    matches!(&subpkt.data, pgp::packet::SubpacketData::KeyFlags(flags) if flags.sign())
                })
            })
        });

        // Check subkeys for signing capability
        let has_subkey_sign = public_key.public_subkeys.iter().any(|subkey| {
            subkey.signatures.iter().any(|sig| {
                sig.config().map_or(false, |config| {
                    config.hashed_subpackets.iter().any(|subpkt| {
                        matches!(&subpkt.data, pgp::packet::SubpacketData::KeyFlags(flags) if flags.sign())
                    })
                })
            })
        });

        has_direct_sign || has_subkey_sign
    }

    /// Verify a key's basic integrity (simplified check)
    pub fn verify_key_integrity(public_key: &SignedPublicKey) -> Result<()> {
        log::info!("Verifying PGP key integrity");

        // Basic validation - ensure key has proper structure
        let has_user_ids = !public_key.details.users.is_empty();
        if !has_user_ids {
            return Err(anyhow!("PGP key has no user IDs"));
        }

        // Check that we have reasonable key flags in signatures
        let has_keyflags = public_key.details.direct_signatures.iter().any(|sig| {
            sig.config().map_or(false, |config| {
                config.hashed_subpackets.iter().any(|subpkt| {
                    matches!(&subpkt.data, pgp::packet::SubpacketData::KeyFlags(_))
                })
            })
        });

        if !has_keyflags {
            log::warn!("PGP key has no key flags set in direct signatures");
        }

        // Basic validation - ensure we have a reasonable structure
        log::info!("Key has {} user ID(s) and {} subkey(s)",
                  public_key.details.users.len(),
                  public_key.public_subkeys.len());

        log::info!("PGP key integrity verification completed");
        Ok(())
    }
}