//! PGP-based MLS credentials and identity provider
//!
//! This module provides PGP-based identity integration for MLS,
//! allowing the use of PGP keys as MLS credentials.

use anyhow::{Result, anyhow};
use mls_rs::IdentityProvider;
use pgp::composed::SignedPublicKey;
use serde::{Deserialize, Serialize};
use mls_rs_core::identity::{
    Credential, CredentialType, CustomCredential, MemberValidationContext, MlsCredential,
    SigningIdentity,
};
use mls_rs_core::error::IntoAnyError;
use mls_rs_core::time::MlsTime;
use crate::crypto::pgp::PgpKeyManager;

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
                let pgp_cred: PgpCredential = serde_json::from_slice(&custom_cred.data)
                    .map_err(|e| PgpIdentityError(format!("Failed to deserialize PGP credential: {}", e)))?;

                // Validate PGP credential
                if pgp_cred.user_id.is_empty() {
                    return Err(PgpIdentityError("Empty user ID in PGP credential".to_string()));
                }

                if pgp_cred.public_key_armored.is_empty() {
                    return Err(PgpIdentityError("Empty public key in PGP credential".to_string()));
                }

                // TODO: Add PGP key format validation and signature verification
                return Ok(());
            }
        }

        Err(PgpIdentityError("Not a PGP credential".to_string()))
    }

    fn validate_external_sender(
        &self,
        _signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _extensions: Option<&mls_rs_core::extension::ExtensionList>,
    ) -> Result<(), Self::Error> {
        // PGP credentials don't support external senders
        Err(PgpIdentityError("PGP credentials do not support external senders".to_string()))
    }

    fn identity(
        &self,
        signing_identity: &SigningIdentity,
        _extensions: &mls_rs_core::extension::ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        // Extract identity from PGP credential
        let credential = &signing_identity.credential;
        if let Some(custom_cred) = credential.as_custom() {
            if custom_cred.credential_type == PgpCredential::credential_type() {
                let pgp_cred: PgpCredential = serde_json::from_slice(&custom_cred.data)
                    .map_err(|e| PgpIdentityError(format!("Failed to deserialize PGP credential: {}", e)))?;
                return Ok(pgp_cred.user_id.into_bytes());
            }
        }
        Err(PgpIdentityError("Not a PGP credential".to_string()))
    }

    fn valid_successor(
        &self,
        _predecessor: &SigningIdentity,
        _successor: &SigningIdentity,
        _extensions: &mls_rs_core::extension::ExtensionList,
    ) -> Result<bool, Self::Error> {
        // For PGP credentials, we don't support key rotation
        Ok(false)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![PgpCredential::credential_type()]
    }
}