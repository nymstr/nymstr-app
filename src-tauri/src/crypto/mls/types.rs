//! MLS message types and data structures

#![allow(dead_code)] // Many types are part of the public API for MLS operations

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// MLS encrypted message format
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedMessage {
    pub conversation_id: Vec<u8>, // Group ID for both 1:1 and group chats
    pub mls_message: Vec<u8>,
    pub message_type: MlsMessageType,
}

/// MLS group message format
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MlsGroupMessage {
    pub group_id: Vec<u8>,
    pub mls_message: Vec<u8>,
    pub message_type: MlsMessageType,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum MlsMessageType {
    Commit,
    Application,
    Welcome,
    KeyPackage,
}

/// MLS group information
#[derive(Debug, Clone)]
pub struct MlsGroupInfo {
    pub group_id: Vec<u8>,
    pub client_identity: String,
}

/// Conversation information for both 1:1 and group chats
#[derive(Debug, Clone)]
pub struct ConversationInfo {
    pub conversation_id: Vec<u8>,
    pub conversation_type: ConversationType,
    pub participants: u32,
    pub welcome_message: Option<Vec<u8>>, // For inviting others
    pub commit_message: Option<Vec<u8>>,  // Serialized Commit for deferred application
    pub group_info: MlsGroupInfo,
    pub ratchet_tree: Option<Vec<u8>>, // Exported tree for Welcome recipient
}

/// Type of conversation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConversationType {
    OneToOne,
    Group,
}

/// Default credential validity period (90 days in seconds)
const DEFAULT_CREDENTIAL_VALIDITY_SECS: u64 = 90 * 24 * 60 * 60;

/// MLS Credential that binds PGP identity to MLS signature key
/// Based on RFC 9420 credential binding requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsCredential {
    /// Username/identity of the credential holder
    pub username: String,
    /// SHA-256 fingerprint of the PGP public key
    pub pgp_key_fingerprint: Vec<u8>,
    /// Public key used for MLS signing operations
    pub mls_signature_key: Vec<u8>,
    /// Type of credential (currently only "basic" supported)
    pub credential_type: String,
    /// Unix timestamp when credential was issued
    pub issued_at: u64,
    /// Unix timestamp when credential expires
    pub expires_at: u64,
}

impl MlsCredential {
    /// Create a new MLS credential binding a PGP identity to an MLS signature key
    ///
    /// # Arguments
    /// * `username` - The user's identity/username
    /// * `pgp_public_key_bytes` - The serialized PGP public key
    /// * `mls_signature_key` - The MLS signature public key bytes
    ///
    /// # Returns
    /// A new MlsCredential with default validity period (90 days)
    pub fn new(
        username: &str,
        pgp_public_key_bytes: &[u8],
        mls_signature_key: Vec<u8>,
    ) -> Result<Self> {
        if username.is_empty() {
            return Err(anyhow!("Username cannot be empty"));
        }

        if pgp_public_key_bytes.is_empty() {
            return Err(anyhow!("PGP public key cannot be empty"));
        }

        if mls_signature_key.is_empty() {
            return Err(anyhow!("MLS signature key cannot be empty"));
        }

        // Compute SHA-256 fingerprint of PGP public key
        let mut hasher = Sha256::new();
        hasher.update(pgp_public_key_bytes);
        let pgp_key_fingerprint = hasher.finalize().to_vec();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow!("System time error: {}", e))?
            .as_secs();

        Ok(Self {
            username: username.to_string(),
            pgp_key_fingerprint,
            mls_signature_key,
            credential_type: "basic".to_string(),
            issued_at: now,
            expires_at: now + DEFAULT_CREDENTIAL_VALIDITY_SECS,
        })
    }

    /// Create a new MLS credential with custom validity period
    ///
    /// # Arguments
    /// * `username` - The user's identity/username
    /// * `pgp_public_key_bytes` - The serialized PGP public key
    /// * `mls_signature_key` - The MLS signature public key bytes
    /// * `validity_secs` - Custom validity period in seconds
    pub fn new_with_validity(
        username: &str,
        pgp_public_key_bytes: &[u8],
        mls_signature_key: Vec<u8>,
        validity_secs: u64,
    ) -> Result<Self> {
        let mut credential = Self::new(username, pgp_public_key_bytes, mls_signature_key)?;
        credential.expires_at = credential.issued_at + validity_secs;
        Ok(credential)
    }

    /// Verify that a PGP public key matches this credential's fingerprint
    ///
    /// # Arguments
    /// * `pgp_public_key_bytes` - The PGP public key bytes to verify
    ///
    /// # Returns
    /// `true` if the fingerprint matches, `false` otherwise
    pub fn verify_pgp_binding(&self, pgp_public_key_bytes: &[u8]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(pgp_public_key_bytes);
        let computed_fingerprint = hasher.finalize();

        // Constant-time comparison to prevent timing attacks
        use subtle::ConstantTimeEq;
        bool::from(computed_fingerprint.as_slice().ct_eq(&self.pgp_key_fingerprint))
    }

    /// Check if the credential has expired
    ///
    /// # Returns
    /// `true` if the credential has expired, `false` if still valid
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        now >= self.expires_at
    }

    /// Check if the credential is valid (not expired and properly formed)
    ///
    /// # Returns
    /// `true` if the credential is valid, `false` otherwise
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
            && !self.username.is_empty()
            && !self.pgp_key_fingerprint.is_empty()
            && !self.mls_signature_key.is_empty()
            && self.credential_type == "basic"
    }

    /// Get the remaining validity time in seconds
    ///
    /// # Returns
    /// Remaining seconds until expiration, or 0 if already expired
    pub fn remaining_validity_secs(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if now >= self.expires_at {
            0
        } else {
            self.expires_at - now
        }
    }

    /// Serialize the credential to bytes for storage or transmission
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| anyhow!("Failed to serialize MlsCredential: {}", e))
    }

    /// Deserialize a credential from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| anyhow!("Failed to deserialize MlsCredential: {}", e))
    }

    /// Get the hex-encoded fingerprint for display purposes
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(&self.pgp_key_fingerprint)
    }
}

/// MLS Welcome message for inviting new members to a group
/// Based on RFC 9420 Section 12.4.3.1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsWelcome {
    /// The group identifier
    pub group_id: String,
    /// The cipher suite used by the group
    pub cipher_suite: u16,
    /// Base64-encoded MLS Welcome message bytes
    pub welcome_bytes: String,
    /// Optional Base64-encoded ratchet tree for the group
    pub ratchet_tree: Option<String>,
    /// The current epoch of the group
    pub epoch: u64,
    /// The sender (inviter) username
    pub sender: String,
    /// Unix timestamp when the welcome was created
    pub timestamp: u64,
}

impl MlsWelcome {
    /// Create a new MlsWelcome from raw welcome bytes
    pub fn new(
        group_id: &str,
        cipher_suite: u16,
        welcome_bytes: &[u8],
        ratchet_tree: Option<&[u8]>,
        epoch: u64,
        sender: &str,
    ) -> Self {
        use base64::Engine;

        let welcome_b64 = base64::engine::general_purpose::STANDARD.encode(welcome_bytes);
        let ratchet_tree_b64 =
            ratchet_tree.map(|rt| base64::engine::general_purpose::STANDARD.encode(rt));

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            group_id: group_id.to_string(),
            cipher_suite,
            welcome_bytes: welcome_b64,
            ratchet_tree: ratchet_tree_b64,
            epoch,
            sender: sender.to_string(),
            timestamp,
        }
    }

    /// Decode the welcome bytes from base64
    pub fn decode_welcome_bytes(&self) -> Result<Vec<u8>> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&self.welcome_bytes)
            .map_err(|e| anyhow!("Failed to decode welcome bytes: {}", e))
    }

    /// Decode the ratchet tree from base64 if present
    pub fn decode_ratchet_tree(&self) -> Result<Option<Vec<u8>>> {
        use base64::Engine;
        match &self.ratchet_tree {
            Some(rt_b64) => {
                let rt_bytes = base64::engine::general_purpose::STANDARD
                    .decode(rt_b64)
                    .map_err(|e| anyhow!("Failed to decode ratchet tree: {}", e))?;
                Ok(Some(rt_bytes))
            }
            None => Ok(None),
        }
    }

    /// Serialize the welcome to JSON bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| anyhow!("Failed to serialize MlsWelcome: {}", e))
    }

    /// Deserialize from JSON bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| anyhow!("Failed to deserialize MlsWelcome: {}", e))
    }
}

/// Result of adding a member to an MLS group
/// Contains both the Welcome (for the new member) and the Commit (for existing members)
#[derive(Debug, Clone)]
pub struct MlsAddMemberResult {
    /// The Welcome message to send to the new member
    pub welcome: MlsWelcome,
    /// The Commit message bytes (base64 encoded) to send to existing members via server
    pub commit_bytes: String,
    /// The epoch after the commit is applied
    pub new_epoch: u64,
}

impl MlsAddMemberResult {
    /// Create a new MlsAddMemberResult
    pub fn new(welcome: MlsWelcome, commit_bytes: &[u8], new_epoch: u64) -> Self {
        use base64::Engine;
        Self {
            welcome,
            commit_bytes: base64::engine::general_purpose::STANDARD.encode(commit_bytes),
            new_epoch,
        }
    }

    /// Decode the commit bytes from base64
    pub fn decode_commit_bytes(&self) -> Result<Vec<u8>> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&self.commit_bytes)
            .map_err(|e| anyhow!("Failed to decode commit bytes: {}", e))
    }
}

/// Group information for external joins and group management
/// Per RFC 9420, this provides publicly accessible group metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsGroupInfoPublic {
    /// The unique group identifier (user-provided, e.g., server address)
    pub group_id: String,
    /// The actual MLS-generated group ID (base64 encoded)
    /// This is the ID used internally by MLS for group storage/lookup
    pub mls_group_id: String,
    /// Current epoch of the group
    pub epoch: u64,
    /// Hash of the group's ratchet tree
    pub tree_hash: Vec<u8>,
    /// Base64-encoded GroupInfo TLS serialization
    pub group_info_bytes: String,
    /// Optional external public key for external joins
    pub external_pub: Option<String>,
    /// Username of the group creator
    pub created_by: String,
    /// Unix timestamp when the group was created
    pub created_at: u64,
}

impl MlsGroupInfoPublic {
    /// Create new group info from raw bytes
    pub fn new(
        group_id: &str,
        mls_group_id: &[u8],
        epoch: u64,
        tree_hash: Vec<u8>,
        group_info_bytes: &[u8],
        external_pub: Option<&[u8]>,
        created_by: &str,
    ) -> Self {
        use base64::Engine;

        let mls_group_id_b64 = base64::engine::general_purpose::STANDARD.encode(mls_group_id);
        let group_info_b64 = base64::engine::general_purpose::STANDARD.encode(group_info_bytes);
        let external_pub_b64 =
            external_pub.map(|ep| base64::engine::general_purpose::STANDARD.encode(ep));

        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            group_id: group_id.to_string(),
            mls_group_id: mls_group_id_b64,
            epoch,
            tree_hash,
            group_info_bytes: group_info_b64,
            external_pub: external_pub_b64,
            created_by: created_by.to_string(),
            created_at,
        }
    }

    /// Decode the group info bytes from base64
    pub fn decode_group_info_bytes(&self) -> Result<Vec<u8>> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&self.group_info_bytes)
            .map_err(|e| anyhow!("Failed to decode group info bytes: {}", e))
    }

    /// Decode the external public key if present
    pub fn decode_external_pub(&self) -> Result<Option<Vec<u8>>> {
        use base64::Engine;
        match &self.external_pub {
            Some(ep_b64) => {
                let ep_bytes = base64::engine::general_purpose::STANDARD
                    .decode(ep_b64)
                    .map_err(|e| anyhow!("Failed to decode external pub: {}", e))?;
                Ok(Some(ep_bytes))
            }
            None => Ok(None),
        }
    }

    /// Serialize to JSON bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| anyhow!("Failed to serialize MlsGroupInfoPublic: {}", e))
    }

    /// Deserialize from JSON bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| anyhow!("Failed to deserialize MlsGroupInfoPublic: {}", e))
    }

    /// Get hex-encoded tree hash for display
    pub fn tree_hash_hex(&self) -> String {
        hex::encode(&self.tree_hash)
    }
}

/// Result of removing a member from an MLS group
/// Contains the Commit message that needs to be sent to remaining members
#[derive(Debug, Clone)]
pub struct MlsRemoveMemberResult {
    /// The Commit message bytes (base64 encoded) to send to remaining members via server
    pub commit_bytes: String,
    /// The epoch after the commit is applied
    pub new_epoch: u64,
    /// The username of the removed member
    pub removed_member: String,
}

impl MlsRemoveMemberResult {
    /// Create a new MlsRemoveMemberResult
    pub fn new(commit_bytes: &[u8], new_epoch: u64, removed_member: &str) -> Self {
        use base64::Engine;
        Self {
            commit_bytes: base64::engine::general_purpose::STANDARD.encode(commit_bytes),
            new_epoch,
            removed_member: removed_member.to_string(),
        }
    }

    /// Decode the commit bytes from base64
    pub fn decode_commit_bytes(&self) -> Result<Vec<u8>> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&self.commit_bytes)
            .map_err(|e| anyhow!("Failed to decode commit bytes: {}", e))
    }
}

/// Stored Welcome message for database persistence
#[derive(Debug, Clone)]
pub struct StoredWelcome {
    /// Database row ID
    pub id: i64,
    /// The group ID this welcome is for
    pub group_id: String,
    /// The sender who created this welcome
    pub sender: String,
    /// Base64-encoded welcome message bytes
    pub welcome_bytes: String,
    /// Optional base64-encoded ratchet tree
    pub ratchet_tree: Option<String>,
    /// The cipher suite used
    pub cipher_suite: u16,
    /// The group epoch
    pub epoch: u64,
    /// When the welcome was received (RFC3339 string)
    pub received_at: String,
    /// Whether this welcome has been processed
    pub processed: bool,
    /// When the welcome was processed (RFC3339 string)
    pub processed_at: Option<String>,
    /// Processing error if any
    pub error_message: Option<String>,
}

impl StoredWelcome {
    /// Convert to MlsWelcome for processing
    pub fn to_mls_welcome(&self) -> MlsWelcome {
        MlsWelcome {
            group_id: self.group_id.clone(),
            cipher_suite: self.cipher_suite,
            welcome_bytes: self.welcome_bytes.clone(),
            ratchet_tree: self.ratchet_tree.clone(),
            epoch: self.epoch,
            sender: self.sender.clone(),
            timestamp: chrono::DateTime::parse_from_rfc3339(&self.received_at)
                .map(|dt| dt.timestamp() as u64)
                .unwrap_or(0),
        }
    }
}

/// Validation result for credential verification
#[derive(Debug, Clone)]
pub struct CredentialValidationResult {
    /// Whether the credential is valid overall
    pub valid: bool,
    /// Whether the PGP binding was verified
    pub pgp_binding_verified: bool,
    /// Whether the credential has expired
    pub expired: bool,
    /// Whether the MLS signature key is present
    pub has_signature_key: bool,
    /// Any validation errors encountered
    pub errors: Vec<String>,
}

impl Default for CredentialValidationResult {
    fn default() -> Self {
        Self {
            valid: false,
            pgp_binding_verified: false,
            expired: true,
            has_signature_key: false,
            errors: Vec::new(),
        }
    }
}

impl CredentialValidationResult {
    /// Create a successful validation result
    pub fn success() -> Self {
        Self {
            valid: true,
            pgp_binding_verified: true,
            expired: false,
            has_signature_key: true,
            errors: Vec::new(),
        }
    }

    /// Create a failed validation result with an error message
    pub fn failure(error: &str) -> Self {
        Self {
            valid: false,
            pgp_binding_verified: false,
            expired: false,
            has_signature_key: false,
            errors: vec![error.to_string()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mls_credential_creation() {
        let username = "alice";
        let pgp_key = b"fake_pgp_public_key_data";
        let mls_key = vec![1, 2, 3, 4, 5];

        let credential = MlsCredential::new(username, pgp_key, mls_key.clone())
            .expect("Failed to create credential");

        assert_eq!(credential.username, username);
        assert_eq!(credential.mls_signature_key, mls_key);
        assert_eq!(credential.credential_type, "basic");
        assert!(!credential.is_expired());
        assert!(credential.is_valid());
    }

    #[test]
    fn test_pgp_binding_verification() {
        let username = "bob";
        let pgp_key = b"test_pgp_key_bytes";
        let mls_key = vec![10, 20, 30];

        let credential =
            MlsCredential::new(username, pgp_key, mls_key).expect("Failed to create credential");

        // Should verify with same key
        assert!(credential.verify_pgp_binding(pgp_key));

        // Should fail with different key
        assert!(!credential.verify_pgp_binding(b"different_key_bytes"));
    }

    #[test]
    fn test_credential_serialization() {
        let credential =
            MlsCredential::new("charlie", b"pgp_key", vec![1, 2, 3]).expect("Failed to create credential");

        let bytes = credential.to_bytes().expect("Failed to serialize");
        let restored = MlsCredential::from_bytes(&bytes).expect("Failed to deserialize");

        assert_eq!(credential.username, restored.username);
        assert_eq!(credential.pgp_key_fingerprint, restored.pgp_key_fingerprint);
        assert_eq!(credential.mls_signature_key, restored.mls_signature_key);
    }

    #[test]
    fn test_empty_username_rejected() {
        let result = MlsCredential::new("", b"pgp_key", vec![1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_pgp_key_rejected() {
        let result = MlsCredential::new("user", &[], vec![1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_mls_key_rejected() {
        let result = MlsCredential::new("user", b"pgp_key", vec![]);
        assert!(result.is_err());
    }
}
