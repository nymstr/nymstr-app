# Crypto Module Documentation

## Overview

The `crypto` module (`src/crypto/`) handles all cryptographic operations in Nymstr, including MLS-based end-to-end encryption and PGP-based digital signatures.

## Module Structure

```
src/crypto/
├── mod.rs              # Module exports
├── utils.rs            # General crypto utilities
├── message_crypto.rs   # Message-level operations
├── mls/                # MLS protocol implementation
│   ├── mod.rs
│   ├── client.rs           # MLS client wrapper
│   ├── conversation_manager.rs  # Conversation management
│   ├── epoch_buffer.rs     # Out-of-order message handling
│   ├── key_packages.rs     # Key package management
│   ├── persistence.rs      # MLS state persistence
│   ├── types.rs            # MLS data structures
│   └── *_test.rs           # Test files
└── pgp/                # PGP implementation
    ├── mod.rs
    ├── keypair.rs          # Key generation/management
    └── signing.rs          # Signature operations
```

---

## MLS Submodule (`crypto/mls/`)

### Purpose

Implement the Message Layer Security (MLS) protocol for end-to-end encrypted group messaging. MLS provides:

- **Forward Secrecy**: Past messages remain secure if keys are compromised
- **Post-Compromise Security**: Future messages secure after compromise recovery
- **Efficient Group Operations**: Add/remove members without full rekeying

### 1. MLS Client (`client.rs`)

#### Purpose
Wrapper around the `mls-rs` library providing a simplified interface for MLS operations.

#### Key Types

```rust
pub struct MlsClient {
    identity: String,
    pgp_secret_key: SignedSecretKey,
    pgp_public_key: SignedPublicKey,
    db: Arc<Db>,
}

pub struct PgpCredential {
    user_id: String,
    public_key_armored: String,
}

pub struct PgpIdentityProvider;  // Custom identity validation
```

#### MLS Key Management

```rust
pub struct MlsKeyManager;

impl MlsKeyManager {
    /// Load or generate persistent MLS signature keys
    pub fn load_or_generate_keys(
        cipher_suite_provider: &impl CipherSuiteProvider,
        username: &str,
        passphrase: &SecurePassphrase,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey)>;

    /// Check if keys exist for a user
    pub fn keys_exist(username: &str) -> bool;
}
```

**Key Storage**:
- Keys stored in `storage/mls_keys_{username}.enc`
- Encrypted with passphrase-derived key (Argon2)
- Includes HMAC for integrity verification

#### Key Methods

| Method | Description |
|--------|-------------|
| `new(identity, secret_key, public_key, db, passphrase)` | Create client |
| `generate_key_package()` | Generate key package for handshake |
| `create_client()` | Create underlying mls-rs client |
| `create_group()` | Create new MLS group |
| `join_conversation(welcome_bytes)` | Join group via Welcome |
| `export_group_state(conversation_id)` | Export group for persistence |

#### Client Creation Flow

```rust
// 1. Load/generate persistent MLS keys
let (secret_key, public_key) = MlsKeyManager::load_or_generate_keys(...)?;

// 2. Create PGP credential
let pgp_credential = PgpCredential::new(username, pgp_public_key)?;
let credential = pgp_credential.into_credential()?;

// 3. Create signing identity
let signing_identity = SigningIdentity::new(credential, public_key);

// 4. Setup storage
let storage_engine = SqLiteDataStorageEngine::new(connection_strategy)?;

// 5. Build client
Client::builder()
    .group_state_storage(storage_engine.group_state_storage()?)
    .key_package_repo(storage_engine.key_package_storage()?)
    .psk_store(storage_engine.pre_shared_key_storage()?)
    .identity_provider(PgpIdentityProvider)
    .crypto_provider(OpensslCryptoProvider::default())
    .signing_identity(signing_identity, secret_key, cipher_suite)
    .build()
```

---

### 2. Conversation Manager (`conversation_manager.rs`)

#### Purpose
Manage MLS conversations including handshakes, group operations, and message processing with epoch-aware buffering.

#### Structure

```rust
pub struct MlsConversationManager {
    pub db: Arc<Db>,
    pub service: Arc<MixnetService>,
    pub current_user: Option<String>,
    pub pgp_secret_key: Option<SignedSecretKey>,
    pub pgp_public_key: Option<SignedPublicKey>,
    pub pgp_passphrase: Option<SecurePassphrase>,
    pub mls_storage_path: Option<String>,
    pub epoch_buffer: EpochAwareBuffer,
}
```

#### Key Methods

| Method | Description |
|--------|-------------|
| `new(...)` | Create manager |
| `init_epoch_buffer()` | Initialize buffer for current user |
| `handle_key_package_request(sender, key_package)` | Process handshake request |
| `handle_group_welcome(sender, welcome, group_id)` | Process group invitation |
| `handle_mls_protocol_message(envelope)` | Route MLS messages |
| `process_incoming_message_buffered(...)` | Process with epoch handling |
| `process_buffered_messages(conv_id)` | Retry buffered messages |
| `cleanup_expired_buffered(max_age)` | Remove old messages |

#### MLS Handshake Flow

```
Alice                                              Bob
  │                                                  │
  │  1. generate_key_package()                       │
  │  2. send keyPackageRequest                       │
  │────────────────────────────────────────────────▶│
  │                                                  │
  │                       3. handle_key_package_request()
  │                       4. generate_key_package()
  │                       5. send keyPackageResponse
  │◀────────────────────────────────────────────────│
  │                                                  │
  │  6. Create MLS group                             │
  │  7. Add Bob with his key package                 │
  │  8. Generate Welcome message                     │
  │  9. send groupWelcome                            │
  │────────────────────────────────────────────────▶│
  │                                                  │
  │                      10. handle_group_welcome()
  │                      11. Join group via Welcome
  │                      12. send groupJoinResponse
  │◀────────────────────────────────────────────────│
  │                                                  │
  │  ════════ MLS Group Established ════════        │
```

#### Epoch-Aware Processing

```rust
pub async fn process_incoming_message_buffered(
    &mut self,
    conv_id: &str,
    sender: &str,
    mls_message_b64: &str,
) -> Result<Option<(String, String)>> {
    match self.try_process_mls_message(conv_id, mls_message_b64).await {
        Ok(result) => {
            // Success - also process any buffered messages
            self.process_buffered_messages(conv_id).await?;
            Ok(Some((sender.to_string(), result)))
        }
        Err(e) if self.is_epoch_error(&e) => {
            // Epoch mismatch - buffer for later
            self.epoch_buffer.queue_message(conv_id, sender, mls_message_b64).await?;
            Ok(None)
        }
        Err(e) => Err(e),
    }
}
```

#### Epoch Error Detection

```rust
fn is_epoch_error(&self, error: &anyhow::Error) -> bool {
    let msg = error.to_string().to_lowercase();
    msg.contains("epoch")
        || msg.contains("generation")
        || msg.contains("stale")
        || msg.contains("wrong epoch")
        || msg.contains("cannot decrypt")
        || msg.contains("secret tree")
        || msg.contains("ratchet")
}
```

---

### 3. Epoch Buffer (`epoch_buffer.rs`)

#### Purpose
Handle out-of-order MLS message delivery caused by Nym mixnet latency.

#### Problem Statement

MLS requires strict message ordering within epochs:
- Messages encrypted under epoch N cannot be decrypted at epoch N-1
- Messages from epoch N-1 cannot be processed at epoch N+1
- The mixnet introduces variable latency (seconds to minutes)

#### Solution

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ Nym Mixnet  │────▶│ EpochAwareBuffer │────▶│ MLS Processing  │
│  (random    │     │                  │     │                 │
│   delays)   │     │ - Queue by epoch │     │ - Decrypt msg   │
└─────────────┘     │ - Track expected │     │ - Advance state │
                    │ - Retry pending  │     └─────────────────┘
                    └──────────────────┘
                            │
                            ▼
                    ┌──────────────────┐
                    │ SQLite Storage   │
                    │ pending_messages │
                    └──────────────────┘
```

#### Structure

```rust
pub struct EpochAwareBuffer {
    /// In-memory buffer for fast access
    memory_buffer: Arc<Mutex<HashMap<String, VecDeque<BufferedMessage>>>>,
    /// Track known epochs per conversation
    known_epochs: Arc<Mutex<HashMap<String, u64>>>,
    /// Database for persistence
    db: Arc<Db>,
    /// Current username
    username: Arc<Mutex<Option<String>>>,
}

pub struct BufferedMessage {
    pub sender: String,
    pub mls_message_b64: String,
    pub received_at: DateTime<Utc>,
    pub retry_count: i32,
    pub db_id: Option<i64>,
}

pub struct BufferStats {
    pub total_memory_messages: usize,
    pub conversations_with_pending: usize,
    pub tracked_epochs: usize,
}
```

#### Constants

```rust
pub const MAX_BUFFER_AGE_SECS: i64 = 300;   // 5 minutes
pub const MAX_BUFFER_SIZE: usize = 100;      // Per conversation
pub const MAX_RETRY_COUNT: i32 = 10;
```

#### Key Methods

| Method | Description |
|--------|-------------|
| `new(db)` | Create buffer |
| `set_username(username)` | Set current user |
| `queue_message(conv_id, sender, msg)` | Buffer a message |
| `update_epoch(conv_id, epoch)` | Update known epoch |
| `get_retry_candidates(conv_id)` | Get messages to retry |
| `mark_processed(conv_id, msg)` | Mark as processed |
| `mark_failed(conv_id, msg, error)` | Mark as failed |
| `increment_retry(conv_id, msg)` | Increment retry count |
| `cleanup_expired(max_age)` | Remove old messages |
| `reload_from_db()` | Recover after restart |

#### Processing Flow

```
Message arrives from mixnet
  │
  ├─ Try MLS decryption
  │   │
  │   ├─ Success
  │   │   ├─ Return decrypted message
  │   │   └─ Process buffered messages (may now succeed)
  │   │
  │   └─ Epoch error
  │       └─ Queue in buffer
  │           ├─ Store in memory (up to MAX_BUFFER_SIZE)
  │           └─ Persist to database
  │
  └─ Background processor (every 5s)
      │
      ├─ Get conversations with pending
      ├─ For each: try process buffered
      │   ├─ Success → mark processed
      │   ├─ Still epoch error → increment retry
      │   └─ Max retries → mark failed
      │
      └─ Cleanup expired (every ~1 min)
```

---

### 4. Key Packages (`key_packages.rs`)

#### Purpose
Manage MLS key package generation and exchange.

#### Structure

```rust
pub struct KeyPackageManager {
    stored: HashMap<String, String>,  // username -> key_package_b64
    db: Arc<Db>,
}

pub struct KeyPackageValidationResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub cipher_suite: Option<String>,
    pub protocol_version: Option<String>,
}
```

#### Key Methods

| Method | Description |
|--------|-------------|
| `new(db)` | Create manager |
| `store_key_package(username, key_package)` | Store received package |
| `validate_key_package(key_package_b64)` | Basic validation |
| `validate_key_package_detailed(key_package_b64)` | Full validation |
| `get_key_package(username)` | Retrieve stored package |

---

### 5. Types (`types.rs`)

#### Purpose
Define MLS-related data structures.

```rust
pub struct EncryptedMessage {
    pub conversation_id: Vec<u8>,
    pub mls_message: Vec<u8>,
    pub message_type: MlsMessageType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MlsMessageType {
    Commit,
    Application,
    Welcome,
    KeyPackage,
}

#[derive(Debug, Clone)]
pub struct MlsGroupInfo {
    pub group_id: Vec<u8>,
    pub client_identity: String,
}

#[derive(Debug, Clone)]
pub struct ConversationInfo {
    pub conversation_id: Vec<u8>,
    pub conversation_type: ConversationType,
    pub participants: u32,
    pub welcome_message: Option<Vec<u8>>,
    pub group_info: MlsGroupInfo,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConversationType {
    OneToOne,
    Group,
}
```

---

### 6. Persistence (`persistence.rs`)

#### Purpose
Manage MLS group state persistence with caching.

```rust
pub struct MlsGroupPersistence {
    username: String,
    db: Arc<Db>,
    cache: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
}
```

#### Methods

| Method | Description |
|--------|-------------|
| `new(username, db)` | Create persistence layer |
| `save_group_state(group_id, state)` | Save with caching |
| `load_group_state(group_id)` | Load with cache check |
| `delete_group_state(group_id)` | Remove state |
| `group_exists(group_id)` | Check existence |
| `clear_cache()` | Clear memory cache |

---

## PGP Submodule (`crypto/pgp/`)

### Purpose

Provide PGP key management and digital signature operations for authentication.

### 1. Keypair (`keypair.rs`)

#### Secure Passphrase

```rust
pub struct SecurePassphrase {
    inner: Zeroizing<String>,  // Cleared from memory on drop
}

impl SecurePassphrase {
    pub fn new(passphrase: String) -> Self;
    pub fn from_user_input() -> Result<Self>;  // Interactive prompt
    pub fn generate_strong() -> Self;          // Random 32-char passphrase
    pub fn expose_secret(&self) -> &str;       // Access passphrase
}
```

#### Key Manager

```rust
pub struct PgpKeyManager;

impl PgpKeyManager {
    /// Generate new Ed25519 keypair
    pub fn generate_keypair_secure(
        user_id: &str,
        passphrase: &SecurePassphrase,
    ) -> Result<(SignedSecretKey, SignedPublicKey)>;

    /// Generate RSA keypair (4096-bit)
    pub fn generate_keypair_rsa_secure(
        user_id: &str,
        passphrase: &SecurePassphrase,
    ) -> Result<(SignedSecretKey, SignedPublicKey)>;

    /// Save keys to files
    pub fn save_keypair_secure(
        username: &str,
        secret_key: &SignedSecretKey,
        public_key: &SignedPublicKey,
        passphrase: &SecurePassphrase,
    ) -> Result<()>;

    /// Load keys from files
    pub fn load_keypair_secure(
        username: &str,
        passphrase: &SecurePassphrase,
    ) -> Result<Option<(SignedSecretKey, SignedPublicKey)>>;

    /// Check if keys exist
    pub fn keys_exist(username: &str) -> bool;
}
```

#### Key Storage Format

Keys are stored in `storage/keys/`:
- `{username}_secret.asc` - Encrypted private key (PGP armor)
- `{username}_public.asc` - Public key (PGP armor)

---

### 2. Signing (`signing.rs`)

#### Types

```rust
pub struct VerifiedSignature {
    pub signer_id: String,
    pub is_valid: bool,
    pub created_at: Option<DateTime<Utc>>,
}
```

#### Signer

```rust
pub struct PgpSigner;

impl PgpSigner {
    /// Create detached signature
    pub fn sign_detached_secure(
        secret_key: &SignedSecretKey,
        data: &[u8],
        passphrase: &SecurePassphrase,
    ) -> Result<String>;  // Hex-encoded signature

    /// Verify detached signature
    pub fn verify_detached(
        public_key: &SignedPublicKey,
        data: &[u8],
        signature_hex: &str,
    ) -> Result<VerifiedSignature>;

    /// Create cleartext signature
    pub fn sign_cleartext(
        secret_key: &SignedSecretKey,
        message: &str,
        passphrase: &SecurePassphrase,
    ) -> Result<String>;
}
```

---

## Message Crypto (`message_crypto.rs`)

### Purpose

Message-level cryptographic operations for extracting and validating message components.

```rust
pub struct MessageCrypto;

impl MessageCrypto {
    /// Extract MLS message from envelope
    pub fn extract_mls_message(
        envelope: &MixnetMessage,
    ) -> Result<(String, String)>;  // (conversation_id, mls_message_b64)

    /// Extract key package from envelope
    pub fn extract_key_package(
        envelope: &MixnetMessage,
    ) -> Result<String>;

    /// Extract group welcome from envelope
    pub fn extract_group_welcome(
        envelope: &MixnetMessage,
    ) -> Result<(String, String)>;  // (welcome_message, group_id)

    /// Validate message structure
    pub fn validate_message_structure(
        envelope: &MixnetMessage,
    ) -> Result<()>;
}
```

---

## Security Considerations

### Key Hierarchy

```
PGP Master Key (long-term)
    │
    ├─── Signs all network messages
    │
    └─── MLS Signature Key (per-user)
              │
              ├─── Key Packages (ephemeral)
              │
              └─── Group Keys (per-epoch)
                       │
                       └─── Message Keys (per-message)
```

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Key compromise | Forward secrecy via MLS ratcheting |
| Network surveillance | Nym mixnet anonymity |
| Message tampering | PGP signatures |
| Replay attacks | Message timestamps |
| Key extraction | Passphrase-encrypted storage |
| Memory attacks | Zeroizing passphrases |

### Best Practices

1. **Key Storage**: All private keys encrypted at rest
2. **Passphrase Handling**: Use `SecurePassphrase` for memory safety
3. **Signature Verification**: Always verify signatures on received messages
4. **Epoch Management**: Use epoch buffer for reliable message delivery
5. **State Persistence**: Save MLS state after every operation
