# Nymstr Backend Integration Plan

## Executive Summary

This plan details the complete integration of the Nym mixnet backend from the existing `nymstr-app` TUI client into the new `nymstr-app-v2` Tauri desktop application. The integration covers all core functionality: PGP key management, Nym mixnet connectivity, authentication flows, direct P2P messaging, group messaging with MLS encryption, and epoch-aware message buffering.

---

## Phase 1: Core Dependencies and Project Structure

### 1.1 Add Required Dependencies to Cargo.toml

Add the following dependencies to `src-tauri/Cargo.toml`:

```toml
# Nym SDK for mixnet connectivity
nym-sdk = { git = "https://github.com/nymtech/nym", branch = "master" }

# PGP cryptography
pgp = "0.16"

# MLS (Message Layer Security) for end-to-end encryption
mls-rs = { version = "0.51.0", features = ["sqlite"] }
mls-rs-core = "0.24.0"
mls-rs-crypto-openssl = "0.18.0"
mls-rs-provider-sqlite = "0.19.0"

# Cryptographic utilities
aes-gcm = "0.10"
argon2 = "0.5"
hkdf = "0.12"
sha2 = "0.10"
hmac = "0.12"
rand = "0.8"
openssl = "0.10"

# Security
zeroize = { version = "1.7", features = ["derive"] }
subtle = "2.5"

# Serialization and encoding
base64 = "0.21"
hex = "0.4"

# Async and concurrency
tokio-stream = "0.1"

# Logging
log = "0.4"
env_logger = "0.9"

# Platform-specific
libc = "0.2"
```

### 1.2 Create New Module Structure

Create the following directory structure under `src-tauri/src/`:

```
src/
├── lib.rs                    # Update with new modules
├── main.rs                   # Entry point (unchanged)
├── commands/                 # Tauri commands (exists)
│   ├── mod.rs
│   ├── auth.rs              # Update with real implementation
│   ├── messaging.rs         # Update with real implementation
│   ├── contacts.rs          # Update with real implementation
│   ├── groups.rs            # Update with real implementation
│   └── connection.rs        # Update with real implementation
├── state/                    # Application state (exists)
│   └── mod.rs               # Update with new fields
├── types/                    # DTOs (exists)
│   └── mod.rs
├── events/                   # Event system (exists)
│   └── mod.rs
├── core/                     # NEW: Core backend modules
│   ├── mod.rs
│   ├── mixnet_client.rs     # Copy from nymstr-app
│   ├── messages.rs          # Copy from nymstr-app
│   ├── message_router.rs    # Copy from nymstr-app
│   ├── message_handler/     # Copy directory from nymstr-app
│   │   ├── mod.rs
│   │   ├── auth.rs
│   │   ├── mls.rs
│   │   ├── group.rs
│   │   ├── direct.rs
│   │   ├── welcome.rs
│   │   └── buffer.rs
│   └── db/                   # Copy directory from nymstr-app
│       ├── mod.rs
│       ├── user.rs
│       ├── contacts.rs
│       ├── messages.rs
│       ├── mls.rs
│       └── group.rs
├── tasks/                    # NEW: Background tasks
│   ├── mod.rs
│   ├── message_loop.rs
│   ├── buffer_processor.rs
│   └── connection_monitor.rs
└── crypto/                   # NEW: Cryptographic modules
    ├── mod.rs
    ├── utils.rs              # Copy from nymstr-app
    ├── message_crypto.rs     # Copy from nymstr-app
    ├── pgp/                  # Copy directory from nymstr-app
    │   ├── mod.rs
    │   ├── keypair.rs
    │   └── signing.rs
    └── mls/                  # Copy directory from nymstr-app
        ├── mod.rs
        ├── client.rs
        ├── key_packages.rs
        ├── types.rs
        ├── persistence.rs
        ├── conversation_manager.rs
        └── epoch_buffer.rs
```

---

## Phase 2: PGP Key Management Integration

### 2.1 Copy PGP Modules

Copy the following files from `nymstr-app/src/crypto/pgp/`:
- `keypair.rs` - Key generation, secure storage, and loading
- `signing.rs` - Digital signature creation and verification

Key types to expose:
- `SecurePassphrase` - Zeroizing passphrase wrapper
- `PgpKeyManager` - Key generation/storage/loading
- `PgpSigner` - Signing operations
- `VerifiedSignature` - Verification result

### 2.2 Update State Module

Update `src-tauri/src/state/mod.rs` to add:

```rust
use std::sync::Arc;
use tokio::sync::RwLock;
use pgp::composed::{SignedSecretKey, SignedPublicKey};

pub type ArcSecretKey = Arc<SignedSecretKey>;
pub type ArcPublicKey = Arc<SignedPublicKey>;
pub type ArcPassphrase = Arc<SecurePassphrase>;

pub struct AppState {
    // ... existing fields ...

    /// PGP secret key (Arc-wrapped for cheap cloning)
    pub pgp_secret_key: RwLock<Option<ArcSecretKey>>,

    /// PGP public key (Arc-wrapped for cheap cloning)
    pub pgp_public_key: RwLock<Option<ArcPublicKey>>,

    /// Secure passphrase (Arc-wrapped for cheap cloning)
    pub pgp_passphrase: RwLock<Option<ArcPassphrase>>,
}
```

### 2.3 Storage Location

Keys should be stored in:
- `{app_data_dir}/{username}/pgp_keys/secret.asc` - Encrypted private key
- `{app_data_dir}/{username}/pgp_keys/public.asc` - Public key
- `{app_data_dir}/{username}/pgp_keys/*.hmac` - Integrity verification files

---

## Phase 3: Mixnet Client Integration

### 3.1 Copy Mixnet Modules

Copy from `nymstr-app/src/core/`:
- `mixnet_client.rs` - MixnetService wrapper (~500 lines)
- `messages.rs` - MixnetMessage unified format
- `message_router.rs` - Message routing logic

### 3.2 Update State Module

Add to AppState:

```rust
use crate::core::mixnet_client::MixnetService;

pub struct AppState {
    // ... existing fields ...

    /// Mixnet service instance
    pub mixnet_service: RwLock<Option<Arc<MixnetService>>>,

    /// Incoming message receiver (for background task)
    pub message_rx: RwLock<Option<mpsc::Receiver<Incoming>>>,
}
```

### 3.3 Key MixnetService Methods

From `nymstr-app/src/core/mixnet_client.rs`:

```rust
impl MixnetService {
    pub async fn new(storage_path: PathBuf) -> Result<Self>;
    pub async fn connect(&mut self) -> Result<Recipient>;
    pub fn our_address(&self) -> &Recipient;
    pub async fn send_with_reply<T>(&self, msg: &MixnetMessage, recipient: &Recipient) -> Result<T>;
    pub async fn send_no_reply(&self, msg: &MixnetMessage, recipient: &Recipient) -> Result<()>;
    pub async fn send_mls_message(&self, encrypted: &EncryptedMessage, recipient: &Recipient) -> Result<()>;
}
```

### 3.4 Background Message Receive Loop

Create `src/tasks/message_loop.rs`:

```rust
pub async fn start_message_receive_loop(
    app_handle: AppHandle,
    state: Arc<AppState>,
    mut rx: mpsc::Receiver<Incoming>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(incoming) = rx.recv().await {
            let route = MessageRouter::route_message(&incoming);

            match route {
                MessageRoute::Authentication => {
                    // Forward to waiting auth command
                }
                MessageRoute::MlsProtocol | MessageRoute::Chat => {
                    // Decrypt and emit MessageReceived event
                    let emitter = EventEmitter::new(app_handle.clone());
                    emitter.message_received(message, conversation_id);
                }
                MessageRoute::Group => {
                    // Handle group responses
                }
                MessageRoute::WelcomeFlow => {
                    // Handle welcome messages
                }
                _ => {}
            }
        }
    })
}
```

---

## Phase 4: Authentication Flows

### 4.1 Registration Flow

Update `src-tauri/src/commands/auth.rs`:

```rust
#[tauri::command]
pub async fn register_user(
    state: State<'_, AppState>,
    app_handle: AppHandle,
    username: String,
    passphrase: String,
) -> Result<UserDTO, ApiError> {
    // 1. Validate username (alphanumeric, 1-64 chars)
    if !is_valid_username(&username) {
        return Err(ApiError::validation("Invalid username"));
    }

    // 2. Generate PGP keypair
    let secure_passphrase = SecurePassphrase::new(passphrase);
    let (secret_key, public_key) = PgpKeyManager::generate_keypair_secure(
        &username,
        &secure_passphrase,
    )?;

    // 3. Store keys locally
    let keys_dir = state.app_dir.join(&username).join("pgp_keys");
    std::fs::create_dir_all(&keys_dir)?;
    PgpKeyManager::store_keypair(
        &secret_key,
        &public_key,
        &secure_passphrase,
        &keys_dir,
    )?;

    // 4. Connect to mixnet if not connected
    let mixnet = ensure_mixnet_connected(&state).await?;

    // 5. Send registration request
    let server_address = state.get_server_address().await
        .ok_or(ApiError::validation("Server address not configured"))?;
    let recipient = Recipient::try_from_base58_string(&server_address)?;

    let public_key_armored = public_key.to_armored_string()?;
    let reg_msg = MixnetMessage::register(&username, &public_key_armored);

    // 6. Wait for challenge
    let challenge: ChallengeResponse = mixnet.send_with_reply(&reg_msg, &recipient).await?;

    // 7. Sign nonce
    let signature = PgpSigner::sign_message(
        &secret_key,
        &secure_passphrase,
        challenge.nonce.as_bytes(),
    )?;

    // 8. Send challenge response
    let response_msg = MixnetMessage::challenge_response(&username, &signature);
    let result: RegistrationResult = mixnet.send_with_reply(&response_msg, &recipient).await?;

    if !result.success {
        return Err(ApiError::new("REGISTRATION_FAILED", result.error.unwrap_or_default()));
    }

    // 9. Store user in database
    save_user_to_db(&state.db, &username, &public_key_armored).await?;

    // 10. Update state
    let user = UserDTO {
        username: username.clone(),
        display_name: username.clone(),
        public_key: public_key_armored,
        online: true,
    };
    state.set_current_user(Some(user.clone())).await;

    // Store Arc-wrapped keys in state
    *state.pgp_secret_key.write().await = Some(Arc::new(secret_key));
    *state.pgp_public_key.write().await = Some(Arc::new(public_key));
    *state.pgp_passphrase.write().await = Some(Arc::new(secure_passphrase));

    Ok(user)
}
```

### 4.2 Login Flow

```rust
#[tauri::command]
pub async fn login_user(
    state: State<'_, AppState>,
    username: String,
    passphrase: String,
) -> Result<UserDTO, ApiError> {
    // 1. Load PGP keys from disk
    let keys_dir = state.app_dir.join(&username).join("pgp_keys");
    let secure_passphrase = SecurePassphrase::new(passphrase);

    let (secret_key, public_key) = PgpKeyManager::load_keypair(
        &keys_dir,
        &secure_passphrase,
    ).map_err(|_| ApiError::unauthorized("Invalid passphrase or keys not found"))?;

    // 2. Store Arc-wrapped keys in state
    *state.pgp_secret_key.write().await = Some(Arc::new(secret_key.clone()));
    *state.pgp_public_key.write().await = Some(Arc::new(public_key.clone()));
    *state.pgp_passphrase.write().await = Some(Arc::new(secure_passphrase.clone()));

    // 3. Connect to mixnet
    let mixnet = ensure_mixnet_connected(&state).await?;

    // 4. Send login request
    let server_address = state.get_server_address().await
        .ok_or(ApiError::validation("Server address not configured"))?;
    let recipient = Recipient::try_from_base58_string(&server_address)?;

    let login_msg = MixnetMessage::login(&username);

    // 5. Wait for challenge
    let challenge: ChallengeResponse = mixnet.send_with_reply(&login_msg, &recipient).await?;

    // 6. Sign nonce
    let signature = PgpSigner::sign_message(
        &secret_key,
        &secure_passphrase,
        challenge.nonce.as_bytes(),
    )?;

    // 7. Send login response
    let response_msg = MixnetMessage::login_response(&username, &signature);
    let result: LoginResult = mixnet.send_with_reply(&response_msg, &recipient).await?;

    if !result.success {
        return Err(ApiError::unauthorized("Login failed"));
    }

    // 8. Set current user
    let user = UserDTO {
        username: username.clone(),
        display_name: username.clone(),
        public_key: public_key.to_armored_string()?,
        online: true,
    };
    state.set_current_user(Some(user.clone())).await;

    // 9. Start background tasks
    start_background_tasks(&state, &app_handle).await;

    Ok(user)
}
```

### 4.3 Event Emissions

Add to `events/mod.rs`:

```rust
pub enum AppEvent {
    // Authentication
    AuthChallenge { context: String },
    RegistrationSuccess { username: String },
    RegistrationFailed { error: String },
    LoginSuccess { username: String },
    LoginFailed { error: String },

    // Connection
    MixnetConnected { address: String },
    MixnetDisconnected { reason: String },

    // Messaging
    MessageReceived { message: MessageDTO, conversation_id: String },
    MessageSent { message: MessageDTO },
    MessageDelivered { message_id: String },
    MessageFailed { message_id: String, error: String },

    // Groups
    GroupJoined { group: GroupDTO },
    GroupLeft { group_id: String },
    GroupMessageReceived { message: MessageDTO, group_id: String },
}
```

---

## Phase 5: Direct Messaging

### 5.1 MLS Conversation Establishment

The flow for establishing an MLS conversation:

```
Alice                          Discovery Server                    Bob
  │                                    │                             │
  │── keyPackageRequest(bob) ─────────►│                             │
  │                                    │── keyPackageRequest ───────►│
  │                                    │                             │
  │                                    │◄── keyPackageResponse ──────│
  │◄── keyPackageResponse ─────────────│                             │
  │                                    │                             │
  │  [Create MLS group]                │                             │
  │  [Add Bob with KeyPackage]         │                             │
  │  [Generate Welcome]                │                             │
  │                                    │                             │
  │── groupWelcome(bob, welcome) ─────►│                             │
  │                                    │── groupWelcome ────────────►│
  │                                    │                             │
  │                                    │◄── groupJoinResponse ───────│
  │◄── groupJoinResponse ──────────────│                             │
  │                                    │                             │
  │  [Conversation established!]       │                             │
```

### 5.2 Update Messaging Commands

```rust
#[tauri::command]
pub async fn send_message(
    state: State<'_, AppState>,
    recipient: String,
    content: String,
) -> Result<MessageDTO, ApiError> {
    // 1. Get current user
    let current_user = state.get_current_user().await
        .ok_or(ApiError::unauthorized("Not logged in"))?;

    // 2. Get MLS client
    let mls_client = state.mls_client.read().await
        .as_ref()
        .ok_or(ApiError::internal("MLS not initialized"))?
        .clone();

    // 3. Get or create MLS conversation
    let conversation_id = get_or_create_conversation(
        &state,
        &mls_client,
        &recipient,
    ).await?;

    // 4. Encrypt message with MLS
    let encrypted = mls_client.encrypt_message(
        &conversation_id,
        content.as_bytes(),
    ).await?;

    // 5. Get PGP keys for signing
    let secret_key = state.pgp_secret_key.read().await
        .as_ref()
        .ok_or(ApiError::internal("PGP keys not loaded"))?
        .clone();
    let passphrase = state.pgp_passphrase.read().await
        .as_ref()
        .ok_or(ApiError::internal("Passphrase not loaded"))?
        .clone();

    // 6. Sign the encrypted message
    let signature = PgpSigner::sign_message(
        &secret_key,
        &passphrase,
        &encrypted.ciphertext,
    )?;

    // 7. Send via mixnet
    let mixnet = state.mixnet_service.read().await
        .as_ref()
        .ok_or(ApiError::internal("Not connected"))?
        .clone();

    let recipient_address = get_recipient_address(&state, &recipient).await?;
    mixnet.send_mls_message(&encrypted, &recipient_address).await?;

    // 8. Store locally with pending status
    let message_id = uuid::Uuid::new_v4().to_string();
    let message = MessageDTO {
        id: message_id,
        sender: current_user.username,
        content,
        timestamp: chrono::Utc::now().to_rfc3339(),
        status: MessageStatus::Pending,
        is_own: true,
    };

    save_message_to_db(&state.db, &conversation_id, &message).await?;

    Ok(message)
}
```

---

## Phase 6: Group Messaging with MLS

### 6.1 Copy MLS Modules

Copy entire directory from `nymstr-app/src/crypto/mls/`:
- `client.rs` - MlsClient, MlsKeyManager, PgpCredential, PgpIdentityProvider
- `conversation_manager.rs` - MlsConversationManager
- `epoch_buffer.rs` - EpochAwareBuffer for out-of-order handling
- `key_packages.rs` - KeyPackageManager
- `types.rs` - EncryptedMessage, MlsWelcome, etc.
- `persistence.rs` - MlsGroupPersistence

### 6.2 MLS Client Initialization

Add to login flow:

```rust
// Initialize MLS client after loading PGP keys
let mls_storage_path = state.app_dir.join(&username).join("mls.db");
let mls_client = MlsClient::new(
    &username,
    secret_key.clone(),
    public_key.clone(),
    mls_storage_path,
).await?;

*state.mls_client.write().await = Some(Arc::new(mls_client));
```

### 6.3 Group Commands

```rust
#[tauri::command]
pub async fn join_group(
    state: State<'_, AppState>,
    group_address: String,
) -> Result<GroupDTO, ApiError> {
    let current_user = state.get_current_user().await
        .ok_or(ApiError::unauthorized("Not logged in"))?;

    // 1. Authenticate with group server (timestamp-based signature)
    let timestamp = chrono::Utc::now().to_rfc3339();
    let auth_data = format!("{}:{}", current_user.username, timestamp);

    let secret_key = state.pgp_secret_key.read().await.as_ref().unwrap().clone();
    let passphrase = state.pgp_passphrase.read().await.as_ref().unwrap().clone();
    let signature = PgpSigner::sign_message(&secret_key, &passphrase, auth_data.as_bytes())?;

    // 2. Send registration to group server
    let mixnet = state.mixnet_service.read().await.as_ref().unwrap().clone();
    let recipient = Recipient::try_from_base58_string(&group_address)?;

    let public_key = state.pgp_public_key.read().await.as_ref().unwrap().clone();
    let reg_msg = MixnetMessage::group_register(
        &current_user.username,
        &public_key.to_armored_string()?,
        &timestamp,
        &signature,
    );

    let result: GroupJoinResult = mixnet.send_with_reply(&reg_msg, &recipient).await?;

    if !result.approved {
        return Err(ApiError::new("PENDING_APPROVAL", "Waiting for admin approval"));
    }

    // 3. Store group membership locally
    let group = GroupDTO {
        id: result.group_id,
        name: result.group_name,
        address: group_address.clone(),
        member_count: result.member_count,
        is_public: result.is_public,
        description: result.description,
    };

    save_group_to_db(&state.db, &group).await?;

    // 4. Initialize MLS group if welcome provided
    if let Some(welcome_bytes) = result.welcome {
        let mls_client = state.mls_client.read().await.as_ref().unwrap().clone();
        mls_client.process_welcome(&welcome_bytes).await?;
    }

    Ok(group)
}

#[tauri::command]
pub async fn send_group_message(
    state: State<'_, AppState>,
    group_address: String,
    content: String,
) -> Result<MessageDTO, ApiError> {
    let current_user = state.get_current_user().await
        .ok_or(ApiError::unauthorized("Not logged in"))?;

    // 1. Get MLS group ID for this server
    let mls_group_id = get_mls_group_id(&state.db, &group_address).await?;

    // 2. Encrypt with MLS
    let mls_client = state.mls_client.read().await.as_ref().unwrap().clone();
    let encrypted = mls_client.encrypt_message(&mls_group_id, content.as_bytes()).await?;

    // 3. Sign with PGP
    let secret_key = state.pgp_secret_key.read().await.as_ref().unwrap().clone();
    let passphrase = state.pgp_passphrase.read().await.as_ref().unwrap().clone();
    let signature = PgpSigner::sign_message(&secret_key, &passphrase, &encrypted.ciphertext)?;

    // 4. Send to group server
    let mixnet = state.mixnet_service.read().await.as_ref().unwrap().clone();
    let recipient = Recipient::try_from_base58_string(&group_address)?;

    let msg = MixnetMessage::send_group(
        &current_user.username,
        &base64::encode(&encrypted.ciphertext),
        &signature,
    );

    let result: SendGroupResult = mixnet.send_with_reply(&msg, &recipient).await?;

    // 5. Create local message record
    let message = MessageDTO {
        id: result.message_id,
        sender: current_user.username,
        content,
        timestamp: chrono::Utc::now().to_rfc3339(),
        status: MessageStatus::Sent,
        is_own: true,
    };

    save_message_to_db(&state.db, &group_address, &message).await?;

    Ok(message)
}

#[tauri::command]
pub async fn fetch_group_messages(
    state: State<'_, AppState>,
    group_address: String,
    limit: Option<u32>,
) -> Result<Vec<MessageDTO>, ApiError> {
    let current_user = state.get_current_user().await
        .ok_or(ApiError::unauthorized("Not logged in"))?;

    // 1. Get cursor from database
    let cursor = get_group_cursor(&state.db, &group_address).await?;

    // 2. Sign fetch request
    let secret_key = state.pgp_secret_key.read().await.as_ref().unwrap().clone();
    let passphrase = state.pgp_passphrase.read().await.as_ref().unwrap().clone();
    let signature = PgpSigner::sign_message(
        &secret_key,
        &passphrase,
        format!("{}:{}", current_user.username, cursor).as_bytes(),
    )?;

    // 3. Send fetch request
    let mixnet = state.mixnet_service.read().await.as_ref().unwrap().clone();
    let recipient = Recipient::try_from_base58_string(&group_address)?;

    let msg = MixnetMessage::fetch_group(
        &current_user.username,
        cursor,
        &signature,
    );

    let result: FetchGroupResult = mixnet.send_with_reply(&msg, &recipient).await?;

    // 4. Decrypt each message with MLS
    let mls_client = state.mls_client.read().await.as_ref().unwrap().clone();
    let mls_group_id = get_mls_group_id(&state.db, &group_address).await?;

    let mut messages = Vec::new();
    for encrypted_msg in result.messages {
        match mls_client.decrypt_message(&mls_group_id, &encrypted_msg.ciphertext).await {
            Ok(plaintext) => {
                let content = String::from_utf8_lossy(&plaintext).to_string();
                messages.push(MessageDTO {
                    id: encrypted_msg.id,
                    sender: encrypted_msg.sender,
                    content,
                    timestamp: encrypted_msg.timestamp,
                    status: MessageStatus::Delivered,
                    is_own: encrypted_msg.sender == current_user.username,
                });
            }
            Err(MlsError::EpochMismatch) => {
                // Buffer for later retry
                buffer_message(&state, &mls_group_id, &encrypted_msg).await?;
            }
            Err(e) => {
                tracing::warn!("Failed to decrypt message: {}", e);
            }
        }
    }

    // 5. Update cursor
    if let Some(last) = result.messages.last() {
        update_group_cursor(&state.db, &group_address, last.id).await?;
    }

    // 6. Store decrypted messages
    for msg in &messages {
        save_message_to_db(&state.db, &group_address, msg).await?;
    }

    Ok(messages)
}
```

### 6.4 Epoch-Aware Buffering

Copy `epoch_buffer.rs` from nymstr-app. The buffer handles:

1. **Queue on epoch mismatch**: When MLS decryption fails due to epoch mismatch
2. **Persist to database**: Buffered messages survive app restart
3. **Retry on epoch advance**: When a Commit is processed, retry buffered messages
4. **Background processor**: Periodic retry of buffered messages

```rust
// tasks/buffer_processor.rs
pub async fn start_buffer_processor(
    state: Arc<AppState>,
    app_handle: AppHandle,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));

        loop {
            interval.tick().await;

            let mls_client = match state.mls_client.read().await.as_ref() {
                Some(c) => c.clone(),
                None => continue,
            };

            // Get buffered messages from database
            let buffered = get_buffered_messages(&state.db).await.unwrap_or_default();

            for msg in buffered {
                match mls_client.decrypt_message(&msg.group_id, &msg.ciphertext).await {
                    Ok(plaintext) => {
                        // Success! Remove from buffer and emit event
                        remove_from_buffer(&state.db, msg.id).await.ok();

                        let emitter = EventEmitter::new(app_handle.clone());
                        emitter.group_message_received(/* ... */);
                    }
                    Err(MlsError::EpochMismatch) => {
                        // Still can't decrypt, keep buffered
                        increment_retry_count(&state.db, msg.id).await.ok();
                    }
                    Err(_) => {
                        // Permanent failure, remove from buffer
                        remove_from_buffer(&state.db, msg.id).await.ok();
                    }
                }
            }

            // Clean up old messages (> 5 minutes)
            cleanup_expired_buffer(&state.db, Duration::from_secs(300)).await.ok();
        }
    })
}
```

---

## Phase 7: Database Schema Updates

### 7.1 Additional Tables

Add to migrations in `state/mod.rs`:

```sql
-- MLS Groups
CREATE TABLE IF NOT EXISTS mls_groups (
    conversation_id TEXT PRIMARY KEY,
    group_state BLOB,
    updated_at TEXT
);

-- MLS Credentials
CREATE TABLE IF NOT EXISTS mls_credentials (
    username TEXT PRIMARY KEY,
    pgp_key_fingerprint BLOB,
    mls_signature_key BLOB,
    credential_type TEXT,
    issued_at INTEGER,
    expires_at INTEGER,
    credential_data BLOB,
    updated_at TEXT
);

-- Key Packages
CREATE TABLE IF NOT EXISTS key_packages (
    id INTEGER PRIMARY KEY,
    key_package_b64 TEXT,
    credential_username TEXT,
    cipher_suite TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT,
    used INTEGER DEFAULT 0
);

-- Group Welcomes
CREATE TABLE IF NOT EXISTS group_welcomes (
    id INTEGER PRIMARY KEY,
    group_id TEXT,
    sender TEXT,
    welcome_bytes BLOB,
    ratchet_tree BLOB,
    cipher_suite INTEGER,
    epoch INTEGER,
    received_at TEXT,
    processed INTEGER DEFAULT 0,
    processed_at TEXT,
    error_message TEXT
);

-- Group Memberships
CREATE TABLE IF NOT EXISTS group_members (
    conversation_id TEXT,
    member_username TEXT,
    credential_fingerprint TEXT,
    credential_verified INTEGER,
    verified_at TEXT,
    joined_at TEXT DEFAULT CURRENT_TIMESTAMP,
    role TEXT DEFAULT 'member',
    PRIMARY KEY (conversation_id, member_username)
);

-- Pending MLS Messages (epoch buffer)
CREATE TABLE IF NOT EXISTS pending_mls_messages (
    id INTEGER PRIMARY KEY,
    conversation_id TEXT,
    sender TEXT,
    mls_message_b64 TEXT,
    received_at TEXT DEFAULT CURRENT_TIMESTAMP,
    retry_count INTEGER DEFAULT 0,
    last_retry_at TEXT,
    status TEXT DEFAULT 'pending',
    error_message TEXT
);

-- Group Servers
CREATE TABLE IF NOT EXISTS group_servers (
    server_address TEXT PRIMARY KEY,
    mls_group_id TEXT,
    last_cursor INTEGER DEFAULT 0,
    joined_at TEXT DEFAULT CURRENT_TIMESTAMP
);
```

---

## Phase 8: Background Tasks

### 8.1 Task Module Structure

```rust
// tasks/mod.rs
pub mod message_loop;
pub mod buffer_processor;
pub mod connection_monitor;

use std::sync::Arc;
use tauri::AppHandle;
use tokio::task::JoinHandle;

pub struct BackgroundTasks {
    pub message_loop: Option<JoinHandle<()>>,
    pub buffer_processor: Option<JoinHandle<()>>,
    pub connection_monitor: Option<JoinHandle<()>>,
}

impl BackgroundTasks {
    pub async fn start(state: Arc<AppState>, app_handle: AppHandle) -> Self {
        let message_loop = message_loop::start(state.clone(), app_handle.clone()).await;
        let buffer_processor = buffer_processor::start(state.clone(), app_handle.clone()).await;
        let connection_monitor = connection_monitor::start(state.clone(), app_handle.clone()).await;

        Self {
            message_loop: Some(message_loop),
            buffer_processor: Some(buffer_processor),
            connection_monitor: Some(connection_monitor),
        }
    }

    pub async fn stop(&mut self) {
        if let Some(handle) = self.message_loop.take() {
            handle.abort();
        }
        if let Some(handle) = self.buffer_processor.take() {
            handle.abort();
        }
        if let Some(handle) = self.connection_monitor.take() {
            handle.abort();
        }
    }
}
```

### 8.2 Connection Monitor

```rust
// tasks/connection_monitor.rs
pub async fn start(
    state: Arc<AppState>,
    app_handle: AppHandle,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        let emitter = EventEmitter::new(app_handle);

        loop {
            interval.tick().await;

            let is_connected = state.mixnet_service.read().await
                .as_ref()
                .map(|s| s.is_connected())
                .unwrap_or(false);

            let current_status = state.get_connection_status().await;

            if is_connected != current_status.connected {
                if is_connected {
                    let address = state.mixnet_service.read().await
                        .as_ref()
                        .map(|s| s.our_address().to_string());
                    state.set_connection_status(true, address.clone()).await;
                    emitter.emit("mixnet_connected", address);
                } else {
                    state.set_connection_status(false, None).await;
                    emitter.emit("mixnet_disconnected", "Connection lost");

                    // Attempt reconnection
                    if let Err(e) = reconnect(&state).await {
                        tracing::error!("Reconnection failed: {}", e);
                    }
                }
            }
        }
    })
}
```

---

## Critical Source Files Reference

| Purpose | Source File (nymstr-app) | Target Location |
|---------|--------------------------|-----------------|
| Mixnet connectivity | `src/core/mixnet_client.rs` | `src/core/mixnet_client.rs` |
| Message format | `src/core/messages.rs` | `src/core/messages.rs` |
| Message routing | `src/core/message_router.rs` | `src/core/message_router.rs` |
| Auth handler | `src/core/message_handler/auth.rs` | `src/core/message_handler/auth.rs` |
| MLS handler | `src/core/message_handler/mls.rs` | `src/core/message_handler/mls.rs` |
| Group handler | `src/core/message_handler/group.rs` | `src/core/message_handler/group.rs` |
| Direct handler | `src/core/message_handler/direct.rs` | `src/core/message_handler/direct.rs` |
| Welcome handler | `src/core/message_handler/welcome.rs` | `src/core/message_handler/welcome.rs` |
| Buffer processor | `src/core/message_handler/buffer.rs` | `src/tasks/buffer_processor.rs` |
| PGP keypair | `src/crypto/pgp/keypair.rs` | `src/crypto/pgp/keypair.rs` |
| PGP signing | `src/crypto/pgp/signing.rs` | `src/crypto/pgp/signing.rs` |
| MLS client | `src/crypto/mls/client.rs` | `src/crypto/mls/client.rs` |
| MLS conversations | `src/crypto/mls/conversation_manager.rs` | `src/crypto/mls/conversation_manager.rs` |
| Epoch buffer | `src/crypto/mls/epoch_buffer.rs` | `src/crypto/mls/epoch_buffer.rs` |
| Key packages | `src/crypto/mls/key_packages.rs` | `src/crypto/mls/key_packages.rs` |
| Database user | `src/core/db/user.rs` | `src/core/db/user.rs` |
| Database contacts | `src/core/db/contacts.rs` | `src/core/db/contacts.rs` |
| Database messages | `src/core/db/messages.rs` | `src/core/db/messages.rs` |
| Database MLS | `src/core/db/mls.rs` | `src/core/db/mls.rs` |
| Database groups | `src/core/db/group.rs` | `src/core/db/group.rs` |

---

## Implementation Checklist

### Week 1: Foundation
- [ ] Add dependencies to Cargo.toml
- [ ] Create module directory structure
- [ ] Copy and adapt PGP modules
- [ ] Implement SecurePassphrase with zeroize
- [ ] Test key generation/storage/loading

### Week 2: Mixnet Connectivity
- [ ] Copy mixnet_client.rs
- [ ] Copy messages.rs
- [ ] Copy message_router.rs
- [ ] Update AppState with mixnet fields
- [ ] Implement connect_to_mixnet command
- [ ] Test connectivity with real network

### Week 3: Authentication
- [ ] Implement full registration flow
- [ ] Implement full login flow
- [ ] Add challenge-response handling
- [ ] Test with nymstr-server

### Week 4: Direct Messaging
- [ ] Copy MLS modules
- [ ] Implement MLS client initialization
- [ ] Implement key package exchange
- [ ] Implement send_message with encryption
- [ ] Test P2P messaging

### Week 5: Group Messaging
- [ ] Implement join_group
- [ ] Implement send_group_message
- [ ] Implement fetch_group_messages
- [ ] Implement epoch buffering
- [ ] Test with nymstr-group server

### Week 6: Background Tasks & Polish
- [ ] Implement message receive loop
- [ ] Implement buffer processor
- [ ] Implement connection monitor
- [ ] Error handling improvements
- [ ] Integration testing

---

*Generated: 2026-01-18*
