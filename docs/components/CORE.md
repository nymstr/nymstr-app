# Core Module Documentation

## Overview

The `core` module (`src/core/`) contains the fundamental messaging infrastructure for Nymstr. It handles database persistence, network communication, message routing, and authentication.

## Module Structure

```
src/core/
├── mod.rs              # Module exports
├── db.rs               # SQLite persistence layer
├── messages.rs         # Message envelope format
├── message_handler.rs  # High-level message operations
├── message_router.rs   # Message routing logic
├── mixnet_client.rs    # Nym mixnet integration
├── auth_handler.rs     # Authentication flows
└── chat_handler.rs     # Chat message processing
```

---

## Components

### 1. Database (`db.rs`)

#### Purpose
SQLite persistence layer for all application data including users, contacts, messages, MLS group state, and pending messages.

#### Schema

```sql
-- Global user registry
CREATE TABLE users (
    username TEXT PRIMARY KEY,
    public_key TEXT NOT NULL
);

-- Per-user tables (created with init_user)
CREATE TABLE contacts_{user} (
    username TEXT PRIMARY KEY,
    public_key TEXT NOT NULL
);

CREATE TABLE messages_{user} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    type TEXT CHECK(type IN ('to','from')) NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE mls_groups_{user} (
    conversation_id TEXT PRIMARY KEY,
    group_state BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE pending_mls_messages_{user} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    mls_message_b64 TEXT NOT NULL,
    received_at TEXT NOT NULL,
    retry_count INTEGER DEFAULT 0,
    last_retry_at TEXT,
    status TEXT DEFAULT 'pending',
    error_message TEXT,
    UNIQUE(conversation_id, mls_message_b64)
);
```

#### Key Types

```rust
pub struct Db {
    pool: SqlitePool,
}

pub struct PendingMlsMessage {
    pub id: i64,
    pub conversation_id: String,
    pub sender: String,
    pub mls_message_b64: String,
    pub received_at: String,
    pub retry_count: i32,
    pub last_retry_at: Option<String>,
    pub status: String,
    pub error_message: Option<String>,
}
```

#### Key Methods

| Method | Description |
|--------|-------------|
| `open(path)` | Open/create database at path |
| `init_global()` | Create global tables |
| `init_user(username)` | Create per-user tables |
| `register_user(username, public_key)` | Register new user |
| `save_message(...)` | Persist a message |
| `load_messages(me, contact)` | Load conversation history |
| `save_mls_group_state(...)` | Persist MLS group state |
| `store_pending_message(...)` | Queue message for retry |
| `get_pending_messages(...)` | Get buffered messages |
| `cleanup_expired_messages(...)` | Remove old pending messages |

#### Security Considerations

- Table names are sanitized via `sanitize_table_name()` to prevent SQL injection
- Only alphanumeric characters and underscores allowed in usernames
- Maximum username length of 64 characters enforced

---

### 2. Messages (`messages.rs`)

#### Purpose
Define the unified message envelope format used for all mixnet communication.

#### Message Format

```rust
pub struct MixnetMessage {
    pub message_type: String,  // "message", "response", "system"
    pub action: String,        // Operation type
    pub sender: String,
    pub recipient: String,
    pub payload: serde_json::Value,
    pub signature: String,     // PGP signature (hex)
    pub timestamp: String,     // ISO-8601
}
```

#### Message Types

| message_type | Description |
|--------------|-------------|
| `message` | Outgoing request/message |
| `response` | Server response |
| `system` | System notification |

#### Actions

| Action | Direction | Description |
|--------|-----------|-------------|
| `register` | → Server | Registration request |
| `login` | → Server | Login request |
| `challenge` | ← Server | Auth challenge |
| `challengeResponse` | ↔ | Challenge response |
| `query` | → Server | User lookup |
| `queryResponse` | ← Server | User info |
| `send` | → Recipient | Chat message |
| `incomingMessage` | ← Sender | Received message |
| `keyPackageRequest` | → Recipient | MLS handshake start |
| `keyPackageResponse` | ← Recipient | MLS handshake reply |
| `groupWelcome` | → Recipient | MLS group invitation |
| `groupJoinResponse` | ← Recipient | MLS join confirmation |

#### Builder Methods

```rust
impl MixnetMessage {
    pub fn register(username, public_key) -> Self;
    pub fn login(username) -> Self;
    pub fn query(username) -> Self;
    pub fn send(sender, recipient, body) -> Self;
    pub fn set_signature(&mut self, signature);
}
```

---

### 3. Message Handler (`message_handler.rs`)

#### Purpose
High-level orchestration of all message send/receive operations.

#### Structure

```rust
pub struct MessageHandler {
    pub crypto: Crypto,
    pub service: MixnetService,
    pub incoming_rx: Receiver<Incoming>,
    pub db: Arc<Db>,
    pub current_user: Option<String>,
    pub nym_address: Option<String>,
    pub mls_storage_path: Option<String>,
    pub pgp_public_key: Option<SignedPublicKey>,
    pub pgp_secret_key: Option<SignedSecretKey>,
    pub pgp_passphrase: Option<SecurePassphrase>,
    pub key_package_manager: KeyPackageManager,
    pub mls_persistence: Option<MlsGroupPersistence>,
}
```

#### Key Methods

| Method | Description |
|--------|-------------|
| `new(service, incoming_rx, db_path)` | Create handler |
| `set_pgp_keys(secret, public, passphrase)` | Set session keys |
| `register_user(username)` | Full registration flow |
| `login_user(username)` | Full login flow |
| `query_user(username)` | Lookup user |
| `send_direct_message(recipient, content)` | Send encrypted message |
| `send_handshake(recipient)` | P2P handshake |
| `process_received_message(incoming)` | Process incoming |

#### Registration Flow

```
1. Ensure PGP keys available
2. Initialize MLS storage
3. Store user in database
4. Send registration request
5. Wait for challenge
6. Sign challenge with PGP
7. Send challenge response
8. Process server response
9. Initialize user tables on success
```

#### Message Processing Flow

```
1. Route message via MessageRouter
2. Check if should process immediately
3. Create handlers (AuthHandler, MlsManager, ChatHandler)
4. Initialize epoch buffer
5. Process based on route type
6. Return decrypted messages
```

---

### 4. Message Router (`message_router.rs`)

#### Purpose
Route incoming messages to appropriate handlers based on message type and action.

#### Routes

```rust
pub enum MessageRoute {
    Authentication,  // challenge, challengeResponse
    Query,          // query, queryResponse
    Chat,           // Plain chat messages
    Handshake,      // P2P handshake
    MlsProtocol,    // MLS messages (keyPackage*, groupWelcome, etc.)
    System,         // System messages
    Unknown,
}
```

#### Routing Logic

```rust
pub fn route_message(incoming: &Incoming) -> MessageRoute {
    match action {
        "challenge" | "challengeResponse" => Authentication,
        "query" | "queryResponse" => Query,
        "keyPackageRequest" | "keyPackageResponse" |
        "groupWelcome" | "groupJoinResponse" => MlsProtocol,
        "send" | "incomingMessage" => {
            if payload contains MLS data => MlsProtocol
            else if payload contains handshake => Handshake
            else => Chat
        }
        _ => Unknown
    }
}
```

---

### 5. Mixnet Client (`mixnet_client.rs`)

#### Purpose
Integration with the Nym mixnet SDK for anonymous network communication.

#### Structure

```rust
pub struct MixnetService {
    client: MixnetClient,
    server_address: Recipient,
}

pub struct Incoming {
    pub envelope: MixnetMessage,
    pub received_at: DateTime<Utc>,
}
```

#### Key Methods

| Method | Description |
|--------|-------------|
| `connect(server_address)` | Connect to mixnet |
| `send_registration_request(...)` | Send registration |
| `send_login_request(...)` | Send login |
| `send_query_request(...)` | Query user |
| `send_mls_message(...)` | Send MLS message |
| `send_key_package_request(...)` | MLS handshake |
| `send_group_welcome(...)` | MLS group invite |

#### Connection Flow

```
1. Parse server address as Recipient
2. Connect to Nym mixnet
3. Create message channel for incoming
4. Return (MixnetService, Receiver<Incoming>)
```

---

### 6. Auth Handler (`auth_handler.rs`)

#### Purpose
Handle authentication flows including registration and login challenges.

#### Structure

```rust
pub struct AuthenticationHandler {
    pub db: Arc<Db>,
    pub service: Arc<MixnetService>,
    pub pgp_secret_key: Option<SignedSecretKey>,
    pub pgp_public_key: Option<SignedPublicKey>,
    pub pgp_passphrase: Option<SecurePassphrase>,
}
```

#### Key Methods

| Method | Description |
|--------|-------------|
| `process_register_challenge(username, nonce)` | Handle registration challenge |
| `process_register_response(username, result)` | Handle registration result |
| `process_login_challenge(username, nonce)` | Handle login challenge |
| `process_login_response(username, result)` | Handle login result |

#### Challenge/Response Flow

```
Server                          Client
  |                               |
  |  challenge(nonce)             |
  |------------------------------>|
  |                               | Sign nonce with PGP key
  |  challengeResponse(signature) |
  |<------------------------------|
  | Verify signature              |
  |  result(success/failure)      |
  |------------------------------>|
```

---

### 7. Chat Handler (`chat_handler.rs`)

#### Purpose
Process chat-specific message types.

#### Structure

```rust
pub struct ChatHandler {
    pub db: Arc<Db>,
    pub current_user: Option<String>,
}

pub enum ChatResult {
    TextMessage { sender: String, content: String },
    Handshake { nym_address: String },
    None,
}
```

#### Key Methods

| Method | Description |
|--------|-------------|
| `handle_chat_message(envelope)` | Process chat message |
| `handle_handshake(envelope)` | Process P2P handshake |

---

## Background Processing

### Buffer Processor

A background task processes buffered MLS messages periodically:

```rust
pub async fn start_buffer_processor(
    db: Arc<Db>,
    service: Arc<MixnetService>,
    current_user: String,
    pgp_secret_key: Option<SignedSecretKey>,
    pgp_public_key: Option<SignedPublicKey>,
    pgp_passphrase: Option<SecurePassphrase>,
    mls_storage_path: Option<String>,
    shutdown_rx: broadcast::Receiver<()>,
)
```

**Behavior**:
- Runs every 5 seconds
- Processes pending messages for each conversation
- Cleans up expired messages every ~1 minute
- Responds to shutdown signal

---

## Interactions with Other Modules

```
┌─────────────────────────────────────────────────────────┐
│                      core/                              │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              message_handler.rs                  │   │
│  └───────────────────────┬─────────────────────────┘   │
│                          │                             │
│          ┌───────────────┼───────────────┐             │
│          │               │               │             │
│          ▼               ▼               ▼             │
│  ┌──────────────┐ ┌─────────────┐ ┌──────────────┐    │
│  │   db.rs      │ │mixnet_client│ │message_router│    │
│  └──────────────┘ └─────────────┘ └──────────────┘    │
│                                                         │
└───────────────────────────┬─────────────────────────────┘
                            │
            ┌───────────────┼───────────────┐
            │               │               │
            ▼               ▼               ▼
    ┌──────────────┐ ┌─────────────┐ ┌──────────────┐
    │  crypto/mls  │ │  crypto/pgp │ │    model/    │
    │              │ │             │ │              │
    └──────────────┘ └─────────────┘ └──────────────┘
```

---

## Error Handling

The core module uses `anyhow::Result` for error handling throughout. Key error scenarios:

1. **Database errors**: Connection failures, constraint violations
2. **Network errors**: Mixnet connection issues, timeouts
3. **Auth errors**: Invalid signatures, failed challenges
4. **Message errors**: Invalid format, missing fields

All errors are logged and propagated to the caller for handling.
