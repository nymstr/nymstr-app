# Nymstr Architecture Documentation

## Overview

Nymstr is a privacy-focused messaging application built in Rust that provides end-to-end encrypted messaging over the Nym mixnet. It features both a TUI (Terminal User Interface) mode and a CLI mode.

### Core Technologies

- **Nym Mixnet**: Anonymous network routing via nym-sdk
- **MLS (Message Layer Security)**: End-to-end encrypted group messaging via mls-rs
- **PGP**: Digital signatures for authentication
- **SQLite**: Local message and state persistence
- **Ratatui**: Terminal UI framework

---

## Component Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           Application Layer                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │    app.rs    │  │   cli/       │  │        event/            │  │
│  │  (TUI State) │  │ (CLI Mode)   │  │   (Input Handling)       │  │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                            Core Layer                                │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────┐    │
│  │ message_handler│  │ message_router │  │   mixnet_client    │    │
│  │  (Send/Recv)   │  │   (Routing)    │  │  (Nym Integration) │    │
│  └────────────────┘  └────────────────┘  └────────────────────┘    │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────┐    │
│  │  auth_handler  │  │  chat_handler  │  │     messages       │    │
│  │ (Auth Flows)   │  │ (Chat Logic)   │  │ (Message Format)   │    │
│  └────────────────┘  └────────────────┘  └────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                           Crypto Layer                               │
│  ┌──────────────────────────────┐  ┌────────────────────────────┐  │
│  │           MLS                │  │           PGP              │  │
│  │  ┌────────────────────────┐  │  │  ┌──────────────────────┐  │  │
│  │  │      client.rs         │  │  │  │     keypair.rs       │  │  │
│  │  │  (MLS Protocol)        │  │  │  │  (Key Management)    │  │  │
│  │  └────────────────────────┘  │  │  └──────────────────────┘  │  │
│  │  ┌────────────────────────┐  │  │  ┌──────────────────────┐  │  │
│  │  │ conversation_manager   │  │  │  │     signing.rs       │  │  │
│  │  │ (Group Management)     │  │  │  │  (Signatures)        │  │  │
│  │  └────────────────────────┘  │  │  └──────────────────────┘  │  │
│  │  ┌────────────────────────┐  │  └────────────────────────────┘  │
│  │  │    epoch_buffer.rs     │  │                                  │
│  │  │ (Message Ordering)     │  │                                  │
│  │  └────────────────────────┘  │                                  │
│  └──────────────────────────────┘                                  │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Persistence Layer                            │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                         db.rs                                 │  │
│  │  - Users table           - Messages table                     │  │
│  │  - Contacts table        - MLS groups table                   │  │
│  │  - Pending messages      - Key storage                        │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Module Documentation

### 1. Application Entry (`src/main.rs`, `src/app.rs`)

**Purpose**: Application entry point and main state machine.

**Responsibilities**:
- Route between TUI and CLI modes based on command-line arguments
- Manage application lifecycle
- Handle the main event loop in TUI mode
- Coordinate between UI rendering and message handling

**Key Types**:
```rust
App {
    running: bool,              // Event loop control
    phase: Phase,               // UI phase (Connect, Login, Chat, etc.)
    screen: ScreenState,        // Current screen state
    logged_in_user: Option<User>,
    handler: MessageHandler,    // Core message operations
    input_buffer: String,       // User input
    pending_outgoing: Vec<...>, // Queued messages
}
```

**Interactions**:
- Receives keyboard events from `event/`
- Delegates rendering to `ui/`
- Uses `MessageHandler` for all network operations
- Updates `screen/` state based on user actions

---

### 2. CLI Module (`src/cli/`)

**Purpose**: Command-line interface for non-interactive operations.

**Files**:
- `mod.rs` - Module exports
- `commands.rs` - CLI command definitions (uses clap)
- `key_manager.rs` - PGP key management utilities

**Key Commands**:
```rust
enum Commands {
    Register { username: String },
    Login { username: String },
    Send { recipient: String, message: String },
    Query { username: String },
    Listen,
    Handshake { recipient: String },
    Group { action: String, ... },
}
```

**Interactions**:
- Creates `MessageHandler` for operations
- Uses `crypto/pgp/` for key management
- Outputs results to stdout

---

### 3. Core Module (`src/core/`)

The core module contains the fundamental messaging infrastructure.

#### 3.1 Database (`db.rs`)

**Purpose**: SQLite persistence layer for all application data.

**Tables**:
```sql
users                    -- Global user registry
contacts_{user}          -- Per-user contact list
messages_{user}          -- Per-user message history
mls_groups_{user}        -- MLS group state
pending_mls_messages_{user} -- Buffered out-of-order messages
```

**Key Operations**:
- User registration and lookup
- Contact management
- Message persistence
- MLS group state storage
- Pending message buffer for epoch-aware processing

**Interactions**:
- Used by `MessageHandler` for all persistence
- Used by `EpochAwareBuffer` for message buffering
- Used by `MlsConversationManager` for group state

#### 3.2 Messages (`messages.rs`)

**Purpose**: Define the unified message envelope format for mixnet communication.

**Message Structure**:
```rust
MixnetMessage {
    message_type: String,  // "message", "response", "system"
    action: String,        // Operation type
    sender: String,
    recipient: String,
    payload: Value,        // JSON payload
    signature: String,     // PGP signature
    timestamp: String,     // ISO-8601
}
```

**Actions**:
- `register`, `login` - Authentication
- `query`, `queryResponse` - User lookup
- `send`, `incomingMessage` - Chat messages
- `keyPackageRequest`, `keyPackageResponse` - MLS handshake
- `groupWelcome`, `groupJoinResponse` - MLS group operations

#### 3.3 Message Handler (`message_handler.rs`)

**Purpose**: High-level orchestration of message send/receive operations.

**Responsibilities**:
- User registration and login flows
- Direct message sending with MLS encryption
- Processing incoming messages
- Coordinating with MLS conversation manager
- Managing the background buffer processor

**Key Methods**:
```rust
register_user()           // Registration with challenge/response
login_user()              // Login with PGP authentication
send_direct_message()     // Send MLS-encrypted message
process_received_message() // Route and handle incoming
start_buffer_processor()  // Background retry task
```

**Interactions**:
- Uses `MixnetService` for network operations
- Uses `MlsConversationManager` for encryption
- Uses `Db` for persistence
- Coordinates with `AuthHandler` and `ChatHandler`

#### 3.4 Message Router (`message_router.rs`)

**Purpose**: Route incoming messages to appropriate handlers based on type.

**Routes**:
```rust
enum MessageRoute {
    Authentication,  // Challenge/response flows
    Query,          // User lookups
    Chat,           // Direct messages
    Handshake,      // P2P connection setup
    MlsProtocol,    // MLS key exchange, welcomes
    System,         // System messages
    Unknown,
}
```

#### 3.5 Mixnet Client (`mixnet_client.rs`)

**Purpose**: Integration with the Nym mixnet SDK.

**Responsibilities**:
- Connect to Nym mixnet
- Send messages through mixnet
- Receive messages from mixnet
- Manage connection lifecycle

**Key Types**:
```rust
MixnetService {
    client: MixnetClient,
    server_address: Recipient,
}

Incoming {
    envelope: MixnetMessage,
    received_at: DateTime,
}
```

#### 3.6 Auth Handler (`auth_handler.rs`)

**Purpose**: Handle authentication flows (registration, login).

**Flow**:
```
1. Send register/login request
2. Server sends challenge (nonce)
3. Sign challenge with PGP key
4. Send challenge response
5. Server validates and authorizes
```

#### 3.7 Chat Handler (`chat_handler.rs`)

**Purpose**: Process chat-specific message types.

**Responsibilities**:
- Handle incoming chat messages
- Process handshake messages for P2P routing
- Extract message content from envelopes

---

### 4. Crypto Module (`src/crypto/`)

The crypto module handles all cryptographic operations.

#### 4.1 MLS Submodule (`crypto/mls/`)

**Purpose**: End-to-end encrypted messaging using the MLS protocol.

##### client.rs

**Purpose**: MLS client wrapper around the mls-rs library.

**Key Types**:
```rust
MlsClient {
    identity: String,
    pgp_secret_key: SignedSecretKey,
    pgp_public_key: SignedPublicKey,
}
```

**Operations**:
- Key package generation
- Group creation and joining
- Message encryption/decryption
- Member addition/removal

##### conversation_manager.rs

**Purpose**: Manage MLS conversations and protocol operations.

**Key Methods**:
```rust
handle_key_package_request()     // Respond to MLS handshake
handle_group_welcome()           // Join MLS group
handle_mls_protocol_message()    // Route MLS messages
process_incoming_message_buffered() // Process with epoch buffering
```

**Epoch-Aware Processing**:
```
Message arrives
  ├─ Try process directly
  │   ├─ Success → Return decrypted message
  │   │            └─ Process buffered messages
  │   └─ Epoch error → Buffer message
  └─ Non-epoch error → Return error
```

##### epoch_buffer.rs

**Purpose**: Handle out-of-order MLS messages from mixnet latency.

**Problem Solved**: MLS requires strict message ordering within epochs. The mixnet introduces variable latency causing messages to arrive out of order.

**Solution**:
```rust
EpochAwareBuffer {
    memory_buffer: HashMap<String, VecDeque<BufferedMessage>>,
    known_epochs: HashMap<String, u64>,
    db: Arc<Db>,  // Persistence for restart recovery
}
```

**Constants**:
- `MAX_BUFFER_AGE_SECS = 300` (5 minutes)
- `MAX_BUFFER_SIZE = 100` per conversation
- `MAX_RETRY_COUNT = 10`

##### key_packages.rs

**Purpose**: Manage MLS key package generation and exchange.

**Operations**:
- Generate key packages for handshakes
- Validate received key packages
- Store key packages per user

##### types.rs

**Purpose**: MLS-related data structures.

```rust
EncryptedMessage {
    conversation_id: Vec<u8>,
    mls_message: Vec<u8>,
    message_type: MlsMessageType,
}

enum MlsMessageType {
    Commit,
    Application,
    Welcome,
    KeyPackage,
}
```

#### 4.2 PGP Submodule (`crypto/pgp/`)

**Purpose**: PGP key management and digital signatures.

##### keypair.rs

**Purpose**: Generate and manage PGP keypairs.

**Key Types**:
```rust
SecurePassphrase        // Zeroizing password wrapper
PgpKeyManager           // Key generation and storage
```

**Operations**:
- Generate RSA/Ed25519 keypairs
- Save/load keys with encryption
- Passphrase management

##### signing.rs

**Purpose**: Create and verify PGP signatures.

**Operations**:
- Sign data with private key
- Verify signatures with public key
- Detached signature support

#### 4.3 Message Crypto (`message_crypto.rs`)

**Purpose**: Message-level cryptographic operations.

**Operations**:
- Extract MLS messages from envelopes
- Extract key packages and welcome messages
- Validate message structure

---

### 5. Model Module (`src/model/`)

**Purpose**: Core data models used throughout the application.

**Types**:
```rust
type Id = String;  // User/contact identifier

User {
    id: Id,
    username: String,
    display_name: String,
    online: bool,
}

Contact {
    id: Id,
    display_name: String,
    online: bool,
}

Message {
    sender: String,
    content: String,
    timestamp: DateTime<Utc>,
}
```

---

### 6. Screen Module (`src/screen/`)

**Purpose**: UI screen state management.

**Key Types**:
```rust
enum Screen {
    Chat(ChatScreen),
}

ChatScreen {
    section: ChatSection,        // Current focus
    contacts: Vec<Contact>,
    selected_contact: usize,
    messages: Vec<Vec<Message>>, // Per-contact messages
    chat_scroll: usize,
}

enum ChatSection {
    Contacts,
    Messages,
    Input,
}
```

---

### 7. UI Module (`src/ui/`)

**Purpose**: Terminal UI rendering using ratatui.

**Structure**:
```
ui/
├── mod.rs           # Main render_ui() function
├── layout.rs        # Layout calculations
├── components/      # Reusable UI components
│   ├── chat.rs      # Chat area rendering
│   └── footer.rs    # Status bar
└── widgets/         # Custom widgets
    ├── splash.rs    # Splash screen
    └── input.rs     # Text input
```

**Render Flow**:
```
render_ui()
  ├─ Calculate layout (main_layout)
  ├─ Render chat component (render_chat)
  │   ├─ Contacts list
  │   ├─ Message area
  │   └─ Input field
  └─ Render footer (render_footer)
```

---

### 8. Event Module (`src/event/`)

**Purpose**: Keyboard event handling.

**Key Bindings**:
- `Ctrl+Q` - Quit
- `Tab` - Navigate sections
- `i` - Enter input mode
- `s` - Search mode
- `g` - Group search
- `Arrow keys` - Navigate
- `Enter` - Select/send
- `Esc` - Exit mode

---

## Data Flow Diagrams

### Message Sending

```
┌─────────┐     ┌──────────────┐     ┌─────────────────────┐
│  User   │────▶│ MessageHandler│────▶│ MlsConversationMgr │
│  Input  │     │              │     │                     │
└─────────┘     └──────────────┘     └─────────────────────┘
                       │                        │
                       │                        ▼
                       │              ┌─────────────────┐
                       │              │    MlsClient    │
                       │              │  (Encrypt msg)  │
                       │              └─────────────────┘
                       │                        │
                       ▼                        ▼
              ┌──────────────┐       ┌─────────────────┐
              │     Db       │       │   PgpSigner     │
              │ (Save local) │       │  (Sign msg)     │
              └──────────────┘       └─────────────────┘
                                              │
                                              ▼
                                    ┌─────────────────┐
                                    │  MixnetService  │
                                    │  (Send to net)  │
                                    └─────────────────┘
```

### Message Receiving

```
┌─────────────────┐
│  Nym Mixnet     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌──────────────────┐
│  MixnetService  │────▶│  MessageRouter   │
│  (Receive)      │     │  (Route msg)     │
└─────────────────┘     └────────┬─────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│  AuthHandler    │   │  ChatHandler    │   │ MlsConvManager  │
│ (Auth flows)    │   │ (Plain msgs)    │   │ (MLS protocol)  │
└─────────────────┘   └─────────────────┘   └────────┬────────┘
                                                     │
                                                     ▼
                                           ┌─────────────────┐
                                           │ EpochAwareBuffer│
                                           │ (Handle order)  │
                                           └────────┬────────┘
                                                    │
                                                    ▼
                                           ┌─────────────────┐
                                           │    MlsClient    │
                                           │   (Decrypt)     │
                                           └─────────────────┘
```

### MLS Handshake

```
┌─────────┐                                       ┌─────────┐
│  Alice  │                                       │   Bob   │
└────┬────┘                                       └────┬────┘
     │                                                 │
     │  1. Generate KeyPackage                         │
     │─────────────────────────────────────────────────▶
     │                                                 │
     │                              2. Generate KeyPackage
     │◀─────────────────────────────────────────────────
     │                                                 │
     │  3. Create MLS Group                            │
     │  4. Add Bob with his KeyPackage                 │
     │  5. Send Welcome message                        │
     │─────────────────────────────────────────────────▶
     │                                                 │
     │                              6. Process Welcome │
     │                              7. Join Group      │
     │                              8. Send Confirmation
     │◀─────────────────────────────────────────────────
     │                                                 │
     │  ═══════ MLS Group Established ═══════         │
     │                                                 │
     │  9. Encrypt message with MLS                    │
     │─────────────────────────────────────────────────▶
     │                                                 │
```

---

## Security Architecture

### Layers of Protection

1. **Network Layer**: Nym mixnet provides anonymous routing
2. **Transport Layer**: MLS provides forward secrecy and post-compromise security
3. **Authentication Layer**: PGP signatures verify message authenticity
4. **Storage Layer**: Encrypted key storage with secure passphrases

### Key Management

```
┌─────────────────────────────────────────────────────────┐
│                    Key Hierarchy                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────────┐                                    │
│  │  PGP Keypair    │  - Long-term identity              │
│  │  (RSA/Ed25519)  │  - Signs all messages              │
│  └────────┬────────┘  - Stored encrypted on disk        │
│           │                                             │
│           ▼                                             │
│  ┌─────────────────┐                                    │
│  │ MLS Signature   │  - Per-user MLS identity           │
│  │     Keys        │  - Derived/stored per user         │
│  └────────┬────────┘                                    │
│           │                                             │
│           ▼                                             │
│  ┌─────────────────┐                                    │
│  │  Key Packages   │  - Ephemeral for each handshake    │
│  │                 │  - Enable async group joins        │
│  └────────┬────────┘                                    │
│           │                                             │
│           ▼                                             │
│  ┌─────────────────┐                                    │
│  │  Group Keys     │  - Per-epoch encryption keys       │
│  │  (per epoch)    │  - Forward secrecy via ratcheting  │
│  └─────────────────┘                                    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Configuration

### Environment Variables

```bash
NYMSTR_PGP_PASSPHRASE  # Passphrase for PGP key encryption
NYM_SERVER_ADDRESS     # Nym mixnet server address
```

### File Locations

```
storage/
├── nymstr_{username}.db     # Main database
├── nymstr_mls_{username}.db # MLS state database
└── keys/
    ├── {username}_secret.asc # Encrypted PGP private key
    └── {username}_public.asc # PGP public key
```

---

## Testing

### Test Categories

1. **Unit Tests**: Per-module tests in `#[cfg(test)]` blocks
2. **Integration Tests**: `crypto/mls/integration_test.rs`
3. **Basic Tests**: `crypto/mls/basic_test.rs`

### Running Tests

```bash
cargo test                    # All tests
cargo test epoch_buffer       # Specific module
cargo test --lib              # Library tests only
```
