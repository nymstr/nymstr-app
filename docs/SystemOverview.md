<!-- This file provides a high-level overview of the Rust TUI client codebase and guidelines for extending it -->
# System Overview

This document describes the overall architecture, module structure, and development workflow of the nymCHAT Rust TUI client.

---

## 1. Architecture Diagram

```text
       +-----------+      +-------------------+
       | main.rs   |----->| App (UI & event)  |
       +-----------+      +---------+---------+
                                  |
               +------------------+------------------+
               |                                     |
     +---------v---------+                 +---------v-----------+
     | MessageHandler     |                 | Event & UI modules  |
     +---------+---------+                 +---------------------+
               |
     +---------v---------+
     | MixnetService      |
     +---------+---------+
               |
     +---------v---------+
     | Core Modules       |
     | (crypto, db,       |
     |  messages,         |
     |  mixnet_client)    |
     +--------------------+
```  

## 2. Repository Layout

```text
Cargo.toml                   # Rust package manifest
README.md                    # High-level repo overview
docs/Build.md                # Build & install instructions
docs/Protocol.md             # Nym mixnet message protocol
docs/NymRustSDK.md           # SDK usage guide for Rust
docs/SystemOverview.md       # << this file >>
src/
  main.rs                    # Entry point; loads .env, logger, starts App
  app.rs                     # `App` struct: TUI state machine and render logic
  core/                      # Core backend logic
    crypto.rs                # ECDSA/ECDH/AES-GCM via OpenSSL (keygen, sign, encrypt, decrypt)
    db.rs                    # SQLite persistence mirroring Python schema
    mixnet_client.rs         # Wraps nym-sdk client, receives & sends mixnet envelopes
    message_handler.rs       # High-level registration/login, secure messaging flows
    messages.rs              # JSON envelope definitions (MixnetMessage)
  event/                     # Keyboard and UI event handlers
  model/                     # Data models (Contact, Message, User)
  screen/                    # TUI chat screen state & widgets
  ui/                        # Low-level TUI component layouts
tests/
  mixnet_client_loopback.rs  # Integration test for mixnet send/receive loop
```

## 3. Component Responsibilities

### `src/main.rs`
- Loads environment variables (.env), initializes logging buffer.
- Launches the TUI `App` run loop under Tokio.

### `src/app.rs`
- Defines the `App` enum for UI phases (Connect, Register, Login, Chat, etc.).
- Manages the splash screen, connect spinner, and delegates to screens based on state.

### `src/core/crypto.rs`
- Provides `Crypto` for key generation, signing/verifying, ECDH key derivation,
  and AES-256-GCM encryption/decryption.
- Added helpers to persist/load PEM key files for registered users.

### `src/core/db.rs`
- Implements `Db` on top of SQLx/SQLite, matching the Python schema:
  - Global `users` table
  - Per-user `contacts_{username}` and `messages_{username}` tables
- Methods: register, add/get/delete contacts, save/load/delete messages, and
  convenience methods (`get_all_users`, `get_all_messages`).

### `src/core/mixnet_client.rs`
- Manages a `MixnetService` that wraps the nym-sdk MixnetClient.
    - Handles connecting to the mixnet, splitting sender/receiver,
  and relaying `MixnetMessage` frames to the application.

### `src/core/message_handler.rs`
- Coordinates registration/login challenge–response with server.
- Implements end-to-end secure messaging:
  - ECDH/AES-GCM encryption + nested payload signature
  - ECDSA signing of both inner and outer payloads
  - Handshake (type=1) exchange for direct P2P replies
- Persists and decrypts incoming messages into the local DB.

### `src/core/messages.rs`
- Defines the `MixnetMessage` struct and helper constructors for all
  envelope actions (query, register, login, send, direct_message, etc.).

### UI & Event Modules (`event/`, `model/`, `screen/`, `ui/`)
- Contain the TUI layout, key bindings, and widgets (via Ratatui) for the
  chat interface, contact list, message panel, and input bar.

---

## 4. How to Add Features

1. **Design Data & Protocol Change**
   - If you need new data persistence, update `src/core/db.rs` to create tables
     or add CRUD methods, then mirror tests in `tests/`.
   - If you need new message types, extend `src/core/messages.rs` and adjust
     serialization/deserialization in `mixnet_client.rs` and `message_handler.rs`.

2. **Backend Logic**
   - Implement core logic in `src/core/message_handler.rs` or `mixnet_client.rs`.
   - Write unit tests alongside in `src/core/...` modules or in `tests/`.

3. **UI Integration**
   - Add new UI states or screens in `src/app.rs` and `src/screen/`.
   - Bind keys in `src/event/` and render new elements in `src/ui/`.

4. **End-to-End Testing**
   - Use `tests/mixnet_client_loopback.rs` for protocol-level smoke tests.
   - Add Rust unit tests (`cargo test`) and run the Python integration 
     if needed.

5. **Documentation & Examples**
   - Update this SystemOverview.md when new subsystems are added.
   - Add usage snippets to `docs/Build.md` or create new docs under `docs/`.

---

*Last updated: $(date '+%Y-%m-%d')*