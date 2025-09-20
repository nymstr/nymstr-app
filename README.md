# nymstr

> **⚠️ Under Active Development**
 Features and APIs may change without notice.

## Quick Start

### Prerequisites

1. **Rust**: Install from [rustup.rs](https://rustup.rs/)

### Setup

1. **Set the server address**:
   ```bash
   echo 'SERVER_ADDRESS=<server_address>' >> .env
   ```

2. **Set PGP passphrase** (optional, will prompt if not set):
   ```bash
   echo 'NYMSTR_PGP_PASSPHRASE=your_secure_passphrase' >> .env
   ```

3. **Build and run**:
   ```bash
   cargo run
   ```

## Usage Modes

Nymstr can be used in two ways:

### 1. **Interactive TUI Mode** (default)
Launch the Terminal User Interface for real-time messaging:
```bash
cargo run
```

### 2. **CLI Mode**
Use command-line interface for scripting and automation:
```bash
cargo run -- [COMMAND]
```

---

## CLI Commands

### User Management

**Register a new user:**
```bash
cargo run -- register <username>
```
- Creates new PGP keypair with secure passphrase
- Registers with the Nymstr server
- Stores keys securely with HMAC integrity protection

**Login with existing user:**
```bash
cargo run -- login <username>
```
- Loads existing PGP keys (requires passphrase)
- Authenticates with the Nymstr server

### Direct Messaging

**Send a message:**
```bash
cargo run -- send <from_username> <recipient> "<message>"
```
- Encrypts message end-to-end using recipient's PGP key
- Routes through Nym mixnet for privacy

**Query user's public key:**
```bash
cargo run -- query <username>
```
- Retrieves public key for a registered user
- Needed before sending first message

**Listen for messages:**
```bash
cargo run -- listen <username> [--duration <seconds>]
```
- Listens for incoming messages
- Duration: 0 = indefinite, >0 = specific timeout

**Send handshake:**
```bash
cargo run -- handshake <from_username> <recipient>
```
- Establishes P2P routing for faster subsequent messages

### Group Messaging

**Register with group server:**
```bash
cargo run -- group register <server_address> <username>
```
- Authenticates with MLS group server using PGP credentials

**Send group message:**
```bash
cargo run -- group send <server_address> "<message>"
```
- Sends message to all group participants
- Uses MLS for forward secrecy

**Get group statistics:**
```bash
cargo run -- group stats <server_address>
```
- Shows group member count and server status

### Examples

```bash
# Complete workflow
cargo run -- register alice
cargo run -- register bob
cargo run -- query bob
cargo run -- send alice bob "Hello Bob!"
cargo run -- listen bob --duration 30

# Group messaging
cargo run -- group register group.example.com alice
cargo run -- group send group.example.com "Hello everyone!"
```

---

## TUI Controls

When running in interactive mode, use these keyboard shortcuts:

### Global
- `q` or `Ctrl+Q` — Quit application

### Messages Section (default focus)
- `Tab` — Switch to **Contacts**
- `i` — Switch to **Input**
- `s` — Open **Search** mode
- `g` — Open **Group Search** mode

### Contacts Section
- `↑` / `↓` — Navigate contact list
- `Tab` — Next contact
- `Enter` — Select contact (show messages)
- `Esc` — Back to **Messages**

### Input Section
- *Type* — Compose message
- `Enter` — Send message
- `Esc` — Back to **Messages**

### Search Mode
- *Type* — Enter username to search
- `Enter` — Submit search
- `1` — Start chat with found user
- `2` — Search again
- `3` or `Esc` — Cancel

### Group Search Mode
- *Type* — Enter group server address
- `Enter` — Connect to server
- `1` — View group messages
- `2` — Search again
- `3` or `Esc` — Cancel

### Group View Mode
- `i` — Switch to input for group messaging
- `s` — Get server statistics
- `Esc` — Return to **Chat**

### Group Input Mode
- *Type* — Compose group message
- `Enter` — Send to group
- `Esc` — Return to **Group View**

---

## Security Features

- **End-to-End Encryption**: PGP encryption for direct messages, MLS for groups
- **Forward Secrecy**: Group messages use MLS protocol with automatic key rotation
- **Privacy-Enhanced Routing**: All traffic routed through Nym mixnet
- **Secure Key Storage**: PGP keys stored with passphrase protection and HMAC integrity
- **No Legacy Fallbacks**: All deprecated insecure methods removed

## Troubleshooting

**Connection Issues:**
- Verify `SERVER_ADDRESS` in `.env`
- Check Nym mixnet connectivity
- Ensure firewall allows connections

**Key Issues:**
- Set `NYMSTR_PGP_PASSPHRASE` or enter when prompted
- Re-register if keys are corrupted
- Check `storage/<username>/pgp_keys/` directory

**Performance:**
- Use handshakes for frequently contacted users
- Group messaging is more efficient for multiple recipients

---

## Development

### Building
```bash
cargo build --release
```

### Testing
```bash
cargo test
```

### Logging
```bash
RUST_LOG=debug cargo run
```

For more information, see the source code and inline documentation.
