# Nymstr Documentation

Welcome to the Nymstr documentation. This directory contains comprehensive documentation for all components of the Nymstr privacy-focused messaging application.

## Quick Links

| Document | Description |
|----------|-------------|
| [Architecture Overview](ARCHITECTURE.md) | High-level system architecture and data flow |
| [Core Module](components/CORE.md) | Database, networking, and message handling |
| [Crypto Module](components/CRYPTO.md) | MLS encryption and PGP signatures |
| [UI Module](components/UI.md) | Terminal user interface components |
| [Model Module](components/MODEL.md) | Data structures (User, Contact, Message) |

## Architecture at a Glance

```
┌─────────────────────────────────────────────────────────────┐
│                      Application                             │
│   app.rs (TUI)  │  cli/ (Command Line)  │  event/ (Input)   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                         Core                                 │
│  message_handler │ message_router │ mixnet_client │ db      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                        Crypto                                │
│         MLS (encryption)    │    PGP (signatures)           │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                       Storage                                │
│              SQLite (messages, MLS state, keys)             │
└─────────────────────────────────────────────────────────────┘
```

## Key Concepts

### Privacy Layer: Nym Mixnet
All messages are routed through the Nym mixnet, which provides:
- Anonymous network routing
- Traffic analysis resistance
- Variable latency (by design)

### Encryption Layer: MLS Protocol
Messages are end-to-end encrypted using MLS (RFC 9420):
- Forward secrecy
- Post-compromise security
- Efficient group operations

### Authentication Layer: PGP
Digital signatures provide:
- Message authenticity
- Non-repudiation
- Identity verification

### Epoch-Aware Buffering
The mixnet's variable latency can cause out-of-order message delivery. The epoch buffer handles this by:
- Detecting epoch mismatch errors
- Buffering messages for retry
- Processing buffered messages when epochs advance

## Component Interaction Summary

```
User Input → App (TUI/CLI)
                │
                ▼
         MessageHandler
                │
    ┌───────────┼───────────┐
    │           │           │
    ▼           ▼           ▼
AuthHandler  ChatHandler  MlsConvManager
    │           │           │
    │           │           ├── EpochBuffer
    │           │           │
    └───────────┼───────────┘
                │
                ▼
          MixnetService ←──── PGP Signer
                │
                ▼
           Nym Mixnet
```

## File Organization

```
src/
├── main.rs              # Entry point
├── app.rs               # TUI application state
├── lib.rs               # Library exports
│
├── cli/                 # Command-line interface
│   ├── commands.rs      # CLI commands
│   └── key_manager.rs   # Key operations
│
├── core/                # Core functionality
│   ├── db.rs            # SQLite persistence
│   ├── messages.rs      # Message format
│   ├── message_handler.rs
│   ├── message_router.rs
│   ├── mixnet_client.rs
│   ├── auth_handler.rs
│   └── chat_handler.rs
│
├── crypto/              # Cryptography
│   ├── mls/             # MLS protocol
│   │   ├── client.rs
│   │   ├── conversation_manager.rs
│   │   ├── epoch_buffer.rs
│   │   ├── key_packages.rs
│   │   ├── persistence.rs
│   │   └── types.rs
│   ├── pgp/             # PGP operations
│   │   ├── keypair.rs
│   │   └── signing.rs
│   └── message_crypto.rs
│
├── model/               # Data models
│   ├── user.rs
│   ├── contact.rs
│   └── message.rs
│
├── screen/              # Screen state
│   └── chat.rs
│
├── ui/                  # UI rendering
│   ├── layout.rs
│   ├── components/
│   └── widgets/
│
└── event/               # Event handling
    └── navigation.rs
```

## Getting Started

### Running the Application

```bash
# TUI Mode (default)
cargo run

# CLI Mode
cargo run -- --help
cargo run -- login alice
cargo run -- send bob "Hello!"
```

### Environment Variables

```bash
# PGP passphrase for key encryption
export NYMSTR_PGP_PASSPHRASE="your-secure-passphrase"

# Nym server address (if not using default)
export NYM_SERVER_ADDRESS="address@gateway"
```

### Running Tests

```bash
# All tests
cargo test

# Specific module
cargo test core::db
cargo test crypto::mls
cargo test model
```

## Security Model

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Network surveillance | Nym mixnet anonymity |
| Message interception | MLS end-to-end encryption |
| Message tampering | PGP signatures |
| Key compromise | MLS forward secrecy |
| Replay attacks | Timestamps + MLS generations |

### Key Hierarchy

```
User PGP Key (long-term identity)
    │
    ├── Signs all messages
    │
    └── MLS Signature Key (per-user)
            │
            ├── Key Packages (handshakes)
            │
            └── Group Keys (per-epoch)
                    │
                    └── Message Keys (per-message)
```

## Contributing

When modifying the codebase:

1. **Read relevant documentation** in this `docs/` folder
2. **Follow existing patterns** - check similar code for conventions
3. **Update documentation** when changing public interfaces
4. **Run tests** before submitting: `cargo test`
5. **Check compilation**: `cargo check`

## Further Reading

- [MLS Protocol (RFC 9420)](https://www.rfc-editor.org/rfc/rfc9420.html)
- [Nym Documentation](https://nymtech.net/docs/)
- [ratatui Guide](https://ratatui.rs/)
- [PGP/OpenPGP](https://www.openpgp.org/)
