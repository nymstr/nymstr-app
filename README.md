# Nymstr

A privacy-first messaging application built on the [Nym mixnet](https://nymtech.net/).

## Features

- **Anonymous Messaging** - All traffic routed through the Nym mixnet to prevent surveillance and traffic analysis
- **End-to-End Encryption** - MLS (Message Layer Security, RFC 9420) for group chats with forward secrecy
- **Cryptographic Authentication** - PGP-based identity verification
- **Group Chat** - Encrypted group messaging with admin controls
- **Contact Management** - Add and manage contacts securely

## Architecture

Nymstr is a desktop application built with:

- **Frontend**: React + TypeScript + Vite
- **Backend**: Rust + Tauri
- **Crypto**: OpenMLS for group encryption, PGP for identity
- **Network**: Nym SDK for mixnet communication
- **Storage**: SQLite for local persistence

## Prerequisites

- [Rust](https://rustup.rs/) (1.86+)
- [Node.js](https://nodejs.org/) (18+)
- [pnpm](https://pnpm.io/) or npm

## Development

```bash
# Install frontend dependencies
pnpm install

# Run in development mode
pnpm tauri dev

# Build for production
pnpm tauri build
```

## Configuration

The app connects to Nymstr discovery and group servers over the Nym mixnet. On first run, you'll be prompted to:

1. Create or import a PGP keypair
2. Register a username with a discovery server
3. Add contacts and join groups

## Security Model

| Layer | Protection | Technology |
|-------|-----------|------------|
| Transport | Network anonymity | Nym mixnet |
| Encryption | Message confidentiality | MLS, AES-256-GCM |
| Authentication | Identity verification | PGP signatures |
| Key Management | Key protection at rest | PBKDF2 + AES-256-GCM |

## License

GPL-3.0
