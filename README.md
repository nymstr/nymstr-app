# nymstr-app

Privacy-preserving messaging client for the [Nym mixnet](https://nymtech.net/).

> **Under Active Development** - APIs may change.

## Features

- End-to-end encryption (PGP for direct, MLS for groups)
- Interactive TUI and scriptable CLI
- Anonymous routing via Nym mixnet

## Quick Start

```bash
echo 'SERVER_ADDRESS=<discovery_server_nym_address>' >> .env
cargo run --release
```

## Usage

### TUI Mode (default)
```bash
cargo run
```

### CLI Mode
```bash
cargo run -- register <username>
cargo run -- login <username>
cargo run -- send <from> <to> "message"
cargo run -- group register <server> <username>
cargo run -- group send <server> <username> "message"
```

### TUI Controls

- `L`/`R` - Login/Register on welcome screen
- `Tab` - Switch between sections
- `i` - Focus input
- `s` - Search users
- `g` - Group search
- `q` - Quit

## Configuration

- `SERVER_ADDRESS` - Discovery server Nym address (required)
- `NYMSTR_PGP_PASSPHRASE` - PGP passphrase (prompts if not set)
- `RUST_LOG` - Log level (`info`, `debug`, `trace`)

## License

GNU GPLv3.0
