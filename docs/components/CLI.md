# CLI Module Documentation

## Overview

The `cli` module (`src/cli/`) provides a command-line interface for non-interactive operations in Nymstr.

## Module Structure

```
src/cli/
├── mod.rs          # Module exports
├── commands.rs     # CLI command definitions
└── key_manager.rs  # Key management utilities
```

---

## Commands (`commands.rs`)

### Purpose
Define CLI commands using the `clap` crate for argument parsing.

### Main Structure

```rust
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "nymstr")]
#[command(about = "Privacy-focused messaging over Nym mixnet")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Register a new user
    Register {
        #[arg(short, long)]
        username: String,
    },

    /// Login as an existing user
    Login {
        #[arg(short, long)]
        username: String,
    },

    /// Send a message to a recipient
    Send {
        #[arg(short, long)]
        recipient: String,
        #[arg(short, long)]
        message: String,
    },

    /// Query a user's information
    Query {
        #[arg(short, long)]
        username: String,
    },

    /// Listen for incoming messages
    Listen,

    /// Send a handshake to establish P2P connection
    Handshake {
        #[arg(short, long)]
        recipient: String,
    },

    /// Group operations
    Group {
        #[arg(short, long)]
        action: String,
        #[arg(short, long)]
        name: Option<String>,
        #[arg(short, long)]
        server: Option<String>,
    },
}
```

### Usage Examples

```bash
# Register a new user
nymstr register --username alice

# Login
nymstr login --username alice

# Send a message
nymstr send --recipient bob --message "Hello Bob!"

# Query a user
nymstr query --username bob

# Listen for messages
nymstr listen

# Send handshake
nymstr handshake --recipient bob

# Group operations
nymstr group --action create --name mygroup
nymstr group --action join --name mygroup --server address@gateway
```

---

## Key Manager (`key_manager.rs`)

### Purpose
Utilities for managing PGP keys in CLI mode.

### Structure

```rust
pub struct KeyManager;

impl KeyManager {
    /// Load existing keys or create new ones
    pub fn load_or_create_keys(
        username: &str,
    ) -> Result<(SignedSecretKey, SignedPublicKey, SecurePassphrase)>;

    /// Create new PGP keys
    pub fn create_new_keys(
        username: &str,
    ) -> Result<(SignedSecretKey, SignedPublicKey, SecurePassphrase)>;

    /// Verify key pair is valid
    pub fn verify_keys(
        secret_key: &SignedSecretKey,
        public_key: &SignedPublicKey,
    ) -> Result<()>;

    /// Get armored public key string
    pub fn get_public_key_armored(
        public_key: &SignedPublicKey,
    ) -> Result<String>;
}
```

### Key Loading Flow

```rust
pub fn load_or_create_keys(username: &str) -> Result<...> {
    // Check for NYMSTR_PGP_PASSPHRASE environment variable
    let passphrase = std::env::var("NYMSTR_PGP_PASSPHRASE")
        .map(SecurePassphrase::new)
        .unwrap_or_else(|_| SecurePassphrase::generate_strong());

    // Try to load existing keys
    if PgpKeyManager::keys_exist(username) {
        if let Some((secret, public)) = PgpKeyManager::load_keypair_secure(username, &passphrase)? {
            return Ok((secret, public, passphrase));
        }
    }

    // Generate new keys if none exist
    let (secret, public) = Crypto::generate_pgp_keypair_secure(username, &passphrase)?;
    PgpKeyManager::save_keypair_secure(username, &secret, &public, &passphrase)?;

    Ok((secret, public, passphrase))
}
```

---

## CLI Entry Point

In `main.rs`, the CLI is invoked when command-line arguments are provided:

```rust
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 {
        // CLI mode
        setup_cli_logging()?;
        run_cli()?;
    } else {
        // TUI mode
        setup_tui_logging()?;
        run_tui()?;
    }

    Ok(())
}
```

### CLI Runtime

```rust
async fn run_cli() -> Result<()> {
    let cli = Cli::parse();

    // Connect to mixnet
    let (service, incoming_rx) = MixnetService::connect(SERVER_ADDRESS).await?;

    // Create message handler
    let mut handler = MessageHandler::new(service, incoming_rx, DB_PATH).await?;

    match cli.command {
        Commands::Register { username } => {
            let (secret, public, passphrase) = KeyManager::load_or_create_keys(&username)?;
            handler.set_pgp_keys(secret, public, passphrase);

            if handler.register_user(&username).await? {
                println!("Registration successful!");
            } else {
                println!("Registration failed.");
            }
        }

        Commands::Login { username } => {
            if handler.login_user(&username).await? {
                println!("Login successful!");
            } else {
                println!("Login failed.");
            }
        }

        Commands::Send { recipient, message } => {
            handler.send_direct_message(&recipient, &message).await?;
            println!("Message sent to {}", recipient);
        }

        Commands::Query { username } => {
            if let Some((user, pk)) = handler.query_user(&username).await? {
                println!("User: {}", user);
                println!("Public Key: {}", pk);
            } else {
                println!("User not found.");
            }
        }

        Commands::Listen => {
            println!("Listening for messages... (Ctrl+C to quit)");
            loop {
                // Process incoming messages
                if let Some(incoming) = handler.incoming_rx.recv().await {
                    let messages = handler.process_received_message(incoming).await;
                    for (sender, content) in messages {
                        println!("[{}] {}", sender, content);
                    }
                }
            }
        }

        Commands::Handshake { recipient } => {
            handler.send_handshake(&recipient).await?;
            println!("Handshake sent to {}", recipient);
        }

        Commands::Group { action, name, server } => {
            match action.as_str() {
                "create" => {
                    println!("Group creation not yet implemented");
                }
                "join" => {
                    if let (Some(name), Some(server)) = (name, server) {
                        println!("Joining group {} on {}", name, server);
                    }
                }
                _ => {
                    println!("Unknown group action: {}", action);
                }
            }
        }
    }

    Ok(())
}
```

---

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `NYMSTR_PGP_PASSPHRASE` | Passphrase for PGP key encryption | No (auto-generated if not set) |
| `NYM_SERVER_ADDRESS` | Nym mixnet server address | No (uses default) |

### Setting Environment Variables

```bash
# Bash/Zsh
export NYMSTR_PGP_PASSPHRASE="your-secure-passphrase"

# Or for a single command
NYMSTR_PGP_PASSPHRASE="passphrase" nymstr login --username alice
```

---

## Output Formats

### Success Messages

```
Registration successful!
Login successful!
Message sent to bob
User: bob
Public Key: -----BEGIN PGP PUBLIC KEY BLOCK-----...
Handshake sent to bob
```

### Error Messages

```
Registration failed.
Login failed.
User not found.
Error: Failed to connect to mixnet
Error: PGP key not found
```

### Listen Mode Output

```
Listening for messages... (Ctrl+C to quit)
[alice] Hello!
[bob] Hi there!
[alice] How are you?
```

---

## Scripting Examples

### Automated Registration

```bash
#!/bin/bash
export NYMSTR_PGP_PASSPHRASE="secure-passphrase-here"

# Register multiple users
for user in alice bob charlie; do
    nymstr register --username "$user"
done
```

### Send Message Script

```bash
#!/bin/bash
RECIPIENT="$1"
MESSAGE="$2"

if [ -z "$RECIPIENT" ] || [ -z "$MESSAGE" ]; then
    echo "Usage: $0 <recipient> <message>"
    exit 1
fi

nymstr send --recipient "$RECIPIENT" --message "$MESSAGE"
```

### Message Listener with Logging

```bash
#!/bin/bash
LOG_FILE="messages.log"

nymstr listen | while read line; do
    echo "$(date -Iseconds) $line" >> "$LOG_FILE"
    echo "$line"
done
```

---

## Comparison: CLI vs TUI

| Feature | CLI | TUI |
|---------|-----|-----|
| Interactive | No | Yes |
| Scriptable | Yes | No |
| Message history | No | Yes |
| Contact list | No | Yes |
| Real-time updates | Listen mode | Yes |
| Key management | Manual | Automatic |

### When to Use CLI

- Automated scripts
- Single operations (send one message)
- Server/headless environments
- Integration with other tools
- Testing and debugging

### When to Use TUI

- Interactive chat sessions
- Managing multiple contacts
- Viewing message history
- User-friendly experience
