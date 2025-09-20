use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::cli::KeyManager;
use crate::core::message_handler::MessageHandler;
use crate::core::mixnet_client::MixnetService;
use log::info;

#[derive(Parser)]
#[command(name = "nymstr")]
#[command(about = "Nymstr - Anonymous messaging over the Nym mixnet")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Username for operations
    #[arg(short, long)]
    pub username: Option<String>,

    /// Enable verbose logging
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Register a new user
    Register {
        /// Username to register
        username: String,
    },
    /// Login with existing user
    Login {
        /// Username to login with
        username: String,
    },
    /// Send a message to a recipient
    Send {
        /// Sender username (must be logged in)
        from: String,
        /// Recipient username
        recipient: String,
        /// Message content
        message: String,
    },
    /// Query for a user's public key
    Query {
        /// Username to query
        username: String,
    },
    /// Listen for incoming messages
    Listen {
        /// Username to listen as (must be logged in)
        username: String,
        /// Duration to listen in seconds (0 = indefinite)
        #[arg(short, long, default_value = "0")]
        duration: u64,
    },
    /// Send a handshake to establish p2p routing
    Handshake {
        /// Sender username (must be logged in)
        from: String,
        /// Recipient username
        recipient: String,
    },
    /// Group operations
    Group {
        #[command(subcommand)]
        action: GroupCommands,
    },
}

#[derive(Subcommand)]
pub enum GroupCommands {
    /// Register with a group server
    Register {
        /// Group server address
        server: String,
        /// Username for group
        username: String,
    },
    /// Send a message to the group
    Send {
        /// Group server address
        server: String,
        /// Message content
        message: String,
    },
    /// Get group statistics
    Stats {
        /// Group server address
        server: String,
    },
}

pub struct CliApp {
    handler: Option<MessageHandler>,
}

impl CliApp {
    pub fn new() -> Self {
        Self { handler: None }
    }

    pub async fn connect(&mut self) -> Result<()> {
        info!("Connecting to mixnet...");

        // Initialize mixnet service
        let (service, incoming_rx) = MixnetService::new("nymstr.db").await?;

        // Initialize message handler
        let mut handler = MessageHandler::new(service, incoming_rx, "nymstr.db").await?;

        // Store the nym address for later use
        handler.nym_address = Some(handler.service.get_nym_address().to_string());

        self.handler = Some(handler);
        info!("Connected to mixnet successfully");
        Ok(())
    }


    pub async fn login(&mut self, username: &str) -> Result<bool> {
        let handler = self.handler.as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        info!("Logging in user: {}", username);

        // Use KeyManager to load existing keys with password prompting
        let (secret_key, public_key, passphrase) = KeyManager::load_existing_keys(username)?;

        // Verify keys are valid
        KeyManager::verify_keys(&secret_key, &public_key)?;

        // Set the keys in the message handler
        handler.set_pgp_keys(secret_key, public_key, passphrase);

        // Now login with the server
        let success = handler.login_user(username).await?;

        if success {
            info!("Login successful for user: {}", username);
        } else {
            info!("Login failed for user: {}", username);
        }

        Ok(success)
    }

    pub async fn send_message(&mut self, from: &str, recipient: &str, message: &str) -> Result<()> {
        let handler = self.handler.as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        // Ensure user is logged in first
        if handler.current_user.as_deref() != Some(from) {
            info!("Logging in user {} before sending message", from);
            let login_success = handler.login_user(from).await?;
            if !login_success {
                return Err(anyhow::anyhow!("Failed to login user: {}", from));
            }
        }

        info!("Sending message from {} to {}: {}", from, recipient, message);
        handler.send_direct_message(recipient, message).await?;
        info!("Message sent successfully");
        Ok(())
    }

    pub async fn query_user(&mut self, username: &str) -> Result<Option<(String, String)>> {
        let handler = self.handler.as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        info!("Querying user: {}", username);
        let result = handler.query_user(username).await?;

        match &result {
            Some((user, pk)) => {
                info!("Query successful - User: {}, Public Key: {}", user, pk);
                println!("User: {}\nPublic Key: {}", user, pk);
            }
            None => {
                info!("User not found: {}", username);
                println!("User not found: {}", username);
            }
        }

        Ok(result)
    }

    pub async fn send_handshake(&mut self, from: &str, recipient: &str) -> Result<()> {
        let handler = self.handler.as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        // Ensure user is logged in first
        if handler.current_user.as_deref() != Some(from) {
            info!("Logging in user {} before sending handshake", from);
            let login_success = handler.login_user(from).await?;
            if !login_success {
                return Err(anyhow::anyhow!("Failed to login user: {}", from));
            }
        }

        info!("Sending handshake from {} to: {}", from, recipient);
        handler.send_handshake(recipient).await?;
        info!("Handshake sent successfully");
        Ok(())
    }

    pub async fn listen(&mut self, username: &str, duration: u64) -> Result<()> {
        let handler = self.handler.as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        // Ensure user is logged in first
        if handler.current_user.as_deref() != Some(username) {
            info!("Logging in user {} before listening", username);
            let login_success = handler.login_user(username).await?;
            if !login_success {
                return Err(anyhow::anyhow!("Failed to login user: {}", username));
            }
        }

        info!("Listening for messages as {}{}...",
              username,
              if duration > 0 { format!(" for {} seconds", duration) } else { String::new() });

        let timeout = if duration > 0 {
            Some(std::time::Duration::from_secs(duration))
        } else {
            None
        };

        let start_time = std::time::Instant::now();

        loop {
            // Check timeout
            if let Some(timeout_duration) = timeout {
                if start_time.elapsed() >= timeout_duration {
                    info!("Listen timeout reached");
                    break;
                }
            }

            // Listen for incoming messages with a reasonable timeout
            tokio::select! {
                incoming = handler.incoming_rx.recv() => {
                    if let Some(incoming) = incoming {
                        let messages = handler.process_received_message(incoming).await;
                        for (sender, message) in messages {
                            println!("Message from {}: {}", sender, message);
                            info!("Received message from {}: {}", sender, message);
                        }
                    } else {
                        info!("Message channel closed");
                        break;
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                    // Continue listening
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Listen cancelled by user");
                    break;
                }
            }
        }

        Ok(())
    }

    pub async fn group_register(&mut self, server: &str, username: &str) -> Result<bool> {
        let handler = self.handler.as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        info!("Registering with group server {}", server);
        let success = handler.authenticate_group(username, server).await?;

        if success {
            info!("Group registration successful");
        } else {
            info!("Group registration failed");
        }

        Ok(success)
    }

    pub async fn group_send(&mut self, server: &str, message: &str) -> Result<()> {
        let handler = self.handler.as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        info!("Sending group message to {}: {}", server, message);
        handler.send_group_message(message, server).await?;
        info!("Group message sent successfully");
        Ok(())
    }

    pub async fn group_stats(&mut self, server: &str) -> Result<()> {
        let handler = self.handler.as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;

        info!("Getting group stats from {}", server);
        handler.service.get_group_stats(server).await?;
        info!("Group stats request sent");
        Ok(())
    }
}

pub async fn run_cli(cli: Cli) -> Result<()> {
    let mut app = CliApp::new();

    // Connect to mixnet first
    app.connect().await?;

    match cli.command {
        Commands::Register { username } => {
            let handler = app.handler.as_mut()
                .ok_or_else(|| anyhow::anyhow!("Not connected to mixnet"))?;
            handler.register_user(&username).await?;
        }

        Commands::Login { username } => {
            app.login(&username).await?;
        }

        Commands::Send { from, recipient, message } => {
            app.send_message(&from, &recipient, &message).await?;
            // Wait for message to be transmitted through mixnet before shutting down
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        }

        Commands::Query { username } => {
            app.query_user(&username).await?;
        }

        Commands::Listen { username, duration } => {
            app.listen(&username, duration).await?;
        }

        Commands::Handshake { from, recipient } => {
            app.send_handshake(&from, &recipient).await?;
        }

        Commands::Group { action } => {
            match action {
                GroupCommands::Register { server, username } => {
                    app.group_register(&server, &username).await?;
                }
                GroupCommands::Send { server, message } => {
                    app.group_send(&server, &message).await?;
                }
                GroupCommands::Stats { server } => {
                    app.group_stats(&server).await?;
                }
            }
        }
    }

    Ok(())
}