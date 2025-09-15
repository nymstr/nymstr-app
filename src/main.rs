mod app;
mod cli;
mod core;
mod crypto;
mod event;
mod model;
mod screen;
mod ui;

use crate::app::App;
use crate::cli::{Cli, run_cli};
use clap::Parser;
use color_eyre::Result;
// Custom logger to capture log output in TUI
mod log_buffer;
use chrono::Utc;
use dotenvy::dotenv;
use env_logger::Builder;
use log::LevelFilter;
use log_buffer::LOG_BUFFER;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    // load environment variables from .env file, if present
    dotenv().ok();

    // Check if CLI arguments are provided
    let args: Vec<String> = std::env::args().collect();

    // If arguments are provided (beyond just the program name), use CLI mode
    if args.len() > 1 {
        // Parse CLI arguments
        let cli = Cli::parse();

        // Setup simple logging for CLI mode (no TUI buffer needed)
        setup_cli_logging(cli.verbose)?;

        // Run CLI mode
        if let Err(e) = run_cli(cli).await {
            eprintln!("CLI error: {}", e);
            std::process::exit(1);
        }
    } else {
        // No arguments provided, run TUI mode
        setup_tui_logging()?;

        let mut terminal = ratatui::init();
        let mut app = App::new();
        // Load splash pages before entering main UI loop
        app.load_splash()?;
        app.run(&mut terminal).await?;
        ratatui::restore();
    }

    Ok(())
}

fn setup_cli_logging(verbose: bool) -> Result<()> {
    let level = if verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    // Get username for log file (use from env or default)
    let username = std::env::var("USER").unwrap_or_else(|_| "client".to_string());
    let log_filename = format!("nymstr_{}.log", username);

    use std::fs::OpenOptions;
    use std::io::Write;

    Builder::from_default_env()
        .format(move |_buf, record| {
            // Simple console output for CLI mode
            let ts = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
            let s = format!(
                "[{}] {} [{}] {}",
                ts,
                record.level(),
                record.target(),
                record.args()
            );

            // Print to console
            println!("{}", s);

            // Also write to file
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_filename)
            {
                let _ = writeln!(file, "{}", s);
            }

            Ok(())
        })
        .filter(None, level)
        .init();

    Ok(())
}

fn setup_tui_logging() -> Result<()> {
    // Get username for log file (use from env or default)
    let username = std::env::var("USER").unwrap_or_else(|_| "client".to_string());
    let log_filename = format!("nymstr_{}.log", username);

    // initialize logging with in-app buffer and file output
    use std::fs::OpenOptions;
    use std::io::Write;

    Builder::from_default_env()
        .format(move |_buf, record| {
            // Format log message and capture in TUI log buffer + write to file
            let ts = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
            let s = format!(
                "[{}] {} [{}] {}",
                ts,
                record.level(),
                record.target(),
                record.args()
            );

            // Add to TUI buffer
            if let Ok(mut v) = LOG_BUFFER.lock() {
                v.push(s.clone());
                if v.len() > 1000 {
                    v.remove(0);
                }
            }

            // Write to file
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_filename)
            {
                let _ = writeln!(file, "{}", s);
            }

            Ok(())
        })
        .filter(None, LevelFilter::Info)
        .init();

    Ok(())
}
