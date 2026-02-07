//! Nymstr Desktop Application
//!
//! A privacy-first messaging application built on the Nym mixnet.
//! This crate provides the Tauri backend for the desktop application.

pub mod commands;
pub mod core;
pub mod crypto;
pub mod events;
pub mod state;
pub mod tasks;
pub mod types;

// Test utilities module (only available in tests)
#[cfg(test)]
pub mod test_utils;

use tauri::Manager;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::state::AppState;

/// Initialize logging
fn init_logging() {
    let filter = EnvFilter::from_default_env()
        .add_directive("nymstr_app_v2=info".parse().unwrap_or_else(|_| {
            tracing_subscriber::filter::LevelFilter::INFO.into()
        }));

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    init_logging();
    tracing::info!("Starting Nymstr application");

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let app_handle = app.handle().clone();

            // Initialize state asynchronously
            tauri::async_runtime::block_on(async {
                match AppState::new(&app_handle).await {
                    Ok(state) => {
                        app.manage(state);
                        tracing::info!("Application state initialized");
                    }
                    Err(e) => {
                        tracing::error!("Failed to initialize state: {}", e);
                        panic!("Failed to initialize application state: {}", e);
                    }
                }
            });

            // Note: Background tasks (message loop, buffer processor, connection monitor)
            // are started after successful authentication in auth.rs.
            // This is intentional - the message loop requires:
            // - A logged-in user with PGP keys for signature verification
            // - An MLS client for message decryption
            // - The mixnet service to be connected
            //
            // See: register_user() and login_user() in commands/auth.rs

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Auth commands
            commands::initialize,
            commands::register_user,
            commands::login_user,
            commands::logout,
            commands::get_current_user,
            // Connection commands
            commands::connect_to_mixnet,
            commands::connect_to_mixnet_for_user,
            commands::disconnect_from_mixnet,
            commands::get_connection_status,
            commands::set_server_address,
            commands::get_server_address,
            // Contact commands
            commands::get_contacts,
            commands::add_contact,
            commands::remove_contact,
            commands::query_user,
            // Messaging commands
            commands::send_message,
            commands::get_conversation,
            commands::mark_as_read,
            commands::initiate_conversation,
            commands::generate_key_package,
            commands::check_conversation_exists,
            commands::get_pending_messages,
            // Group commands
            commands::discover_groups,
            commands::init_group,
            commands::join_group,
            commands::leave_group,
            commands::send_group_message,
            commands::fetch_group_messages,
            commands::get_joined_groups,
            commands::get_pending_welcomes,
            commands::process_welcome,
            commands::set_mls_group_id,
            commands::approve_member,
            commands::get_pending_join_requests,
            commands::get_group_members,
            commands::get_current_user_role,
            // Invite commands
            commands::get_contact_requests,
            commands::accept_contact_request,
            commands::deny_contact_request,
            commands::deny_welcome,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
