//! Nymstr - Privacy-focused messaging application
//!
//! This crate provides the core functionality for the Nymstr messaging application,
//! including cryptographic operations, database management, and user interface components.

pub mod app;
pub mod cli;
pub mod core;
pub mod crypto;
pub mod event;
pub mod log_buffer;
pub mod model;
pub mod screen;
pub mod ui;

#[cfg(test)]
pub mod test_pgp;

// Re-export commonly used items for convenience
pub use core::db::Db;
pub use crypto::mls::MlsClient;
