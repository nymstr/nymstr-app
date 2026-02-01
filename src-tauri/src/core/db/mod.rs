//! Database module for SQLite persistence.
//!
//! This module provides database operations for the Nymstr client:
//! - User registration and management
//! - Contact management
//! - Message storage and retrieval
//! - MLS state and credential operations
//! - Group membership and server operations
//!
//! The database uses a global schema (not per-user tables) since this is a
//! Tauri desktop app where each user has their own database file.
//!
//! ## Architecture
//!
//! - `schema.rs` - Centralized table and index definitions
//! - `user.rs` - User operations
//! - `contacts.rs` - Contact operations
//! - `messages.rs` - Message operations
//! - `mls.rs` - MLS credential, key package, and welcome operations
//! - `group.rs` - Group membership, server, invite, and join request operations

pub mod contacts;
pub mod group;
pub mod messages;
pub mod mls;
pub mod schema;
pub mod user;

// Re-export database operation structs
pub use contacts::ContactDb;
pub use group::{GroupCursor, GroupDb, GroupMember, GroupMembership, GroupServer};
pub use messages::{BufferedMessage, MessageDb};
pub use mls::{MlsDb, StoredCredential, StoredKeyPackage};
pub use schema::run_migrations;
pub use user::UserDb;

// Re-export MLS types from crypto module
pub use crate::crypto::mls::types::{MlsGroupInfoPublic, StoredWelcome};

use anyhow::Result;
use sqlx::SqlitePool;

use crate::types::{ContactDTO, MessageDTO, UserDTO};

/// High-level database interface that wraps the SqlitePool
///
/// This struct provides a unified interface to all database operations,
/// delegating to the specialized submodules.
pub struct Db;

impl Db {
    // ========== User Operations ==========

    /// Save or update a user
    pub async fn save_user(pool: &SqlitePool, user: &UserDTO) -> Result<()> {
        UserDb::save_user(pool, user).await
    }

    /// Get a user by username
    pub async fn get_user(pool: &SqlitePool, username: &str) -> Result<Option<UserDTO>> {
        UserDb::get_user(pool, username).await
    }

    /// Get the first registered user
    pub async fn get_first_user(pool: &SqlitePool) -> Result<Option<UserDTO>> {
        UserDb::get_first_user(pool).await
    }

    /// Check if a user exists
    pub async fn user_exists(pool: &SqlitePool, username: &str) -> Result<bool> {
        UserDb::user_exists(pool, username).await
    }

    // ========== Contact Operations ==========

    /// Save or update a contact
    pub async fn save_contact(pool: &SqlitePool, contact: &ContactDTO) -> Result<()> {
        ContactDb::save_contact(pool, contact).await
    }

    /// Save a contact with public key
    pub async fn save_contact_with_key(
        pool: &SqlitePool,
        username: &str,
        display_name: &str,
        public_key: &str,
    ) -> Result<()> {
        ContactDb::save_contact_with_key(pool, username, display_name, public_key).await
    }

    /// Get all contacts
    pub async fn get_contacts(pool: &SqlitePool) -> Result<Vec<ContactDTO>> {
        ContactDb::get_contacts(pool).await
    }

    /// Get a contact by username
    pub async fn get_contact(pool: &SqlitePool, username: &str) -> Result<Option<ContactDTO>> {
        ContactDb::get_contact(pool, username).await
    }

    /// Remove a contact
    pub async fn remove_contact(pool: &SqlitePool, username: &str) -> Result<()> {
        ContactDb::remove_contact(pool, username).await
    }

    // ========== Message Operations ==========

    /// Save a message to a conversation
    pub async fn save_message(pool: &SqlitePool, conv_id: &str, msg: &MessageDTO) -> Result<()> {
        MessageDb::save_message(pool, conv_id, msg).await
    }

    /// Get messages for a conversation with limit
    pub async fn get_messages(
        pool: &SqlitePool,
        conv_id: &str,
        limit: u32,
    ) -> Result<Vec<MessageDTO>> {
        MessageDb::get_messages(pool, conv_id, limit).await
    }

    /// Get all messages for a conversation
    pub async fn get_all_messages(pool: &SqlitePool, conv_id: &str) -> Result<Vec<MessageDTO>> {
        MessageDb::get_all_messages(pool, conv_id).await
    }

    // ========== MLS Welcome Operations ==========

    /// Save a welcome message
    pub async fn save_welcome(pool: &SqlitePool, welcome: &StoredWelcome) -> Result<i64> {
        MlsDb::save_welcome(pool, welcome).await
    }

    /// Get pending welcomes
    pub async fn get_pending_welcomes(pool: &SqlitePool) -> Result<Vec<StoredWelcome>> {
        MlsDb::get_pending_welcomes(pool).await
    }

    /// Mark a welcome as processed
    pub async fn mark_welcome_processed(pool: &SqlitePool, id: i64) -> Result<()> {
        MlsDb::mark_welcome_processed(pool, id).await
    }

    // ========== Epoch Buffer Operations ==========

    /// Buffer a message for later processing
    pub async fn buffer_message(pool: &SqlitePool, msg: &BufferedMessage) -> Result<()> {
        MessageDb::buffer_message(pool, msg).await
    }

    /// Get buffered messages for a conversation
    pub async fn get_buffered_messages(
        pool: &SqlitePool,
        conv_id: &str,
    ) -> Result<Vec<BufferedMessage>> {
        MessageDb::get_buffered_messages(pool, conv_id).await
    }

    /// Remove a buffered message
    pub async fn remove_buffered_message(pool: &SqlitePool, id: i64) -> Result<()> {
        MessageDb::remove_buffered_message(pool, id).await
    }

    // ========== Group Server Operations ==========

    /// Save a group server
    pub async fn save_group_server(pool: &SqlitePool, server: &GroupServer) -> Result<()> {
        GroupDb::save_group_server(pool, server).await
    }

    /// Get all group servers
    pub async fn get_group_servers(pool: &SqlitePool) -> Result<Vec<GroupServer>> {
        GroupDb::get_group_servers(pool).await
    }

    /// Update group cursor
    pub async fn update_group_cursor(
        pool: &SqlitePool,
        addr: &str,
        cursor: i64,
    ) -> Result<()> {
        GroupDb::update_group_cursor(pool, addr, cursor).await
    }

    /// Get MLS group ID by server address
    pub async fn get_mls_group_id_by_server(
        pool: &SqlitePool,
        server_address: &str,
    ) -> Result<Option<String>> {
        GroupDb::get_mls_group_id_by_server(pool, server_address).await
    }

    // ========== MLS Group State Operations ==========

    /// Save MLS group state
    pub async fn save_mls_group_state(
        pool: &SqlitePool,
        conversation_id: &str,
        group_state: &[u8],
    ) -> Result<()> {
        MlsDb::save_group_state(pool, conversation_id, group_state).await
    }

    /// Load MLS group state
    pub async fn load_mls_group_state(
        pool: &SqlitePool,
        conversation_id: &str,
    ) -> Result<Option<Vec<u8>>> {
        MlsDb::load_group_state(pool, conversation_id).await
    }

    // ========== MLS Credential Operations ==========

    /// Store an MLS credential
    pub async fn store_credential(pool: &SqlitePool, credential: &StoredCredential) -> Result<()> {
        MlsDb::store_credential(pool, credential).await
    }

    /// Get an MLS credential
    pub async fn get_credential(
        pool: &SqlitePool,
        username: &str,
    ) -> Result<Option<StoredCredential>> {
        MlsDb::get_credential(pool, username).await
    }

    // ========== Key Package Operations ==========

    /// Store a key package
    pub async fn store_key_package(
        pool: &SqlitePool,
        key_package_b64: &str,
        credential_username: Option<&str>,
        cipher_suite: &str,
        expires_at: Option<&str>,
    ) -> Result<i64> {
        MlsDb::store_key_package(pool, key_package_b64, credential_username, cipher_suite, expires_at)
            .await
    }

    /// Get an unused key package
    pub async fn get_key_package(pool: &SqlitePool) -> Result<Option<StoredKeyPackage>> {
        MlsDb::get_key_package(pool).await
    }

    /// Mark a key package as used
    pub async fn mark_key_package_used(pool: &SqlitePool, id: i64) -> Result<()> {
        MlsDb::mark_key_package_used(pool, id).await
    }

    // ========== Group Info Operations ==========

    /// Store group info
    pub async fn store_group_info(
        pool: &SqlitePool,
        group_id: &str,
        group_info: &MlsGroupInfoPublic,
    ) -> Result<()> {
        MlsDb::store_group_info(pool, group_id, group_info).await
    }

    /// Get group info
    pub async fn get_group_info(
        pool: &SqlitePool,
        group_id: &str,
    ) -> Result<Option<MlsGroupInfoPublic>> {
        MlsDb::get_group_info(pool, group_id).await
    }

    // ========== Group Membership Operations ==========

    /// Add a member to a group
    pub async fn add_group_member(
        pool: &SqlitePool,
        conversation_id: &str,
        member_username: &str,
        credential_fingerprint: Option<&str>,
        credential_verified: bool,
        role: &str,
    ) -> Result<()> {
        GroupDb::add_member(
            pool,
            conversation_id,
            member_username,
            credential_fingerprint,
            credential_verified,
            role,
        )
        .await
    }

    /// Get group members
    pub async fn get_group_members(
        pool: &SqlitePool,
        conversation_id: &str,
    ) -> Result<Vec<GroupMember>> {
        GroupDb::get_members(pool, conversation_id).await
    }

    // ========== Conversation Operations ==========

    /// Create a conversation
    pub async fn create_conversation(
        pool: &SqlitePool,
        id: &str,
        conv_type: &str,
        participant: Option<&str>,
        group_address: Option<&str>,
        mls_group_id: Option<&str>,
    ) -> Result<()> {
        GroupDb::create_conversation(pool, id, conv_type, participant, group_address, mls_group_id)
            .await
    }

    /// Update conversation last message time
    pub async fn update_conversation_last_message(pool: &SqlitePool, id: &str) -> Result<()> {
        GroupDb::update_conversation_last_message(pool, id).await
    }

    // ========== Group Invite Operations ==========

    /// Store a group invite
    pub async fn store_group_invite(
        pool: &SqlitePool,
        group_id: &str,
        group_name: Option<&str>,
        sender: &str,
    ) -> Result<i64> {
        GroupDb::store_invite(pool, group_id, group_name, sender).await
    }

    /// Get pending invites
    pub async fn get_pending_invites(
        pool: &SqlitePool,
    ) -> Result<Vec<(i64, String, Option<String>, String, String)>> {
        GroupDb::get_pending_invites(pool).await
    }

    /// Update invite status
    pub async fn update_invite_status(pool: &SqlitePool, invite_id: i64, status: &str) -> Result<()> {
        GroupDb::update_invite_status(pool, invite_id, status).await
    }

    // ========== Join Request Operations ==========

    /// Store a join request
    pub async fn store_join_request(
        pool: &SqlitePool,
        group_id: &str,
        requester: &str,
        key_package: &str,
    ) -> Result<i64> {
        GroupDb::store_join_request(pool, group_id, requester, key_package).await
    }

    /// Get pending join requests for a group
    pub async fn get_pending_join_requests(
        pool: &SqlitePool,
        group_id: &str,
    ) -> Result<Vec<(i64, String, String, String)>> {
        GroupDb::get_pending_join_requests(pool, group_id).await
    }

    /// Get all pending join requests
    pub async fn get_all_pending_join_requests(
        pool: &SqlitePool,
    ) -> Result<Vec<(i64, String, String, String, String)>> {
        GroupDb::get_all_pending_join_requests(pool).await
    }

    /// Update join request status
    pub async fn update_join_request_status(
        pool: &SqlitePool,
        request_id: i64,
        status: &str,
    ) -> Result<()> {
        GroupDb::update_join_request_status(pool, request_id, status).await
    }

    // ========== Group Membership Operations (Per-User Scoped) ==========

    /// Add or update a group membership for a user
    pub async fn add_group_membership(
        pool: &SqlitePool,
        server_address: &str,
        username: &str,
        mls_group_id: Option<&str>,
        role: &str,
    ) -> Result<()> {
        GroupDb::add_group_membership(pool, server_address, username, mls_group_id, role).await
    }

    /// Get a group membership for a user
    pub async fn get_group_membership(
        pool: &SqlitePool,
        server_address: &str,
        username: &str,
    ) -> Result<Option<GroupMembership>> {
        GroupDb::get_group_membership(pool, server_address, username).await
    }

    /// Get all group memberships for a user
    pub async fn get_user_memberships(
        pool: &SqlitePool,
        username: &str,
    ) -> Result<Vec<GroupMembership>> {
        GroupDb::get_user_memberships(pool, username).await
    }

    /// Get MLS group ID for a user's membership
    pub async fn get_membership_mls_group_id(
        pool: &SqlitePool,
        server_address: &str,
        username: &str,
    ) -> Result<Option<String>> {
        GroupDb::get_membership_mls_group_id(pool, server_address, username).await
    }

    /// Update MLS group ID for a user's membership
    pub async fn update_membership_mls_group_id(
        pool: &SqlitePool,
        server_address: &str,
        username: &str,
        mls_group_id: &str,
    ) -> Result<()> {
        GroupDb::update_membership_mls_group_id(pool, server_address, username, mls_group_id).await
    }

    /// Remove a group membership for a user
    pub async fn remove_group_membership(
        pool: &SqlitePool,
        server_address: &str,
        username: &str,
    ) -> Result<()> {
        GroupDb::remove_group_membership(pool, server_address, username).await
    }

    // ========== Group Cursor Operations (Per-User Scoped) ==========

    /// Get the message cursor for a user's group
    pub async fn get_group_cursor_for_user(
        pool: &SqlitePool,
        server_address: &str,
        username: &str,
    ) -> Result<i64> {
        GroupDb::get_group_cursor_for_user(pool, server_address, username).await
    }

    /// Update the message cursor for a user's group
    pub async fn update_group_cursor_for_user(
        pool: &SqlitePool,
        server_address: &str,
        username: &str,
        last_message_id: i64,
    ) -> Result<()> {
        GroupDb::update_group_cursor_for_user(pool, server_address, username, last_message_id).await
    }

    /// Remove cursor for a user's group
    pub async fn remove_group_cursor_for_user(
        pool: &SqlitePool,
        server_address: &str,
        username: &str,
    ) -> Result<()> {
        GroupDb::remove_group_cursor_for_user(pool, server_address, username).await
    }
}
