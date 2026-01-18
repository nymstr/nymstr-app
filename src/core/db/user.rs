//! User-related database operations
//!
//! This module contains methods for user registration, initialization, and retrieval.

use super::{Db, sanitize_table_name};
use anyhow::Result;
use sqlx::Row;

impl Db {
    /// Create per-user tables (contacts, messages, and MLS groups).
    pub async fn init_user(&self, username: &str) -> Result<()> {
        let safe_name = sanitize_table_name(username)?;
        let contacts_table = format!("contacts_{}", safe_name);
        let messages_table = format!("messages_{}", safe_name);
        let mls_groups_table = format!("mls_groups_{}", safe_name);

        sqlx::query(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {contacts_table} (
                username TEXT PRIMARY KEY,
                public_key TEXT NOT NULL
            )
            "#,
            contacts_table = contacts_table,
        ))
        .execute(&self.pool)
        .await?;

        sqlx::query(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {messages_table} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                type TEXT CHECK(type IN ('to','from')) NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#,
            messages_table = messages_table,
        ))
        .execute(&self.pool)
        .await?;

        sqlx::query(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {mls_groups_table} (
                conversation_id TEXT PRIMARY KEY,
                group_state BLOB NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#,
            mls_groups_table = mls_groups_table,
        ))
        .execute(&self.pool)
        .await?;

        // Create pending MLS messages table for epoch-aware buffering
        let pending_messages_table = format!("pending_mls_messages_{}", safe_name);
        sqlx::query(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {pending_messages_table} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                mls_message_b64 TEXT NOT NULL,
                received_at TEXT NOT NULL,
                retry_count INTEGER DEFAULT 0,
                last_retry_at TEXT,
                status TEXT DEFAULT 'pending',
                error_message TEXT,
                UNIQUE(conversation_id, mls_message_b64)
            )
            "#,
            pending_messages_table = pending_messages_table,
        ))
        .execute(&self.pool)
        .await?;

        // Create index for efficient lookups
        sqlx::query(&format!(
            r#"
            CREATE INDEX IF NOT EXISTS idx_pending_conv_status_{safe_name}
            ON {pending_messages_table}(conversation_id, status)
            "#,
            safe_name = safe_name,
            pending_messages_table = pending_messages_table,
        ))
        .execute(&self.pool)
        .await?;

        // Create group messages table for storing fetched group messages
        let group_messages_table = format!("group_messages_{}", safe_name);
        sqlx::query(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {group_messages_table} (
                id INTEGER PRIMARY KEY,
                group_server TEXT NOT NULL,
                sender TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                message_timestamp TEXT NOT NULL,
                fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                decrypted_content TEXT,
                UNIQUE(group_server, id)
            )
            "#,
            group_messages_table = group_messages_table,
        ))
        .execute(&self.pool)
        .await?;

        // Create group fetch cursor table
        let group_cursor_table = format!("group_cursor_{}", safe_name);
        sqlx::query(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {group_cursor_table} (
                group_server TEXT PRIMARY KEY,
                last_seen_id INTEGER NOT NULL DEFAULT 0,
                last_fetch_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#,
            group_cursor_table = group_cursor_table,
        ))
        .execute(&self.pool)
        .await?;

        // Create MLS credentials table for storing credential bindings
        let mls_credentials_table = format!("mls_credentials_{}", safe_name);
        sqlx::query(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {mls_credentials_table} (
                username TEXT PRIMARY KEY,
                pgp_key_fingerprint BLOB NOT NULL,
                mls_signature_key BLOB NOT NULL,
                credential_type TEXT NOT NULL DEFAULT 'basic',
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                credential_data BLOB NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#,
            mls_credentials_table = mls_credentials_table,
        ))
        .execute(&self.pool)
        .await?;

        // Create key packages table for storing generated key packages
        let key_packages_table = format!("key_packages_{}", safe_name);
        sqlx::query(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {key_packages_table} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_package_b64 TEXT NOT NULL,
                credential_username TEXT,
                cipher_suite TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME,
                used BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (credential_username) REFERENCES {mls_credentials_table}(username)
            )
            "#,
            key_packages_table = key_packages_table,
            mls_credentials_table = mls_credentials_table,
        ))
        .execute(&self.pool)
        .await?;

        // Create index for unused key packages lookup
        sqlx::query(&format!(
            r#"
            CREATE INDEX IF NOT EXISTS idx_key_packages_unused_{safe_name}
            ON {key_packages_table}(used, created_at)
            "#,
            safe_name = safe_name,
            key_packages_table = key_packages_table,
        ))
        .execute(&self.pool)
        .await?;

        // Create group memberships table for tracking group membership and credential verification
        let group_memberships_table = format!("group_memberships_{}", safe_name);
        sqlx::query(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {group_memberships_table} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id TEXT NOT NULL,
                member_username TEXT NOT NULL,
                credential_fingerprint TEXT,
                credential_verified BOOLEAN DEFAULT FALSE,
                verified_at DATETIME,
                joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                role TEXT DEFAULT 'member',
                UNIQUE(conversation_id, member_username)
            )
            "#,
            group_memberships_table = group_memberships_table,
        ))
        .execute(&self.pool)
        .await?;

        // Create index for group membership lookups
        sqlx::query(&format!(
            r#"
            CREATE INDEX IF NOT EXISTS idx_group_memberships_conv_{safe_name}
            ON {group_memberships_table}(conversation_id)
            "#,
            safe_name = safe_name,
            group_memberships_table = group_memberships_table,
        ))
        .execute(&self.pool)
        .await?;

        // Create group_welcomes table for storing received Welcome messages
        let group_welcomes_table = format!("group_welcomes_{}", safe_name);
        sqlx::query(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {group_welcomes_table} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                welcome_bytes BLOB NOT NULL,
                ratchet_tree BLOB,
                cipher_suite INTEGER DEFAULT 0,
                epoch INTEGER DEFAULT 0,
                received_at INTEGER NOT NULL,
                processed BOOLEAN DEFAULT FALSE,
                processed_at DATETIME,
                error_message TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#,
            group_welcomes_table = group_welcomes_table,
        ))
        .execute(&self.pool)
        .await?;

        // Create index for pending welcomes lookup
        sqlx::query(&format!(
            r#"
            CREATE INDEX IF NOT EXISTS idx_group_welcomes_pending_{safe_name}
            ON {group_welcomes_table}(processed, created_at)
            "#,
            safe_name = safe_name,
            group_welcomes_table = group_welcomes_table,
        ))
        .execute(&self.pool)
        .await?;

        // Create group_info table for storing published GroupInfo
        let group_info_table = format!("group_info_{}", safe_name);
        sqlx::query(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {group_info_table} (
                group_id TEXT PRIMARY KEY,
                mls_group_id TEXT,
                epoch INTEGER NOT NULL,
                tree_hash BLOB NOT NULL,
                group_info_bytes BLOB NOT NULL,
                external_pub BLOB,
                created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#,
            group_info_table = group_info_table,
        ))
        .execute(&self.pool)
        .await?;

        // Group invites table - stores incoming invitations to join groups
        let group_invites_table = format!("group_invites_{}", safe_name);
        sqlx::query(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {group_invites_table} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id TEXT NOT NULL,
                group_name TEXT,
                sender TEXT NOT NULL,
                received_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending'
            )
            "#,
            group_invites_table = group_invites_table,
        ))
        .execute(&self.pool)
        .await?;

        sqlx::query(&format!(
            "CREATE INDEX IF NOT EXISTS idx_{}_invites_status ON {} (status)",
            safe_name, group_invites_table
        ))
        .execute(&self.pool)
        .await?;

        // Join requests table - stores pending requests to join groups we manage
        let join_requests_table = format!("join_requests_{}", safe_name);
        sqlx::query(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {join_requests_table} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id TEXT NOT NULL,
                requester TEXT NOT NULL,
                key_package TEXT NOT NULL,
                requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending'
            )
            "#,
            join_requests_table = join_requests_table,
        ))
        .execute(&self.pool)
        .await?;

        sqlx::query(&format!(
            "CREATE INDEX IF NOT EXISTS idx_{}_requests_group ON {} (group_id, status)",
            safe_name, join_requests_table
        ))
        .execute(&self.pool)
        .await?;

        // Group servers table - maps group IDs to their server addresses and admins
        let group_servers_table = format!("group_servers_{}", safe_name);
        sqlx::query(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {group_servers_table} (
                group_id TEXT PRIMARY KEY,
                server_address TEXT NOT NULL,
                admin_username TEXT NOT NULL,
                mls_group_id TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#,
            group_servers_table = group_servers_table,
        ))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Register a new user and create their tables.
    pub async fn register_user(&self, username: &str, public_key: &str) -> Result<()> {
        sqlx::query(r#"INSERT OR REPLACE INTO users (username, public_key) VALUES (?, ?)"#)
            .bind(username)
            .bind(public_key)
            .execute(&self.pool)
            .await?;
        self.init_user(username).await?;
        Ok(())
    }

    /// Get a registered user's public key.
    pub async fn get_user(&self, username: &str) -> Result<Option<(String, String)>> {
        let row = sqlx::query(r#"SELECT username, public_key FROM users WHERE username = ?"#)
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        if let Some(r) = row {
            let name: String = r.try_get("username")?;
            let pk: String = r.try_get("public_key")?;
            Ok(Some((name, pk)))
        } else {
            Ok(None)
        }
    }

    /// Retrieve all registered users.
    #[allow(dead_code)] // Part of public API for user management
    pub async fn get_all_users(&self) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query(r#"SELECT username, public_key FROM users"#)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let name: String = r.try_get("username").unwrap();
                let pk: String = r.try_get("public_key").unwrap();
                (name, pk)
            })
            .collect())
    }
}
