//! Centralized database schema definitions.
//!
//! All table and index definitions are consolidated here for:
//! - Single source of truth for database structure
//! - Easy schema auditing and documentation
//! - Consistent table creation across the application

use sqlx::SqlitePool;

/// Run all database migrations/table creation
pub async fn run_migrations(db: &SqlitePool) -> Result<(), sqlx::Error> {
    create_tables(db).await?;
    create_indexes(db).await?;
    tracing::info!("Database migrations completed");
    Ok(())
}

/// Create all tables
async fn create_tables(db: &SqlitePool) -> Result<(), sqlx::Error> {
    // ========== User & Contact Tables ==========

    // Users table - registered users
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            public_key TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        "#,
    )
    .execute(db)
    .await?;

    // Contacts table - per-user contact list
    // owner_username scopes contacts to each user
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS contacts (
            owner_username TEXT NOT NULL,
            username TEXT NOT NULL,
            display_name TEXT NOT NULL,
            public_key TEXT NOT NULL,
            last_seen TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (owner_username, username)
        )
        "#,
    )
    .execute(db)
    .await?;

    // ========== Message Tables ==========

    // Messages table - all message storage
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            conversation_id TEXT NOT NULL,
            sender TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            is_own INTEGER NOT NULL DEFAULT 0
        )
        "#,
    )
    .execute(db)
    .await?;

    // Pending MLS messages table - epoch buffer for reordering
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS pending_mls_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id TEXT NOT NULL,
            sender TEXT NOT NULL,
            mls_message_b64 TEXT NOT NULL,
            received_at TEXT NOT NULL DEFAULT (datetime('now')),
            retry_count INTEGER NOT NULL DEFAULT 0,
            last_retry_at TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            error_message TEXT
        )
        "#,
    )
    .execute(db)
    .await?;

    // ========== Group Tables ==========

    // Groups table - group directory & metadata
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS groups (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            address TEXT NOT NULL,
            member_count INTEGER NOT NULL DEFAULT 0,
            is_public INTEGER NOT NULL DEFAULT 0,
            description TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        "#,
    )
    .execute(db)
    .await?;

    // Group memberships table - tracks which groups each user has joined
    // Scoped per-user to support multiple users in shared database
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS group_memberships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_address TEXT NOT NULL,
            username TEXT NOT NULL,
            mls_group_id TEXT,
            joined_at TEXT NOT NULL DEFAULT (datetime('now')),
            role TEXT NOT NULL DEFAULT 'member',
            UNIQUE(server_address, username)
        )
        "#,
    )
    .execute(db)
    .await?;

    // Group cursors table - message fetch position per server
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS group_cursors (
            server_address TEXT NOT NULL,
            username TEXT NOT NULL,
            last_message_id INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (server_address, username)
        )
        "#,
    )
    .execute(db)
    .await?;

    // Group members table - members of a specific MLS group/conversation
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS group_members (
            conversation_id TEXT,
            member_username TEXT,
            credential_fingerprint TEXT,
            credential_verified INTEGER DEFAULT 0,
            verified_at TEXT,
            joined_at TEXT DEFAULT (datetime('now')),
            role TEXT DEFAULT 'member',
            PRIMARY KEY (conversation_id, member_username)
        )
        "#,
    )
    .execute(db)
    .await?;

    // Group servers table - server address to MLS group mapping
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS group_servers (
            server_address TEXT PRIMARY KEY,
            mls_group_id TEXT,
            group_name TEXT,
            last_cursor INTEGER DEFAULT 0,
            joined_at TEXT DEFAULT (datetime('now'))
        )
        "#,
    )
    .execute(db)
    .await?;

    // Group invites table - incoming invitations
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS group_invites (
            id INTEGER PRIMARY KEY,
            group_id TEXT NOT NULL,
            group_name TEXT,
            sender TEXT NOT NULL,
            received_at TEXT DEFAULT (datetime('now')),
            status TEXT DEFAULT 'pending'
        )
        "#,
    )
    .execute(db)
    .await?;

    // Join requests table - pending requests to join groups we manage
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS join_requests (
            id INTEGER PRIMARY KEY,
            group_id TEXT NOT NULL,
            requester TEXT NOT NULL,
            key_package TEXT NOT NULL,
            requested_at TEXT DEFAULT (datetime('now')),
            status TEXT DEFAULT 'pending'
        )
        "#,
    )
    .execute(db)
    .await?;

    // Group info table - published GroupInfo for external joins
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS group_info (
            group_id TEXT PRIMARY KEY,
            mls_group_id TEXT,
            epoch INTEGER NOT NULL,
            tree_hash BLOB NOT NULL,
            group_info_bytes BLOB NOT NULL,
            external_pub BLOB,
            created_by TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at TEXT DEFAULT (datetime('now'))
        )
        "#,
    )
    .execute(db)
    .await?;

    // ========== Conversation Tables ==========

    // Conversations table - unified view of DMs and groups
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS conversations (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            participant TEXT,
            group_address TEXT,
            mls_group_id TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            last_message_at TEXT
        )
        "#,
    )
    .execute(db)
    .await?;

    // ========== MLS Tables ==========

    // MLS credentials table - bind MLS identity to PGP
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS mls_credentials (
            username TEXT PRIMARY KEY,
            pgp_key_fingerprint BLOB,
            mls_signature_key BLOB,
            credential_type TEXT,
            issued_at INTEGER,
            expires_at INTEGER,
            credential_data BLOB,
            updated_at TEXT DEFAULT (datetime('now'))
        )
        "#,
    )
    .execute(db)
    .await?;

    // Key packages table - our own packages for handshakes
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS key_packages (
            id INTEGER PRIMARY KEY,
            key_package_b64 TEXT,
            credential_username TEXT,
            cipher_suite TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            expires_at TEXT,
            used INTEGER DEFAULT 0
        )
        "#,
    )
    .execute(db)
    .await?;

    // MLS group state table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS mls_groups (
            conversation_id TEXT PRIMARY KEY,
            group_state BLOB NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        )
        "#,
    )
    .execute(db)
    .await?;

    // Group welcomes table - pending welcomes to process
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS group_welcomes (
            id INTEGER PRIMARY KEY,
            group_id TEXT,
            sender TEXT,
            welcome_bytes BLOB,
            ratchet_tree BLOB,
            cipher_suite INTEGER,
            epoch INTEGER,
            received_at TEXT,
            processed INTEGER DEFAULT 0,
            processed_at TEXT,
            error_message TEXT
        )
        "#,
    )
    .execute(db)
    .await?;

    // Pending welcomes table - alternative storage for welcome messages
    // Used by group commands for welcome processing
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS pending_welcomes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id TEXT NOT NULL,
            sender TEXT NOT NULL,
            welcome_bytes TEXT NOT NULL,
            ratchet_tree TEXT,
            cipher_suite INTEGER NOT NULL,
            epoch INTEGER NOT NULL,
            received_at TEXT NOT NULL,
            processed INTEGER NOT NULL DEFAULT 0,
            processed_at TEXT,
            error_message TEXT
        )
        "#,
    )
    .execute(db)
    .await?;

    Ok(())
}

/// Create all indexes for efficient lookups
async fn create_indexes(db: &SqlitePool) -> Result<(), sqlx::Error> {
    // Message indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id)")
        .execute(db)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)")
        .execute(db)
        .await?;

    // Pending MLS messages index
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_pending_mls_status ON pending_mls_messages(conversation_id, status)")
        .execute(db)
        .await?;

    // Group welcomes index
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_group_welcomes_pending ON group_welcomes(processed, received_at)")
        .execute(db)
        .await?;

    // Key packages index
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_key_packages_unused ON key_packages(used, created_at)")
        .execute(db)
        .await?;

    // Group members index
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_group_members_conv ON group_members(conversation_id)")
        .execute(db)
        .await?;

    // Group invites index
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_group_invites_status ON group_invites(status)")
        .execute(db)
        .await?;

    // Join requests index
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_join_requests_group ON join_requests(group_id, status)")
        .execute(db)
        .await?;

    // Group memberships index
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_group_memberships_user ON group_memberships(username)")
        .execute(db)
        .await?;

    // Group cursors index
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_group_cursors_user ON group_cursors(username)")
        .execute(db)
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_migrations_run_successfully() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        run_migrations(&pool).await.unwrap();

        // Verify tables exist by querying them
        let _: Vec<(String,)> = sqlx::query_as("SELECT username FROM users LIMIT 1")
            .fetch_all(&pool)
            .await
            .unwrap();

        let _: Vec<(String,)> = sqlx::query_as("SELECT server_address FROM group_memberships LIMIT 1")
            .fetch_all(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_migrations_are_idempotent() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();

        // Run migrations twice - should not fail
        run_migrations(&pool).await.unwrap();
        run_migrations(&pool).await.unwrap();
    }
}
