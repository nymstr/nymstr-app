//! Database setup utilities for testing
//!
//! Provides helpers for creating isolated test databases with proper schema.

use anyhow::Result;
use sqlx::SqlitePool;

use crate::core::db::schema::run_migrations;

/// Create an in-memory SQLite database for testing with full schema
pub async fn create_test_db() -> Result<SqlitePool> {
    let pool = SqlitePool::connect("sqlite::memory:").await?;
    run_migrations(&pool).await?;
    Ok(pool)
}

/// Create a file-based SQLite database for testing (useful for inspection)
pub async fn create_test_db_file(path: &str) -> Result<SqlitePool> {
    // Ensure the database file is fresh
    if std::path::Path::new(path).exists() {
        std::fs::remove_file(path)?;
    }

    let pool = SqlitePool::connect(&format!("sqlite:{}", path)).await?;
    run_migrations(&pool).await?;
    Ok(pool)
}

/// Create a test database using tempfile (automatically cleaned up)
pub async fn create_temp_test_db() -> Result<(SqlitePool, tempfile::TempDir)> {
    let temp_dir = tempfile::tempdir()?;
    let db_path = temp_dir.path().join("test.db");
    // Use create_if_missing=true to ensure file is created
    let pool = SqlitePool::connect(&format!("sqlite:{}?mode=rwc", db_path.display())).await?;
    run_migrations(&pool).await?;
    Ok((pool, temp_dir))
}

/// Seed a test database with sample users
pub async fn seed_test_users(pool: &SqlitePool, users: &[(&str, &str)]) -> Result<()> {
    for (username, public_key) in users {
        sqlx::query(
            r#"
            INSERT INTO users (username, display_name, public_key)
            VALUES (?, ?, ?)
            ON CONFLICT(username) DO NOTHING
            "#,
        )
        .bind(username)
        .bind(username) // display_name same as username for tests
        .bind(public_key)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Seed a test database with contacts for a user
pub async fn seed_test_contacts(
    pool: &SqlitePool,
    owner: &str,
    contacts: &[(&str, &str)],
) -> Result<()> {
    for (username, public_key) in contacts {
        sqlx::query(
            r#"
            INSERT INTO contacts (owner_username, username, display_name, public_key)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(owner_username, username) DO NOTHING
            "#,
        )
        .bind(owner)
        .bind(username)
        .bind(username)
        .bind(public_key)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Seed a test database with pending MLS messages
pub async fn seed_pending_mls_messages(
    pool: &SqlitePool,
    messages: &[(&str, &str, &str)], // (conversation_id, sender, mls_message_b64)
) -> Result<()> {
    for (conv_id, sender, mls_message_b64) in messages {
        sqlx::query(
            r#"
            INSERT INTO pending_mls_messages (conversation_id, sender, mls_message_b64, received_at, retry_count, processed, failed)
            VALUES (?, ?, ?, datetime('now'), 0, 0, 0)
            "#,
        )
        .bind(conv_id)
        .bind(sender)
        .bind(mls_message_b64)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Seed a test database with group memberships
pub async fn seed_group_memberships(
    pool: &SqlitePool,
    memberships: &[(&str, &str, Option<&str>, &str)], // (server_address, username, mls_group_id, role)
) -> Result<()> {
    for (server_address, username, mls_group_id, role) in memberships {
        sqlx::query(
            r#"
            INSERT INTO group_memberships (server_address, username, mls_group_id, role)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(server_address, username) DO NOTHING
            "#,
        )
        .bind(server_address)
        .bind(username)
        .bind(mls_group_id)
        .bind(role)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Seed a test database with pending welcomes
pub async fn seed_pending_welcomes(
    pool: &SqlitePool,
    welcomes: &[(&str, &str, &str, u16, u64)], // (group_id, sender, welcome_bytes, cipher_suite, epoch)
) -> Result<()> {
    for (group_id, sender, welcome_bytes, cipher_suite, epoch) in welcomes {
        sqlx::query(
            r#"
            INSERT INTO pending_welcomes (group_id, sender, welcome_bytes, cipher_suite, epoch, received_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
            "#,
        )
        .bind(group_id)
        .bind(sender)
        .bind(welcome_bytes)
        .bind(cipher_suite)
        .bind(*epoch as i64)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Get the count of pending messages for a conversation
pub async fn count_pending_messages(pool: &SqlitePool, conv_id: &str) -> Result<i64> {
    let result: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM pending_mls_messages WHERE conversation_id = ? AND processed = 0 AND failed = 0",
    )
    .bind(conv_id)
    .fetch_one(pool)
    .await?;
    Ok(result.0)
}

/// Get the count of processed messages for a conversation
pub async fn count_processed_messages(pool: &SqlitePool, conv_id: &str) -> Result<i64> {
    let result: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM pending_mls_messages WHERE conversation_id = ? AND processed = 1",
    )
    .bind(conv_id)
    .fetch_one(pool)
    .await?;
    Ok(result.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_test_db() {
        let pool = create_test_db().await.unwrap();

        // Verify tables exist
        let _: Vec<(String,)> = sqlx::query_as("SELECT username FROM users LIMIT 1")
            .fetch_all(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_seed_test_users() {
        let pool = create_test_db().await.unwrap();

        seed_test_users(&pool, &[("alice", "pk_alice"), ("bob", "pk_bob")])
            .await
            .unwrap();

        let users: Vec<(String,)> = sqlx::query_as("SELECT username FROM users ORDER BY username")
            .fetch_all(&pool)
            .await
            .unwrap();

        assert_eq!(users.len(), 2);
        assert_eq!(users[0].0, "alice");
        assert_eq!(users[1].0, "bob");
    }

    #[tokio::test]
    async fn test_seed_pending_mls_messages() {
        let pool = create_test_db().await.unwrap();

        seed_pending_mls_messages(
            &pool,
            &[("conv1", "alice", "msg1"), ("conv1", "bob", "msg2")],
        )
        .await
        .unwrap();

        let count = count_pending_messages(&pool, "conv1").await.unwrap();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn test_temp_db_cleanup() {
        let (pool, temp_dir) = create_temp_test_db().await.unwrap();
        let temp_dir_path = temp_dir.path().to_path_buf();

        // Database should exist
        assert!(temp_dir_path.join("test.db").exists());

        // Can use the pool
        seed_test_users(&pool, &[("test", "pk_test")]).await.unwrap();

        // Verify the user was inserted
        let users: Vec<(String,)> =
            sqlx::query_as("SELECT username FROM users").fetch_all(&pool).await.unwrap();
        assert_eq!(users.len(), 1);

        // temp_dir will be cleaned up when this function returns
        // Note: We keep temp_dir in scope until the end to ensure the database connection works
    }
}
