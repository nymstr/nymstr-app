//! User-related database operations
//!
//! This module contains methods for user registration, management, and retrieval.

use anyhow::Result;
use sqlx::{Row, SqlitePool};

use crate::types::UserDTO;

/// User database operations
pub struct UserDb;

impl UserDb {
    /// Save or update a user in the database
    pub async fn save_user(pool: &SqlitePool, user: &UserDTO) -> Result<()> {
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO users (username, display_name, public_key)
            VALUES (?, ?, ?)
            "#,
        )
        .bind(&user.username)
        .bind(&user.display_name)
        .bind(&user.public_key)
        .execute(pool)
        .await?;

        tracing::debug!("Saved user: {}", user.username);
        Ok(())
    }

    /// Get a user by username
    pub async fn get_user(pool: &SqlitePool, username: &str) -> Result<Option<UserDTO>> {
        let row = sqlx::query(
            r#"SELECT username, display_name, public_key FROM users WHERE username = ?"#,
        )
        .bind(username)
        .fetch_optional(pool)
        .await?;

        match row {
            Some(r) => Ok(Some(UserDTO {
                username: r.try_get("username")?,
                display_name: r.try_get("display_name")?,
                public_key: r.try_get("public_key")?,
                online: false, // Will be updated by connection status
            })),
            None => Ok(None),
        }
    }

    /// Get all registered users
    pub async fn get_all_users(pool: &SqlitePool) -> Result<Vec<UserDTO>> {
        let rows = sqlx::query(r#"SELECT username, display_name, public_key FROM users"#)
            .fetch_all(pool)
            .await?;

        let mut users = Vec::new();
        for r in rows {
            users.push(UserDTO {
                username: r.try_get("username")?,
                display_name: r.try_get("display_name")?,
                public_key: r.try_get("public_key")?,
                online: false,
            });
        }
        Ok(users)
    }

    /// Delete a user by username
    #[allow(dead_code)]
    pub async fn delete_user(pool: &SqlitePool, username: &str) -> Result<()> {
        sqlx::query("DELETE FROM users WHERE username = ?")
            .bind(username)
            .execute(pool)
            .await?;

        tracing::debug!("Deleted user: {}", username);
        Ok(())
    }

    /// Check if a user exists
    pub async fn user_exists(pool: &SqlitePool, username: &str) -> Result<bool> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT COUNT(*) FROM users WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|(count,)| count > 0).unwrap_or(false))
    }

    /// Get the first registered user (for auto-login scenarios)
    pub async fn get_first_user(pool: &SqlitePool) -> Result<Option<UserDTO>> {
        let row = sqlx::query(
            r#"SELECT username, display_name, public_key FROM users LIMIT 1"#,
        )
        .fetch_optional(pool)
        .await?;

        match row {
            Some(r) => Ok(Some(UserDTO {
                username: r.try_get("username")?,
                display_name: r.try_get("display_name")?,
                public_key: r.try_get("public_key")?,
                online: false,
            })),
            None => Ok(None),
        }
    }

    /// Update user's display name
    #[allow(dead_code)]
    pub async fn update_display_name(
        pool: &SqlitePool,
        username: &str,
        display_name: &str,
    ) -> Result<()> {
        sqlx::query("UPDATE users SET display_name = ? WHERE username = ?")
            .bind(display_name)
            .bind(username)
            .execute(pool)
            .await?;

        tracing::debug!("Updated display name for user: {}", username);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    async fn setup_test_db() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
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
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[tokio::test]
    async fn test_save_and_get_user() {
        let pool = setup_test_db().await;
        let user = UserDTO {
            username: "alice".to_string(),
            display_name: "Alice".to_string(),
            public_key: "pk_alice".to_string(),
            online: false,
        };

        UserDb::save_user(&pool, &user).await.unwrap();
        let retrieved = UserDb::get_user(&pool, "alice").await.unwrap();

        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.username, "alice");
        assert_eq!(retrieved.display_name, "Alice");
        assert_eq!(retrieved.public_key, "pk_alice");
    }

    #[tokio::test]
    async fn test_user_exists() {
        let pool = setup_test_db().await;
        let user = UserDTO {
            username: "bob".to_string(),
            display_name: "Bob".to_string(),
            public_key: "pk_bob".to_string(),
            online: false,
        };

        assert!(!UserDb::user_exists(&pool, "bob").await.unwrap());
        UserDb::save_user(&pool, &user).await.unwrap();
        assert!(UserDb::user_exists(&pool, "bob").await.unwrap());
    }
}
