//! Contact-related database operations
//!
//! This module contains methods for managing contacts.

use anyhow::Result;
use sqlx::{Row, SqlitePool};

use crate::types::ContactDTO;

/// Contact database operations
pub struct ContactDb;

impl ContactDb {
    /// Save or update a contact in the database
    pub async fn save_contact(pool: &SqlitePool, contact: &ContactDTO) -> Result<()> {
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO contacts (username, display_name, public_key, last_seen)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(&contact.username)
        .bind(&contact.display_name)
        .bind("") // We don't store public_key in ContactDTO, use empty string
        .bind(&contact.last_seen)
        .execute(pool)
        .await?;

        tracing::debug!("Saved contact: {}", contact.username);
        Ok(())
    }

    /// Save a contact with public key
    pub async fn save_contact_with_key(
        pool: &SqlitePool,
        username: &str,
        display_name: &str,
        public_key: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO contacts (username, display_name, public_key)
            VALUES (?, ?, ?)
            "#,
        )
        .bind(username)
        .bind(display_name)
        .bind(public_key)
        .execute(pool)
        .await?;

        tracing::debug!("Saved contact with key: {}", username);
        Ok(())
    }

    /// Get a contact by username
    pub async fn get_contact(pool: &SqlitePool, username: &str) -> Result<Option<ContactDTO>> {
        let row = sqlx::query(
            r#"SELECT username, display_name, public_key, last_seen FROM contacts WHERE username = ?"#,
        )
        .bind(username)
        .fetch_optional(pool)
        .await?;

        match row {
            Some(r) => Ok(Some(ContactDTO {
                username: r.try_get("username")?,
                display_name: r.try_get("display_name")?,
                avatar_url: None,
                last_seen: r.try_get("last_seen")?,
                unread_count: 0,
                online: false,
            })),
            None => Ok(None),
        }
    }

    /// Get all contacts
    pub async fn get_contacts(pool: &SqlitePool) -> Result<Vec<ContactDTO>> {
        let rows = sqlx::query(
            r#"SELECT username, display_name, public_key, last_seen FROM contacts ORDER BY display_name"#,
        )
        .fetch_all(pool)
        .await?;

        let mut contacts = Vec::new();
        for r in rows {
            contacts.push(ContactDTO {
                username: r.try_get("username")?,
                display_name: r.try_get("display_name")?,
                avatar_url: None,
                last_seen: r.try_get("last_seen")?,
                unread_count: 0,
                online: false,
            });
        }
        Ok(contacts)
    }

    /// Get contact's public key
    pub async fn get_contact_public_key(
        pool: &SqlitePool,
        username: &str,
    ) -> Result<Option<String>> {
        let row = sqlx::query("SELECT public_key FROM contacts WHERE username = ?")
            .bind(username)
            .fetch_optional(pool)
            .await?;

        match row {
            Some(r) => Ok(r.try_get("public_key")?),
            None => Ok(None),
        }
    }

    /// Remove a contact by username
    pub async fn remove_contact(pool: &SqlitePool, username: &str) -> Result<()> {
        sqlx::query("DELETE FROM contacts WHERE username = ?")
            .bind(username)
            .execute(pool)
            .await?;

        tracing::debug!("Removed contact: {}", username);
        Ok(())
    }

    /// Update contact's last seen timestamp
    pub async fn update_last_seen(pool: &SqlitePool, username: &str, last_seen: &str) -> Result<()> {
        sqlx::query("UPDATE contacts SET last_seen = ? WHERE username = ?")
            .bind(last_seen)
            .bind(username)
            .execute(pool)
            .await?;

        Ok(())
    }

    /// Check if a contact exists
    #[allow(dead_code)]
    pub async fn contact_exists(pool: &SqlitePool, username: &str) -> Result<bool> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT COUNT(*) FROM contacts WHERE username = ?")
                .bind(username)
                .fetch_optional(pool)
                .await?;

        Ok(row.map(|(count,)| count > 0).unwrap_or(false))
    }

    /// Get contact count
    #[allow(dead_code)]
    pub async fn get_contact_count(pool: &SqlitePool) -> Result<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM contacts")
            .fetch_one(pool)
            .await?;

        Ok(row.0)
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
            CREATE TABLE IF NOT EXISTS contacts (
                username TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                public_key TEXT NOT NULL,
                last_seen TEXT,
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
    async fn test_save_and_get_contact() {
        let pool = setup_test_db().await;

        ContactDb::save_contact_with_key(&pool, "alice", "Alice", "pk_alice")
            .await
            .unwrap();

        let contact = ContactDb::get_contact(&pool, "alice").await.unwrap();
        assert!(contact.is_some());
        let contact = contact.unwrap();
        assert_eq!(contact.username, "alice");
        assert_eq!(contact.display_name, "Alice");
    }

    #[tokio::test]
    async fn test_remove_contact() {
        let pool = setup_test_db().await;

        ContactDb::save_contact_with_key(&pool, "bob", "Bob", "pk_bob")
            .await
            .unwrap();
        assert!(ContactDb::contact_exists(&pool, "bob").await.unwrap());

        ContactDb::remove_contact(&pool, "bob").await.unwrap();
        assert!(!ContactDb::contact_exists(&pool, "bob").await.unwrap());
    }

    #[tokio::test]
    async fn test_get_contacts() {
        let pool = setup_test_db().await;

        ContactDb::save_contact_with_key(&pool, "alice", "Alice", "pk_alice")
            .await
            .unwrap();
        ContactDb::save_contact_with_key(&pool, "bob", "Bob", "pk_bob")
            .await
            .unwrap();

        let contacts = ContactDb::get_contacts(&pool).await.unwrap();
        assert_eq!(contacts.len(), 2);
    }
}
