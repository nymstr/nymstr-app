//! Contact-related database operations
//!
//! This module contains methods for managing contacts.

use super::{Db, sanitize_table_name};
use anyhow::Result;
use sqlx::Row;

impl Db {
    /// Add or update a contact for the given user.
    pub async fn add_contact(&self, me: &str, user: &str, public_key: &str) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("contacts_{}", safe_name);
        sqlx::query(&format!(
            r#"INSERT OR REPLACE INTO {table} (username, public_key) VALUES (?, ?)"#,
            table = table
        ))
        .bind(user)
        .bind(public_key)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Get a contact's public key for the given user.
    #[allow(dead_code)] // Part of public API for contact management
    pub async fn get_contact(&self, me: &str, user: &str) -> Result<Option<(String, String)>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("contacts_{}", safe_name);
        if let Some(row) = sqlx::query(&format!(
            r#"SELECT username, public_key FROM {table} WHERE username = ?"#,
            table = table
        ))
        .bind(user)
        .fetch_optional(&self.pool)
        .await?
        {
            let name: String = row.try_get("username")?;
            let pk: String = row.try_get("public_key")?;
            Ok(Some((name, pk)))
        } else {
            Ok(None)
        }
    }

    /// Load all contacts for the given user.
    pub async fn load_contacts(&self, me: &str) -> Result<Vec<(String, String)>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("contacts_{}", safe_name);
        let rows = sqlx::query(&format!(
            r#"SELECT username, public_key FROM {table}"#,
            table = table
        ))
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

    /// Delete a contact for the specified user.
    #[allow(dead_code)] // Part of public API for contact management
    pub async fn delete_contact(&self, me: &str, user: &str) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("contacts_{}", safe_name);
        sqlx::query(&format!(
            "DELETE FROM {table} WHERE username = ?",
            table = table
        ))
        .bind(user)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
