//! SQLite persistence using the schema from dbUtils.py
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool, sqlite::SqlitePoolOptions};
use std::{fs, path::Path};

/// Get the full path for an MLS database file in the storage directory
pub fn get_mls_db_path(username: &str) -> String {
    format!("storage/nymstr_mls_{}.db", username)
}

/// SQLite-backed database.
#[derive(Debug)]
pub struct Db {
    pool: SqlitePool,
}

impl Db {
    /// Open or create a database at the given path.
    pub async fn open(path: &str) -> Result<Self> {
        // ensure parent directories exist so SQLite can create/open the file
        if let Some(dir) = Path::new(path).parent() {
            fs::create_dir_all(dir)?;
        }
        let url = format!("sqlite://{}?mode=rwc", path);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await?;
        Ok(Db { pool })
    }

    /// Create global tables (users).
    pub async fn init_global(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                public_key TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Create per-user tables (contacts, messages, and MLS groups).
    pub async fn init_user(&self, username: &str) -> Result<()> {
        let contacts_table = format!("contacts_{}", username);
        let messages_table = format!("messages_{}", username);
        let mls_groups_table = format!("mls_groups_{}", username);

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

    /// Add or update a contact for the given user.
    pub async fn add_contact(&self, me: &str, user: &str, public_key: &str) -> Result<()> {
        let table = format!("contacts_{}", me);
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
    pub async fn get_contact(&self, me: &str, user: &str) -> Result<Option<(String, String)>> {
        let table = format!("contacts_{}", me);
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

    /// Save a message (to/from) for the given user.
    pub async fn save_message(
        &self,
        me: &str,
        contact: &str,
        sent: bool,
        text: &str,
        ts: DateTime<Utc>,
    ) -> Result<()> {
        let table = format!("messages_{}", me);
        let msg_type = if sent { "to" } else { "from" };
        sqlx::query(&format!(
            r#"
            INSERT INTO {table} (username, type, message, timestamp)
            VALUES (?, ?, ?, ?)
            "#,
            table = table
        ))
        .bind(contact)
        .bind(msg_type)
        .bind(text)
        .bind(ts)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Load all contacts for the given user.
    pub async fn load_contacts(&self, me: &str) -> Result<Vec<(String, String)>> {
        let table = format!("contacts_{}", me);
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

    /// Load all messages exchanged with a contact for the given user.
    pub async fn load_messages(
        &self,
        me: &str,
        contact: &str,
    ) -> Result<Vec<(bool, String, DateTime<Utc>)>> {
        let table = format!("messages_{}", me);
        let rows = sqlx::query(&format!(
            r#"
            SELECT type, message, timestamp
            FROM {table}
            WHERE username = ?
            ORDER BY timestamp ASC
            "#,
            table = table
        ))
        .bind(contact)
        .fetch_all(&self.pool)
        .await?;
        let mut msgs = Vec::new();
        for row in rows {
            let t: String = row.try_get("type")?;
            let sent = t == "to";
            let msg: String = row.try_get("message")?;
            let ts: DateTime<Utc> = row.try_get("timestamp")?;
            msgs.push((sent, msg, ts));
        }
        Ok(msgs)
    }

    /// Delete a contact for the specified user.
    pub async fn delete_contact(&self, me: &str, user: &str) -> Result<()> {
        let table = format!("contacts_{}", me);
        sqlx::query(&format!(
            "DELETE FROM {table} WHERE username = ?",
            table = table
        ))
        .bind(user)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete all messages for the specified user.
    pub async fn delete_all_messages(&self, me: &str) -> Result<()> {
        let table = format!("messages_{}", me);
        sqlx::query(&format!("DELETE FROM {table}", table = table))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Retrieve all registered users.
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

    /// Retrieve all messages for the specified user.
    pub async fn get_all_messages(
        &self,
        me: &str,
    ) -> Result<Vec<(String, String, String, DateTime<Utc>)>> {
        let table = format!("messages_{}", me);
        let query = format!(
            "SELECT username, type, message, timestamp FROM {table} ORDER BY username, timestamp ASC",
            table = table
        );
        let rows = sqlx::query(&query).fetch_all(&self.pool).await?;
        let mut msgs = Vec::new();
        for row in rows {
            let username: String = row.try_get("username")?;
            let msg_type: String = row.try_get("type")?;
            let message: String = row.try_get("message")?;
            let ts: DateTime<Utc> = row.try_get("timestamp")?;
            msgs.push((username, msg_type, message, ts));
        }
        Ok(msgs)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[tokio::test]
    async fn test_register_and_get_user() -> Result<()> {
        let db = Db::open(":memory:").await?;
        db.init_global().await?;
        db.register_user("alice", "pk_alice").await?;
        let user = db.get_user("alice").await?;
        assert_eq!(user, Some(("alice".to_string(), "pk_alice".to_string())));
        Ok(())
    }

    #[tokio::test]
    async fn test_contact_and_messages_flow() -> Result<()> {
        let db = Db::open(":memory:").await?;
        db.init_global().await?;
        db.init_user("bob").await?;
        db.add_contact("bob", "alice", "pk1").await?;
        let ct = db.get_contact("bob", "alice").await?;
        assert_eq!(ct, Some(("alice".to_string(), "pk1".to_string())));

        let ts = Utc::now();
        db.save_message("bob", "alice", true, "hello", ts).await?;
        let msgs = db.load_messages("bob", "alice").await?;
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].0, true);
        assert_eq!(msgs[0].1, "hello".to_string());
        Ok(())
    }

    #[tokio::test]
    async fn test_delete_contact_and_messages() -> Result<()> {
        let db = Db::open(":memory:").await?;
        db.init_global().await?;
        db.init_user("bob").await?;
        db.add_contact("bob", "alice", "pk1").await?;
        db.delete_contact("bob", "alice").await?;
        assert!(db.get_contact("bob", "alice").await?.is_none());

        let ts = Utc::now();
        db.save_message("bob", "alice", false, "hey", ts).await?;
        db.delete_all_messages("bob").await?;
        let msgs = db.load_messages("bob", "alice").await?;
        assert!(msgs.is_empty());
        Ok(())
    }
}
