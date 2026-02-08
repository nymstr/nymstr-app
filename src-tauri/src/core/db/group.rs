//! Group-related database operations
//!
//! This module contains methods for managing group memberships, group servers,
//! group invites, and join requests.

use anyhow::Result;
use sqlx::{Row, SqlitePool};

/// Represents a group member with verification status
#[derive(Debug, Clone)]
pub struct GroupMember {
    pub username: String,
    pub credential_fingerprint: Option<String>,
    pub credential_verified: bool,
    pub verified_at: Option<String>,
    pub joined_at: String,
    pub role: String,
}

/// Represents a group server (server address to MLS group mapping)
#[derive(Debug, Clone)]
pub struct GroupServer {
    pub server_address: String,
    pub mls_group_id: Option<String>,
    pub group_name: Option<String>,
    pub joined_at: String,
}

/// Represents a user's membership in a group (per-user scoped)
#[derive(Debug, Clone)]
pub struct GroupMembership {
    pub id: i64,
    pub server_address: String,
    pub username: String,
    pub mls_group_id: Option<String>,
    pub joined_at: String,
    pub role: String,
}

/// Represents a group cursor for message fetching
#[derive(Debug, Clone)]
pub struct GroupCursor {
    pub server_address: String,
    pub username: String,
    pub last_message_id: i64,
    pub updated_at: String,
}

/// Group database operations
pub struct GroupDb;

impl GroupDb {
    // ========== Group Membership ==========

    /// Add a member to a group
    pub async fn add_member(
        pool: &SqlitePool,
        conversation_id: &str,
        member_username: &str,
        credential_fingerprint: Option<&str>,
        credential_verified: bool,
        role: &str,
    ) -> Result<()> {
        let verified_at: Option<String> = if credential_verified {
            Some(chrono::Utc::now().to_rfc3339())
        } else {
            None
        };

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO group_members
            (conversation_id, member_username, credential_fingerprint, credential_verified, verified_at, role)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(conversation_id)
        .bind(member_username)
        .bind(credential_fingerprint)
        .bind(credential_verified)
        .bind(&verified_at)
        .bind(role)
        .execute(pool)
        .await?;

        tracing::debug!(
            "Added group membership: {} in {} (verified: {})",
            member_username,
            conversation_id,
            credential_verified
        );
        Ok(())
    }

    /// Get all members of a group
    pub async fn get_members(
        pool: &SqlitePool,
        conversation_id: &str,
    ) -> Result<Vec<GroupMember>> {
        let rows = sqlx::query(
            r#"
            SELECT member_username, credential_fingerprint, credential_verified, verified_at, joined_at, role
            FROM group_members
            WHERE conversation_id = ?
            ORDER BY joined_at ASC
            "#,
        )
        .bind(conversation_id)
        .fetch_all(pool)
        .await?;

        let mut members = Vec::new();
        for r in rows {
            members.push(GroupMember {
                username: r.try_get("member_username")?,
                credential_fingerprint: r.try_get("credential_fingerprint")?,
                credential_verified: r.try_get("credential_verified")?,
                verified_at: r.try_get("verified_at")?,
                joined_at: r.try_get("joined_at")?,
                role: r.try_get("role")?,
            });
        }
        Ok(members)
    }

    /// Update credential verification status for a member
    #[allow(dead_code)]
    pub async fn update_member_verification(
        pool: &SqlitePool,
        conversation_id: &str,
        member_username: &str,
        verified: bool,
        fingerprint: Option<&str>,
    ) -> Result<()> {
        let verified_at: Option<String> = if verified {
            Some(chrono::Utc::now().to_rfc3339())
        } else {
            None
        };

        sqlx::query(
            r#"
            UPDATE group_members
            SET credential_verified = ?, verified_at = ?, credential_fingerprint = ?
            WHERE conversation_id = ? AND member_username = ?
            "#,
        )
        .bind(verified)
        .bind(&verified_at)
        .bind(fingerprint)
        .bind(conversation_id)
        .bind(member_username)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Remove a member from a group
    #[allow(dead_code)]
    pub async fn remove_member(
        pool: &SqlitePool,
        conversation_id: &str,
        member_username: &str,
    ) -> Result<()> {
        sqlx::query(
            "DELETE FROM group_members WHERE conversation_id = ? AND member_username = ?",
        )
        .bind(conversation_id)
        .bind(member_username)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Get all groups a user is a member of
    #[allow(dead_code)]
    pub async fn get_user_groups(pool: &SqlitePool) -> Result<Vec<String>> {
        let rows = sqlx::query("SELECT DISTINCT conversation_id FROM group_members")
            .fetch_all(pool)
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| r.try_get("conversation_id").unwrap())
            .collect())
    }

    // ========== Group Server Operations ==========

    /// Save a group server mapping
    pub async fn save_group_server(pool: &SqlitePool, server: &GroupServer) -> Result<()> {
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO group_servers
            (server_address, mls_group_id, group_name, joined_at)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(&server.server_address)
        .bind(&server.mls_group_id)
        .bind(&server.group_name)
        .bind(&server.joined_at)
        .execute(pool)
        .await?;

        tracing::debug!("Saved group server: {}", server.server_address);
        Ok(())
    }

    /// Get all group servers
    pub async fn get_group_servers(pool: &SqlitePool) -> Result<Vec<GroupServer>> {
        let rows = sqlx::query(
            r#"
            SELECT server_address, mls_group_id, group_name, joined_at
            FROM group_servers
            ORDER BY joined_at DESC
            "#,
        )
        .fetch_all(pool)
        .await?;

        let mut servers = Vec::new();
        for r in rows {
            servers.push(GroupServer {
                server_address: r.try_get("server_address")?,
                mls_group_id: r.try_get("mls_group_id")?,
                group_name: r.try_get("group_name")?,
                joined_at: r.try_get("joined_at")?,
            });
        }
        Ok(servers)
    }

    /// Get a group server by address
    pub async fn get_group_server(
        pool: &SqlitePool,
        server_address: &str,
    ) -> Result<Option<GroupServer>> {
        let row = sqlx::query(
            r#"
            SELECT server_address, mls_group_id, group_name, joined_at
            FROM group_servers
            WHERE server_address = ?
            "#,
        )
        .bind(server_address)
        .fetch_optional(pool)
        .await?;

        match row {
            Some(r) => Ok(Some(GroupServer {
                server_address: r.try_get("server_address")?,
                mls_group_id: r.try_get("mls_group_id")?,
                group_name: r.try_get("group_name")?,
                joined_at: r.try_get("joined_at")?,
            })),
            None => Ok(None),
        }
    }

    /// Get MLS group ID by server address
    pub async fn get_mls_group_id_by_server(
        pool: &SqlitePool,
        server_address: &str,
    ) -> Result<Option<String>> {
        let row = sqlx::query("SELECT mls_group_id FROM group_servers WHERE server_address = ?")
            .bind(server_address)
            .fetch_optional(pool)
            .await?;

        match row {
            Some(r) => Ok(r.try_get("mls_group_id")?),
            None => Ok(None),
        }
    }

    /// Get server address by MLS group ID
    pub async fn get_server_address_by_group_id(
        pool: &SqlitePool,
        mls_group_id: &str,
    ) -> Result<Option<String>> {
        let row = sqlx::query("SELECT server_address FROM group_servers WHERE mls_group_id = ?")
            .bind(mls_group_id)
            .fetch_optional(pool)
            .await?;

        match row {
            Some(r) => Ok(r.try_get("server_address")?),
            None => Ok(None),
        }
    }

    /// Delete a group server
    #[allow(dead_code)]
    pub async fn delete_group_server(pool: &SqlitePool, server_address: &str) -> Result<()> {
        sqlx::query("DELETE FROM group_servers WHERE server_address = ?")
            .bind(server_address)
            .execute(pool)
            .await?;

        Ok(())
    }

    // ========== Group Memberships (Per-User Scoped) ==========

    /// Add or update a group membership for a user
    pub async fn add_group_membership(
        pool: &SqlitePool,
        server_address: &str,
        username: &str,
        mls_group_id: Option<&str>,
        role: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO group_memberships (server_address, username, mls_group_id, role)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(server_address)
        .bind(username)
        .bind(mls_group_id)
        .bind(role)
        .execute(pool)
        .await?;

        tracing::debug!(
            "Added group membership: {} joined {} as {}",
            username,
            server_address,
            role
        );
        Ok(())
    }

    /// Get a group membership for a user
    pub async fn get_group_membership(
        pool: &SqlitePool,
        server_address: &str,
        username: &str,
    ) -> Result<Option<GroupMembership>> {
        let row = sqlx::query(
            r#"
            SELECT id, server_address, username, mls_group_id, joined_at, role
            FROM group_memberships
            WHERE server_address = ? AND username = ?
            "#,
        )
        .bind(server_address)
        .bind(username)
        .fetch_optional(pool)
        .await?;

        match row {
            Some(r) => Ok(Some(GroupMembership {
                id: r.try_get("id")?,
                server_address: r.try_get("server_address")?,
                username: r.try_get("username")?,
                mls_group_id: r.try_get("mls_group_id")?,
                joined_at: r.try_get("joined_at")?,
                role: r.try_get("role")?,
            })),
            None => Ok(None),
        }
    }

    /// Get all group memberships for a user
    pub async fn get_user_memberships(
        pool: &SqlitePool,
        username: &str,
    ) -> Result<Vec<GroupMembership>> {
        let rows = sqlx::query(
            r#"
            SELECT id, server_address, username, mls_group_id, joined_at, role
            FROM group_memberships
            WHERE username = ?
            ORDER BY joined_at DESC
            "#,
        )
        .bind(username)
        .fetch_all(pool)
        .await?;

        let mut memberships = Vec::new();
        for r in rows {
            memberships.push(GroupMembership {
                id: r.try_get("id")?,
                server_address: r.try_get("server_address")?,
                username: r.try_get("username")?,
                mls_group_id: r.try_get("mls_group_id")?,
                joined_at: r.try_get("joined_at")?,
                role: r.try_get("role")?,
            });
        }
        Ok(memberships)
    }

    /// Get MLS group ID for a user's membership
    pub async fn get_membership_mls_group_id(
        pool: &SqlitePool,
        server_address: &str,
        username: &str,
    ) -> Result<Option<String>> {
        let row: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT mls_group_id FROM group_memberships WHERE server_address = ? AND username = ?",
        )
        .bind(server_address)
        .bind(username)
        .fetch_optional(pool)
        .await?;

        Ok(row.and_then(|(id,)| id))
    }

    /// Update MLS group ID for a user's membership
    pub async fn update_membership_mls_group_id(
        pool: &SqlitePool,
        server_address: &str,
        username: &str,
        mls_group_id: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE group_memberships SET mls_group_id = ? WHERE server_address = ? AND username = ?",
        )
        .bind(mls_group_id)
        .bind(server_address)
        .bind(username)
        .execute(pool)
        .await?;

        tracing::debug!(
            "Updated MLS group ID for {} at {}: {}",
            username,
            server_address,
            mls_group_id
        );
        Ok(())
    }

    /// Remove a group membership for a user
    pub async fn remove_group_membership(
        pool: &SqlitePool,
        server_address: &str,
        username: &str,
    ) -> Result<()> {
        sqlx::query("DELETE FROM group_memberships WHERE server_address = ? AND username = ?")
            .bind(server_address)
            .bind(username)
            .execute(pool)
            .await?;

        tracing::debug!("Removed group membership: {} from {}", username, server_address);
        Ok(())
    }

    // ========== Group Cursors (Per-User Scoped) ==========

    /// Get the message cursor for a user's group
    pub async fn get_group_cursor_for_user(
        pool: &SqlitePool,
        server_address: &str,
        username: &str,
    ) -> Result<i64> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT last_message_id FROM group_cursors WHERE server_address = ? AND username = ?",
        )
        .bind(server_address)
        .bind(username)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|(id,)| id).unwrap_or(0))
    }

    /// Update the message cursor for a user's group
    pub async fn update_group_cursor_for_user(
        pool: &SqlitePool,
        server_address: &str,
        username: &str,
        last_message_id: i64,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO group_cursors (server_address, username, last_message_id, updated_at)
            VALUES (?, ?, ?, datetime('now'))
            "#,
        )
        .bind(server_address)
        .bind(username)
        .bind(last_message_id)
        .execute(pool)
        .await?;

        tracing::debug!(
            "Updated cursor for {} at {}: {}",
            username,
            server_address,
            last_message_id
        );
        Ok(())
    }

    /// Remove cursor for a user's group
    pub async fn remove_group_cursor_for_user(
        pool: &SqlitePool,
        server_address: &str,
        username: &str,
    ) -> Result<()> {
        sqlx::query("DELETE FROM group_cursors WHERE server_address = ? AND username = ?")
            .bind(server_address)
            .bind(username)
            .execute(pool)
            .await?;

        Ok(())
    }

    // ========== Group Invites ==========

    /// Store an incoming group invite
    pub async fn store_invite(
        pool: &SqlitePool,
        group_id: &str,
        group_name: Option<&str>,
        sender: &str,
    ) -> Result<i64> {
        let result = sqlx::query(
            r#"
            INSERT INTO group_invites (group_id, group_name, sender)
            VALUES (?, ?, ?)
            "#,
        )
        .bind(group_id)
        .bind(group_name)
        .bind(sender)
        .execute(pool)
        .await?;

        let id = result.last_insert_rowid();
        tracing::debug!(
            "Stored group invite {} from {} for group {}",
            id,
            sender,
            group_id
        );
        Ok(id)
    }

    /// Get pending group invites
    pub async fn get_pending_invites(
        pool: &SqlitePool,
    ) -> Result<Vec<(i64, String, Option<String>, String, String)>> {
        let rows = sqlx::query(
            r#"
            SELECT id, group_id, group_name, sender, received_at
            FROM group_invites
            WHERE status = 'pending'
            ORDER BY received_at DESC
            "#,
        )
        .fetch_all(pool)
        .await?;

        let mut invites = Vec::new();
        for r in rows {
            invites.push((
                r.try_get::<i64, _>("id")?,
                r.try_get::<String, _>("group_id")?,
                r.try_get::<Option<String>, _>("group_name")?,
                r.try_get::<String, _>("sender")?,
                r.try_get::<String, _>("received_at")?,
            ));
        }
        Ok(invites)
    }

    /// Update invite status (accepted/rejected)
    pub async fn update_invite_status(pool: &SqlitePool, invite_id: i64, status: &str) -> Result<()> {
        sqlx::query("UPDATE group_invites SET status = ? WHERE id = ?")
            .bind(status)
            .bind(invite_id)
            .execute(pool)
            .await?;

        Ok(())
    }

    /// Delete a group invite
    #[allow(dead_code)]
    pub async fn delete_invite(pool: &SqlitePool, invite_id: i64) -> Result<()> {
        sqlx::query("DELETE FROM group_invites WHERE id = ?")
            .bind(invite_id)
            .execute(pool)
            .await?;

        Ok(())
    }

    // ========== Join Requests ==========

    /// Store a join request
    pub async fn store_join_request(
        pool: &SqlitePool,
        group_id: &str,
        requester: &str,
        key_package: &str,
    ) -> Result<i64> {
        let result = sqlx::query(
            r#"
            INSERT INTO join_requests (group_id, requester, key_package)
            VALUES (?, ?, ?)
            "#,
        )
        .bind(group_id)
        .bind(requester)
        .bind(key_package)
        .execute(pool)
        .await?;

        let id = result.last_insert_rowid();
        tracing::debug!(
            "Stored join request {} from {} for group {}",
            id,
            requester,
            group_id
        );
        Ok(id)
    }

    /// Get pending join requests for a group
    pub async fn get_pending_join_requests(
        pool: &SqlitePool,
        group_id: &str,
    ) -> Result<Vec<(i64, String, String, String)>> {
        let rows = sqlx::query(
            r#"
            SELECT id, requester, key_package, requested_at
            FROM join_requests
            WHERE group_id = ? AND status = 'pending'
            ORDER BY requested_at ASC
            "#,
        )
        .bind(group_id)
        .fetch_all(pool)
        .await?;

        let mut requests = Vec::new();
        for r in rows {
            requests.push((
                r.try_get::<i64, _>("id")?,
                r.try_get::<String, _>("requester")?,
                r.try_get::<String, _>("key_package")?,
                r.try_get::<String, _>("requested_at")?,
            ));
        }
        Ok(requests)
    }

    /// Get all pending join requests across all groups
    pub async fn get_all_pending_join_requests(
        pool: &SqlitePool,
    ) -> Result<Vec<(i64, String, String, String, String)>> {
        let rows = sqlx::query(
            r#"
            SELECT id, group_id, requester, key_package, requested_at
            FROM join_requests
            WHERE status = 'pending'
            ORDER BY requested_at ASC
            "#,
        )
        .fetch_all(pool)
        .await?;

        let mut requests = Vec::new();
        for r in rows {
            requests.push((
                r.try_get::<i64, _>("id")?,
                r.try_get::<String, _>("group_id")?,
                r.try_get::<String, _>("requester")?,
                r.try_get::<String, _>("key_package")?,
                r.try_get::<String, _>("requested_at")?,
            ));
        }
        Ok(requests)
    }

    /// Update join request status (approved/rejected)
    pub async fn update_join_request_status(
        pool: &SqlitePool,
        request_id: i64,
        status: &str,
    ) -> Result<()> {
        sqlx::query("UPDATE join_requests SET status = ? WHERE id = ?")
            .bind(status)
            .bind(request_id)
            .execute(pool)
            .await?;

        Ok(())
    }

    /// Delete a join request
    #[allow(dead_code)]
    pub async fn delete_join_request(pool: &SqlitePool, request_id: i64) -> Result<()> {
        sqlx::query("DELETE FROM join_requests WHERE id = ?")
            .bind(request_id)
            .execute(pool)
            .await?;

        Ok(())
    }

    // ========== Conversations ==========

    /// Create a conversation (DM conversation → MLS group ID mapping)
    pub async fn create_conversation(
        pool: &SqlitePool,
        id: &str,
        mls_group_id: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO conversations (id, mls_group_id)
            VALUES (?, ?)
            "#,
        )
        .bind(id)
        .bind(mls_group_id)
        .execute(pool)
        .await?;

        tracing::debug!("Created conversation: {}", id);
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
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS group_servers (
                server_address TEXT PRIMARY KEY,
                mls_group_id TEXT,
                group_name TEXT,
                joined_at TEXT DEFAULT (datetime('now'))
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

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
        .execute(&pool)
        .await
        .unwrap();

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
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                mls_group_id TEXT
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        pool
    }

    #[tokio::test]
    async fn test_add_and_get_member() {
        let pool = setup_test_db().await;

        GroupDb::add_member(&pool, "conv1", "alice", None, false, "member")
            .await
            .unwrap();

        let members = GroupDb::get_members(&pool, "conv1").await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].username, "alice");
        assert_eq!(members[0].role, "member");
    }

    #[tokio::test]
    async fn test_group_server_operations() {
        let pool = setup_test_db().await;

        let server = GroupServer {
            server_address: "server1".to_string(),
            mls_group_id: Some("group1".to_string()),
            group_name: Some("Test Group".to_string()),
            joined_at: chrono::Utc::now().to_rfc3339(),
        };

        GroupDb::save_group_server(&pool, &server).await.unwrap();

        let retrieved = GroupDb::get_group_server(&pool, "server1").await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.server_address, "server1");
        assert_eq!(retrieved.mls_group_id, Some("group1".to_string()));
    }

    #[tokio::test]
    async fn test_group_invite() {
        let pool = setup_test_db().await;

        let id = GroupDb::store_invite(&pool, "group1", Some("Test Group"), "bob")
            .await
            .unwrap();

        let invites = GroupDb::get_pending_invites(&pool).await.unwrap();
        assert_eq!(invites.len(), 1);
        assert_eq!(invites[0].0, id);
        assert_eq!(invites[0].1, "group1");

        GroupDb::update_invite_status(&pool, id, "accepted")
            .await
            .unwrap();
        let invites = GroupDb::get_pending_invites(&pool).await.unwrap();
        assert_eq!(invites.len(), 0);
    }
}
