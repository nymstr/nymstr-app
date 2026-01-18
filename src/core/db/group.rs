//! Group-related database operations
//!
//! This module contains methods for managing group memberships, group servers,
//! group invites, and join requests.

use super::{Db, sanitize_table_name, GroupMember};
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::Row;

impl Db {
    // ========== Group Membership Storage ==========

    /// Add a member to a group
    pub async fn add_group_membership(
        &self,
        me: &str,
        conversation_id: &str,
        member_username: &str,
        credential_fingerprint: Option<&str>,
        credential_verified: bool,
        role: &str,
    ) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_memberships_{}", safe_name);

        let verified_at: Option<DateTime<Utc>> = if credential_verified {
            Some(Utc::now())
        } else {
            None
        };

        sqlx::query(&format!(
            r#"
            INSERT OR REPLACE INTO {table}
            (conversation_id, member_username, credential_fingerprint, credential_verified, verified_at, role)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
            table = table
        ))
        .bind(conversation_id)
        .bind(member_username)
        .bind(credential_fingerprint)
        .bind(credential_verified)
        .bind(verified_at)
        .bind(role)
        .execute(&self.pool)
        .await?;

        log::info!(
            "Added group membership: {} in {} (verified: {})",
            member_username, conversation_id, credential_verified
        );
        Ok(())
    }

    /// Get all members of a group
    #[allow(dead_code)] // Part of public API for group membership
    pub async fn get_group_members(
        &self,
        me: &str,
        conversation_id: &str,
    ) -> Result<Vec<GroupMember>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_memberships_{}", safe_name);

        let rows = sqlx::query(&format!(
            r#"
            SELECT member_username, credential_fingerprint, credential_verified, verified_at, joined_at, role
            FROM {table}
            WHERE conversation_id = ?
            ORDER BY joined_at ASC
            "#,
            table = table
        ))
        .bind(conversation_id)
        .fetch_all(&self.pool)
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
    #[allow(dead_code)] // Part of public API for group membership
    pub async fn update_member_verification(
        &self,
        me: &str,
        conversation_id: &str,
        member_username: &str,
        verified: bool,
        fingerprint: Option<&str>,
    ) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_memberships_{}", safe_name);

        let verified_at: Option<DateTime<Utc>> = if verified {
            Some(Utc::now())
        } else {
            None
        };

        sqlx::query(&format!(
            r#"
            UPDATE {table}
            SET credential_verified = ?, verified_at = ?, credential_fingerprint = ?
            WHERE conversation_id = ? AND member_username = ?
            "#,
            table = table
        ))
        .bind(verified)
        .bind(verified_at)
        .bind(fingerprint)
        .bind(conversation_id)
        .bind(member_username)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Remove a member from a group
    #[allow(dead_code)] // Part of public API for group membership
    pub async fn remove_group_membership(
        &self,
        me: &str,
        conversation_id: &str,
        member_username: &str,
    ) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_memberships_{}", safe_name);

        sqlx::query(&format!(
            "DELETE FROM {table} WHERE conversation_id = ? AND member_username = ?",
            table = table
        ))
        .bind(conversation_id)
        .bind(member_username)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get all groups a user is a member of
    pub async fn get_user_groups(&self, me: &str) -> Result<Vec<String>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_memberships_{}", safe_name);

        let rows = sqlx::query(&format!(
            "SELECT DISTINCT conversation_id FROM {table}",
            table = table
        ))
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| r.try_get("conversation_id").unwrap())
            .collect())
    }

    // ========== Group Server Association ==========

    /// Store association between a group ID and its server address/admin
    pub async fn store_group_server(
        &self,
        me: &str,
        group_id: &str,
        server_address: &str,
        admin_username: &str,
        mls_group_id: Option<&str>,
    ) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_servers_{}", safe_name);

        sqlx::query(&format!(
            r#"
            INSERT OR REPLACE INTO {table}
            (group_id, server_address, admin_username, mls_group_id)
            VALUES (?, ?, ?, ?)
            "#,
            table = table
        ))
        .bind(group_id)
        .bind(server_address)
        .bind(admin_username)
        .bind(mls_group_id)
        .execute(&self.pool)
        .await?;

        log::info!(
            "Stored group server association: group={}, server={}, admin={}, mls_group_id={:?}",
            group_id, server_address, admin_username, mls_group_id
        );
        Ok(())
    }

    /// Get the server address, admin, and MLS group ID for a group
    #[allow(dead_code)] // Part of public API for group server management
    pub async fn get_group_server(
        &self,
        me: &str,
        group_id: &str,
    ) -> Result<Option<(String, String, Option<String>)>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_servers_{}", safe_name);

        let row = sqlx::query(&format!(
            "SELECT server_address, admin_username, mls_group_id FROM {table} WHERE group_id = ?",
            table = table
        ))
        .bind(group_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| {
            (
                r.try_get::<String, _>("server_address").unwrap(),
                r.try_get::<String, _>("admin_username").unwrap(),
                r.try_get::<Option<String>, _>("mls_group_id").unwrap_or(None),
            )
        }))
    }

    /// Get the MLS group ID for a server address
    pub async fn get_mls_group_id_by_server(
        &self,
        me: &str,
        server_address: &str,
    ) -> Result<Option<String>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_servers_{}", safe_name);

        let row = sqlx::query(&format!(
            "SELECT mls_group_id FROM {table} WHERE server_address = ?",
            table = table
        ))
        .bind(server_address)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.and_then(|r| r.try_get::<Option<String>, _>("mls_group_id").unwrap_or(None)))
    }

    // ==================== Group Invite Methods ====================

    /// Store an incoming group invite
    pub async fn store_group_invite(
        &self,
        me: &str,
        group_id: &str,
        group_name: Option<&str>,
        sender: &str,
    ) -> Result<i64> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_invites_{}", safe_name);

        let result = sqlx::query(&format!(
            r#"
            INSERT INTO {table} (group_id, group_name, sender)
            VALUES (?, ?, ?)
            "#,
            table = table
        ))
        .bind(group_id)
        .bind(group_name)
        .bind(sender)
        .execute(&self.pool)
        .await?;

        let id = result.last_insert_rowid();
        log::info!("Stored group invite {} from {} for group {} (user: {})", id, sender, group_id, me);
        Ok(id)
    }

    /// Get pending group invites
    pub async fn get_pending_invites(&self, me: &str) -> Result<Vec<(i64, String, Option<String>, String, String)>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_invites_{}", safe_name);

        let rows = sqlx::query(&format!(
            r#"
            SELECT id, group_id, group_name, sender, received_at
            FROM {table}
            WHERE status = 'pending'
            ORDER BY received_at DESC
            "#,
            table = table
        ))
        .fetch_all(&self.pool)
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

    /// Mark an invite as accepted or rejected
    pub async fn update_invite_status(&self, me: &str, invite_id: i64, status: &str) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_invites_{}", safe_name);

        sqlx::query(&format!(
            "UPDATE {table} SET status = ? WHERE id = ?",
            table = table
        ))
        .bind(status)
        .bind(invite_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Delete a group invite
    #[allow(dead_code)] // Part of public API for group invite management
    pub async fn delete_group_invite(&self, me: &str, invite_id: i64) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("group_invites_{}", safe_name);

        sqlx::query(&format!(
            "DELETE FROM {table} WHERE id = ?",
            table = table
        ))
        .bind(invite_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // ==================== Join Request Methods ====================

    /// Store a join request from someone wanting to join a group we manage
    pub async fn store_join_request(
        &self,
        me: &str,
        group_id: &str,
        requester: &str,
        key_package: &str,
    ) -> Result<i64> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("join_requests_{}", safe_name);

        let result = sqlx::query(&format!(
            r#"
            INSERT INTO {table} (group_id, requester, key_package)
            VALUES (?, ?, ?)
            "#,
            table = table
        ))
        .bind(group_id)
        .bind(requester)
        .bind(key_package)
        .execute(&self.pool)
        .await?;

        let id = result.last_insert_rowid();
        log::info!("Stored join request {} from {} for group {} (user: {})", id, requester, group_id, me);
        Ok(id)
    }

    /// Get pending join requests for a group
    pub async fn get_pending_join_requests(
        &self,
        me: &str,
        group_id: &str,
    ) -> Result<Vec<(i64, String, String, String)>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("join_requests_{}", safe_name);

        let rows = sqlx::query(&format!(
            r#"
            SELECT id, requester, key_package, requested_at
            FROM {table}
            WHERE group_id = ? AND status = 'pending'
            ORDER BY requested_at ASC
            "#,
            table = table
        ))
        .bind(group_id)
        .fetch_all(&self.pool)
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
        &self,
        me: &str,
    ) -> Result<Vec<(i64, String, String, String, String)>> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("join_requests_{}", safe_name);

        let rows = sqlx::query(&format!(
            r#"
            SELECT id, group_id, requester, key_package, requested_at
            FROM {table}
            WHERE status = 'pending'
            ORDER BY requested_at ASC
            "#,
            table = table
        ))
        .fetch_all(&self.pool)
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

    /// Mark a join request as approved or rejected
    pub async fn update_join_request_status(&self, me: &str, request_id: i64, status: &str) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("join_requests_{}", safe_name);

        sqlx::query(&format!(
            "UPDATE {table} SET status = ? WHERE id = ?",
            table = table
        ))
        .bind(status)
        .bind(request_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Delete a join request
    #[allow(dead_code)] // Part of public API for join request management
    pub async fn delete_join_request(&self, me: &str, request_id: i64) -> Result<()> {
        let safe_name = sanitize_table_name(me)?;
        let table = format!("join_requests_{}", safe_name);

        sqlx::query(&format!(
            "DELETE FROM {table} WHERE id = ?",
            table = table
        ))
        .bind(request_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
