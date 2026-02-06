//! Integration tests for group operations
//!
//! Tests group messaging lifecycle including registration, message sending,
//! and fetching with MLS encryption.

mod common;

use anyhow::Result;
use nymstr_app_v2_lib::core::messages::MixnetMessage;
use common::TestContext;

/// Test group registration message format
#[tokio::test]
async fn test_group_registration_message_format() -> Result<()> {
    let msg = MixnetMessage::register_with_group_server(
        "alice",
        "pk_alice",
        "signature123",
        1706000000,
        "group-server-address",
    );

    assert_eq!(msg.message_type, "system");
    assert_eq!(msg.action, "register");
    assert_eq!(msg.sender, "alice");
    assert_eq!(msg.recipient, "group-server");
    assert_eq!(msg.payload["username"], "alice");
    assert_eq!(msg.payload["publicKey"], "pk_alice");
    assert_eq!(msg.payload["timestamp"], 1706000000);

    Ok(())
}

/// Test group message format
#[tokio::test]
async fn test_send_group_message_format() -> Result<()> {
    let msg = MixnetMessage::send_group("alice", "encrypted_ciphertext", "signature456");

    assert_eq!(msg.message_type, "message");
    assert_eq!(msg.action, "sendGroup");
    assert_eq!(msg.sender, "alice");
    assert_eq!(msg.recipient, "group-server");
    assert_eq!(msg.payload["ciphertext"], "encrypted_ciphertext");
    assert_eq!(msg.signature, "signature456");

    Ok(())
}

/// Test fetch group message format
#[tokio::test]
async fn test_fetch_group_message_format() -> Result<()> {
    let msg = MixnetMessage::fetch_group("alice", 42, "signature789");

    assert_eq!(msg.message_type, "system");
    assert_eq!(msg.action, "fetchGroup");
    assert_eq!(msg.sender, "alice");
    assert_eq!(msg.payload["lastSeenId"], 42);
    assert_eq!(msg.signature, "signature789");

    Ok(())
}

/// Test approve group member message format
#[tokio::test]
async fn test_approve_group_member_format() -> Result<()> {
    let msg = MixnetMessage::approve_group_member("admin", "new_member", "signature", "group-server-1", 1700000000);

    assert_eq!(msg.message_type, "system");
    assert_eq!(msg.action, "approveGroup");
    assert_eq!(msg.sender, "admin");
    assert_eq!(msg.payload["username"], "new_member");

    Ok(())
}

/// Test group membership database operations
#[tokio::test]
async fn test_group_membership_storage() -> Result<()> {
    let ctx = TestContext::new().await?;

    // Insert a group membership
    sqlx::query(
        r#"
        INSERT INTO group_memberships (server_address, username, mls_group_id, role)
        VALUES (?, ?, ?, ?)
        "#,
    )
    .bind("group-server-1")
    .bind("alice")
    .bind("mls-group-123")
    .bind("admin")
    .execute(&ctx.db)
    .await?;

    // Query the membership
    let membership: (String, String, Option<String>, String) = sqlx::query_as(
        "SELECT server_address, username, mls_group_id, role FROM group_memberships WHERE username = ?",
    )
    .bind("alice")
    .fetch_one(&ctx.db)
    .await?;

    assert_eq!(membership.0, "group-server-1");
    assert_eq!(membership.1, "alice");
    assert_eq!(membership.2, Some("mls-group-123".to_string()));
    assert_eq!(membership.3, "admin");

    Ok(())
}

/// Test group cursor tracking
#[tokio::test]
async fn test_group_cursor_tracking() -> Result<()> {
    let ctx = TestContext::new().await?;

    // Insert a cursor
    sqlx::query(
        r#"
        INSERT INTO group_cursors (server_address, username, last_message_id)
        VALUES (?, ?, ?)
        "#,
    )
    .bind("group-server-1")
    .bind("alice")
    .bind(100)
    .execute(&ctx.db)
    .await?;

    // Query the cursor
    let cursor: (i64,) = sqlx::query_as(
        "SELECT last_message_id FROM group_cursors WHERE server_address = ? AND username = ?",
    )
    .bind("group-server-1")
    .bind("alice")
    .fetch_one(&ctx.db)
    .await?;

    assert_eq!(cursor.0, 100);

    // Update the cursor
    sqlx::query(
        r#"
        UPDATE group_cursors SET last_message_id = ? WHERE server_address = ? AND username = ?
        "#,
    )
    .bind(150)
    .bind("group-server-1")
    .bind("alice")
    .execute(&ctx.db)
    .await?;

    let cursor: (i64,) = sqlx::query_as(
        "SELECT last_message_id FROM group_cursors WHERE server_address = ? AND username = ?",
    )
    .bind("group-server-1")
    .bind("alice")
    .fetch_one(&ctx.db)
    .await?;

    assert_eq!(cursor.0, 150);

    Ok(())
}

/// Test query pending users message format
#[tokio::test]
async fn test_query_pending_users_format() -> Result<()> {
    let msg = MixnetMessage::query_pending_users("admin", "signature");

    assert_eq!(msg.message_type, "system");
    assert_eq!(msg.action, "queryPendingUsers");
    assert_eq!(msg.sender, "admin");
    assert_eq!(msg.recipient, "group-server");

    Ok(())
}

/// Test group server registration with key package
#[tokio::test]
async fn test_register_with_key_package() -> Result<()> {
    let msg = MixnetMessage::register_with_group_server_and_key_package(
        "alice",
        "pk_alice",
        "signature",
        1706000000,
        "group-server-address",
        Some("key_package_b64"),
    );

    assert_eq!(msg.action, "register");
    assert_eq!(msg.payload["keyPackage"], "key_package_b64");

    // Test without key package
    let msg_no_kp = MixnetMessage::register_with_group_server_and_key_package(
        "bob",
        "pk_bob",
        "signature",
        1706000000,
        "group-server-address",
        None,
    );

    assert!(msg_no_kp.payload.get("keyPackage").is_none());

    Ok(())
}

/// Test group members table operations
#[tokio::test]
async fn test_group_members_storage() -> Result<()> {
    let ctx = TestContext::new().await?;

    // Add members to a conversation/group
    let members = vec![("alice", "admin"), ("bob", "member"), ("charlie", "member")];

    for (username, role) in &members {
        sqlx::query(
            r#"
            INSERT INTO group_members (conversation_id, member_username, role)
            VALUES (?, ?, ?)
            "#,
        )
        .bind("conv-123")
        .bind(username)
        .bind(role)
        .execute(&ctx.db)
        .await?;
    }

    // Query all members
    let result: Vec<(String, String)> = sqlx::query_as(
        "SELECT member_username, role FROM group_members WHERE conversation_id = ? ORDER BY member_username",
    )
    .bind("conv-123")
    .fetch_all(&ctx.db)
    .await?;

    assert_eq!(result.len(), 3);
    assert_eq!(result[0], ("alice".to_string(), "admin".to_string()));
    assert_eq!(result[1], ("bob".to_string(), "member".to_string()));
    assert_eq!(result[2], ("charlie".to_string(), "member".to_string()));

    Ok(())
}

/// Test store welcome message format
#[tokio::test]
async fn test_store_welcome_format() -> Result<()> {
    let msg = MixnetMessage::store_welcome(
        "admin",
        "group-123",
        "new_member",
        "welcome_bytes_b64",
        "signature",
    );

    assert_eq!(msg.message_type, "system");
    assert_eq!(msg.action, "storeWelcome");
    assert_eq!(msg.sender, "admin");
    assert_eq!(msg.payload["groupId"], "group-123");
    assert_eq!(msg.payload["targetUsername"], "new_member");
    assert_eq!(msg.payload["welcome"], "welcome_bytes_b64");

    Ok(())
}

/// Test buffer commit message format
#[tokio::test]
async fn test_buffer_commit_format() -> Result<()> {
    let msg = MixnetMessage::buffer_commit("alice", "group-123", 5, "commit_bytes_b64", "signature");

    assert_eq!(msg.message_type, "system");
    assert_eq!(msg.action, "bufferCommit");
    assert_eq!(msg.payload["groupId"], "group-123");
    assert_eq!(msg.payload["epoch"], 5);
    assert_eq!(msg.payload["commit"], "commit_bytes_b64");

    Ok(())
}

/// Test sync epoch message format
#[tokio::test]
async fn test_sync_epoch_format() -> Result<()> {
    let msg = MixnetMessage::sync_epoch("alice", "group-123", 3, "signature");

    assert_eq!(msg.message_type, "system");
    assert_eq!(msg.action, "syncEpoch");
    assert_eq!(msg.payload["groupId"], "group-123");
    assert_eq!(msg.payload["sinceEpoch"], 3);

    Ok(())
}

/// Test join request storage
#[tokio::test]
async fn test_join_request_storage() -> Result<()> {
    let ctx = TestContext::new().await?;

    // Insert a join request
    sqlx::query(
        r#"
        INSERT INTO join_requests (group_id, requester, key_package, status)
        VALUES (?, ?, ?, ?)
        "#,
    )
    .bind("group-123")
    .bind("new_member")
    .bind("key_package_b64")
    .bind("pending")
    .execute(&ctx.db)
    .await?;

    // Query pending requests
    let requests: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT group_id, requester, key_package FROM join_requests WHERE status = 'pending'",
    )
    .fetch_all(&ctx.db)
    .await?;

    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].0, "group-123");
    assert_eq!(requests[0].1, "new_member");

    Ok(())
}
