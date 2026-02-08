//! Integration tests for welcome flow operations
//!
//! Tests the group invitation and MLS welcome processing workflow.

mod common;

use anyhow::Result;
use nymstr_app_v2_lib::core::messages::MixnetMessage;
use common::TestContext;

/// Test MLS welcome message format
#[tokio::test]
async fn test_mls_welcome_message_format() -> Result<()> {
    let msg = MixnetMessage::mls_welcome(
        "admin",
        "new_member",
        "group-123",
        1, // cipher suite
        "welcome_bytes_b64",
        Some("ratchet_tree_b64"),
        5,          // epoch
        1706000000, // timestamp
        "signature",
    );

    assert_eq!(msg.message_type, "system");
    assert_eq!(msg.action, "mlsWelcome");
    assert_eq!(msg.sender, "admin");
    assert_eq!(msg.recipient, "new_member");
    assert_eq!(msg.payload["group_id"], "group-123");
    assert_eq!(msg.payload["cipher_suite"], 1);
    assert_eq!(msg.payload["welcome_bytes"], "welcome_bytes_b64");
    assert_eq!(msg.payload["ratchet_tree"], "ratchet_tree_b64");
    assert_eq!(msg.payload["epoch"], 5);
    assert_eq!(msg.payload["timestamp"], 1706000000u64);

    Ok(())
}

/// Test group join request message format
#[tokio::test]
async fn test_group_join_request_format() -> Result<()> {
    let msg = MixnetMessage::group_join_request(
        "new_member",
        "group-123",
        "key_package_b64",
        "signature",
    );

    assert_eq!(msg.message_type, "system");
    assert_eq!(msg.action, "groupJoinRequest");
    assert_eq!(msg.sender, "new_member");
    assert_eq!(msg.payload["groupId"], "group-123");
    assert_eq!(msg.payload["keyPackage"], "key_package_b64");

    Ok(())
}

/// Test welcome acknowledgment message format
#[tokio::test]
async fn test_welcome_ack_format() -> Result<()> {
    let msg = MixnetMessage::welcome_ack("new_member", "admin", "group-123", true, "signature");

    assert_eq!(msg.message_type, "system");
    assert_eq!(msg.action, "welcomeAck");
    assert_eq!(msg.sender, "new_member");
    assert_eq!(msg.recipient, "admin");
    assert_eq!(msg.payload["groupId"], "group-123");
    assert_eq!(msg.payload["success"], true);

    // Test failure case
    let msg_fail = MixnetMessage::welcome_ack("new_member", "admin", "group-123", false, "signature");
    assert_eq!(msg_fail.payload["success"], false);

    Ok(())
}

/// Test group invite message format
#[tokio::test]
async fn test_group_invite_format() -> Result<()> {
    let msg = MixnetMessage::group_invite(
        "admin",
        "new_member",
        "group-123",
        Some("Test Group"),
        "signature",
    );

    assert_eq!(msg.message_type, "system");
    assert_eq!(msg.action, "groupInvite");
    assert_eq!(msg.sender, "admin");
    assert_eq!(msg.recipient, "new_member");
    assert_eq!(msg.payload["groupId"], "group-123");
    assert_eq!(msg.payload["groupName"], "Test Group");

    // Test without group name
    let msg_no_name =
        MixnetMessage::group_invite("admin", "new_member", "group-123", None, "signature");
    assert_eq!(msg_no_name.payload["groupName"], "group-123");

    Ok(())
}

/// Test key package for group request format
#[tokio::test]
async fn test_key_package_for_group_format() -> Result<()> {
    let msg = MixnetMessage::key_package_for_group("admin", "new_member", "group-123", "signature");

    assert_eq!(msg.message_type, "system");
    assert_eq!(msg.action, "keyPackageForGroup");
    assert_eq!(msg.sender, "admin");
    assert_eq!(msg.recipient, "new_member");
    assert_eq!(msg.payload["groupId"], "group-123");
    assert_eq!(msg.payload["purpose"], "groupJoin");

    Ok(())
}

/// Test key package for group response format
#[tokio::test]
async fn test_key_package_for_group_response_format() -> Result<()> {
    let msg = MixnetMessage::key_package_for_group_response(
        "new_member",
        "admin",
        "group-123",
        "key_package_b64",
        "signature",
    );

    assert_eq!(msg.message_type, "system");
    assert_eq!(msg.action, "keyPackageForGroupResponse");
    assert_eq!(msg.sender, "new_member");
    assert_eq!(msg.recipient, "admin");
    assert_eq!(msg.payload["groupId"], "group-123");
    assert_eq!(msg.payload["keyPackage"], "key_package_b64");

    Ok(())
}

/// Test pending welcomes database storage
#[tokio::test]
async fn test_pending_welcomes_storage() -> Result<()> {
    let ctx = TestContext::new().await?;

    // Insert a pending welcome
    sqlx::query(
        r#"
        INSERT INTO pending_welcomes (group_id, sender, welcome_bytes, cipher_suite, epoch, received_at)
        VALUES (?, ?, ?, ?, ?, datetime('now'))
        "#,
    )
    .bind("group-123")
    .bind("admin")
    .bind("welcome_bytes_b64")
    .bind(1)
    .bind(5)
    .execute(&ctx.db)
    .await?;

    // Query the welcome
    let welcome: (String, String, String, i32, i64) = sqlx::query_as(
        "SELECT group_id, sender, welcome_bytes, cipher_suite, epoch FROM pending_welcomes WHERE group_id = ?",
    )
    .bind("group-123")
    .fetch_one(&ctx.db)
    .await?;

    assert_eq!(welcome.0, "group-123");
    assert_eq!(welcome.1, "admin");
    assert_eq!(welcome.2, "welcome_bytes_b64");
    assert_eq!(welcome.3, 1);
    assert_eq!(welcome.4, 5);

    Ok(())
}

/// Test marking welcome as processed
#[tokio::test]
async fn test_mark_welcome_processed() -> Result<()> {
    let ctx = TestContext::new().await?;

    // Insert a pending welcome
    sqlx::query(
        r#"
        INSERT INTO pending_welcomes (group_id, sender, welcome_bytes, cipher_suite, epoch, received_at)
        VALUES (?, ?, ?, ?, ?, datetime('now'))
        "#,
    )
    .bind("group-123")
    .bind("admin")
    .bind("welcome_bytes")
    .bind(1)
    .bind(5)
    .execute(&ctx.db)
    .await?;

    // Get the ID
    let (id,): (i64,) = sqlx::query_as("SELECT id FROM pending_welcomes WHERE group_id = ?")
        .bind("group-123")
        .fetch_one(&ctx.db)
        .await?;

    // Mark as processed
    sqlx::query("UPDATE pending_welcomes SET processed = 1, processed_at = datetime('now') WHERE id = ?")
        .bind(id)
        .execute(&ctx.db)
        .await?;

    // Verify
    let (processed,): (i32,) = sqlx::query_as("SELECT processed FROM pending_welcomes WHERE id = ?")
        .bind(id)
        .fetch_one(&ctx.db)
        .await?;

    assert_eq!(processed, 1);

    Ok(())
}

/// Test fetch welcome message format
#[tokio::test]
async fn test_fetch_welcome_format() -> Result<()> {
    // With group filter
    let msg = MixnetMessage::fetch_welcome("alice", Some("group-123"), "signature");

    assert_eq!(msg.message_type, "system");
    assert_eq!(msg.action, "fetchWelcome");
    assert_eq!(msg.sender, "alice");
    assert_eq!(msg.payload["groupId"], "group-123");

    // Without group filter
    let msg_all = MixnetMessage::fetch_welcome("alice", None, "signature");
    assert!(msg_all.payload.get("groupId").is_none());

    Ok(())
}

/// Test group invites storage
#[tokio::test]
async fn test_group_invites_storage() -> Result<()> {
    let ctx = TestContext::new().await?;

    // Insert an invite
    sqlx::query(
        r#"
        INSERT INTO group_invites (group_id, group_name, sender, status)
        VALUES (?, ?, ?, ?)
        "#,
    )
    .bind("group-123")
    .bind("Test Group")
    .bind("admin")
    .bind("pending")
    .execute(&ctx.db)
    .await?;

    // Query pending invites
    let invites: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT group_id, group_name, sender, status FROM group_invites WHERE status = 'pending'",
    )
    .fetch_all(&ctx.db)
    .await?;

    assert_eq!(invites.len(), 1);
    assert_eq!(invites[0].0, "group-123");
    assert_eq!(invites[0].1, "Test Group");
    assert_eq!(invites[0].2, "admin");

    Ok(())
}

/// Test group join response message format
#[tokio::test]
async fn test_group_join_response_format() -> Result<()> {
    let msg = MixnetMessage::group_join_response("admin", "new_member", "group-123", true, "signature");

    assert_eq!(msg.message_type, "system");
    assert_eq!(msg.action, "groupJoinResponse");
    assert_eq!(msg.sender, "admin");
    assert_eq!(msg.recipient, "new_member");
    assert_eq!(msg.payload["groupId"], "group-123");
    assert_eq!(msg.payload["success"], true);

    Ok(())
}

/// Test multiple welcomes for same user
#[tokio::test]
async fn test_multiple_welcomes_same_user() -> Result<()> {
    let ctx = TestContext::new().await?;

    // Insert welcomes for different groups
    for i in 1..=3 {
        sqlx::query(
            r#"
            INSERT INTO pending_welcomes (group_id, sender, welcome_bytes, cipher_suite, epoch, received_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
            "#,
        )
        .bind(format!("group-{}", i))
        .bind("admin")
        .bind(format!("welcome_{}", i))
        .bind(1)
        .bind(i as i64)
        .execute(&ctx.db)
        .await?;
    }

    // Query all pending welcomes
    let welcomes: Vec<(String, String)> = sqlx::query_as(
        "SELECT group_id, welcome_bytes FROM pending_welcomes WHERE processed = 0 ORDER BY group_id",
    )
    .fetch_all(&ctx.db)
    .await?;

    assert_eq!(welcomes.len(), 3);
    assert_eq!(welcomes[0].0, "group-1");
    assert_eq!(welcomes[1].0, "group-2");
    assert_eq!(welcomes[2].0, "group-3");

    Ok(())
}
