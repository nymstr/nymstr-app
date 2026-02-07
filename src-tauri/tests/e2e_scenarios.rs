//! End-to-end scenario tests
//!
//! Tests complete workflows combining multiple operations.

mod common;

use anyhow::Result;
use nymstr_app_v2_lib::core::messages::MixnetMessage;
use common::TestContext;

/// Test complete registration flow message sequence
#[tokio::test]
async fn test_registration_message_sequence() -> Result<()> {
    // 1. Client sends registration request
    let register_msg = MixnetMessage::register("alice", "pk_alice_armored");
    assert_eq!(register_msg.action, "register");
    assert_eq!(register_msg.payload["username"], "alice");
    assert_eq!(register_msg.payload["publicKey"], "pk_alice_armored");

    // 2. Server sends challenge
    let challenge_msg = MixnetMessage::challenge("server", "alice", "nonce123", "registration");
    assert_eq!(challenge_msg.action, "challenge");
    assert_eq!(challenge_msg.payload["nonce"], "nonce123");

    // 3. Client responds with signed nonce
    let response_msg = MixnetMessage::challenge_response("alice", "server", "signed_nonce", "registration");
    assert_eq!(response_msg.action, "registrationResponse");

    // 4. Server confirms registration
    let confirm_msg = MixnetMessage::registration_response("server", "alice", "success", "registration");
    assert_eq!(confirm_msg.action, "challengeResponse");
    assert_eq!(confirm_msg.payload["result"], "success");

    Ok(())
}

/// Test complete login flow message sequence
#[tokio::test]
async fn test_login_message_sequence() -> Result<()> {
    // 1. Client sends login request
    let login_msg = MixnetMessage::login("alice");
    assert_eq!(login_msg.action, "login");
    assert_eq!(login_msg.payload["username"], "alice");

    // 2. Server sends challenge
    let challenge_msg = MixnetMessage::challenge("server", "alice", "nonce456", "login");
    assert_eq!(challenge_msg.action, "challenge");
    assert_eq!(challenge_msg.payload["context"], "login");

    // 3. Client responds with signed nonce
    let response_msg = MixnetMessage::challenge_response("alice", "server", "signed_nonce", "login");
    assert_eq!(response_msg.action, "loginResponse");

    // 4. Server confirms login
    let confirm_msg = MixnetMessage::login_response("server", "alice", "success", "login");
    assert_eq!(confirm_msg.action, "loginResponse");

    Ok(())
}

/// Test complete DM handshake flow
#[tokio::test]
async fn test_dm_handshake_flow() -> Result<()> {
    // 1. Alice queries Bob's public key
    let query_msg = MixnetMessage::query("alice", "bob");
    assert_eq!(query_msg.action, "query");

    // 2. Server responds with Bob's info
    let query_resp = MixnetMessage::query_response("server", "alice", "bob", "pk_bob_armored");
    assert_eq!(query_resp.action, "queryResponse");

    // 3. Alice requests Bob's key package
    let kp_request = MixnetMessage::key_package_request(
        "alice",
        "bob",
        "signature",
    );
    assert_eq!(kp_request.action, "keyPackageRequest");

    // 4. Bob responds with his key package
    let kp_response = MixnetMessage::key_package_response(
        "bob",
        "alice",
        "bob_key_package",
        "alice_key_package",
        "signature",
    );
    assert_eq!(kp_response.action, "keyPackageResponse");

    // 5. Alice can now establish MLS group and send messages
    let dm = MixnetMessage::direct_message(
        "alice",
        "bob",
        "encrypted_hello",
        "conv-alice-bob",
        "signature",
    );
    assert_eq!(dm.action, "send");

    Ok(())
}

/// Test complete group join flow
#[tokio::test]
async fn test_group_join_flow() -> Result<()> {
    // 1. Admin invites user
    let invite_msg = MixnetMessage::group_invite(
        "admin",
        "new_member",
        "group-123",
        Some("Test Group"),
        "signature",
    );
    assert_eq!(invite_msg.action, "groupInvite");

    // 2. Admin requests user's key package
    let kp_request = MixnetMessage::key_package_for_group(
        "admin",
        "new_member",
        "group-123",
        "signature",
    );
    assert_eq!(kp_request.action, "keyPackageForGroup");

    // 3. User provides key package
    let kp_response = MixnetMessage::key_package_for_group_response(
        "new_member",
        "admin",
        "group-123",
        "key_package_b64",
        "signature",
    );
    assert_eq!(kp_response.action, "keyPackageForGroupResponse");

    // 4. Admin sends Welcome
    let welcome_msg = MixnetMessage::mls_welcome(
        "admin",
        "new_member",
        "group-123",
        1,
        "welcome_bytes",
        Some("ratchet_tree"),
        5,
        1706000000,
        "signature",
    );
    assert_eq!(welcome_msg.action, "mlsWelcome");

    // 5. User acknowledges
    let ack_msg = MixnetMessage::welcome_ack(
        "new_member",
        "admin",
        "group-123",
        true,
        "signature",
    );
    assert_eq!(ack_msg.action, "welcomeAck");

    Ok(())
}

/// Test complete group message flow
#[tokio::test]
async fn test_group_message_flow() -> Result<()> {
    // 1. User registers with group server
    let register_msg = MixnetMessage::register_with_group_server(
        "alice",
        "pk_alice",
        "signature",
        1706000000,
        "group-server-address",
    );
    assert_eq!(register_msg.action, "register");

    // 2. User sends encrypted group message
    let send_msg = MixnetMessage::send_group(
        "alice",
        "mls_encrypted_message",
        "signature",
    );
    assert_eq!(send_msg.action, "sendGroup");

    // 3. Other users fetch messages
    let fetch_msg = MixnetMessage::fetch_group("bob", 42, "signature");
    assert_eq!(fetch_msg.action, "fetchGroup");

    Ok(())
}

/// Test database state transitions during registration
#[tokio::test]
async fn test_registration_db_state() -> Result<()> {
    let ctx = TestContext::new().await?;

    // Initially no users
    let count = common::count_records(&ctx.db, "users").await?;
    assert_eq!(count, 0);

    // After registration
    common::seed_users(&ctx.db, &[("alice", "pk_alice")]).await?;

    let count = common::count_records(&ctx.db, "users").await?;
    assert_eq!(count, 1);

    // Query the user
    let user: (String, String) = sqlx::query_as(
        "SELECT username, public_key FROM users WHERE username = ?",
    )
    .bind("alice")
    .fetch_one(&ctx.db)
    .await?;

    assert_eq!(user.0, "alice");
    assert_eq!(user.1, "pk_alice");

    Ok(())
}

/// Test full conversation lifecycle
#[tokio::test]
async fn test_conversation_lifecycle() -> Result<()> {
    let ctx = TestContext::new().await?;

    // 1. Create users
    common::seed_users(&ctx.db, &[("alice", "pk_alice"), ("bob", "pk_bob")]).await?;

    // 2. Create conversation
    sqlx::query(
        "INSERT INTO conversations (id, type, participant, mls_group_id) VALUES (?, ?, ?, ?)",
    )
    .bind("conv-alice-bob")
    .bind("dm")
    .bind("bob")
    .bind("mls-group-123")
    .execute(&ctx.db)
    .await?;

    // 3. Store MLS group state
    sqlx::query("INSERT INTO mls_groups (conversation_id, group_state) VALUES (?, ?)")
        .bind("conv-alice-bob")
        .bind(vec![1u8, 2, 3, 4, 5])
        .execute(&ctx.db)
        .await?;

    // 4. Exchange messages
    for i in 1..=3 {
        let sender = if i % 2 == 0 { "bob" } else { "alice" };
        sqlx::query(
            r#"
            INSERT INTO messages (id, conversation_id, sender, content, timestamp, status, is_own)
            VALUES (?, ?, ?, ?, datetime('now'), ?, ?)
            "#,
        )
        .bind(format!("msg-{}", i))
        .bind("conv-alice-bob")
        .bind(sender)
        .bind(format!("Message {}", i))
        .bind("delivered")
        .bind(sender == "alice")
        .execute(&ctx.db)
        .await?;
    }

    // Verify state
    let msg_count = common::count_records(&ctx.db, "messages").await?;
    assert_eq!(msg_count, 3);

    let conv_count = common::count_records(&ctx.db, "conversations").await?;
    assert_eq!(conv_count, 1);

    Ok(())
}

/// Test epoch buffer integration with message processing
#[tokio::test]
async fn test_epoch_buffer_integration() -> Result<()> {
    let ctx = TestContext::new().await?;

    // Simulate out-of-order messages arriving
    for i in 1..=3 {
        sqlx::query(
            r#"
            INSERT INTO pending_mls_messages
            (conversation_id, sender, mls_message_b64, received_at, retry_count, processed, failed)
            VALUES (?, ?, ?, datetime('now'), ?, ?, ?)
            "#,
        )
        .bind("conv-123")
        .bind("bob")
        .bind(format!("mls_msg_{}", i))
        .bind(0)
        .bind(0) // not processed
        .bind(0) // not failed
        .execute(&ctx.db)
        .await?;
    }

    // Check pending count (processed = 0 AND failed = 0)
    let pending: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM pending_mls_messages WHERE processed = 0 AND failed = 0",
    )
    .fetch_one(&ctx.db)
    .await?;
    assert_eq!(pending.0, 3);

    // Mark one as processed
    sqlx::query(
        "UPDATE pending_mls_messages SET processed = 1 WHERE mls_message_b64 = ?",
    )
    .bind("mls_msg_1")
    .execute(&ctx.db)
    .await?;

    let pending: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM pending_mls_messages WHERE processed = 0 AND failed = 0",
    )
    .fetch_one(&ctx.db)
    .await?;
    assert_eq!(pending.0, 2);

    Ok(())
}

/// Test multi-user group scenario
#[tokio::test]
async fn test_multi_user_group() -> Result<()> {
    let ctx = TestContext::new().await?;

    // Create users
    common::seed_users(
        &ctx.db,
        &[
            ("alice", "pk_alice"),
            ("bob", "pk_bob"),
            ("charlie", "pk_charlie"),
        ],
    )
    .await?;

    // Create group memberships
    let server = "group-server-1";
    let members = vec![
        ("alice", "admin"),
        ("bob", "member"),
        ("charlie", "member"),
    ];

    for (user, role) in members {
        sqlx::query(
            r#"
            INSERT INTO group_memberships (server_address, username, mls_group_id, role)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(server)
        .bind(user)
        .bind("mls-group-123")
        .bind(role)
        .execute(&ctx.db)
        .await?;

        // Add to group_members
        sqlx::query(
            "INSERT INTO group_members (conversation_id, member_username, role) VALUES (?, ?, ?)",
        )
        .bind("conv-group-123")
        .bind(user)
        .bind(role)
        .execute(&ctx.db)
        .await?;
    }

    // Verify memberships
    let membership_count = common::count_records(&ctx.db, "group_memberships").await?;
    assert_eq!(membership_count, 3);

    let member_count = common::count_records(&ctx.db, "group_members").await?;
    assert_eq!(member_count, 3);

    // Query admin
    let admin: (String,) = sqlx::query_as(
        "SELECT member_username FROM group_members WHERE conversation_id = ? AND role = 'admin'",
    )
    .bind("conv-group-123")
    .fetch_one(&ctx.db)
    .await?;
    assert_eq!(admin.0, "alice");

    Ok(())
}

/// Test message serialization roundtrip
#[tokio::test]
async fn test_message_serialization_roundtrip() -> Result<()> {
    let original = MixnetMessage::send(
        "alice",
        "bob",
        "encrypted_content",
        "conv-123",
        "signature123",
    );

    let json = original.to_json()?;
    let deserialized: MixnetMessage = serde_json::from_str(&json)?;

    assert_eq!(deserialized.message_type, original.message_type);
    assert_eq!(deserialized.action, original.action);
    assert_eq!(deserialized.sender, original.sender);
    assert_eq!(deserialized.recipient, original.recipient);
    assert_eq!(deserialized.signature, original.signature);
    assert_eq!(deserialized.payload["conversation_id"], original.payload["conversation_id"]);

    Ok(())
}

/// Test payload signing format
#[test]
fn test_payload_for_signing() {
    let msg = MixnetMessage::send("alice", "bob", "content", "conv-123", "sig");
    let payload_str = msg.payload_for_signing().unwrap();

    // Should be valid JSON
    let _: serde_json::Value = serde_json::from_str(&payload_str).unwrap();

    // Should contain expected fields
    assert!(payload_str.contains("conversation_id"));
    assert!(payload_str.contains("mls_message"));
}
