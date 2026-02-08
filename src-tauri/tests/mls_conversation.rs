//! Integration tests for MLS conversation flows
//!
//! Tests the MLS protocol integration for establishing and managing
//! encrypted conversations.

mod common;

use anyhow::Result;
use nymstr_app_v2_lib::core::messages::MixnetMessage;
use common::TestContext;

/// Test key package request message format
#[tokio::test]
async fn test_key_package_request_format() -> Result<()> {
    let msg = MixnetMessage::key_package_request(
        "alice",
        "bob",
        "signature",
    );

    assert_eq!(msg.message_type, "system");
    assert_eq!(msg.action, "keyPackageRequest");
    assert_eq!(msg.sender, "alice");
    assert_eq!(msg.recipient, "bob");

    Ok(())
}

/// Test key package response message format
#[tokio::test]
async fn test_key_package_response_format() -> Result<()> {
    let msg = MixnetMessage::key_package_response(
        "bob",
        "alice",
        "bob_key_package_b64",
        "alice_key_package_b64",
        "signature",
    );

    assert_eq!(msg.message_type, "system");
    assert_eq!(msg.action, "keyPackageResponse");
    assert_eq!(msg.sender, "bob");
    assert_eq!(msg.recipient, "alice");
    assert_eq!(msg.payload["senderKeyPackage"], "bob_key_package_b64");
    assert_eq!(msg.payload["recipientKeyPackage"], "alice_key_package_b64");

    Ok(())
}

/// Test direct message format
#[tokio::test]
async fn test_direct_message_format() -> Result<()> {
    let msg = MixnetMessage::direct_message(
        "alice",
        "bob",
        "mls_encrypted_content",
        "conversation-123",
        "signature",
    );

    assert_eq!(msg.message_type, "message");
    assert_eq!(msg.action, "send");
    assert_eq!(msg.sender, "alice");
    assert_eq!(msg.recipient, "bob");
    assert_eq!(msg.payload["conversation_id"], "conversation-123");
    assert_eq!(msg.payload["mls_message"], "mls_encrypted_content");

    Ok(())
}

/// Test MLS message raw format (with byte arrays)
#[tokio::test]
async fn test_mls_message_raw_format() -> Result<()> {
    let conv_id = b"conversation-bytes";
    let mls_message = b"encrypted-mls-message-bytes";

    let msg = MixnetMessage::mls_message_raw(
        "alice",
        "bob",
        conv_id,
        mls_message,
        "signature",
    );

    assert_eq!(msg.message_type, "message");
    assert_eq!(msg.action, "send");
    assert_eq!(msg.sender, "alice");
    assert_eq!(msg.recipient, "bob");

    // Check that the fields are base64 encoded
    use base64::Engine;
    let expected_conv = base64::engine::general_purpose::STANDARD.encode(conv_id);
    let expected_mls = base64::engine::general_purpose::STANDARD.encode(mls_message);

    assert_eq!(msg.payload["conversation_id"], expected_conv);
    assert_eq!(msg.payload["mls_message"], expected_mls);

    Ok(())
}

/// Test MLS credentials storage
#[tokio::test]
async fn test_mls_credentials_storage() -> Result<()> {
    let ctx = TestContext::new().await?;

    // Insert MLS credentials
    sqlx::query(
        r#"
        INSERT INTO mls_credentials (username, pgp_key_fingerprint, mls_signature_key, credential_type, issued_at)
        VALUES (?, ?, ?, ?, ?)
        "#,
    )
    .bind("alice")
    .bind(vec![1u8, 2, 3, 4, 5, 6, 7, 8])
    .bind(vec![10u8, 20, 30, 40])
    .bind("basic")
    .bind(1706000000i64)
    .execute(&ctx.db)
    .await?;

    // Query credentials
    let cred: (String, Vec<u8>, String) = sqlx::query_as(
        "SELECT username, pgp_key_fingerprint, credential_type FROM mls_credentials WHERE username = ?",
    )
    .bind("alice")
    .fetch_one(&ctx.db)
    .await?;

    assert_eq!(cred.0, "alice");
    assert_eq!(cred.1, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(cred.2, "basic");

    Ok(())
}

/// Test key packages storage
#[tokio::test]
async fn test_key_packages_storage() -> Result<()> {
    let ctx = TestContext::new().await?;

    // Insert a key package
    sqlx::query(
        r#"
        INSERT INTO key_packages (key_package_b64, credential_username, cipher_suite, used)
        VALUES (?, ?, ?, ?)
        "#,
    )
    .bind("key_package_data_b64")
    .bind("alice")
    .bind("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")
    .bind(0)
    .execute(&ctx.db)
    .await?;

    // Query unused key packages
    let packages: Vec<(String, String, i32)> = sqlx::query_as(
        "SELECT key_package_b64, credential_username, used FROM key_packages WHERE used = 0",
    )
    .fetch_all(&ctx.db)
    .await?;

    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].0, "key_package_data_b64");
    assert_eq!(packages[0].1, "alice");
    assert_eq!(packages[0].2, 0);

    // Mark as used
    sqlx::query("UPDATE key_packages SET used = 1 WHERE credential_username = ?")
        .bind("alice")
        .execute(&ctx.db)
        .await?;

    let packages: Vec<(i32,)> =
        sqlx::query_as("SELECT used FROM key_packages WHERE credential_username = ?")
            .bind("alice")
            .fetch_all(&ctx.db)
            .await?;

    assert_eq!(packages[0].0, 1);

    Ok(())
}

/// Test MLS groups storage
#[tokio::test]
async fn test_mls_groups_storage() -> Result<()> {
    let ctx = TestContext::new().await?;

    // Insert MLS group state
    let group_state = vec![1u8, 2, 3, 4, 5]; // Simulated serialized MLS group

    sqlx::query(
        "INSERT INTO mls_groups (conversation_id, group_state) VALUES (?, ?)",
    )
    .bind("conv-123")
    .bind(&group_state)
    .execute(&ctx.db)
    .await?;

    // Query group state
    let (stored_state,): (Vec<u8>,) = sqlx::query_as(
        "SELECT group_state FROM mls_groups WHERE conversation_id = ?",
    )
    .bind("conv-123")
    .fetch_one(&ctx.db)
    .await?;

    assert_eq!(stored_state, group_state);

    // Update group state
    let new_state = vec![6u8, 7, 8, 9, 10];
    sqlx::query(
        "UPDATE mls_groups SET group_state = ?, updated_at = datetime('now') WHERE conversation_id = ?",
    )
    .bind(&new_state)
    .bind("conv-123")
    .execute(&ctx.db)
    .await?;

    let (updated_state,): (Vec<u8>,) = sqlx::query_as(
        "SELECT group_state FROM mls_groups WHERE conversation_id = ?",
    )
    .bind("conv-123")
    .fetch_one(&ctx.db)
    .await?;

    assert_eq!(updated_state, new_state);

    Ok(())
}

/// Test conversations storage
#[tokio::test]
async fn test_conversations_storage() -> Result<()> {
    let ctx = TestContext::new().await?;

    // Insert a DM conversation
    sqlx::query(
        "INSERT INTO conversations (id, mls_group_id) VALUES (?, ?)",
    )
    .bind("conv-dm-123")
    .bind("mls-group-456")
    .execute(&ctx.db)
    .await?;

    // Insert a group conversation
    sqlx::query(
        "INSERT INTO conversations (id, mls_group_id) VALUES (?, ?)",
    )
    .bind("conv-group-789")
    .bind("mls-group-789")
    .execute(&ctx.db)
    .await?;

    // Query conversations
    let convs: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT id, mls_group_id FROM conversations ORDER BY id",
    )
    .fetch_all(&ctx.db)
    .await?;

    assert_eq!(convs.len(), 2);
    assert_eq!(convs[0].0, "conv-dm-123");
    assert_eq!(convs[0].1, Some("mls-group-456".to_string()));

    assert_eq!(convs[1].0, "conv-group-789");
    assert_eq!(convs[1].1, Some("mls-group-789".to_string()));

    Ok(())
}

/// Test messages storage
#[tokio::test]
async fn test_messages_storage() -> Result<()> {
    let ctx = TestContext::new().await?;

    // Insert messages
    for i in 1..=5 {
        sqlx::query(
            r#"
            INSERT INTO messages (id, conversation_id, sender, content, timestamp, status, is_own)
            VALUES (?, ?, ?, ?, datetime('now'), ?, ?)
            "#,
        )
        .bind(format!("msg-{}", i))
        .bind("conv-123")
        .bind(if i % 2 == 0 { "alice" } else { "bob" })
        .bind(format!("Message content {}", i))
        .bind("delivered")
        .bind(i % 2 == 0)
        .execute(&ctx.db)
        .await?;
    }

    // Query messages for conversation
    let messages: Vec<(String, String, String, i32)> = sqlx::query_as(
        "SELECT id, sender, content, is_own FROM messages WHERE conversation_id = ? ORDER BY id",
    )
    .bind("conv-123")
    .fetch_all(&ctx.db)
    .await?;

    assert_eq!(messages.len(), 5);
    assert_eq!(messages[0].1, "bob"); // msg-1 from bob
    assert_eq!(messages[1].1, "alice"); // msg-2 from alice
    assert_eq!(messages[0].3, 0); // is_own = false for bob's message

    Ok(())
}

/// Test send message format (with conversation_id and mls_message)
#[tokio::test]
async fn test_send_message_format() -> Result<()> {
    let msg = MixnetMessage::send(
        "alice",
        "bob",
        "encrypted_mls_content",
        "conversation-123",
        "signature",
    );

    assert_eq!(msg.message_type, "message");
    assert_eq!(msg.action, "send");
    assert_eq!(msg.sender, "alice");
    assert_eq!(msg.recipient, "bob");
    assert_eq!(msg.payload["conversation_id"], "conversation-123");
    assert_eq!(msg.payload["mls_message"], "encrypted_mls_content");

    Ok(())
}

/// Test challenge message format
#[tokio::test]
async fn test_challenge_message_format() -> Result<()> {
    let msg = MixnetMessage::challenge("server", "alice", "nonce123", "registration");

    assert_eq!(msg.message_type, "system");
    assert_eq!(msg.action, "challenge");
    assert_eq!(msg.sender, "server");
    assert_eq!(msg.recipient, "alice");
    assert_eq!(msg.payload["nonce"], "nonce123");
    assert_eq!(msg.payload["context"], "registration");

    Ok(())
}

/// Test challenge response message format
#[tokio::test]
async fn test_challenge_response_format() -> Result<()> {
    // Registration context
    let msg = MixnetMessage::challenge_response("alice", "server", "signed_nonce", "registration");

    assert_eq!(msg.message_type, "system");
    assert_eq!(msg.action, "registrationResponse");
    assert_eq!(msg.payload["signature"], "signed_nonce");
    assert_eq!(msg.payload["context"], "registration");

    // Login context
    let msg_login = MixnetMessage::challenge_response("alice", "server", "signed_nonce", "login");
    assert_eq!(msg_login.action, "loginResponse");

    Ok(())
}

/// Test contacts storage
#[tokio::test]
async fn test_contacts_storage() -> Result<()> {
    let ctx = TestContext::new().await?;

    // Add contacts for alice
    let contacts = vec![("bob", "pk_bob"), ("charlie", "pk_charlie")];

    for (username, public_key) in &contacts {
        sqlx::query(
            r#"
            INSERT INTO contacts (owner_username, username, display_name, public_key)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind("alice")
        .bind(username)
        .bind(username)
        .bind(public_key)
        .execute(&ctx.db)
        .await?;
    }

    // Query alice's contacts
    let result: Vec<(String, String)> = sqlx::query_as(
        "SELECT username, public_key FROM contacts WHERE owner_username = ? ORDER BY username",
    )
    .bind("alice")
    .fetch_all(&ctx.db)
    .await?;

    assert_eq!(result.len(), 2);
    assert_eq!(result[0].0, "bob");
    assert_eq!(result[1].0, "charlie");

    Ok(())
}
