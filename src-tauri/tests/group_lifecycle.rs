//! Group Lifecycle Integration Tests
//!
//! Tests a realistic group lifecycle over time including:
//! - Group creation
//! - Member joining
//! - Message exchanges
//! - Member removal
//! - New members after removal
//!
//! All operations are interspersed with messages to simulate real usage.

mod common;

use anyhow::Result;
use base64::Engine;
use nymstr_app_v2_lib::crypto::mls::MlsClient;
use nymstr_app_v2_lib::crypto::pgp::{PgpKeyManager, SecurePassphrase};
use pgp::composed::{SignedPublicKey, SignedSecretKey};
use std::sync::Arc;

/// A test user with PGP keys for MLS testing
struct TestUser {
    username: String,
    secret_key: Arc<SignedSecretKey>,
    public_key: Arc<SignedPublicKey>,
    passphrase: Arc<SecurePassphrase>,
}

impl TestUser {
    /// Create a new test user with generated PGP keys
    fn new(username: &str) -> Result<Self> {
        let passphrase = SecurePassphrase::generate_strong();
        let (secret_key, public_key) =
            PgpKeyManager::generate_keypair_secure(username, &passphrase)?;

        Ok(Self {
            username: username.to_string(),
            secret_key: Arc::new(secret_key),
            public_key: Arc::new(public_key),
            passphrase: Arc::new(passphrase),
        })
    }

    fn username(&self) -> &str {
        &self.username
    }
}

/// Helper struct to manage test MLS clients with proper cleanup
struct TestMlsClient {
    client: MlsClient,
    #[allow(dead_code)]
    user: TestUser,
    _temp_dir: tempfile::TempDir,
}

impl TestMlsClient {
    fn new(user: TestUser) -> Result<Self> {
        let temp_dir = tempfile::tempdir()?;
        let client = MlsClient::new(
            user.username(),
            Arc::clone(&user.secret_key),
            Arc::clone(&user.public_key),
            &user.passphrase,
            temp_dir.path().to_path_buf(),
        )?;
        Ok(Self {
            client,
            user,
            _temp_dir: temp_dir,
        })
    }
}

/// Helper to create a test user and their MLS client
fn create_user_with_client(username: &str) -> Result<TestMlsClient> {
    let user = TestUser::new(username)?;
    TestMlsClient::new(user)
}

/// Test a complete group lifecycle with realistic usage patterns
/// Note: In MLS, you cannot decrypt your own messages, so we test
/// message exchange between different members.
#[tokio::test]
async fn test_complete_group_lifecycle() -> Result<()> {
    // ========== Phase 1: Group Creation ==========
    println!("\n=== Phase 1: Alice creates the group ===");

    let alice = create_user_with_client("alice")?;

    // Alice creates the group
    let group_info = alice.client.create_mls_group("test-group-lifecycle").await?;
    let group_id = group_info.mls_group_id.clone();
    let group_id_bytes = base64::engine::general_purpose::STANDARD.decode(&group_id)?;

    let initial_epoch = alice.client.get_group_epoch(&group_id)?;
    println!("Group created at epoch {}", initial_epoch);

    assert_eq!(initial_epoch, 0);
    let mut message_count = 0;

    // ========== Phase 2: Bob joins the group ==========
    println!("\n=== Phase 2: Bob joins the group ===");

    let bob = create_user_with_client("bob")?;

    // Bob generates a key package
    let bob_key_package = bob.client.generate_key_package()?;

    // Alice adds Bob to the group
    let add_result = alice.client.add_member_to_group(&group_id, &bob_key_package).await?;

    let epoch = add_result.new_epoch;
    println!("Bob added, epoch now: {}", epoch);

    // Bob processes the welcome message to join
    let joined_group_id = bob.client.process_welcome(&add_result.welcome).await?;
    assert_eq!(joined_group_id, group_id);

    // ========== Phase 3: Alice and Bob exchange messages ==========
    println!("\n=== Phase 3: Alice and Bob exchange messages ===");

    // Alice sends a message
    {
        let plaintext = "Hey Bob, welcome to the group!";
        let encrypted = alice.client.encrypt_message(&group_id_bytes, plaintext.as_bytes()).await?;

        // Bob decrypts Alice's message
        let decrypted = bob.client.decrypt_message(&encrypted).await?;
        assert_eq!(String::from_utf8(decrypted)?, plaintext);

        message_count += 1;
        println!("Alice -> Bob: {}", plaintext);
    }

    // Bob replies
    {
        let plaintext = "Thanks Alice! Excited to be here.";
        let encrypted = bob.client.encrypt_message(&group_id_bytes, plaintext.as_bytes()).await?;

        // Alice decrypts Bob's message
        let decrypted = alice.client.decrypt_message(&encrypted).await?;
        assert_eq!(String::from_utf8(decrypted)?, plaintext);

        message_count += 1;
        println!("Bob -> Alice: {}", plaintext);
    }

    // A few more exchanges
    for i in 1..=2 {
        let msg = format!("Status update #{}", i);
        let encrypted = alice.client.encrypt_message(&group_id_bytes, msg.as_bytes()).await?;

        let decrypted = bob.client.decrypt_message(&encrypted).await?;
        assert_eq!(String::from_utf8(decrypted)?, msg);

        message_count += 1;
        println!("Alice: {}", msg);
    }

    // ========== Phase 4: Charlie joins ==========
    println!("\n=== Phase 4: Charlie joins the group ===");

    let charlie = create_user_with_client("charlie")?;

    let charlie_key_package = charlie.client.generate_key_package()?;

    let add_result = alice.client.add_member_to_group(&group_id, &charlie_key_package).await?;

    // Bob needs to process the commit to stay in sync
    let commit_bytes = add_result.decode_commit_bytes()?;
    let bob_epoch = bob.client.process_commit(&group_id, &commit_bytes)?;

    let epoch = add_result.new_epoch;
    println!("Charlie added, epoch now: {} (Bob's epoch: {})", epoch, bob_epoch);
    assert_eq!(bob_epoch, epoch);

    // Charlie processes welcome
    let joined = charlie.client.process_welcome(&add_result.welcome).await?;
    assert_eq!(joined, group_id);

    // ========== Phase 5: Three-way conversation ==========
    println!("\n=== Phase 5: Three-way conversation ===");

    // Alice announces Charlie
    {
        let plaintext = "Everyone, please welcome Charlie!";
        let encrypted = alice.client.encrypt_message(&group_id_bytes, plaintext.as_bytes()).await?;

        let bob_decrypted = bob.client.decrypt_message(&encrypted).await?;
        let charlie_decrypted = charlie.client.decrypt_message(&encrypted).await?;

        assert_eq!(String::from_utf8(bob_decrypted)?, plaintext);
        assert_eq!(String::from_utf8(charlie_decrypted)?, plaintext);

        message_count += 1;
        println!("Alice: {}", plaintext);
    }

    // Bob says hi
    {
        let plaintext = "Hi Charlie! Welcome aboard!";
        let encrypted = bob.client.encrypt_message(&group_id_bytes, plaintext.as_bytes()).await?;

        let alice_decrypted = alice.client.decrypt_message(&encrypted).await?;
        let charlie_decrypted = charlie.client.decrypt_message(&encrypted).await?;

        assert_eq!(String::from_utf8(alice_decrypted)?, plaintext);
        assert_eq!(String::from_utf8(charlie_decrypted)?, plaintext);

        message_count += 1;
        println!("Bob: {}", plaintext);
    }

    // Charlie responds
    {
        let plaintext = "Thanks everyone! Happy to be here.";
        let encrypted = charlie.client.encrypt_message(&group_id_bytes, plaintext.as_bytes()).await?;

        let alice_decrypted = alice.client.decrypt_message(&encrypted).await?;
        let bob_decrypted = bob.client.decrypt_message(&encrypted).await?;

        assert_eq!(String::from_utf8(alice_decrypted)?, plaintext);
        assert_eq!(String::from_utf8(bob_decrypted)?, plaintext);

        message_count += 1;
        println!("Charlie: {}", plaintext);
    }

    // ========== Phase 6: Dave and Eve join ==========
    println!("\n=== Phase 6: Dave and Eve join ===");

    let dave = create_user_with_client("dave")?;
    let eve = create_user_with_client("eve")?;

    // Add Dave
    let dave_key_package = dave.client.generate_key_package()?;
    let dave_add_result = alice.client.add_member_to_group(&group_id, &dave_key_package).await?;

    // Existing members process commit
    let commit_bytes = dave_add_result.decode_commit_bytes()?;
    bob.client.process_commit(&group_id, &commit_bytes)?;
    charlie.client.process_commit(&group_id, &commit_bytes)?;

    // Dave joins
    dave.client.process_welcome(&dave_add_result.welcome).await?;
    println!("Dave added, epoch now: {}", dave_add_result.new_epoch);

    // Add Eve
    let eve_key_package = eve.client.generate_key_package()?;
    let eve_add_result = alice.client.add_member_to_group(&group_id, &eve_key_package).await?;

    // Existing members process commit
    let commit_bytes = eve_add_result.decode_commit_bytes()?;
    bob.client.process_commit(&group_id, &commit_bytes)?;
    charlie.client.process_commit(&group_id, &commit_bytes)?;
    dave.client.process_commit(&group_id, &commit_bytes)?;

    // Eve joins
    eve.client.process_welcome(&eve_add_result.welcome).await?;
    let epoch = eve_add_result.new_epoch;
    println!("Eve added, epoch now: {}", epoch);

    // ========== Phase 7: Five-person chat ==========
    println!("\n=== Phase 7: Five-person chat ===");

    // Alice sends and everyone else decrypts
    {
        let plaintext = "Group is getting big! 5 members now.";
        let encrypted = alice.client.encrypt_message(&group_id_bytes, plaintext.as_bytes()).await?;
        assert_eq!(String::from_utf8(bob.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(charlie.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(dave.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(eve.client.decrypt_message(&encrypted).await?)?, plaintext);
        message_count += 1;
        println!("Alice: {}", plaintext);
    }

    // Bob sends
    {
        let plaintext = "This is exciting!";
        let encrypted = bob.client.encrypt_message(&group_id_bytes, plaintext.as_bytes()).await?;
        assert_eq!(String::from_utf8(alice.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(charlie.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(dave.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(eve.client.decrypt_message(&encrypted).await?)?, plaintext);
        message_count += 1;
        println!("Bob: {}", plaintext);
    }

    // Charlie sends
    {
        let plaintext = "Let's get started on the project.";
        let encrypted = charlie.client.encrypt_message(&group_id_bytes, plaintext.as_bytes()).await?;
        assert_eq!(String::from_utf8(alice.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(bob.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(dave.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(eve.client.decrypt_message(&encrypted).await?)?, plaintext);
        message_count += 1;
        println!("Charlie: {}", plaintext);
    }

    // Dave sends
    {
        let plaintext = "I'm new here but ready to contribute.";
        let encrypted = dave.client.encrypt_message(&group_id_bytes, plaintext.as_bytes()).await?;
        assert_eq!(String::from_utf8(alice.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(bob.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(charlie.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(eve.client.decrypt_message(&encrypted).await?)?, plaintext);
        message_count += 1;
        println!("Dave: {}", plaintext);
    }

    // Eve sends
    {
        let plaintext = "Same here! Looking forward to working together.";
        let encrypted = eve.client.encrypt_message(&group_id_bytes, plaintext.as_bytes()).await?;
        assert_eq!(String::from_utf8(alice.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(bob.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(charlie.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(dave.client.decrypt_message(&encrypted).await?)?, plaintext);
        message_count += 1;
        println!("Eve: {}", plaintext);
    }

    // ========== Phase 8: Bob is removed ==========
    println!("\n=== Phase 8: Alice removes Bob from the group ===");

    let pre_remove_epoch = alice.client.get_group_epoch(&group_id)?;

    // Alice removes Bob
    let remove_result = alice.client.remove_member_from_group(&group_id, "bob").await?;

    let epoch = remove_result.new_epoch;
    println!(
        "Bob removed by Alice, epoch changed from {} to {}",
        pre_remove_epoch, epoch
    );

    // Remaining members process the remove commit
    let commit_bytes = remove_result.decode_commit_bytes()?;
    charlie.client.process_commit(&group_id, &commit_bytes)?;
    dave.client.process_commit(&group_id, &commit_bytes)?;
    eve.client.process_commit(&group_id, &commit_bytes)?;

    // Alice announces the removal
    {
        let plaintext = "Bob has left the group.";
        let encrypted = alice.client.encrypt_message(&group_id_bytes, plaintext.as_bytes()).await?;

        // Remaining members can decrypt
        assert_eq!(String::from_utf8(charlie.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(dave.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(eve.client.decrypt_message(&encrypted).await?)?, plaintext);

        message_count += 1;
        println!("Alice: {}", plaintext);
    }

    // ========== Phase 9: Messages after removal ==========
    println!("\n=== Phase 9: Messages after Bob's removal ===");

    // Chat continues without Bob
    {
        let plaintext = "Moving forward with the plan.";
        let encrypted = charlie.client.encrypt_message(&group_id_bytes, plaintext.as_bytes()).await?;
        assert_eq!(String::from_utf8(alice.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(dave.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(eve.client.decrypt_message(&encrypted).await?)?, plaintext);
        message_count += 1;
        println!("Charlie: {}", plaintext);
    }

    {
        let plaintext = "I can help with the implementation.";
        let encrypted = dave.client.encrypt_message(&group_id_bytes, plaintext.as_bytes()).await?;
        assert_eq!(String::from_utf8(alice.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(charlie.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(eve.client.decrypt_message(&encrypted).await?)?, plaintext);
        message_count += 1;
        println!("Dave: {}", plaintext);
    }

    {
        let plaintext = "I'll handle the documentation.";
        let encrypted = eve.client.encrypt_message(&group_id_bytes, plaintext.as_bytes()).await?;
        assert_eq!(String::from_utf8(alice.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(charlie.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(dave.client.decrypt_message(&encrypted).await?)?, plaintext);
        message_count += 1;
        println!("Eve: {}", plaintext);
    }

    {
        let plaintext = "Great teamwork everyone!";
        let encrypted = alice.client.encrypt_message(&group_id_bytes, plaintext.as_bytes()).await?;
        assert_eq!(String::from_utf8(charlie.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(dave.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(eve.client.decrypt_message(&encrypted).await?)?, plaintext);
        message_count += 1;
        println!("Alice: {}", plaintext);
    }

    // ========== Phase 10: Frank joins as Bob's replacement ==========
    println!("\n=== Phase 10: Frank joins as Bob's replacement ===");

    let frank = create_user_with_client("frank")?;

    let frank_key_package = frank.client.generate_key_package()?;
    let frank_add_result = alice.client.add_member_to_group(&group_id, &frank_key_package).await?;

    // Existing members process commit
    let commit_bytes = frank_add_result.decode_commit_bytes()?;
    charlie.client.process_commit(&group_id, &commit_bytes)?;
    dave.client.process_commit(&group_id, &commit_bytes)?;
    eve.client.process_commit(&group_id, &commit_bytes)?;

    // Frank joins
    frank.client.process_welcome(&frank_add_result.welcome).await?;
    let final_epoch = frank_add_result.new_epoch;

    println!("Frank added, epoch now: {}", final_epoch);

    // ========== Phase 11: Final round of messages ==========
    println!("\n=== Phase 11: Final round of messages ===");

    // Welcome Frank and close out the test
    {
        let plaintext = "Welcome Frank! You're replacing Bob on the project.";
        let encrypted = alice.client.encrypt_message(&group_id_bytes, plaintext.as_bytes()).await?;

        assert_eq!(String::from_utf8(charlie.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(dave.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(eve.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(frank.client.decrypt_message(&encrypted).await?)?, plaintext);

        message_count += 1;
        println!("Alice: {}", plaintext);
    }

    {
        let plaintext = "Thanks Alice! I'm ready to get started.";
        let encrypted = frank.client.encrypt_message(&group_id_bytes, plaintext.as_bytes()).await?;

        assert_eq!(String::from_utf8(alice.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(charlie.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(dave.client.decrypt_message(&encrypted).await?)?, plaintext);
        assert_eq!(String::from_utf8(eve.client.decrypt_message(&encrypted).await?)?, plaintext);

        message_count += 1;
        println!("Frank: {}", plaintext);
    }

    // ========== Verification ==========
    println!("\n=== Verification ===");
    println!("Total messages exchanged: {}", message_count);
    println!("Final epoch: {}", final_epoch);

    // The epoch should have advanced multiple times:
    // - 0: Group created
    // - 1: Bob added
    // - 2: Charlie added
    // - 3: Dave added
    // - 4: Eve added
    // - 5: Bob removed
    // - 6: Frank added
    assert!(final_epoch >= 6, "Expected at least 6 epoch changes, got {}", final_epoch);

    // Verify message count
    assert!(message_count >= 15, "Expected at least 15 messages, got {}", message_count);

    println!("\nGroup lifecycle test completed successfully!");

    Ok(())
}

/// Test that removed members cannot decrypt new messages (forward secrecy)
#[tokio::test]
async fn test_forward_secrecy_after_removal() -> Result<()> {
    println!("\n=== Testing forward secrecy after member removal ===");

    // Create Alice (admin) and Bob
    let alice = create_user_with_client("alice")?;
    let bob = create_user_with_client("bob")?;

    // Alice creates group and adds Bob
    let group_info = alice.client.create_mls_group("forward-secrecy-test").await?;
    let group_id = group_info.mls_group_id.clone();
    let group_id_bytes = base64::engine::general_purpose::STANDARD.decode(&group_id)?;

    let bob_key_package = bob.client.generate_key_package()?;
    let add_result = alice.client.add_member_to_group(&group_id, &bob_key_package).await?;
    bob.client.process_welcome(&add_result.welcome).await?;

    // Verify Bob can decrypt messages before removal
    let pre_removal_msg = "Message before removal";
    let encrypted = alice.client.encrypt_message(&group_id_bytes, pre_removal_msg.as_bytes()).await?;
    let decrypted = bob.client.decrypt_message(&encrypted).await?;
    assert_eq!(String::from_utf8(decrypted)?, pre_removal_msg);
    println!("Bob successfully decrypted message before removal");

    // Alice removes Bob
    let _remove_result = alice.client.remove_member_from_group(&group_id, "bob").await?;
    println!("Bob removed from group");

    // Alice sends a new message after removal
    let post_removal_msg = "Secret message after Bob was removed";
    let encrypted_after = alice.client.encrypt_message(&group_id_bytes, post_removal_msg.as_bytes()).await?;

    // Bob should NOT be able to decrypt the new message
    // His group state is at the old epoch
    let bob_decrypt_result = bob.client.decrypt_message(&encrypted_after).await;

    // This should fail because Bob's group state hasn't been updated
    // and the message is encrypted for the new epoch
    assert!(
        bob_decrypt_result.is_err(),
        "Bob should not be able to decrypt messages after removal"
    );
    println!("Forward secrecy verified: Bob cannot decrypt post-removal messages");

    Ok(())
}

/// Test rapid successive member additions
#[tokio::test]
async fn test_rapid_member_additions() -> Result<()> {
    println!("\n=== Testing rapid successive member additions ===");

    let alice = create_user_with_client("alice")?;
    let group_info = alice.client.create_mls_group("rapid-additions-test").await?;
    let group_id = group_info.mls_group_id.clone();

    let mut members: Vec<TestMlsClient> = vec![];
    let mut epoch = alice.client.get_group_epoch(&group_id)?;

    // Rapidly add 5 members
    for i in 0..5 {
        let username = format!("user_{}", i);
        let client = create_user_with_client(&username)?;

        let key_package = client.client.generate_key_package()?;
        let add_result = alice.client.add_member_to_group(&group_id, &key_package).await?;

        // Existing members process commit
        let commit_bytes = add_result.decode_commit_bytes()?;
        for member in &members {
            member.client.process_commit(&group_id, &commit_bytes)?;
        }

        // New member processes welcome
        client.client.process_welcome(&add_result.welcome).await?;

        members.push(client);
        epoch = add_result.new_epoch;

        println!("Added {}, epoch now: {}", username, epoch);
    }

    // Verify all 6 members (alice + 5 users) can communicate
    let group_id_bytes = base64::engine::general_purpose::STANDARD.decode(&group_id)?;
    let test_msg = "Test message to all members";
    let encrypted = alice.client.encrypt_message(&group_id_bytes, test_msg.as_bytes()).await?;

    for member in &members {
        let decrypted = member.client.decrypt_message(&encrypted).await?;
        assert_eq!(String::from_utf8(decrypted)?, test_msg);
    }

    println!("All {} members can decrypt messages successfully", members.len() + 1);

    // Verify epoch advanced correctly (one per addition)
    assert_eq!(epoch, 5, "Expected epoch 5 after 5 additions");

    Ok(())
}

/// Test message exchange across multiple epoch changes
#[tokio::test]
async fn test_messages_across_epoch_changes() -> Result<()> {
    println!("\n=== Testing messages across epoch changes ===");

    let alice = create_user_with_client("alice")?;
    let bob = create_user_with_client("bob")?;
    let charlie = create_user_with_client("charlie")?;

    // Create group and immediately add Bob so we can test message exchange
    let group_info = alice.client.create_mls_group("epoch-messages-test").await?;
    let group_id = group_info.mls_group_id.clone();
    let group_id_bytes = base64::engine::general_purpose::STANDARD.decode(&group_id)?;

    // Add Bob (epoch 1)
    let bob_kp = bob.client.generate_key_package()?;
    let add_bob = alice.client.add_member_to_group(&group_id, &bob_kp).await?;
    bob.client.process_welcome(&add_bob.welcome).await?;
    let mut epoch = add_bob.new_epoch;
    println!("Epoch {}: Bob joined", epoch);

    // Messages at epoch 1
    {
        let msg = format!("Message at epoch {}", epoch);
        let encrypted = alice.client.encrypt_message(&group_id_bytes, msg.as_bytes()).await?;
        let decrypted = bob.client.decrypt_message(&encrypted).await?;
        assert_eq!(String::from_utf8(decrypted)?, msg);
        println!("Epoch {}: Alice -> Bob message succeeded", epoch);
    }

    // Add Charlie (epoch 2)
    let charlie_kp = charlie.client.generate_key_package()?;
    let add_charlie = alice.client.add_member_to_group(&group_id, &charlie_kp).await?;
    bob.client.process_commit(&group_id, &add_charlie.decode_commit_bytes()?)?;
    charlie.client.process_welcome(&add_charlie.welcome).await?;
    epoch = add_charlie.new_epoch;
    println!("Epoch {}: Charlie joined", epoch);

    // Messages at epoch 2
    {
        let msg = format!("Message at epoch {} from Bob", epoch);
        let encrypted = bob.client.encrypt_message(&group_id_bytes, msg.as_bytes()).await?;

        let alice_dec = alice.client.decrypt_message(&encrypted).await?;
        let charlie_dec = charlie.client.decrypt_message(&encrypted).await?;

        assert_eq!(String::from_utf8(alice_dec)?, msg);
        assert_eq!(String::from_utf8(charlie_dec)?, msg);
        println!("Epoch {}: Bob -> Alice,Charlie message succeeded", epoch);
    }

    // Remove Bob (epoch 3)
    let remove_bob = alice.client.remove_member_from_group(&group_id, "bob").await?;
    charlie.client.process_commit(&group_id, &remove_bob.decode_commit_bytes()?)?;
    epoch = remove_bob.new_epoch;
    println!("Epoch {}: Bob removed", epoch);

    // Messages at epoch 3 (without Bob)
    {
        let msg = format!("Message at epoch {} (Bob removed)", epoch);
        let encrypted = charlie.client.encrypt_message(&group_id_bytes, msg.as_bytes()).await?;
        let decrypted = alice.client.decrypt_message(&encrypted).await?;
        assert_eq!(String::from_utf8(decrypted)?, msg);
        println!("Epoch {}: Charlie -> Alice message succeeded", epoch);
    }

    println!("\nSuccessfully sent messages across {} epoch changes", epoch);

    Ok(())
}
