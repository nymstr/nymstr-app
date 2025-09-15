//! Real MLS integration tests following mls-rs patterns

#[cfg(test)]
mod tests {
    use crate::crypto::mls::test_client::test_client::TestMlsClient;
    use crate::core::db::Db;
    use std::sync::Arc;
    use tempfile::NamedTempFile;

    async fn setup_test_db() -> (Arc<Db>, NamedTempFile) {
        let temp_file = NamedTempFile::new().unwrap();
        let db_path = temp_file.path().to_str().unwrap();

        let db = Db::open(db_path).await.unwrap();
        db.init_global().await.unwrap();
        db.init_user("alice").await.unwrap();
        db.init_user("bob").await.unwrap();
        db.init_user("charlie").await.unwrap();

        (Arc::new(db), temp_file)
    }

    #[tokio::test]
    async fn test_full_mls_conversation_flow() {
        // Create two clients exactly like the mls-rs basic_usage example
        let alice = TestMlsClient::new("alice").unwrap();
        let bob = TestMlsClient::new("bob").unwrap();

        // Step 1: Bob generates a key package (like basic_usage.rs:50)
        let bob_key_package = bob.generate_key_package().unwrap();

        // Step 2: Alice starts conversation with Bob's key package
        let conversation_info = alice.start_conversation(&bob_key_package).await.unwrap();
        let conversation_id = conversation_info.conversation_id;
        let welcome_message = conversation_info.welcome_message.expect("Should have welcome message");

        // Step 3: Bob joins the group with the welcome message (like basic_usage.rs:65)
        let _join_result = bob.join_conversation(&welcome_message).await.unwrap();

        // Step 4: Alice encrypts application message (like basic_usage.rs:68)
        let test_message = b"hello world";
        let encrypted = alice.encrypt_message(&conversation_id, test_message).await.unwrap();

        // Verify the message is actually encrypted
        assert_ne!(encrypted.mls_message, test_message.to_vec(), "Message should be encrypted, not plaintext");
        assert!(!encrypted.mls_message.is_empty(), "Encrypted message should not be empty");

        // Step 5: Bob decrypts the message (like basic_usage.rs:71)
        let decrypted = bob.decrypt_message(&encrypted).await.unwrap();
        assert_eq!(decrypted, test_message.to_vec(), "Decrypted message should match original");

        // Step 6: Test bidirectional communication
        let bob_message = b"hello alice";
        let bob_encrypted = bob.encrypt_message(&conversation_id, bob_message).await.unwrap();
        let alice_decrypted = alice.decrypt_message(&bob_encrypted).await.unwrap();
        assert_eq!(alice_decrypted, bob_message.to_vec());
    }

    #[tokio::test]
    async fn test_mls_group_member_addition() {
        let alice = TestMlsClient::new("alice").unwrap();
        let bob = TestMlsClient::new("bob").unwrap();
        let charlie = TestMlsClient::new("charlie").unwrap();

        // Alice and Bob establish a conversation
        let bob_key_package = bob.generate_key_package().unwrap();
        let conversation_info = alice.start_conversation(&bob_key_package).await.unwrap();
        let conversation_id = conversation_info.conversation_id;
        let welcome_message = conversation_info.welcome_message.unwrap();
        let _join_result = bob.join_conversation(&welcome_message).await.unwrap();

        // Test initial 2-party communication works
        let initial_msg = b"initial message";
        let encrypted = alice.encrypt_message(&conversation_id, initial_msg).await.unwrap();
        let decrypted = bob.decrypt_message(&encrypted).await.unwrap();
        assert_eq!(decrypted, initial_msg.to_vec());

        // Alice adds Charlie to the group (following mls-rs commit_builder pattern)
        let charlie_key_package = charlie.generate_key_package().unwrap();
        let add_commit = alice.add_member(&conversation_id, &charlie_key_package).await.unwrap();

        // Verify the commit message is produced
        assert!(!add_commit.mls_message.is_empty(), "Add member commit should produce a message");

        // Bob needs to process the commit message to update his group state
        // Note: In a real application, this commit would be distributed via a server
        let _processed_result = bob.decrypt_message(&add_commit).await;
        // It's ok if this fails because commit messages don't contain application data
        // The important thing is that Bob's group state gets updated

        // Test that existing members can still communicate after group change
        let post_add_msg = b"message after adding charlie";
        let encrypted_post = alice.encrypt_message(&conversation_id, post_add_msg).await.unwrap();
        let decrypted_post = bob.decrypt_message(&encrypted_post).await.unwrap();
        assert_eq!(decrypted_post, post_add_msg.to_vec());
    }

    #[tokio::test]
    async fn test_mls_message_ordering() {
        let alice = TestMlsClient::new("alice").unwrap();
        let bob = TestMlsClient::new("bob").unwrap();

        // Setup conversation
        let bob_key_package = bob.generate_key_package().unwrap();
        let conversation_info = alice.start_conversation(&bob_key_package).await.unwrap();
        let conversation_id = conversation_info.conversation_id;
        let welcome_message = conversation_info.welcome_message.unwrap();
        let _join_result = bob.join_conversation(&welcome_message).await.unwrap();

        // Send multiple messages in sequence to test ordering
        let messages = vec![
            b"first message".as_slice(),
            b"second message".as_slice(),
            b"third message".as_slice(),
            b"fourth message".as_slice(),
        ];

        let mut encrypted_messages = Vec::new();

        // Alice sends all messages
        for (i, msg) in messages.iter().enumerate() {
            let encrypted = alice.encrypt_message(&conversation_id, msg).await.unwrap();

            // Each encrypted message should be different
            for prev_encrypted in &encrypted_messages {
                assert_ne!(encrypted.mls_message, *prev_encrypted, "Message {} should be uniquely encrypted", i);
            }

            encrypted_messages.push(encrypted.mls_message.clone());

            // Bob should be able to decrypt each message correctly
            let decrypted = bob.decrypt_message(&encrypted).await.unwrap();
            assert_eq!(decrypted, msg.to_vec(), "Message {} should decrypt correctly", i);
        }
    }

    #[tokio::test]
    async fn test_mls_group_state_consistency() {
        let alice = TestMlsClient::new("alice").unwrap();
        let bob = TestMlsClient::new("bob").unwrap();

        // Setup conversation
        let bob_key_package = bob.generate_key_package().unwrap();
        let conversation_info = alice.start_conversation(&bob_key_package).await.unwrap();
        let conversation_id = conversation_info.conversation_id;
        let welcome_message = conversation_info.welcome_message.unwrap();
        let _join_result = bob.join_conversation(&welcome_message).await.unwrap();

        // Send some messages to advance group state
        for i in 0..5 {
            let msg = format!("test message {}", i);
            let encrypted = alice.encrypt_message(&conversation_id, msg.as_bytes()).await.unwrap();
            let decrypted = bob.decrypt_message(&encrypted).await.unwrap();
            assert_eq!(decrypted, msg.as_bytes());

            // Send reply from Bob
            let reply = format!("reply {}", i);
            let encrypted_reply = bob.encrypt_message(&conversation_id, reply.as_bytes()).await.unwrap();
            let decrypted_reply = alice.decrypt_message(&encrypted_reply).await.unwrap();
            assert_eq!(decrypted_reply, reply.as_bytes());
        }

        // Test that group state can be exported (like basic_usage.rs:76-77)
        let alice_state = alice.export_group_state(&conversation_id).await.unwrap();
        let bob_state = bob.export_group_state(&conversation_id).await.unwrap();

        assert!(!alice_state.is_empty(), "Alice should have exportable group state");
        assert!(!bob_state.is_empty(), "Bob should have exportable group state");
    }

    #[tokio::test]
    async fn test_mls_error_conditions() {
        let alice = TestMlsClient::new("alice").unwrap();
        let bob = TestMlsClient::new("bob").unwrap();

        // Test 1: Try to encrypt without establishing group first
        let fake_conversation_id = vec![1, 2, 3, 4];
        let encrypt_result = alice.encrypt_message(&fake_conversation_id, b"test").await;
        assert!(encrypt_result.is_err(), "Should fail to encrypt to non-existent group");

        // Test 2: Try to decrypt invalid message
        let bob_key_package = bob.generate_key_package().unwrap();
        let conversation_info = alice.start_conversation(&bob_key_package).await.unwrap();
        let conversation_id = conversation_info.conversation_id;
        let welcome_message = conversation_info.welcome_message.unwrap();
        let _join_result = bob.join_conversation(&welcome_message).await.unwrap();

        // Create a fake encrypted message
        let fake_encrypted = crate::crypto::mls::types::EncryptedMessage {
            conversation_id: conversation_id.clone(),
            mls_message: vec![1, 2, 3, 4, 5], // Invalid MLS message
            message_type: crate::crypto::mls::types::MlsMessageType::Application,
        };

        let decrypt_result = bob.decrypt_message(&fake_encrypted).await;
        assert!(decrypt_result.is_err(), "Should fail to decrypt invalid message");

        // Test 3: Valid flow should still work after errors
        let valid_message = b"valid message after errors";
        let encrypted = alice.encrypt_message(&conversation_id, valid_message).await.unwrap();
        let decrypted = bob.decrypt_message(&encrypted).await.unwrap();
        assert_eq!(decrypted, valid_message.to_vec());
    }
}