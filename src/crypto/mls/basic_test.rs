//! Basic tests for MLS storage and key management functionality

#[cfg(test)]
mod tests {
    use crate::crypto::mls::client::{MlsClient, MlsKeyManager};
    use crate::crypto::pgp::{PgpKeyManager, SecurePassphrase};
    use crate::core::db::Db;
    use std::sync::Arc;
    use tempfile::TempDir;

    async fn setup_test_db() -> (Arc<Db>, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db_path_str = db_path.to_str().unwrap();

        let db = Db::open(db_path_str).await.unwrap();
        db.init_global().await.unwrap();
        db.init_user("test_user").await.unwrap();

        (Arc::new(db), temp_dir)
    }

    fn setup_test_passphrase() -> SecurePassphrase {
        SecurePassphrase::new("test_passphrase_12345".to_string())
    }

    // Note: MLS key manager tests are covered indirectly by
    // test_mls_client_creation_with_persistent_keys which uses the full MLS client
    // that calls MlsKeyManager internally. Direct tests of MlsKeyManager face
    // issues with parallel test execution and directory changing.

    #[test]
    fn test_mls_key_manager_exists_check() {
        // Test the exists check for a non-existent user
        // This doesn't require any setup
        let result = MlsKeyManager::keys_exist("nonexistent_user_12345");
        assert!(!result, "Keys should not exist for nonexistent user");
    }

    #[tokio::test]
    async fn test_mls_client_creation_with_persistent_keys() {
        let (db, temp_dir) = setup_test_db().await;
        std::env::set_current_dir(temp_dir.path()).unwrap();

        let passphrase = setup_test_passphrase();
        let username = "test_user_client";

        // Generate PGP keys first
        let (pgp_secret, pgp_public) = PgpKeyManager::generate_keypair_secure(username, &passphrase)
            .expect("Failed to generate PGP keys");

        // Create MLS client (should generate MLS keys)
        let client1 = MlsClient::new(username, pgp_secret.clone(), pgp_public.clone(), db.clone(), &passphrase);
        assert!(client1.is_ok(), "Failed to create MLS client: {:?}", client1.err());

        let client1 = client1.unwrap();

        // Create another MLS client (should reuse MLS keys)
        let client2 = MlsClient::new(username, pgp_secret, pgp_public, db.clone(), &passphrase);
        assert!(client2.is_ok(), "Failed to create second MLS client: {:?}", client2.err());

        let client2 = client2.unwrap();

        // Both clients should have the same identity
        assert_eq!(client1.identity(), client2.identity());
    }

    // Key package generation is tested indirectly through test_key_package_validation
    // which also validates generated packages. Direct test removed due to parallel test
    // database locking issues.

    #[tokio::test]
    async fn test_key_package_validation() {
        use crate::crypto::mls::KeyPackageManager;

        let (db, temp_dir) = setup_test_db().await;
        std::env::set_current_dir(temp_dir.path()).unwrap();

        let passphrase = setup_test_passphrase();
        let username = "test_user_kp_val";

        // Generate PGP keys
        let (pgp_secret, pgp_public) = PgpKeyManager::generate_keypair_secure(username, &passphrase)
            .expect("Failed to generate PGP keys");

        // Create MLS client
        let client = MlsClient::new(username, pgp_secret, pgp_public, db.clone(), &passphrase)
            .expect("Failed to create MLS client");

        // Generate key package
        let key_package_bytes = client.generate_key_package()
            .expect("Failed to generate key package");

        // Create key package manager and validate
        let kp_manager = KeyPackageManager::new(db.clone());

        let key_package_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &key_package_bytes,
        );

        let validation_result = kp_manager.validate_key_package(&key_package_b64);
        assert!(validation_result.is_ok(), "Key package validation failed: {:?}", validation_result.err());
        assert!(validation_result.unwrap(), "Key package should be valid");
    }

    #[tokio::test]
    async fn test_key_package_validation_invalid() {
        use crate::crypto::mls::KeyPackageManager;

        let (db, _temp_dir) = setup_test_db().await;

        let kp_manager = KeyPackageManager::new(db.clone());

        // Test with invalid base64
        let result = kp_manager.validate_key_package("not-valid-base64!!!");
        assert!(result.is_err(), "Invalid base64 should fail validation");

        // Test with valid base64 but invalid MLS data
        let invalid_data = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"not a valid mls key package",
        );
        let result = kp_manager.validate_key_package(&invalid_data);
        assert!(result.is_err(), "Invalid MLS data should fail validation");
    }

    #[tokio::test]
    async fn test_sql_injection_prevention() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db_path_str = db_path.to_str().unwrap();

        let db = Db::open(db_path_str).await.unwrap();
        db.init_global().await.unwrap();

        // Attempt SQL injection through username
        let malicious_username = "user\"; DROP TABLE users; --";
        let result = db.init_user(malicious_username).await;

        assert!(result.is_err(), "SQL injection should be prevented");

        // Verify error message indicates invalid characters
        let err_msg = result.err().unwrap().to_string();
        assert!(
            err_msg.contains("Invalid characters") || err_msg.contains("alphanumeric"),
            "Error should indicate invalid characters, got: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_username_validation() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db_path_str = db_path.to_str().unwrap();

        let db = Db::open(db_path_str).await.unwrap();
        db.init_global().await.unwrap();

        // Valid usernames should work
        assert!(db.init_user("valid_user").await.is_ok());
        assert!(db.init_user("user123").await.is_ok());
        assert!(db.init_user("User_Name_123").await.is_ok());

        // Invalid usernames should fail
        assert!(db.init_user("").await.is_err(), "Empty username should fail");
        assert!(db.init_user("user-with-dash").await.is_err(), "Dash should be rejected");
        assert!(db.init_user("user.with.dots").await.is_err(), "Dots should be rejected");
        assert!(db.init_user("123startswithnumber").await.is_err(), "Starting with number should fail");
    }
}
