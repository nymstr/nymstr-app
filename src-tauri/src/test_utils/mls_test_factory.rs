//! MLS client factory for multi-client test scenarios
//!
//! Provides utilities for creating MLS clients for testing group operations
//! without requiring full application setup.

use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;

use crate::crypto::mls::MlsClient;
use crate::test_utils::pgp_test_keys::TestUser;

/// Configuration for creating test MLS clients
#[derive(Debug, Clone)]
pub struct MlsTestConfig {
    /// Base storage directory for MLS state
    pub storage_dir: PathBuf,
}

impl Default for MlsTestConfig {
    fn default() -> Self {
        Self {
            storage_dir: std::env::temp_dir().join("nymstr_mls_test"),
        }
    }
}

/// Factory for creating MLS clients in test scenarios
pub struct MlsTestFactory {
    #[allow(dead_code)]
    config: MlsTestConfig,
    temp_dirs: Vec<tempfile::TempDir>,
}

impl MlsTestFactory {
    /// Create a new MLS test factory with default configuration
    pub fn new() -> Self {
        Self {
            config: MlsTestConfig::default(),
            temp_dirs: Vec::new(),
        }
    }

    /// Create a new MLS test factory with custom configuration
    pub fn with_config(config: MlsTestConfig) -> Self {
        Self {
            config,
            temp_dirs: Vec::new(),
        }
    }

    /// Create an MLS client for a test user with temporary storage
    pub fn create_client(&mut self, user: &TestUser) -> Result<TestMlsClient> {
        let temp_dir = tempfile::tempdir()?;
        let base_dir = temp_dir.path().to_path_buf();

        let mls_client = MlsClient::new(
            user.username(),
            Arc::clone(&user.secret_key),
            Arc::clone(&user.public_key),
            &user.passphrase,
            base_dir.clone(),
        )?;

        let client = TestMlsClient {
            client: mls_client,
            user: user.clone(),
            base_dir,
        };

        self.temp_dirs.push(temp_dir);
        Ok(client)
    }

    /// Create MLS clients for multiple users
    pub fn create_clients(&mut self, users: &[TestUser]) -> Result<Vec<TestMlsClient>> {
        let mut clients = Vec::new();
        for user in users {
            clients.push(self.create_client(user)?);
        }
        Ok(clients)
    }

    /// Create clients for a typical 3-user test scenario (Alice, Bob, Charlie)
    pub fn create_abc_scenario(
        &mut self,
    ) -> Result<(TestUser, TestUser, TestUser, TestMlsClient, TestMlsClient, TestMlsClient)> {
        use crate::test_utils::pgp_test_keys::generate_abc_users;

        let (alice, bob, charlie) = generate_abc_users()?;

        let alice_client = self.create_client(&alice)?;
        let bob_client = self.create_client(&bob)?;
        let charlie_client = self.create_client(&charlie)?;

        Ok((alice, bob, charlie, alice_client, bob_client, charlie_client))
    }

    /// Create clients for a direct messaging test scenario
    pub fn create_dm_scenario(
        &mut self,
    ) -> Result<(TestUser, TestUser, TestMlsClient, TestMlsClient)> {
        use crate::test_utils::pgp_test_keys::generate_dm_pair;

        let (sender, recipient) = generate_dm_pair()?;

        let sender_client = self.create_client(&sender)?;
        let recipient_client = self.create_client(&recipient)?;

        Ok((sender, recipient, sender_client, recipient_client))
    }

    /// Create clients for a large group test scenario
    ///
    /// Generates `size` users with names like "user_0", "user_1", etc.
    /// The first user (user_0) is typically the group admin.
    ///
    /// # Example
    /// ```ignore
    /// let mut factory = MlsTestFactory::new();
    /// let group = factory.create_group_scenario(10)?;
    /// let admin = &group.clients[0];
    /// let members = &group.clients[1..];
    /// ```
    pub fn create_group_scenario(&mut self, size: usize) -> Result<TestGroup> {
        if size == 0 {
            anyhow::bail!("Group size must be at least 1");
        }

        let mut users = Vec::with_capacity(size);
        let mut clients = Vec::with_capacity(size);

        for i in 0..size {
            let username = format!("user_{}", i);
            let user = TestUser::new(&username)?;
            let client = self.create_client(&user)?;
            users.push(user);
            clients.push(client);
        }

        Ok(TestGroup {
            users,
            clients,
            group_id: format!("test-group-{}", uuid::Uuid::new_v4()),
        })
    }

    /// Create a named group scenario with specific usernames
    ///
    /// # Example
    /// ```ignore
    /// let mut factory = MlsTestFactory::new();
    /// let group = factory.create_named_group(&["admin", "alice", "bob", "carol", "dave"])?;
    /// ```
    pub fn create_named_group(&mut self, names: &[&str]) -> Result<TestGroup> {
        if names.is_empty() {
            anyhow::bail!("Group must have at least one member");
        }

        let mut users = Vec::with_capacity(names.len());
        let mut clients = Vec::with_capacity(names.len());

        for name in names {
            let user = TestUser::new(name)?;
            let client = self.create_client(&user)?;
            users.push(user);
            clients.push(client);
        }

        Ok(TestGroup {
            users,
            clients,
            group_id: format!("test-group-{}", uuid::Uuid::new_v4()),
        })
    }
}

/// A test group with multiple users and their MLS clients
pub struct TestGroup {
    /// All users in the group
    pub users: Vec<TestUser>,
    /// All MLS clients (same order as users)
    pub clients: Vec<TestMlsClient>,
    /// Group identifier
    pub group_id: String,
}

impl TestGroup {
    /// Get the number of members
    pub fn size(&self) -> usize {
        self.users.len()
    }

    /// Get the admin (first user)
    pub fn admin(&self) -> (&TestUser, &TestMlsClient) {
        (&self.users[0], &self.clients[0])
    }

    /// Get the admin client mutably
    pub fn admin_mut(&mut self) -> (&TestUser, &mut TestMlsClient) {
        let user = &self.users[0];
        let client = &mut self.clients[0];
        (user, client)
    }

    /// Get all members except admin
    pub fn members(&self) -> impl Iterator<Item = (&TestUser, &TestMlsClient)> {
        self.users.iter().zip(self.clients.iter()).skip(1)
    }

    /// Get a specific member by index
    pub fn get(&self, index: usize) -> Option<(&TestUser, &TestMlsClient)> {
        self.users.get(index).zip(self.clients.get(index))
    }

    /// Get a specific member mutably by index
    pub fn get_mut(&mut self, index: usize) -> Option<(&TestUser, &mut TestMlsClient)> {
        if index < self.users.len() {
            let user = &self.users[index];
            let client = &mut self.clients[index];
            Some((user, client))
        } else {
            None
        }
    }

    /// Generate key packages for all members
    pub fn generate_all_key_packages(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let mut packages = Vec::with_capacity(self.clients.len());
        for (user, client) in self.users.iter().zip(self.clients.iter()) {
            let kp = client.generate_key_package()?;
            packages.push((user.username.clone(), kp));
        }
        Ok(packages)
    }

    /// Get usernames of all members
    pub fn usernames(&self) -> Vec<&str> {
        self.users.iter().map(|u| u.username.as_str()).collect()
    }
}

impl Default for MlsTestFactory {
    fn default() -> Self {
        Self::new()
    }
}

/// A test MLS client wrapper with associated user and cleanup
pub struct TestMlsClient {
    /// The underlying MLS client
    pub client: MlsClient,
    /// The test user associated with this client
    pub user: TestUser,
    /// Base directory for storage
    pub base_dir: PathBuf,
}

impl TestMlsClient {
    /// Get the username of this client
    pub fn username(&self) -> &str {
        &self.user.username
    }

    /// Get the MLS client reference
    pub fn mls_client(&self) -> &MlsClient {
        &self.client
    }

    /// Get a mutable reference to the MLS client
    pub fn mls_client_mut(&mut self) -> &mut MlsClient {
        &mut self.client
    }

    /// Generate a key package for this client
    pub fn generate_key_package(&self) -> Result<Vec<u8>> {
        self.client.generate_key_package()
    }

    /// Get a key package as base64 for transmission
    pub fn key_package_b64(&self) -> Result<String> {
        let kp = self.generate_key_package()?;
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &kp,
        ))
    }
}

/// Helper to create a standalone test MLS client
pub fn create_standalone_client(username: &str) -> Result<(TestUser, TestMlsClient)> {
    let user = TestUser::new(username)?;
    let mut factory = MlsTestFactory::new();
    let client = factory.create_client(&user)?;

    Ok((user, client))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_mls_client() {
        let user = TestUser::new("test_mls_user").unwrap();
        let mut factory = MlsTestFactory::new();

        let client = factory.create_client(&user).unwrap();

        assert_eq!(client.username(), "test_mls_user");
    }

    #[test]
    fn test_create_multiple_clients() {
        use crate::test_utils::pgp_test_keys::generate_test_users;

        let users = generate_test_users(&["user1", "user2"]).unwrap();
        let mut factory = MlsTestFactory::new();

        let clients = factory.create_clients(&users).unwrap();

        assert_eq!(clients.len(), 2);
        assert_eq!(clients[0].username(), "user1");
        assert_eq!(clients[1].username(), "user2");
    }

    #[test]
    fn test_generate_key_package() {
        let user = TestUser::new("kp_user").unwrap();
        let mut factory = MlsTestFactory::new();
        let client = factory.create_client(&user).unwrap();

        let kp = client.generate_key_package().unwrap();

        assert!(!kp.is_empty());
    }

    #[test]
    fn test_standalone_client() {
        let (user, client) = create_standalone_client("standalone").unwrap();

        assert_eq!(user.username(), "standalone");
        assert_eq!(client.username(), "standalone");
    }

    #[test]
    fn test_create_group_scenario_10_members() {
        let mut factory = MlsTestFactory::new();
        let group = factory.create_group_scenario(10).unwrap();

        assert_eq!(group.size(), 10);
        assert_eq!(group.usernames().len(), 10);

        // Verify admin
        let (admin_user, admin_client) = group.admin();
        assert_eq!(admin_user.username(), "user_0");
        assert_eq!(admin_client.username(), "user_0");

        // Verify members
        let members: Vec<_> = group.members().collect();
        assert_eq!(members.len(), 9);
        assert_eq!(members[0].0.username(), "user_1");
        assert_eq!(members[8].0.username(), "user_9");
    }

    #[test]
    fn test_create_group_scenario_20_members() {
        let mut factory = MlsTestFactory::new();
        let group = factory.create_group_scenario(20).unwrap();

        assert_eq!(group.size(), 20);

        // All clients should be able to generate key packages
        let packages = group.generate_all_key_packages().unwrap();
        assert_eq!(packages.len(), 20);

        for (username, kp) in &packages {
            assert!(!kp.is_empty(), "Key package for {} should not be empty", username);
        }
    }

    #[test]
    fn test_create_named_group() {
        let mut factory = MlsTestFactory::new();
        let group = factory.create_named_group(&[
            "admin", "alice", "bob", "carol", "dave", "eve"
        ]).unwrap();

        assert_eq!(group.size(), 6);
        assert_eq!(group.usernames(), vec!["admin", "alice", "bob", "carol", "dave", "eve"]);

        let (admin_user, _) = group.admin();
        assert_eq!(admin_user.username(), "admin");
    }

    #[test]
    fn test_group_get_member() {
        let mut factory = MlsTestFactory::new();
        let group = factory.create_group_scenario(5).unwrap();

        // Get by index
        let (user2, client2) = group.get(2).unwrap();
        assert_eq!(user2.username(), "user_2");
        assert_eq!(client2.username(), "user_2");

        // Out of bounds returns None
        assert!(group.get(10).is_none());
    }

    #[test]
    fn test_large_group_key_package_generation() {
        let mut factory = MlsTestFactory::new();
        let group = factory.create_group_scenario(15).unwrap();

        // Generate all key packages and verify they're unique
        let packages = group.generate_all_key_packages().unwrap();

        let mut seen_packages: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        for (username, kp) in packages {
            assert!(
                seen_packages.insert(kp.clone()),
                "Key package for {} should be unique",
                username
            );
        }
    }

    #[test]
    fn test_empty_group_fails() {
        let mut factory = MlsTestFactory::new();
        let result = factory.create_group_scenario(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_named_group_fails() {
        let mut factory = MlsTestFactory::new();
        let result = factory.create_named_group(&[]);
        assert!(result.is_err());
    }
}
