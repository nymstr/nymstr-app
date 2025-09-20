use crate::model::Id;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: Id,
    pub username: String,
    pub display_name: String,
    pub online: bool,
}

impl User {
    pub fn new(username: &str) -> Self {
        Self {
            id: username.to_string(),
            username: username.to_string(),
            display_name: username.to_string(),
            online: false,
        }
    }

    pub fn with_display_name(username: &str, display_name: &str) -> Self {
        Self {
            id: username.to_string(),
            username: username.to_string(),
            display_name: display_name.to_string(),
            online: false,
        }
    }

    pub fn set_online(&mut self, online: bool) {
        self.online = online;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_new() {
        let user = User::new("alice");
        assert_eq!(user.id, "alice");
        assert_eq!(user.username, "alice");
        assert_eq!(user.display_name, "alice");
        assert!(!user.online);
    }

    #[test]
    fn test_user_with_display_name() {
        let user = User::with_display_name("bob", "Bob Smith");
        assert_eq!(user.id, "bob");
        assert_eq!(user.username, "bob");
        assert_eq!(user.display_name, "Bob Smith");
        assert!(!user.online);
    }

    #[test]
    fn test_user_set_online() {
        let mut user = User::new("charlie");
        assert!(!user.online);
        
        user.set_online(true);
        assert!(user.online);
        
        user.set_online(false);
        assert!(!user.online);
    }

    #[test]
    fn test_user_fields() {
        let mut user = User::new("dave");
        assert_eq!(user.id, "dave");
        assert_eq!(user.username, "dave");
        assert_eq!(user.display_name, "dave");
        assert!(!user.online);
        
        user.display_name = "David".to_string();
        user.online = true;
        
        assert_eq!(user.id, "dave");
        assert_eq!(user.username, "dave");
        assert_eq!(user.display_name, "David");
        assert!(user.online);
    }

    #[test]
    fn test_user_clone() {
        let user1 = User::new("eve");
        let user2 = user1.clone();
        
        assert_eq!(user1, user2);
        assert_eq!(user1.id, user2.id);
        assert_eq!(user1.username, user2.username);
        assert_eq!(user1.display_name, user2.display_name);
        assert_eq!(user1.online, user2.online);
    }

    #[test]
    fn test_user_equality() {
        let user1 = User::new("frank");
        let user2 = User::new("frank");
        let user3 = User::new("grace");
        
        assert_eq!(user1, user2);
        assert_ne!(user1, user3);
    }

    #[test]
    fn test_user_debug() {
        let user = User::new("henry");
        let debug_str = format!("{:?}", user);
        assert!(debug_str.contains("User"));
        assert!(debug_str.contains("henry"));
        assert!(debug_str.contains("online: false"));
    }

    #[test]
    fn test_user_with_empty_username() {
        let user = User::new("");
        assert_eq!(user.id, "");
        assert_eq!(user.username, "");
        assert_eq!(user.display_name, "");
        assert!(!user.online);
    }

    #[test]
    fn test_user_with_special_characters() {
        let user = User::new("user@example.com");
        assert_eq!(user.id, "user@example.com");
        assert_eq!(user.username, "user@example.com");
        assert_eq!(user.display_name, "user@example.com");
        assert!(!user.online);
    }

    #[test]
    fn test_user_with_unicode() {
        let user = User::with_display_name("用户", "用户显示名");
        assert_eq!(user.id, "用户");
        assert_eq!(user.username, "用户");
        assert_eq!(user.display_name, "用户显示名");
        assert!(!user.online);
    }

    #[test]
    fn test_user_modification() {
        let mut user = User {
            id: "id1".to_string(),
            username: "username1".to_string(),
            display_name: "Original Name".to_string(),
            online: false,
        };
        
        user.display_name = "Modified Name".to_string();
        user.online = true;
        
        assert_eq!(user.id, "id1");
        assert_eq!(user.username, "username1");
        assert_eq!(user.display_name, "Modified Name");
        assert!(user.online);
    }

    #[test]
    fn test_user_partial_eq() {
        let user1 = User {
            id: "test".to_string(),
            username: "test".to_string(),
            display_name: "Test User".to_string(),
            online: true,
        };
        
        let user2 = User {
            id: "test".to_string(),
            username: "test".to_string(),
            display_name: "Test User".to_string(),
            online: true,
        };
        
        let user3 = User {
            id: "test".to_string(),
            username: "test".to_string(),
            display_name: "Test User".to_string(),
            online: false,
        };
        
        assert_eq!(user1, user2);
        assert_ne!(user1, user3);
    }

    #[test]
    fn test_user_different_id_and_username() {
        let mut user = User::new("initial");
        user.id = "different_id".to_string();
        
        assert_eq!(user.id, "different_id");
        assert_eq!(user.username, "initial");
        assert_eq!(user.display_name, "initial");
        assert!(!user.online);
    }
}
