use crate::model::Id;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    pub id: Id,
    pub display_name: String,
    pub online: bool,
}

impl Contact {
    pub fn new(name: &str) -> Self {
        Self {
            id: name.to_string(),
            display_name: name.to_string(),
            online: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contact_new() {
        let contact = Contact::new("alice");
        assert_eq!(contact.id, "alice");
        assert_eq!(contact.display_name, "alice");
        assert!(contact.online);
    }

    #[test]
    fn test_contact_fields() {
        let mut contact = Contact::new("bob");
        assert_eq!(contact.id, "bob");
        assert_eq!(contact.display_name, "bob");
        assert!(contact.online);

        contact.display_name = "Bob Smith".to_string();
        contact.online = false;

        assert_eq!(contact.id, "bob");
        assert_eq!(contact.display_name, "Bob Smith");
        assert!(!contact.online);
    }

    #[test]
    fn test_contact_clone() {
        let contact1 = Contact::new("charlie");
        let contact2 = contact1.clone();

        assert_eq!(contact1, contact2);
        assert_eq!(contact1.id, contact2.id);
        assert_eq!(contact1.display_name, contact2.display_name);
        assert_eq!(contact1.online, contact2.online);
    }

    #[test]
    fn test_contact_equality() {
        let contact1 = Contact::new("dave");
        let contact2 = Contact::new("dave");
        let contact3 = Contact::new("eve");

        assert_eq!(contact1, contact2);
        assert_ne!(contact1, contact3);
    }

    #[test]
    fn test_contact_debug() {
        let contact = Contact::new("frank");
        let debug_str = format!("{:?}", contact);
        assert!(debug_str.contains("Contact"));
        assert!(debug_str.contains("frank"));
        assert!(debug_str.contains("online: true"));
    }

    #[test]
    fn test_contact_with_empty_name() {
        let contact = Contact::new("");
        assert_eq!(contact.id, "");
        assert_eq!(contact.display_name, "");
        assert!(contact.online);
    }

    #[test]
    fn test_contact_with_special_characters() {
        let contact = Contact::new("user@example.com");
        assert_eq!(contact.id, "user@example.com");
        assert_eq!(contact.display_name, "user@example.com");
        assert!(contact.online);
    }

    #[test]
    fn test_contact_with_unicode() {
        let contact = Contact::new("用户名");
        assert_eq!(contact.id, "用户名");
        assert_eq!(contact.display_name, "用户名");
        assert!(contact.online);
    }

    #[test]
    fn test_contact_modification() {
        let mut contact = Contact {
            id: "id1".to_string(),
            display_name: "Original Name".to_string(),
            online: true,
        };

        contact.display_name = "Modified Name".to_string();
        contact.online = false;

        assert_eq!(contact.id, "id1");
        assert_eq!(contact.display_name, "Modified Name");
        assert!(!contact.online);
    }

    #[test]
    fn test_contact_partial_eq() {
        let contact1 = Contact {
            id: "test".to_string(),
            display_name: "Test User".to_string(),
            online: true,
        };

        let contact2 = Contact {
            id: "test".to_string(),
            display_name: "Test User".to_string(),
            online: true,
        };

        let contact3 = Contact {
            id: "test".to_string(),
            display_name: "Test User".to_string(),
            online: false,
        };

        assert_eq!(contact1, contact2);
        assert_ne!(contact1, contact3);
    }
}
