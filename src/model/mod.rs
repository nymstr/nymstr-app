pub mod contact;
pub mod message;
pub mod user;

pub type Id = String;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_type_alias() {
        let id: Id = "test_id".to_string();
        assert_eq!(id, "test_id");
        
        let id2: Id = String::from("another_id");
        assert_eq!(id2, "another_id");
    }

    #[test]
    fn test_id_comparison() {
        let id1: Id = "same_id".to_string();
        let id2: Id = "same_id".to_string();
        let id3: Id = "different_id".to_string();
        
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_id_empty() {
        let empty_id: Id = String::new();
        assert!(empty_id.is_empty());
        
        let non_empty_id: Id = "non_empty".to_string();
        assert!(!non_empty_id.is_empty());
    }
}
