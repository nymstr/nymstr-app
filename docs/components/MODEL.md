# Model Module Documentation

## Overview

The `model` module (`src/model/`) defines the core data structures used throughout Nymstr for representing users, contacts, and messages.

## Module Structure

```
src/model/
├── mod.rs          # Module exports and common types
├── user.rs         # User data structure
├── contact.rs      # Contact data structure
└── message.rs      # Message data structure
```

---

## Common Types (`mod.rs`)

```rust
/// Type alias for identifiers (user IDs, contact IDs)
pub type Id = String;
```

The `Id` type is used consistently throughout the application to identify users and contacts.

---

## User (`user.rs`)

### Purpose
Represent a registered user account in the system.

### Structure

```rust
#[derive(Debug, Clone, PartialEq)]
pub struct User {
    /// Unique identifier
    pub id: Id,
    /// Login username
    pub username: String,
    /// Display name shown in UI
    pub display_name: String,
    /// Online status
    pub online: bool,
}
```

### Constructors

```rust
impl User {
    /// Create a new user with username as display name
    pub fn new(username: &str) -> Self {
        Self {
            id: username.to_string(),
            username: username.to_string(),
            display_name: username.to_string(),
            online: false,
        }
    }

    /// Create a user with custom display name
    pub fn with_display_name(username: &str, display_name: &str) -> Self {
        Self {
            id: username.to_string(),
            username: username.to_string(),
            display_name: display_name.to_string(),
            online: false,
        }
    }
}
```

### Methods

| Method | Description |
|--------|-------------|
| `new(username)` | Create user with default display name |
| `with_display_name(username, display_name)` | Create with custom display name |
| `set_online(online)` | Update online status |

### Usage

```rust
// Create a new user
let user = User::new("alice");

// Create with display name
let user = User::with_display_name("alice", "Alice Smith");

// Update online status
user.set_online(true);
```

### Serialization

The `User` struct is not directly serialized to the database. Instead, user information is stored as separate fields:
- Username and public key in the `users` table
- User state managed by `MessageHandler`

---

## Contact (`contact.rs`)

### Purpose
Represent a contact in a user's contact list.

### Structure

```rust
#[derive(Debug, Clone, PartialEq)]
pub struct Contact {
    /// Unique identifier (typically username)
    pub id: Id,
    /// Display name shown in UI
    pub display_name: String,
    /// Online status indicator
    pub online: bool,
}
```

### Constructors

```rust
impl Contact {
    /// Create a new contact
    pub fn new(id: &str, display_name: &str) -> Self {
        Self {
            id: id.to_string(),
            display_name: display_name.to_string(),
            online: false,
        }
    }
}
```

### Database Mapping

Contacts are stored in per-user tables:

```sql
CREATE TABLE contacts_{user} (
    username TEXT PRIMARY KEY,    -- maps to Contact.id
    public_key TEXT NOT NULL      -- for encryption
);
```

The `display_name` is typically derived from the username, and `online` status is tracked in-memory.

### Usage

```rust
// Create a contact
let contact = Contact::new("bob", "Bob");

// Check if online
if contact.online {
    println!("{} is online", contact.display_name);
}
```

### UI Rendering

Contacts are rendered in the contacts panel:

```rust
// In ui/components/chat.rs
let items: Vec<ListItem> = contacts
    .iter()
    .map(|c| {
        let style = if c.online {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::Gray)
        };
        ListItem::new(c.display_name.clone()).style(style)
    })
    .collect();
```

---

## Message (`message.rs`)

### Purpose
Represent a single message in a conversation.

### Structure

```rust
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    /// Message sender (username)
    pub sender: String,
    /// Message content (plaintext)
    pub content: String,
    /// Timestamp when message was sent/received
    pub timestamp: DateTime<Utc>,
}
```

### Constructors

```rust
impl Message {
    /// Create a new message with current timestamp
    pub fn new(sender: &str, content: &str) -> Self {
        Self {
            sender: sender.to_string(),
            content: content.to_string(),
            timestamp: Utc::now(),
        }
    }

    /// Create a message with specific timestamp
    pub fn with_timestamp(sender: &str, content: &str, timestamp: DateTime<Utc>) -> Self {
        Self {
            sender: sender.to_string(),
            content: content.to_string(),
            timestamp,
        }
    }
}
```

### Database Mapping

Messages are stored in per-user tables:

```sql
CREATE TABLE messages_{user} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,       -- The other party (contact)
    type TEXT NOT NULL,           -- 'to' or 'from'
    message TEXT NOT NULL,        -- Content
    timestamp DATETIME            -- When sent/received
);
```

Conversion between database rows and `Message`:

```rust
// Loading from database
let (sent, text, ts) = row;  // (bool, String, DateTime)
let sender = if sent { current_user } else { contact };
Message::with_timestamp(&sender, &text, ts)
```

### Message Flow

```
Sending:
  User types → input_buffer
            → Message::new(current_user, content)
            → MLS encryption
            → Network send
            → Save to database (type='to')

Receiving:
  Network receive → MLS decryption
                 → Message::new(sender, content)
                 → Add to screen
                 → Save to database (type='from')
```

### UI Rendering

Messages are rendered in the messages panel:

```rust
fn message_to_line(msg: &Message) -> Line {
    let time = msg.timestamp.format("%H:%M");
    Line::from(vec![
        Span::styled(
            format!("[{}] ", time),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            format!("{}: ", msg.sender),
            Style::default().fg(Color::Cyan).bold(),
        ),
        Span::raw(&msg.content),
    ])
}
```

Output example:
```
[14:32] alice: Hello Bob!
[14:33] bob: Hi Alice, how are you?
```

---

## Relationships

```
┌─────────────────────────────────────────────────────────┐
│                    User                                  │
│  ┌─────────────────────────────────────────────────┐   │
│  │ id: "alice"                                      │   │
│  │ username: "alice"                                │   │
│  │ display_name: "Alice"                            │   │
│  │ online: true                                     │   │
│  └─────────────────────────────────────────────────┘   │
│                         │                               │
│                         │ has many                      │
│                         ▼                               │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Contacts                            │   │
│  │  ┌────────────────┐  ┌────────────────┐         │   │
│  │  │ id: "bob"      │  │ id: "charlie"  │         │   │
│  │  │ display: "Bob" │  │ display: "Chas"│         │   │
│  │  │ online: true   │  │ online: false  │         │   │
│  │  └───────┬────────┘  └────────────────┘         │   │
│  └──────────│──────────────────────────────────────┘   │
│             │ has many                                  │
│             ▼                                           │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Messages (with bob)                 │   │
│  │  ┌────────────────────────────────────────┐     │   │
│  │  │ sender: "alice", content: "Hi Bob"     │     │   │
│  │  │ timestamp: 2024-01-15T14:32:00Z        │     │   │
│  │  └────────────────────────────────────────┘     │   │
│  │  ┌────────────────────────────────────────┐     │   │
│  │  │ sender: "bob", content: "Hello!"       │     │   │
│  │  │ timestamp: 2024-01-15T14:33:00Z        │     │   │
│  │  └────────────────────────────────────────┘     │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## Usage in ChatScreen

```rust
pub struct ChatScreen {
    pub contacts: Vec<Contact>,           // List of contacts
    pub messages: Vec<Vec<Message>>,      // Messages per contact
    pub selected_contact: usize,          // Index into contacts
    // ...
}

impl ChatScreen {
    /// Get messages for currently selected contact
    pub fn get_messages_for_selected(&self) -> &[Message] {
        self.messages
            .get(self.selected_contact)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Add message to a contact's conversation
    pub fn add_message(&mut self, contact_idx: usize, message: Message) {
        if contact_idx < self.messages.len() {
            self.messages[contact_idx].push(message);
        }
    }
}
```

---

## Testing

Each model has comprehensive unit tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_new() {
        let user = User::new("alice");
        assert_eq!(user.username, "alice");
        assert_eq!(user.display_name, "alice");
        assert!(!user.online);
    }

    #[test]
    fn test_contact_new() {
        let contact = Contact::new("bob", "Bob Smith");
        assert_eq!(contact.id, "bob");
        assert_eq!(contact.display_name, "Bob Smith");
    }

    #[test]
    fn test_message_timestamp() {
        let msg1 = Message::new("alice", "First");
        let msg2 = Message::new("alice", "Second");
        assert!(msg2.timestamp >= msg1.timestamp);
    }
}
```

Run model tests:
```bash
cargo test model
```
