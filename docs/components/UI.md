# UI Module Documentation

## Overview

The UI module (`src/ui/`, `src/screen/`, `src/event/`) provides the Terminal User Interface (TUI) for Nymstr using the ratatui framework.

## Module Structure

```
src/
├── ui/                     # Rendering
│   ├── mod.rs              # Main render function
│   ├── layout.rs           # Layout calculations
│   ├── components/         # UI components
│   │   ├── mod.rs
│   │   ├── chat.rs         # Chat area
│   │   └── footer.rs       # Status bar
│   └── widgets/            # Custom widgets
│       ├── mod.rs
│       ├── splash.rs       # Splash screen
│       └── input.rs        # Text input
├── screen/                 # Screen state
│   ├── mod.rs
│   └── chat.rs             # Chat screen state
└── event/                  # Event handling
    ├── mod.rs
    └── navigation.rs       # Key bindings
```

---

## Screen Module (`src/screen/`)

### Purpose
Manage UI screen states and data.

### Screen Enumeration

```rust
pub enum Screen {
    Chat(ChatScreen),
    // Future: Settings, Groups, etc.
}

pub struct ScreenState {
    pub current: Screen,
}
```

### Chat Screen (`chat.rs`)

```rust
pub struct ChatScreen {
    /// Current section with focus
    pub section: ChatSection,
    /// List of contacts
    pub contacts: Vec<Contact>,
    /// Currently selected contact index
    pub selected_contact: usize,
    /// Messages per contact (indexed by contact position)
    pub messages: Vec<Vec<Message>>,
    /// Scroll position in message view
    pub chat_scroll: usize,
    /// Ratatui list state for contacts
    pub contacts_state: ListState,
}

pub enum ChatSection {
    Contacts,   // Left panel
    Messages,   // Center panel
    Input,      // Bottom input area
}
```

#### Key Methods

| Method | Description |
|--------|-------------|
| `new()` | Create empty chat screen |
| `select_next_contact()` | Move selection down |
| `select_previous_contact()` | Move selection up |
| `get_selected_contact()` | Get current contact |
| `add_message(contact_idx, message)` | Add message to conversation |
| `get_messages_for_selected()` | Get current conversation |
| `set_section(section)` | Change focus |
| `next_section()` | Cycle through sections |

---

## UI Module (`src/ui/`)

### Main Render Function (`mod.rs`)

```rust
pub fn render_ui(
    frame: &mut Frame,
    app: &App,
) {
    // Calculate layout
    let areas = main_layout(frame.area());

    // Render components based on app phase
    match &app.phase {
        Phase::Splash => render_splash(frame, app),
        Phase::Chat => {
            render_chat(frame, &app.screen, &areas);
            render_footer(frame, app, areas.footer);
        }
        // ... other phases
    }
}
```

### Layout (`layout.rs`)

```rust
pub struct LayoutAreas {
    pub header: Rect,
    pub contacts: Rect,
    pub messages: Rect,
    pub input: Rect,
    pub footer: Rect,
}

pub fn main_layout(area: Rect) -> LayoutAreas {
    // Vertical split: header, main, footer
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),     // Header
            Constraint::Min(10),       // Main content
            Constraint::Length(3),     // Footer
        ])
        .split(area);

    // Horizontal split for main: contacts, messages
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25), // Contacts
            Constraint::Percentage(75), // Messages + Input
        ])
        .split(vertical[1]);

    // Vertical split for right side: messages, input
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(5),        // Messages
            Constraint::Length(3),     // Input
        ])
        .split(horizontal[1]);

    LayoutAreas {
        header: vertical[0],
        contacts: horizontal[0],
        messages: right[0],
        input: right[1],
        footer: vertical[2],
    }
}
```

### Screen Layout

```
┌─────────────────────────────────────────────────────────┐
│                        Header                            │
├──────────────┬──────────────────────────────────────────┤
│              │                                          │
│   Contacts   │              Messages                    │
│              │                                          │
│  > Alice     │  Alice: Hey there!                       │
│    Bob       │  You: Hi Alice!                          │
│    Charlie   │  Alice: How are you?                     │
│              │                                          │
│              ├──────────────────────────────────────────┤
│              │  Input: Type message here...             │
├──────────────┴──────────────────────────────────────────┤
│  Footer: Status | Help: Tab to switch | Ctrl+Q to quit  │
└─────────────────────────────────────────────────────────┘
```

---

## Components (`ui/components/`)

### Chat Component (`chat.rs`)

```rust
pub fn render_chat(
    frame: &mut Frame,
    screen: &ScreenState,
    areas: &LayoutAreas,
) {
    if let Screen::Chat(chat) = &screen.current {
        render_contacts(frame, chat, areas.contacts);
        render_messages(frame, chat, areas.messages);
        render_input(frame, chat, areas.input);
    }
}
```

#### Contacts Panel

```rust
fn render_contacts(frame: &mut Frame, chat: &ChatScreen, area: Rect) {
    let items: Vec<ListItem> = chat.contacts
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

    let list = List::new(items)
        .block(Block::default()
            .title("Contacts")
            .borders(Borders::ALL)
            .border_style(border_style(chat, ChatSection::Contacts)))
        .highlight_style(Style::default().bg(Color::DarkGray));

    frame.render_stateful_widget(list, area, &mut chat.contacts_state.clone());
}
```

#### Messages Panel

```rust
fn render_messages(frame: &mut Frame, chat: &ChatScreen, area: Rect) {
    let messages = chat.get_messages_for_selected();

    let lines: Vec<Line> = messages
        .iter()
        .map(|msg| message_to_line(msg))
        .collect();

    let paragraph = Paragraph::new(lines)
        .block(Block::default()
            .title("Messages")
            .borders(Borders::ALL)
            .border_style(border_style(chat, ChatSection::Messages)))
        .scroll((chat.chat_scroll as u16, 0));

    frame.render_widget(paragraph, area);
}

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

#### Input Area

```rust
fn render_input(frame: &mut Frame, chat: &ChatScreen, area: Rect) {
    let input = Paragraph::new(chat.input_buffer.as_str())
        .block(Block::default()
            .title("Message")
            .borders(Borders::ALL)
            .border_style(border_style(chat, ChatSection::Input)));

    frame.render_widget(input, area);

    // Show cursor if input is focused
    if chat.section == ChatSection::Input {
        frame.set_cursor(
            area.x + chat.input_buffer.len() as u16 + 1,
            area.y + 1,
        );
    }
}
```

### Footer Component (`footer.rs`)

```rust
pub fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let status = format!(
        "{} | {} | {}",
        app.logged_in_user.as_ref()
            .map(|u| format!("User: {}", u.username))
            .unwrap_or("Not logged in".to_string()),
        "Tab: Switch section",
        "Ctrl+Q: Quit",
    );

    let footer = Paragraph::new(status)
        .style(Style::default().fg(Color::White).bg(Color::DarkGray));

    frame.render_widget(footer, area);
}
```

---

## Widgets (`ui/widgets/`)

### Splash Screen (`splash.rs`)

```rust
pub struct SplashWidget {
    frames: Vec<String>,    // Figlet ASCII art frames
    current_frame: usize,
}

impl SplashWidget {
    pub fn new(frames: Vec<String>) -> Self;
    pub fn next_frame(&mut self);
    pub fn render(&self, frame: &mut Frame, area: Rect);
}
```

### Input Widget (`input.rs`)

```rust
pub struct InputWidget {
    content: String,
    cursor_position: usize,
    placeholder: String,
}

impl InputWidget {
    pub fn new(placeholder: &str) -> Self;
    pub fn insert_char(&mut self, c: char);
    pub fn delete_char(&mut self);
    pub fn move_cursor_left(&mut self);
    pub fn move_cursor_right(&mut self);
    pub fn get_content(&self) -> &str;
    pub fn clear(&mut self);
}
```

---

## Event Module (`src/event/`)

### Key Event Handling (`mod.rs`)

```rust
pub fn handle_key_event(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        // Global bindings
        KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.running = false;
            return true;
        }

        // Phase-specific handling
        _ => match &app.phase {
            Phase::Chat => handle_chat_keys(app, key),
            Phase::Login => handle_login_keys(app, key),
            Phase::Search => handle_search_keys(app, key),
            _ => false,
        }
    }
}
```

### Chat Key Bindings

| Key | Action |
|-----|--------|
| `Tab` | Next section |
| `i` | Focus input |
| `s` | Open search |
| `g` | Open group search |
| `Esc` | Exit current section |
| `Up/k` | Previous item |
| `Down/j` | Next item |
| `Enter` | Select/send |
| `Backspace` | Delete character |
| Regular char | Type in input |

```rust
fn handle_chat_keys(app: &mut App, key: KeyEvent) -> bool {
    if let Screen::Chat(chat) = &mut app.screen.current {
        match chat.section {
            ChatSection::Contacts => {
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        chat.select_previous_contact();
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        chat.select_next_contact();
                    }
                    KeyCode::Enter => {
                        chat.set_section(ChatSection::Messages);
                    }
                    KeyCode::Tab => {
                        chat.next_section();
                    }
                    _ => return false,
                }
            }
            ChatSection::Input => {
                match key.code {
                    KeyCode::Enter => {
                        // Send message
                        let content = app.input_buffer.clone();
                        app.send_message(&content);
                        app.input_buffer.clear();
                    }
                    KeyCode::Char(c) => {
                        app.input_buffer.push(c);
                    }
                    KeyCode::Backspace => {
                        app.input_buffer.pop();
                    }
                    KeyCode::Esc => {
                        chat.set_section(ChatSection::Messages);
                    }
                    _ => return false,
                }
            }
            // ... Messages section
        }
    }
    true
}
```

---

## Application Phases

```rust
pub enum Phase {
    Splash,      // Startup animation
    Connect,     // Connecting to mixnet
    Login,       // Login prompt
    Chat,        // Main chat view
    Search,      // User search
    GroupSearch, // Group search
}
```

### Phase Transitions

```
Splash → Connect → Login → Chat
                     ↑       │
                     └───────┘ (logout)

Chat ←→ Search (s key)
Chat ←→ GroupSearch (g key)
```

---

## Styling

### Color Scheme

| Element | Color |
|---------|-------|
| Active border | Cyan |
| Inactive border | Gray |
| Online contact | Green |
| Offline contact | Gray |
| Message sender | Cyan (bold) |
| Message time | Dark Gray |
| Input cursor | White |
| Footer background | Dark Gray |

### Border Styles

```rust
fn border_style(chat: &ChatScreen, section: ChatSection) -> Style {
    if chat.section == section {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::Gray)
    }
}
```

---

## Integration with App State

The UI modules interact with the main `App` struct:

```rust
pub struct App {
    pub running: bool,
    pub phase: Phase,
    pub screen: ScreenState,
    pub logged_in_user: Option<User>,
    pub input_buffer: String,
    pub handler: MessageHandler,
    pub pending_outgoing: Vec<PendingMessage>,
    // ... other fields
}
```

### Render Loop

```rust
// In app.rs
pub async fn run(&mut self) -> Result<()> {
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

    loop {
        // Render UI
        terminal.draw(|frame| {
            render_ui(frame, self);
        })?;

        // Handle events
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                handle_key_event(self, key);
            }
        }

        // Process messages
        self.process_messages().await?;

        if !self.running {
            break;
        }
    }

    Ok(())
}
```
