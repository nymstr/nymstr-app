 # nymstr
 
 > **⚠️ Under Active Development**
 > This is a minimal prototype and may contain bugs. Features and APIs may
 change without notice.
 
 Use the steps below to get started:
 
 ## Quickstart
 
 1. Set the server address:
 
    ```bash
    echo 'SERVER_ADDRESS=<server_address>' >> .env
    ```
 
2. Build and run the client:
 
    ```bash
    cargo run
    ```
 
 ## Keybindings (Chat UI Navigation)
 
 **Global**
 
 - `q` or `Ctrl+Q` — Quit the application
 
 ---
 
 **Messages Section** (default)
 
 - `Tab` — Switch focus to **Contacts**
 - `i` — Switch focus to **Input**
 - `s` — Open **Search** mode
- `g` — Open **Group Search** mode
 - `q` — Quit
 
 ---
 
 **Contacts Section**
 
 - `↑` / `↓` — Move up/down the contact list
 - `Tab` — Next contact
 - `Enter` — Select highlighted contact (show messages)
 - `Esc` — Back to **Messages**
 
 ---
 
 **Input Section**
 
 - *Type to compose*
 - `Enter` — Send message
 - `Esc` — Back to **Messages**
 
 ---
 
 **Search Mode**
 
 - *Type* — Enter username query
 - `Enter` — Submit search (loader appears)
 - `1` — Start chat with found user
 - `2` — Search again (clear)
 - `3` or `Esc` — Cancel and return to **Chat**
 
 ---
**Group Search Mode**

- *Type* — Enter group server address
- `Enter` — Connect to group server
- `1` — View group messages (when connected)
- `2` — Search again (clear)
- `3` or `Esc` — Cancel and return to **Chat**

---

**Group View Mode**

- `i` — Switch to input mode to type messages
- `s` — Get server statistics (queue status)
- `Esc` — Return to **Chat**

---

**Group Input Mode**

- *Type* — Enter message text
- `Enter` — Send message to group
- `Esc` — Return to **Group View**

---

