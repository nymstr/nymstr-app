use crate::core::message_handler::MessageHandler;
use crate::event::handle_key_event;
use crate::log_buffer::LOG_BUFFER;
use crate::model::contact::Contact;
use crate::model::message::Message;
use crate::model::user::User;
use crate::screen::ScreenState;
use crossterm::event::{self, Event as CEvent, KeyCode};
use log::info;
use ratatui::layout::Rect;
use ratatui::{DefaultTerminal, Frame};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::sync::Mutex;
use std::time::Duration;

/// The different UI phases
/// The different UI phases
#[derive(Debug, PartialEq, Eq)]
pub enum Phase {
    Connect,
    Connecting,
    Welcome,
    Register,
    Registering,
    RegisterSuccess,
    Login,
    LoggingIn,
    Chat,
    Search,
    GroupSearch,
    GroupView,
    GroupInput,
}

pub struct App {
    pub running: bool,
    /// Current UI phase
    pub(crate) phase: Phase,
    pub screen: ScreenState,
    pub logged_in_user: Option<User>,
    pub input_buffer: String,
    /// Backend message handler (initialized on connect)
    pub handler: Option<MessageHandler>,
    /// Post-registration success flag
    reg_success: bool,
    /// Search mode buffer & result
    search_buffer: String,
    search_result: Option<String>,
    // search loading animation state
    search_loading: bool,
    search_spinner_idx: usize,
    // handle for in-flight search query (returns handler and query result)
    search_handle:
        Option<tokio::task::JoinHandle<(MessageHandler, anyhow::Result<Option<(String, String)>>)>>,
    /// Group search mode buffer & result
    group_search_buffer: String,
    group_search_result: Option<String>,
    group_search_loading: bool,
    group_search_spinner_idx: usize,
    group_search_handle: Option<tokio::task::JoinHandle<(MessageHandler, anyhow::Result<bool>)>>,
    /// Group messages
    group_messages: Vec<String>,
    /// Group authentication state
    group_authenticated: bool,
    group_server_address: String,
    /// Group input buffer for typing messages
    group_input_buffer: String,
    /// Log panel scroll offset (0 = bottom/latest)
    log_scroll: usize,
    /// Outgoing messages queued for sending after local echo
    pub(crate) pending_outgoing: Vec<(usize, String)>,
    // Splash animation state
    splash_pages: Vec<String>,       // pre-rendered Figlet outputs
    splash_fonts: Vec<&'static str>, // font names for labels
    splash_idx: usize,               // current font/page index
    splash_step: usize,              // current glow step (0..max)
    splash_rising: bool,             // glow direction
    spinner_idx: usize,              // spinner animation index
}

impl App {
    pub fn new() -> Self {
        Self {
            running: true,
            phase: Phase::Connect,
            screen: ScreenState::default(),
            logged_in_user: None,
            input_buffer: String::new(),
            handler: None,
            reg_success: false,
            search_buffer: String::new(),
            search_result: None,
            search_loading: false,
            search_spinner_idx: 0,
            search_handle: None,
            group_search_buffer: String::new(),
            group_search_result: None,
            group_search_loading: false,
            group_search_spinner_idx: 0,
            group_search_handle: None,
            group_messages: Vec::new(),
            group_authenticated: false,
            group_server_address: String::new(),
            group_input_buffer: String::new(),
            log_scroll: 0,
            pending_outgoing: Vec::new(),
            // Splash animation state
            splash_pages: Vec::new(),
            splash_fonts: vec![
                "slant",
                "roman",
                "red_phoenix",
                "rammstein",
                "poison",
                "maxiwi",
                "merlin1",
                "larry 3d",
                "ghost",
                "georgi16",
                "flowerpower",
                "dos rebel",
                "dancingfont",
                "cosmike",
                "bloody",
                "blocks",
                "big money-sw",
                "banner3-d",
                "amc aaa01",
                "3d-ascii",
            ],
            splash_idx: 0,
            splash_step: 0,
            splash_rising: true,
            spinner_idx: 0,
        }
    }
    /// Pre-render a single random splash page by calling figlet for one randomly chosen font
    pub fn load_splash(&mut self) -> io::Result<()> {
        let font_dir = "/usr/share/figlet";
        // Build lowercase → filename map for .flf files
        let mut map: HashMap<String, String> = HashMap::new();
        for entry in fs::read_dir(font_dir)? {
            let entry = entry?;
            let f = entry.file_name().into_string().unwrap_or_default();
            if f.to_lowercase().ends_with(".flf") {
                let name = f[..f.len() - 4].to_lowercase();
                map.insert(name, f);
            }
        }
        // Select one random font from the list
        let idx = fastrand::usize(..self.splash_fonts.len());
        let font = self.splash_fonts[idx];
        let key = font.to_lowercase();
        // Attempt to render with figlet, fallback on missing
        let page = if let Some(filename) = map.get(&key) {
            let path = format!("{}/{}", font_dir, filename);
            match std::process::Command::new("figlet")
                .args(&["-f", &path, "nymstr"])
                .output()
            {
                Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
                _ => format!("★ missing font: {} ★", font),
            }
        } else {
            format!("★ missing font: {} ★", font)
        };
        // Store only the selected splash page
        self.splash_pages.clear();
        self.splash_pages.push(page);
        // Reset indexes
        self.splash_idx = 0;
        self.splash_step = 0;
        self.splash_rising = true;
        Ok(())
    }

    pub async fn run(&mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        // Splash phase (animated)
        let splash_timeout = Duration::from_millis(100);
        const MAX_STEPS: usize = 20;
        loop {
            terminal.draw(|f| self.draw_splash(f))?;
            // on any key, either quit or advance to Connecting
            if event::poll(splash_timeout)? {
                if let CEvent::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') => {
                            // exit the app immediately
                            self.quit();
                            return Ok(());
                        }
                        _ => {
                            // any other key → proceed to connecting
                            self.phase = Phase::Connecting;
                            break;
                        }
                    }
                }
            }
            // update glow and cycle fonts
            if self.splash_rising {
                self.splash_step += 1;
                if self.splash_step >= MAX_STEPS {
                    self.splash_rising = false;
                }
            } else {
                self.splash_step = self.splash_step.saturating_sub(1);
                if self.splash_step == 0 {
                    self.splash_rising = true;
                    self.splash_idx = (self.splash_idx + 1) % self.splash_pages.len();
                }
            }
        }
        // Connecting: spawn mixnet client creation and show spinner until done or timeout
        self.spinner_idx = 0;
        let connect_handle = tokio::spawn(async {
            crate::core::mixnet_client::MixnetService::new("storage/client.db").await
        });
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(10);
        while !connect_handle.is_finished() {
            terminal.draw(|f| self.draw(f))?;
            // advance spinner and throttle
            std::thread::sleep(Duration::from_millis(100));
            // update spinner index
            self.spinner_idx = self.spinner_idx.wrapping_add(1);
            // update splash glow and cycle fonts
            if self.splash_rising {
                self.splash_step += 1;
                if self.splash_step >= MAX_STEPS {
                    self.splash_rising = false;
                }
            } else {
                self.splash_step = self.splash_step.saturating_sub(1);
                if self.splash_step == 0 {
                    self.splash_rising = true;
                    self.splash_idx = (self.splash_idx + 1) % self.splash_pages.len();
                }
            }
            if start.elapsed() >= timeout {
                // timed out: cancel attempt
                connect_handle.abort();
                break;
            }
        }
        // Retrieve connection result if any
        if let Ok(conn_res) = connect_handle.await {
            match conn_res {
                Ok((svc, rx)) => {
                    if let Ok(handler) = MessageHandler::new(svc, rx, "storage/client.db").await {
                        self.handler = Some(handler);
                    }
                }
                Err(e) => {
                    log::error!("Mixnet connection failed: {}", e);
                }
            }
        }
        // Move to welcome screen
        self.phase = Phase::Welcome;
        // Main event loop
        while self.running {
            // —————— Poll outstanding search and advance spinner ——————
            if let Some(handle) = &mut self.search_handle {
                if handle.is_finished() {
                    // retrieve handler and result
                    if let Ok((handler, res)) = handle.await {
                        // restore handler
                        self.handler = Some(handler);
                        // set search result
                        match res {
                            Ok(opt) => {
                                self.search_result =
                                    opt.map(|(u, _)| u).or(Some("<not found>".into()));
                            }
                            Err(_) => {
                                self.search_result = Some("<not found>".into());
                            }
                        }
                    }
                    self.search_handle = None;
                    self.search_loading = false;
                } else {
                    // animate loader
                    self.search_spinner_idx = self.search_spinner_idx.wrapping_add(1);
                }
            }

            // —————— Poll outstanding group search and advance spinner ——————
            if let Some(handle) = &mut self.group_search_handle {
                if handle.is_finished() {
                    // retrieve handler and result
                    if let Ok((handler, res)) = handle.await {
                        // restore handler
                        self.handler = Some(handler);
                        // set group search result
                        match res {
                            Ok(success) if success => {
                                self.group_search_result = Some("Authenticated with group".to_string());
                                self.group_authenticated = true;
                            }
                            Ok(_) => {
                                self.group_search_result = Some("Authentication failed".to_string());
                            }
                            Err(_) => {
                                self.group_search_result = Some("Connection failed".to_string());
                            }
                        }
                    }
                    self.group_search_handle = None;
                    self.group_search_loading = false;
                } else {
                    // animate loader
                    self.group_search_spinner_idx = self.group_search_spinner_idx.wrapping_add(1);
                }
            }
            // ——— auto‑drain incoming messages ———
            if let Some(handler) = &mut self.handler {
                while let Ok(incoming_msg) = handler.incoming_rx.try_recv() {
                    let msgs = handler.process_received_message(incoming_msg).await;
                    for (from, text) in msgs {
                        // Check if this is a group message by looking at the message format
                        if text.starts_with("Group:") || self.phase == Phase::GroupView || self.phase == Phase::GroupInput {
                            // Add to group messages
                            self.group_messages.push(format!("{}: {}", from, text));
                        } else if self.phase == Phase::Chat {
                            // Add to regular chat messages
                            if let Some(chat) = self.screen.as_chat_mut() {
                                let idx = match chat.contacts.iter().position(|c| c.id == from) {
                                    Some(i) => i,
                                    None => {
                                        chat.contacts.push(Contact::new(&from));
                                        chat.messages.push(Vec::new());
                                        // Save new contact to database
                                        if let Some(current_user) = &self.logged_in_user {
                                            let _ = handler.db.add_contact(&current_user.username, &from, "").await;
                                        }
                                        chat.contacts.len() - 1
                                    }
                                };
                                chat.messages[idx].push(Message::new(&from, &text));
                            }
                        }
                    }
                }
            }
            // draw every frame
            terminal.draw(|f| self.draw(f))?;
            // small delay to reduce CPU
            std::thread::sleep(Duration::from_millis(50));
            if event::poll(Duration::from_millis(100))? {
                if let CEvent::Key(key) = event::read()? {
                    // scroll log panel for non-chat phases
                    if self.phase != Phase::Chat {
                        match key.code {
                            KeyCode::Up => {
                                self.log_scroll = self.log_scroll.saturating_add(1);
                                continue;
                            }
                            KeyCode::Down => {
                                self.log_scroll = self.log_scroll.saturating_sub(1);
                                continue;
                            }
                            _ => {}
                        }
                    }
                    match self.phase {
                        Phase::Welcome => match key.code {
                            KeyCode::Char('l') | KeyCode::Char('L') => {
                                self.input_buffer.clear();
                                self.phase = Phase::Login;
                            }
                            KeyCode::Char('r') | KeyCode::Char('R') => {
                                self.input_buffer.clear();
                                self.phase = Phase::Register;
                            }
                            KeyCode::Char('q') => self.quit(),
                            _ => {}
                        },
                        Phase::Register => match key.code {
                            KeyCode::Char(c) => self.input_buffer.push(c),
                            KeyCode::Backspace => {
                                self.input_buffer.pop();
                            }
                            KeyCode::Enter => {
                                if let Some(mut handler) = self.handler.take() {
                                    let user = self.input_buffer.clone();
                                    if let Ok(mut logs) = LOG_BUFFER.lock() {
                                        logs.clear();
                                    }
                                    info!("Registering user: {}", user);
                                    // spawn registration task, moving handler
                                    let reg_handle = tokio::spawn(async move {
                                        let success =
                                            handler.register_user(&user).await.unwrap_or(false);
                                        (handler, success)
                                    });
                                    self.phase = Phase::Registering;
                                    // poll task until completion, updating UI
                                    while !reg_handle.is_finished() {
                                        terminal.draw(|f| self.draw(f))?;
                                        std::thread::sleep(Duration::from_millis(100));
                                        self.spinner_idx = self.spinner_idx.wrapping_add(1);
                                    }
                                    // retrieve handler and result
                                    match reg_handle.await {
                                        Ok((handler, success)) => {
                                            self.handler = Some(handler);
                                            if success {
                                                self.reg_success = true;
                                                self.phase = Phase::RegisterSuccess;
                                            } else {
                                                if let Ok(mut logs) = LOG_BUFFER.lock() {
                                                    logs.push("Registration failed".to_string());
                                                }
                                                self.phase = Phase::Register;
                                            }
                                        }
                                        Err(e) => {
                                            if let Ok(mut logs) = LOG_BUFFER.lock() {
                                                logs.push(format!(
                                                    "Registration task failed: {:?}",
                                                    e
                                                ));
                                            }
                                            self.phase = Phase::Register;
                                        }
                                    }
                                }
                            }
                            KeyCode::Esc => self.phase = Phase::Welcome,
                            _ => {}
                        },
                        Phase::RegisterSuccess => match key.code {
                            KeyCode::Char('l') | KeyCode::Char('L') => {
                                self.phase = Phase::Login;
                                self.input_buffer.clear();
                            }
                            KeyCode::Esc => self.phase = Phase::Welcome,
                            _ => {}
                        },
                        Phase::Login => match key.code {
                            KeyCode::Char(c) => self.input_buffer.push(c),
                            KeyCode::Backspace => {
                                self.input_buffer.pop();
                            }
                            KeyCode::Enter => {
                                if let Some(mut handler) = self.handler.take() {
                                    let user = self.input_buffer.clone();
                                    let user_task = user.clone();
                                    if let Ok(mut logs) = LOG_BUFFER.lock() {
                                        logs.clear();
                                    }
                                    info!("Logging in user: {}", user);
                                    let login_handle = tokio::spawn(async move {
                                        let success =
                                            handler.login_user(&user_task).await.unwrap_or(false);
                                        (handler, success)
                                    });
                                    self.phase = Phase::LoggingIn;
                                    while !login_handle.is_finished() {
                                        terminal.draw(|f| self.draw(f))?;
                                        std::thread::sleep(Duration::from_millis(100));
                                        self.spinner_idx = self.spinner_idx.wrapping_add(1);
                                    }
                                    match login_handle.await {
                                        Ok((handler, success)) => {
                                            self.handler = Some(handler);
                                            if success {
                                                self.logged_in_user = Some(User {
                                                    id: user.clone(),
                                                    username: user.clone(),
                                                    display_name: user.clone(),
                                                    online: true,
                                                });
                                                // clear so the chat input box starts empty
                                                self.input_buffer.clear();
                                                self.phase = Phase::Chat;
                                                // Load chat history after successful login
                                                if let Err(e) = self.load_chat_history_to_screen().await {
                                                    if let Ok(mut logs) = LOG_BUFFER.lock() {
                                                        logs.push(format!("Failed to load chat history: {:?}", e));
                                                    }
                                                }
                                            } else {
                                                if let Ok(mut logs) = LOG_BUFFER.lock() {
                                                    logs.push("Login failed".to_string());
                                                }
                                                self.phase = Phase::Login;
                                            }
                                        }
                                        Err(e) => {
                                            if let Ok(mut logs) = LOG_BUFFER.lock() {
                                                logs.push(format!("Login task failed: {:?}", e));
                                            }
                                            self.phase = Phase::Login;
                                        }
                                    }
                                }
                            }
                            KeyCode::Esc => self.phase = Phase::Welcome,
                            _ => {}
                        },
                        Phase::Chat => {
                            // 1) Drain incoming messages
                            if let Some(handler) = &mut self.handler {
                                while let Ok(incoming_msg) = handler.incoming_rx.try_recv() {
                                    let msgs = handler.process_received_message(incoming_msg).await;
                                    for (from, text) in msgs {
                                        if let Some(chat) = self.screen.as_chat_mut() {
                                            let idx = match chat
                                                .contacts
                                                .iter()
                                                .position(|c| c.id == from)
                                            {
                                                Some(i) => i,
                                                None => {
                                                    chat.contacts.push(Contact::new(&from));
                                                    chat.messages.push(Vec::new());
                                                    chat.contacts.len() - 1
                                                }
                                            };
                                            chat.messages[idx].push(Message::new(&from, &text));
                                        }
                                    }
                                }
                            }

                            // 2) Dispatch key to unified handler
                            handle_key_event(self, key)?;

                            // 3) Send queued outgoing messages via backend
                            if let Some(handler) = &mut self.handler {
                                let pending = std::mem::take(&mut self.pending_outgoing);
                                for (sel, msg) in pending {
                                    if let Some(chat) = self.screen.as_chat_mut() {
                                        if sel < chat.contacts.len() {
                                            let to = chat.contacts[sel].id.clone();
                                            if let Err(e) =
                                                handler.send_direct_message(&to, &msg).await
                                            {
                                                chat.messages[sel].push(Message::new(
                                                    "error",
                                                    &format!("send failed: {}", e),
                                                ));
                                                chat.chat_scroll =
                                                    chat.messages[sel].len().saturating_sub(1);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Phase::Search => {
                            match key.code {
                                // --- MENU COMMANDS (only when a result is present) ---
                                KeyCode::Char('1')
                                    if self
                                        .search_result
                                        .as_deref()
                                        .map(|r| r != "<not found>")
                                        .unwrap_or(false) =>
                                {
                                    // Start chat
                                    if let Some(username) = &self.search_result {
                                        let chat = self.screen.as_chat_mut().unwrap();
                                        chat.contacts.push(Contact::new(username));
                                        chat.messages.push(Vec::new());
                                        chat.highlighted_contact = chat.contacts.len() - 1;
                                        chat.contacts_state.select(Some(chat.highlighted_contact));
                                    }
                                    // Clear search state and exit
                                    self.search_buffer.clear();
                                    self.search_result = None;
                                    self.search_loading = false;
                                    self.search_handle = None;
                                    self.phase = Phase::Chat;
                                }
                                KeyCode::Char('2') if self.search_result.is_some() => {
                                    // Search again: clear only search state
                                    self.search_buffer.clear();
                                    self.search_result = None;
                                    self.search_loading = false;
                                    self.search_handle = None;
                                }
                                KeyCode::Char('3') | KeyCode::Esc
                                    if self.search_result.is_some() =>
                                {
                                    // Back to chat: clear state and exit
                                    self.search_buffer.clear();
                                    self.search_result = None;
                                    self.search_loading = false;
                                    self.search_handle = None;
                                    self.phase = Phase::Chat;
                                }

                                // --- REGULAR TYPING (only when no result & not loading) ---
                                KeyCode::Char(c)
                                    if !self.search_loading && self.search_result.is_none() =>
                                {
                                    self.search_buffer.push(c);
                                }
                                KeyCode::Backspace
                                    if !self.search_loading && self.search_result.is_none() =>
                                {
                                    self.search_buffer.pop();
                                }

                                // --- START SEARCH (only when no result & not loading) ---
                                KeyCode::Enter
                                    if !self.search_loading && self.search_result.is_none() =>
                                {
                                    // start the query, taking handler
                                    if let Some(mut handler) = self.handler.take() {
                                        let q = self.search_buffer.clone();
                                        let h = tokio::spawn(async move {
                                            let res = handler.query_user(&q).await;
                                            (handler, res)
                                        });
                                        self.search_handle = Some(h);
                                        self.search_loading = true;
                                        self.search_spinner_idx = 0;
                                    }
                                }

                                // Ignore all other keys in Search
                                _ => {}
                            }
                        }
                        Phase::GroupSearch => {
                            match key.code {
                                // --- MENU COMMANDS (only when authenticated) ---
                                KeyCode::Char('1')
                                    if self.group_authenticated =>
                                {
                                    // View group messages
                                    self.phase = Phase::GroupView;
                                }
                                KeyCode::Char('2') if self.group_search_result.is_some() => {
                                    // Search again: clear only search state
                                    self.group_search_buffer.clear();
                                    self.group_search_result = None;
                                    self.group_search_loading = false;
                                    self.group_search_handle = None;
                                }
                                KeyCode::Char('3') | KeyCode::Esc
                                    if self.group_search_result.is_some() =>
                                {
                                    // Back to chat: clear state and exit
                                    self.group_search_buffer.clear();
                                    self.group_search_result = None;
                                    self.group_search_loading = false;
                                    self.group_search_handle = None;
                                    self.phase = Phase::Chat;
                                }

                                // --- REGULAR TYPING (only when no result & not loading) ---
                                KeyCode::Char(c)
                                    if !self.group_search_loading && self.group_search_result.is_none() =>
                                {
                                    self.group_search_buffer.push(c);
                                }
                                KeyCode::Backspace
                                    if !self.group_search_loading && self.group_search_result.is_none() =>
                                {
                                    self.group_search_buffer.pop();
                                }

                                // --- START GROUP SEARCH (only when no result & not loading) ---
                                KeyCode::Enter
                                    if !self.group_search_loading && self.group_search_result.is_none() =>
                                {
                                    // Start group authentication
                                    if let Some(mut handler) = self.handler.take() {
                                        if let Some(user) = &self.logged_in_user {
                                            let username = user.username.clone();
                                            let server_addr = self.group_search_buffer.clone();
                                            // Store the server address for later use
                                            self.group_server_address = server_addr.clone();
                                            let h = tokio::spawn(async move {
                                                let res = handler.authenticate_group(&username, &server_addr).await;
                                                (handler, res)
                                            });
                                            self.group_search_handle = Some(h);
                                            self.group_search_loading = true;
                                            self.group_search_spinner_idx = 0;
                                        } else {
                                            self.group_search_result = Some("Please login first".to_string());
                                        }
                                    }
                                }

                                // Ignore all other keys in GroupSearch
                                _ => {}
                            }
                        }
                        Phase::GroupView => {
                            match key.code {
                                KeyCode::Char('s') => {
                                    // Get server statistics
                                    if let Some(mut handler) = self.handler.take() {
                                        let group_addr = self.group_server_address.clone();
                                        let h = tokio::spawn(async move {
                                            let res = handler.get_group_stats(&group_addr).await;
                                            // Convert () to bool for consistency
                                            (handler, res.map(|_| true))
                                        });
                                        self.group_search_handle = Some(h);
                                        self.group_search_loading = true;
                                    }
                                }
                                KeyCode::Char('i') => {
                                    // Switch to input mode
                                    self.phase = Phase::GroupInput;
                                }
                                KeyCode::Esc => {
                                    // Back to chat
                                    self.phase = Phase::Chat;
                                }
                                _ => {}
                            }
                        }
                        Phase::GroupInput => {
                            match key.code {
                                KeyCode::Char(c) => {
                                    self.group_input_buffer.push(c);
                                }
                                KeyCode::Backspace => {
                                    self.group_input_buffer.pop();
                                }
                                KeyCode::Enter => {
                                    // Send message to group
                                    if !self.group_input_buffer.trim().is_empty() {
                                        if let Some(mut handler) = self.handler.take() {
                                            let message = self.group_input_buffer.clone();
                                            let message_display = message.clone();
                                            let group_addr = self.group_server_address.clone();
                                            let h = tokio::spawn(async move {
                                                let res = handler.send_group_message(&message, &group_addr).await;
                                                // Convert () to bool for consistency
                                                (handler, res.map(|_| true))
                                            });
                                            self.group_search_handle = Some(h);
                                            self.group_search_loading = true;
                                            // Add message to local display immediately
                                            let user = self.logged_in_user.as_ref().map(|u| u.username.as_str()).unwrap_or("You");
                                            self.group_messages.push(format!("{}: {}", user, message_display));
                                            self.group_input_buffer.clear();
                                        }
                                    }
                                    self.phase = Phase::GroupView;
                                }
                                KeyCode::Esc => {
                                    // Back to group view
                                    self.phase = Phase::GroupView;
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }

    pub fn draw(&mut self, frame: &mut Frame) {
        use ratatui::layout::{Constraint, Direction, Layout, Rect};
        use ratatui::widgets::Clear;
        // during connecting, show splash with spinner bar
        if self.phase == Phase::Connecting {
            frame.render_widget(Clear, frame.area());
            self.draw_splash(frame);
            return;
        }
        // clear entire frame
        frame.render_widget(Clear, frame.area());
        // reserve top for log panel (4 rows: border + 2 lines + border) and rest for content
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(4), Constraint::Min(0)].as_ref())
            .split(frame.area());
        // combined log panel
        self.render_log_box(frame, chunks[0], "Logs", &LOG_BUFFER);
        // content area below logs
        let content_area: Rect = chunks[1];
        use Phase::*;
        match self.phase {
            Connect => self.draw_connect(frame, content_area),
            Connecting => self.draw_connecting(frame, content_area),
            Registering => {
                let username = &self.input_buffer;
                self.draw_registration_status(frame, content_area, username);
            }
            Welcome => self.draw_welcome(frame, content_area),
            Register => self.draw_register(frame, content_area),
            RegisterSuccess => self.draw_register_success(frame, content_area),
            LoggingIn => {
                let username = &self.input_buffer;
                self.draw_login_status(frame, content_area, username);
            }
            Login => self.draw_login(frame, content_area),
            Chat => crate::ui::render_ui(self, frame, content_area),
            Search => self.draw_search(frame, content_area),
            GroupSearch => self.draw_group_search(frame, content_area),
            GroupView => self.draw_group_view(frame, content_area),
            GroupInput => self.draw_group_input(frame, content_area),
        }
    }

    pub fn quit(&mut self) {
        self.running = false;
    }
    // --- UI phase drawing helpers ---
    fn draw_connect(&self, frame: &mut Frame, area: Rect) {
        use ratatui::{
            layout::Alignment,
            widgets::{Block, Borders, Paragraph},
        };
        let p = Paragraph::new("press any button to connect to mixnet, q to quit")
            .block(Block::default().borders(Borders::NONE))
            .alignment(Alignment::Center);
        frame.render_widget(p, area);
    }
    fn draw_connecting(&self, frame: &mut Frame, area: Rect) {
        use crate::log_buffer::LOG_BUFFER;
        use ratatui::{
            text::{Line, Text},
            widgets::{Block, Borders, Clear, Paragraph, Wrap},
        };
        frame.render_widget(Clear, area);
        let block = Block::default().borders(Borders::ALL).title("Mixnet Logs");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let logs = LOG_BUFFER.lock().unwrap();
        let lines: Vec<Line> = logs.iter().map(|l| Line::from(l.as_str())).collect();
        let paragraph = Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false });
        frame.render_widget(paragraph, inner);
    }

    fn draw_splash(&self, frame: &mut Frame) {
        use crate::ui::widgets::splash;

        let splash_text = &self.splash_pages[self.splash_idx];
        // only spin once the user has pressed a key (i.e. in Connecting phase)
        let show_spinner = self.phase == Phase::Connecting;
        let label = match self.phase {
            // include the quit hint on initial splash
            Phase::Connect => "press any button to connect to mixnet, q to quit",
            Phase::Connecting => "Connecting to Mixnet",
            _ => "",
        };

        splash::render_splash(
            frame,
            frame.area(),
            splash_text,
            self.splash_step,
            true,         // still glow dynamically
            show_spinner, // only bounce once Connecting
            self.spinner_idx,
            label,
        );
    }

    // Registration and login animated status screens
    fn draw_registration_status(&self, frame: &mut Frame, area: Rect, username: &str) {
        use crate::ui::widgets::splash;
        let label = format!("Registering {}", username);
        splash::render_splash(
            frame,
            area,
            &self.splash_pages[self.splash_idx],
            20,
            false,
            true,
            self.spinner_idx,
            &label,
        );
    }

    fn draw_login_status(&self, frame: &mut Frame, area: Rect, username: &str) {
        use crate::ui::widgets::splash;
        let label = format!("Logging in as {}", username);
        splash::render_splash(
            frame,
            area,
            &self.splash_pages[self.splash_idx],
            20,
            false,
            true,
            self.spinner_idx,
            &label,
        );
    }

    // Bouncing-ball logic moved to ui/widgets/splash.rs
    fn draw_welcome(&self, frame: &mut Frame, area: Rect) {
        use ratatui::{
            layout::{Alignment, Constraint, Direction, Layout},
            style::{Color, Style},
            widgets::{Block, Borders, Paragraph},
        };

        let block = Block::default()
            .title("Welcome")
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Rgb(0, 255, 0)));

        let inner = block.inner(area);
        frame.render_widget(block, area);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Percentage(40),
                    Constraint::Percentage(20),
                    Constraint::Percentage(40),
                ]
                .as_ref(),
            )
            .split(inner);

        let opts = "[L] Login    [R] Register    [Q] Quit";
        let p = Paragraph::new(opts)
            .style(Style::default().fg(Color::Rgb(0, 255, 0)))
            .alignment(Alignment::Center);
        frame.render_widget(p, chunks[1]);
    }
    fn draw_register(&self, frame: &mut Frame, area: Rect) {
        use ratatui::{
            layout::{Alignment, Constraint, Direction, Layout},
            widgets::{Block, Borders, Paragraph},
        };
        let title = "Register: Enter username and press Enter";
        let block = Block::default().title(title).borders(Borders::ALL);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Percentage(50),
                    Constraint::Length(3),
                    Constraint::Percentage(47),
                ]
                .as_ref(),
            )
            .split(inner);
        let input = Paragraph::new(self.input_buffer.as_str())
            .block(Block::default().borders(Borders::ALL).title("Username"))
            .alignment(Alignment::Left);
        frame.render_widget(input, chunks[1]);
    }
    fn draw_register_success(&self, frame: &mut Frame, area: Rect) {
        use ratatui::{
            layout::Alignment,
            widgets::{Block, Borders, Paragraph},
        };
        let text = "Registration successful! Press L to login.";
        let p = Paragraph::new(text)
            .block(Block::default().borders(Borders::NONE))
            .alignment(Alignment::Center);
        frame.render_widget(p, area);
    }
    fn draw_login(&self, frame: &mut Frame, area: Rect) {
        use ratatui::{
            layout::{Alignment, Constraint, Direction, Layout},
            widgets::{Block, Borders, Paragraph},
        };
        let title = "Login: Enter username and press Enter";
        let block = Block::default().title(title).borders(Borders::ALL);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Percentage(50),
                    Constraint::Length(3),
                    Constraint::Percentage(47),
                ]
                .as_ref(),
            )
            .split(inner);
        let input = Paragraph::new(self.input_buffer.as_str())
            .block(Block::default().borders(Borders::ALL).title("Username"))
            .alignment(Alignment::Left);
        frame.render_widget(input, chunks[1]);
    }
    fn draw_search(&self, frame: &mut Frame, area: Rect) {
        use ratatui::{
            layout::{Alignment, Constraint, Direction, Layout},
            style::{Color, Style},
            widgets::{Block, Borders, Paragraph},
        };
        let title = "Search User: type username and press Enter, Esc to cancel";
        let block = Block::default().title(title).borders(Borders::ALL);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        // Split into 3 rows: input, result, options
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Length(1),
                ]
                .as_ref(),
            )
            .split(inner);

        // 1) Username input
        let input = Paragraph::new(self.search_buffer.as_str())
            .block(Block::default().borders(Borders::ALL).title("Username"))
            .alignment(Alignment::Left);
        frame.render_widget(input, chunks[0]);

        // 2) Loading spinner or Result
        if self.search_loading {
            // bouncing ball animation
            let spin = crate::ui::widgets::splash::bouncing_ball(self.search_spinner_idx, 12);
            let p = Paragraph::new(spin)
                .style(Style::default().fg(Color::Rgb(0, 255, 0)))
                .alignment(Alignment::Left);
            frame.render_widget(p, chunks[1]);
        } else if let Some(res) = &self.search_result {
            let result = Paragraph::new(res.as_str())
                .block(Block::default().borders(Borders::ALL).title("Result"))
                .alignment(Alignment::Left);
            frame.render_widget(result, chunks[1]);
        }

        // 3) Options, only if we got a real user back and not loading
        if !self.search_loading {
            if let Some(res) = &self.search_result {
                if res != "<not found>" {
                    let opts = "[1] Start Chat    [2] Search Again    [3] Home";
                    let menu = Paragraph::new(opts).alignment(Alignment::Center);
                    frame.render_widget(menu, chunks[2]);
                }
            }
        }
    }

    /// Render a log buffer in a small box of the last 2 lines at given area
    fn render_log_box(
        &self,
        frame: &mut Frame,
        area: Rect,
        title: &str,
        buffer: &Mutex<Vec<String>>,
    ) {
        use ratatui::{
            text::{Line, Text},
            widgets::{Block, Borders, Clear, Paragraph, Wrap},
        };
        // clear log area
        frame.render_widget(Clear, area);
        // border and title
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        // collect last N log lines based on inner area height and scroll offset
        let logs = buffer.lock().unwrap();
        let total = logs.len();
        let height = inner.height as usize;
        // scroll offset must not exceed available logs
        let scroll = self.log_scroll.min(total.saturating_sub(1));
        let end = total.saturating_sub(scroll);
        let start = end.saturating_sub(height);
        let slice = logs.get(start..end).unwrap_or(&[]);
        let lines: Vec<Line> = slice.iter().map(|l| Line::from(l.as_str())).collect();
        let paragraph = Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false });
        frame.render_widget(paragraph, inner);
    }

    fn draw_group_search(&self, frame: &mut Frame, area: Rect) {
        use ratatui::{
            layout::{Alignment, Constraint, Direction, Layout},
            style::{Color, Style},
            widgets::{Block, Borders, Paragraph},
        };
        let title = "Group Search: enter group server address and press Enter, Esc to cancel";
        let block = Block::default().title(title).borders(Borders::ALL);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        // Split into 3 rows: input, result, options
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Length(1),
                ]
                .as_ref(),
            )
            .split(inner);

        // 1) Group server address input
        let input = Paragraph::new(self.group_search_buffer.as_str())
            .block(Block::default().borders(Borders::ALL).title("Group Server Address"))
            .alignment(Alignment::Left);
        frame.render_widget(input, chunks[0]);

        // 2) Loading spinner or Result
        if self.group_search_loading {
            // bouncing ball animation
            let spin = crate::ui::widgets::splash::bouncing_ball(self.group_search_spinner_idx, 12);
            let p = Paragraph::new(spin)
                .style(Style::default().fg(Color::Rgb(0, 255, 0)))
                .alignment(Alignment::Left);
            frame.render_widget(p, chunks[1]);
        } else if let Some(res) = &self.group_search_result {
            let result = Paragraph::new(res.as_str())
                .block(Block::default().borders(Borders::ALL).title("Result"))
                .alignment(Alignment::Left);
            frame.render_widget(result, chunks[1]);
        }

        // 3) Options, only if we got a result and not loading
        if !self.group_search_loading {
            if let Some(res) = &self.group_search_result {
                if self.group_authenticated {
                    let opts = "[1] View Group    [2] Search Again    [3] Home";
                    let menu = Paragraph::new(opts).alignment(Alignment::Center);
                    frame.render_widget(menu, chunks[2]);
                } else if res != "Connection failed" && res != "Please login first" {
                    let menu = Paragraph::new("[2] Search Again    [3] Home").alignment(Alignment::Center);
                    frame.render_widget(menu, chunks[2]);
                }
            }
        }
    }

    fn draw_group_view(&self, frame: &mut Frame, area: Rect) {
        use ratatui::{
            layout::{Alignment, Constraint, Direction, Layout},
            style::{Color, Style},
            text::Line,
            widgets::{Block, Borders, List, ListItem, Paragraph},
        };
        let title = "Group View: i to type message, s for stats, Esc to go back";
        let block = Block::default().title(title).borders(Borders::ALL);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        
        // Split into message area and instructions
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(1)].as_ref())
            .split(inner);

        // Show group messages
        if self.group_messages.is_empty() {
            let empty_msg = Paragraph::new("No messages yet. Messages are delivered automatically via push.")
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::Gray));
            frame.render_widget(empty_msg, chunks[0]);
        } else {
            let items: Vec<ListItem> = self.group_messages
                .iter()
                .map(|msg| ListItem::new(Line::from(msg.as_str())))
                .collect();
            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title("Group Messages"));
            frame.render_widget(list, chunks[0]);
        }

        // Instructions
        let instructions = Paragraph::new("[I] Type Message    [S] Server Stats    [Esc] Back")
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::Gray));
        frame.render_widget(instructions, chunks[1]);
    }

    fn draw_group_input(&self, frame: &mut Frame, area: Rect) {
        use ratatui::{
            layout::{Alignment, Constraint, Direction, Layout},
            style::{Color, Style},
            text::Line,
            widgets::{Block, Borders, List, ListItem, Paragraph},
        };
        let title = "Group Input: type message and press Enter, Esc to go back";
        let block = Block::default().title(title).borders(Borders::ALL);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        
        // Split into message area, input area, and instructions
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(0), 
                Constraint::Length(3), 
                Constraint::Length(1)
            ].as_ref())
            .split(inner);

        // Show group messages (recent ones)
        if self.group_messages.is_empty() {
            let empty_msg = Paragraph::new("No messages yet. Type a message below.")
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::Gray));
            frame.render_widget(empty_msg, chunks[0]);
        } else {
            // Show last 10 messages
            let recent_messages: Vec<ListItem> = self.group_messages
                .iter()
                .rev()
                .take(10)
                .rev()
                .map(|msg| ListItem::new(Line::from(msg.as_str())))
                .collect();
            let list = List::new(recent_messages)
                .block(Block::default().borders(Borders::ALL).title("Recent Messages"));
            frame.render_widget(list, chunks[0]);
        }

        // Input field
        let input = Paragraph::new(self.group_input_buffer.as_str())
            .block(Block::default().borders(Borders::ALL).title("Type Message"))
            .alignment(Alignment::Left);
        frame.render_widget(input, chunks[1]);

        // Instructions
        let instructions = Paragraph::new("[Enter] Send    [Esc] Back to View")
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::Gray));
        frame.render_widget(instructions, chunks[2]);
    }

    /// Load chat history from database and populate the chat screen
    async fn load_chat_history_to_screen(&mut self) -> io::Result<()> {
        if let Some(handler) = &self.handler {
            match handler.load_chat_history().await {
                Ok(chat_history) => {
                    if let Some(chat) = self.screen.as_chat_mut() {
                        // Clear existing data
                        chat.contacts.clear();
                        chat.messages.clear();

                        // Load contacts and messages from database
                        for (contact_name, messages) in chat_history {
                            // Add contact
                            chat.contacts.push(Contact::new(&contact_name));

                            // Convert database messages to TUI Message format
                            let mut contact_messages = Vec::new();
                            for (sent, content, timestamp) in messages {
                                let sender = if sent {
                                    // Message sent by current user - use their username
                                    self.logged_in_user.as_ref()
                                        .map(|u| u.username.as_str())
                                        .unwrap_or("You")
                                } else {
                                    // Message received from contact
                                    &contact_name
                                };
                                contact_messages.push(Message {
                                    sender: sender.to_string(),
                                    content,
                                    timestamp,
                                });
                            }
                            chat.messages.push(contact_messages);
                        }

                        // Update UI state if we have contacts
                        if !chat.contacts.is_empty() {
                            chat.highlighted_contact = 0;
                            chat.contacts_state.select(Some(0));
                        }

                        info!("Loaded {} contacts with chat history", chat.contacts.len());
                    }
                }
                Err(e) => {
                    log::error!("Failed to load chat history: {}", e);
                }
            }
        }
        Ok(())
    }
}
