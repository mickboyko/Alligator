use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alligator::auth::AuthManager;
use alligator::providers::{
    OAuthRefresher, OAuthSessionManager, RefreshResult, SessionCredentialProvider,
};
use alligator::vault::Vault;
use alligator::{Bridge, MockBridge, Source, UnifiedTimeline};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

const SPLASH_DURATION: Duration = Duration::from_secs(3);
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(90);
const LOCK_COOLDOWN: Duration = Duration::from_secs(10);
const MAX_FAILED_ATTEMPTS: u32 = 3;

const SPLASH_ART: &[&str] = &[
    "                          ..........                                                                ",
    "                     ...:.          ::...                                                           ",
    "                    ..     ...:.::....  ..:.....;.:..                                               ",
    "                ....     .....      .....   ..:.    .:                                              ",
    "            . :.       ....  .........  ...    .;.    ;.                                            ",
    "          .::.        ...  ..:++++.+++.:. .:.   ..:;. ..;                                           ",
    "        ;;..    ........ ...;+x+++ +++++.:...::.    ..;:..;;..                                      ",
    "     ...      ... ...     ....++x+.+x++.. .. .....      ........:.                     .. ..        ",
    "   ...       ..         .    ..;;;:;;;...                   ..   ......;....        ............    ",
    " ...                            ..... .                                  .::.........   .       ..  ",
    ".             ....:;;;::....                                                           :;:..     .. ",
    "      .    ..; .. :. ..... .:.                                                         .....      :.",
    "    .    ..   .             .....                                                                  ;",
    "  ...    ..                    ......           ...                                               .:",
    "   ..     ..           ......   .;. .....:+::::.....;....;::;.     ...+..       .       .       .:.",
    "      .     ...             ...  .  ::.   :..;.     .:...:. ..........  ..:::;;...+..::...;;:++::.",
    "       ..     .......        ..... ...    .+;.       :;:;.    ::.;.       ::;.   .;.;.      :::    ",
    "        .        ..  .           ......... ..       .:;.      :+:.        ;;:     +;.       ;;..   ",
];
const SPLASH_TITLE: &[&str] = &[
    "          :::     :::        :::        ::::::::::: ::::::::      ::: ::::::::::: ::::::::  ::::::::: ",
    "       :+: :+:   :+:        :+:            :+:    :+:    :+:   :+: :+:   :+:    :+:    :+: :+:    :+:",
    "     +:+   +:+  +:+        +:+            +:+    +:+         +:+   +:+  +:+    +:+    +:+ +:+    +:+ ",
    "   +#++:++#++: +#+        +#+            +#+    :#:        +#++:++#++: +#+    +#+    +:+ +#++:++#:  ",
    "  +#+     +#+ +#+        +#+            +#+    +#+   +#+# +#+     +#+ +#+    +#+    +#+ +#+    +#+  ",
    "#+#+#+#+# #+# #+#        #+#            #+#    #+#    #+# #+#     #+# #+#    #+#    #+# #+#    #+#   ",
    "###     ### ########## ########## ########### ########  ###     ### ###     ########  ###    ###    ",
];

#[derive(Clone, Copy, Eq, PartialEq)]
enum Screen {
    Splash,
    Unlock,
    Timeline,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum InputMode {
    UnlockPassword,
    UnlockPasskey,
    EnrollPasskey,
    RotatePassword,
    RevokePasskey,
}

struct BridgeRuntime {
    rx: mpsc::Receiver<alligator::Message>,
    timeline: UnifiedTimeline,
}

struct DemoRefresher;

impl OAuthRefresher for DemoRefresher {
    fn refresh(
        &self,
        provider: &str,
        refresh_token: &str,
        now_epoch_secs: u64,
    ) -> Option<RefreshResult> {
        Some(RefreshResult {
            access_token: format!("{provider}-access-{now_epoch_secs}"),
            refresh_token: format!("{refresh_token}-rotated"),
            expires_at_epoch_secs: Some(now_epoch_secs + 300),
        })
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut terminal = ratatui::init();
    let run_result = run_app(&mut terminal);
    ratatui::restore();
    run_result
}

fn run_app(terminal: &mut ratatui::DefaultTerminal) -> Result<(), Box<dyn Error>> {
    let mut vault = load_or_initialize_vault()?;
    let refresh_manager = OAuthSessionManager::new(DemoRefresher);
    let mut auth = AuthManager::new(MAX_FAILED_ATTEMPTS, LOCK_COOLDOWN, INACTIVITY_TIMEOUT);

    let splash_started = Instant::now();
    let mut screen = Screen::Splash;
    let mut selected = 0usize;
    let mut runtime: Option<BridgeRuntime> = None;
    let mut input_mode: Option<InputMode> = None;
    let mut input_buffer = String::new();
    let mut status_message = String::new();

    loop {
        if screen == Screen::Splash && splash_started.elapsed() >= SPLASH_DURATION {
            screen = Screen::Unlock;
        }

        if auth.is_unlocked() {
            let now = current_epoch_secs();
            if let Some(unlocked) = auth.unlocked_mut() {
                let refreshed = refresh_manager.refresh_expiring_tokens(unlocked, now)?;
                if refreshed > 0 {
                    vault.commit(unlocked)?;
                    status_message = format!("Refreshed {refreshed} OAuth token(s)");
                }
            }

            if auth.should_auto_lock() {
                auth.lock("inactivity_timeout");
                runtime = None;
                screen = Screen::Unlock;
                input_mode = None;
                input_buffer.clear();
                status_message = "Auto-locked due to inactivity".to_string();
            }
        }

        if let Some(active_runtime) = runtime.as_mut() {
            while let Ok(message) = active_runtime.rx.try_recv() {
                active_runtime.timeline.ingest(message);
            }
        }

        let rooms = runtime
            .as_ref()
            .map(|active_runtime| active_runtime.timeline.ordered_rooms())
            .unwrap_or_default();
        if selected >= rooms.len() && !rooms.is_empty() {
            selected = rooms.len() - 1;
        }

        terminal.draw(|frame| {
            draw(
                frame,
                screen,
                &rooms,
                selected,
                input_mode,
                &input_buffer,
                &status_message,
                &vault,
            )
        })?;

        if event::poll(Duration::from_millis(100))? {
            let key = match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => key,
                _ => continue,
            };

            if key.code == KeyCode::Char('q') {
                return Ok(());
            }

            auth.mark_activity();

            match screen {
                Screen::Splash => screen = Screen::Unlock,
                Screen::Unlock => {
                    if let Some(mode) = input_mode {
                        if handle_text_edit(&mut input_buffer, key) {
                            let result = match mode {
                                InputMode::UnlockPassword => {
                                    auth.unlock_with_password(&vault, input_buffer.as_str())
                                }
                                InputMode::UnlockPasskey => {
                                    let (credential_id, passkey_secret) =
                                        parse_passkey_input(input_buffer.as_str());
                                    auth.unlock_with_passkey(&vault, credential_id, passkey_secret)
                                }
                                _ => Ok(()),
                            };

                            match result {
                                Ok(()) => {
                                    runtime = auth
                                        .unlocked()
                                        .map(start_bridges)
                                        .transpose()
                                        .map_err(|err| -> Box<dyn Error> { Box::new(err) })?;
                                    screen = Screen::Timeline;
                                    status_message = "Unlocked".to_string();
                                }
                                Err(err) => {
                                    status_message = format!("Unlock failed: {err}");
                                }
                            }

                            input_mode = None;
                            input_buffer.clear();
                        }
                    } else {
                        match key.code {
                            KeyCode::Char('p') => {
                                input_mode = Some(InputMode::UnlockPassword);
                                input_buffer.clear();
                                status_message = "Enter password and press Enter".to_string();
                            }
                            KeyCode::Char('k') => {
                                input_mode = Some(InputMode::UnlockPasskey);
                                input_buffer.clear();
                                status_message =
                                    "Enter passkey as credential_id:secret then Enter".to_string();
                            }
                            _ => {}
                        }
                    }
                }
                Screen::Timeline => {
                    if let Some(mode) = input_mode {
                        if handle_text_edit(&mut input_buffer, key) {
                            if let Some(unlocked) = auth.unlocked_mut() {
                                let op = match mode {
                                    InputMode::EnrollPasskey => {
                                        let (credential_id, passkey_secret) =
                                            parse_passkey_input(input_buffer.as_str());
                                        vault.enroll_passkey(
                                            unlocked,
                                            credential_id,
                                            passkey_secret,
                                        )
                                    }
                                    InputMode::RotatePassword => {
                                        vault.rotate_password(unlocked, input_buffer.as_str())
                                    }
                                    InputMode::RevokePasskey => {
                                        vault.revoke_passkey(input_buffer.as_str())
                                    }
                                    _ => Ok(()),
                                };

                                match op {
                                    Ok(()) => {
                                        status_message = "Security settings updated".to_string()
                                    }
                                    Err(err) => {
                                        status_message = format!("Security update failed: {err}")
                                    }
                                }
                            }

                            input_mode = None;
                            input_buffer.clear();
                        }
                        continue;
                    }

                    match key.code {
                        KeyCode::Up => selected = selected.saturating_sub(1),
                        KeyCode::Down => {
                            if selected + 1 < rooms.len() {
                                selected += 1;
                            }
                        }
                        KeyCode::Char('l') => {
                            auth.lock("manual_lock");
                            runtime = None;
                            screen = Screen::Unlock;
                            status_message = "Locked".to_string();
                        }
                        KeyCode::Char('e') => {
                            input_mode = Some(InputMode::EnrollPasskey);
                            input_buffer.clear();
                            status_message =
                                "Enroll passkey as credential_id:secret then Enter".to_string();
                        }
                        KeyCode::Char('r') => {
                            input_mode = Some(InputMode::RotatePassword);
                            input_buffer.clear();
                            status_message = "Enter new password then Enter".to_string();
                        }
                        KeyCode::Char('x') => {
                            input_mode = Some(InputMode::RevokePasskey);
                            input_buffer.clear();
                            status_message = "Enter passkey credential_id to revoke".to_string();
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

fn load_or_initialize_vault() -> Result<Vault, Box<dyn Error>> {
    let path = PathBuf::from(".alligator-vault.json");
    if path.exists() {
        return Ok(Vault::open(&path)?);
    }

    let bootstrap_password = std::env::var("ALLIGATOR_BOOTSTRAP_PASSWORD").map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Set ALLIGATOR_BOOTSTRAP_PASSWORD before first run",
        )
    })?;

    let bootstrap_passkey_1 = std::env::var("ALLIGATOR_BOOTSTRAP_PASSKEY_1").map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Set ALLIGATOR_BOOTSTRAP_PASSKEY_1 before first run",
        )
    })?;

    let bootstrap_passkey_2 = std::env::var("ALLIGATOR_BOOTSTRAP_PASSKEY_2").map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Set ALLIGATOR_BOOTSTRAP_PASSKEY_2 before first run",
        )
    })?;

    let mut vault = Vault::create(
        &path,
        Some(bootstrap_password.as_str()),
        &[
            ("device-key-1".to_string(), bootstrap_passkey_1),
            ("device-key-2".to_string(), bootstrap_passkey_2),
        ],
    )?;

    let mut unlocked = vault.unlock_with_password(bootstrap_password.as_str())?;
    unlocked.upsert_token(
        "slack",
        vec!["chat:read".to_string()],
        Some(current_epoch_secs() + 60),
        "slack-demo-access",
        "slack-demo-refresh",
    );
    unlocked.upsert_token(
        "teams",
        vec!["chat:read".to_string()],
        Some(current_epoch_secs() + 60),
        "teams-demo-access",
        "teams-demo-refresh",
    );
    unlocked.upsert_token(
        "google-chat",
        vec!["chat:read".to_string()],
        Some(current_epoch_secs() + 60),
        "gchat-demo-access",
        "gchat-demo-refresh",
    );
    vault.commit(&unlocked)?;

    Ok(vault)
}

fn start_bridges(
    unlocked: &alligator::vault::UnlockedVault,
) -> Result<BridgeRuntime, std::io::Error> {
    let credentials = Arc::new(SessionCredentialProvider::from_unlocked(unlocked));
    let (tx, rx) = mpsc::channel();

    let bridges = vec![
        MockBridge::new(
            Source::Slack,
            "slack-primary",
            "eng",
            "Engineering",
            "marina",
            vec![
                "Deploy complete",
                "Can someone review #42?",
                "Standup in 5m",
            ],
            Duration::from_millis(900),
        ),
        MockBridge::new(
            Source::Teams,
            "teams-primary",
            "ops",
            "Operations",
            "drew",
            vec![
                "Database CPU normal",
                "Incident closed",
                "New on-call rotation posted",
            ],
            Duration::from_millis(1200),
        ),
        MockBridge::new(
            Source::Teams,
            "teams-secondary",
            "meeting-q3",
            "Q3 Planning Meeting",
            "avery",
            vec![
                "Can we lock down next week for planning?",
                "Shared the latest roadmap doc",
                "Action items are in the meeting notes",
            ],
            Duration::from_millis(1100),
        ),
        MockBridge::new(
            Source::GoogleChat,
            "gchat-primary",
            "design",
            "Design",
            "sofia",
            vec!["Uploaded mockups", "Need feedback on color tokens"],
            Duration::from_millis(1500),
        ),
    ];

    for bridge in bridges {
        bridge.start(tx.clone(), credentials.clone());
    }
    drop(tx);

    Ok(BridgeRuntime {
        rx,
        timeline: UnifiedTimeline::new(),
    })
}

fn parse_passkey_input(input: &str) -> (&str, &str) {
    let mut parts = input.splitn(2, ':');
    let credential_id = parts.next().unwrap_or("").trim();
    let secret = parts.next().unwrap_or("").trim();
    (credential_id, secret)
}

fn handle_text_edit(buffer: &mut String, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Char(c) => buffer.push(c),
        KeyCode::Backspace => {
            buffer.pop();
        }
        KeyCode::Enter => return true,
        KeyCode::Esc => {
            buffer.clear();
            return true;
        }
        _ => {}
    }
    false
}

fn draw(
    frame: &mut Frame,
    screen: Screen,
    rooms: &[&alligator::Room],
    selected: usize,
    input_mode: Option<InputMode>,
    input_buffer: &str,
    status_message: &str,
    vault: &Vault,
) {
    match screen {
        Screen::Splash => draw_splash(frame),
        Screen::Unlock => draw_unlock(frame, input_mode, input_buffer, status_message, vault),
        Screen::Timeline => draw_timeline(frame, rooms, selected, input_mode, status_message),
    }
}

fn draw_splash(frame: &mut Frame) {
    let area = frame.area();
    let theme = Style::default().fg(Color::LightGreen);
    let accent = Style::default().fg(Color::Magenta);

    frame.render_widget(
        Block::default().style(Style::default().bg(Color::Black)),
        area,
    );

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(area);

    let header = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(layout[0]);

    frame.render_widget(
        Paragraph::new(format!("v{APP_VERSION}"))
            .style(theme)
            .alignment(Alignment::Left),
        header[0],
    );
    frame.render_widget(
        Paragraph::new("[ secure. unified. real-time ]")
            .style(theme)
            .alignment(Alignment::Right),
        header[1],
    );

    let mut lines = vec![Line::styled("", theme)];
    lines.extend(SPLASH_ART.iter().map(|line| Line::styled(*line, theme)));
    lines.push(Line::styled("", theme));
    lines.extend(
        SPLASH_TITLE
            .iter()
            .map(|line| Line::styled(*line, theme.add_modifier(Modifier::BOLD))),
    );
    lines.push(Line::styled("", theme));
    lines.push(Line::styled("Corporate Communications Aggregator", theme));

    frame.render_widget(
        Paragraph::new(Text::from(lines)).alignment(Alignment::Center),
        layout[1],
    );
    frame.render_widget(
        Paragraph::new("[ press any key to continue | q quits ]")
            .style(accent)
            .alignment(Alignment::Center),
        layout[2],
    );
}

fn draw_unlock(
    frame: &mut Frame,
    input_mode: Option<InputMode>,
    input_buffer: &str,
    status_message: &str,
    vault: &Vault,
) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(6),
            Constraint::Length(4),
            Constraint::Length(5),
            Constraint::Min(1),
        ])
        .split(frame.area());

    let passkeys = vault.passkey_ids().collect::<Vec<_>>().join(", ");
    let help = format!(
        "App is locked.\n[p] Unlock with password\n[k] Unlock with passkey (credential_id:secret)\nAvailable passkey IDs: {passkeys}"
    );

    frame.render_widget(
        Paragraph::new(help)
            .block(Block::default().borders(Borders::ALL).title("Unlock"))
            .wrap(Wrap { trim: true }),
        layout[0],
    );

    let prompt = match input_mode {
        Some(InputMode::UnlockPassword) => "Password:",
        Some(InputMode::UnlockPasskey) => "Passkey (credential_id:secret):",
        _ => "",
    };

    frame.render_widget(
        Paragraph::new(format!("{prompt} {input_buffer}"))
            .block(Block::default().borders(Borders::ALL).title("Input")),
        layout[1],
    );

    frame.render_widget(
        Paragraph::new(status_message)
            .block(Block::default().borders(Borders::ALL).title("Status"))
            .wrap(Wrap { trim: true }),
        layout[2],
    );
}

fn draw_timeline(
    frame: &mut Frame,
    rooms: &[&alligator::Room],
    selected: usize,
    input_mode: Option<InputMode>,
    status_message: &str,
) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(frame.area());

    let room_items: Vec<ListItem> = rooms
        .iter()
        .map(|room| {
            ListItem::new(format!(
                "[{}] {}\n{}",
                room.source.as_str(),
                room.title,
                room.preview
            ))
        })
        .collect();

    let rooms_list = List::new(room_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Rooms (q quit | l lock | e enroll key | r rotate pw | x revoke key)"),
        )
        .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan))
        .highlight_symbol(">> ");

    let mut state = ratatui::widgets::ListState::default();
    if !rooms.is_empty() {
        state.select(Some(selected));
    }
    frame.render_stateful_widget(rooms_list, columns[0], &mut state);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),
            Constraint::Length(4),
            Constraint::Length(4),
        ])
        .split(columns[1]);

    let timeline_text = rooms
        .get(selected)
        .map(|room| {
            room.messages
                .iter()
                .map(|msg| format!("{}: {}", msg.author, msg.body))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_else(|| {
            "No messages yet. OAuth credentials must be unlocked first.".to_string()
        });

    frame.render_widget(
        Paragraph::new(timeline_text)
            .block(Block::default().borders(Borders::ALL).title("Timeline"))
            .wrap(Wrap { trim: true }),
        right[0],
    );

    let input_prompt = match input_mode {
        Some(InputMode::EnrollPasskey) => "Enroll passkey as credential_id:secret",
        Some(InputMode::RotatePassword) => "Enter new password",
        Some(InputMode::RevokePasskey) => "Enter credential_id to revoke",
        _ => "",
    };

    frame.render_widget(
        Paragraph::new(input_prompt)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Security Input"),
            )
            .wrap(Wrap { trim: true }),
        right[1],
    );

    frame.render_widget(
        Paragraph::new(status_message)
            .block(Block::default().borders(Borders::ALL).title("Status"))
            .wrap(Wrap { trim: true }),
        right[2],
    );
}

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}
