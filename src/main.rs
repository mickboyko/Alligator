use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alligator::auth::AuthManager;
use alligator::providers::{
    OAuthRefresher, OAuthSessionManager, RefreshResult, SessionCredentialProvider,
};
use alligator::vault::{UnlockedVault, Vault};
use alligator::{Bridge, MockBridge, Source, UnifiedTimeline};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::prelude::*;
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use sha2::{Digest, Sha256};

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const SPLASH_DURATION: Duration = Duration::from_secs(3);
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
    SetupProfile,
    Splash,
    Unlock,
    Timeline,
    Settings,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum InputMode {
    UnlockPassword,
    UnlockSecurityKeyPin,
    EnrollSecurityKeyPin,
    RotatePassword,
    RevokeSecurityKey,
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
    let profile_path = profile_vault_path();
    let mut vault = if profile_path.exists() {
        Some(Vault::open(&profile_path)?)
    } else {
        None
    };

    let refresh_manager = OAuthSessionManager::new(DemoRefresher);
    let mut auth = AuthManager::new(MAX_FAILED_ATTEMPTS, LOCK_COOLDOWN, INACTIVITY_TIMEOUT);
    let mut screen = if vault.is_some() {
        Screen::Splash
    } else {
        Screen::SetupProfile
    };

    let mut selected = 0usize;
    let mut runtime: Option<BridgeRuntime> = None;
    let mut input_mode: Option<InputMode> = None;
    let mut input_buffer = String::new();
    let mut status_message = String::new();
    let mut splash_entered_at = Instant::now();

    loop {
        if screen == Screen::Splash && splash_entered_at.elapsed() >= SPLASH_DURATION {
            screen = Screen::Unlock;
            input_mode = None;
            input_buffer.clear();
            status_message = "Choose unlock method".to_string();
        }

        if auth.is_unlocked() {
            let now = current_epoch_secs();
            if let (Some(vault_ref), Some(unlocked)) = (vault.as_mut(), auth.unlocked_mut()) {
                let refreshed = refresh_manager.refresh_expiring_tokens(unlocked, now)?;
                if refreshed > 0 {
                    vault_ref.commit(unlocked)?;
                    status_message = format!("Refreshed {refreshed} OAuth token(s)");
                }
            }

            if auth.should_auto_lock() {
                auth.lock("inactivity_timeout");
                runtime = None;
                screen = Screen::Splash;
                splash_entered_at = Instant::now();
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
                vault.as_ref(),
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
                Screen::SetupProfile => match edit_input(&mut input_buffer, key) {
                    EditAction::Submit => {
                        let password = input_buffer.trim();
                        if password.is_empty() {
                            status_message = "Password cannot be empty".to_string();
                            continue;
                        }

                        let mut created = Vault::create(&profile_path, Some(password), &[])?;
                        let mut unlocked = created.unlock_with_password(password)?;
                        seed_demo_tokens(&mut unlocked);
                        created.commit(&unlocked)?;
                        vault = Some(created);
                        input_buffer.clear();
                        status_message = "Profile created. Continue to splash/login.".to_string();
                        screen = Screen::Splash;
                        splash_entered_at = Instant::now();
                    }
                    EditAction::Cancel => {
                        input_buffer.clear();
                    }
                    EditAction::Continue => {}
                },
                Screen::Splash => {
                    screen = Screen::Unlock;
                    input_mode = None;
                    input_buffer.clear();
                    status_message = "Choose unlock method".to_string();
                }
                Screen::Unlock => {
                    if let Some(mode) = input_mode {
                        match edit_input(&mut input_buffer, key) {
                            EditAction::Submit => {
                                let result = if let Some(vault_ref) = vault.as_ref() {
                                    match mode {
                                        InputMode::UnlockPassword => auth
                                            .unlock_with_password(vault_ref, input_buffer.as_str()),
                                        InputMode::UnlockSecurityKeyPin => {
                                            unlock_with_security_key_pin(
                                                &mut auth,
                                                vault_ref,
                                                input_buffer.as_str(),
                                            )
                                        }
                                        _ => Ok(()),
                                    }
                                } else {
                                    Err(alligator::auth::AuthError::Vault(
                                        alligator::vault::VaultError::InvalidInput(
                                            "missing vault".to_string(),
                                        ),
                                    ))
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
                            EditAction::Cancel => {
                                input_mode = None;
                                input_buffer.clear();
                            }
                            EditAction::Continue => {}
                        }
                    } else {
                        match key.code {
                            KeyCode::Char('p') => {
                                input_mode = Some(InputMode::UnlockPassword);
                                input_buffer.clear();
                                status_message = "Enter password and press Enter".to_string();
                            }
                            KeyCode::Char('k') => {
                                input_mode = Some(InputMode::UnlockSecurityKeyPin);
                                input_buffer.clear();
                                status_message =
                                    "Tap security key, then enter key PIN and press Enter"
                                        .to_string();
                            }
                            _ => {}
                        }
                    }
                }
                Screen::Timeline => match key.code {
                    KeyCode::Up => selected = selected.saturating_sub(1),
                    KeyCode::Down => {
                        if selected + 1 < rooms.len() {
                            selected += 1;
                        }
                    }
                    KeyCode::Char('l') => {
                        auth.lock("manual_lock");
                        runtime = None;
                        screen = Screen::Splash;
                        splash_entered_at = Instant::now();
                        status_message = "Locked".to_string();
                    }
                    KeyCode::Char('s') => {
                        screen = Screen::Settings;
                        input_mode = None;
                        input_buffer.clear();
                        status_message = "Settings opened".to_string();
                    }
                    _ => {}
                },
                Screen::Settings => {
                    if let Some(mode) = input_mode {
                        match edit_input(&mut input_buffer, key) {
                            EditAction::Submit => {
                                if let (Some(vault_ref), Some(unlocked)) =
                                    (vault.as_mut(), auth.unlocked_mut())
                                {
                                    match mode {
                                        InputMode::EnrollSecurityKeyPin => {
                                            match enroll_security_key(
                                                vault_ref,
                                                unlocked,
                                                input_buffer.as_str(),
                                            ) {
                                                Ok(credential_id) => {
                                                    status_message = format!(
                                                        "Security key enrolled. Credential ID: {credential_id}"
                                                    );
                                                }
                                                Err(err) => {
                                                    status_message =
                                                        format!("Security update failed: {err}")
                                                }
                                            }
                                        }
                                        InputMode::RotatePassword => match vault_ref
                                            .rotate_password(unlocked, input_buffer.as_str())
                                        {
                                            Ok(()) => {
                                                status_message =
                                                    "Password updated successfully".to_string()
                                            }
                                            Err(err) => {
                                                status_message =
                                                    format!("Security update failed: {err}")
                                            }
                                        },
                                        InputMode::RevokeSecurityKey => match vault_ref
                                            .revoke_passkey(input_buffer.as_str())
                                        {
                                            Ok(()) => {
                                                status_message = "Security key revoked".to_string()
                                            }
                                            Err(err) => {
                                                status_message =
                                                    format!("Security update failed: {err}")
                                            }
                                        },
                                        _ => {}
                                    }
                                }
                                input_mode = None;
                                input_buffer.clear();
                            }
                            EditAction::Cancel => {
                                input_mode = None;
                                input_buffer.clear();
                            }
                            EditAction::Continue => {}
                        }
                    } else {
                        match key.code {
                            KeyCode::Char('b') => screen = Screen::Timeline,
                            KeyCode::Char('l') => {
                                auth.lock("manual_lock");
                                runtime = None;
                                screen = Screen::Splash;
                                splash_entered_at = Instant::now();
                                status_message = "Locked".to_string();
                            }
                            KeyCode::Char('e') => {
                                input_mode = Some(InputMode::EnrollSecurityKeyPin);
                                input_buffer.clear();
                                status_message =
                                    "Tap security key and enter a PIN to enroll".to_string();
                            }
                            KeyCode::Char('r') => {
                                input_mode = Some(InputMode::RotatePassword);
                                input_buffer.clear();
                                status_message = "Enter new password then Enter".to_string();
                            }
                            KeyCode::Char('x') => {
                                input_mode = Some(InputMode::RevokeSecurityKey);
                                input_buffer.clear();
                                status_message =
                                    "Enter credential id to revoke (e.g. fido2:local:123456)"
                                        .to_string();
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }
}

fn enroll_security_key(
    vault: &mut Vault,
    unlocked: &UnlockedVault,
    pin: &str,
) -> Result<String, String> {
    if pin.trim().is_empty() {
        return Err("Security key PIN cannot be empty".to_string());
    }
    let credential_id = generate_security_key_credential_id();
    let passkey_secret = derive_security_key_secret(credential_id.as_str(), pin)?;
    vault
        .enroll_passkey(unlocked, credential_id.as_str(), passkey_secret.as_str())
        .map_err(|err| err.to_string())?;

    Ok(credential_id)
}

fn unlock_with_security_key_pin(
    auth: &mut AuthManager,
    vault: &Vault,
    pin: &str,
) -> Result<(), alligator::auth::AuthError> {
    if pin.trim().is_empty() {
        return Err(alligator::auth::AuthError::Vault(
            alligator::vault::VaultError::InvalidInput(
                "security key PIN cannot be empty".to_string(),
            ),
        ));
    }

    let enrolled = vault
        .passkey_ids()
        .filter(|credential_id| credential_id.starts_with("fido2:"))
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    if enrolled.is_empty() {
        return Err(alligator::auth::AuthError::Vault(
            alligator::vault::VaultError::InvalidInput(
                "no enrolled security-key credentials".to_string(),
            ),
        ));
    }

    for credential_id in &enrolled {
        let passkey_secret =
            derive_security_key_secret(credential_id.as_str(), pin).map_err(|err| {
                alligator::auth::AuthError::Vault(alligator::vault::VaultError::InvalidInput(err))
            })?;
        match vault.unlock_with_passkey(credential_id.as_str(), passkey_secret.as_str()) {
            Ok(_) => {
                return auth.unlock_with_passkey(
                    vault,
                    credential_id.as_str(),
                    passkey_secret.as_str(),
                );
            }
            Err(_) => continue,
        }
    }

    if let Some(first_credential) = enrolled.first() {
        let secret = derive_security_key_secret(first_credential.as_str(), pin).map_err(|err| {
            alligator::auth::AuthError::Vault(alligator::vault::VaultError::InvalidInput(err))
        })?;
        return auth.unlock_with_passkey(vault, first_credential.as_str(), secret.as_str());
    }

    Err(alligator::auth::AuthError::Vault(
        alligator::vault::VaultError::InvalidInput("security-key login failed".to_string()),
    ))
}

fn generate_security_key_credential_id() -> String {
    let value = rand::random::<u64>();
    let encoded = format!("{value:016x}");
    format!("fido2:local:{}-{}", &encoded[..8], &encoded[8..])
}

fn derive_security_key_secret(credential_id: &str, pin: &str) -> Result<String, String> {
    let mut salt_hasher = Sha256::new();
    salt_hasher.update("alligator-local-fido2-salt");
    salt_hasher.update(credential_id.as_bytes());
    let salt = salt_hasher.finalize();

    let params = Params::new(19_456, 2, 1, Some(32))
        .map_err(|_| "failed to prepare key-derivation parameters".to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(pin.as_bytes(), &salt[..16], &mut out)
        .map_err(|_| "failed to derive security key secret".to_string())?;

    Ok(base64::engine::general_purpose::STANDARD.encode(out))
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EditAction {
    Continue,
    Submit,
    Cancel,
}

fn edit_input(buffer: &mut String, key: KeyEvent) -> EditAction {
    match key.code {
        KeyCode::Char(c) => buffer.push(c),
        KeyCode::Backspace => {
            buffer.pop();
        }
        KeyCode::Enter => return EditAction::Submit,
        KeyCode::Esc => return EditAction::Cancel,
        _ => {}
    }
    EditAction::Continue
}

fn profile_vault_path() -> PathBuf {
    let user = Vault::current_os_user().replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    );
    PathBuf::from(format!(".alligator-vault-{user}.json"))
}

fn seed_demo_tokens(unlocked: &mut UnlockedVault) {
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
}

fn start_bridges(unlocked: &UnlockedVault) -> Result<BridgeRuntime, std::io::Error> {
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

fn draw(
    frame: &mut Frame,
    screen: Screen,
    rooms: &[&alligator::Room],
    selected: usize,
    input_mode: Option<InputMode>,
    input_buffer: &str,
    status_message: &str,
    vault: Option<&Vault>,
) {
    match screen {
        Screen::SetupProfile => draw_setup_profile(frame, input_buffer, status_message),
        Screen::Splash => draw_splash(frame),
        Screen::Unlock => draw_unlock(frame, input_mode, input_buffer, status_message, vault),
        Screen::Timeline => draw_timeline(frame, rooms, selected, status_message),
        Screen::Settings => draw_settings(frame, input_mode, input_buffer, status_message, vault),
    }
}

fn draw_setup_profile(frame: &mut Frame, input_buffer: &str, status_message: &str) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(5),
            Constraint::Length(3),
            Constraint::Length(4),
            Constraint::Min(1),
        ])
        .split(frame.area());

    frame.render_widget(
        Paragraph::new(
            "No local profile found for this OS user.\nCreate a password profile to initialize encrypted auth vault.",
        )
        .block(Block::default().borders(Borders::ALL).title("Profile setup"))
        .wrap(Wrap { trim: true }),
        layout[0],
    );

    let masked_password = masked_input(input_buffer);
    frame.render_widget(
        Paragraph::new(format!("Password: {masked_password}")).block(
            Block::default()
                .borders(Borders::ALL)
                .title("New password (Enter to create)"),
        ),
        layout[1],
    );

    frame.render_widget(
        Paragraph::new(status_message)
            .block(Block::default().borders(Borders::ALL).title("Status"))
            .wrap(Wrap { trim: true }),
        layout[2],
    );
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
    vault: Option<&Vault>,
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

    let credential_count = vault
        .map(|vault| {
            vault
                .passkey_ids()
                .filter(|id| id.starts_with("fido2:"))
                .count()
        })
        .unwrap_or_default();
    let help = format!(
        "Authenticate to unlock local encrypted profile.\n[p] Password\n[k] Physical security key (tap key, then enter key PIN)\nConfigured security keys: {credential_count}",
    );

    frame.render_widget(
        Paragraph::new(help)
            .block(Block::default().borders(Borders::ALL).title("Login"))
            .wrap(Wrap { trim: true }),
        layout[0],
    );

    let prompt = match input_mode {
        Some(InputMode::UnlockPassword) => "Password:",
        Some(InputMode::UnlockSecurityKeyPin) => "Security key PIN:",
        _ => "",
    };

    let visible_input = if is_secret_input_mode(input_mode) {
        masked_input(input_buffer)
    } else {
        input_buffer.to_string()
    };
    frame.render_widget(
        Paragraph::new(format!("{prompt} {visible_input}"))
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
                .title("Rooms (q quit | l lock | s settings)"),
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
        .constraints([Constraint::Min(1), Constraint::Length(4)])
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

    frame.render_widget(
        Paragraph::new(status_message)
            .block(Block::default().borders(Borders::ALL).title("Status"))
            .wrap(Wrap { trim: true }),
        right[1],
    );
}

fn draw_settings(
    frame: &mut Frame,
    input_mode: Option<InputMode>,
    input_buffer: &str,
    status_message: &str,
    vault: Option<&Vault>,
) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(6),
            Constraint::Length(3),
            Constraint::Length(4),
            Constraint::Min(1),
        ])
        .split(frame.area());

    let credential_count = vault
        .map(|vault| {
            vault
                .passkey_ids()
                .filter(|id| id.starts_with("fido2:"))
                .count()
        })
        .unwrap_or_default();
    let text = format!(
        "Authentication settings\n[e] Enroll physical security key (tap key + set PIN)\n[r] Rotate password\n[x] Revoke credential\n[l] Lock now\n[b] Back to timeline\nConfigured security keys: {credential_count}",
    );

    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title("Settings"))
            .wrap(Wrap { trim: true }),
        layout[0],
    );

    let prompt = match input_mode {
        Some(InputMode::EnrollSecurityKeyPin) => "Security key PIN for enrollment",
        Some(InputMode::RotatePassword) => "New password",
        Some(InputMode::RevokeSecurityKey) => "Credential id to revoke",
        _ => "",
    };

    let visible_input = if is_secret_input_mode(input_mode) {
        masked_input(input_buffer)
    } else {
        input_buffer.to_string()
    };
    frame.render_widget(
        Paragraph::new(format!("{prompt}: {visible_input}"))
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

fn is_secret_input_mode(input_mode: Option<InputMode>) -> bool {
    matches!(
        input_mode,
        Some(InputMode::UnlockPassword)
            | Some(InputMode::UnlockSecurityKeyPin)
            | Some(InputMode::EnrollSecurityKeyPin)
            | Some(InputMode::RotatePassword)
    )
}

fn masked_input(raw: &str) -> String {
    "•".repeat(raw.chars().count())
}

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}
