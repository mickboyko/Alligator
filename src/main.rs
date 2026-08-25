use std::error::Error;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use alligator::{Bridge, MockBridge, Source, UnifiedTimeline};
use crossterm::event::{self, Event, KeyCode};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

enum AppState {
    Splash { started: Instant, boot_step: usize },
    Main,
}

const BOOT_STEPS: &[(&str, &str)] = &[
    ("> initializing adapters", "[ OK ]"),
    ("> connecting to services", "[ OK ]"),
    ("> aggregating channels", "[ OK ]"),
    ("> syncing message streams", "[ OK ]"),
    ("> securing data pipeline", "[ OK ]"),
];

const BOOT_STEP_INTERVAL_MS: u128 = 400;
const SPLASH_HOLD_MS: u128 =
    BOOT_STEP_INTERVAL_MS * (BOOT_STEPS.len() as u128) + 1000;

fn main() -> Result<(), Box<dyn Error>> {
    let mut terminal = ratatui::init();

    let run_result = run_app(&mut terminal);

    ratatui::restore();

    run_result
}

fn run_app(terminal: &mut ratatui::DefaultTerminal) -> Result<(), Box<dyn Error>> {
    let (tx, rx) = mpsc::channel();
    let bridges = vec![
        MockBridge::new(
            Source::Slack,
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
            Source::GoogleChat,
            "design",
            "Design",
            "sofia",
            vec!["Uploaded mockups", "Need feedback on color tokens"],
            Duration::from_millis(1500),
        ),
    ];

    for bridge in bridges {
        bridge.start(tx.clone());
    }
    drop(tx);

    let mut timeline = UnifiedTimeline::new();
    let mut selected = 0usize;
    let mut state = AppState::Splash {
        started: Instant::now(),
        boot_step: 0,
    };

    loop {
        while let Ok(message) = rx.try_recv() {
            timeline.ingest(message);
        }

        match &mut state {
            AppState::Splash { started, boot_step } => {
                let elapsed = started.elapsed().as_millis();
                let visible_steps =
                    ((elapsed / BOOT_STEP_INTERVAL_MS) as usize).min(BOOT_STEPS.len());
                *boot_step = visible_steps;

                let done = elapsed >= SPLASH_HOLD_MS;
                let step_snap = *boot_step;
                terminal.draw(|frame| draw_splash(frame, step_snap, done))?;

                if event::poll(Duration::from_millis(50))? {
                    if let Event::Key(_) = event::read()? {
                        state = AppState::Main;
                    }
                }
                if done {
                    state = AppState::Main;
                }
            }
            AppState::Main => {
                let rooms = timeline.ordered_rooms();
                if selected >= rooms.len() && !rooms.is_empty() {
                    selected = rooms.len() - 1;
                }

                terminal.draw(|frame| draw(frame, &rooms, selected))?;

                if event::poll(Duration::from_millis(100))? {
                    if let Event::Key(key) = event::read()? {
                        match key.code {
                            KeyCode::Char('q') => return Ok(()),
                            KeyCode::Up => selected = selected.saturating_sub(1),
                            KeyCode::Down => {
                                if selected + 1 < rooms.len() {
                                    selected += 1;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }
}

fn draw_splash(frame: &mut Frame, boot_step: usize, all_done: bool) {
    let area = frame.area();

    // Dark background
    let bg = Block::default().style(Style::default().bg(Color::Black));
    frame.render_widget(bg, area);

    // Outer border
    let border = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green))
        .style(Style::default().bg(Color::Black));
    frame.render_widget(border, area);

    let inner = area.inner(Margin { horizontal: 2, vertical: 1 });

    // Layout: version row | ascii art | title | tagline | boot log | prompt
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),  // version + tagline top row
            Constraint::Length(14), // ASCII alligator
            Constraint::Length(6),  // ALLIGATOR title
            Constraint::Length(1),  // service icons line
            Constraint::Length(1),  // dashes + tagline
            Constraint::Min(8),     // boot log
            Constraint::Length(1),  // prompt
        ])
        .split(inner);

    // Version + secure unified real-time
    let version_line = Line::from(vec![
        Span::styled("v1.0.0", Style::default().fg(Color::Green)),
        Span::raw("                    "),
        Span::styled(
            "[ secure. unified. real-time ]",
            Style::default().fg(Color::Green),
        ),
    ]);
    frame.render_widget(Paragraph::new(version_line), chunks[0]);

    // ASCII alligator art
    let gator_art = concat!(
        "                    ░░▒▒▒▓▓▓▒▒▒░░\n",
        "                 ░▒▓▓██████████▓▓▒░\n",
        "               ░▒▓███▓▓▒▒▒▒▒▓▓███▓▒░\n",
        "              ▒▓███▒░   ◉     ░▒███▓▒\n",
        "             ▒████▒░  ▄▀▀▄     ░▒████▒\n",
        "            ▒████▓░ ▄█▀  ▀█▄    ░▓████▒\n",
        "    ░▒▓▓▒░▒▓█████▓▄█▀      ▀█▄▄▓█████▓▒░▒▓▓▒░\n",
        "  ▒▓███████████████▓▒░░░░░▒▒▓███████████████▓▒\n",
        " ▓████▓▒░░▒▒▓▓▓▒▒░░        ░░▒▒▓▓▓▒▒░░▒▓████▓\n",
        " ▀▓██▓  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▓██▓▀\n",
        "  ░▓▓  ▐█ ▐█ ▐█ ▐█ ▐█ ▐█ ▐█ ▐█ ▐█ ▐█ █▌  ▓▓░\n",
        "   ░░  ▐█▄▐█▄▐█▄▐█▄▐█▄▐█▄▐█▄▐█▄▐█▄▐█▄█▌  ░░\n",
        "        ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀\n",
    );
    let gator_para = Paragraph::new(gator_art)
        .style(Style::default().fg(Color::Green).bg(Color::Black))
        .alignment(Alignment::Center);
    frame.render_widget(gator_para, chunks[1]);

    // ALLIGATOR big text title
    let title_art = concat!(
        " ▄▄▄  ▄   ▄   ▄  ▄▄▄  ▄▄▄  ▄▄▄  ▄▄▄  ▄▄▄  ▄▄▄ \n",
        "█   █ █   █   █ █   █ █   █ █   █ █   █ █   █ █   █\n",
        "█▄▄▄█ █   █   █ █▄▄▄█ █▄▄▄█ █▄▄▄█ █   █ █   █ █▄▄▄█\n",
        "█   █ █   █   █ █   █ █     █   █   █▄█   █▄█  █   █\n",
        "█   █ █▄▄▄█▄▄▄█ █   █ █     █   █    █      █   █   █\n",
    );
    let title_para = Paragraph::new(title_art)
        .style(Style::default().fg(Color::Green).bg(Color::Black))
        .alignment(Alignment::Center);
    frame.render_widget(title_para, chunks[2]);

    // Service icons line (text representation)
    let icons_line = Line::from(vec![
        Span::styled("  [ # ]", Style::default().fg(Color::Blue)),
        Span::styled("   |   ", Style::default().fg(Color::Green)),
        Span::styled("[ T ]", Style::default().fg(Color::Magenta)),
        Span::styled("   |   ", Style::default().fg(Color::Green)),
        Span::styled("[ @ ]  ", Style::default().fg(Color::Cyan)),
    ]);
    frame.render_widget(
        Paragraph::new(icons_line).alignment(Alignment::Center),
        chunks[3],
    );

    // Tagline
    let tagline = Paragraph::new(
        "·-·-·-·-·-·-·- Corporate Communications Aggregator -·-·-·-·-·-·-",
    )
    .style(Style::default().fg(Color::Green))
    .alignment(Alignment::Center);
    frame.render_widget(tagline, chunks[4]);

    // Boot log area: split into left (log lines) and right (diagram)
    let boot_area = chunks[5];
    let boot_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(boot_area);

    let mut log_lines: Vec<Line> = BOOT_STEPS[..boot_step]
        .iter()
        .map(|(step, ok)| {
            Line::from(vec![
                Span::styled(format!("{} ", step), Style::default().fg(Color::Green)),
                Span::styled(
                    format!("......... {}", ok),
                    Style::default().fg(Color::Green),
                ),
            ])
        })
        .collect();

    if all_done {
        log_lines.push(Line::from(""));
        log_lines.push(Line::from(vec![Span::styled(
            "·-·-·-· [ ALL SYSTEMS OPERATIONAL ] ·-·-·-·",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )]));
    }

    let log_para = Paragraph::new(log_lines)
        .style(Style::default().bg(Color::Black))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green))
                .style(Style::default().bg(Color::Black)),
        );
    frame.render_widget(log_para, boot_cols[0]);

    // Right side: simple circuit/eye diagram in text
    let diagram = concat!(
        "\n",
        "  ●━━━━━━━━━━━━━━►\n",
        "  ●━━━━━━━┓\n",
        "          ┗━[◉]━━►\n",
        "  ●━━━━━━━┛\n",
        "  ●━━━━━━━━━━━━━━►\n",
    );
    let diagram_para = Paragraph::new(diagram)
        .style(Style::default().fg(Color::Green).bg(Color::Black))
        .alignment(Alignment::Center);
    frame.render_widget(diagram_para, boot_cols[1]);

    // Prompt line
    let prompt = Paragraph::new("alligator@corp:~$ █")
        .style(Style::default().fg(Color::Green).bg(Color::Black));
    frame.render_widget(prompt, chunks[6]);
}

fn draw(frame: &mut Frame, rooms: &[&alligator::Room], selected: usize) {
    let layout = Layout::default()
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
                .title("Rooms (q to quit, ↑/↓ to navigate)"),
        )
        .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan))
        .highlight_symbol(">> ");

    let mut state = ratatui::widgets::ListState::default();
    if !rooms.is_empty() {
        state.select(Some(selected));
    }
    frame.render_stateful_widget(rooms_list, layout[0], &mut state);

    let timeline_text = rooms
        .get(selected)
        .map(|room| {
            room.messages
                .iter()
                .map(|msg| format!("{}: {}", msg.author, msg.body))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_else(|| "Waiting for messages from connected bridges...".to_string());

    let timeline = Paragraph::new(timeline_text)
        .block(Block::default().borders(Borders::ALL).title("Timeline"))
        .wrap(Wrap { trim: true });

    frame.render_widget(timeline, layout[1]);
}
