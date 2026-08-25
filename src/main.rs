use std::error::Error;
use std::sync::mpsc;
use std::time::Duration;

use alligator::{Bridge, MockBridge, Source, UnifiedTimeline};
use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

fn main() -> Result<(), Box<dyn Error>> {
    enable_raw_mode()?;
    let mut terminal = ratatui::init();

    let run_result = run_app(&mut terminal);

    ratatui::restore();
    disable_raw_mode()?;

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

    loop {
        while let Ok(message) = rx.try_recv() {
            timeline.ingest(message);
        }

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
