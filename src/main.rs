use std::error::Error;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use alligator::{Bridge, MockBridge, Source, UnifiedTimeline};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::prelude::*;
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

const SPLASH_DURATION: Duration = Duration::from_secs(3);
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
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
    "#+#     #+# #+#        #+#            #+#    #+#    #+# #+#     #+# #+#    #+#    #+# #+#    #+#   ",
    "###     ### ########## ########## ########### ########  ###     ### ###     ########  ###    ###    ",
];

#[derive(Clone, Copy, Eq, PartialEq)]
enum Screen {
    Splash,
    Timeline,
}

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
    let splash_started = Instant::now();
    let mut screen = Screen::Splash;

    loop {
        while let Ok(message) = rx.try_recv() {
            timeline.ingest(message);
        }

        let rooms = timeline.ordered_rooms();
        if selected >= rooms.len() && !rooms.is_empty() {
            selected = rooms.len() - 1;
        }

        if screen == Screen::Splash && splash_started.elapsed() >= SPLASH_DURATION {
            screen = Screen::Timeline;
        }

        terminal.draw(|frame| draw(frame, &rooms, selected, screen))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match screen {
                    Screen::Splash => match key.code {
                        KeyCode::Char('q') => return Ok(()),
                        _ => screen = Screen::Timeline,
                    },
                    Screen::Timeline => match key.code {
                        KeyCode::Char('q') => return Ok(()),
                        KeyCode::Up => selected = selected.saturating_sub(1),
                        KeyCode::Down => {
                            if selected + 1 < rooms.len() {
                                selected += 1;
                            }
                        }
                        _ => {}
                    },
                }
            }
        }
    }
}

fn draw(frame: &mut Frame, rooms: &[&alligator::Room], selected: usize, screen: Screen) {
    match screen {
        Screen::Splash => draw_splash(frame),
        Screen::Timeline => draw_timeline(frame, rooms, selected),
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

fn draw_timeline(frame: &mut Frame, rooms: &[&alligator::Room], selected: usize) {
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
