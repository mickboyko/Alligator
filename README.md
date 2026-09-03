# Alligator
Corporate Comms Aggregator

Rust TUI application that aggregates messages from multiple bridge sources into a unified interface.

## Current behavior

- Startup splash screen with custom ASCII alligator art and title treatment
- Simulated single-stream Slack bridge demo
- Left sidebar showing:
  - source indicator
  - room title
  - preview of latest message
- Main timeline showing messages for the selected room
- Demo updates every 2-5 seconds to mimic a single incoming stream

## Run

```bash
cargo run
```

Use `↑` / `↓` to change selected room and `q` to quit.
Press any key to dismiss the splash screen immediately, or wait for it to continue automatically.
