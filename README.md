# Alligator
Corporate Comms Aggregator

Rust TUI application that aggregates messages from multiple bridge sources into a unified interface.

## Current behavior

- Simulated bridge sources for Slack, Teams, and Google Chat
- Left sidebar showing:
  - source indicator
  - room title
  - preview of latest message
- Main timeline showing messages for the selected room
- Near real-time updates as bridge messages are received

## Run

```bash
cargo run
```

Use `↑` / `↓` to change selected room and `q` to quit.
