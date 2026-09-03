# Alligator
Corporate Comms Aggregator

Rust TUI application that aggregates messages from multiple bridge sources into a unified interface.

## Current behavior

- Startup splash screen with custom ASCII alligator art and title treatment
- First-run profile setup prompt when no local user profile exists
- Local app lock screen before any bridge connections are started
- Vault-first credential model:
  - OAuth token secrets are encrypted on disk
  - Non-secret token metadata (provider/scopes/expiry) is stored separately
  - Vault file is bound to the current OS user identity
  - Vault unlock supports password or passkey-style credential IDs + secrets
- Simulated bridge sources for Slack, Teams, and Google Chat (only active when unlocked)
- Left sidebar showing:
  - source indicator
  - room title
  - preview of latest message
- Main timeline showing messages for the selected room
- Near real-time updates as bridge messages are received
- Auto-lock on inactivity, lock/unlock audit events in memory, and unlock rate limiting with cooldown

## Run

```bash
cargo run
```

On first run for an OS user, create your profile password when prompted.
After setup, use any key on splash to open login.

## Security controls

- Unlock methods:
  - `p` → password unlock
  - `k` → passkey unlock with `credential_id:secret`
- Timeline actions:
  - `↑` / `↓` → move selected room
  - `l` → lock immediately (returns to splash)
  - `s` → open authentication settings
- Authentication settings actions:
  - `l` → lock immediately
  - `e` → enroll passkey (`credential_id:secret`)
  - `r` → rotate password
  - `x` → revoke passkey
  - `b` → back to timeline
