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
  - Vault unlock currently supports password
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
  - `k` → reserved; hardware-key unlock is currently disabled
- Timeline actions:
  - `↑` / `↓` → move selected room
  - `l` → lock immediately (returns to splash)
  - `s` → open authentication settings
- Authentication settings actions:
  - `l` → lock immediately
  - `e` → reserved; hardware-key enrollment is currently disabled
  - `r` → rotate password
  - `x` → revoke key credential by ID (for example `fido2:local:12ab34cd-56ef7890`)
  - `b` → back to timeline

## Generic security-key notes

- Hardware-key flows are intentionally disabled until a secure device-backed challenge/verification path is implemented.
- This avoids insecure tap-only simulation behavior that could permit Enter-only unlock.
