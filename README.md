# Alligator
Corporate Comms Aggregator

Rust TUI application that aggregates messages from multiple bridge sources into a unified interface.

## Current behavior

- Startup splash screen with custom ASCII alligator art and title treatment
- Local app lock screen before any bridge connections are started
- Vault-first credential model:
  - OAuth token secrets are encrypted on disk
  - Non-secret token metadata (provider/scopes/expiry) is stored separately
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

Use `↑` / `↓` to change selected room and `q` to quit.
Press any key to dismiss the splash screen immediately, or wait for it to continue automatically.

## Security controls

- Unlock methods:
  - `p` → password unlock
  - `k` → passkey unlock with `credential_id:secret`
- Timeline security actions:
  - `l` → lock immediately
  - `e` → enroll passkey (`credential_id:secret`)
  - `r` → rotate password
  - `x` → revoke passkey
- Before first run, set bootstrap secrets:
  - `ALLIGATOR_BOOTSTRAP_PASSWORD`
  - `ALLIGATOR_BOOTSTRAP_PASSKEY_1` (for `device-key-1`)
  - `ALLIGATOR_BOOTSTRAP_PASSKEY_2` (for `device-key-2`)
