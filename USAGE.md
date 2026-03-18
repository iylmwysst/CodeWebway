# Usage

CodeWebway has one global option parser plus a few manual subcommands handled before Clap.

Global form:

```text
codewebway [OPTIONS]
```

Manual subcommands:

```text
codewebway enable [<token>] [--endpoint <url>] [--pin <pin>] [--service|--no-service]
codewebway fleet [OPTIONS]
codewebway disable
codewebway uninstall-service
```

These subcommands are routed manually in `src/main.rs`, so `codewebway --help` only prints the global option set.

## Common Examples

```bash
# Local-only terminal on localhost
codewebway --pin 123456

# Public share through zrok
codewebway -z --pin 123456

# Restrict the HTTP file/editor root
codewebway -z --cwd ~/project --pin 123456

# Terminal only: no file browser or editor routes
codewebway -z --terminal-only --pin 123456

# Print one startup temp link
codewebway -z --temp-link --temp-link-scope read-only --temp-link-ttl-minutes 15 --pin 123456

# Auto-disable the zrok share after 30 minutes
codewebway -z --public-timeout-minutes 30 --pin 123456

# Register a headless machine with WebWayFleet
codewebway enable

# After registration, run the long-lived fleet daemon
codewebway fleet
```

## Global Options

These are the current `codewebway --help` flags:

```text
  --host <HOST>                                   Host/IP to bind (default: localhost only)
  --port <PORT>                                   Port to listen on
  --password <PASSWORD>                           Access token (auto-generated if not provided)
  --pin <PIN>                                     Secondary login PIN
  --dashboard-auth-api-base <URL>                 WebWayFleet API base for host-login challenge verification
  --dashboard-auth-machine-token <TOKEN>          Machine token used for WebWayFleet host-login verification
  --dashboard-auth-clerk-publishable-key <KEY>    Parsed today but not used by the runtime
  --sso-shared-secret <SECRET>                    Shared secret for signed SSO ticket login
  --shell <SHELL>                                 Shell executable
  --cwd <PATH>                                    Working directory / file API root
  --scrollback <BYTES>                            Scrollback buffer size in bytes
  -z, --zrok                                      Create a public URL with zrok
  --public-timeout-minutes <N>                    Auto-disable zrok share after N minutes
  --public-no-expiry                              Keep zrok share active until shutdown
  --max-connections <N>                           Maximum concurrent WebSocket clients
  --terminal-only                                 Disable file explorer and editor routes
  --temp-link                                     Print one temporary link at startup
  --temp-link-ttl-minutes <N>                     Temporary link TTL: 5, 15, or 60
  --temp-link-scope <SCOPE>                       read-only | interactive
  --temp-link-max-uses <N>                        Temporary link max uses
```

Notes:

- `--max-connections` limits concurrent WebSocket clients, not terminal tabs.
- Terminal tab count is currently fixed at 8 per process.
- `--dashboard-auth-api-base`, `--dashboard-auth-machine-token`, and `--sso-shared-secret` are usually set by fleet mode, not by hand.
- `--dashboard-auth-clerk-publishable-key` is currently a no-op in the runtime.

## Direct Login Modes

### Access Token + PIN

The default login page asks for:

- access token
- machine PIN

If `--password` is omitted, CodeWebway generates a token and prints it once at startup.

### Signed SSO Ticket + PIN

If `--sso-shared-secret` is configured, `/auth/login` also accepts:

```text
<base64url(payload_json)>.<hex_hmac_sha256_signature>
```

Required payload fields:

- `sub`
- `nonce`
- `exp`

This is what the WebWayFleet dashboard uses for "Open Terminal". The ticket replaces the access token prompt, but the machine PIN is still required.

Launch tickets are now also bound to the current runtime instance in fleet mode, so a stale launch URL from an older terminal run cannot be replayed against a newer run.

### Temporary Links

Temporary links are created either:

- at startup with `--temp-link`
- after login from the Share dialog in the web UI

Current behavior:

- TTL: 5, 15, or 60 minutes
- scope: `read-only` or `interactive`
- max uses: 1 to 100
- optional binding to one terminal tab
- max 2 active links at once
- `interactive` links created on dashboard-enabled hosts redeem through owner approval before the guest session is minted

Read-only temp sessions can still view output, but server-side input and file writes are dropped.

## Fleet Mode

Fleet mode lets WebWayFleet start and stop CodeWebway remotely without SSH.

### One-Time Registration

Current primary flow:

```bash
codewebway enable
```

When you run `codewebway enable` in an interactive terminal, CodeWebway shows a menu:

- `Scan QR Code`
- `Enter Token`

That is the normal current setup flow for real users.

Recommended flow:

1. Run `codewebway enable`
2. Choose `Scan QR Code` for headless machines, or `Enter Token` if you already copied a token from WebWayFleet
3. Complete the PIN prompt
4. Optionally install the auto-start service

Direct token mode is still supported as a shortcut:

```bash
codewebway enable <token-from-dashboard>
```

Self-hosted API:

```bash
codewebway enable --endpoint https://your-fleet-api.example.com
```

Direct token + self-hosted API:

```bash
codewebway enable <token-from-dashboard> --endpoint https://your-fleet-api.example.com
```

`enable` currently supports:

- QR/device-code approval flow
- manual token entry from the prompt
- direct `enable <token>` shortcut
- optional PIN prompt
- optional service install prompt after registration

If you skip service installation, `enable` immediately starts the fleet daemon in the foreground.

After success, credentials are stored in:

```text
~/.config/codewebway/fleet.toml
```

### Running the Daemon

Foreground daemon:

```bash
codewebway fleet
```

You can still pass normal runtime flags to the daemon, for example:

```bash
codewebway fleet --cwd /srv/app --scrollback 262144
```

Important fleet-mode behavior:

- `codewebway fleet` always forces `--zrok --public-no-expiry`
- if `--pin` is omitted, CodeWebway loads the stored PIN from `fleet.toml`
- healthy realtime-connected daemons use the machine channel for stop commands and only fall back to heartbeat polling when the channel is unavailable; legacy/degraded paths still heartbeat every 30 seconds
- dashboard start/stop requests are delivered through the pending command channel
- each dashboard "Start Terminal" creates a fresh runtime access token for that run

### Service Installation

There is no separate `install-service` subcommand. Service install happens after `enable`.

Examples:

```bash
# Register, then immediately install the user service
codewebway enable <token> --service

# Register, but skip the install prompt
codewebway enable <token> --no-service

# Remove the installed service
codewebway uninstall-service
```

Current platform support:

- macOS: LaunchAgent
- Linux: `systemd --user`

`codewebway uninstall-service` removes the auto-start service only. It does not delete `fleet.toml`.

### Disable Fleet

```bash
codewebway disable
```

This removes the local `fleet.toml` credentials file.

## WebWayFleet Dashboard Access Paths

Once a machine is running, the dashboard supports three ways to reach it:

1. `Open Terminal`
   - gets a short-lived signed launch URL
   - opens CodeWebway with `?sso_ticket=...`
   - still requires the machine PIN on the host page

2. `Reveal Token`
   - fetches the runtime access token stored in WebWayFleet KV
   - intended for recovery only when launch URLs are not enough
   - still requires the machine PIN
   - the token is bound to the current runtime instance and is rejected after a new runtime replaces it

3. Host page `Continue`
   - starts a WebWayFleet approval challenge from the CodeWebway login page itself
   - you approve the request on the dashboard
   - the host then asks for the machine PIN

## Dashboard Policy Overrides

When the dashboard starts a terminal, it can send policy values from the project or machine record:

- `cwd`
- `shell`
- `terminal_only`
- `scrollback`
- `max_connections`
- `temp_link_enabled`
- `temp_link_ttl_minutes`
- `temp_link_scope`
- `temp_link_max_uses`

Those values are merged in WebWayFleet and sent in the `run_codewebway` command payload.

## Public Exposure

### zrok (recommended)

```bash
codewebway -z --pin 123456
```

Requirements:

```bash
# macOS
brew install openziti/ziti/zrok

# Linux
curl -sSf https://get.zrok.io | bash

# one-time account enable
zrok enable <token>
```

### Reverse Proxy

Point your HTTPS proxy at `127.0.0.1:8080`.

Forward these headers:

- `Host`
- `X-Forwarded-Host`
- `X-Forwarded-Proto`

CodeWebway uses them when validating WebSocket `Origin`.

### Tailscale / LAN-only

Bind to a specific interface instead of using zrok:

```bash
codewebway --host <tailscale-ip> --pin 123456
```

## Runtime Notes

- File API operations only work on existing paths under the configured root.
- Directory listings hide dotfiles, but explicit file requests can still access known dotfile paths under the root.
- `--terminal-only` removes the file routes entirely.
- Auto-shutdown is disabled only when `--zrok --public-no-expiry` is combined.
- `--public-timeout-minutes` and `--public-no-expiry` only affect zrok mode.
