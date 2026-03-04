# Usage

## CLI Options

```text
codewebway [OPTIONS]

Options:
  --host <HOST>                   Listen host [default: 127.0.0.1]
  --port <PORT>                   Listen port [default: 8080]
  --password <PASSWORD>           Token (min 16 chars; auto-generated if omitted)
  --pin <PIN>                     Secondary PIN (numeric, min 6 digits)
  --sso-shared-secret <SECRET>    Enable signed SSO ticket login (still supports token+PIN)
  --shell <PATH>                  Shell executable [default: $SHELL]
  --cwd <PATH>                    Working directory [default: current dir]
  --scrollback <BYTES>            Scrollback buffer size [default: 131072]
  --max-connections <N>           Max concurrent WebSocket connections [default: 8]
  --terminal-only                 Disable file explorer and editor
  --temp-link                     Generate one temporary link at startup
  --temp-link-ttl-minutes <N>     Temporary link TTL: 5, 15, or 60 [default: 15]
  --temp-link-scope <SCOPE>       read-only | interactive [default: read-only]
  --temp-link-max-uses <N>        Max redemptions [default: 1]
  -z, --zrok                      Start zrok public share (zrok must be installed)
  --public-timeout-minutes <N>    Auto-close zrok share after N minutes
  --public-no-expiry              Keep zrok share open until manual shutdown
  -h, --help                      Print help
```

## Examples

```bash
# Basic local access (LAN or localhost only)
codewebway

# Public access via zrok with PIN
codewebway -z --pin 123456

# Restrict to a specific project directory
codewebway -z --cwd ~/project

# Terminal only — no file browser or editor
codewebway -z --terminal-only

# Auto-close the public share after 30 minutes
codewebway -z --public-timeout-minutes 30

# Generate a temporary read-only link (expires in 15 min, single use)
codewebway -z --temp-link

# Generate a temporary interactive link (one use, 60 min TTL)
codewebway -z --temp-link --temp-link-scope interactive --temp-link-ttl-minutes 60

# Let an AI coding agent access a remote shell session
codewebway -z --temp-link --temp-link-scope interactive

# Share a read-only terminal view for debugging help
codewebway -z --temp-link --temp-link-scope read-only --temp-link-ttl-minutes 15
```

## Fleet Mode

Control CodeWebway remotely from a browser — no SSH required.

### Setup (first time)

1. Create a machine on the [WebwayFleet dashboard](https://webwayfleet.dev)
2. Run on your Pi / Jetson / headless device:

```bash
# Register device with WebwayFleet
codewebway enable <token-from-dashboard>

# Start the fleet daemon (waits for start/stop commands from the dashboard)
codewebway fleet --zrok --public-no-expiry --pin 123456
```

### Commands

| Command | Purpose |
|---------|---------|
| `codewebway enable <token>` | Register this device with WebwayFleet |
| `codewebway enable <token> --endpoint <url>` | Register with a self-hosted fleet server |
| `codewebway fleet [flags]` | Run as fleet daemon (polls for start/stop commands) |
| `codewebway disable` | Remove fleet credentials from this device |

### Systemd service (recommended)

```ini
[Unit]
Description=CodeWebway Fleet Daemon
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/codewebway fleet --zrok --public-no-expiry --pin 123456
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now codewebway-fleet
```

---

## Public Access

### zrok (recommended)

The easiest way to expose CodeWebway over a public HTTPS URL with no port forwarding or VPS required.

```bash
codewebway -z
```

Requires `zrok` installed and enabled:

```bash
# macOS
brew install openziti/ziti/zrok

# Linux
curl -sSf https://get.zrok.io | bash

# Enable (one-time, from https://zrok.io)
zrok enable <your_token>
```

### ngrok

```bash
codewebway --port 8080
ngrok http 8080
```

### Tailscale

Bind CodeWebway to your Tailscale IP so it is only reachable within your Tailnet:

```bash
codewebway --host <tailscale-ip>
```

### Reverse Proxy (Caddy, Nginx)

CodeWebway can sit behind any TLS-terminating reverse proxy. Point the proxy at `127.0.0.1:8080`. Ensure the proxy forwards the `Host` and `X-Forwarded-Host` headers — CodeWebway validates the `Origin` header against these on WebSocket upgrade.

## Signed SSO Ticket Login

When `--sso-shared-secret` is set, `/auth/login` accepts either:
- `password + pin` (existing flow)
- `sso_ticket + pin` (no token copy/paste)

Ticket format:

```text
<base64url(payload_json)>.<hex_hmac_sha256_signature>
```

`payload_json` must include:
- `sub` (user id/string)
- `nonce` (16+ chars, single-use)
- `exp` (unix timestamp; must be within 5 minutes)

Signature rule:

```text
signature = HMAC_SHA256_HEX(secret, base64url(payload_json))
```

Open URL example:

```text
https://your-codewebway-host/?sso_ticket=<ticket>
```

The login screen will request only PIN when a valid ticket is present.
