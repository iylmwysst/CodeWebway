```text
      ____          _     __        __   _
     / ___|___   __| | ___\ \      / /__| |____      ____ _ _   _
    | |   / _ \ / _` |/ _ \\ \ /\ / / _ \ '_ \ \ /\ / / _` | | | |
    | |__| (_) | (_| |  __/ \ V  V /  __/ |_) \ V  V / (_| | |_| |
     \____\___/ \__,_|\___|  \_/\_/ \___|_.__/ \_/\_/ \__,_|\__, |
                                                            |___/
```

> **Browser-based remote terminal and file editor — no port forwarding, no VPS, no network admin required.**

CodeWebway is a single Rust binary that gives you a full terminal and file editor in the browser. It is built for developers working on machines behind firewalls, NAT, or institutional networks where traditional SSH access is not practical.

## How It Works

```text
Browser  ──HTTPS──▶  zrok edge  ──tunnel──▶  CodeWebway  ──PTY──▶  Shell
```

- One process serves both the backend and the web UI — no separate frontend server.
- Terminal sessions are real server-side PTYs with scrollback replay on reconnect.
- The server binds to `127.0.0.1` by default. Public access is opt-in via `--zrok` or a reverse proxy.

## Quick Start

**Install (macOS / Linux)**

```bash
curl -fsSL https://raw.githubusercontent.com/iylmwysst/CodeWebway/main/install.sh | sh
```

**Run**

```bash
codewebway -z
```

The startup output prints the token, bind address, and public URL. Open the URL, log in with token + PIN, and you have a terminal.

## When to Use CodeWebway

CodeWebway is optimized for a specific gap: **single-operator remote access from a machine you do not fully control the network on.**

It is not a VPN replacement. It is not an enterprise access platform. It fills the space where those tools are impractical:

- Your machine is behind a university, corporate, or ISP NAT with no port forwarding.
- You cannot get the network team to open a firewall rule.
- You tried VPN but it disconnects on every Wi-Fi handoff or wakes from sleep.
- You want a browser tab, not a separate SSH client install.

## Comparison

| | CodeWebway + zrok | OpenSSH | SSH + VPS | Tailscale | ttyd |
|---|---|---|---|---|---|
| **Requires port forwarding** | No | Yes | No | No | Yes |
| **Requires network admin** | No | Yes | No | No | Yes |
| **Works behind strict firewall** | ✅ | ❌ | ⚠ depends | ⚠ sometimes blocked | ❌ |
| **Connection layer** | Application | Network | Network | Network mesh | Application |
| **Stable across Wi-Fi changes** | ✅ | ❌ reconnects | ❌ reconnects | ⚠ | ✅ |
| **Direct cost** | Free | Free | ~$5/mo VPS | Free (small scale) | Free |
| **Needs VPS** | No | No | Yes | No | No |
| **Built-in 2FA** | ✅ token + PIN | ❌ | ❌ | ❌ | ❌ |
| **Browser-native** | ✅ | ❌ | ❌ | ❌ | ✅ |
| **File editor included** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Single binary** | ✅ | ❌ | ❌ | ❌ | ✅ |

**On the "strict firewall" row:** tools like Tailscale use UDP-based mesh protocols that institutional firewalls (Fortinet, Palo Alto, etc.) actively identify and block. CodeWebway uses outbound HTTPS only — the same channel as ordinary web browsing — which is effectively never blocked.

**On the "connection layer" row:** SSH and VPN tools operate at the network layer. When the connection drops they must re-establish routing state. CodeWebway is an application-layer tunnel. A brief Wi-Fi interruption or laptop waking from sleep causes a WebSocket reconnect, not a full tunnel teardown. This is why it feels more stable in practice on unreliable institutional networks.

**On cost:** "free" tools still have infrastructure cost. OpenSSH requires control over a router or firewall to enable inbound access — in a university or shared office environment, this means asking a network administrator, which is often not possible for individual users. CodeWebway requires none of that.

## CLI Usage

```text
codewebway [OPTIONS]

Options:
  --host <HOST>                   Listen host [default: 127.0.0.1]
  --port <PORT>                   Listen port [default: 8080]
  --password <PASSWORD>           Token (min 16 chars; auto-generated if omitted)
  --pin <PIN>                     Secondary PIN (numeric, min 6 digits)
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

## Public Access Options

**zrok (recommended)**

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

**Tailscale or ngrok**

```bash
# ngrok
ngrok http 8080

# Tailscale — bind to Tailscale interface
codewebway --host <tailscale-ip>
```

## Security

CodeWebway is built for personal public exposure. A terminal in a browser carries full shell access, so security was a first-class design constraint.

### Transport

**Do not expose CodeWebway over plain HTTP to the public internet.** Use `-z` (zrok) or a TLS-terminating reverse proxy. With `-z`, all traffic travels over zrok's HTTPS tunnel before reaching the host. The default bind of `127.0.0.1` means the server is unreachable from any external network unless you explicitly opt in.

### Two-Factor Authentication

Login requires both factors to be submitted together:

| Factor | Constraint |
|--------|-----------|
| **Token** | Minimum 16 characters. Auto-generated (80-bit entropy) if omitted. |
| **PIN** | Numeric, minimum 6 digits. Never printed to stdout. |

Both are compared using **constant-time equality** (byte-by-byte XOR fold), which eliminates timing side-channels.

### Brute-Force Lockout

Failed attempts are tracked per client IP. After **3 failures within 5 minutes** the endpoint returns `429 Too Many Requests` with a `Retry-After` header. A successful login clears the counter. Under `--zrok`, the local port is only reachable via the zrok process — external clients cannot spoof the IP that the rate limiter sees.

### Session Management

- Session tokens: 48-character random alphanumeric (~285-bit entropy).
- Cookies: `HttpOnly; SameSite=Strict` — no JavaScript access, no cross-site submission.
- Idle timeout: 30 minutes. Absolute timeout: 12 hours. Both enforced server-side.
- Extending a session via `POST /auth/extend` requires re-submitting the PIN — a stolen cookie alone cannot silently renew the session.

### Temporary Links

For sharing access without giving out your primary credentials:

- Links are **HMAC-signed** (SHA-256, random signing key per process, per-link nonce + expiry). Forgery is computationally infeasible.
- Scope is enforced **server-side**: `read-only` sessions have terminal input and file writes silently dropped at the server, not just hidden in the UI.
- Configurable TTL (5 / 15 / 60 min), max-use count, and optional binding to a single terminal tab.
- At most 2 active links at a time. Any link can be individually revoked.

### File Access

- All file paths go through a **canonical prefix check** against the configured root directory. Absolute paths and `..` segments are rejected before canonicalization. Post-canonicalization the result must be a descendant of the root — symlink escapes are blocked.
- File preview capped at 256 KB; writes at 512 KB.
- File APIs are absent entirely in `--terminal-only` mode.

### WebSocket

- The upgrade handler validates the `Origin` header against `Host` (and `X-Forwarded-Host`) before accepting any connection, preventing cross-origin WebSocket hijacking.
- Concurrent connections are capped (default 8, configurable).
- Session validity is re-checked every 15 seconds inside the WebSocket loop; expired sessions are disconnected without waiting for client action.

### Emergency Shutdown

`POST /auth/logout` with `{ "revoke_all": true }` (requires a valid session):

1. Invalidates all sessions and temporary links immediately.
2. Locks the login endpoint — no new sessions until the process restarts.
3. Closes all open terminal tabs.
4. Triggers graceful process shutdown.

### Threat Model

CodeWebway is designed for a **single trusted operator** accessing their own machine. It is not a multi-tenant platform. Anyone who successfully authenticates gets a shell with the same OS privileges as the user who started CodeWebway — that is the intended behavior.

Practical attack surface with `codewebway -z --pin <pin>` (auto-generated token):

| Attack vector | Mitigation |
|---------------|-----------|
| Token brute-force | Lockout after 3 attempts; 80-bit token is infeasible to guess |
| Credential sniffing | zrok provides end-to-end TLS; local bind is 127.0.0.1 |
| Cross-site request forgery | `SameSite=Strict` cookie + `Origin` header validation on WebSocket |
| Path traversal | Canonical prefix check on every file request |
| Session hijack | Short-lived tokens; idle + absolute expiry; PIN required to extend |
| Temp link forgery | HMAC-signed with nonce; forgery is computationally infeasible |
| Stale zrok share after crash | PID-file ownership check reclaims orphaned shares on restart |

### Reporting a Vulnerability

If you find a security vulnerability, **please do not open a public GitHub issue.**

Use [GitHub private security advisories](https://github.com/iylmwysst/CodeWebway/security/advisories/new) to report it privately. Include a description of the issue, reproduction steps, and any relevant environment details.

We aim to acknowledge reports within **48 hours** and to ship a fix as quickly as possible. Researchers will be credited in the release notes unless anonymity is requested.

## Build From Source

Requirements: [Rust](https://rustup.rs) 1.75+

```bash
git clone https://github.com/iylmwysst/CodeWebway
cd CodeWebway
cargo build --release
./target/release/codewebway
```

## Tech Stack

| Component | Library |
|---|---|
| HTTP + WebSocket | `axum` |
| PTY | `portable-pty` |
| Async runtime | `tokio` |
| Embedded assets | `rust-embed` |
| CLI | `clap` |
| Terminal renderer | `xterm.js` |

## License

GNU GPL v3.0. See [LICENSE](LICENSE).
