```text
      ____          _     __        __   _
     / ___|___   __| | ___\ \      / /__| |____      ____ _ _   _
    | |   / _ \ / _` |/ _ \\ \ /\ / / _ \ '_ \ \ /\ / / _` | | | |
    | |__| (_) | (_| |  __/ \ V  V /  __/ |_) \ V  V / (_| | |_| |
     \____\___/ \__,_|\___|  \_/\_/ \___|_.__/ \_/\_/ \__,_|\__, |
                                                            |___/
          [ Lightweight AI Agent Workspace • Powered by Rust ]
```

A lightweight web terminal written in Rust. Run it on any machine and access your shell from any browser — no remote desktop, no VNC, no heavy software required.

**Powered by Rust**

## How it works

```
Browser ←── WebSocket ──→ CodeWebway ←──→ $SHELL (PTY)
                                ↕
                       broadcast channel
                    (shared across all tabs)
```

- **Single binary** — no runtime dependencies, embeds the web UI inside
- **Multi-terminal tabs** — open multiple PTYs and close each one server-side
- **Auto-generated token** — no need to set a password manually
- **Login screen** — enter password on first page before terminal opens
- **Login rate limit** — 3 failed attempts per 5 minutes per client IP
- **Expiring web sessions** — login session cookie expires after 30 minutes
- **Logout controls** — choose logout for current browser or all active web sessions
- **2-step login by default** — password + PIN required for access
- **Scrollback replay** — reconnecting clients see previous output
- **Session resume** — reconnecting tabs/devices continue each terminal session
- **File explorer + preview** — browse project structure and open shell in selected folder
- **Built-in editor mode** — switch from preview to edit and save text files in-browser
- **Traffic meter** — see Today/Session data usage from terminal + file APIs
- **Data-saving defaults** — manual refresh, file-size guardrails, diff-based saves, HTTP compression
- **PTY resize** — terminal resizes when you resize the browser window
- **Cross-platform** — macOS, Linux, Windows (ConPTY)

## Quick start

### Install (macOS / Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/iylmwysst/CodeWebway/main/install.sh | sh
```

### Run

```bash
codewebway -z
```

Output:
```
  CodeWebway
  ─────────────────────────────────
  Token  : A1b2C3d4E5f6G7h8
  Open   : http://localhost:8080
  ─────────────────────────────────
```

Open the URL in your browser — done.

## Usage

```
codewebway [OPTIONS]

Options:
  --host <HOST>          Listen host [default: 127.0.0.1]
  --port <PORT>          Listen port [default: 8080]
  --password <PASSWORD>  Set a fixed token (auto-generated if omitted)
  --pin <PIN>            Set secondary login PIN (if omitted, interactive hidden prompt)
  --shell <PATH>         Shell to spawn [default: $SHELL]
  --cwd <PATH>           Working directory for shell [default: current directory]
  --scrollback <BYTES>   Scrollback buffer size [default: 131072]
  -z, --zrok             Create a public zrok URL (requires zrok installed/enabled)
  -h, --help             Print help
```

### Public URL with zrok

```bash
codewebway -z
# or
codewebway --zrok
```

This starts `zrok share public <port>` automatically and keeps terminal auth in the login page.

### Access from another device

Pair with [Tailscale](https://tailscale.com) or [ngrok](https://ngrok.com) to expose the port:

```bash
# With ngrok
ngrok http 8080

# With Tailscale — just use your Tailscale IP
codewebway --port 8080
# open http://<tailscale-ip>:8080 then enter password
```

## Build from source

Requires [Rust](https://rustup.rs) 1.75+.

```bash
git clone https://github.com/iylmwysst/CodeWebway
cd CodeWebway
cargo build --release
./target/release/codewebway
```

## Tech stack

| Component | Crate |
|-----------|-------|
| HTTP + WebSocket | `axum` 0.7 |
| PTY (cross-platform) | `portable-pty` 0.8 |
| Async runtime | `tokio` 1 |
| Embedded assets | `rust-embed` 8 |
| CLI | `clap` 4 |
| Frontend | xterm.js 5.3 |

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).
