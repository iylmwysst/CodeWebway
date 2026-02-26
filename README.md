# rust-webtty

A lightweight web terminal written in Rust. Run it on any machine and access your shell from any browser — no remote desktop, no VNC, no heavy software required.

## How it works

```
Browser ←── WebSocket ──→ rust-webtty ←──→ $SHELL (PTY)
                                ↕
                       broadcast channel
                    (shared across all tabs)
```

- **Single binary** — no runtime dependencies, embeds the web UI inside
- **Shared session** — all browser tabs see the same terminal (like tmux over the web)
- **Auto-generated token** — no need to set a password manually
- **Login screen** — enter password on first page before terminal opens
- **Login rate limit** — 3 failed attempts per 5 minutes per client IP
- **Scrollback replay** — reconnecting clients see previous output
- **PTY resize** — terminal resizes when you resize the browser window
- **Cross-platform** — macOS, Linux, Windows (ConPTY)

## Quick start

### Install (macOS / Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/iylmwysst/remote-CLI-for-AI-Agent/main/install.sh | sh
```

### Run

```bash
rust-webtty
```

Output:
```
  rust-webtty
  ─────────────────────────────────
  Token  : A1b2C3d4E5f6G7h8
  Open   : http://localhost:8080
  ─────────────────────────────────
```

Open the URL in your browser — done.

## Usage

```
rust-webtty [OPTIONS]

Options:
  --port <PORT>          Listen port [default: 8080]
  --password <PASSWORD>  Set a fixed token (auto-generated if omitted)
  --shell <PATH>         Shell to spawn [default: $SHELL]
  --scrollback <BYTES>   Scrollback buffer size [default: 10240]
  -z, --zrok             Create a public zrok URL (requires zrok installed/enabled)
  -h, --help             Print help
```

### Public URL with zrok

```bash
rust-webtty --zrok
# or
rust-webtty -zrok
```

This starts `zrok share public <port>` automatically and keeps terminal auth in the login page.

### Access from another device

Pair with [Tailscale](https://tailscale.com) or [ngrok](https://ngrok.com) to expose the port:

```bash
# With ngrok
ngrok http 8080

# With Tailscale — just use your Tailscale IP
rust-webtty --port 8080
# open http://<tailscale-ip>:8080 then enter password
```

## Build from source

Requires [Rust](https://rustup.rs) 1.75+.

```bash
git clone https://github.com/iylmwysst/remote-CLI-for-AI-Agent
cd remote-CLI-for-AI-Agent
cargo build --release
./target/release/rust-webtty
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
