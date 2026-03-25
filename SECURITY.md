# Security

CodeWebway is a single-user remote terminal with optional WebWayFleet control. It is designed for one trusted operator accessing their own machine, not for multi-tenant hosting or shared team shells.

Anyone who successfully authenticates gets a shell with the same OS privileges as the user who started `codewebway`. That is the core trust boundary.

## Deployment Recommendations

Before exposing a host publicly:

- Use TLS. The built-in server speaks plain HTTP; use standalone public ingress (`--zrok`), fleet-managed Cloudflare ingress, or an HTTPS reverse proxy.
- Run as a non-root dedicated user.
- Narrow the filesystem root with `--cwd`.
- Use `--terminal-only` when you do not need the file browser/editor routes.
- Protect `~/.config/codewebway/fleet.toml` if you use fleet mode. It stores the raw machine token and PIN in plaintext.
- Avoid passing long-lived secrets on the CLI in multi-user environments. `ps` can expose `--password` and `--pin`.

## System Overview

CodeWebway supports four access paths:

1. Direct login: access token plus machine PIN.
2. Fleet host-login challenge: dashboard account approval plus machine PIN.
3. Fleet launch URL: short-lived signed `sso_ticket` plus machine PIN.
4. Temporary links: delegated access minted from a signed link. Read-only links can redeem directly; interactive links on dashboard-enabled hosts require owner approval before the guest session is issued.

The default bind is `127.0.0.1:8080`, so nothing is reachable off-host unless you explicitly opt into public exposure.

## Trust Boundaries

- Browser to CodeWebway: HTTP on localhost by default, or HTTPS when fronted by public ingress / reverse proxy.
- CodeWebway to PTY/filesystem: same OS user privileges as the CodeWebway process.
- CodeWebway to WebWayFleet API: outbound HTTPS with bearer machine token in fleet mode.
- WebWayFleet Dashboard/API to users: Clerk bearer tokens for dashboard auth, D1 for persistent state, KV for short-lived challenge/token state.

Current fleet control behavior:

- Remote start, stop, and client-update actions depend on the realtime machine channel.
- `/api/v1/agent/heartbeat` is no longer a command-delivery path; it is only used for coarse lease/reconcile behavior while the presence redesign is still in progress.

## Authentication Flows

### 1. Direct Token Login

- `--password` may be provided or auto-generated.
- The token must be at least 16 characters.
- `--pin` is required for standard interactive use and must be at least 6 digits.
- `/auth/login` accepts the access factor (`password`, `sso_ticket`, `dashboard_ticket`, or `dashboard_token`) plus the PIN.

### 2. Fleet Host-Login Challenge

This is the "Continue" button on the host login page.

Flow:

1. CodeWebway calls WebWayFleet `/api/v1/agent/host-auth/challenge` using the machine token.
2. WebWayFleet stores a 180-second challenge in KV and returns an approval URL.
3. The dashboard user signs in with Clerk and approves `/api/v1/machines/host-auth/approve`.
4. CodeWebway polls `/api/v1/agent/host-auth/challenge/:id`.
5. After approval, CodeWebway creates a local `dashboard_pending_login_id`.
6. The browser must still submit the machine PIN to `/auth/login`.

This keeps account ownership verification in WebWayFleet and PIN verification local to the device.

Current local guardrails:

- the pending local login window lives for 180 seconds
- the pending login is discarded after 5 wrong PIN submissions

### 3. Fleet Launch URL (`sso_ticket`)

This is the "Open Terminal" flow from the dashboard.

Flow:

1. The dashboard calls `/api/v1/machines/:id/terminal/launch-url`.
2. WebWayFleet signs a short-lived ticket with HMAC-SHA256 using the hashed machine token stored in D1.
3. The browser opens `https://host/?sso_ticket=...`.
4. CodeWebway verifies the signature with `--sso-shared-secret`.
5. The user still enters the machine PIN locally.
6. In fleet mode, the ticket is also bound to the current runtime instance so stale launch material cannot be replayed against a newer run.

Current runtime behavior:

- WebWayFleet issues launch URLs with about 120 seconds of validity.
- CodeWebway rejects expired tickets and rejects tickets with `exp` more than 5 minutes in the future.
- Nonces are single-use. Replays are rejected.

### 4. Temporary Links

Temporary links are explicit delegated access, separate from token+PIN auth.

Current behavior:

- Max 2 active links at a time.
- TTL must be 5, 15, or 60 minutes.
- `max_uses` can be 1 to 100.
- Scope can be `read-only` or `interactive`.
- Links can optionally be bound to one terminal tab.

Implementation details:

- The URL token is signed with a random per-process signing key and SHA-256 over `key:id.expires.nonce`.
- Tokens include a nonce and expiry timestamp.
- Links are enforced server-side. Read-only sessions silently drop PTY input and file writes.
- Read-only links mint a narrow session cookie plus an in-memory grant describing read-only or terminal-bound restrictions.
- Interactive links on dashboard-enabled hosts show an owner-approval page first and only mint the guest session after approval succeeds.

## Rate Limiting

CodeWebway tracks attempts by client key. The client key prefers:

1. `CF-Connecting-IP`
2. First IP in `X-Forwarded-For`
3. `X-Real-IP`
4. A fingerprint derived from headers such as `User-Agent`, `Accept-Language`, and `Host`

Current limits in CodeWebway:

- Credential attempts: 5 per 5 minutes
- PIN attempts: 8 per 5 minutes
- Host-login challenge polls: 90 per 120 seconds

When limited, CodeWebway returns `429 Too Many Requests` with `Retry-After`.

WebWayFleet adds separate best-effort in-memory rate limits on machine endpoints:

- `/api/v1/agent/heartbeat`: 20 requests/minute per machine token, 120/minute per client IP
- `/api/v1/agent/report`: 30 requests/minute per machine token, 180/minute per client IP

When those trip, WebWayFleet records a `security_events` audit entry when the table exists.

Important fleet note:

- heartbeat rate limiting no longer gates command delivery because command dispatch is realtime-only

## Comparison and Secret Handling

- Token and PIN comparisons use a byte-wise XOR fold when the lengths match.
- Length mismatches fail immediately. This is not a fully constant-time comparison across different lengths.
- Token and PIN are stored as plain `String` values in process memory.
- There is no explicit memory zeroization on exit.

## Sessions and Cookies

Current session behavior:

- Session tokens are 48 random alphanumeric characters.
- Idle timeout: 30 minutes.
- Absolute timeout: 12 hours.
- `/auth/extend` requires a valid session plus the machine PIN.
- Session validity is re-checked inside the WebSocket loop every 15 seconds.

Current cookie attributes:

```text
codewebway_session=<token>; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800[; Secure when request arrives over HTTPS]
```

Current behavior:

- CodeWebway now adds `Secure` when the request arrives through `X-Forwarded-Proto: https` or an HTTPS `Origin`/`Referer`.
- Plain local HTTP still works without `Secure` so localhost development is not broken.
- If you expose the service publicly, terminate TLS externally and do not serve the same public hostname over plain HTTP.

## Shutdown and Session Revocation

### `POST /auth/logout`

- Without `revoke_all`, only the current session is revoked.
- With `{ "revoke_all": true }`, a valid session can:
  - revoke all sessions
  - revoke all temporary links
  - clear temp grants
  - set `access_locked = true`
  - close all terminals
  - trigger process shutdown

This flow does not ask for the PIN again.

### `POST /auth/stop-terminal`

- Requires a valid session and the machine PIN.
- Revokes all sessions, temp grants, and temp links.
- Closes all terminals and shuts the process down.

## Auto-Shutdown Behavior

CodeWebway has an inactivity shutdown timer unless public ingress is enabled with `--public-no-expiry`.

Current behavior:

- Fresh process with no authenticated activity: shuts down after 3 hours.
- After authenticated activity: shutdown deadline becomes `now + 30 minutes idle timeout + 3 hours grace`.
- Public status is exposed through `/auth/public-status` so the host page can show the remaining time.

## WebSocket Protections

- WebSocket upgrade is rejected unless `Origin` matches `Host` or `X-Forwarded-Host`.
- If `X-Forwarded-Proto` is present, the scheme must also match exactly.
- Concurrent WebSocket clients are limited by `--max-connections`.
- Terminal tab count is a separate hard limit and is currently fixed at 8 tabs per process.

## Filesystem and Editor Surface

If `--terminal-only` is enabled, CodeWebway does not register any `/api/fs/*` routes.

When file routes are enabled:

- Absolute paths are rejected.
- `..` path segments are rejected.
- Requested paths are canonicalized and must stay under the configured root directory.
- The HTTP editor only works on paths that already exist.
- Preview is capped at 256 KiB.
- Save/diff writes are capped at 512 KiB.
- Diff saves require the current SHA-256 file hash and valid UTF-8 file contents.

Important nuance:

- Directory listing hides names starting with `.`
- Explicit file requests can still read or overwrite existing dotfiles under the root if the caller already knows the path

That means `--cwd` remains a primary containment control.

## Fleet Credential Storage

`codewebway enable` stores this file locally:

```text
~/.config/codewebway/fleet.toml
```

It contains:

- raw machine token
- machine name
- fleet endpoint
- PIN

Current implementation notes:

- The file is written with normal OS defaults and whatever umask is active.
- The binary does not currently apply stricter permissions with `chmod`.
- WebWayFleet stores the machine token hashed in D1; the raw token is not returned again after enable.

## Runtime Access Tokens in Fleet Mode

Each `run_codewebway` command creates a fresh runtime access token for that one live terminal run.

Current pipeline:

1. CodeWebway fleet daemon generates a 24-character runtime token.
2. The daemon reports structured JSON back to WebWayFleet:
   - `url`
   - `access_token`
   - `access_token_ttl_secs`
3. WebWayFleet stores the public URL in D1.
4. WebWayFleet stores the runtime access token only in KV `terminal_access:<machineId>` with a TTL capped at 12 hours.
5. The token record is tied to the current runtime instance. Once a new runtime instance is reported, older recovery material is rejected.

## Fleet Activity And Rotation

- CodeWebway now emits runtime access events back to WebWayFleet for secure launch entries, dashboard-approved sign-ins, recovery-token sign-ins, and temp-link creation/redemption.
- WebWayFleet aggregates these into machine access insights so token-heavy paths can be measured and reduced over time.
- Machine-plane trust is narrowed with token rotation support:
  - the active machine token can be rotated through the API
  - the previous token remains valid only during a grace window
  - fleet daemons rotate tokens only while idle so live terminal runs are not interrupted
5. Execution logs in D1 receive sanitized output with the secret removed.

This limits secret persistence compared with storing runtime tokens in execution history.

## Static Analysis and CI

This repository currently runs:

- `cargo test`
- `cargo clippy --all-targets -- -D warnings`
- `cargo fmt --all -- --check`

on every push to `main` and every pull request.

CodeQL runs on:

- push to `main`
- pull requests to `main`
- a weekly scheduled scan

Results are published in the repository Security tab.

## Reporting a Vulnerability

Please do not open a public issue for a security report.

Use GitHub private security advisories:

- https://github.com/iylmwysst/CodeWebway/security/advisories/new

Include:

- affected version or commit
- deployment mode (`local`, `standalone public ingress`, `reverse proxy`, `fleet`)
- reproduction steps
- whether WebWayFleet is involved

Target response time is 48 hours for initial acknowledgement.
