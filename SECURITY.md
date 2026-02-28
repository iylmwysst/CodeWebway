# Security

CodeWebway is built for **personal public exposure** — a single trusted operator accessing their own machine. A terminal in a browser carries full shell access, so security was a first-class design constraint.

This document covers the threat model, implemented mitigations, and how to report vulnerabilities.

## Best Practices

Before exposing CodeWebway publicly:

- **Always use TLS.** Use `--zrok` or a TLS-terminating reverse proxy (Caddy, Nginx). Never expose plain HTTP to the public internet.
- **Set a PIN.** The auto-generated token is strong, but adding `--pin` gives you a second independent factor.
- **Set a public timeout.** Use `--public-timeout-minutes` to cap how long the share stays active. Avoid `--public-no-expiry` unless you have a specific reason.
- **Restrict the working directory.** Use `--cwd` to point CodeWebway at a specific project folder rather than your home directory.
- **Run as a non-root user.** CodeWebway requires no elevated privileges. Running it as a dedicated low-privilege user limits blast radius if something goes wrong.
- **Use `--terminal-only` when file access is not needed.** Disables the file browser and editor API surface entirely.

## Transport Flow

```text
Browser
  │
  │  HTTPS (TLS by zrok)
  ▼
zrok edge server  (public internet)
  │
  │  outbound tunnel (no inbound port required)
  ▼
CodeWebway  127.0.0.1:8080  (your machine)
  │  ✔ origin check
  │  ✔ session cookie validated
  │  ✔ rate limit enforced
  ▼
PTY / file system
```

**Do not expose CodeWebway over plain HTTP to the public internet.** Use `-z` (zrok) or a TLS-terminating reverse proxy. With `-z`, all traffic travels over zrok's HTTPS tunnel before reaching the host. The default bind of `127.0.0.1` means the server is unreachable from any external network unless you explicitly opt in.

## Two-Factor Authentication

Login requires both factors to be submitted together:

| Factor | Constraint |
|--------|-----------|
| **Token** | Minimum 16 characters. Auto-generated (80-bit entropy) if omitted. |
| **PIN** | Numeric, minimum 6 digits. Never printed to stdout. |

Both are compared using **constant-time equality** (byte-by-byte XOR fold), which eliminates timing side-channels.

## Brute-Force Lockout

Failed attempts are tracked per client IP. After **3 failures within 5 minutes** the endpoint returns `429 Too Many Requests` with a `Retry-After` header. A successful login clears the counter. Under `--zrok`, the local port is only reachable via the zrok process — external clients cannot spoof the IP that the rate limiter sees.

## Session Management

- Session tokens: 48-character random alphanumeric (~285-bit entropy).
- Cookies: `HttpOnly; SameSite=Strict` — no JavaScript access, no cross-site submission.
- Idle timeout: 30 minutes. Absolute timeout: 12 hours. Both enforced server-side.
- Extending a session via `POST /auth/extend` requires re-submitting the PIN — a stolen cookie alone cannot silently renew the session.

## Temporary Links

For sharing access without giving out your primary credentials:

- Links are **HMAC-signed** (SHA-256, random signing key per process, per-link nonce + expiry). Forgery is computationally infeasible.
- Scope is enforced **server-side**: `read-only` sessions have terminal input and file writes silently dropped at the server, not just hidden in the UI.
- Configurable TTL (5 / 15 / 60 min), max-use count, and optional binding to a single terminal tab.
- At most 2 active links at a time. Any link can be individually revoked.

## File Access

- All file paths go through a **canonical prefix check** against the configured root directory. Absolute paths and `..` segments are rejected before canonicalization. Post-canonicalization the result must be a descendant of the root — symlink escapes are blocked.
- File preview capped at 256 KB; writes at 512 KB.
- File APIs are absent entirely in `--terminal-only` mode.

## WebSocket

- The upgrade handler validates the `Origin` header against `Host` (and `X-Forwarded-Host`) before accepting any connection, preventing cross-origin WebSocket hijacking.
- Concurrent connections are capped (default 8, configurable).
- Session validity is re-checked every 15 seconds inside the WebSocket loop; expired sessions are disconnected without waiting for client action.

## Emergency Shutdown

`POST /auth/logout` with `{ "revoke_all": true }` (requires a valid session):

1. Invalidates all sessions and temporary links immediately.
2. Locks the login endpoint — no new sessions until the process restarts.
3. Closes all open terminal tabs.
4. Triggers graceful process shutdown.

## Threat Model

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
| PTY escape sequence injection | Any authenticated session can already write to the PTY — escape sequences are an in-scope capability, not a bypass. Unauthenticated users cannot reach the PTY. |
| Privilege escalation via shell | CodeWebway runs as the invoking user. The shell it spawns inherits the same OS privileges — no privilege boundary exists by design. Run as a low-privilege user to limit blast radius. |

## Secret Management

**Avoid passing credentials as raw CLI arguments in shared or multi-user environments.** Arguments passed via `--password` and `--pin` are visible to other users on the same machine via `ps aux` or `/proc/<pid>/cmdline` for the lifetime of the process.

Safer patterns:

```bash
# Read token from environment variable (not visible in ps on most systems)
export CODEWEBWAY_TOKEN=$(openssl rand -hex 16)
codewebway --password "$CODEWEBWAY_TOKEN" --pin 123456

# Or: let CodeWebway auto-generate the token (printed once at startup)
# and type the PIN interactively when prompted
codewebway -z
```

On Linux, you can additionally restrict `/proc/<pid>/cmdline` visibility with tools like `hidepid` on the `/proc` mount, or run CodeWebway under a dedicated user account that others cannot inspect.

## Credential Storage in Memory

Token and PIN are stored as plain `String` values in process memory for the lifetime of the process. They are **not hashed or salted** — this is by design, because constant-time equality comparison (which prevents timing attacks) requires both values to be in plaintext at comparison time. Hashing would break this property.

There is currently no explicit memory zeroing (`zeroize`) on process exit. An attacker with local memory access (e.g., `ptrace`, `/proc/<pid>/mem`, or a core dump) could extract the credentials. This is an acceptable risk for the intended single-operator personal-use case where the attacker would already need elevated OS access to perform such a read — at which point the machine itself is compromised regardless.

If your threat model includes local privilege escalation, run CodeWebway under a dedicated non-root user account with minimal OS permissions, and ensure core dumps are disabled for that account.

## Static Analysis

CodeQL static analysis runs automatically on every push to `main` and on every pull request via GitHub Actions. Results are visible in the [Security tab](https://github.com/iylmwysst/CodeWebway/security/code-scanning) of this repository.

## Reporting a Vulnerability

If you find a security vulnerability, **please do not open a public GitHub issue.**

Use [GitHub private security advisories](https://github.com/iylmwysst/CodeWebway/security/advisories/new) to report it privately. Include a description of the issue, reproduction steps, and any relevant environment details.

We aim to acknowledge reports within **48 hours** and to ship a fix as quickly as possible. Researchers will be credited in the release notes unless anonymity is requested.
