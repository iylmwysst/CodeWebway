# Terminal-Only Flag Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `--terminal-only` runtime flag that drops `/api/fs/*` routes and hides the Files panel in the browser UI so the terminal takes full width.

**Architecture:** Single binary; `terminal_only: bool` propagated from `Config` → `AppState`. Router skips the three fs routes conditionally. A new unauthenticated `/api/capabilities` endpoint lets the frontend apply `body.terminal-only` CSS class at bootstrap time.

**Tech Stack:** Rust 2021, Axum 0.7, clap 4 (derive), serde_json, vanilla JS in `assets/index.html`

---

### Task 1: Add `--terminal-only` flag to Config

**Files:**
- Modify: `src/config.rs`

**Step 1: Write the failing test**

Add to the existing `#[cfg(test)] mod tests` block at the bottom of `src/config.rs`:

```rust
#[test]
fn test_terminal_only_default() {
    let cfg = Config::parse_from(["codewebway"]);
    assert!(!cfg.terminal_only);
}

#[test]
fn test_terminal_only_flag() {
    let cfg = Config::parse_from(["codewebway", "--terminal-only"]);
    assert!(cfg.terminal_only);
}
```

**Step 2: Run tests to confirm they fail**

```bash
cargo test test_terminal_only --lib 2>&1 | tail -20
```
Expected: `error[E0609]: no field 'terminal_only'`

**Step 3: Add the field to Config**

In `src/config.rs`, add after the `max_connections` field (around line 48):

```rust
/// Terminal-only mode: disable file explorer and editor
#[arg(long)]
pub terminal_only: bool,
```

**Step 4: Run tests to confirm they pass**

```bash
cargo test test_terminal_only --lib 2>&1 | tail -10
```
Expected: `test test_terminal_only_default ... ok` and `test test_terminal_only_flag ... ok`

**Step 5: Commit**

```bash
git add src/config.rs
git commit -m "feat: add --terminal-only flag to Config"
```

---

### Task 2: Add `terminal_only` to AppState and wire from main

**Files:**
- Modify: `src/server.rs` (AppState struct only)
- Modify: `src/main.rs` (AppState construction)

**Step 1: Add field to AppState**

In `src/server.rs`, add to the `AppState` struct after `auto_shutdown_disabled`:

```rust
pub terminal_only: bool,
```

**Step 2: Wire from main**

In `src/main.rs`, in the `AppState { ... }` literal (around line 222), add after `auto_shutdown_disabled`:

```rust
terminal_only: cfg.terminal_only,
```

**Step 3: Verify it compiles**

```bash
cargo build 2>&1 | tail -20
```
Expected: compiles with no errors (may have unused-field warning — fine, will be used in Task 3).

**Step 4: Commit**

```bash
git add src/server.rs src/main.rs
git commit -m "feat: propagate terminal_only into AppState"
```

---

### Task 3: Conditional fs routes + `/api/capabilities` endpoint

**Files:**
- Modify: `src/server.rs`

**Step 1: Write the failing tests**

Add to the existing `#[cfg(test)] mod tests` in `src/server.rs` (or create one if absent):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt; // for `.oneshot()`
    use std::time::{Duration, Instant};

    fn make_state(terminal_only: bool) -> Arc<AppState> {
        Arc::new(AppState {
            password: "token".to_string(),
            pin: None,
            failed_logins: Mutex::new(FailedLoginTracker::new(3, Duration::from_secs(300))),
            sessions: Mutex::new(SessionStore::new(
                Duration::from_secs(1800),
                Duration::from_secs(43200),
            )),
            access_locked: Mutex::new(false),
            terminals: Mutex::new(TerminalManager::new(8)),
            default_shell: "/bin/sh".to_string(),
            root_dir: std::env::temp_dir(),
            scrollback: 131072,
            usage: Mutex::new(UsageTracker::new()),
            ws_connections: Mutex::new(0),
            max_ws_connections: 8,
            idle_timeout: Duration::from_secs(1800),
            shutdown_grace: Duration::from_secs(10800),
            warning_window: Duration::from_secs(120),
            shutdown_deadline: Mutex::new(Instant::now() + Duration::from_secs(10800)),
            shutdown_tx: tokio::sync::mpsc::unbounded_channel::<()>().0,
            temp_links: Mutex::new(TempLinkStore::new()),
            temp_grants: Mutex::new(std::collections::HashMap::new()),
            temp_link_signing_key: "signingkey123456789012345678901234567890123456".to_string(),
            auto_shutdown_disabled: false,
            terminal_only,
        })
    }

    #[tokio::test]
    async fn test_capabilities_terminal_only_false() {
        let app = router(make_state(false));
        let req = Request::builder()
            .uri("/api/capabilities")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["terminal_only"], false);
    }

    #[tokio::test]
    async fn test_capabilities_terminal_only_true() {
        let app = router(make_state(true));
        let req = Request::builder()
            .uri("/api/capabilities")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["terminal_only"], true);
    }

    #[tokio::test]
    async fn test_fs_tree_absent_in_terminal_only() {
        let app = router(make_state(true));
        let req = Request::builder()
            .uri("/api/fs/tree")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_fs_tree_present_in_normal_mode() {
        let app = router(make_state(false));
        let req = Request::builder()
            .uri("/api/fs/tree")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        // Not 404 — returns 401 Unauthorized (no session cookie)
        assert_ne!(res.status(), StatusCode::NOT_FOUND);
    }
}
```

**Step 2: Add `tower` as test dependency and run to confirm fail**

Check `Cargo.toml` — if `tower` is not present under `[dev-dependencies]`, add:
```toml
[dev-dependencies]
tower = "0.4"
```

Then:
```bash
cargo test test_capabilities test_fs_tree --lib 2>&1 | tail -20
```
Expected: compile error — `capabilities` handler does not exist yet.

**Step 3: Add the capabilities handler**

In `src/server.rs`, add after the `serve_favicon` function (around line 716):

```rust
#[derive(Serialize)]
struct CapabilitiesResponse {
    terminal_only: bool,
}

async fn capabilities(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(CapabilitiesResponse {
        terminal_only: state.terminal_only,
    })
}
```

**Step 4: Register route and make fs routes conditional**

Replace the `router()` function body with:

```rust
pub fn router(state: Arc<AppState>) -> Router {
    let terminal_only = state.terminal_only;
    let mut r = Router::new()
        .route("/", get(serve_index))
        .route("/favicon.svg", get(serve_favicon))
        .route("/api/capabilities", get(capabilities))
        .route("/auth/login", post(auth_login))
        .route("/auth/logout", post(auth_logout))
        .route("/auth/session", get(auth_session))
        .route("/auth/session/status", get(auth_session_status))
        .route("/auth/extend", post(auth_extend))
        .route(
            "/auth/temp-links",
            get(list_temp_links).post(create_temp_link),
        )
        .route("/auth/temp-links/:id", delete(revoke_temp_link))
        .route("/auth/public-status", get(auth_public_status))
        .route("/t/:token", get(redeem_temp_link))
        .route("/api/terminals", get(list_terminals).post(create_terminal))
        .route(
            "/api/terminals/:id",
            delete(delete_terminal).patch(rename_terminal),
        )
        .route("/api/usage", get(usage_stats))
        .route("/ws", get(ws_handler));

    if !terminal_only {
        r = r
            .route("/api/fs/tree", get(fs_tree))
            .route("/api/fs/file", get(fs_file).put(save_file))
            .route("/api/fs/file/diff", patch(save_file_diff));
    }

    r.with_state(state).layer(CompressionLayer::new())
}
```

**Step 5: Run tests to confirm they pass**

```bash
cargo test test_capabilities test_fs_tree --lib 2>&1 | tail -20
```
Expected: 4 tests pass.

**Step 6: Run all tests**

```bash
cargo test 2>&1 | tail -10
```
Expected: all pass.

**Step 7: Commit**

```bash
git add src/server.rs Cargo.toml
git commit -m "feat: add capabilities endpoint and conditional fs routes"
```

---

### Task 4: Frontend — CSS + capability check in bootstrapWorkspace

**Files:**
- Modify: `assets/index.html`

**Step 1: Add CSS rules**

Find the CSS block for `#files` (around line 100):
```css
#files {
  width: 34%;
```

Directly after the closing `}` of the `#terms` rule (find `#terms {`), add these two lines in the `<style>` block:

```css
body.terminal-only #files { display: none; }
body.terminal-only #terms  { flex: 1; }
```

**Step 2: Add capability fetch to bootstrapWorkspace**

Find `bootstrapWorkspace()` (around line 1456):

```js
async function bootstrapWorkspace() {
  initTerminal();
  login.style.display = 'none';
  app.style.display = 'flex';
```

Add a capabilities fetch right after `app.style.display = 'flex';`:

```js
  try {
    const caps = await api('/api/capabilities');
    if (caps && caps.terminal_only) {
      document.body.classList.add('terminal-only');
    }
  } catch (_) { /* non-fatal */ }
```

**Step 3: Manual smoke test**

```bash
cargo run -- --pin 123456 --terminal-only
```

Open `http://localhost:8080`, login → verify Files panel is gone and terminal fills the full width.

Then without the flag:
```bash
cargo run -- --pin 123456
```
Login → verify Files panel is still present.

**Step 4: Commit**

```bash
git add assets/index.html
git commit -m "ux: hide files panel in terminal-only mode"
```

---

### Task 5: Bump version and release

**Files:**
- Modify: `Cargo.toml`

**Step 1: Bump version**

In `Cargo.toml`, change:
```toml
version = "0.3.24"
```
to:
```toml
version = "0.3.25"
```

**Step 2: Run full checks**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
```
Expected: all pass, no warnings.

**Step 3: Commit and tag**

```bash
git add Cargo.toml
git commit -m "build: bump version to 0.3.25"
git tag -a v0.3.25 -m "v0.3.25"
```

**Step 4: Build macOS release binary**

```bash
cargo build --release
cp target/release/codewebway target/release/codewebway-x86_64-apple-darwin
```

**Step 5: Push and create GitHub release**

```bash
git push origin main
git push origin v0.3.25
gh release create v0.3.25 --title "v0.3.25" --generate-notes
```

**Step 6: Upload macOS binary**

```bash
gh release upload v0.3.25 target/release/codewebway-x86_64-apple-darwin --clobber
```

**Step 7: Verify**

```bash
gh release view v0.3.25 --json assets,url
```
Expected: asset `codewebway-x86_64-apple-darwin` listed.
