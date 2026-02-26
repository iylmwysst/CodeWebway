use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{
        ws::{Message, WebSocket},
        Json, Path as AxumPath, Query, State, WebSocketUpgrade,
    },
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, patch, post},
    Router,
};
use portable_pty::PtySize;
use rand::distributions::Alphanumeric;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;
use tower_http::compression::CompressionLayer;

use crate::assets::Assets;
use crate::session::{self, Session};

const MAX_FILE_PREVIEW_BYTES: usize = 256 * 1024;
const MAX_FILE_EDIT_BYTES: usize = 512 * 1024;

pub struct AppState {
    pub password: String,
    pub pin: Option<String>,
    pub failed_logins: Mutex<FailedLoginTracker>,
    pub sessions: Mutex<SessionStore>,
    pub access_locked: Mutex<bool>,
    pub terminals: Mutex<TerminalManager>,
    pub default_shell: String,
    pub root_dir: PathBuf,
    pub scrollback: usize,
    pub usage: Mutex<UsageTracker>,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    password: String,
    pin: Option<String>,
}

#[derive(Deserialize)]
pub struct LogoutRequest {
    revoke_all: Option<bool>,
}

#[derive(Deserialize)]
pub struct WsQuery {
    terminal_id: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateTerminalRequest {
    cwd: Option<String>,
    shell: Option<String>,
    title: Option<String>,
}

#[derive(Deserialize)]
pub struct FsQuery {
    path: Option<String>,
}

#[derive(Deserialize)]
pub struct SaveFileRequest {
    path: String,
    content: String,
}

#[derive(Deserialize)]
pub struct SaveFileDiffRequest {
    path: String,
    base_hash: String,
    start: usize,
    delete_count: usize,
    insert_text: String,
}

#[derive(Serialize, Clone)]
pub struct TerminalSummary {
    id: String,
    title: String,
    cwd: String,
    shell: String,
}

#[derive(Clone)]
struct TerminalEntry {
    summary: TerminalSummary,
    session: Session,
}

pub struct TerminalManager {
    entries: HashMap<String, TerminalEntry>,
    max_tabs: usize,
}

impl TerminalManager {
    pub fn new(max_tabs: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_tabs,
        }
    }

    fn make_terminal_id(&self) -> String {
        loop {
            let id: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(8)
                .map(char::from)
                .collect();
            if !self.entries.contains_key(&id) {
                return id;
            }
        }
    }

    pub fn create(
        &mut self,
        title: String,
        cwd: PathBuf,
        shell: String,
        scrollback: usize,
    ) -> anyhow::Result<TerminalSummary> {
        if self.entries.len() >= self.max_tabs {
            anyhow::bail!("Maximum number of terminal tabs reached");
        }
        let session = session::spawn_session(&shell, &cwd, scrollback)?;
        let id = self.make_terminal_id();
        let summary = TerminalSummary {
            id: id.clone(),
            title,
            cwd: cwd.display().to_string(),
            shell,
        };
        self.entries.insert(
            id,
            TerminalEntry {
                summary: summary.clone(),
                session,
            },
        );
        Ok(summary)
    }

    pub fn list(&self) -> Vec<TerminalSummary> {
        let mut out: Vec<TerminalSummary> = self
            .entries
            .values()
            .map(|entry| entry.summary.clone())
            .collect();
        out.sort_by(|a, b| a.title.cmp(&b.title).then_with(|| a.id.cmp(&b.id)));
        out
    }

    pub fn get_session(&self, id: &str) -> Option<Session> {
        self.entries.get(id).map(|entry| Arc::clone(&entry.session))
    }

    pub fn remove(&mut self, id: &str) -> bool {
        let Some(entry) = self.entries.remove(id) else {
            return false;
        };
        let _ = session::close_session(&entry.session);
        true
    }

    pub fn remove_all(&mut self) {
        let ids: Vec<String> = self.entries.keys().cloned().collect();
        for id in ids {
            let _ = self.remove(&id);
        }
    }
}

#[derive(Serialize)]
struct FsTreeResponse {
    path: String,
    entries: Vec<FsEntry>,
}

#[derive(Serialize)]
struct FsEntry {
    name: String,
    path: String,
    is_dir: bool,
    size_bytes: Option<u64>,
}

#[derive(Serialize)]
struct FsFileResponse {
    path: String,
    content: String,
    truncated: bool,
    size_bytes: usize,
    hash: String,
}

#[derive(Serialize)]
struct SaveFileResponse {
    hash: String,
    size_bytes: usize,
}

#[derive(Serialize)]
struct UsageResponse {
    today_rx_bytes: u64,
    today_tx_bytes: u64,
    today_total_bytes: u64,
    session_rx_bytes: u64,
    session_tx_bytes: u64,
    session_total_bytes: u64,
}

#[derive(Clone, Copy)]
struct UsageSnapshot {
    today_rx_bytes: u64,
    today_tx_bytes: u64,
    session_rx_bytes: u64,
    session_tx_bytes: u64,
}

pub struct UsageTracker {
    current_utc_day: u64,
    today_rx_bytes: u64,
    today_tx_bytes: u64,
    session_rx_bytes: u64,
    session_tx_bytes: u64,
}

impl UsageTracker {
    pub fn new() -> Self {
        Self {
            current_utc_day: utc_day_index(),
            today_rx_bytes: 0,
            today_tx_bytes: 0,
            session_rx_bytes: 0,
            session_tx_bytes: 0,
        }
    }

    fn rotate_day_if_needed(&mut self) {
        let now_day = utc_day_index();
        if now_day != self.current_utc_day {
            self.current_utc_day = now_day;
            self.today_rx_bytes = 0;
            self.today_tx_bytes = 0;
        }
    }

    pub fn add_rx(&mut self, bytes: u64) {
        self.rotate_day_if_needed();
        self.today_rx_bytes = self.today_rx_bytes.saturating_add(bytes);
        self.session_rx_bytes = self.session_rx_bytes.saturating_add(bytes);
    }

    pub fn add_tx(&mut self, bytes: u64) {
        self.rotate_day_if_needed();
        self.today_tx_bytes = self.today_tx_bytes.saturating_add(bytes);
        self.session_tx_bytes = self.session_tx_bytes.saturating_add(bytes);
    }

    fn snapshot(&mut self) -> UsageSnapshot {
        self.rotate_day_if_needed();
        UsageSnapshot {
            today_rx_bytes: self.today_rx_bytes,
            today_tx_bytes: self.today_tx_bytes,
            session_rx_bytes: self.session_rx_bytes,
            session_tx_bytes: self.session_tx_bytes,
        }
    }
}

pub struct FailedLoginTracker {
    by_client: HashMap<String, VecDeque<Instant>>,
    max_attempts: usize,
    window: Duration,
}

impl FailedLoginTracker {
    pub fn new(max_attempts: usize, window: Duration) -> Self {
        Self {
            by_client: HashMap::new(),
            max_attempts,
            window,
        }
    }

    fn purge_expired(&mut self, client: &str, now: Instant) {
        let Some(queue) = self.by_client.get_mut(client) else {
            return;
        };
        while let Some(first) = queue.front() {
            if now.duration_since(*first) >= self.window {
                queue.pop_front();
            } else {
                break;
            }
        }
        if queue.is_empty() {
            self.by_client.remove(client);
        }
    }

    pub fn retry_after(&mut self, client: &str, now: Instant) -> Option<Duration> {
        self.purge_expired(client, now);
        let queue = self.by_client.get(client)?;
        if queue.len() < self.max_attempts {
            return None;
        }
        let earliest = *queue.front()?;
        Some(self.window.saturating_sub(now.duration_since(earliest)))
    }

    pub fn record_failure(&mut self, client: &str, now: Instant) {
        self.purge_expired(client, now);
        let queue = self.by_client.entry(client.to_string()).or_default();
        queue.push_back(now);
    }

    pub fn clear(&mut self, client: &str) {
        self.by_client.remove(client);
    }
}

pub struct SessionStore {
    by_token: HashMap<String, Instant>,
    ttl: Duration,
}

impl SessionStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            by_token: HashMap::new(),
            ttl,
        }
    }

    fn purge_expired(&mut self, now: Instant) {
        self.by_token.retain(|_, expires_at| *expires_at > now);
    }

    pub fn create(&mut self, now: Instant) -> String {
        self.purge_expired(now);
        let token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(48)
            .map(char::from)
            .collect();
        self.by_token.insert(token.clone(), now + self.ttl);
        token
    }

    pub fn is_valid(&mut self, token: &str, now: Instant) -> bool {
        self.purge_expired(now);
        self.by_token.contains_key(token)
    }

    pub fn revoke(&mut self, token: &str) {
        self.by_token.remove(token);
    }

    pub fn revoke_all(&mut self) {
        self.by_token.clear();
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/auth/login", post(auth_login))
        .route("/auth/logout", post(auth_logout))
        .route("/auth/session", get(auth_session))
        .route("/api/terminals", get(list_terminals).post(create_terminal))
        .route("/api/terminals/:id", delete(delete_terminal))
        .route("/api/fs/tree", get(fs_tree))
        .route("/api/fs/file", get(fs_file).put(save_file))
        .route("/api/fs/file/diff", patch(save_file_diff))
        .route("/api/usage", get(usage_stats))
        .route("/ws", get(ws_handler))
        .with_state(Arc::new(state))
        .layer(CompressionLayer::new())
}

async fn serve_index() -> impl IntoResponse {
    let html = Assets::get("index.html").unwrap();
    Html(std::str::from_utf8(html.data.as_ref()).unwrap().to_string())
}

async fn auth_login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Response {
    if *state.access_locked.lock().unwrap() {
        return (
            StatusCode::LOCKED,
            "Access is locked. Restart rust-webtty to enable login again.",
        )
            .into_response();
    }

    let now = Instant::now();
    let client = client_key_from_headers(&headers);
    let mut limiter = state.failed_logins.lock().unwrap();

    if let Some(wait) = limiter.retry_after(&client, now) {
        let wait_seconds = wait.as_secs().max(1).to_string();
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, wait_seconds)],
            "Too many failed login attempts. Try again later.",
        )
            .into_response();
    }

    let password_ok = check_token(&req.password, &state.password);
    let pin_ok = verify_pin(req.pin.as_deref(), state.pin.as_deref());

    if password_ok && pin_ok {
        limiter.clear(&client);
        let mut sessions = state.sessions.lock().unwrap();
        let session_token = sessions.create(now);
        let set_cookie = format!(
            "webtty_session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800",
            session_token
        );
        return (StatusCode::OK, [(header::SET_COOKIE, set_cookie)], "OK").into_response();
    }
    limiter.record_failure(&client, now);

    if let Some(wait) = limiter.retry_after(&client, now) {
        let wait_seconds = wait.as_secs().max(1).to_string();
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, wait_seconds)],
            "Too many failed login attempts. Try again later.",
        )
            .into_response();
    }
    (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
}

async fn auth_session(headers: HeaderMap, State(state): State<Arc<AppState>>) -> Response {
    if has_valid_session_cookie(&headers, &state).is_some() {
        return (StatusCode::OK, "OK").into_response();
    }
    (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
}

async fn auth_logout(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<LogoutRequest>,
) -> Response {
    let token = session_token_from_headers(&headers);
    let revoke_all = req.revoke_all.unwrap_or(false);

    let mut sessions = state.sessions.lock().unwrap();
    if let Some(current) = token {
        if revoke_all {
            if !sessions.is_valid(&current, Instant::now()) {
                return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
            }
            sessions.revoke_all();
            *state.access_locked.lock().unwrap() = true;
            state.terminals.lock().unwrap().remove_all();
        } else {
            sessions.revoke(&current);
        }
    } else if revoke_all {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    (
        StatusCode::OK,
        [(
            header::SET_COOKIE,
            "webtty_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".to_string(),
        )],
        "OK",
    )
        .into_response()
}

async fn list_terminals(headers: HeaderMap, State(state): State<Arc<AppState>>) -> Response {
    if has_valid_session_cookie(&headers, &state).is_none() {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }
    let items = state.terminals.lock().unwrap().list();
    Json(items).into_response()
}

async fn create_terminal(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateTerminalRequest>,
) -> Response {
    if has_valid_session_cookie(&headers, &state).is_none() {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    let cwd = match resolve_user_path(&state.root_dir, req.cwd.as_deref()) {
        Ok(path) => path,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };
    if !cwd.is_dir() {
        return (StatusCode::BAD_REQUEST, "cwd must be an existing directory").into_response();
    }

    let shell = req.shell.unwrap_or_else(|| state.default_shell.clone());
    let title = req.title.unwrap_or_else(|| {
        cwd.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("terminal")
            .to_string()
    });

    let created = match state
        .terminals
        .lock()
        .unwrap()
        .create(title, cwd, shell, state.scrollback)
    {
        Ok(summary) => summary,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };

    (StatusCode::CREATED, Json(created)).into_response()
}

async fn delete_terminal(
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    State(state): State<Arc<AppState>>,
) -> Response {
    if has_valid_session_cookie(&headers, &state).is_none() {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }
    let removed = state.terminals.lock().unwrap().remove(&id);
    if removed {
        return StatusCode::NO_CONTENT.into_response();
    }
    (StatusCode::NOT_FOUND, "Terminal not found").into_response()
}

async fn fs_tree(
    headers: HeaderMap,
    Query(query): Query<FsQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    if has_valid_session_cookie(&headers, &state).is_none() {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    let path = match resolve_user_path(&state.root_dir, query.path.as_deref()) {
        Ok(path) => path,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };
    if !path.is_dir() {
        return (StatusCode::BAD_REQUEST, "path must be a directory").into_response();
    }

    let mut entries: Vec<FsEntry> = match std::fs::read_dir(&path) {
        Ok(read_dir) => read_dir
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let file_type = entry.file_type().ok()?;
                let name = entry.file_name().into_string().ok()?;
                if name.starts_with('.') {
                    return None;
                }
                let abs = entry.path();
                let rel = abs
                    .strip_prefix(&state.root_dir)
                    .ok()?
                    .to_string_lossy()
                    .to_string();
                Some(FsEntry {
                    name,
                    path: rel,
                    is_dir: file_type.is_dir(),
                    size_bytes: if file_type.is_file() {
                        entry.metadata().ok().map(|meta| meta.len())
                    } else {
                        None
                    },
                })
            })
            .collect(),
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to read directory",
            )
                .into_response()
        }
    };

    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));

    let rel_path = path
        .strip_prefix(&state.root_dir)
        .ok()
        .map(|p| p.to_string_lossy().to_string())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| ".".to_string());

    let payload = FsTreeResponse {
        path: rel_path,
        entries,
    };
    count_tx_json(&state, &payload);
    Json(payload).into_response()
}

async fn fs_file(
    headers: HeaderMap,
    Query(query): Query<FsQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    if has_valid_session_cookie(&headers, &state).is_none() {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    let path = match resolve_user_path(&state.root_dir, query.path.as_deref()) {
        Ok(path) => path,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };

    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::BAD_REQUEST, "unable to read file").into_response(),
    };

    let truncated = bytes.len() > MAX_FILE_PREVIEW_BYTES;
    let slice = if truncated {
        &bytes[..MAX_FILE_PREVIEW_BYTES]
    } else {
        &bytes[..]
    };
    let content = String::from_utf8_lossy(slice).to_string();
    let hash = hash_bytes_hex(&bytes);

    let rel_path = path
        .strip_prefix(&state.root_dir)
        .ok()
        .map(|p| p.to_string_lossy().to_string())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| ".".to_string());

    let payload = FsFileResponse {
        path: rel_path,
        content,
        truncated,
        size_bytes: bytes.len(),
        hash,
    };
    count_tx_json(&state, &payload);
    Json(payload).into_response()
}

async fn save_file(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<SaveFileRequest>,
) -> Response {
    if has_valid_session_cookie(&headers, &state).is_none() {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }
    count_rx(&state, req.content.len() as u64);

    if req.content.len() > MAX_FILE_EDIT_BYTES {
        return (
            StatusCode::BAD_REQUEST,
            "file is too large for in-browser editor",
        )
            .into_response();
    }

    let path = match resolve_user_path(&state.root_dir, Some(&req.path)) {
        Ok(path) => path,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };
    if path.is_dir() {
        return (StatusCode::BAD_REQUEST, "path must be a file").into_response();
    }

    match std::fs::write(&path, req.content.as_bytes()) {
        Ok(_) => {
            let payload = SaveFileResponse {
                hash: hash_bytes_hex(req.content.as_bytes()),
                size_bytes: req.content.len(),
            };
            count_tx_json(&state, &payload);
            (StatusCode::OK, Json(payload)).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "unable to save file").into_response(),
    }
}

async fn save_file_diff(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<SaveFileDiffRequest>,
) -> Response {
    if has_valid_session_cookie(&headers, &state).is_none() {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }
    count_rx(&state, req.insert_text.len() as u64);

    let path = match resolve_user_path(&state.root_dir, Some(&req.path)) {
        Ok(path) => path,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };
    if path.is_dir() {
        return (StatusCode::BAD_REQUEST, "path must be a file").into_response();
    }

    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::BAD_REQUEST, "unable to read file").into_response(),
    };
    if bytes.len() > MAX_FILE_EDIT_BYTES {
        return (
            StatusCode::BAD_REQUEST,
            "file is too large for in-browser editor",
        )
            .into_response();
    }

    let current_hash = hash_bytes_hex(&bytes);
    if current_hash != req.base_hash {
        return (
            StatusCode::CONFLICT,
            "file changed on disk. reload before saving",
        )
            .into_response();
    }

    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => return (StatusCode::BAD_REQUEST, "file is not valid UTF-8").into_response(),
    };
    let chars: Vec<char> = text.chars().collect();
    if req.start > chars.len() || req.start.saturating_add(req.delete_count) > chars.len() {
        return (StatusCode::BAD_REQUEST, "invalid diff range").into_response();
    }

    let mut out = String::new();
    out.extend(chars[..req.start].iter().copied());
    out.push_str(&req.insert_text);
    out.extend(chars[req.start + req.delete_count..].iter().copied());

    match std::fs::write(&path, out.as_bytes()) {
        Ok(_) => {
            let payload = SaveFileResponse {
                hash: hash_bytes_hex(out.as_bytes()),
                size_bytes: out.len(),
            };
            count_tx_json(&state, &payload);
            (StatusCode::OK, Json(payload)).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "unable to save file").into_response(),
    }
}

async fn usage_stats(headers: HeaderMap, State(state): State<Arc<AppState>>) -> Response {
    if has_valid_session_cookie(&headers, &state).is_none() {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }
    let snapshot = state.usage.lock().unwrap().snapshot();
    let payload = UsageResponse {
        today_rx_bytes: snapshot.today_rx_bytes,
        today_tx_bytes: snapshot.today_tx_bytes,
        today_total_bytes: snapshot
            .today_rx_bytes
            .saturating_add(snapshot.today_tx_bytes),
        session_rx_bytes: snapshot.session_rx_bytes,
        session_tx_bytes: snapshot.session_tx_bytes,
        session_total_bytes: snapshot
            .session_rx_bytes
            .saturating_add(snapshot.session_tx_bytes),
    };
    Json(payload).into_response()
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    Query(query): Query<WsQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    if !is_allowed_origin(&headers) {
        return (StatusCode::FORBIDDEN, "Forbidden origin").into_response();
    }
    let Some(session_token) = has_valid_session_cookie(&headers, &state) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };

    let Some(terminal_id) = query.terminal_id else {
        return (StatusCode::BAD_REQUEST, "terminal_id is required").into_response();
    };
    let terminal_session = {
        let manager = state.terminals.lock().unwrap();
        manager.get_session(&terminal_id)
    };
    let Some(terminal_session) = terminal_session else {
        return (StatusCode::NOT_FOUND, "Terminal not found").into_response();
    };

    ws.on_upgrade(move |socket| handle_socket(socket, state, session_token, terminal_session))
}

async fn handle_socket(
    mut socket: WebSocket,
    state: Arc<AppState>,
    session_token: String,
    terminal: Session,
) {
    let (scrollback, mut rx) = {
        let s = terminal.lock().unwrap();
        (s.scrollback.snapshot(), s.tx.subscribe())
    };
    if !scrollback.is_empty() {
        count_tx(&state, scrollback.len() as u64);
        let _ = socket.send(Message::Binary(scrollback.into())).await;
    }

    let mut session_tick = tokio::time::interval(Duration::from_secs(15));

    loop {
        tokio::select! {
            _ = session_tick.tick() => {
                if !is_session_token_valid(&state, &session_token) {
                    count_tx(&state, 26);
                    let _ = socket
                        .send(Message::Text("{\"type\":\"session_expired\"}".into()))
                        .await;
                    let _ = socket.close().await;
                    break;
                }
            }
            result = rx.recv() => {
                match result {
                    Ok(data) => {
                        count_tx(&state, data.len() as u64);
                        if socket.send(Message::Binary(data.to_vec().into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
            result = socket.recv() => {
                match result {
                    Some(Ok(Message::Binary(data))) => {
                        count_rx(&state, data.len() as u64);
                        let mut s = terminal.lock().unwrap();
                        let _ = s.pty_writer.write_all(&data);
                    }
                    Some(Ok(Message::Text(text))) => {
                        count_rx(&state, text.len() as u64);
                        if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&text) {
                            if msg["type"] == "resize" {
                                let cols = msg["cols"].as_u64().unwrap_or(80) as u16;
                                let rows = msg["rows"].as_u64().unwrap_or(24) as u16;
                                let s = terminal.lock().unwrap();
                                let _ = s.pty_master.resize(PtySize {
                                    rows,
                                    cols,
                                    pixel_width: 0,
                                    pixel_height: 0,
                                });
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }
}

pub fn check_token(token: &str, password: &str) -> bool {
    if token.len() != password.len() {
        return false;
    }
    token
        .as_bytes()
        .iter()
        .zip(password.as_bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

fn has_valid_session_cookie(headers: &HeaderMap, state: &Arc<AppState>) -> Option<String> {
    let session = session_token_from_headers(headers)?;
    if !is_session_token_valid(state, &session) {
        return None;
    }
    Some(session)
}

fn session_token_from_headers(headers: &HeaderMap) -> Option<String> {
    let raw_cookie = match headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
    {
        Some(value) => value,
        None => return None,
    };
    cookie_value(raw_cookie, "webtty_session").map(|value| value.to_string())
}

fn is_session_token_valid(state: &Arc<AppState>, session: &str) -> bool {
    let mut sessions = state.sessions.lock().unwrap();
    sessions.is_valid(session, Instant::now())
}

fn cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    for part in cookie_header.split(';') {
        let trimmed = part.trim();
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        if key == name {
            return Some(value);
        }
    }
    None
}

fn client_key_from_headers(headers: &HeaderMap) -> String {
    if let Some(forwarded) = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
    {
        if let Some(client) = forwarded.split(',').next() {
            let trimmed = client.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    if let Some(real_ip) = headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
    {
        let trimmed = real_ip.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "unknown".to_string()
}

fn is_allowed_origin(headers: &HeaderMap) -> bool {
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };

    if let Some(proto) = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
    {
        let expected = format!("{proto}://{host}");
        return origin == expected;
    }

    origin == format!("http://{host}") || origin == format!("https://{host}")
}

fn verify_pin(input: Option<&str>, expected: Option<&str>) -> bool {
    match expected {
        Some(expected_pin) => input
            .map(|candidate| check_token(candidate, expected_pin))
            .unwrap_or(false),
        None => true,
    }
}

fn utc_day_index() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(dur) => dur.as_secs() / 86_400,
        Err(_) => 0,
    }
}

fn count_rx(state: &Arc<AppState>, bytes: u64) {
    state.usage.lock().unwrap().add_rx(bytes);
}

fn count_tx(state: &Arc<AppState>, bytes: u64) {
    state.usage.lock().unwrap().add_tx(bytes);
}

fn count_tx_json<T: Serialize>(state: &Arc<AppState>, payload: &T) {
    if let Ok(buf) = serde_json::to_vec(payload) {
        count_tx(state, buf.len() as u64);
    }
}

fn hash_bytes_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn resolve_user_path(root_dir: &Path, requested: Option<&str>) -> Result<PathBuf, &'static str> {
    let relative = requested.unwrap_or(".");
    let rel_path = Path::new(relative);
    if rel_path.is_absolute() {
        return Err("absolute paths are not allowed");
    }
    if rel_path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("parent path segments are not allowed");
    }

    let abs = root_dir.join(rel_path);
    if !abs.exists() {
        return Err("path does not exist");
    }

    let canonical = abs.canonicalize().map_err(|_| "invalid path")?;
    if !canonical.starts_with(root_dir) {
        return Err("path is outside allowed root");
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correct_token() {
        assert!(check_token("secret", "secret"));
    }

    #[test]
    fn test_wrong_token() {
        assert!(!check_token("wrong", "secret"));
    }

    #[test]
    fn test_empty_token() {
        assert!(!check_token("", "secret"));
    }

    #[test]
    fn test_token_length_mismatch() {
        assert!(!check_token("sec", "secret"));
    }

    #[test]
    fn test_cookie_value_found() {
        let value = cookie_value("foo=1; webtty_session=abc123; bar=2", "webtty_session");
        assert_eq!(value, Some("abc123"));
    }

    #[test]
    fn test_cookie_value_missing() {
        let value = cookie_value("foo=1; bar=2", "webtty_session");
        assert_eq!(value, None);
    }

    #[test]
    fn test_failed_login_tracker_blocks_after_limit() {
        let mut tracker = FailedLoginTracker::new(3, Duration::from_secs(300));
        let now = Instant::now();
        tracker.record_failure("1.2.3.4", now);
        tracker.record_failure("1.2.3.4", now);
        assert_eq!(tracker.retry_after("1.2.3.4", now), None);

        tracker.record_failure("1.2.3.4", now);
        assert!(tracker.retry_after("1.2.3.4", now).is_some());
    }

    #[test]
    fn test_client_key_from_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.8, 10.0.0.1".parse().unwrap());
        assert_eq!(client_key_from_headers(&headers), "203.0.113.8");
    }

    #[test]
    fn test_origin_allowed_with_forwarded_proto() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "https://example.com".parse().unwrap());
        headers.insert(header::HOST, "example.com".parse().unwrap());
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(is_allowed_origin(&headers));
    }

    #[test]
    fn test_origin_rejected_on_mismatch() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
        headers.insert(header::HOST, "example.com".parse().unwrap());
        assert!(!is_allowed_origin(&headers));
    }

    #[test]
    fn test_session_store_expiry() {
        let mut store = SessionStore::new(Duration::from_secs(10));
        let now = Instant::now();
        let token = store.create(now);
        assert!(store.is_valid(&token, now + Duration::from_secs(9)));
        assert!(!store.is_valid(&token, now + Duration::from_secs(10)));
    }

    #[test]
    fn test_session_token_from_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "foo=1; webtty_session=abc123".parse().unwrap(),
        );
        assert_eq!(
            session_token_from_headers(&headers),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn test_verify_pin_when_required() {
        assert!(verify_pin(Some("4321"), Some("4321")));
        assert!(!verify_pin(Some("1111"), Some("4321")));
        assert!(!verify_pin(None, Some("4321")));
    }

    #[test]
    fn test_verify_pin_when_not_required() {
        assert!(verify_pin(None, None));
        assert!(verify_pin(Some("anything"), None));
    }
}
