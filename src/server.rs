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
    response::{Html, IntoResponse, Redirect, Response},
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
const MAX_ACTIVE_TEMP_LINKS: usize = 2;
const DEFAULT_TEMP_LINK_TTL_MINUTES: u64 = 15;
const TEMP_LINK_GRACE_SECS: u64 = 120;
const WS_HEARTBEAT_PAYLOAD: &str = "{\"type\":\"heartbeat\"}";

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
    pub ws_connections: Mutex<usize>,
    pub max_ws_connections: usize,
    pub idle_timeout: Duration,
    pub shutdown_grace: Duration,
    pub warning_window: Duration,
    pub shutdown_deadline: Mutex<Instant>,
    pub shutdown_tx: tokio::sync::mpsc::UnboundedSender<()>,
    pub temp_links: Mutex<TempLinkStore>,
    pub temp_grants: Mutex<HashMap<String, TempSessionGrant>>,
    pub temp_link_signing_key: String,
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
pub struct ExtendSessionRequest {
    pin: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateTempLinkRequest {
    ttl_minutes: Option<u64>,
    scope: Option<String>,
    one_time: Option<bool>,
    max_uses: Option<u32>,
    bound_terminal_id: Option<String>,
}

#[derive(Deserialize)]
pub struct WsQuery {
    terminal_id: Option<String>,
    skip_scrollback: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateTerminalRequest {
    cwd: Option<String>,
    shell: Option<String>,
    title: Option<String>,
}

#[derive(Deserialize)]
pub struct RenameTerminalRequest {
    title: String,
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

    pub fn rename(&mut self, id: &str, title: String) -> Option<TerminalSummary> {
        let entry = self.entries.get_mut(id)?;
        entry.summary.title = title;
        Some(entry.summary.clone())
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

#[derive(Serialize)]
struct SessionStatusResponse {
    remaining_idle_secs: u64,
    remaining_absolute_secs: u64,
    warning_window_secs: u64,
    read_only: bool,
    bound_terminal_id: Option<String>,
    temp_link_id: Option<String>,
}

#[derive(Serialize)]
struct PublicStatusResponse {
    shutdown_remaining_secs: u64,
    access_locked: bool,
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TempLinkScope {
    ReadOnly,
    Interactive,
}

impl TempLinkScope {
    pub fn from_input(value: &str) -> Option<Self> {
        match value {
            "read-only" => Some(Self::ReadOnly),
            "interactive" => Some(Self::Interactive),
            _ => None,
        }
    }
}

#[derive(Clone)]
struct TempLinkRecord {
    id: String,
    created_at_unix: u64,
    expires_at_unix: u64,
    revoked_at_unix: Option<u64>,
    max_uses: u32,
    used_count: u32,
    scope: TempLinkScope,
    bound_terminal_id: Option<String>,
    created_by_session: String,
}

#[derive(Clone)]
pub struct TempSessionGrant {
    read_only: bool,
    bound_terminal_id: Option<String>,
    source_link_id: String,
}

#[derive(Serialize)]
struct TempLinkSummary {
    id: String,
    created_at_unix: u64,
    expires_at_unix: u64,
    remaining_secs: u64,
    max_uses: u32,
    used_count: u32,
    scope: TempLinkScope,
    bound_terminal_id: Option<String>,
    created_by_session: String,
}

#[derive(Serialize)]
pub struct TempLinkCreateResponse {
    pub id: String,
    pub url: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub remaining_secs: u64,
    pub max_uses: u32,
    pub scope: TempLinkScope,
    pub bound_terminal_id: Option<String>,
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
    by_token: HashMap<String, SessionRecord>,
    idle_timeout: Duration,
    absolute_timeout: Duration,
}

#[derive(Clone, Copy)]
struct SessionRecord {
    created_at: Instant,
    last_activity_at: Instant,
}

pub struct TempLinkStore {
    by_id: HashMap<String, TempLinkRecord>,
}

impl TempLinkStore {
    pub fn new() -> Self {
        Self {
            by_id: HashMap::new(),
        }
    }

    fn make_id(&self) -> String {
        loop {
            let id: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(10)
                .map(char::from)
                .collect();
            if !self.by_id.contains_key(&id) {
                return id;
            }
        }
    }

    fn purge_stale(&mut self, now_unix: u64) {
        self.by_id.retain(|_, record| {
            record.revoked_at_unix.is_none()
                && record.used_count < record.max_uses
                && now_unix < record.expires_at_unix
        });
    }

    fn active_count(&mut self, now_unix: u64) -> usize {
        self.purge_stale(now_unix);
        self.by_id.len()
    }

    fn create(
        &mut self,
        now_unix: u64,
        ttl_minutes: u64,
        max_uses: u32,
        scope: TempLinkScope,
        bound_terminal_id: Option<String>,
        created_by_session: String,
    ) -> anyhow::Result<TempLinkRecord> {
        if self.active_count(now_unix) >= MAX_ACTIVE_TEMP_LINKS {
            anyhow::bail!(
                "Maximum active temporary links reached ({}). Revoke one first.",
                MAX_ACTIVE_TEMP_LINKS
            );
        }
        let id = self.make_id();
        let record = TempLinkRecord {
            id: id.clone(),
            created_at_unix: now_unix,
            expires_at_unix: now_unix.saturating_add(ttl_minutes.saturating_mul(60)),
            revoked_at_unix: None,
            max_uses,
            used_count: 0,
            scope,
            bound_terminal_id,
            created_by_session,
        };
        self.by_id.insert(id, record.clone());
        Ok(record)
    }

    fn list_active(&mut self, now_unix: u64) -> Vec<TempLinkSummary> {
        self.purge_stale(now_unix);
        let mut out: Vec<TempLinkSummary> = self
            .by_id
            .values()
            .map(|record| TempLinkSummary {
                id: record.id.clone(),
                created_at_unix: record.created_at_unix,
                expires_at_unix: record.expires_at_unix,
                remaining_secs: record.expires_at_unix.saturating_sub(now_unix),
                max_uses: record.max_uses,
                used_count: record.used_count,
                scope: record.scope,
                bound_terminal_id: record.bound_terminal_id.clone(),
                created_by_session: record.created_by_session.clone(),
            })
            .collect();
        out.sort_by(|a, b| {
            a.expires_at_unix
                .cmp(&b.expires_at_unix)
                .then_with(|| a.id.cmp(&b.id))
        });
        out
    }

    fn revoke(&mut self, id: &str, now_unix: u64) -> bool {
        let Some(record) = self.by_id.get_mut(id) else {
            return false;
        };
        record.revoked_at_unix = Some(now_unix);
        true
    }

    fn revoke_all(&mut self, now_unix: u64) {
        for record in self.by_id.values_mut() {
            record.revoked_at_unix = Some(now_unix);
        }
    }

    fn redeem(
        &mut self,
        id: &str,
        now_unix: u64,
        token_expires_unix: u64,
    ) -> Option<(String, TempLinkScope, Option<String>)> {
        let record = self.by_id.get_mut(id)?;
        if record.revoked_at_unix.is_some() {
            return None;
        }
        if record.expires_at_unix != token_expires_unix {
            return None;
        }
        if now_unix > record.expires_at_unix.saturating_add(TEMP_LINK_GRACE_SECS) {
            return None;
        }
        if record.used_count >= record.max_uses {
            return None;
        }
        record.used_count = record.used_count.saturating_add(1);
        Some((
            record.id.clone(),
            record.scope,
            record.bound_terminal_id.clone(),
        ))
    }
}

impl SessionStore {
    pub fn new(idle_timeout: Duration, absolute_timeout: Duration) -> Self {
        Self {
            by_token: HashMap::new(),
            idle_timeout,
            absolute_timeout,
        }
    }

    fn purge_expired(&mut self, now: Instant) {
        let idle_timeout = self.idle_timeout;
        let absolute_timeout = self.absolute_timeout;
        self.by_token.retain(|_, record| {
            now.duration_since(record.last_activity_at) < idle_timeout
                && now.duration_since(record.created_at) < absolute_timeout
        });
    }

    pub fn create(&mut self, now: Instant) -> String {
        self.purge_expired(now);
        let token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(48)
            .map(char::from)
            .collect();
        self.by_token.insert(
            token.clone(),
            SessionRecord {
                created_at: now,
                last_activity_at: now,
            },
        );
        token
    }

    pub fn is_valid(&mut self, token: &str, now: Instant) -> bool {
        self.purge_expired(now);
        self.by_token.contains_key(token)
    }

    pub fn touch_if_valid(&mut self, token: &str, now: Instant) -> bool {
        self.purge_expired(now);
        let Some(record) = self.by_token.get_mut(token) else {
            return false;
        };
        if now.duration_since(record.created_at) >= self.absolute_timeout {
            self.by_token.remove(token);
            return false;
        }
        record.last_activity_at = now;
        true
    }

    pub fn remaining_secs(&mut self, token: &str, now: Instant) -> Option<(u64, u64)> {
        self.purge_expired(now);
        let record = *self.by_token.get(token)?;
        let idle_elapsed = now.duration_since(record.last_activity_at);
        let absolute_elapsed = now.duration_since(record.created_at);
        if idle_elapsed >= self.idle_timeout || absolute_elapsed >= self.absolute_timeout {
            self.by_token.remove(token);
            return None;
        }
        let idle_remaining = self.idle_timeout.saturating_sub(idle_elapsed).as_secs();
        let absolute_remaining = self
            .absolute_timeout
            .saturating_sub(absolute_elapsed)
            .as_secs();
        Some((idle_remaining, absolute_remaining))
    }

    pub fn revoke(&mut self, token: &str) {
        self.by_token.remove(token);
    }

    pub fn revoke_all(&mut self) {
        self.by_token.clear();
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/favicon.svg", get(serve_favicon))
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
        .route("/api/fs/tree", get(fs_tree))
        .route("/api/fs/file", get(fs_file).put(save_file))
        .route("/api/fs/file/diff", patch(save_file_diff))
        .route("/api/usage", get(usage_stats))
        .route("/ws", get(ws_handler))
        .with_state(state)
        .layer(CompressionLayer::new())
}

async fn serve_index() -> impl IntoResponse {
    let html = Assets::get("index.html").unwrap();
    Html(std::str::from_utf8(html.data.as_ref()).unwrap().to_string())
}

async fn serve_favicon() -> Response {
    let Some(icon) = Assets::get("favicon.svg") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    (
        [(header::CONTENT_TYPE, "image/svg+xml; charset=utf-8")],
        icon.data.into_owned(),
    )
        .into_response()
}

async fn auth_login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Response {
    if *state.access_locked.lock().unwrap() {
        return (
            StatusCode::LOCKED,
            "Access is locked. Restart CodeWebway to enable login again.",
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
        bump_shutdown_deadline_from_activity(&state, now);
        let set_cookie = format!(
            "codewebway_session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800",
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
    if has_valid_session_cookie(&headers, &state, false).is_some() {
        return (StatusCode::OK, "OK").into_response();
    }
    (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
}

async fn auth_session_status(headers: HeaderMap, State(state): State<Arc<AppState>>) -> Response {
    let Some(session_token) = has_valid_session_cookie(&headers, &state, false) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };
    let now = Instant::now();
    let remaining = {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.remaining_secs(&session_token, now)
    };
    let Some((remaining_idle_secs, remaining_absolute_secs)) = remaining else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };
    let grant = state
        .temp_grants
        .lock()
        .unwrap()
        .get(&session_token)
        .cloned();

    Json(SessionStatusResponse {
        remaining_idle_secs,
        remaining_absolute_secs,
        warning_window_secs: state.warning_window.as_secs(),
        read_only: grant.as_ref().map(|g| g.read_only).unwrap_or(false),
        bound_terminal_id: grant.as_ref().and_then(|g| g.bound_terminal_id.clone()),
        temp_link_id: grant.as_ref().map(|g| g.source_link_id.clone()),
    })
    .into_response()
}

async fn auth_extend(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<ExtendSessionRequest>,
) -> Response {
    let Some(session_token) = has_valid_session_cookie(&headers, &state, false) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };
    let pin_ok = verify_pin(req.pin.as_deref(), state.pin.as_deref());
    if !pin_ok {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }
    let now = Instant::now();
    let touched = {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.touch_if_valid(&session_token, now)
    };
    if !touched {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }
    bump_shutdown_deadline_from_activity(&state, now);
    (StatusCode::OK, "OK").into_response()
}

async fn create_temp_link(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateTempLinkRequest>,
) -> Response {
    let Some(session_token) = has_valid_session_cookie(&headers, &state, true) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };
    if is_session_read_only(&state, &session_token) {
        return (
            StatusCode::FORBIDDEN,
            "Read-only sessions cannot create temporary links",
        )
            .into_response();
    }
    if is_temporary_session(&state, &session_token) {
        return (
            StatusCode::FORBIDDEN,
            "Temporary sessions cannot create more links",
        )
            .into_response();
    }

    let ttl_minutes = req.ttl_minutes.unwrap_or(DEFAULT_TEMP_LINK_TTL_MINUTES);
    if !matches!(ttl_minutes, 5 | 15 | 60) {
        return (
            StatusCode::BAD_REQUEST,
            "ttl_minutes must be one of: 5, 15, 60",
        )
            .into_response();
    }

    let scope = match req.scope.as_deref() {
        None => TempLinkScope::ReadOnly,
        Some(raw) => match TempLinkScope::from_input(raw) {
            Some(scope) => scope,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    "scope must be read-only or interactive",
                )
                    .into_response()
            }
        },
    };

    let one_time = req.one_time.unwrap_or(true);
    let max_uses = if one_time {
        1
    } else {
        req.max_uses.unwrap_or(5)
    };
    if max_uses == 0 || max_uses > 100 {
        return (
            StatusCode::BAD_REQUEST,
            "max_uses must be between 1 and 100",
        )
            .into_response();
    }

    let bound_terminal_id = req.bound_terminal_id.and_then(|id| {
        let trimmed = id.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });
    if let Some(ref id) = bound_terminal_id {
        let exists = state.terminals.lock().unwrap().get_session(id).is_some();
        if !exists {
            return (StatusCode::BAD_REQUEST, "bound_terminal_id not found").into_response();
        }
    }

    let now_unix = unix_now();
    let created = {
        let mut links = state.temp_links.lock().unwrap();
        match links.create(
            now_unix,
            ttl_minutes,
            max_uses,
            scope,
            bound_terminal_id.clone(),
            session_token,
        ) {
            Ok(record) => record,
            Err(err) => return (StatusCode::TOO_MANY_REQUESTS, err.to_string()).into_response(),
        }
    };
    let token = mint_temp_link_token(
        &state.temp_link_signing_key,
        &created.id,
        created.expires_at_unix,
    );

    let payload = TempLinkCreateResponse {
        id: created.id,
        url: format!("/t/{token}"),
        created_at_unix: created.created_at_unix,
        expires_at_unix: created.expires_at_unix,
        remaining_secs: created.expires_at_unix.saturating_sub(now_unix),
        max_uses: created.max_uses,
        scope: created.scope,
        bound_terminal_id: created.bound_terminal_id,
    };
    count_tx_json(&state, &payload);
    (StatusCode::CREATED, Json(payload)).into_response()
}

async fn list_temp_links(headers: HeaderMap, State(state): State<Arc<AppState>>) -> Response {
    let Some(session_token) = has_valid_session_cookie(&headers, &state, true) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };
    if is_session_read_only(&state, &session_token) {
        return (
            StatusCode::FORBIDDEN,
            "Read-only sessions cannot list temporary links",
        )
            .into_response();
    }
    if is_temporary_session(&state, &session_token) {
        return (
            StatusCode::FORBIDDEN,
            "Temporary sessions cannot list links",
        )
            .into_response();
    }
    let now_unix = unix_now();
    let payload = state.temp_links.lock().unwrap().list_active(now_unix);
    count_tx_json(&state, &payload);
    Json(payload).into_response()
}

async fn revoke_temp_link(
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    State(state): State<Arc<AppState>>,
) -> Response {
    let Some(session_token) = has_valid_session_cookie(&headers, &state, true) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };
    if is_session_read_only(&state, &session_token) {
        return (
            StatusCode::FORBIDDEN,
            "Read-only sessions cannot revoke temporary links",
        )
            .into_response();
    }
    if is_temporary_session(&state, &session_token) {
        return (
            StatusCode::FORBIDDEN,
            "Temporary sessions cannot revoke links",
        )
            .into_response();
    }
    let revoked = state.temp_links.lock().unwrap().revoke(&id, unix_now());
    if revoked {
        return StatusCode::NO_CONTENT.into_response();
    }
    (StatusCode::NOT_FOUND, "Temporary link not found").into_response()
}

async fn redeem_temp_link(
    AxumPath(token): AxumPath<String>,
    State(state): State<Arc<AppState>>,
) -> Response {
    if *state.access_locked.lock().unwrap() {
        return (
            StatusCode::LOCKED,
            "Access is locked. Restart CodeWebway to enable login again.",
        )
            .into_response();
    }

    let parsed = parse_and_verify_temp_link_token(&state.temp_link_signing_key, &token);
    let Some(parsed) = parsed else {
        return temp_link_error_page(
            "Temporary link invalid",
            "This temporary link is invalid. Please request a new link from the sender.",
        );
    };

    let now = Instant::now();
    let now_unix = unix_now();
    if now_unix > parsed.expires_at_unix.saturating_add(TEMP_LINK_GRACE_SECS) {
        return temp_link_error_page(
            "Temporary link expired",
            "This link has expired. If you still need access, please contact the sender for a new link.",
        );
    }

    let redeemed =
        state
            .temp_links
            .lock()
            .unwrap()
            .redeem(&parsed.id, now_unix, parsed.expires_at_unix);
    let Some((link_id, scope, bound_terminal_id)) = redeemed else {
        return temp_link_error_page(
            "Temporary link unavailable",
            "This link is no longer available (expired, revoked, or already used). Please request a new link.",
        );
    };

    let session_token = {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.create(now)
    };

    state.temp_grants.lock().unwrap().insert(
        session_token.clone(),
        TempSessionGrant {
            read_only: scope == TempLinkScope::ReadOnly,
            bound_terminal_id,
            source_link_id: link_id,
        },
    );
    bump_shutdown_deadline_from_activity(&state, now);

    let set_cookie = format!(
        "codewebway_session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800",
        session_token
    );
    let mut response = Redirect::to("/").into_response();
    if let Ok(value) = set_cookie.parse() {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

async fn auth_public_status(State(state): State<Arc<AppState>>) -> Response {
    let remaining = shutdown_remaining_secs(&state, Instant::now());
    Json(PublicStatusResponse {
        shutdown_remaining_secs: remaining,
        access_locked: *state.access_locked.lock().unwrap(),
    })
    .into_response()
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
            state.temp_grants.lock().unwrap().clear();
            state.temp_links.lock().unwrap().revoke_all(unix_now());
            *state.access_locked.lock().unwrap() = true;
            state.terminals.lock().unwrap().remove_all();
            let _ = state.shutdown_tx.send(());
        } else {
            sessions.revoke(&current);
            state.temp_grants.lock().unwrap().remove(&current);
        }
    } else if revoke_all {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    (
        StatusCode::OK,
        [(
            header::SET_COOKIE,
            "codewebway_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".to_string(),
        )],
        "OK",
    )
        .into_response()
}

async fn list_terminals(headers: HeaderMap, State(state): State<Arc<AppState>>) -> Response {
    let Some(session_token) = has_valid_session_cookie(&headers, &state, true) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };
    let mut items = state.terminals.lock().unwrap().list();
    if let Some(bound_id) = session_bound_terminal_id(&state, &session_token) {
        items.retain(|item| item.id == bound_id);
    }
    Json(items).into_response()
}

async fn create_terminal(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateTerminalRequest>,
) -> Response {
    let Some(session_token) = has_valid_session_cookie(&headers, &state, true) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };
    if is_session_read_only(&state, &session_token) {
        return (
            StatusCode::FORBIDDEN,
            "Read-only sessions cannot create terminals",
        )
            .into_response();
    }
    if session_bound_terminal_id(&state, &session_token).is_some() {
        return (
            StatusCode::FORBIDDEN,
            "This session is bound to one terminal and cannot create more",
        )
            .into_response();
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
    let Some(session_token) = has_valid_session_cookie(&headers, &state, true) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };
    if is_session_read_only(&state, &session_token) {
        return (
            StatusCode::FORBIDDEN,
            "Read-only sessions cannot close terminals",
        )
            .into_response();
    }
    if session_bound_terminal_id(&state, &session_token).is_some() {
        return (
            StatusCode::FORBIDDEN,
            "This session is bound to one terminal and cannot close terminals",
        )
            .into_response();
    }
    let removed = state.terminals.lock().unwrap().remove(&id);
    if removed {
        return StatusCode::NO_CONTENT.into_response();
    }
    (StatusCode::NOT_FOUND, "Terminal not found").into_response()
}

async fn rename_terminal(
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<RenameTerminalRequest>,
) -> Response {
    let Some(session_token) = has_valid_session_cookie(&headers, &state, true) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };
    if is_session_read_only(&state, &session_token) {
        return (
            StatusCode::FORBIDDEN,
            "Read-only sessions cannot rename terminals",
        )
            .into_response();
    }
    if session_bound_terminal_id(&state, &session_token).is_some() {
        return (
            StatusCode::FORBIDDEN,
            "This session is bound to one terminal and cannot rename terminals",
        )
            .into_response();
    }
    let title = req.title.trim();
    if title.is_empty() {
        return (StatusCode::BAD_REQUEST, "title cannot be empty").into_response();
    }
    if title.chars().count() > 48 {
        return (StatusCode::BAD_REQUEST, "title is too long").into_response();
    }

    let renamed = state
        .terminals
        .lock()
        .unwrap()
        .rename(&id, title.to_string());
    match renamed {
        Some(summary) => Json(summary).into_response(),
        None => (StatusCode::NOT_FOUND, "Terminal not found").into_response(),
    }
}

async fn fs_tree(
    headers: HeaderMap,
    Query(query): Query<FsQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    if has_valid_session_cookie(&headers, &state, true).is_none() {
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
    if has_valid_session_cookie(&headers, &state, true).is_none() {
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
    let Some(session_token) = has_valid_session_cookie(&headers, &state, true) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };
    if is_session_read_only(&state, &session_token) {
        return (
            StatusCode::FORBIDDEN,
            "Read-only sessions cannot edit files",
        )
            .into_response();
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
    let Some(session_token) = has_valid_session_cookie(&headers, &state, true) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };
    if is_session_read_only(&state, &session_token) {
        return (
            StatusCode::FORBIDDEN,
            "Read-only sessions cannot edit files",
        )
            .into_response();
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
    if has_valid_session_cookie(&headers, &state, false).is_none() {
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
    let Some(session_token) = has_valid_session_cookie(&headers, &state, false) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };

    let Some(terminal_id) = query.terminal_id else {
        return (StatusCode::BAD_REQUEST, "terminal_id is required").into_response();
    };
    if let Some(bound_id) = session_bound_terminal_id(&state, &session_token) {
        if bound_id != terminal_id {
            return (
                StatusCode::FORBIDDEN,
                "This session is bound to a different terminal",
            )
                .into_response();
        }
    }
    let terminal_session = {
        let manager = state.terminals.lock().unwrap();
        manager.get_session(&terminal_id)
    };
    let Some(terminal_session) = terminal_session else {
        return (StatusCode::NOT_FOUND, "Terminal not found").into_response();
    };

    {
        let mut current = state.ws_connections.lock().unwrap();
        if *current >= state.max_ws_connections {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "Maximum concurrent connections reached",
            )
                .into_response();
        }
        *current += 1;
    }

    let skip_scrollback = parse_query_bool(query.skip_scrollback.as_deref());
    ws.on_upgrade(move |socket| {
        handle_socket(
            socket,
            state,
            session_token,
            terminal_session,
            skip_scrollback,
            terminal_id,
        )
    })
}

async fn handle_socket(
    mut socket: WebSocket,
    state: Arc<AppState>,
    session_token: String,
    terminal: Session,
    skip_scrollback: bool,
    terminal_id: String,
) {
    let (scrollback, mut rx) = {
        let s = terminal.lock().unwrap();
        (s.scrollback.snapshot(), s.tx.subscribe())
    };
    if !skip_scrollback && !scrollback.is_empty() {
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
                count_tx(&state, WS_HEARTBEAT_PAYLOAD.len() as u64);
                if socket
                    .send(Message::Text(WS_HEARTBEAT_PAYLOAD.into()))
                    .await
                    .is_err()
                {
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
                        if is_session_read_only(&state, &session_token) {
                            continue;
                        }
                        touch_session_token_if_valid(&state, &session_token);
                        count_rx(&state, data.len() as u64);
                        let mut s = terminal.lock().unwrap();
                        let _ = s.pty_writer.write_all(&data);
                    }
                    Some(Ok(Message::Text(text))) => {
                        if is_session_read_only(&state, &session_token) {
                            continue;
                        }
                        touch_session_token_if_valid(&state, &session_token);
                        count_rx(&state, text.len() as u64);
                        if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&text) {
                            if msg["type"] == "resize" {
                                if let Some(bound) = session_bound_terminal_id(&state, &session_token) {
                                    if bound != terminal_id {
                                        continue;
                                    }
                                }
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

    let mut current = state.ws_connections.lock().unwrap();
    *current = current.saturating_sub(1);
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

fn has_valid_session_cookie(
    headers: &HeaderMap,
    state: &Arc<AppState>,
    touch: bool,
) -> Option<String> {
    let session = session_token_from_headers(headers)?;
    let now = Instant::now();
    let valid = if touch {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.touch_if_valid(&session, now)
    } else {
        is_session_token_valid_at(state, &session, now)
    };
    if !valid {
        state.temp_grants.lock().unwrap().remove(&session);
        return None;
    }
    if touch {
        bump_shutdown_deadline_from_activity(state, now);
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
    cookie_value(raw_cookie, "codewebway_session").map(|value| value.to_string())
}

fn is_session_token_valid(state: &Arc<AppState>, session: &str) -> bool {
    is_session_token_valid_at(state, session, Instant::now())
}

fn is_session_token_valid_at(state: &Arc<AppState>, session: &str, now: Instant) -> bool {
    let mut sessions = state.sessions.lock().unwrap();
    sessions.is_valid(session, now)
}

fn touch_session_token_if_valid(state: &Arc<AppState>, session: &str) -> bool {
    let now = Instant::now();
    let touched = {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.touch_if_valid(session, now)
    };
    if touched {
        bump_shutdown_deadline_from_activity(state, now);
    }
    touched
}

fn is_session_read_only(state: &Arc<AppState>, session: &str) -> bool {
    state
        .temp_grants
        .lock()
        .unwrap()
        .get(session)
        .map(|grant| grant.read_only)
        .unwrap_or(false)
}

fn session_bound_terminal_id(state: &Arc<AppState>, session: &str) -> Option<String> {
    state
        .temp_grants
        .lock()
        .unwrap()
        .get(session)
        .and_then(|grant| grant.bound_terminal_id.clone())
}

fn is_temporary_session(state: &Arc<AppState>, session: &str) -> bool {
    state.temp_grants.lock().unwrap().contains_key(session)
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

fn parse_query_bool(value: Option<&str>) -> bool {
    let Some(raw) = value else {
        return false;
    };
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
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
    let forwarded_host = headers
        .get("x-forwarded-host")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let origin_host = parse_origin_host(origin);
    let Some(origin_host) = origin_host else {
        return false;
    };

    if origin_host == host {
        if let Some(proto) = headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
        {
            return origin == format!("{proto}://{host}");
        }
        return origin == format!("http://{host}") || origin == format!("https://{host}");
    }

    if let Some(fwd_host) = forwarded_host {
        if origin_host != fwd_host {
            return false;
        }
        if let Some(proto) = headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
        {
            return origin == format!("{proto}://{fwd_host}");
        }
        return origin == format!("http://{fwd_host}") || origin == format!("https://{fwd_host}");
    }
    false
}

fn parse_origin_host(origin: &str) -> Option<&str> {
    let without_scheme = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))?;
    without_scheme.split('/').next()
}

fn verify_pin(input: Option<&str>, expected: Option<&str>) -> bool {
    match expected {
        Some(expected_pin) => input
            .map(|candidate| check_token(candidate, expected_pin))
            .unwrap_or(false),
        None => true,
    }
}

fn bump_shutdown_deadline_from_activity(state: &Arc<AppState>, now: Instant) {
    let next_deadline = now + state.idle_timeout + state.shutdown_grace;
    let mut deadline = state.shutdown_deadline.lock().unwrap();
    *deadline = next_deadline;
}

pub fn shutdown_remaining_secs(state: &Arc<AppState>, now: Instant) -> u64 {
    let deadline = *state.shutdown_deadline.lock().unwrap();
    deadline.saturating_duration_since(now).as_secs()
}

fn utc_day_index() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(dur) => dur.as_secs() / 86_400,
        Err(_) => 0,
    }
}

fn unix_now() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(dur) => dur.as_secs(),
        Err(_) => 0,
    }
}

fn generate_random_token(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

struct ParsedTempToken {
    id: String,
    expires_at_unix: u64,
}

fn temp_link_signature(signing_key: &str, id: &str, expires_at_unix: u64, nonce: &str) -> String {
    let payload = format!("{id}.{expires_at_unix}.{nonce}");
    hash_bytes_hex(format!("{signing_key}:{payload}").as_bytes())
}

fn mint_temp_link_token(signing_key: &str, id: &str, expires_at_unix: u64) -> String {
    let nonce = generate_random_token(24);
    let signature = temp_link_signature(signing_key, id, expires_at_unix, &nonce);
    format!("{id}.{expires_at_unix}.{nonce}.{signature}")
}

fn parse_and_verify_temp_link_token(signing_key: &str, token: &str) -> Option<ParsedTempToken> {
    let mut parts = token.split('.');
    let id = parts.next()?.to_string();
    let expires_raw = parts.next()?;
    let nonce = parts.next()?.to_string();
    let signature = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let expires_at_unix = expires_raw.parse::<u64>().ok()?;
    let expected = temp_link_signature(signing_key, &id, expires_at_unix, &nonce);
    if !check_token(signature, &expected) {
        return None;
    }
    Some(ParsedTempToken {
        id,
        expires_at_unix,
    })
}

pub fn create_temp_link_for_host(
    state: &Arc<AppState>,
    ttl_minutes: u64,
    scope: TempLinkScope,
    max_uses: u32,
    bound_terminal_id: Option<String>,
) -> anyhow::Result<TempLinkCreateResponse> {
    let now_unix = unix_now();
    let created = state.temp_links.lock().unwrap().create(
        now_unix,
        ttl_minutes,
        max_uses,
        scope,
        bound_terminal_id,
        "host-cli".to_string(),
    )?;
    let token = mint_temp_link_token(
        &state.temp_link_signing_key,
        &created.id,
        created.expires_at_unix,
    );
    Ok(TempLinkCreateResponse {
        id: created.id,
        url: format!("/t/{token}"),
        created_at_unix: created.created_at_unix,
        expires_at_unix: created.expires_at_unix,
        remaining_secs: created.expires_at_unix.saturating_sub(now_unix),
        max_uses: created.max_uses,
        scope: created.scope,
        bound_terminal_id: created.bound_terminal_id,
    })
}

fn temp_link_error_page(title: &str, message: &str) -> Response {
    let html = format!(
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{}</title><style>body{{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;background:#111;color:#ddd;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:20px}}.card{{max-width:520px;background:#1b1b1b;border:1px solid #333;border-radius:12px;padding:20px}}h1{{margin:0 0 8px;font-size:20px}}p{{margin:0;color:#bbb;line-height:1.5}}</style></head><body><div class='card'><h1>{}</h1><p>{}</p></div></body></html>",
        title, title, message
    );
    (StatusCode::UNAUTHORIZED, Html(html)).into_response()
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
        let value = cookie_value(
            "foo=1; codewebway_session=abc123; bar=2",
            "codewebway_session",
        );
        assert_eq!(value, Some("abc123"));
    }

    #[test]
    fn test_cookie_value_missing() {
        let value = cookie_value("foo=1; bar=2", "codewebway_session");
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
    fn test_origin_allowed_with_forwarded_host() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ORIGIN,
            "https://public-share.example.com".parse().unwrap(),
        );
        headers.insert(header::HOST, "127.0.0.1:8080".parse().unwrap());
        headers.insert(
            "x-forwarded-host",
            "public-share.example.com".parse().unwrap(),
        );
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(is_allowed_origin(&headers));
    }

    #[test]
    fn test_origin_rejected_when_forwarded_host_mismatch() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ORIGIN,
            "https://public-share.example.com".parse().unwrap(),
        );
        headers.insert(header::HOST, "127.0.0.1:8080".parse().unwrap());
        headers.insert(
            "x-forwarded-host",
            "other-share.example.com".parse().unwrap(),
        );
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(!is_allowed_origin(&headers));
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
        let mut store = SessionStore::new(Duration::from_secs(10), Duration::from_secs(60));
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
            "foo=1; codewebway_session=abc123".parse().unwrap(),
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

    #[test]
    fn test_temp_link_redeem_one_time() {
        let mut store = TempLinkStore::new();
        let now = 1_700_000_000u64;
        let record = store
            .create(
                now,
                15,
                1,
                TempLinkScope::ReadOnly,
                None,
                "session-main".to_string(),
            )
            .unwrap();
        assert_eq!(record.max_uses, 1);

        let first = store.redeem(&record.id, now + 1, record.expires_at_unix);
        assert!(first.is_some());
        let second = store.redeem(&record.id, now + 2, record.expires_at_unix);
        assert!(second.is_none());
    }

    #[test]
    fn test_temp_link_expired_not_redeemable() {
        let mut store = TempLinkStore::new();
        let now = 1_700_000_000u64;
        let created = store
            .create(
                now,
                5,
                5,
                TempLinkScope::Interactive,
                Some("tab1".to_string()),
                "session-main".to_string(),
            )
            .unwrap();
        assert!(store
            .redeem(
                &created.id,
                created.expires_at_unix + TEMP_LINK_GRACE_SECS + 1,
                created.expires_at_unix
            )
            .is_none());
    }

    #[test]
    fn test_temp_link_revoke_removes_from_active_list() {
        let mut store = TempLinkStore::new();
        let now = 1_700_000_000u64;
        let created = store
            .create(
                now,
                15,
                2,
                TempLinkScope::Interactive,
                None,
                "session-main".to_string(),
            )
            .unwrap();
        assert_eq!(store.list_active(now).len(), 1);
        assert!(store.revoke(&created.id, now + 1));
        assert!(store.list_active(now + 2).is_empty());
    }

    #[test]
    fn test_temp_link_token_signature_roundtrip() {
        let key = "signing-key";
        let token = mint_temp_link_token(key, "abc123", 1_700_000_600);
        let parsed = parse_and_verify_temp_link_token(key, &token).unwrap();
        assert_eq!(parsed.id, "abc123");
        assert_eq!(parsed.expires_at_unix, 1_700_000_600);
    }

    #[test]
    fn test_temp_link_token_signature_rejects_tamper() {
        let key = "signing-key";
        let token = mint_temp_link_token(key, "abc123", 1_700_000_600);
        let tampered = token.replacen("abc123", "xyz999", 1);
        assert!(parse_and_verify_temp_link_token(key, &tampered).is_none());
    }
}
