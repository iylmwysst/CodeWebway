use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::{
    body::Body,
    extract::{
        ws::{Message, WebSocket},
        Json, Path as AxumPath, Query, State, WebSocketUpgrade,
    },
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{delete, get, patch, post},
    Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use hmac::{Hmac, Mac};
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
const MAX_UPLOAD_BYTES: usize = 50 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 200 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 10_000;
const MAX_ACTIVE_TEMP_LINKS: usize = 2;
const DEFAULT_TEMP_LINK_TTL_MINUTES: u64 = 15;
const TEMP_LINK_GRACE_SECS: u64 = 120;
const WS_HEARTBEAT_PAYLOAD: &str = "{\"type\":\"heartbeat\"}";
pub const DASHBOARD_PENDING_LOGIN_TTL_SECS: u64 = 15 * 60;
pub const DASHBOARD_PENDING_LOGIN_MAX_PIN_ATTEMPTS: usize = 5;
const CREDENTIAL_ATTEMPT_MAX: usize = 5;
const PIN_ATTEMPT_MAX: usize = 8;
const CHALLENGE_POLL_ATTEMPT_MAX: usize = 90;
const AUTH_ATTEMPT_WINDOW_SECS: u64 = 300;
const CHALLENGE_POLL_WINDOW_SECS: u64 = 120;
const SSO_TICKET_CLOCK_SKEW_SECS: u64 = 30;

pub struct AppState {
    pub password: String,
    pub pin: Option<String>,
    pub auth_attempts: Mutex<AuthAttemptTracker>,
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
    pub dashboard_pending_logins: Mutex<DashboardPendingLoginStore>,
    pub temp_link_signing_key: String,
    pub auto_shutdown_disabled: bool,
    pub terminal_only: bool,
    pub runtime_instance_id: Option<String>,
    pub sso_shared_secret: Option<String>,
    pub used_sso_nonces: Mutex<HashMap<String, u64>>,
    pub dashboard_auth: Option<DashboardAuthConfig>,
}

#[derive(Clone)]
pub struct DashboardAuthConfig {
    pub api_base: String,
    pub machine_token: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    password: Option<String>,
    sso_ticket: Option<String>,
    dashboard_ticket: Option<String>,
    dashboard_token: Option<String>,
    dashboard_pending_login_id: Option<String>,
    pin: Option<String>,
}

#[derive(Serialize)]
pub struct DashboardChallengeResponse {
    challenge_id: String,
    approve_url: String,
    expires_in: u64,
}

#[derive(Serialize)]
pub struct DashboardChallengeStatusResponse {
    status: String,
    pending_login_id: Option<String>,
}

#[derive(Deserialize)]
struct DashboardTicketExchangeRequest {
    dashboard_ticket: String,
}

#[derive(Serialize)]
struct DashboardTicketExchangeResponse {
    pending_login_id: String,
}

#[derive(Deserialize)]
struct TempLinkChallengeQuery {
    token: String,
}

#[derive(Serialize)]
struct TempLinkChallengeStatusResponse {
    status: String,
    redirect_to: Option<String>,
}

#[derive(Serialize)]
struct ApiErrorResponse {
    code: String,
    message: String,
}

async fn emit_dashboard_activity(
    state: &Arc<AppState>,
    event_type: &str,
    event_name: &str,
    status: &str,
    detail: Option<String>,
) {
    let Some(cfg) = state.dashboard_auth.as_ref() else {
        return;
    };
    let client = reqwest::Client::new();
    let url = format!(
        "{}/api/v1/agent/activity",
        cfg.api_base.trim_end_matches('/')
    );
    let _ = client
        .post(url)
        .bearer_auth(&cfg.machine_token)
        .json(&serde_json::json!({
            "event_type": event_type,
            "event_name": event_name,
            "status": status,
            "detail": detail,
        }))
        .timeout(Duration::from_secs(8))
        .send()
        .await;
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
pub struct StopTerminalRequest {
    pin: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateTempLinkRequest {
    ttl_minutes: Option<u64>,
    scope: Option<String>,
    one_time: Option<bool>,
    max_uses: Option<u32>,
    bound_terminal_id: Option<String>,
    pin: Option<String>,
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
pub struct TerminalHistoryQuery {
    before_seq: Option<u64>,
    limit: Option<usize>,
}

#[derive(Deserialize)]
pub struct UploadFileRequest {
    path: String,
    data_b64: String,
    overwrite: Option<bool>,
}

#[derive(Deserialize)]
pub struct ArchiveRequest {
    paths: Vec<String>,
}

#[derive(Deserialize)]
pub struct MovePathsRequest {
    paths: Vec<String>,
    target_dir: String,
}

#[derive(Deserialize)]
pub struct DeletePathsRequest {
    paths: Vec<String>,
    pin: Option<String>,
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
struct TerminalHistoryChunkResponse {
    seq: u64,
    data_b64: String,
    byte_len: usize,
}

#[derive(Serialize)]
struct TerminalHistoryResponse {
    terminal_id: String,
    chunks: Vec<TerminalHistoryChunkResponse>,
    has_more: bool,
    first_seq: Option<u64>,
    next_seq: u64,
    total_bytes: usize,
    trimmed: bool,
}

#[derive(Serialize)]
struct TerminalTailResponse {
    terminal_id: String,
    data_b64: String,
    first_seq: Option<u64>,
    next_seq: u64,
    total_bytes: usize,
    trimmed: bool,
}

#[derive(Serialize)]
struct UploadFileResponse {
    path: String,
    size_bytes: usize,
    overwritten: bool,
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
    auto_shutdown_disabled: bool,
    sso_enabled: bool,
    dashboard_login_enabled: bool,
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

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::Interactive => "interactive",
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum AuthAttemptBucket {
    Credentials,
    Pin,
    ChallengePoll,
}

#[derive(Clone, Copy)]
struct AuthAttemptPolicy {
    max_attempts: usize,
    window: Duration,
}

pub struct AuthAttemptTracker {
    by_client: HashMap<(AuthAttemptBucket, String), VecDeque<Instant>>,
}

pub struct DashboardPendingLoginStore {
    by_id: HashMap<String, DashboardPendingLoginRecord>,
    by_challenge: HashMap<String, String>,
    ttl: Duration,
    max_pin_attempts: usize,
}

#[derive(Clone)]
struct DashboardPendingLoginRecord {
    challenge_id: String,
    expires_at: Instant,
    failed_pin_attempts: usize,
}

impl DashboardPendingLoginStore {
    pub fn new(ttl: Duration, max_pin_attempts: usize) -> Self {
        Self {
            by_id: HashMap::new(),
            by_challenge: HashMap::new(),
            ttl,
            max_pin_attempts,
        }
    }

    fn make_id(&self) -> String {
        loop {
            let id: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(24)
                .map(char::from)
                .collect();
            if !self.by_id.contains_key(&id) {
                return id;
            }
        }
    }

    fn purge_expired(&mut self, now: Instant) {
        let expired_ids: Vec<String> = self
            .by_id
            .iter()
            .filter_map(|(id, record)| {
                if now >= record.expires_at || record.failed_pin_attempts >= self.max_pin_attempts {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();
        for id in expired_ids {
            self.remove(&id);
        }
    }

    fn get_by_challenge(&mut self, challenge_id: &str, now: Instant) -> Option<String> {
        self.purge_expired(now);
        let id = self.by_challenge.get(challenge_id)?.clone();
        if self.by_id.contains_key(&id) {
            Some(id)
        } else {
            self.by_challenge.remove(challenge_id);
            None
        }
    }

    fn create(&mut self, challenge_id: String, now: Instant) -> String {
        self.purge_expired(now);
        if let Some(existing) = self.get_by_challenge(&challenge_id, now) {
            return existing;
        }
        let id = self.make_id();
        self.by_id.insert(
            id.clone(),
            DashboardPendingLoginRecord {
                challenge_id: challenge_id.clone(),
                expires_at: now + self.ttl,
                failed_pin_attempts: 0,
            },
        );
        self.by_challenge.insert(challenge_id, id.clone());
        id
    }

    fn is_valid(&mut self, id: &str, now: Instant) -> bool {
        self.purge_expired(now);
        self.by_id.contains_key(id)
    }

    fn record_pin_failure(&mut self, id: &str, now: Instant) -> bool {
        self.purge_expired(now);
        let Some(record) = self.by_id.get_mut(id) else {
            return false;
        };
        record.failed_pin_attempts = record.failed_pin_attempts.saturating_add(1);
        let still_valid =
            record.failed_pin_attempts < self.max_pin_attempts && now < record.expires_at;
        if !still_valid {
            self.remove(id);
        }
        still_valid
    }

    fn consume(&mut self, id: &str, now: Instant) -> bool {
        self.purge_expired(now);
        if !self.by_id.contains_key(id) {
            return false;
        }
        self.remove(id);
        true
    }

    fn remove(&mut self, id: &str) {
        if let Some(record) = self.by_id.remove(id) {
            if self
                .by_challenge
                .get(&record.challenge_id)
                .map(|mapped| mapped == id)
                .unwrap_or(false)
            {
                self.by_challenge.remove(&record.challenge_id);
            }
        }
    }
}

impl AuthAttemptTracker {
    pub fn new() -> Self {
        Self {
            by_client: HashMap::new(),
        }
    }

    fn policy(bucket: AuthAttemptBucket) -> AuthAttemptPolicy {
        match bucket {
            AuthAttemptBucket::Credentials => AuthAttemptPolicy {
                max_attempts: CREDENTIAL_ATTEMPT_MAX,
                window: Duration::from_secs(AUTH_ATTEMPT_WINDOW_SECS),
            },
            AuthAttemptBucket::Pin => AuthAttemptPolicy {
                max_attempts: PIN_ATTEMPT_MAX,
                window: Duration::from_secs(AUTH_ATTEMPT_WINDOW_SECS),
            },
            AuthAttemptBucket::ChallengePoll => AuthAttemptPolicy {
                max_attempts: CHALLENGE_POLL_ATTEMPT_MAX,
                window: Duration::from_secs(CHALLENGE_POLL_WINDOW_SECS),
            },
        }
    }

    fn purge_expired(&mut self, bucket: AuthAttemptBucket, client: &str, now: Instant) {
        let key = (bucket, client.to_string());
        let Some(queue) = self.by_client.get_mut(&key) else {
            return;
        };
        let policy = Self::policy(bucket);
        while let Some(first) = queue.front() {
            if now.duration_since(*first) >= policy.window {
                queue.pop_front();
            } else {
                break;
            }
        }
        if queue.is_empty() {
            self.by_client.remove(&key);
        }
    }

    fn retry_after(
        &mut self,
        bucket: AuthAttemptBucket,
        client: &str,
        now: Instant,
    ) -> Option<Duration> {
        self.purge_expired(bucket, client, now);
        let key = (bucket, client.to_string());
        let queue = self.by_client.get(&key)?;
        let policy = Self::policy(bucket);
        if queue.len() < policy.max_attempts {
            return None;
        }
        let earliest = *queue.front()?;
        Some(policy.window.saturating_sub(now.duration_since(earliest)))
    }

    fn record_attempt(&mut self, bucket: AuthAttemptBucket, client: &str, now: Instant) {
        self.purge_expired(bucket, client, now);
        let key = (bucket, client.to_string());
        let queue = self.by_client.entry(key).or_default();
        queue.push_back(now);
    }

    fn clear_bucket(&mut self, bucket: AuthAttemptBucket, client: &str) {
        self.by_client.remove(&(bucket, client.to_string()));
    }

    fn clear_login(&mut self, client: &str) {
        self.clear_bucket(AuthAttemptBucket::Credentials, client);
        self.clear_bucket(AuthAttemptBucket::Pin, client);
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

    fn inspect(
        &mut self,
        id: &str,
        now_unix: u64,
        token_expires_unix: u64,
    ) -> Option<(TempLinkScope, Option<String>)> {
        let record = self.by_id.get(id)?;
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
        Some((record.scope, record.bound_terminal_id.clone()))
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
    let terminal_only = state.terminal_only;
    let mut r = Router::new()
        .route("/", get(serve_index))
        .route("/favicon.svg", get(serve_favicon))
        .route("/assets/*path", get(serve_asset))
        .route("/api/capabilities", get(capabilities))
        .route("/auth/login", post(auth_login))
        .route("/auth/dashboard/challenge", post(auth_dashboard_challenge))
        .route(
            "/auth/dashboard/ticket",
            post(auth_dashboard_ticket_exchange),
        )
        .route(
            "/auth/dashboard/challenge/:id",
            get(auth_dashboard_challenge_status),
        )
        .route("/auth/logout", post(auth_logout))
        .route("/auth/session", get(auth_session))
        .route("/auth/session/status", get(auth_session_status))
        .route("/auth/extend", post(auth_extend))
        .route("/auth/stop-terminal", post(auth_stop_terminal))
        .route(
            "/auth/temp-links",
            get(list_temp_links).post(create_temp_link),
        )
        .route("/auth/temp-links/:id", delete(revoke_temp_link))
        .route(
            "/auth/temp-links/interactive/challenge/:id",
            get(auth_temp_link_interactive_challenge_status),
        )
        .route("/auth/public-status", get(auth_public_status))
        .route("/t/:token", get(redeem_temp_link))
        .route("/api/terminals", get(list_terminals).post(create_terminal))
        .route(
            "/api/terminals/:id",
            delete(delete_terminal).patch(rename_terminal),
        )
        .route("/api/terminals/:id/history", get(terminal_history))
        .route("/api/terminals/:id/tail", get(terminal_tail))
        .route("/api/usage", get(usage_stats))
        .route("/ws", get(ws_handler));

    if !terminal_only {
        r = r
            .route("/api/fs/tree", get(fs_tree))
            .route("/api/fs/file", get(fs_file).put(save_file))
            .route("/api/fs/file/diff", patch(save_file_diff))
            .route("/api/fs/upload", post(upload_file))
            .route("/api/fs/download", get(download_file))
            .route("/api/fs/archive", post(download_archive))
            .route("/api/fs/move", post(move_paths))
            .route("/api/fs/delete", delete(delete_paths));
    }

    r.with_state(state).layer(CompressionLayer::new())
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

async fn serve_asset(AxumPath(path): AxumPath<String>) -> Response {
    let embedded_path = sanitize_embedded_asset_path(&path).unwrap_or_default();
    if embedded_path.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let Some(asset) = Assets::get(&embedded_path) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    (
        [(
            header::CONTENT_TYPE,
            embedded_asset_content_type(&embedded_path),
        )],
        asset.data.into_owned(),
    )
        .into_response()
}

fn sanitize_embedded_asset_path(path: &str) -> Option<String> {
    let mut parts = Vec::new();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(segment) => parts.push(segment.to_string_lossy().into_owned()),
            Component::CurDir => {}
            _ => return None,
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

fn embedded_asset_content_type(path: &str) -> &'static str {
    match Path::new(path).extension().and_then(|ext| ext.to_str()) {
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("svg") => "image/svg+xml; charset=utf-8",
        Some("html") => "text/html; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[derive(Serialize)]
struct CapabilitiesResponse {
    terminal_only: bool,
}

async fn capabilities(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(CapabilitiesResponse {
        terminal_only: state.terminal_only,
    })
}

#[derive(Deserialize)]
struct FleetChallengeEnvelope {
    data: FleetChallengeData,
}

#[derive(Deserialize)]
struct FleetChallengeData {
    challenge_id: String,
    approve_url: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct FleetChallengeStatusEnvelope {
    data: FleetChallengeStatusData,
}

#[derive(Deserialize)]
struct FleetChallengeStatusData {
    status: String,
    ticket: Option<String>,
}

async fn auth_dashboard_challenge(State(state): State<Arc<AppState>>) -> Response {
    if *state.access_locked.lock().unwrap() {
        return access_paused_response();
    }
    let Some(cfg) = state.dashboard_auth.as_ref() else {
        return (
            StatusCode::BAD_REQUEST,
            "Dashboard login is not configured on this host",
        )
            .into_response();
    };
    let client = reqwest::Client::new();
    let url = format!(
        "{}/api/v1/agent/host-auth/challenge",
        cfg.api_base.trim_end_matches('/')
    );
    let result = client
        .post(url)
        .bearer_auth(&cfg.machine_token)
        .timeout(Duration::from_secs(8))
        .send()
        .await;
    let response = match result {
        Ok(res) => res,
        Err(_) => return (StatusCode::BAD_GATEWAY, "Cannot reach dashboard API").into_response(),
    };
    if !response.status().is_success() {
        return (
            StatusCode::BAD_GATEWAY,
            "Dashboard API rejected challenge request",
        )
            .into_response();
    }
    let payload = match response.json::<FleetChallengeEnvelope>().await {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_GATEWAY, "Invalid challenge response").into_response(),
    };
    let out = DashboardChallengeResponse {
        challenge_id: payload.data.challenge_id,
        approve_url: payload.data.approve_url,
        expires_in: payload.data.expires_in,
    };
    Json(out).into_response()
}

async fn auth_dashboard_challenge_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if *state.access_locked.lock().unwrap() {
        return access_paused_response();
    }
    let Some(cfg) = state.dashboard_auth.as_ref() else {
        return (
            StatusCode::BAD_REQUEST,
            "Dashboard login is not configured on this host",
        )
            .into_response();
    };
    let now = Instant::now();
    let client = client_key_from_headers(&headers);
    let poll_client = format!("{client}:{id}");
    {
        let mut attempts = state.auth_attempts.lock().unwrap();
        if let Some(wait) =
            attempts.retry_after(AuthAttemptBucket::ChallengePoll, &poll_client, now)
        {
            return too_many_attempts_response(
                wait,
                "Too many approval checks. Wait a moment and try again.",
            );
        }
        attempts.record_attempt(AuthAttemptBucket::ChallengePoll, &poll_client, now);
    }
    if let Some(pending_login_id) = state
        .dashboard_pending_logins
        .lock()
        .unwrap()
        .get_by_challenge(&id, now)
    {
        state
            .auth_attempts
            .lock()
            .unwrap()
            .clear_bucket(AuthAttemptBucket::ChallengePoll, &poll_client);
        return Json(DashboardChallengeStatusResponse {
            status: "pin_required".to_string(),
            pending_login_id: Some(pending_login_id),
        })
        .into_response();
    }

    let client = reqwest::Client::new();
    let url = format!(
        "{}/api/v1/agent/host-auth/challenge/{}",
        cfg.api_base.trim_end_matches('/'),
        id
    );
    let result = client
        .get(url)
        .bearer_auth(&cfg.machine_token)
        .timeout(Duration::from_secs(8))
        .send()
        .await;
    let response = match result {
        Ok(res) => res,
        Err(_) => return (StatusCode::BAD_GATEWAY, "Cannot reach dashboard API").into_response(),
    };
    if !response.status().is_success() {
        let status = match response.status() {
            StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND | StatusCode::GONE => "expired",
            StatusCode::FORBIDDEN => "denied",
            _ => "unavailable",
        };
        state
            .auth_attempts
            .lock()
            .unwrap()
            .clear_bucket(AuthAttemptBucket::ChallengePoll, &poll_client);
        return Json(DashboardChallengeStatusResponse {
            status: status.to_string(),
            pending_login_id: None,
        })
        .into_response();
    }
    let payload = match response.json::<FleetChallengeStatusEnvelope>().await {
        Ok(v) => v,
        Err(_) => {
            return (StatusCode::BAD_GATEWAY, "Invalid challenge status response").into_response()
        }
    };
    let upstream_status = payload.data.status.trim().to_ascii_lowercase();
    match upstream_status.as_str() {
        "approved" => {
            let Some(ticket) = payload.data.ticket.as_deref() else {
                return Json(DashboardChallengeStatusResponse {
                    status: "unavailable".to_string(),
                    pending_login_id: None,
                })
                .into_response();
            };
            let redeem = redeem_dashboard_ticket(&state, ticket).await;
            let local_status = match redeem {
                DashboardTicketRedeemResult::Approved => {
                    state
                        .auth_attempts
                        .lock()
                        .unwrap()
                        .clear_bucket(AuthAttemptBucket::ChallengePoll, &poll_client);
                    let pending_login_id = state
                        .dashboard_pending_logins
                        .lock()
                        .unwrap()
                        .create(id, now);
                    return Json(DashboardChallengeStatusResponse {
                        status: "pin_required".to_string(),
                        pending_login_id: Some(pending_login_id),
                    })
                    .into_response();
                }
                DashboardTicketRedeemResult::Expired => "expired",
                DashboardTicketRedeemResult::Denied => "denied",
                DashboardTicketRedeemResult::Unavailable => "unavailable",
            };
            state
                .auth_attempts
                .lock()
                .unwrap()
                .clear_bucket(AuthAttemptBucket::ChallengePoll, &poll_client);
            Json(DashboardChallengeStatusResponse {
                status: local_status.to_string(),
                pending_login_id: None,
            })
            .into_response()
        }
        "expired" => {
            state
                .auth_attempts
                .lock()
                .unwrap()
                .clear_bucket(AuthAttemptBucket::ChallengePoll, &poll_client);
            Json(DashboardChallengeStatusResponse {
                status: "expired".to_string(),
                pending_login_id: None,
            })
            .into_response()
        }
        "denied" | "rejected" | "revoked" => {
            state
                .auth_attempts
                .lock()
                .unwrap()
                .clear_bucket(AuthAttemptBucket::ChallengePoll, &poll_client);
            Json(DashboardChallengeStatusResponse {
                status: "denied".to_string(),
                pending_login_id: None,
            })
            .into_response()
        }
        "pending" | "waiting" | "created" => Json(DashboardChallengeStatusResponse {
            status: "pending".to_string(),
            pending_login_id: None,
        })
        .into_response(),
        _ => {
            state
                .auth_attempts
                .lock()
                .unwrap()
                .clear_bucket(AuthAttemptBucket::ChallengePoll, &poll_client);
            Json(DashboardChallengeStatusResponse {
                status: "unavailable".to_string(),
                pending_login_id: None,
            })
            .into_response()
        }
    }
}

async fn auth_dashboard_ticket_exchange(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<DashboardTicketExchangeRequest>,
) -> Response {
    if *state.access_locked.lock().unwrap() {
        return access_paused_response();
    }
    if state.dashboard_auth.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            "Dashboard login is not configured on this host",
        )
            .into_response();
    }

    let now = Instant::now();
    let client = client_key_from_headers(&headers);
    {
        let mut attempts = state.auth_attempts.lock().unwrap();
        if let Some(wait) = attempts.retry_after(AuthAttemptBucket::ChallengePoll, &client, now) {
            return too_many_attempts_response(
                wait,
                "Too many approval checks. Wait a moment and try again.",
            );
        }
        attempts.record_attempt(AuthAttemptBucket::ChallengePoll, &client, now);
    }

    let ticket = req.dashboard_ticket.trim();
    if ticket.is_empty() {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "approval_expired",
            "This sign-in expired. Continue again.",
        );
    }

    let synthetic_challenge_id = format!("ticket:{ticket}");
    if let Some(existing) = state
        .dashboard_pending_logins
        .lock()
        .unwrap()
        .get_by_challenge(&synthetic_challenge_id, now)
    {
        state
            .auth_attempts
            .lock()
            .unwrap()
            .clear_bucket(AuthAttemptBucket::ChallengePoll, &client);
        return Json(DashboardTicketExchangeResponse {
            pending_login_id: existing,
        })
        .into_response();
    }

    match redeem_dashboard_ticket(&state, ticket).await {
        DashboardTicketRedeemResult::Approved => {
            state
                .auth_attempts
                .lock()
                .unwrap()
                .clear_bucket(AuthAttemptBucket::ChallengePoll, &client);
            let pending_login_id = state
                .dashboard_pending_logins
                .lock()
                .unwrap()
                .create(synthetic_challenge_id, now);
            Json(DashboardTicketExchangeResponse { pending_login_id }).into_response()
        }
        DashboardTicketRedeemResult::Expired => {
            state
                .auth_attempts
                .lock()
                .unwrap()
                .clear_bucket(AuthAttemptBucket::ChallengePoll, &client);
            api_error(
                StatusCode::UNAUTHORIZED,
                "approval_expired",
                "This sign-in expired. Continue again.",
            )
        }
        DashboardTicketRedeemResult::Denied => {
            state
                .auth_attempts
                .lock()
                .unwrap()
                .clear_bucket(AuthAttemptBucket::ChallengePoll, &client);
            api_error(
                StatusCode::FORBIDDEN,
                "approval_denied",
                "This sign-in was denied. Continue again.",
            )
        }
        DashboardTicketRedeemResult::Unavailable => {
            state
                .auth_attempts
                .lock()
                .unwrap()
                .clear_bucket(AuthAttemptBucket::ChallengePoll, &client);
            api_error(
                StatusCode::BAD_GATEWAY,
                "approval_unavailable",
                "Cannot finish sign-in right now. Try again in a moment.",
            )
        }
    }
}

async fn auth_login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Response {
    if *state.access_locked.lock().unwrap() {
        return access_paused_response();
    }

    let now = Instant::now();
    let client = client_key_from_headers(&headers);

    if let Some(pending_login_id) = req.dashboard_pending_login_id.as_deref() {
        {
            let mut attempts = state.auth_attempts.lock().unwrap();
            if let Some(wait) = attempts.retry_after(AuthAttemptBucket::Pin, &client, now) {
                return too_many_attempts_response(
                    wait,
                    "Too many PIN attempts. Wait a moment and try again.",
                );
            }
        }
        let pending_valid = state
            .dashboard_pending_logins
            .lock()
            .unwrap()
            .is_valid(pending_login_id, now);
        if !pending_valid {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "approval_expired",
                "This sign-in expired. Continue again.",
            );
        }

        if !verify_pin(req.pin.as_deref(), state.pin.as_deref()) {
            let still_valid = state
                .dashboard_pending_logins
                .lock()
                .unwrap()
                .record_pin_failure(pending_login_id, now);
            let mut attempts = state.auth_attempts.lock().unwrap();
            attempts.record_attempt(AuthAttemptBucket::Pin, &client, now);
            if let Some(wait) = attempts.retry_after(AuthAttemptBucket::Pin, &client, now) {
                return too_many_attempts_response(
                    wait,
                    "Too many PIN attempts. Wait a moment and try again.",
                );
            }
            if !still_valid {
                return api_error(
                    StatusCode::UNAUTHORIZED,
                    "approval_expired",
                    "This sign-in expired. Continue again.",
                );
            }
            return api_error(
                StatusCode::UNAUTHORIZED,
                "pin_invalid",
                "Incorrect machine PIN.",
            );
        }

        let consumed = state
            .dashboard_pending_logins
            .lock()
            .unwrap()
            .consume(pending_login_id, now);
        if !consumed {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "approval_expired",
                "This sign-in expired. Continue again.",
            );
        }

        state.auth_attempts.lock().unwrap().clear_login(&client);
        let session_token = {
            let mut sessions = state.sessions.lock().unwrap();
            sessions.create(now)
        };
        bump_shutdown_deadline_from_activity(&state, now);
        emit_dashboard_activity(
            &state,
            "machine.runtime.entry.dashboard_approval",
            "Completed dashboard-approved runtime sign-in",
            "success",
            None,
        )
        .await;
        let set_cookie = session_cookie_header(&session_token, headers_use_secure_cookie(&headers));
        return (StatusCode::OK, [(header::SET_COOKIE, set_cookie)], "OK").into_response();
    }

    let now_unix = unix_now();
    let password_ok = req
        .password
        .as_deref()
        .map(|password| check_token(password, &state.password))
        .unwrap_or(false);
    let sso_ticket = inspect_sso_ticket(&state, req.sso_ticket.as_deref(), now_unix);
    let sso_ok = sso_ticket.is_some();
    let dashboard_ok = verify_dashboard_ticket(&state, req.dashboard_ticket.as_deref()).await
        || verify_dashboard_token(&state, req.dashboard_token.as_deref()).await;
    let pin_ok = verify_pin(req.pin.as_deref(), state.pin.as_deref());
    let auth_factor_ok = password_ok || sso_ok || dashboard_ok;

    {
        let mut attempts = state.auth_attempts.lock().unwrap();
        if let Some(wait) = attempts.retry_after(AuthAttemptBucket::Credentials, &client, now) {
            return too_many_attempts_response(
                wait,
                "Too many sign-in attempts. Wait a moment and try again.",
            );
        }
        if auth_factor_ok {
            if let Some(wait) = attempts.retry_after(AuthAttemptBucket::Pin, &client, now) {
                return too_many_attempts_response(
                    wait,
                    "Too many PIN attempts. Wait a moment and try again.",
                );
            }
        }
    }

    if auth_factor_ok && pin_ok {
        if let Some(payload) = sso_ticket.as_ref() {
            if !consume_sso_ticket_nonce(&state, &payload.nonce, payload.exp, now_unix) {
                return api_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_sso_or_pin",
                    "Invalid sign-in link or machine PIN.",
                );
            }
        }
        state.auth_attempts.lock().unwrap().clear_login(&client);
        let session_token = {
            let mut sessions = state.sessions.lock().unwrap();
            sessions.create(now)
        };
        bump_shutdown_deadline_from_activity(&state, now);
        if sso_ok {
            emit_dashboard_activity(
                &state,
                "machine.runtime.entry.launch_url",
                "Opened runtime through launch URL",
                "success",
                None,
            )
            .await;
        } else if dashboard_ok {
            emit_dashboard_activity(
                &state,
                "machine.runtime.entry.dashboard_approval",
                "Completed dashboard-approved runtime sign-in",
                "success",
                None,
            )
            .await;
        } else if password_ok {
            emit_dashboard_activity(
                &state,
                "machine.runtime.entry.recovery_token",
                "Opened runtime with recovery token",
                "success",
                None,
            )
            .await;
        }
        let set_cookie = session_cookie_header(&session_token, headers_use_secure_cookie(&headers));
        return (StatusCode::OK, [(header::SET_COOKIE, set_cookie)], "OK").into_response();
    }

    let bucket = if auth_factor_ok {
        AuthAttemptBucket::Pin
    } else {
        AuthAttemptBucket::Credentials
    };
    let wait = {
        let mut attempts = state.auth_attempts.lock().unwrap();
        attempts.record_attempt(bucket, &client, now);
        attempts.retry_after(bucket, &client, now)
    };
    if let Some(wait) = wait {
        let message = if bucket == AuthAttemptBucket::Pin {
            "Too many PIN attempts. Wait a moment and try again."
        } else {
            "Too many sign-in attempts. Wait a moment and try again."
        };
        return too_many_attempts_response(wait, message);
    }
    let (code, message) = if req.sso_ticket.as_deref().is_some() {
        ("invalid_sso_or_pin", "Invalid sign-in link or machine PIN.")
    } else {
        (
            "invalid_credentials",
            "Incorrect access token or machine PIN.",
        )
    };
    api_error(StatusCode::UNAUTHORIZED, code, message)
}

fn api_error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        axum::Json(ApiErrorResponse {
            code: code.to_string(),
            message: message.to_string(),
        }),
    )
        .into_response()
}

fn too_many_attempts_response(wait: Duration, message: &str) -> Response {
    let wait_seconds = wait.as_secs().max(1).to_string();
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, wait_seconds)],
        axum::Json(ApiErrorResponse {
            code: "too_many_attempts".to_string(),
            message: message.to_string(),
        }),
    )
        .into_response()
}

fn access_paused_response() -> Response {
    api_error(
        StatusCode::LOCKED,
        "access_paused",
        "Sign-in is paused on this host. Restart CodeWebway to allow new sign-ins.",
    )
}

async fn auth_session(headers: HeaderMap, State(state): State<Arc<AppState>>) -> Response {
    if let Some(session_token) = has_valid_session_cookie(&headers, &state, true) {
        let set_cookie = session_cookie_header(&session_token, headers_use_secure_cookie(&headers));
        return (StatusCode::OK, [(header::SET_COOKIE, set_cookie)], "OK").into_response();
    }
    (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
}

async fn auth_session_status(headers: HeaderMap, State(state): State<Arc<AppState>>) -> Response {
    let Some(session_token) = has_valid_session_cookie(&headers, &state, true) else {
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

    let payload = SessionStatusResponse {
        remaining_idle_secs,
        remaining_absolute_secs,
        warning_window_secs: state.warning_window.as_secs(),
        read_only: grant.as_ref().map(|g| g.read_only).unwrap_or(false),
        bound_terminal_id: grant.as_ref().and_then(|g| g.bound_terminal_id.clone()),
        temp_link_id: grant.as_ref().map(|g| g.source_link_id.clone()),
    };
    let set_cookie = session_cookie_header(&session_token, headers_use_secure_cookie(&headers));
    (
        StatusCode::OK,
        [(header::SET_COOKIE, set_cookie)],
        Json(payload),
    )
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
    let set_cookie = session_cookie_header(&session_token, headers_use_secure_cookie(&headers));
    (StatusCode::OK, [(header::SET_COOKIE, set_cookie)], "OK").into_response()
}

async fn auth_stop_terminal(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<StopTerminalRequest>,
) -> Response {
    let Some(session_token) = has_valid_session_cookie(&headers, &state, false) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };
    if !verify_pin(req.pin.as_deref(), state.pin.as_deref()) {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "pin_invalid",
            "Incorrect machine PIN.",
        );
    }
    let now = Instant::now();
    if !state.sessions.lock().unwrap().is_valid(&session_token, now) {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    state.sessions.lock().unwrap().revoke_all();
    state.temp_grants.lock().unwrap().clear();
    state.temp_links.lock().unwrap().revoke_all(unix_now());
    state.terminals.lock().unwrap().remove_all();
    let _ = state.shutdown_tx.send(());

    (
        StatusCode::OK,
        [(
            header::SET_COOKIE,
            clear_session_cookie_header(headers_use_secure_cookie(&headers)),
        )],
        "OK",
    )
        .into_response()
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

    let requires_step_up = temp_link_requires_step_up(&scope, ttl_minutes, max_uses);
    if requires_step_up {
        let pin = req.pin.as_deref().map(str::trim).filter(|v| !v.is_empty());
        if state.pin.is_some() && pin.is_none() {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "pin_required",
                "Machine PIN required for interactive or extended share links.",
            );
        }
        if !verify_pin(pin, state.pin.as_deref()) {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "pin_invalid",
                "Incorrect machine PIN.",
            );
        }
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
    let (event_type, event_name) = classify_temp_link_creation(&scope, ttl_minutes, max_uses);
    emit_dashboard_activity(
        &state,
        event_type,
        event_name,
        "info",
        Some(format!(
            "scope={} ttl_minutes={} max_uses={} step_up={}",
            scope.as_str(),
            ttl_minutes,
            max_uses,
            requires_step_up
        )),
    )
    .await;
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
    headers: HeaderMap,
    AxumPath(token): AxumPath<String>,
    State(state): State<Arc<AppState>>,
) -> Response {
    if *state.access_locked.lock().unwrap() {
        return (
            StatusCode::LOCKED,
            "Sign-in is paused on this host. Restart CodeWebway to allow new sign-ins.",
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

    let inspected =
        state
            .temp_links
            .lock()
            .unwrap()
            .inspect(&parsed.id, now_unix, parsed.expires_at_unix);
    let Some((scope, _)) = inspected else {
        return temp_link_error_page(
            "Temporary link unavailable",
            "This link is no longer available (expired, revoked, or already used). Please request a new link.",
        );
    };

    if scope == TempLinkScope::Interactive && state.dashboard_auth.is_some() {
        return interactive_temp_link_approval_page(&token);
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
    emit_dashboard_activity(
        &state,
        "machine.temp_link.redeem.read_only",
        "Redeemed read-only share link",
        "success",
        None,
    )
    .await;

    let set_cookie = session_cookie_header(&session_token, headers_use_secure_cookie(&headers));
    let mut response = Redirect::to("/").into_response();
    if let Ok(value) = set_cookie.parse() {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

async fn auth_temp_link_interactive_challenge_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Query(query): Query<TempLinkChallengeQuery>,
) -> Response {
    if *state.access_locked.lock().unwrap() {
        return access_paused_response();
    }
    let Some(cfg) = state.dashboard_auth.as_ref() else {
        return (
            StatusCode::BAD_REQUEST,
            "Dashboard login is not configured on this host",
        )
            .into_response();
    };

    let parsed = match parse_and_verify_temp_link_token(&state.temp_link_signing_key, &query.token)
    {
        Some(parsed) => parsed,
        None => {
            return Json(TempLinkChallengeStatusResponse {
                status: "expired".to_string(),
                redirect_to: None,
            })
            .into_response()
        }
    };

    let now = Instant::now();
    let now_unix = unix_now();
    let inspected =
        state
            .temp_links
            .lock()
            .unwrap()
            .inspect(&parsed.id, now_unix, parsed.expires_at_unix);
    let Some((scope, _)) = inspected else {
        return Json(TempLinkChallengeStatusResponse {
            status: "expired".to_string(),
            redirect_to: None,
        })
        .into_response();
    };
    if scope != TempLinkScope::Interactive {
        return Json(TempLinkChallengeStatusResponse {
            status: "denied".to_string(),
            redirect_to: None,
        })
        .into_response();
    }

    let client = client_key_from_headers(&headers);
    let poll_client = format!("{client}:{id}:interactive");
    {
        let mut attempts = state.auth_attempts.lock().unwrap();
        if let Some(wait) =
            attempts.retry_after(AuthAttemptBucket::ChallengePoll, &poll_client, now)
        {
            return too_many_attempts_response(
                wait,
                "Too many approval checks. Wait a moment and try again.",
            );
        }
        attempts.record_attempt(AuthAttemptBucket::ChallengePoll, &poll_client, now);
    }

    let client = reqwest::Client::new();
    let url = format!(
        "{}/api/v1/agent/host-auth/challenge/{}",
        cfg.api_base.trim_end_matches('/'),
        id
    );
    let result = client
        .get(url)
        .bearer_auth(&cfg.machine_token)
        .timeout(Duration::from_secs(8))
        .send()
        .await;
    let response = match result {
        Ok(res) => res,
        Err(_) => return (StatusCode::BAD_GATEWAY, "Cannot reach dashboard API").into_response(),
    };
    if !response.status().is_success() {
        let status = match response.status() {
            StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND | StatusCode::GONE => "expired",
            StatusCode::FORBIDDEN => "denied",
            _ => "unavailable",
        };
        state
            .auth_attempts
            .lock()
            .unwrap()
            .clear_bucket(AuthAttemptBucket::ChallengePoll, &poll_client);
        return Json(TempLinkChallengeStatusResponse {
            status: status.to_string(),
            redirect_to: None,
        })
        .into_response();
    }
    let payload = match response.json::<FleetChallengeStatusEnvelope>().await {
        Ok(v) => v,
        Err(_) => {
            return (StatusCode::BAD_GATEWAY, "Invalid challenge status response").into_response()
        }
    };
    let upstream_status = payload.data.status.trim().to_ascii_lowercase();
    match upstream_status.as_str() {
        "approved" => {
            let Some(ticket) = payload.data.ticket.as_deref() else {
                return Json(TempLinkChallengeStatusResponse {
                    status: "unavailable".to_string(),
                    redirect_to: None,
                })
                .into_response();
            };
            match redeem_dashboard_ticket(&state, ticket).await {
                DashboardTicketRedeemResult::Approved => {
                    let redeemed = state.temp_links.lock().unwrap().redeem(
                        &parsed.id,
                        now_unix,
                        parsed.expires_at_unix,
                    );
                    let Some((link_id, scope, bound_terminal_id)) = redeemed else {
                        state
                            .auth_attempts
                            .lock()
                            .unwrap()
                            .clear_bucket(AuthAttemptBucket::ChallengePoll, &poll_client);
                        return Json(TempLinkChallengeStatusResponse {
                            status: "expired".to_string(),
                            redirect_to: None,
                        })
                        .into_response();
                    };
                    if scope != TempLinkScope::Interactive {
                        state
                            .auth_attempts
                            .lock()
                            .unwrap()
                            .clear_bucket(AuthAttemptBucket::ChallengePoll, &poll_client);
                        return Json(TempLinkChallengeStatusResponse {
                            status: "denied".to_string(),
                            redirect_to: None,
                        })
                        .into_response();
                    }

                    let session_token = {
                        let mut sessions = state.sessions.lock().unwrap();
                        sessions.create(now)
                    };
                    state.temp_grants.lock().unwrap().insert(
                        session_token.clone(),
                        TempSessionGrant {
                            read_only: false,
                            bound_terminal_id,
                            source_link_id: link_id,
                        },
                    );
                    bump_shutdown_deadline_from_activity(&state, now);
                    state
                        .auth_attempts
                        .lock()
                        .unwrap()
                        .clear_bucket(AuthAttemptBucket::ChallengePoll, &poll_client);
                    emit_dashboard_activity(
                        &state,
                        "machine.temp_link.redeem.interactive_owner_approved",
                        "Redeemed interactive share link after owner approval",
                        "success",
                        None,
                    )
                    .await;
                    let set_cookie =
                        session_cookie_header(&session_token, headers_use_secure_cookie(&headers));
                    (
                        StatusCode::OK,
                        [(header::SET_COOKIE, set_cookie)],
                        Json(TempLinkChallengeStatusResponse {
                            status: "approved".to_string(),
                            redirect_to: Some("/".to_string()),
                        }),
                    )
                        .into_response()
                }
                DashboardTicketRedeemResult::Expired => {
                    state
                        .auth_attempts
                        .lock()
                        .unwrap()
                        .clear_bucket(AuthAttemptBucket::ChallengePoll, &poll_client);
                    Json(TempLinkChallengeStatusResponse {
                        status: "expired".to_string(),
                        redirect_to: None,
                    })
                    .into_response()
                }
                DashboardTicketRedeemResult::Denied => {
                    state
                        .auth_attempts
                        .lock()
                        .unwrap()
                        .clear_bucket(AuthAttemptBucket::ChallengePoll, &poll_client);
                    Json(TempLinkChallengeStatusResponse {
                        status: "denied".to_string(),
                        redirect_to: None,
                    })
                    .into_response()
                }
                DashboardTicketRedeemResult::Unavailable => {
                    state
                        .auth_attempts
                        .lock()
                        .unwrap()
                        .clear_bucket(AuthAttemptBucket::ChallengePoll, &poll_client);
                    Json(TempLinkChallengeStatusResponse {
                        status: "unavailable".to_string(),
                        redirect_to: None,
                    })
                    .into_response()
                }
            }
        }
        "expired" => {
            state
                .auth_attempts
                .lock()
                .unwrap()
                .clear_bucket(AuthAttemptBucket::ChallengePoll, &poll_client);
            Json(TempLinkChallengeStatusResponse {
                status: "expired".to_string(),
                redirect_to: None,
            })
            .into_response()
        }
        "denied" | "rejected" | "revoked" => {
            state
                .auth_attempts
                .lock()
                .unwrap()
                .clear_bucket(AuthAttemptBucket::ChallengePoll, &poll_client);
            Json(TempLinkChallengeStatusResponse {
                status: "denied".to_string(),
                redirect_to: None,
            })
            .into_response()
        }
        "pending" | "waiting" | "created" => Json(TempLinkChallengeStatusResponse {
            status: "pending".to_string(),
            redirect_to: None,
        })
        .into_response(),
        _ => {
            state
                .auth_attempts
                .lock()
                .unwrap()
                .clear_bucket(AuthAttemptBucket::ChallengePoll, &poll_client);
            Json(TempLinkChallengeStatusResponse {
                status: "unavailable".to_string(),
                redirect_to: None,
            })
            .into_response()
        }
    }
}

async fn auth_public_status(State(state): State<Arc<AppState>>) -> Response {
    let remaining = shutdown_remaining_secs(&state, Instant::now());
    Json(PublicStatusResponse {
        shutdown_remaining_secs: remaining,
        access_locked: *state.access_locked.lock().unwrap(),
        auto_shutdown_disabled: state.auto_shutdown_disabled,
        sso_enabled: state.sso_shared_secret.is_some(),
        dashboard_login_enabled: state.dashboard_auth.is_some(),
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
            clear_session_cookie_header(headers_use_secure_cookie(&headers)),
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

async fn terminal_history(
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    State(state): State<Arc<AppState>>,
    Query(query): Query<TerminalHistoryQuery>,
) -> Response {
    let Some(session_token) = has_valid_session_cookie(&headers, &state, true) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };
    if let Some(bound_id) = session_bound_terminal_id(&state, &session_token) {
        if bound_id != id {
            return (
                StatusCode::FORBIDDEN,
                "Session is bound to another terminal",
            )
                .into_response();
        }
    }
    let Some(session) = state.terminals.lock().unwrap().get_session(&id) else {
        return (StatusCode::NOT_FOUND, "Terminal not found").into_response();
    };
    let page = {
        let mut session = session.lock().unwrap();
        session
            .history
            .page_before(query.before_seq, query.limit.unwrap_or(12))
    };
    let chunks: Vec<TerminalHistoryChunkResponse> = page
        .chunks
        .into_iter()
        .map(|chunk| TerminalHistoryChunkResponse {
            seq: chunk.seq,
            byte_len: chunk.bytes.len(),
            data_b64: STANDARD.encode(&chunk.bytes),
        })
        .collect();
    let payload = TerminalHistoryResponse {
        terminal_id: id,
        chunks,
        has_more: page.has_more,
        first_seq: page.first_seq,
        next_seq: page.next_seq,
        total_bytes: page.total_bytes,
        trimmed: page.trimmed,
    };
    count_tx_json(&state, &payload);
    Json(payload).into_response()
}

async fn terminal_tail(
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    State(state): State<Arc<AppState>>,
) -> Response {
    let Some(session_token) = has_valid_session_cookie(&headers, &state, true) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };
    if let Some(bound_id) = session_bound_terminal_id(&state, &session_token) {
        if bound_id != id {
            return (
                StatusCode::FORBIDDEN,
                "Session is bound to another terminal",
            )
                .into_response();
        }
    }
    let Some(session) = state.terminals.lock().unwrap().get_session(&id) else {
        return (StatusCode::NOT_FOUND, "Terminal not found").into_response();
    };
    let tail = {
        let mut session = session.lock().unwrap();
        session.history.live_tail()
    };
    let payload = TerminalTailResponse {
        terminal_id: id,
        data_b64: STANDARD.encode(&tail.bytes),
        first_seq: tail.first_seq,
        next_seq: tail.next_seq,
        total_bytes: tail.total_bytes,
        trimmed: tail.trimmed,
    };
    count_tx_json(&state, &payload);
    Json(payload).into_response()
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

async fn upload_file(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<UploadFileRequest>,
) -> Response {
    let Some(session_token) = has_valid_session_cookie(&headers, &state, true) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };
    if is_session_read_only(&state, &session_token) {
        return (
            StatusCode::FORBIDDEN,
            "Read-only sessions cannot upload files",
        )
            .into_response();
    }
    let bytes = match STANDARD.decode(req.data_b64.as_bytes()) {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid upload payload").into_response(),
    };
    if bytes.len() > MAX_UPLOAD_BYTES {
        return (StatusCode::BAD_REQUEST, "upload is too large").into_response();
    }
    count_rx(&state, bytes.len() as u64);

    let path = match resolve_user_write_path(&state.root_dir, &req.path) {
        Ok(path) => path,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };
    if path.is_dir() {
        return (StatusCode::BAD_REQUEST, "path must be a file").into_response();
    }
    let existed = path.exists();
    if existed && !req.overwrite.unwrap_or(false) {
        return (StatusCode::CONFLICT, "file already exists").into_response();
    }
    let Some(parent) = path.parent() else {
        return (StatusCode::BAD_REQUEST, "invalid upload path").into_response();
    };
    if let Err(err) = std::fs::create_dir_all(parent) {
        tracing::warn!("failed to create upload directory: {err}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "unable to create upload directory",
        )
            .into_response();
    }
    let temp_name = format!(
        ".codewebway-upload-{}",
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect::<String>()
    );
    let temp_path = parent.join(temp_name);
    if let Err(err) = std::fs::write(&temp_path, &bytes) {
        tracing::warn!("failed to write upload temp file: {err}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "unable to write upload").into_response();
    }
    if let Err(err) = std::fs::rename(&temp_path, &path) {
        let _ = std::fs::remove_file(&temp_path);
        tracing::warn!("failed to finalize upload: {err}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "unable to finalize upload",
        )
            .into_response();
    }
    let rel_path = rel_path_string(&state.root_dir, &path);
    let payload = UploadFileResponse {
        path: rel_path,
        size_bytes: bytes.len(),
        overwritten: existed,
    };
    count_tx_json(&state, &payload);
    (StatusCode::CREATED, Json(payload)).into_response()
}

async fn download_file(
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
    if path.is_dir() {
        return (StatusCode::BAD_REQUEST, "path must be a file").into_response();
    }
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::BAD_REQUEST, "unable to read file").into_response(),
    };
    count_tx(&state, bytes.len() as u64);
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download.bin")
        .replace('"', "'");
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(Body::from(bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn download_archive(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<ArchiveRequest>,
) -> Response {
    if has_valid_session_cookie(&headers, &state, true).is_none() {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }
    if req.paths.is_empty() {
        return (StatusCode::BAD_REQUEST, "no paths selected").into_response();
    }
    let mut archive_bytes = Vec::new();
    {
        let encoder =
            flate2::write::GzEncoder::new(&mut archive_bytes, flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);
        let mut total_bytes = 0u64;
        let mut entry_count = 0usize;
        for requested in req.paths.iter().take(256) {
            let path = match resolve_user_path(&state.root_dir, Some(requested)) {
                Ok(path) => path,
                Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
            };
            if let Err(err) = append_archive_path(
                &state.root_dir,
                &path,
                &mut builder,
                &mut total_bytes,
                &mut entry_count,
            ) {
                return (StatusCode::BAD_REQUEST, err).into_response();
            }
        }
        let encoder = match builder.into_inner() {
            Ok(encoder) => encoder,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "unable to finish archive",
                )
                    .into_response()
            }
        };
        if encoder.finish().is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "unable to finish archive",
            )
                .into_response();
        }
    }
    count_tx(&state, archive_bytes.len() as u64);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/gzip")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"codewebway-files.tar.gz\"",
        )
        .body(Body::from(archive_bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn move_paths(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<MovePathsRequest>,
) -> Response {
    let Some(session_token) = has_valid_session_cookie(&headers, &state, true) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };
    if is_session_read_only(&state, &session_token) {
        return (
            StatusCode::FORBIDDEN,
            "Read-only sessions cannot move files",
        )
            .into_response();
    }
    if req.paths.is_empty() {
        return (StatusCode::BAD_REQUEST, "no paths selected").into_response();
    }

    let target_dir = match resolve_user_path(&state.root_dir, Some(&req.target_dir)) {
        Ok(path) => path,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };
    if !target_dir.is_dir() {
        return (StatusCode::BAD_REQUEST, "target must be a directory").into_response();
    }

    let mut moves = Vec::new();
    for requested in req.paths.iter().take(256) {
        let source = match resolve_user_path(&state.root_dir, Some(requested)) {
            Ok(path) => path,
            Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
        };
        if source == target_dir {
            return (
                StatusCode::BAD_REQUEST,
                "cannot move a directory into itself",
            )
                .into_response();
        }
        if source.is_dir() && target_dir.starts_with(&source) {
            return (
                StatusCode::BAD_REQUEST,
                "cannot move a directory into one of its children",
            )
                .into_response();
        }
        let Some(file_name) = source.file_name() else {
            return (StatusCode::BAD_REQUEST, "invalid source path").into_response();
        };
        let dest = target_dir.join(file_name);
        if dest.exists() {
            return (StatusCode::CONFLICT, "destination already exists").into_response();
        }
        moves.push((source, dest));
    }

    let mut moved = 0usize;
    for (source, dest) in moves {
        if let Err(err) = std::fs::rename(&source, &dest) {
            tracing::warn!("failed to move file: {err}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "unable to move file").into_response();
        }
        moved += 1;
    }
    let payload = serde_json::json!({ "moved": moved });
    count_tx_json(&state, &payload);
    (StatusCode::OK, Json(payload)).into_response()
}

async fn delete_paths(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<DeletePathsRequest>,
) -> Response {
    let Some(session_token) = has_valid_session_cookie(&headers, &state, true) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };
    if is_session_read_only(&state, &session_token) {
        return (
            StatusCode::FORBIDDEN,
            "Read-only sessions cannot delete files",
        )
            .into_response();
    }
    if !verify_pin(req.pin.as_deref(), state.pin.as_deref()) {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "pin_invalid",
            "Incorrect machine PIN.",
        );
    }
    if req.paths.is_empty() {
        return (StatusCode::BAD_REQUEST, "no paths selected").into_response();
    }

    let mut paths = Vec::new();
    for requested in req.paths.iter().take(256) {
        let path = match resolve_user_path(&state.root_dir, Some(requested)) {
            Ok(path) => path,
            Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
        };
        if path == state.root_dir {
            return (StatusCode::BAD_REQUEST, "cannot delete workspace root").into_response();
        }
        paths.push(path);
    }

    let mut deleted = 0usize;
    for path in paths {
        let result = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        if let Err(err) = result {
            tracing::warn!("failed to delete file: {err}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "unable to delete file").into_response();
        }
        deleted += 1;
    }
    let payload = serde_json::json!({ "deleted": deleted });
    count_tx_json(&state, &payload);
    (StatusCode::OK, Json(payload)).into_response()
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
    let (tail, mut rx) = {
        let mut s = terminal.lock().unwrap();
        (s.history.live_tail(), s.tx.subscribe())
    };
    if !skip_scrollback && !tail.bytes.is_empty() {
        count_tx(&state, tail.bytes.len() as u64);
        let _ = socket.send(Message::Binary(tail.bytes)).await;
    }

    let mut session_tick = tokio::time::interval(Duration::from_secs(15));

    loop {
        tokio::select! {
            _ = session_tick.tick() => {
                if !touch_session_token_if_valid(&state, &session_token) {
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
                        if socket.send(Message::Binary(data.to_vec())).await.is_err() {
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

fn headers_use_secure_cookie(headers: &HeaderMap) -> bool {
    let forwarded_proto = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .map(|value| value.eq_ignore_ascii_case("https"))
        .unwrap_or(false);
    if forwarded_proto {
        return true;
    }
    for header_name in [header::ORIGIN, header::REFERER] {
        if headers
            .get(header_name)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.starts_with("https://"))
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

fn session_cookie_header(session_token: &str, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "codewebway_session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800{}",
        session_token, secure_attr
    )
}

fn clear_session_cookie_header(secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "codewebway_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{}",
        secure_attr
    )
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
    let raw_cookie = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())?;
    cookie_value(raw_cookie, "codewebway_session").map(|value| value.to_string())
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
    if let Some(cf_connecting_ip) = headers
        .get("cf-connecting-ip")
        .and_then(|value| value.to_str().ok())
    {
        let trimmed = cf_connecting_ip.trim();
        if !trimmed.is_empty() {
            return format!("ip:{trimmed}");
        }
    }
    if let Some(forwarded) = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
    {
        if let Some(client) = forwarded.split(',').next() {
            let trimmed = client.trim();
            if !trimmed.is_empty() {
                return format!("ip:{trimmed}");
            }
        }
    }
    if let Some(real_ip) = headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
    {
        let trimmed = real_ip.trim();
        if !trimmed.is_empty() {
            return format!("ip:{trimmed}");
        }
    }

    let mut fingerprint_parts = Vec::new();
    for header_name in [
        "user-agent",
        "sec-ch-ua-platform",
        "accept-language",
        "host",
    ] {
        if let Some(value) = headers.get(header_name).and_then(|v| v.to_str().ok()) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                fingerprint_parts.push(trimmed);
            }
        }
    }
    if fingerprint_parts.is_empty() {
        return "client:anonymous".to_string();
    }
    let digest = hash_bytes_hex(fingerprint_parts.join("|").as_bytes());
    format!("fp:{}", &digest[..16])
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

fn temp_link_requires_step_up(scope: &TempLinkScope, ttl_minutes: u64, max_uses: u32) -> bool {
    matches!(scope, TempLinkScope::Interactive) || ttl_minutes > 15 || max_uses > 1
}

fn classify_temp_link_creation(
    scope: &TempLinkScope,
    ttl_minutes: u64,
    max_uses: u32,
) -> (&'static str, &'static str) {
    if *scope == TempLinkScope::ReadOnly && ttl_minutes == 5 && max_uses == 1 {
        (
            "machine.temp_link.create.view_once",
            "Created View Once share link",
        )
    } else if *scope == TempLinkScope::Interactive && ttl_minutes == 15 && max_uses == 1 {
        (
            "machine.temp_link.create.collaborate_once",
            "Created Collaborate Once share link",
        )
    } else {
        (
            "machine.temp_link.create.advanced",
            "Created advanced share link",
        )
    }
}

#[derive(Deserialize)]
struct SsoTicketPayload {
    sub: String,
    nonce: String,
    exp: u64,
    #[serde(default)]
    instance: Option<String>,
}

fn inspect_sso_ticket(
    state: &Arc<AppState>,
    ticket: Option<&str>,
    now_unix: u64,
) -> Option<SsoTicketPayload> {
    let secret = state.sso_shared_secret.as_deref()?;
    let ticket = ticket?;
    let mut parts = ticket.split('.');
    let payload_b64 = match parts.next() {
        Some(v) if !v.is_empty() => v,
        _ => return None,
    };
    let sig_hex = match parts.next() {
        Some(v) if !v.is_empty() => v,
        _ => return None,
    };
    if parts.next().is_some() {
        return None;
    }

    let expected = sso_ticket_signature(secret, payload_b64);
    if !check_token(sig_hex, &expected) {
        return None;
    }
    let payload_bytes = match URL_SAFE_NO_PAD.decode(payload_b64) {
        Ok(v) => v,
        Err(_) => return None,
    };
    let payload: SsoTicketPayload = match serde_json::from_slice(&payload_bytes) {
        Ok(v) => v,
        Err(_) => return None,
    };
    if payload.sub.trim().is_empty() || payload.nonce.len() < 16 || payload.nonce.len() > 128 {
        return None;
    }
    if let Some(expected_instance) = state.runtime_instance_id.as_deref() {
        if payload.instance.as_deref() != Some(expected_instance) {
            return None;
        }
    }
    if payload.exp.saturating_add(SSO_TICKET_CLOCK_SKEW_SECS) < now_unix
        || payload.exp > now_unix.saturating_add(5 * 60 + SSO_TICKET_CLOCK_SKEW_SECS)
    {
        return None;
    }
    Some(payload)
}

fn consume_sso_ticket_nonce(state: &Arc<AppState>, nonce: &str, exp: u64, now_unix: u64) -> bool {
    // Single-use nonce blocks replay if ticket leaks in logs/history.
    let mut used = state.used_sso_nonces.lock().unwrap();
    used.retain(|_, exp| *exp >= now_unix);
    if used.contains_key(nonce) {
        return false;
    }
    used.insert(nonce.to_string(), exp);
    true
}

async fn verify_dashboard_token(state: &Arc<AppState>, dashboard_token: Option<&str>) -> bool {
    let Some(cfg) = state.dashboard_auth.as_ref() else {
        return false;
    };
    let Some(user_token) = dashboard_token else {
        return false;
    };
    if user_token.trim().is_empty() {
        return false;
    }

    let client = reqwest::Client::new();
    let url = format!(
        "{}/api/v1/agent/host-auth/verify",
        cfg.api_base.trim_end_matches('/')
    );
    let response = client
        .post(url)
        .bearer_auth(&cfg.machine_token)
        .json(&serde_json::json!({ "user_token": user_token }))
        .timeout(Duration::from_secs(8))
        .send()
        .await;

    match response {
        Ok(res) => res.status().is_success(),
        Err(_) => false,
    }
}

enum DashboardTicketRedeemResult {
    Approved,
    Expired,
    Denied,
    Unavailable,
}

async fn redeem_dashboard_ticket(
    state: &Arc<AppState>,
    dashboard_ticket: &str,
) -> DashboardTicketRedeemResult {
    let Some(cfg) = state.dashboard_auth.as_ref() else {
        return DashboardTicketRedeemResult::Unavailable;
    };
    if dashboard_ticket.trim().is_empty() {
        return DashboardTicketRedeemResult::Expired;
    }

    let client = reqwest::Client::new();
    let url = format!(
        "{}/api/v1/agent/host-auth/redeem",
        cfg.api_base.trim_end_matches('/')
    );
    let response = client
        .post(url)
        .bearer_auth(&cfg.machine_token)
        .json(&serde_json::json!({ "ticket": dashboard_ticket }))
        .timeout(Duration::from_secs(8))
        .send()
        .await;

    match response {
        Ok(res) if res.status().is_success() => DashboardTicketRedeemResult::Approved,
        Ok(res)
            if matches!(
                res.status(),
                StatusCode::BAD_REQUEST
                    | StatusCode::NOT_FOUND
                    | StatusCode::GONE
                    | StatusCode::UNPROCESSABLE_ENTITY
            ) =>
        {
            DashboardTicketRedeemResult::Expired
        }
        Ok(res) if res.status() == StatusCode::FORBIDDEN => DashboardTicketRedeemResult::Denied,
        Ok(_) => DashboardTicketRedeemResult::Unavailable,
        Err(_) => DashboardTicketRedeemResult::Unavailable,
    }
}

async fn verify_dashboard_ticket(state: &Arc<AppState>, dashboard_ticket: Option<&str>) -> bool {
    let Some(ticket) = dashboard_ticket else {
        return false;
    };
    matches!(
        redeem_dashboard_ticket(state, ticket).await,
        DashboardTicketRedeemResult::Approved
    )
}

fn bump_shutdown_deadline_from_activity(state: &Arc<AppState>, now: Instant) {
    let next_deadline = now + state.idle_timeout + state.shutdown_grace;
    let mut deadline = state.shutdown_deadline.lock().unwrap();
    *deadline = next_deadline;
}

pub fn shutdown_remaining_secs(state: &Arc<AppState>, now: Instant) -> u64 {
    if state.auto_shutdown_disabled {
        return u64::MAX;
    }
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

fn sso_ticket_signature(secret: &str, payload_b64: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(payload_b64.as_bytes());
    let sig = mac.finalize().into_bytes();
    let mut out = String::with_capacity(sig.len() * 2);
    for byte in sig {
        out.push_str(&format!("{byte:02x}"));
    }
    out
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

fn interactive_temp_link_approval_page(token: &str) -> Response {
    let token_json = serde_json::to_string(token).unwrap_or_else(|_| "\"\"".to_string());
    let html = format!(
        r##"<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Interactive Share Approval</title>
  <style>
    body {{
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif;
      background: #0f1115;
      color: #e5e7eb;
      display: flex;
      min-height: 100vh;
      align-items: center;
      justify-content: center;
      padding: 24px;
      margin: 0;
    }}
    .card {{
      width: min(560px, 100%);
      background: #171a20;
      border: 1px solid #313642;
      border-radius: 16px;
      padding: 24px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.35);
    }}
    h1 {{ margin: 0 0 10px; font-size: 22px; }}
    p {{ margin: 0 0 14px; color: #b9c0cb; line-height: 1.6; }}
    .status {{
      margin: 16px 0;
      padding: 14px;
      border-radius: 12px;
      border: 1px solid #313642;
      background: #101319;
      color: #dbe2ea;
      font-size: 14px;
      line-height: 1.5;
      white-space: pre-line;
    }}
    .actions {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-top: 16px;
    }}
    a, button {{
      appearance: none;
      border: 1px solid #3d4654;
      background: #202632;
      color: #f3f4f6;
      border-radius: 10px;
      padding: 10px 14px;
      font-size: 14px;
      text-decoration: none;
      cursor: pointer;
    }}
    button.secondary, a.secondary {{
      background: transparent;
      color: #c6d0dc;
    }}
    .muted {{ color: #97a3b6; font-size: 13px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Interactive Access Needs Owner Approval</h1>
    <p>This share link can open an interactive session only after the machine owner confirms it from the dashboard.</p>
    <div id="status" class="status">Creating approval request…</div>
    <div class="actions">
      <a id="approve-link" href="#" target="_blank" rel="noopener noreferrer" style="display:none;">Open Owner Approval</a>
      <button id="copy-link" class="secondary" type="button" style="display:none;">Copy Approval Link</button>
      <button id="retry" class="secondary" type="button" style="display:none;">Retry</button>
    </div>
    <p class="muted">Keep this page open. It will continue automatically after approval.</p>
  </div>
  <script>
    const token = {token_json};
    const statusEl = document.getElementById('status');
    const approveLinkEl = document.getElementById('approve-link');
    const copyLinkBtn = document.getElementById('copy-link');
    const retryBtn = document.getElementById('retry');
    let challengeId = null;

    async function readProblem(res) {{
      const type = res.headers.get('content-type') || '';
      if (type.includes('application/json')) {{
        try {{
          return await res.json();
        }} catch {{
          return null;
        }}
      }}
      try {{
        const text = await res.text();
        return text ? {{ message: text }} : null;
      }} catch {{
        return null;
      }}
    }}

    async function startApproval() {{
      retryBtn.style.display = 'none';
      statusEl.textContent = 'Creating approval request…';
      const res = await fetch('/auth/dashboard/challenge', {{ method: 'POST', credentials: 'same-origin' }});
      if (!res.ok) {{
        const problem = await readProblem(res);
        statusEl.textContent = problem?.message || 'Cannot create approval request right now. Try again in a moment.';
        retryBtn.style.display = 'inline-flex';
        return;
      }}
      const challenge = await res.json();
      challengeId = challenge.challenge_id;
      approveLinkEl.href = challenge.approve_url;
      approveLinkEl.style.display = 'inline-flex';
      copyLinkBtn.style.display = 'inline-flex';
      statusEl.textContent = 'Waiting for the machine owner to approve this interactive share.\nOpen the owner approval page in another tab or send it to the owner.';
      void pollApproval();
    }}

    async function pollApproval() {{
      while (challengeId) {{
        await new Promise((resolve) => setTimeout(resolve, 900));
        const res = await fetch(`/auth/temp-links/interactive/challenge/${{encodeURIComponent(challengeId)}}?token=${{encodeURIComponent(token)}}`, {{
          method: 'GET',
          credentials: 'same-origin'
        }});
        if (res.status === 429) {{
          statusEl.textContent = 'Checking too often. Waiting a moment before trying again…';
          await new Promise((resolve) => setTimeout(resolve, 1500));
          continue;
        }}
        if (!res.ok) {{
          const problem = await readProblem(res);
          statusEl.textContent = problem?.message || 'Cannot check approval right now. Try again in a moment.';
          retryBtn.style.display = 'inline-flex';
          return;
        }}
        const body = await res.json();
        if (body.status === 'pending') {{
          continue;
        }}
        if (body.status === 'approved') {{
          statusEl.textContent = 'Approved. Opening interactive workspace…';
          window.location.assign(body.redirect_to || '/');
          return;
        }}
        if (body.status === 'denied') {{
          statusEl.textContent = 'The machine owner denied this interactive access request.';
          retryBtn.style.display = 'inline-flex';
          return;
        }}
        if (body.status === 'expired') {{
          statusEl.textContent = 'This share link or approval request expired. Ask the sender for a fresh link.';
          retryBtn.style.display = 'inline-flex';
          return;
        }}
        statusEl.textContent = 'Approval is temporarily unavailable. Try again in a moment.';
        retryBtn.style.display = 'inline-flex';
        return;
      }}
    }}

    copyLinkBtn.addEventListener('click', async () => {{
      if (!approveLinkEl.href || approveLinkEl.href === '#') return;
      await navigator.clipboard?.writeText(approveLinkEl.href).catch(() => {{}});
      statusEl.textContent = 'Approval link copied. Waiting for the machine owner to approve this interactive share.';
    }});
    retryBtn.addEventListener('click', () => {{
      challengeId = null;
      startApproval();
    }});

    startApproval();
  </script>
</body>
</html>"##
    );
    Html(html).into_response()
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

fn rel_path_string(root_dir: &Path, path: &Path) -> String {
    path.strip_prefix(root_dir)
        .ok()
        .map(|p| p.to_string_lossy().to_string())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| ".".to_string())
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

    // Join with the trusted root_dir then canonicalize in one step.
    // canonicalize() fails when the path does not exist, which replaces
    // the earlier explicit exists() check and avoids operating on an
    // intermediate path that still carries user-supplied components.
    let canonical = root_dir
        .join(rel_path)
        .canonicalize()
        .map_err(|_| "path does not exist")?;

    if !canonical.starts_with(root_dir) {
        return Err("path is outside allowed root");
    }
    Ok(canonical)
}

fn resolve_user_write_path(root_dir: &Path, requested: &str) -> Result<PathBuf, &'static str> {
    let rel_path = Path::new(requested);
    if requested.trim().is_empty() {
        return Err("path is required");
    }
    if rel_path.is_absolute() {
        return Err("absolute paths are not allowed");
    }
    if rel_path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("parent path segments are not allowed");
    }
    let parent = rel_path.parent().unwrap_or_else(|| Path::new("."));
    let requested_parent = root_dir.join(parent);
    let mut existing_parent = requested_parent.as_path();
    while !existing_parent.exists() {
        existing_parent = existing_parent
            .parent()
            .ok_or("parent path does not exist")?;
    }
    let canonical_parent = existing_parent
        .canonicalize()
        .map_err(|_| "parent path does not exist")?;
    if !canonical_parent.starts_with(root_dir) || !requested_parent.starts_with(root_dir) {
        return Err("path is outside allowed root");
    }
    let Some(file_name) = rel_path.file_name() else {
        return Err("path must include a file name");
    };
    Ok(requested_parent.join(file_name))
}

fn append_archive_path(
    root_dir: &Path,
    path: &Path,
    builder: &mut tar::Builder<flate2::write::GzEncoder<&mut Vec<u8>>>,
    total_bytes: &mut u64,
    entry_count: &mut usize,
) -> Result<(), &'static str> {
    if *entry_count >= MAX_ARCHIVE_ENTRIES {
        return Err("archive has too many entries");
    }
    let rel = path
        .strip_prefix(root_dir)
        .map_err(|_| "path is outside allowed root")?;
    let meta = std::fs::metadata(path).map_err(|_| "unable to read archive path")?;
    if meta.is_file() {
        *total_bytes = total_bytes.saturating_add(meta.len());
        if *total_bytes > MAX_ARCHIVE_BYTES {
            return Err("archive is too large");
        }
        builder
            .append_path_with_name(path, rel)
            .map_err(|_| "unable to add file to archive")?;
        *entry_count += 1;
        return Ok(());
    }
    if meta.is_dir() {
        builder
            .append_dir(rel, path)
            .map_err(|_| "unable to add directory to archive")?;
        *entry_count += 1;
        let read_dir = std::fs::read_dir(path).map_err(|_| "unable to read directory")?;
        for entry in read_dir.filter_map(Result::ok) {
            append_archive_path(root_dir, &entry.path(), builder, total_bytes, entry_count)?;
        }
        return Ok(());
    }
    Err("unsupported archive path")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correct_token() {
        assert!(check_token("xyzzy_test_input", "xyzzy_test_input"));
    }

    #[test]
    fn test_wrong_token() {
        assert!(!check_token("wrong_input", "xyzzy_test_input"));
    }

    #[test]
    fn test_empty_token() {
        assert!(!check_token("", "xyzzy_test_input"));
    }

    #[test]
    fn test_token_length_mismatch() {
        assert!(!check_token("xyzzy", "xyzzy_test_input"));
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
    fn test_sanitize_embedded_asset_path_accepts_nested_vendor_asset() {
        assert_eq!(
            sanitize_embedded_asset_path("vendor/xterm.min.js").as_deref(),
            Some("vendor/xterm.min.js")
        );
    }

    #[test]
    fn test_sanitize_embedded_asset_path_rejects_parent_segments() {
        assert_eq!(sanitize_embedded_asset_path("../index.html"), None);
        assert_eq!(sanitize_embedded_asset_path("vendor/../../secret"), None);
    }

    #[test]
    fn test_embedded_asset_content_type_for_vendor_assets() {
        assert_eq!(
            embedded_asset_content_type("vendor/xterm.min.css"),
            "text/css; charset=utf-8"
        );
        assert_eq!(
            embedded_asset_content_type("vendor/xterm.min.js"),
            "application/javascript; charset=utf-8"
        );
    }

    #[test]
    fn test_auth_attempt_tracker_separates_buckets() {
        let mut tracker = AuthAttemptTracker::new();
        let now = Instant::now();
        for _ in 0..CREDENTIAL_ATTEMPT_MAX {
            tracker.record_attempt(AuthAttemptBucket::Credentials, "ip:1.2.3.4", now);
        }
        assert!(tracker
            .retry_after(AuthAttemptBucket::Credentials, "ip:1.2.3.4", now)
            .is_some());
        assert_eq!(
            tracker.retry_after(AuthAttemptBucket::Pin, "ip:1.2.3.4", now),
            None
        );
    }

    #[test]
    fn test_client_key_from_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.8, 10.0.0.1".parse().unwrap());
        assert_eq!(client_key_from_headers(&headers), "ip:203.0.113.8");
    }

    #[test]
    fn test_client_key_from_headers_uses_fingerprint_without_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "Mozilla/5.0".parse().unwrap());
        headers.insert("accept-language", "en-US".parse().unwrap());
        let key = client_key_from_headers(&headers);
        assert!(key.starts_with("fp:"));
        assert_ne!(key, "client:anonymous");
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
    fn test_dashboard_pending_login_reuses_same_challenge() {
        let mut store = DashboardPendingLoginStore::new(Duration::from_secs(15 * 60), 5);
        let now = Instant::now();
        let first = store.create("challenge-1".to_string(), now);
        let second = store.create("challenge-1".to_string(), now + Duration::from_secs(1));
        assert_eq!(first, second);
        assert!(store.is_valid(&first, now + Duration::from_secs(2)));
    }

    #[test]
    fn test_dashboard_pending_login_expires_after_pin_failures() {
        let mut store = DashboardPendingLoginStore::new(Duration::from_secs(15 * 60), 2);
        let now = Instant::now();
        let pending = store.create("challenge-2".to_string(), now);
        assert!(store.record_pin_failure(&pending, now + Duration::from_secs(1)));
        assert!(!store.record_pin_failure(&pending, now + Duration::from_secs(2)));
        assert!(!store.is_valid(&pending, now + Duration::from_secs(3)));
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
    fn test_headers_use_secure_cookie_when_forwarded_proto_is_https() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(headers_use_secure_cookie(&headers));
    }

    #[test]
    fn test_headers_use_secure_cookie_false_for_plain_http() {
        let headers = HeaderMap::new();
        assert!(!headers_use_secure_cookie(&headers));
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
    fn test_write_path_allows_missing_upload_parent_inside_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let path = resolve_user_write_path(&root, "uploaded/photo.png").unwrap();
        assert_eq!(path, root.join("uploaded/photo.png"));
    }

    #[cfg(unix)]
    #[test]
    fn test_write_path_rejects_missing_child_under_symlink_escape() {
        let root_dir = tempfile::tempdir().unwrap();
        let outside_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path().canonicalize().unwrap();
        let outside = outside_dir.path().canonicalize().unwrap();
        std::os::unix::fs::symlink(&outside, root.join("outside")).unwrap();
        assert_eq!(
            resolve_user_write_path(&root, "outside/new/file.txt"),
            Err("path is outside allowed root")
        );
    }

    #[test]
    fn test_temp_link_requires_step_up_for_interactive_scope() {
        assert!(temp_link_requires_step_up(
            &TempLinkScope::Interactive,
            DEFAULT_TEMP_LINK_TTL_MINUTES,
            1
        ));
    }

    #[test]
    fn test_temp_link_requires_step_up_for_long_ttl() {
        assert!(temp_link_requires_step_up(&TempLinkScope::ReadOnly, 60, 1));
    }

    #[test]
    fn test_temp_link_requires_step_up_for_multi_use() {
        assert!(temp_link_requires_step_up(&TempLinkScope::ReadOnly, 15, 5));
    }

    #[test]
    fn test_temp_link_allows_low_risk_defaults_without_step_up() {
        assert!(!temp_link_requires_step_up(
            &TempLinkScope::ReadOnly,
            DEFAULT_TEMP_LINK_TTL_MINUTES,
            1
        ));
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
    fn test_temp_link_inspect_does_not_consume_use() {
        let mut store = TempLinkStore::new();
        let now = 1_700_000_000u64;
        let record = store
            .create(
                now,
                15,
                1,
                TempLinkScope::Interactive,
                Some("term-1".to_string()),
                "session-main".to_string(),
            )
            .unwrap();

        let inspected = store.inspect(&record.id, now + 1, record.expires_at_unix);
        assert!(matches!(
            inspected,
            Some((TempLinkScope::Interactive, Some(bound_terminal_id)))
                if bound_terminal_id == "term-1"
        ));

        let redeemed = store.redeem(&record.id, now + 2, record.expires_at_unix);
        assert!(redeemed.is_some());

        let second = store.redeem(&record.id, now + 3, record.expires_at_unix);
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

    #[test]
    fn test_inspect_sso_ticket_does_not_consume_before_success() {
        let state =
            make_state_with_sso(false, Some("0123456789abcdef0123456789abcdef".to_string()));
        let now = unix_now();
        let payload = serde_json::json!({
            "sub": "user_123",
            "nonce": "nonce_1234567890abcd",
            "exp": now + 120
        });
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let sig = sso_ticket_signature(state.sso_shared_secret.as_deref().unwrap(), &payload_b64);
        let ticket = format!("{payload_b64}.{sig}");

        let inspected = inspect_sso_ticket(&state, Some(&ticket), now).expect("valid ticket");
        assert!(inspect_sso_ticket(&state, Some(&ticket), now).is_some());
        assert!(consume_sso_ticket_nonce(
            &state,
            &inspected.nonce,
            inspected.exp,
            now
        ));
        assert!(!consume_sso_ticket_nonce(
            &state,
            &inspected.nonce,
            inspected.exp,
            now
        ));
    }

    #[test]
    fn test_inspect_sso_ticket_rejects_bad_signature() {
        let state =
            make_state_with_sso(false, Some("0123456789abcdef0123456789abcdef".to_string()));
        let now = unix_now();
        let payload = serde_json::json!({
            "sub": "user_123",
            "nonce": "nonce_1234567890abcd",
            "exp": now + 120
        });
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let ticket = format!("{payload_b64}.deadbeef");
        assert!(inspect_sso_ticket(&state, Some(&ticket), now).is_none());
    }

    #[test]
    fn test_inspect_sso_ticket_rejects_wrong_runtime_instance() {
        let state = make_state_with_sso_and_instance(
            false,
            Some("0123456789abcdef0123456789abcdef".to_string()),
            "instance-current".to_string(),
        );
        let now = unix_now();
        let payload = serde_json::json!({
            "sub": "user_123",
            "nonce": "nonce_runtime_instance",
            "exp": now + 120,
            "instance": "instance-old"
        });
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let sig = sso_ticket_signature("0123456789abcdef0123456789abcdef", &payload_b64);
        let ticket = format!("{payload_b64}.{sig}");
        assert!(inspect_sso_ticket(&state, Some(&ticket), now).is_none());
    }

    #[test]
    fn sso_ticket_accepts_within_clock_skew() {
        // exp = now - 25s should pass (within 30s leeway)
        let state =
            make_state_with_sso(false, Some("0123456789abcdef0123456789abcdef".to_string()));
        let now = unix_now();
        let payload = serde_json::json!({
            "sub": "user_clock_skew_ok",
            "nonce": "nonce_clock_skew_ok_12345",
            "exp": now - 25
        });
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let sig = sso_ticket_signature(state.sso_shared_secret.as_deref().unwrap(), &payload_b64);
        let ticket = format!("{payload_b64}.{sig}");
        assert!(
            inspect_sso_ticket(&state, Some(&ticket), now).is_some(),
            "ticket expired 25s ago should be accepted within 30s clock skew"
        );
    }

    #[test]
    fn sso_ticket_rejects_outside_clock_skew() {
        // exp = now - 35s should reject (beyond 30s leeway)
        let state =
            make_state_with_sso(false, Some("0123456789abcdef0123456789abcdef".to_string()));
        let now = unix_now();
        let payload = serde_json::json!({
            "sub": "user_clock_skew_fail",
            "nonce": "nonce_clock_skew_fail_1234",
            "exp": now - 35
        });
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let sig = sso_ticket_signature(state.sso_shared_secret.as_deref().unwrap(), &payload_b64);
        let ticket = format!("{payload_b64}.{sig}");
        assert!(
            inspect_sso_ticket(&state, Some(&ticket), now).is_none(),
            "ticket expired 35s ago should be rejected beyond 30s clock skew"
        );
    }

    fn make_state(terminal_only: bool) -> Arc<AppState> {
        make_state_with_sso(terminal_only, None)
    }

    fn make_state_with_sso(
        terminal_only: bool,
        sso_shared_secret: Option<String>,
    ) -> Arc<AppState> {
        use std::time::{Duration, Instant};
        Arc::new(AppState {
            password: "token".to_string(),
            pin: None,
            auth_attempts: Mutex::new(AuthAttemptTracker::new()),
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
            dashboard_pending_logins: Mutex::new(DashboardPendingLoginStore::new(
                Duration::from_secs(DASHBOARD_PENDING_LOGIN_TTL_SECS),
                DASHBOARD_PENDING_LOGIN_MAX_PIN_ATTEMPTS,
            )),
            temp_link_signing_key: "signingkey123456789012345678901234567890123456".to_string(),
            auto_shutdown_disabled: false,
            terminal_only,
            runtime_instance_id: None,
            sso_shared_secret,
            used_sso_nonces: Mutex::new(std::collections::HashMap::new()),
            dashboard_auth: None,
        })
    }

    fn make_state_with_sso_and_instance(
        terminal_only: bool,
        sso_shared_secret: Option<String>,
        runtime_instance_id: String,
    ) -> Arc<AppState> {
        let mut state = make_state_with_sso(terminal_only, sso_shared_secret);
        Arc::get_mut(&mut state).unwrap().runtime_instance_id = Some(runtime_instance_id);
        state
    }

    fn make_state_with_pin_and_shutdown(
        pin: Option<String>,
    ) -> (Arc<AppState>, tokio::sync::mpsc::UnboundedReceiver<()>) {
        use std::time::{Duration, Instant};
        let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let state = Arc::new(AppState {
            password: "token".to_string(),
            pin,
            auth_attempts: Mutex::new(AuthAttemptTracker::new()),
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
            shutdown_tx,
            temp_links: Mutex::new(TempLinkStore::new()),
            temp_grants: Mutex::new(std::collections::HashMap::new()),
            dashboard_pending_logins: Mutex::new(DashboardPendingLoginStore::new(
                Duration::from_secs(DASHBOARD_PENDING_LOGIN_TTL_SECS),
                DASHBOARD_PENDING_LOGIN_MAX_PIN_ATTEMPTS,
            )),
            temp_link_signing_key: "signingkey123456789012345678901234567890123456".to_string(),
            auto_shutdown_disabled: false,
            terminal_only: false,
            runtime_instance_id: None,
            sso_shared_secret: None,
            used_sso_nonces: Mutex::new(std::collections::HashMap::new()),
            dashboard_auth: None,
        });
        (state, shutdown_rx)
    }

    #[tokio::test]
    async fn test_capabilities_terminal_only_false() {
        use axum::{body::Body, http::Request};
        use tower::util::ServiceExt;
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
    async fn test_stop_terminal_requires_valid_pin_and_does_not_pause_sign_in() {
        use axum::{body::Body, http::Request};
        use tower::util::ServiceExt;

        let (state, mut shutdown_rx) = make_state_with_pin_and_shutdown(Some("4321".to_string()));
        let session_token = state.sessions.lock().unwrap().create(Instant::now());
        let app = router(state.clone());
        let req = Request::builder()
            .method("POST")
            .uri("/auth/stop-terminal")
            .header(
                header::COOKIE,
                format!("codewebway_session={session_token}"),
            )
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"pin":"4321"}"#))
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(shutdown_rx.try_recv().is_ok());
        assert!(!*state.access_locked.lock().unwrap());
        assert!(!state
            .sessions
            .lock()
            .unwrap()
            .is_valid(&session_token, Instant::now()));
    }

    #[tokio::test]
    async fn test_stop_terminal_rejects_wrong_pin() {
        use axum::{body::Body, http::Request};
        use tower::util::ServiceExt;

        let (state, mut shutdown_rx) = make_state_with_pin_and_shutdown(Some("4321".to_string()));
        let session_token = state.sessions.lock().unwrap().create(Instant::now());
        let app = router(state.clone());
        let req = Request::builder()
            .method("POST")
            .uri("/auth/stop-terminal")
            .header(
                header::COOKIE,
                format!("codewebway_session={session_token}"),
            )
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"pin":"0000"}"#))
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert!(shutdown_rx.try_recv().is_err());
        assert!(!*state.access_locked.lock().unwrap());
        assert!(state
            .sessions
            .lock()
            .unwrap()
            .is_valid(&session_token, Instant::now()));
    }

    #[tokio::test]
    async fn test_auth_session_status_touches_idle_session() {
        use axum::{body::Body, http::Request};
        use tower::util::ServiceExt;

        let state = make_state(false);
        let now = Instant::now();
        let session_token = state.sessions.lock().unwrap().create(now);
        {
            let mut sessions = state.sessions.lock().unwrap();
            let record = sessions.by_token.get_mut(&session_token).unwrap();
            record.last_activity_at = now - Duration::from_secs(1799);
        }

        let app = router(state.clone());
        let req = Request::builder()
            .uri("/auth/session/status")
            .header(
                header::COOKIE,
                format!("codewebway_session={session_token}"),
            )
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let remaining_idle = {
            let mut sessions = state.sessions.lock().unwrap();
            let (idle, _) = sessions
                .remaining_secs(&session_token, Instant::now())
                .expect("session should still be valid after status touch");
            idle
        };
        assert!(
            remaining_idle > 1700,
            "remaining idle seconds should be reset, got {remaining_idle}"
        );
    }

    #[tokio::test]
    async fn test_capabilities_terminal_only_true() {
        use axum::{body::Body, http::Request};
        use tower::util::ServiceExt;
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
        use axum::{body::Body, http::Request};
        use tower::util::ServiceExt;
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
        use axum::{body::Body, http::Request};
        use tower::util::ServiceExt;
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
