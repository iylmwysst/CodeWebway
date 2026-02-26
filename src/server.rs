use std::io::Write;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use portable_pty::PtySize;
use rand::distributions::Alphanumeric;
use rand::Rng;

use axum::{
    extract::{Json, State, WebSocketUpgrade},
    extract::ws::{Message, WebSocket},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use tokio::sync::broadcast;

use crate::assets::Assets;
use crate::session::Session;

pub struct AppState {
    pub session: Session,
    pub password: String,
    pub pin: Option<String>,
    pub failed_logins: Mutex<FailedLoginTracker>,
    pub sessions: Mutex<SessionStore>,
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
        .route("/ws", get(ws_handler))
        .with_state(Arc::new(state))
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
        return (
            StatusCode::OK,
            [(header::SET_COOKIE, set_cookie)],
            "OK",
        )
            .into_response();
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

async fn ws_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Response {
    if !is_allowed_origin(&headers) {
        return (StatusCode::FORBIDDEN, "Forbidden origin").into_response();
    }
    let Some(session_token) = has_valid_session_cookie(&headers, &state) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };
    ws.on_upgrade(move |socket| handle_socket(socket, state, session_token))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>, session_token: String) {
    // Send scrollback to newly connected client, then subscribe to broadcast
    let (scrollback, mut rx) = {
        let s = state.session.lock().unwrap();
        (s.scrollback.snapshot(), s.tx.subscribe())
    };
    if !scrollback.is_empty() {
        let _ = socket.send(Message::Binary(scrollback.into())).await;
    }
    let mut session_tick = tokio::time::interval(Duration::from_secs(15));

    loop {
        tokio::select! {
            _ = session_tick.tick() => {
                if !is_session_token_valid(&state, &session_token) {
                    let _ = socket
                        .send(Message::Text("{\"type\":\"session_expired\"}".into()))
                        .await;
                    let _ = socket.close().await;
                    break;
                }
            }
            // PTY output → browser
            result = rx.recv() => {
                match result {
                    Ok(data) => {
                        if socket.send(Message::Binary(data.to_vec().into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
            // Browser input → PTY
            result = socket.recv() => {
                match result {
                    Some(Ok(Message::Binary(data))) => {
                        let mut s = state.session.lock().unwrap();
                        let _ = s.pty_writer.write_all(&data);
                    }
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&text) {
                            if msg["type"] == "resize" {
                                let cols = msg["cols"].as_u64().unwrap_or(80) as u16;
                                let rows = msg["rows"].as_u64().unwrap_or(24) as u16;
                                let s = state.session.lock().unwrap();
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

/// Constant-time token comparison (XOR fold).
/// Note: length check leaks password length via timing — acceptable for a local dev tool.
pub fn check_token(token: &str, password: &str) -> bool {
    if token.len() != password.len() {
        return false;
    }
    token.as_bytes().iter().zip(password.as_bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

fn has_valid_session_cookie(headers: &HeaderMap, state: &Arc<AppState>) -> Option<String> {
    let session = session_token_from_headers(headers)?;
    if !is_session_token_valid(state, &session) {
        return None;
    }
    Some(session)
}

fn session_token_from_headers(headers: &HeaderMap) -> Option<String> {
    let raw_cookie = match headers.get(header::COOKIE).and_then(|value| value.to_str().ok()) {
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
        // Use left-most hop as originating client.
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
        headers.insert(
            "x-forwarded-for",
            "203.0.113.8, 10.0.0.1".parse().unwrap(),
        );
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
        assert_eq!(session_token_from_headers(&headers), Some("abc123".to_string()));
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
