use std::io::Write;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use portable_pty::PtySize;

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
    pub session_cookie: String,
    pub failed_logins: Mutex<FailedLoginTracker>,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    password: String,
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

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/auth/login", post(auth_login))
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

    if check_token(&req.password, &state.password) {
        limiter.clear(&client);
        let set_cookie = format!(
            "webtty_session={}; HttpOnly; SameSite=Strict; Path=/",
            state.session_cookie
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

async fn ws_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Response {
    let authorized = has_valid_session_cookie(&headers, &state.session_cookie);
    if !authorized {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>) {
    // Send scrollback to newly connected client, then subscribe to broadcast
    let (scrollback, mut rx) = {
        let s = state.session.lock().unwrap();
        (s.scrollback.snapshot(), s.tx.subscribe())
    };
    if !scrollback.is_empty() {
        let _ = socket.send(Message::Binary(scrollback.into())).await;
    }

    loop {
        tokio::select! {
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

fn has_valid_session_cookie(headers: &HeaderMap, expected: &str) -> bool {
    let raw_cookie = match headers.get(header::COOKIE).and_then(|value| value.to_str().ok()) {
        Some(value) => value,
        None => return false,
    };
    let Some(session) = cookie_value(raw_cookie, "webtty_session") else {
        return false;
    };
    check_token(session, expected)
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
}
