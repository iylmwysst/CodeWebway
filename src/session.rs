use bytes::Bytes;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

const HISTORY_CHUNK_TARGET: usize = 32 * 1024;
const HISTORY_MIN_BYTES: usize = 2 * 1024 * 1024;
const HISTORY_MAX_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Running,
    Exited,
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SessionLifecycle {
    pub status: SessionStatus,
    pub exit_code: Option<u32>,
    pub exit_success: Option<bool>,
}

impl SessionLifecycle {
    fn running() -> Self {
        Self {
            status: SessionStatus::Running,
            exit_code: None,
            exit_success: None,
        }
    }

    fn exited(exit_code: u32, exit_success: bool) -> Self {
        Self {
            status: SessionStatus::Exited,
            exit_code: Some(exit_code),
            exit_success: Some(exit_success),
        }
    }

    fn closed() -> Self {
        Self {
            status: SessionStatus::Closed,
            exit_code: None,
            exit_success: None,
        }
    }

    pub fn is_running(&self) -> bool {
        matches!(self.status, SessionStatus::Running)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    Exited(SessionLifecycle),
    Closed,
}

#[derive(Clone, Debug)]
pub struct HistoryChunk {
    pub seq: u64,
    pub bytes: Bytes,
}

#[derive(Clone, Debug)]
pub struct HistoryTail {
    pub bytes: Vec<u8>,
    pub first_seq: Option<u64>,
    pub next_seq: u64,
    pub total_bytes: usize,
    pub trimmed: bool,
}

#[derive(Clone, Debug)]
pub struct HistoryPage {
    pub chunks: Vec<HistoryChunk>,
    pub has_more: bool,
    pub first_seq: Option<u64>,
    pub next_seq: u64,
    pub total_bytes: usize,
    pub trimmed: bool,
}

pub struct TerminalHistory {
    chunks: VecDeque<HistoryChunk>,
    pending: Vec<u8>,
    live_tail: VecDeque<u8>,
    live_tail_max: usize,
    history_max: usize,
    history_bytes: usize,
    next_seq: u64,
    trimmed: bool,
}

impl TerminalHistory {
    pub fn new(live_tail_max: usize) -> Self {
        let history_max = live_tail_max
            .saturating_mul(16)
            .clamp(HISTORY_MIN_BYTES, HISTORY_MAX_BYTES);
        Self {
            chunks: VecDeque::new(),
            pending: Vec::new(),
            live_tail: VecDeque::new(),
            live_tail_max,
            history_max,
            history_bytes: 0,
            next_seq: 0,
            trimmed: false,
        }
    }

    pub fn push(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        for &b in data {
            if self.live_tail_max > 0 {
                if self.live_tail.len() >= self.live_tail_max {
                    self.live_tail.pop_front();
                }
                self.live_tail.push_back(b);
            }
            self.pending.push(b);
            if self.pending.len() >= HISTORY_CHUNK_TARGET {
                self.flush_pending();
            }
        }
    }

    pub fn flush_pending(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let split_at = safe_utf8_prefix_len(&self.pending);
        if split_at == 0 && self.pending.len() < HISTORY_CHUNK_TARGET * 2 {
            return;
        }
        let chunk_bytes = if split_at == 0 {
            std::mem::take(&mut self.pending)
        } else {
            let remainder = self.pending.split_off(split_at);
            std::mem::replace(&mut self.pending, remainder)
        };
        self.push_chunk(Bytes::from(chunk_bytes));
    }

    fn push_chunk(&mut self, bytes: Bytes) {
        if bytes.is_empty() {
            return;
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.history_bytes = self.history_bytes.saturating_add(bytes.len());
        self.chunks.push_back(HistoryChunk { seq, bytes });
        self.trim_history();
    }

    fn trim_history(&mut self) {
        while self.history_bytes > self.history_max {
            let Some(chunk) = self.chunks.pop_front() else {
                break;
            };
            self.history_bytes = self.history_bytes.saturating_sub(chunk.bytes.len());
            self.trimmed = true;
        }
    }

    pub fn live_tail(&mut self) -> HistoryTail {
        self.flush_pending();
        HistoryTail {
            bytes: self.live_tail.iter().copied().collect(),
            first_seq: self.chunks.front().map(|chunk| chunk.seq),
            next_seq: self.next_seq,
            total_bytes: self.history_bytes.saturating_add(self.pending.len()),
            trimmed: self.trimmed,
        }
    }

    pub fn page_before(&mut self, before_seq: Option<u64>, limit: usize) -> HistoryPage {
        self.flush_pending();
        let limit = limit.clamp(1, 64);
        let before = before_seq.unwrap_or(self.next_seq);
        let mut selected = Vec::new();
        for chunk in self.chunks.iter().rev() {
            if chunk.seq >= before {
                continue;
            }
            selected.push(chunk.clone());
            if selected.len() >= limit {
                break;
            }
        }
        selected.reverse();
        let first_selected = selected.first().map(|chunk| chunk.seq);
        let has_more = match (self.chunks.front(), first_selected) {
            (Some(front), Some(first)) => front.seq < first,
            _ => false,
        };
        HistoryPage {
            chunks: selected,
            has_more,
            first_seq: self.chunks.front().map(|chunk| chunk.seq),
            next_seq: self.next_seq,
            total_bytes: self.history_bytes.saturating_add(self.pending.len()),
            trimmed: self.trimmed,
        }
    }

    pub fn page_after(&mut self, after_seq: Option<u64>, limit: usize) -> HistoryPage {
        self.flush_pending();
        let limit = limit.clamp(1, 128);
        let after = after_seq.unwrap_or(0);
        let mut selected = Vec::new();
        for chunk in self.chunks.iter() {
            if chunk.seq < after {
                continue;
            }
            selected.push(chunk.clone());
            if selected.len() >= limit {
                break;
            }
        }
        let last_selected = selected.last().map(|chunk| chunk.seq);
        let has_more = match (self.chunks.back(), last_selected) {
            (Some(back), Some(last)) => back.seq > last,
            _ => false,
        };
        HistoryPage {
            chunks: selected,
            has_more,
            first_seq: self.chunks.front().map(|chunk| chunk.seq),
            next_seq: self.next_seq,
            total_bytes: self.history_bytes.saturating_add(self.pending.len()),
            trimmed: self.trimmed,
        }
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.history_bytes
            .saturating_add(self.pending.len())
            .saturating_add(self.live_tail.len())
    }
}

fn safe_utf8_prefix_len(bytes: &[u8]) -> usize {
    if std::str::from_utf8(bytes).is_ok() {
        return bytes.len();
    }
    for idx in (0..bytes.len()).rev().take(4) {
        if std::str::from_utf8(&bytes[..idx]).is_ok() {
            return idx;
        }
    }
    bytes.len()
}

pub struct SharedSession {
    pub history: TerminalHistory,
    tx: broadcast::Sender<Bytes>,
    event_tx: broadcast::Sender<SessionEvent>,
    pty_writer: Box<dyn Write + Send>,
    pty_master: Box<dyn portable_pty::MasterPty + Send>,
    child: Box<dyn portable_pty::Child + Send>,
    lifecycle: SessionLifecycle,
}

pub type Session = Arc<Mutex<SharedSession>>;

fn is_utf8_locale(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    lower.contains("utf-8") || lower.contains("utf8")
}

fn utf8_locale_overrides<'a>(
    lc_all: Option<&'a str>,
    lc_ctype: Option<&'a str>,
    lang: Option<&'a str>,
) -> Vec<(&'static str, &'static str)> {
    let locale_chain = [lc_all, lc_ctype, lang];
    if locale_chain.into_iter().flatten().any(is_utf8_locale) {
        return Vec::new();
    }

    let mut overrides = Vec::with_capacity(2);
    if lc_all.is_some_and(|value| !value.trim().is_empty()) {
        overrides.push(("LC_ALL", "UTF-8"));
    }
    overrides.push(("LC_CTYPE", "UTF-8"));
    overrides
}

fn apply_utf8_locale(cmd: &mut CommandBuilder) {
    let lc_all = std::env::var("LC_ALL").ok();
    let lc_ctype = std::env::var("LC_CTYPE").ok();
    let lang = std::env::var("LANG").ok();

    for (key, value) in
        utf8_locale_overrides(lc_all.as_deref(), lc_ctype.as_deref(), lang.as_deref())
    {
        cmd.env(key, value);
    }
}

pub fn spawn_session(shell: &str, cwd: &Path, scrollback_size: usize) -> anyhow::Result<Session> {
    let pty_system = native_pty_system();
    let pair = pty_system.openpty(PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    })?;

    let mut cmd = CommandBuilder::new(shell);
    cmd.env("TERM", "xterm-256color");
    apply_utf8_locale(&mut cmd);
    cmd.cwd(cwd);
    let child = pair.slave.spawn_command(cmd)?;

    let (tx, _) = broadcast::channel::<Bytes>(256);
    let (event_tx, _) = broadcast::channel::<SessionEvent>(32);

    // Take reader and writer BEFORE moving master into SharedSession
    let pty_writer = pair.master.take_writer()?;
    let mut reader = pair.master.try_clone_reader()?;

    let session = Arc::new(Mutex::new(SharedSession {
        history: TerminalHistory::new(scrollback_size),
        tx: tx.clone(),
        event_tx,
        pty_writer,
        pty_master: pair.master,
        child,
        lifecycle: SessionLifecycle::running(),
    }));

    // Spawn PTY reader thread
    let session_clone = Arc::clone(&session);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let data = Bytes::copy_from_slice(&buf[..n]);
                    let mut s = session_clone.lock().unwrap();
                    s.history.push(&data);
                    let _ = s.tx.send(data);
                }
            }
        }

        let mut s = session_clone.lock().unwrap();
        let _ = refresh_lifecycle_locked(&mut s);
    });

    Ok(session)
}

fn refresh_lifecycle_locked(shared: &mut SharedSession) -> anyhow::Result<SessionLifecycle> {
    if !shared.lifecycle.is_running() {
        return Ok(shared.lifecycle.clone());
    }

    if let Some(exit_status) = shared.child.try_wait()? {
        let lifecycle = SessionLifecycle::exited(exit_status.exit_code(), exit_status.success());
        shared.lifecycle = lifecycle.clone();
        let _ = shared
            .event_tx
            .send(SessionEvent::Exited(lifecycle.clone()));
    }

    Ok(shared.lifecycle.clone())
}

pub fn history_page(session: &Session, before_seq: Option<u64>, limit: usize) -> HistoryPage {
    let mut shared = session.lock().unwrap();
    let _ = refresh_lifecycle_locked(&mut shared);
    shared.history.page_before(before_seq, limit)
}

pub fn history_page_after(session: &Session, after_seq: Option<u64>, limit: usize) -> HistoryPage {
    let mut shared = session.lock().unwrap();
    let _ = refresh_lifecycle_locked(&mut shared);
    shared.history.page_after(after_seq, limit)
}

pub fn history_tail(session: &Session) -> HistoryTail {
    let mut shared = session.lock().unwrap();
    let _ = refresh_lifecycle_locked(&mut shared);
    shared.history.live_tail()
}

pub fn lifecycle(session: &Session) -> SessionLifecycle {
    let mut shared = session.lock().unwrap();
    refresh_lifecycle_locked(&mut shared).unwrap_or_else(|_| shared.lifecycle.clone())
}

pub fn tail_and_subscribe(
    session: &Session,
) -> (
    HistoryTail,
    SessionLifecycle,
    broadcast::Receiver<Bytes>,
    broadcast::Receiver<SessionEvent>,
) {
    let mut shared = session.lock().unwrap();
    let lifecycle =
        refresh_lifecycle_locked(&mut shared).unwrap_or_else(|_| shared.lifecycle.clone());
    (
        shared.history.live_tail(),
        lifecycle,
        shared.tx.subscribe(),
        shared.event_tx.subscribe(),
    )
}

pub fn write_input(session: &Session, data: &[u8]) -> anyhow::Result<()> {
    let mut shared = session.lock().unwrap();
    let lifecycle = refresh_lifecycle_locked(&mut shared)?;
    if !lifecycle.is_running() {
        anyhow::bail!("terminal session is not running");
    }
    shared.pty_writer.write_all(data)?;
    Ok(())
}

pub fn resize_session(session: &Session, rows: u16, cols: u16) -> anyhow::Result<()> {
    let mut shared = session.lock().unwrap();
    let lifecycle = refresh_lifecycle_locked(&mut shared)?;
    if !lifecycle.is_running() {
        anyhow::bail!("terminal session is not running");
    }
    shared.pty_master.resize(PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    })?;
    Ok(())
}

pub fn close_session(session: &Session) -> anyhow::Result<()> {
    let mut shared = session.lock().unwrap();
    if !matches!(shared.lifecycle.status, SessionStatus::Closed) {
        shared.lifecycle = SessionLifecycle::closed();
        let _ = shared.event_tx.send(SessionEvent::Closed);
    }
    let _ = shared.child.kill();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_and_snapshot() {
        let mut sb = TerminalHistory::new(100);
        sb.push(b"hello");
        assert_eq!(sb.live_tail().bytes, b"hello");
    }

    #[test]
    fn test_max_capacity_evicts_oldest() {
        let mut sb = TerminalHistory::new(5);
        sb.push(b"123456789"); // 9 bytes into 5-byte buffer
        assert_eq!(sb.live_tail().bytes, b"56789");
    }

    #[test]
    fn test_empty_snapshot() {
        let mut sb = TerminalHistory::new(100);
        assert_eq!(sb.live_tail().bytes, b"");
    }

    #[test]
    fn test_exact_capacity() {
        let mut sb = TerminalHistory::new(3);
        sb.push(b"abc");
        sb.push(b"d");
        assert_eq!(sb.live_tail().bytes, b"bcd");
    }

    #[test]
    fn test_zero_capacity_stores_nothing() {
        let mut sb = TerminalHistory::new(0);
        sb.push(b"hello");
        assert_eq!(sb.live_tail().bytes, b"");
    }

    #[test]
    fn test_history_pages_before_sequence() {
        let mut history = TerminalHistory::new(16);
        history.push(b"first");
        history.flush_pending();
        history.push(b"second");
        history.flush_pending();
        history.push(b"third");
        history.flush_pending();

        let page = history.page_before(Some(2), 2);
        assert_eq!(page.chunks.len(), 2);
        assert_eq!(page.chunks[0].bytes, Bytes::from_static(b"first"));
        assert_eq!(page.chunks[1].bytes, Bytes::from_static(b"second"));
    }

    #[test]
    fn test_history_pages_after_sequence() {
        let mut history = TerminalHistory::new(16);
        history.push(b"first");
        history.flush_pending();
        history.push(b"second");
        history.flush_pending();
        history.push(b"third");
        history.flush_pending();

        let page = history.page_after(Some(1), 4);
        assert_eq!(page.chunks.len(), 2);
        assert_eq!(page.chunks[0].bytes, Bytes::from_static(b"second"));
        assert_eq!(page.chunks[1].bytes, Bytes::from_static(b"third"));
    }

    #[test]
    fn test_utf8_locale_detection_accepts_common_spellings() {
        assert!(is_utf8_locale("UTF-8"));
        assert!(is_utf8_locale("en_US.UTF-8"));
        assert!(is_utf8_locale("C.UTF8"));
        assert!(!is_utf8_locale("C"));
        assert!(!is_utf8_locale(""));
    }

    #[test]
    fn test_utf8_locale_overrides_when_locale_missing() {
        assert_eq!(
            utf8_locale_overrides(None, None, None),
            vec![("LC_CTYPE", "UTF-8")]
        );
    }

    #[test]
    fn test_utf8_locale_overrides_when_only_non_utf8_lang_exists() {
        assert_eq!(
            utf8_locale_overrides(None, None, Some("C")),
            vec![("LC_CTYPE", "UTF-8")]
        );
    }

    #[test]
    fn test_utf8_locale_overrides_when_lc_all_blocks_utf8() {
        assert_eq!(
            utf8_locale_overrides(Some("C"), None, Some("en_US.ISO8859-1")),
            vec![("LC_ALL", "UTF-8"), ("LC_CTYPE", "UTF-8")]
        );
    }

    #[test]
    fn test_utf8_locale_overrides_skip_when_utf8_already_present() {
        assert!(utf8_locale_overrides(None, Some("en_US.UTF-8"), None).is_empty());
        assert!(utf8_locale_overrides(Some("C.UTF-8"), None, None).is_empty());
        assert!(utf8_locale_overrides(None, None, Some("th_TH.UTF8")).is_empty());
    }

    #[test]
    fn test_session_lifecycle_tracks_natural_exit() {
        let dir = tempfile::tempdir().unwrap();
        let session = spawn_session("/bin/sh", dir.path(), 1024).unwrap();
        let (_, initial, _, mut events) = tail_and_subscribe(&session);
        assert_eq!(initial.status, SessionStatus::Running);

        write_input(&session, b"exit 7\n").unwrap();

        let event = events.blocking_recv().unwrap();
        let SessionEvent::Exited(lifecycle) = event else {
            panic!("expected exit event");
        };
        assert_eq!(lifecycle.status, SessionStatus::Exited);
        assert_eq!(lifecycle.exit_code, Some(7));
        assert_eq!(lifecycle.exit_success, Some(false));

        let latest = self::lifecycle(&session);
        assert_eq!(latest, lifecycle);
    }

    #[test]
    fn test_close_session_marks_closed() {
        let dir = tempfile::tempdir().unwrap();
        let session = spawn_session("/bin/sh", dir.path(), 1024).unwrap();
        let (_, _, _, mut events) = tail_and_subscribe(&session);

        close_session(&session).unwrap();

        let event = events.blocking_recv().unwrap();
        assert_eq!(event, SessionEvent::Closed);
        assert_eq!(self::lifecycle(&session).status, SessionStatus::Closed);
    }
}
