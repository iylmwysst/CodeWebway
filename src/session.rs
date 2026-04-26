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
    pub tx: broadcast::Sender<Bytes>,
    pub pty_writer: Box<dyn Write + Send>,
    pub pty_master: Box<dyn portable_pty::MasterPty + Send>,
    pub child: Box<dyn portable_pty::Child + Send>,
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

    // Take reader and writer BEFORE moving master into SharedSession
    let pty_writer = pair.master.take_writer()?;
    let mut reader = pair.master.try_clone_reader()?;

    let session = Arc::new(Mutex::new(SharedSession {
        history: TerminalHistory::new(scrollback_size),
        tx: tx.clone(),
        pty_writer,
        pty_master: pair.master,
        child,
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
    });

    Ok(session)
}

pub fn close_session(session: &Session) -> anyhow::Result<()> {
    let mut shared = session.lock().unwrap();
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
}
