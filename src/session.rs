use bytes::Bytes;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

pub struct Scrollback {
    buf: VecDeque<u8>,
    max: usize,
}

impl Scrollback {
    pub fn new(max: usize) -> Self {
        Self {
            buf: VecDeque::new(),
            max,
        }
    }

    pub fn push(&mut self, data: &[u8]) {
        if self.max == 0 {
            return;
        }
        for &b in data {
            if self.buf.len() >= self.max {
                self.buf.pop_front();
            }
            self.buf.push_back(b);
        }
    }

    pub fn snapshot(&self) -> Vec<u8> {
        self.buf.iter().copied().collect()
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.buf.len()
    }
}

pub struct SharedSession {
    pub scrollback: Scrollback,
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
        scrollback: Scrollback::new(scrollback_size),
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
                    s.scrollback.push(&data);
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
        let mut sb = Scrollback::new(100);
        sb.push(b"hello");
        assert_eq!(sb.snapshot(), b"hello");
    }

    #[test]
    fn test_max_capacity_evicts_oldest() {
        let mut sb = Scrollback::new(5);
        sb.push(b"123456789"); // 9 bytes into 5-byte buffer
        assert_eq!(sb.len(), 5);
        assert_eq!(sb.snapshot(), b"56789");
    }

    #[test]
    fn test_empty_snapshot() {
        let sb = Scrollback::new(100);
        assert_eq!(sb.snapshot(), b"");
    }

    #[test]
    fn test_exact_capacity() {
        let mut sb = Scrollback::new(3);
        sb.push(b"abc");
        assert_eq!(sb.len(), 3);
        sb.push(b"d");
        assert_eq!(sb.snapshot(), b"bcd");
    }

    #[test]
    fn test_zero_capacity_stores_nothing() {
        let mut sb = Scrollback::new(0);
        sb.push(b"hello");
        assert_eq!(sb.len(), 0);
        assert_eq!(sb.snapshot(), b"");
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
