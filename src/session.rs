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
}
