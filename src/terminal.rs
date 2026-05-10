use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use rand::distributions::Alphanumeric;
use rand::Rng;
use serde::Serialize;

use crate::session::{self, Session};

#[derive(Serialize, Clone)]
pub struct TerminalSummary {
    pub id: String,
    pub title: String,
    pub cwd: String,
    pub shell: String,
    pub status: session::SessionStatus,
    pub exit_code: Option<u32>,
    pub exit_success: Option<bool>,
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
            status: session::SessionStatus::Running,
            exit_code: None,
            exit_success: None,
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
            .map(|entry| self.with_lifecycle(entry))
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
        Some(Self::build_summary(&entry.summary, &entry.session))
    }

    pub fn restart(
        &mut self,
        id: &str,
        scrollback: usize,
    ) -> anyhow::Result<Option<TerminalSummary>> {
        let Some(entry) = self.entries.get_mut(id) else {
            return Ok(None);
        };

        let replacement = session::spawn_session(
            &entry.summary.shell,
            &PathBuf::from(&entry.summary.cwd),
            scrollback,
        )?;
        let old_session = std::mem::replace(&mut entry.session, replacement);
        let _ = session::close_session(&old_session);
        let mut summary = entry.summary.clone();
        summary.status = session::SessionStatus::Running;
        summary.exit_code = None;
        summary.exit_success = None;
        entry.summary = summary.clone();
        Ok(Some(summary))
    }

    pub fn remove_all(&mut self) {
        let ids: Vec<String> = self.entries.keys().cloned().collect();
        for id in ids {
            let _ = self.remove(&id);
        }
    }

    fn with_lifecycle(&self, entry: &TerminalEntry) -> TerminalSummary {
        Self::build_summary(&entry.summary, &entry.session)
    }

    fn build_summary(base: &TerminalSummary, session: &Session) -> TerminalSummary {
        let lifecycle = session::lifecycle(session);
        let mut summary = base.clone();
        summary.status = lifecycle.status;
        summary.exit_code = lifecycle.exit_code;
        summary.exit_success = lifecycle.exit_success;
        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_restart_preserves_terminal_identity() {
        let dir = tempfile::tempdir().unwrap();
        let mut manager = TerminalManager::new(4);
        let created = manager
            .create(
                "main".to_string(),
                dir.path().to_path_buf(),
                "/bin/sh".to_string(),
                1024,
            )
            .unwrap();
        let session = manager.get_session(&created.id).unwrap();
        let (_, _, _, mut events) = session::tail_and_subscribe(&session);
        session::write_input(&session, b"exit 9\n").unwrap();
        let _ = events.blocking_recv().unwrap();

        let restarted = manager.restart(&created.id, 1024).unwrap().unwrap();

        assert_eq!(restarted.id, created.id);
        assert_eq!(restarted.title, created.title);
        assert_eq!(restarted.cwd, created.cwd);
        assert_eq!(restarted.shell, created.shell);
        assert_eq!(restarted.status, session::SessionStatus::Running);
        assert_eq!(restarted.exit_code, None);
        assert_eq!(restarted.exit_success, None);
    }
}
