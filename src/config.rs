use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "rust-webtty", about = "Browser-accessible terminal over WebSocket")]
pub struct Config {
    /// Port to listen on
    #[arg(long, default_value_t = 8080)]
    pub port: u16,

    /// Shared secret password (required)
    #[arg(long)]
    pub password: String,

    /// Shell to spawn (default: $SHELL on Unix, cmd.exe on Windows)
    #[arg(long)]
    pub shell: Option<String>,

    /// Scrollback buffer size in bytes
    #[arg(long, default_value_t = 10240)]
    pub scrollback: usize,
}

impl Config {
    pub fn shell_path(&self) -> String {
        if let Some(s) = &self.shell {
            return s.clone();
        }
        #[cfg(windows)]
        {
            std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_string())
        }
        #[cfg(not(windows))]
        {
            std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_port() {
        let cfg = Config::parse_from(["rust-webtty", "--password", "secret"]);
        assert_eq!(cfg.port, 8080);
    }

    #[test]
    fn test_custom_port() {
        let cfg = Config::parse_from(["rust-webtty", "--password", "secret", "--port", "9090"]);
        assert_eq!(cfg.port, 9090);
    }

    #[test]
    fn test_password_stored() {
        let cfg = Config::parse_from(["rust-webtty", "--password", "mysecret"]);
        assert_eq!(cfg.password, "mysecret");
    }

    #[test]
    fn test_shell_override() {
        let cfg = Config::parse_from(["rust-webtty", "--password", "x", "--shell", "/bin/bash"]);
        assert_eq!(cfg.shell_path(), "/bin/bash");
    }

    #[test]
    fn test_shell_default_falls_back() {
        let cfg = Config::parse_from(["rust-webtty", "--password", "x"]);
        assert!(!cfg.shell_path().is_empty());
    }
}
