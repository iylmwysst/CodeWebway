use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "codewebway", about = "CodeWebway terminal over WebSocket")]
pub struct Config {
    /// Host/IP to bind (default: localhost only)
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Port to listen on
    #[arg(long, default_value_t = 8080)]
    pub port: u16,

    /// Access token (auto-generated if not provided)
    #[arg(long)]
    pub password: Option<String>,

    /// Secondary login PIN (not printed on startup)
    #[arg(long)]
    pub pin: Option<String>,

    /// Shell to spawn (default: $SHELL on Unix, cmd.exe on Windows)
    #[arg(long)]
    pub shell: Option<String>,

    /// Working directory for spawned shell (default: current directory)
    #[arg(long)]
    pub cwd: Option<String>,

    /// Scrollback buffer size in bytes
    #[arg(long, default_value_t = 131072)]
    pub scrollback: usize,

    /// Create a public URL with zrok (requires `zrok` installed and enabled)
    #[arg(short = 'z', long)]
    pub zrok: bool,

    /// Auto-disable public zrok share after N minutes (requires --zrok)
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..), conflicts_with = "public_no_expiry")]
    pub public_timeout_minutes: Option<u64>,

    /// Keep public zrok share active with no automatic expiry (requires --zrok)
    #[arg(long, conflicts_with = "public_timeout_minutes")]
    pub public_no_expiry: bool,

    /// Maximum concurrent WebSocket connections
    #[arg(long, default_value_t = 8)]
    pub max_connections: usize,

    /// Terminal-only mode: disable file explorer and editor
    #[arg(long)]
    pub terminal_only: bool,

    /// Generate one temporary link at startup (printed in host console)
    #[arg(long)]
    pub temp_link: bool,

    /// Temporary link TTL in minutes (allowed: 5, 15, 60)
    #[arg(long, default_value_t = 15, value_parser = parse_temp_ttl)]
    pub temp_link_ttl_minutes: u64,

    /// Temporary link scope: read-only or interactive
    #[arg(long, default_value = "read-only", value_parser = ["read-only", "interactive"])]
    pub temp_link_scope: String,

    /// Temporary link max uses (default 1 = one-time)
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=100))]
    pub temp_link_max_uses: u32,
}

fn parse_temp_ttl(raw: &str) -> Result<u64, String> {
    let value = raw
        .parse::<u64>()
        .map_err(|_| "ttl must be a number".to_string())?;
    if matches!(value, 5 | 15 | 60) {
        Ok(value)
    } else {
        Err("ttl must be one of: 5, 15, 60".to_string())
    }
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
        let cfg = Config::parse_from(["codewebway"]);
        assert_eq!(cfg.port, 8080);
    }

    #[test]
    fn test_default_host() {
        let cfg = Config::parse_from(["codewebway"]);
        assert_eq!(cfg.host, "127.0.0.1");
    }

    #[test]
    fn test_custom_host() {
        let cfg = Config::parse_from(["codewebway", "--host", "0.0.0.0"]);
        assert_eq!(cfg.host, "0.0.0.0");
    }

    #[test]
    fn test_custom_port() {
        let cfg = Config::parse_from(["codewebway", "--port", "9090"]);
        assert_eq!(cfg.port, 9090);
    }

    #[test]
    fn test_password_stored() {
        let cfg = Config::parse_from(["codewebway", "--password", "mysecret"]);
        assert_eq!(cfg.password, Some("mysecret".to_string()));
    }

    #[test]
    fn test_password_optional() {
        let cfg = Config::parse_from(["codewebway"]);
        assert!(cfg.password.is_none());
    }

    #[test]
    fn test_pin_optional() {
        let cfg = Config::parse_from(["codewebway"]);
        assert!(cfg.pin.is_none());
    }

    #[test]
    fn test_pin_stored() {
        let cfg = Config::parse_from(["codewebway", "--pin", "123456"]);
        assert_eq!(cfg.pin, Some("123456".to_string()));
    }

    #[test]
    fn test_shell_override() {
        let cfg = Config::parse_from(["codewebway", "--shell", "/bin/bash"]);
        assert_eq!(cfg.shell_path(), "/bin/bash");
    }

    #[test]
    fn test_cwd_stored() {
        let cfg = Config::parse_from(["codewebway", "--cwd", "/tmp"]);
        assert_eq!(cfg.cwd, Some("/tmp".to_string()));
    }

    #[test]
    fn test_shell_default_falls_back() {
        let cfg = Config::parse_from(["codewebway"]);
        assert!(!cfg.shell_path().is_empty());
    }

    #[test]
    fn test_zrok_flag_long() {
        let cfg = Config::parse_from(["codewebway", "--zrok"]);
        assert!(cfg.zrok);
    }

    #[test]
    fn test_zrok_flag_short() {
        let cfg = Config::parse_from(["codewebway", "-z"]);
        assert!(cfg.zrok);
    }

    #[test]
    fn test_public_timeout_minutes() {
        let cfg = Config::parse_from(["codewebway", "--public-timeout-minutes", "15"]);
        assert_eq!(cfg.public_timeout_minutes, Some(15));
        assert!(!cfg.public_no_expiry);
    }

    #[test]
    fn test_public_no_expiry_flag() {
        let cfg = Config::parse_from(["codewebway", "--public-no-expiry"]);
        assert!(cfg.public_no_expiry);
        assert_eq!(cfg.public_timeout_minutes, None);
    }

    #[test]
    fn test_public_timeout_conflicts_with_no_expiry() {
        let parsed = Config::try_parse_from([
            "codewebway",
            "--public-timeout-minutes",
            "15",
            "--public-no-expiry",
        ]);
        assert!(parsed.is_err());
    }

    #[test]
    fn test_max_connections_default() {
        let cfg = Config::parse_from(["codewebway"]);
        assert_eq!(cfg.max_connections, 8);
    }

    #[test]
    fn test_max_connections_custom() {
        let cfg = Config::parse_from(["codewebway", "--max-connections", "10"]);
        assert_eq!(cfg.max_connections, 10);
    }

    #[test]
    fn test_temp_link_defaults() {
        let cfg = Config::parse_from(["codewebway"]);
        assert!(!cfg.temp_link);
        assert_eq!(cfg.temp_link_ttl_minutes, 15);
        assert_eq!(cfg.temp_link_scope, "read-only");
        assert_eq!(cfg.temp_link_max_uses, 1);
    }

    #[test]
    fn test_temp_link_custom() {
        let cfg = Config::parse_from([
            "codewebway",
            "--temp-link",
            "--temp-link-ttl-minutes",
            "60",
            "--temp-link-scope",
            "interactive",
            "--temp-link-max-uses",
            "3",
        ]);
        assert!(cfg.temp_link);
        assert_eq!(cfg.temp_link_ttl_minutes, 60);
        assert_eq!(cfg.temp_link_scope, "interactive");
        assert_eq!(cfg.temp_link_max_uses, 3);
    }

    #[test]
    fn test_terminal_only_default() {
        let cfg = Config::parse_from(["codewebway"]);
        assert!(!cfg.terminal_only);
    }

    #[test]
    fn test_terminal_only_flag() {
        let cfg = Config::parse_from(["codewebway", "--terminal-only"]);
        assert!(cfg.terminal_only);
    }
}
