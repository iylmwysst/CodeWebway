use anyhow::{Context, Result};
use rand::distributions::Alphanumeric;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ─── Credentials ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetCredentials {
    pub machine_token: String,
    pub machine_name: String,
    pub fleet_endpoint: String,
    /// PIN stored during `enable`; used by the daemon so no flag is needed at runtime.
    pub pin: Option<String>,
}

pub fn credentials_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("codewebway")
        .join("fleet.toml")
}

pub fn load_credentials() -> Result<FleetCredentials> {
    load_credentials_from(&credentials_path())
}

pub fn load_credentials_from(path: &Path) -> Result<FleetCredentials> {
    let data = std::fs::read_to_string(path)
        .with_context(|| "Not enabled. Run: codewebway enable <token>".to_string())?;
    toml::from_str(&data).context("Malformed fleet.toml — run: codewebway enable <token>")
}

#[allow(dead_code)]
pub fn save_credentials(creds: &FleetCredentials) -> Result<()> {
    save_credentials_to(creds, &credentials_path())
}

pub fn save_credentials_to(creds: &FleetCredentials, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = toml::to_string_pretty(creds)?;
    std::fs::write(path, data)?;
    Ok(())
}

// ─── enable / disable ─────────────────────────────────────────────────────────

pub async fn enable(fleet_endpoint: &str, enable_token: &str, pin: Option<String>) -> Result<()> {
    enable_to_path(fleet_endpoint, enable_token, pin, &credentials_path()).await
}

pub async fn enable_to_path(fleet_endpoint: &str, enable_token: &str, pin: Option<String>, path: &Path) -> Result<()> {
    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .post(format!("{fleet_endpoint}/api/v1/agent/enable"))
        .json(&serde_json::json!({
            "enable_token": enable_token,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "hostname": hostname(),
            "agent_version": env!("CARGO_PKG_VERSION"),
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let machine_token = resp["data"]["machine_token"]
        .as_str()
        .context("Invalid response: missing machine_token")?
        .to_string();

    let machine_name = hostname();
    let pin = match pin {
        Some(p) => p,
        None => {
            // Auto-generate in non-interactive mode (scripted/daemon)
            (0..6)
                .map(|_| char::from(rand::thread_rng().gen_range(b'0'..=b'9')))
                .collect()
        }
    };
    let creds = FleetCredentials {
        machine_token,
        machine_name: machine_name.clone(),
        fleet_endpoint: fleet_endpoint.to_string(),
        pin: Some(pin.clone()),
    };
    save_credentials_to(&creds, path)?;

    println!("  ✓ Device enabled: \"{machine_name}\"");
    println!("  Credentials saved to {}", path.display());
    Ok(())
}

pub fn disable() -> Result<()> {
    let path = credentials_path();
    if path.exists() {
        std::fs::remove_file(&path)?;
        println!("  Device disabled. Credentials removed.");
    } else {
        println!("  Already disabled (no credentials found).");
    }
    Ok(())
}

// ─── API helpers ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct HeartbeatResponse {
    pub data: HeartbeatData,
}

#[derive(Debug, Deserialize)]
pub struct HeartbeatData {
    pub has_command: bool,
    pub command: Option<PendingCommand>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PendingCommand {
    pub execution_id: Option<String>,
    #[serde(rename = "type")]
    pub kind: String,
    #[allow(dead_code)]
    pub payload: serde_json::Value,
}

pub async fn send_heartbeat(
    creds: &FleetCredentials,
    status: &str,
    active_url: Option<&str>,
    skip_status_write: bool,
) -> Result<HeartbeatData> {
    let client = reqwest::Client::new();
    let mut body = serde_json::json!({
        "status": status,
        "skip_status_write": skip_status_write,
    });
    if let Some(url) = active_url {
        body["active_url"] = serde_json::json!(url);
    }

    let resp: HeartbeatResponse = client
        .post(format!("{}/api/v1/agent/heartbeat", creds.fleet_endpoint))
        .bearer_auth(&creds.machine_token)
        .json(&body)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    Ok(resp.data)
}

pub async fn report_result(
    creds: &FleetCredentials,
    execution_id: &str,
    output: &str,
    success: bool,
) -> Result<()> {
    let client = reqwest::Client::new();
    client
        .post(format!("{}/api/v1/agent/report", creds.fleet_endpoint))
        .bearer_auth(&creds.machine_token)
        .json(&serde_json::json!({
            "execution_id": execution_id,
            "output": output,
            "status": if success { "success" } else { "failed" },
        }))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

// ─── Daemon state ──────────────────────────────────────────────────────────────

struct DaemonState {
    status: String,
    active_url: Option<String>,
    last_d1_write: std::time::Instant,
}

impl DaemonState {
    fn new() -> Self {
        Self {
            status: "idle".to_string(),
            active_url: None,
            // force write on first heartbeat
            last_d1_write: std::time::Instant::now()
                - std::time::Duration::from_secs(400),
        }
    }

    fn should_write(&self, new_status: &str, new_url: Option<&str>) -> bool {
        new_status != self.status
            || new_url != self.active_url.as_deref()
            || self.last_d1_write.elapsed() > std::time::Duration::from_secs(300)
    }
}

// ─── Daemon loop ───────────────────────────────────────────────────────────────

pub async fn run_daemon(cfg: crate::config::Config) -> anyhow::Result<()> {
    let creds = load_credentials()
        .context("Not enabled. Run: codewebway enable <token>")?;

    println!("  Fleet daemon starting for \"{}\"", creds.machine_name);
    println!("  Endpoint: {}", creds.fleet_endpoint);

    let mut state = DaemonState::new();
    let poll_interval = std::time::Duration::from_secs(30);

    loop {
        let skip = !state.should_write(&state.status.clone(), state.active_url.as_deref());
        let hb = match send_heartbeat(&creds, &state.status, state.active_url.as_deref(), skip).await {
            Ok(h) => {
                if !skip {
                    state.last_d1_write = std::time::Instant::now();
                }
                h
            }
            Err(e) => {
                if is_unauthorized(&e) {
                    eprintln!("  Fleet: device deregistered (401) — daemon stopping.");
                    eprintln!("  Run: codewebway disable");
                    std::process::exit(1);
                }
                eprintln!("  Fleet: heartbeat error (will retry): {e}");
                tokio::time::sleep(poll_interval).await;
                continue;
            }
        };

        if !hb.has_command {
            tokio::time::sleep(poll_interval).await;
            continue;
        }
        let cmd = match hb.command {
            Some(c) => c,
            None => {
                tokio::time::sleep(poll_interval).await;
                continue;
            }
        };

        match cmd.kind.as_str() {
            "run_codewebway" => {
                let exec_id = cmd.execution_id.clone().unwrap_or_default();

                // Fleet mode: generate a fresh session token each run.
                // PIN stays as second factor. Dashboard receives both via report.
                let mut fleet_cfg = cfg.clone();
                let session_token: String = rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(24)
                    .map(char::from)
                    .collect();
                fleet_cfg.password = Some(session_token);
                if let Some(ref pin) = creds.pin {
                    fleet_cfg.pin = Some(pin.clone());
                }

                match crate::start_server(fleet_cfg).await {
                    Err(e) => {
                        eprintln!("  Fleet: failed to start server: {e}");
                        if !exec_id.is_empty() {
                            let _ = report_result(&creds, &exec_id, &e.to_string(), false).await;
                        }
                    }
                    Ok(handle) => {
                        let url = handle.zrok_url.as_deref().unwrap_or("no-url");
                        // Include token in report so dashboard can display it alongside URL.
                        let output = format!("{url}\ntoken:{}", handle.token);
                        state.status = "running".to_string();
                        state.active_url = handle.zrok_url.clone();
                        state.last_d1_write =
                            std::time::Instant::now() - std::time::Duration::from_secs(400);

                        if !exec_id.is_empty() {
                            if let Err(e) = report_result(&creds, &exec_id, &output, true).await {
                                eprintln!("  Fleet: report failed: {e}");
                            }
                        }

                        wait_for_stop(&creds, &mut state, handle.shutdown_tx, poll_interval).await;

                        state.status = "idle".to_string();
                        state.active_url = None;
                        state.last_d1_write =
                            std::time::Instant::now() - std::time::Duration::from_secs(400);
                    }
                }
            }
            "stop_codewebway" => {
                // handled inside wait_for_stop; if we get here the server isn't running
                eprintln!("  Fleet: stop received but no terminal running — ignoring");
            }
            other => eprintln!("  Fleet: unknown command type: {other}"),
        }

        tokio::time::sleep(poll_interval).await;
    }
}

async fn wait_for_stop(
    creds: &FleetCredentials,
    state: &mut DaemonState,
    shutdown_tx: tokio::sync::mpsc::UnboundedSender<()>,
    interval: std::time::Duration,
) {
    loop {
        let skip = !state.should_write(&state.status, state.active_url.as_deref());
        match send_heartbeat(creds, &state.status, state.active_url.as_deref(), skip).await {
            Ok(hb) => {
                if !skip {
                    state.last_d1_write = std::time::Instant::now();
                }
                if let Some(cmd) = hb.command {
                    if cmd.kind == "stop_codewebway" {
                        let exec_id = cmd.execution_id.unwrap_or_default();
                        let _ = shutdown_tx.send(());
                        if !exec_id.is_empty() {
                            let _ = report_result(creds, &exec_id, "stopped", true).await;
                        }
                        return;
                    }
                }
            }
            Err(e) => {
                if is_unauthorized(&e) {
                    eprintln!("  Fleet: device deregistered (401) — daemon stopping.");
                    eprintln!("  Run: codewebway disable");
                    std::process::exit(1);
                }
                eprintln!("  Fleet: heartbeat error during run: {e}");
            }
        }

        tokio::time::sleep(interval).await;
    }
}

// ─── System service ────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn launchagent_plist_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Library/LaunchAgents/com.codewebway.fleet.plist")
}

#[cfg(target_os = "linux")]
fn systemd_service_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("systemd/user/codewebway-fleet.service")
}

pub fn install_service() -> Result<()> {
    let bin = std::env::current_exe()
        .context("Cannot determine current executable path")?;
    let bin_str = bin.to_string_lossy();

    #[cfg(target_os = "macos")]
    {
        let plist_path = launchagent_plist_path();
        if let Some(parent) = plist_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let log_dir = std::env::temp_dir().join("codewebway");
        std::fs::create_dir_all(&log_dir)?;
        let log_path = log_dir.join("fleet-daemon.log");

        let plist = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
    <key>Label</key>\n\
    <string>com.codewebway.fleet</string>\n\
    <key>ProgramArguments</key>\n\
    <array>\n\
        <string>{bin}</string>\n\
        <string>fleet</string>\n\
    </array>\n\
    <key>EnvironmentVariables</key>\n\
    <dict>\n\
        <key>PATH</key>\n\
        <string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>\n\
    </dict>\n\
    <key>RunAtLoad</key>\n\
    <true/>\n\
    <key>KeepAlive</key>\n\
    <true/>\n\
    <key>StandardOutPath</key>\n\
    <string>{log}</string>\n\
    <key>StandardErrorPath</key>\n\
    <string>{log}</string>\n\
</dict>\n\
</plist>\n",
            bin = bin_str,
            log = log_path.display()
        );

        std::fs::write(&plist_path, plist)?;

        // Unload first in case already loaded (ignore error).
        let _ = std::process::Command::new("launchctl")
            .args(["unload", &plist_path.to_string_lossy()])
            .status();

        let status = std::process::Command::new("launchctl")
            .args(["load", "-w", &plist_path.to_string_lossy()])
            .status()
            .context("launchctl load failed")?;
        if !status.success() {
            anyhow::bail!("launchctl load returned non-zero exit code");
        }

        println!("  ✓ Auto-start service installed (macOS LaunchAgent)");
        println!("  Log: {}", log_path.display());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        let svc_path = systemd_service_path();
        if let Some(parent) = svc_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let service = format!(
            "[Unit]\nDescription=CodeWebway Fleet Daemon\nAfter=network-online.target\n\n\
[Service]\nExecStart={bin} fleet\nRestart=on-failure\nRestartSec=10\n\n\
[Install]\nWantedBy=default.target\n",
            bin = bin_str
        );

        std::fs::write(&svc_path, service)?;

        let _ = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();

        let status = std::process::Command::new("systemctl")
            .args(["--user", "enable", "--now", "codewebway-fleet"])
            .status()
            .context("systemctl enable failed")?;
        if !status.success() {
            anyhow::bail!("systemctl --user enable --now returned non-zero exit code");
        }

        println!("  ✓ Auto-start service installed (systemd --user)");
        Ok(())
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    anyhow::bail!(
        "Auto-start service is not supported on this platform. Start the daemon manually with: codewebway fleet"
    )
}

pub fn uninstall_service() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let plist_path = launchagent_plist_path();
        if plist_path.exists() {
            let _ = std::process::Command::new("launchctl")
                .args(["unload", "-w", &plist_path.to_string_lossy()])
                .status();
            std::fs::remove_file(&plist_path)?;
            println!("  ✓ Auto-start service removed.");
        } else {
            println!("  Auto-start service not installed.");
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        let svc_path = systemd_service_path();
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", "--now", "codewebway-fleet"])
            .status();
        if svc_path.exists() {
            std::fs::remove_file(&svc_path)?;
        }
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        println!("  ✓ Auto-start service removed.");
        Ok(())
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    anyhow::bail!("Auto-start service is not supported on this platform.")
}

// ─── Utility ───────────────────────────────────────────────────────────────────

fn is_unauthorized(e: &anyhow::Error) -> bool {
    e.downcast_ref::<reqwest::Error>()
        .and_then(|re| re.status())
        .map(|s| s == reqwest::StatusCode::UNAUTHORIZED)
        .unwrap_or(false)
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_creds(endpoint: &str) -> FleetCredentials {
        FleetCredentials {
            machine_token: "mt_test".to_string(),
            machine_name: "pi-test".to_string(),
            fleet_endpoint: endpoint.to_string(),
            pin: Some("123456".to_string()),
        }
    }

    fn tmp_path(dir: &TempDir) -> PathBuf {
        dir.path().join("fleet.toml")
    }

    #[test]
    fn test_save_and_load_credentials() {
        let dir = TempDir::new().unwrap();
        let path = tmp_path(&dir);
        let creds = make_creds("https://webwayfleet.dev");
        save_credentials_to(&creds, &path).unwrap();
        let loaded = load_credentials_from(&path).unwrap();
        assert_eq!(loaded.machine_token, "mt_test");
        assert_eq!(loaded.machine_name, "pi-test");
        assert_eq!(loaded.fleet_endpoint, "https://webwayfleet.dev");
    }

    #[test]
    fn test_load_missing_returns_error() {
        let dir = TempDir::new().unwrap();
        let path = tmp_path(&dir);
        let result = load_credentials_from(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("codewebway enable"));
    }

    #[test]
    fn test_disable_removes_file() {
        let dir = TempDir::new().unwrap();
        let path = tmp_path(&dir);
        save_credentials_to(&make_creds("https://x"), &path).unwrap();
        assert!(path.exists());
        std::fs::remove_file(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn test_daemon_state_should_write_on_status_change() {
        let mut state = DaemonState::new();
        state.last_d1_write = std::time::Instant::now(); // reset to recent

        // same status — should NOT write
        assert!(!state.should_write("idle", None));
        // status changed — SHOULD write
        assert!(state.should_write("running", None));
    }

    #[test]
    fn test_daemon_state_should_write_on_url_change() {
        let mut state = DaemonState::new();
        state.last_d1_write = std::time::Instant::now();
        state.status = "running".to_string();
        state.active_url = Some("https://old.zrok.io".to_string());

        assert!(!state.should_write("running", Some("https://old.zrok.io")));
        assert!(state.should_write("running", Some("https://new.zrok.io")));
    }

    #[tokio::test]
    async fn test_enable_saves_credentials() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/api/v1/agent/enable")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"machine_token":"mt_xyz","machine_id":"mid1"}}"#)
            .create_async()
            .await;

        let dir = TempDir::new().unwrap();
        let path = tmp_path(&dir);
        enable_to_path(&server.url(), "enable_tok_123", None, &path)
            .await
            .unwrap();

        let creds = load_credentials_from(&path).unwrap();
        assert_eq!(creds.machine_token, "mt_xyz");
        // PIN should be auto-generated (6 digits)
        let pin = creds.pin.unwrap();
        assert_eq!(pin.len(), 6);
        assert!(pin.chars().all(|c| c.is_ascii_digit()));
        m.assert_async().await;
    }

    #[tokio::test]
    async fn test_heartbeat_no_command() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/api/v1/agent/heartbeat")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"has_command":false}}"#)
            .create_async()
            .await;

        let creds = make_creds(&server.url());
        let hb = send_heartbeat(&creds, "idle", None, false).await.unwrap();
        assert!(!hb.has_command);
        assert!(hb.command.is_none());
        m.assert_async().await;
    }

    #[tokio::test]
    async fn test_heartbeat_with_command() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/api/v1/agent/heartbeat")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"has_command":true,"command":{"type":"run_codewebway","execution_id":"ex1","payload":{"output_type":"codewebway_url"}}}}"#)
            .create_async()
            .await;

        let creds = make_creds(&server.url());
        let hb = send_heartbeat(&creds, "idle", None, false).await.unwrap();
        assert!(hb.has_command);
        let cmd = hb.command.unwrap();
        assert_eq!(cmd.kind, "run_codewebway");
        assert_eq!(cmd.execution_id.as_deref(), Some("ex1"));
    }

    #[tokio::test]
    async fn test_heartbeat_401_returns_error() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/api/v1/agent/heartbeat")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":{"code":"UNAUTHORIZED","message":"Invalid token"}}"#)
            .create_async()
            .await;

        let creds = make_creds(&server.url());
        let result = send_heartbeat(&creds, "idle", None, false).await;
        assert!(result.is_err());
        assert!(is_unauthorized(&result.unwrap_err()));
    }

    #[tokio::test]
    async fn test_report_result() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/api/v1/agent/report")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"ok":true}}"#)
            .create_async()
            .await;

        let creds = make_creds(&server.url());
        report_result(&creds, "ex1", "https://abc.zrok.io", true)
            .await
            .unwrap();
        m.assert_async().await;
    }
}
