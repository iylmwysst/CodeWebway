use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use qrcode::render::unicode;
use qrcode::types::Color;
use qrcode::QrCode;
use rand::distributions::Alphanumeric;
use rand::Rng;
use reqwest::header::USER_AGENT;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::Request;
use tokio_tungstenite::tungstenite::Message;

// ─── Credentials ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetCredentials {
    pub machine_token: String,
    pub machine_name: String,
    pub fleet_endpoint: String,
    #[serde(default)]
    pub machine_id: Option<String>,
    #[serde(default = "current_epoch_millis")]
    pub machine_token_issued_at: u64,
    /// PIN stored during `enable`; used by the daemon so no flag is needed at runtime.
    pub pin: Option<String>,
}

const MACHINE_TOKEN_ROTATE_INTERVAL_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const CHANNEL_PING_INTERVAL_SECS: u64 = 30;
const CHANNEL_RECONNECT_INTERVAL_SECS: u64 = 10;
const CHANNEL_STALE_AFTER_MS: u64 = 90_000;
const CONNECTED_IDLE_FALLBACK_CHECK_INTERVAL_SECS: u64 = 60 * 60;
const MACHINE_TOKEN_ROTATE_RETRY_INTERVAL_SECS: u64 = 5 * 60;
const RUNTIME_SYNC_INTERVAL_SECS: u64 = 1;
const RECENT_COMMAND_TTL_SECS: u64 = 30 * 60;
const RELEASE_REPOSITORY_API_BASE: &str = "https://api.github.com/repos/iylmwysst/CodeWebway";

fn current_epoch_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)
            .context("Cannot read fleet.toml metadata")?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms).context("Cannot set fleet.toml permissions")?;
    }
    Ok(())
}

// ─── enable / disable ─────────────────────────────────────────────────────────

pub async fn enable(fleet_endpoint: &str, enable_token: &str, pin: Option<String>) -> Result<()> {
    enable_to_path(fleet_endpoint, enable_token, pin, &credentials_path()).await
}

pub async fn enable_to_path(
    fleet_endpoint: &str,
    enable_token: &str,
    pin: Option<String>,
    path: &Path,
) -> Result<()> {
    let client = reqwest::Client::new();
    let resp = client
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
        .json::<EnableResponse>()
        .await?;

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
        machine_token: resp.data.machine_token,
        machine_name: machine_name.clone(),
        fleet_endpoint: fleet_endpoint.to_string(),
        machine_id: resp.data.machine_id,
        machine_token_issued_at: current_epoch_millis(),
        pin: Some(pin.clone()),
    };
    save_credentials_to(&creds, path)?;

    println!("  ✓ Device enabled: \"{machine_name}\"");
    println!("  Credentials saved to {}", path.display());
    Ok(())
}

pub async fn print_status() -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    println!("CodeWebway {version}");
    println!(
        "Platform     : {} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!("Credentials  : {}", credentials_path().display());
    print_service_status();

    let creds = match load_credentials() {
        Ok(creds) => creds,
        Err(err) => {
            println!("Fleet        : disabled");
            println!("Remote       : unavailable ({err})");
            return Ok(());
        }
    };

    println!("Fleet        : enabled");
    println!("Machine name : {}", creds.machine_name);
    println!(
        "Machine ID   : {}",
        creds.machine_id.as_deref().unwrap_or("unknown")
    );
    println!("Endpoint     : {}", creds.fleet_endpoint);
    println!(
        "PIN          : {}",
        if creds.pin.as_deref().is_some() {
            "configured"
        } else {
            "not stored"
        }
    );

    match fetch_remote_status(&creds).await {
        Ok(remote) => {
            println!("Remote       : reachable");
            println!("Owner user   : {}", remote.user_id);
            println!(
                "Project      : {}",
                match remote.project_name.as_deref() {
                    Some(name) if !name.trim().is_empty() => {
                        format!("{name} ({})", remote.project_id)
                    }
                    _ => remote.project_id.clone(),
                }
            );
            println!("Registered   : {}", remote.machine_id);
            println!(
                "Status       : {}",
                remote.status.as_deref().unwrap_or("unknown")
            );
            println!(
                "Transport    : {}",
                format_transport_status(
                    remote.transport_mode.as_deref(),
                    remote.transport_connected,
                    remote.last_channel_event_at
                )
            );
            println!(
                "Last seen    : {}",
                format_relative_timestamp(remote.last_seen)
            );
            println!(
                "Version      : local {} · fleet {}",
                version,
                remote.agent_version.as_deref().unwrap_or("unknown")
            );
            if let Some(hostname) = remote
                .hostname
                .as_deref()
                .filter(|value| !value.trim().is_empty())
            {
                println!("Hostname     : {hostname}");
            }
            if let Some(machine_id) = creds.machine_id.as_deref() {
                if machine_id != remote.machine_id {
                    println!("Warning      : local machine_id differs from fleet record");
                }
            }
        }
        Err(err) => {
            println!(
                "Remote       : unavailable ({})",
                summarize_remote_status_error(&err)
            );
        }
    }

    Ok(())
}

fn remove_file_if_exists(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    std::fs::remove_file(path)?;
    Ok(true)
}

fn disable_at_path(path: &Path) -> Result<bool> {
    remove_file_if_exists(path)
}

pub fn disable() -> Result<()> {
    let path = credentials_path();
    if disable_at_path(&path)? {
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
struct EnableResponse {
    data: EnableResponseData,
}

#[derive(Debug, Deserialize)]
struct EnableResponseData {
    machine_token: String,
    #[serde(default)]
    machine_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RemoteStatusResponse {
    data: RemoteStatusData,
}

#[derive(Debug, Deserialize)]
struct RemoteStatusData {
    machine_id: String,
    user_id: String,
    project_id: String,
    #[serde(default)]
    project_name: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    transport_mode: Option<String>,
    #[serde(default)]
    transport_connected: Option<u8>,
    #[serde(default)]
    last_seen: Option<u64>,
    #[serde(default)]
    last_channel_event_at: Option<u64>,
    #[serde(default)]
    agent_version: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HeartbeatData {
    pub has_command: bool,
    pub command: Option<PendingCommand>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PendingCommand {
    pub execution_id: Option<String>,
    #[serde(default)]
    pub command_key: Option<String>,
    #[serde(rename = "type")]
    pub kind: String,
    #[allow(dead_code)]
    pub payload: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct ReleaseApiAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug, Deserialize)]
struct ReleaseApiResponse {
    tag_name: String,
    assets: Vec<ReleaseApiAsset>,
}

#[derive(Debug, Clone)]
struct ClientUpdatePlan {
    execution_id: String,
    target_version: String,
    download_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingUpdateReport {
    execution_id: String,
    target_version: String,
}

fn payload_bool(payload: &serde_json::Value, key: &str) -> Option<bool> {
    payload.get(key).and_then(|v| v.as_bool())
}

fn payload_u64_in_range(payload: &serde_json::Value, key: &str, min: u64, max: u64) -> Option<u64> {
    let value = payload.get(key).and_then(|v| v.as_u64())?;
    if value < min || value > max {
        return None;
    }
    Some(value)
}

fn payload_str(payload: &serde_json::Value, key: &str) -> Option<String> {
    payload
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

fn release_tag_from_payload(payload: &serde_json::Value) -> Option<String> {
    payload_str(payload, "release_tag")
}

fn release_api_base_from_payload(payload: &serde_json::Value) -> Option<String> {
    payload_str(payload, "release_api_base")
}

fn current_release_target() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin"),
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-musl"),
        ("linux", "aarch64") => Ok("aarch64-unknown-linux-musl"),
        ("linux", "arm") | ("linux", "armv7") | ("linux", "armv7l") => {
            Ok("aarch64-unknown-linux-musl")
        }
        (os, arch) => anyhow::bail!("Self-update is not supported on {os}/{arch}."),
    }
}

fn normalize_release_version(value: &str) -> &str {
    value.strip_prefix('v').unwrap_or(value)
}

fn current_version_matches_release(tag: &str) -> bool {
    normalize_release_version(tag) == env!("CARGO_PKG_VERSION")
}

fn pending_update_report_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("codewebway")
        .join("pending-update.json")
}

fn load_pending_update_report() -> Result<Option<PendingUpdateReport>> {
    load_pending_update_report_from(&pending_update_report_path())
}

fn load_pending_update_report_from(path: &Path) -> Result<Option<PendingUpdateReport>> {
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read pending update report at {}", path.display()))?;
    let report = serde_json::from_str(&data)
        .with_context(|| format!("Malformed pending update report at {}", path.display()))?;
    Ok(Some(report))
}

fn save_pending_update_report(report: &PendingUpdateReport) -> Result<()> {
    save_pending_update_report_to(report, &pending_update_report_path())
}

fn save_pending_update_report_to(report: &PendingUpdateReport, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_vec_pretty(report)?;
    std::fs::write(path, data)?;
    Ok(())
}

fn clear_pending_update_report() -> Result<bool> {
    clear_pending_update_report_at(&pending_update_report_path())
}

fn clear_pending_update_report_at(path: &Path) -> Result<bool> {
    remove_file_if_exists(path)
}

async fn fetch_remote_status(creds: &FleetCredentials) -> Result<RemoteStatusData> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/api/v1/agent/status", creds.fleet_endpoint))
        .bearer_auth(&creds.machine_token)
        .send()
        .await?
        .error_for_status()?
        .json::<RemoteStatusResponse>()
        .await?;
    Ok(response.data)
}

fn summarize_remote_status_error(err: &anyhow::Error) -> String {
    if let Some(req_err) = err.downcast_ref::<reqwest::Error>() {
        if let Some(status) = req_err.status() {
            return match status {
                reqwest::StatusCode::UNAUTHORIZED => {
                    "token rejected or machine no longer exists".to_string()
                }
                reqwest::StatusCode::NOT_FOUND => "machine not found in fleet".to_string(),
                other => format!("fleet returned {other}"),
            };
        }
    }
    err.to_string()
}

fn format_relative_timestamp(value: Option<u64>) -> String {
    let Some(timestamp_ms) = value else {
        return "unknown".to_string();
    };
    let now = current_epoch_millis();
    if timestamp_ms > now {
        return "just now".to_string();
    }
    let delta_secs = (now - timestamp_ms) / 1000;
    if delta_secs < 60 {
        return format!("{delta_secs}s ago");
    }
    let delta_mins = delta_secs / 60;
    if delta_mins < 60 {
        return format!("{delta_mins}m ago");
    }
    let delta_hours = delta_mins / 60;
    if delta_hours < 48 {
        return format!("{delta_hours}h ago");
    }
    let delta_days = delta_hours / 24;
    format!("{delta_days}d ago")
}

fn format_transport_status(
    mode: Option<&str>,
    connected: Option<u8>,
    last_channel_event_at: Option<u64>,
) -> String {
    match mode.unwrap_or("unknown") {
        "realtime" => {
            if connected == Some(1) {
                "realtime connected".to_string()
            } else if last_channel_event_at.is_some() {
                format!(
                    "realtime reconnecting · last channel event {}",
                    format_relative_timestamp(last_channel_event_at)
                )
            } else {
                "realtime disconnected".to_string()
            }
        }
        "heartbeat" => "heartbeat".to_string(),
        other => other.to_string(),
    }
}

fn print_service_status() {
    #[cfg(target_os = "macos")]
    {
        let service_path = launchagent_plist_path();
        println!(
            "Auto-start    : {} ({})",
            if service_path.exists() {
                "installed"
            } else {
                "not installed"
            },
            service_path.display()
        );
    }

    #[cfg(target_os = "linux")]
    {
        let service_path = systemd_service_path();
        println!(
            "Auto-start    : {} ({})",
            if service_path.exists() {
                "installed"
            } else {
                "not installed"
            },
            service_path.display()
        );
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        println!("Auto-start    : unsupported on this platform");
    }
}

pub async fn send_heartbeat(
    creds: &FleetCredentials,
    status: &str,
    active_url: Option<&str>,
    runtime_instance_id: Option<&str>,
    skip_status_write: bool,
) -> Result<HeartbeatData> {
    let client = reqwest::Client::new();
    let mut body = serde_json::json!({
        "status": status,
        "agent_version": env!("CARGO_PKG_VERSION"),
        "skip_status_write": skip_status_write,
    });
    if let Some(url) = active_url {
        body["active_url"] = serde_json::json!(url);
    }
    if let Some(runtime_instance_id) = runtime_instance_id {
        body["runtime_instance_id"] = serde_json::json!(runtime_instance_id);
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

async fn report_result_via_channel_or_http(
    channel: Option<&MachineChannelClient>,
    creds: &FleetCredentials,
    execution_id: &str,
    output: &str,
    success: bool,
) -> Result<()> {
    if let Some(client) = channel {
        if client.send_report(execution_id, output, success).is_ok() {
            return Ok(());
        }
        eprintln!("  Fleet: realtime report send failed, falling back to HTTP.");
    }
    report_result(creds, execution_id, output, success).await
}

fn release_api_base() -> &'static str {
    RELEASE_REPOSITORY_API_BASE
}

async fn fetch_latest_release_plan_from(
    base: &str,
    execution_id: &str,
) -> Result<ClientUpdatePlan> {
    let asset_target = current_release_target()?;
    let expected_asset_name = format!("codewebway-{asset_target}");
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{base}/releases/latest"))
        .header(
            USER_AGENT,
            format!("codewebway/{}", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .await?
        .error_for_status()?
        .json::<ReleaseApiResponse>()
        .await?;
    let tag_name = response.tag_name;
    let asset = response
        .assets
        .into_iter()
        .find(|candidate| candidate.name == expected_asset_name)
        .with_context(|| {
            format!(
                "Latest release {} did not include asset {}",
                tag_name, expected_asset_name
            )
        })?;

    Ok(ClientUpdatePlan {
        execution_id: execution_id.to_string(),
        target_version: normalize_release_version(&tag_name).to_string(),
        download_url: asset.browser_download_url,
    })
}

async fn fetch_release_plan_by_tag_from(
    base: &str,
    execution_id: &str,
    release_tag: &str,
) -> Result<ClientUpdatePlan> {
    let asset_target = current_release_target()?;
    let expected_asset_name = format!("codewebway-{asset_target}");
    let encoded_tag = release_tag.replace('/', "%2F");
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{base}/releases/tags/{encoded_tag}"))
        .header(
            USER_AGENT,
            format!("codewebway/{}", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .await?
        .error_for_status()?
        .json::<ReleaseApiResponse>()
        .await?;
    let tag_name = response.tag_name;
    let asset = response
        .assets
        .into_iter()
        .find(|candidate| candidate.name == expected_asset_name)
        .with_context(|| {
            format!(
                "Release {} did not include asset {}",
                tag_name, expected_asset_name
            )
        })?;

    Ok(ClientUpdatePlan {
        execution_id: execution_id.to_string(),
        target_version: normalize_release_version(&tag_name).to_string(),
        download_url: asset.browser_download_url,
    })
}

fn staged_update_binary_path(exe_path: &Path) -> Result<PathBuf> {
    let file_name = exe_path
        .file_name()
        .and_then(|value| value.to_str())
        .context("Cannot determine executable filename for self-update")?;
    Ok(exe_path.with_file_name(format!("{file_name}.update-download")))
}

async fn download_release_binary(url: &str, destination: &Path) -> Result<()> {
    let client = reqwest::Client::new();
    let bytes = client
        .get(url)
        .header(
            USER_AGENT,
            format!("codewebway/{}", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    if bytes.is_empty() {
        anyhow::bail!("Downloaded release asset was empty");
    }

    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = remove_file_if_exists(destination);
    std::fs::write(destination, bytes)?;
    Ok(())
}

fn install_downloaded_binary(download_path: &Path, exe_path: &Path) -> Result<()> {
    let metadata = std::fs::metadata(exe_path)
        .with_context(|| format!("Cannot read executable metadata for {}", exe_path.display()))?;
    std::fs::set_permissions(download_path, metadata.permissions()).with_context(|| {
        format!(
            "Cannot set permissions on downloaded binary at {}",
            download_path.display()
        )
    })?;
    std::fs::rename(download_path, exe_path).with_context(|| {
        format!(
            "Cannot replace executable {} with downloaded update",
            exe_path.display()
        )
    })?;
    Ok(())
}

fn restart_current_process() -> Result<()> {
    let exe_path = std::env::current_exe().context("Cannot locate current executable")?;
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        let err = std::process::Command::new(&exe_path).args(&args).exec();
        anyhow::bail!(
            "Failed to exec updated client {}: {}",
            exe_path.display(),
            err
        );
    }

    #[cfg(not(unix))]
    {
        let _ = exe_path;
        let _ = args;
        anyhow::bail!("Self-update restart is not supported on this platform.");
    }
}

async fn flush_pending_update_report(
    creds: &FleetCredentials,
    pending_report: &mut Option<PendingUpdateReport>,
) {
    let Some(report) = pending_report.as_ref() else {
        return;
    };

    let current_version = env!("CARGO_PKG_VERSION");
    let (success, output) = if normalize_release_version(&report.target_version) == current_version
    {
        (true, format!("updated to {current_version}"))
    } else {
        (
            false,
            format!(
                "update restart version mismatch: expected {}, running {}",
                report.target_version, current_version
            ),
        )
    };

    match report_result(creds, &report.execution_id, &output, success).await {
        Ok(_) => {
            if let Err(err) = clear_pending_update_report() {
                eprintln!("  Fleet: failed to clear pending update report: {err}");
            }
            *pending_report = None;
        }
        Err(err) => {
            if is_unauthorized(&err) {
                cleanup_local_fleet_state_and_exit("device deregistered (401)");
            }
            eprintln!("  Fleet: pending update report retry failed: {err}");
        }
    }
}

async fn resolve_client_update_plan(
    channel: Option<&MachineChannelClient>,
    creds: &FleetCredentials,
    cmd: &PendingCommand,
) -> Result<Option<ClientUpdatePlan>> {
    let execution_id = cmd.execution_id.clone().unwrap_or_default();
    if execution_id.is_empty() {
        anyhow::bail!("Update command is missing execution_id");
    }

    let release_api_base = release_api_base_from_payload(&cmd.payload)
        .unwrap_or_else(|| release_api_base().to_string());
    let plan = if let Some(release_tag) = release_tag_from_payload(&cmd.payload) {
        fetch_release_plan_by_tag_from(&release_api_base, &execution_id, &release_tag).await?
    } else {
        fetch_latest_release_plan_from(&release_api_base, &execution_id).await?
    };
    if current_version_matches_release(&plan.target_version) {
        report_result_via_channel_or_http(
            channel,
            creds,
            &execution_id,
            &format!("already on {}", env!("CARGO_PKG_VERSION")),
            true,
        )
        .await?;
        return Ok(None);
    }

    Ok(Some(plan))
}

async fn report_client_update_failure(
    channel: Option<&MachineChannelClient>,
    creds: &FleetCredentials,
    execution_id: &str,
    err: &anyhow::Error,
) {
    if execution_id.is_empty() {
        return;
    }
    if let Err(report_err) =
        report_result_via_channel_or_http(channel, creds, execution_id, &err.to_string(), false)
            .await
    {
        eprintln!("  Fleet: failed to report client update failure: {report_err}");
    }
}

async fn apply_client_update_plan(plan: &ClientUpdatePlan) -> Result<()> {
    let exe_path = std::env::current_exe().context("Cannot determine current executable path")?;
    let staged_binary_path = staged_update_binary_path(&exe_path)?;

    if let Err(err) = download_release_binary(&plan.download_url, &staged_binary_path).await {
        let _ = remove_file_if_exists(&staged_binary_path);
        return Err(err);
    }

    let report = PendingUpdateReport {
        execution_id: plan.execution_id.clone(),
        target_version: plan.target_version.clone(),
    };
    if let Err(err) = save_pending_update_report(&report) {
        let _ = remove_file_if_exists(&staged_binary_path);
        return Err(err);
    }

    if let Err(err) = install_downloaded_binary(&staged_binary_path, &exe_path) {
        let _ = clear_pending_update_report();
        let _ = remove_file_if_exists(&staged_binary_path);
        return Err(err);
    }

    if let Err(err) = restart_current_process() {
        let _ = clear_pending_update_report();
        return Err(err);
    }

    Ok(())
}

async fn perform_client_update(
    channel: Option<&MachineChannelClient>,
    creds: &FleetCredentials,
    cmd: &PendingCommand,
) -> Result<()> {
    let execution_id = cmd.execution_id.clone().unwrap_or_default();
    let plan = match resolve_client_update_plan(channel, creds, cmd).await {
        Ok(plan) => plan,
        Err(err) => {
            report_client_update_failure(channel, creds, &execution_id, &err).await;
            return Err(err);
        }
    };

    let Some(plan) = plan else {
        return Ok(());
    };

    if let Err(err) = apply_client_update_plan(&plan).await {
        report_client_update_failure(channel, creds, &execution_id, &err).await;
        return Err(err);
    }

    Ok(())
}

fn build_runtime_output(url: &str, access_token: &str, runtime_instance_id: &str) -> String {
    serde_json::json!({
        "kind": "codewebway_runtime",
        "url": url,
        "access_token": access_token,
        "access_token_ttl_secs": 12 * 60 * 60,
        "runtime_instance_id": runtime_instance_id,
    })
    .to_string()
}

fn machine_channel_url(fleet_endpoint: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(fleet_endpoint).context("Invalid fleet endpoint URL")?;
    match url.scheme() {
        "https" => {
            url.set_scheme("wss")
                .map_err(|_| anyhow::anyhow!("Failed to convert fleet endpoint to wss"))?;
        }
        "http" => {
            url.set_scheme("ws")
                .map_err(|_| anyhow::anyhow!("Failed to convert fleet endpoint to ws"))?;
        }
        other => anyhow::bail!("Unsupported fleet endpoint scheme for realtime channel: {other}"),
    }
    url.set_path("/api/v1/agent/channel");
    url.set_query(None);
    Ok(url.to_string())
}

fn build_channel_snapshot_message(
    kind: &'static str,
    status: &str,
    active_url: Option<&str>,
    runtime_instance_id: Option<&str>,
    skip_status_write: bool,
) -> String {
    let mut payload = serde_json::json!({
        "type": kind,
        "status": status,
        "agent_version": env!("CARGO_PKG_VERSION"),
    });
    if let Some(url) = active_url {
        payload["active_url"] = serde_json::json!(url);
    }
    if let Some(runtime_instance_id) = runtime_instance_id {
        payload["runtime_instance_id"] = serde_json::json!(runtime_instance_id);
    }
    if skip_status_write {
        payload["skip_status_write"] = serde_json::json!(true);
    }
    payload.to_string()
}

fn build_channel_report_message(execution_id: &str, output: &str, success: bool) -> String {
    serde_json::json!({
        "type": "report",
        "execution_id": execution_id,
        "status": if success { "success" } else { "failed" },
        "output": output,
    })
    .to_string()
}

fn build_channel_command_ack_message(cmd: &PendingCommand, duplicate: bool) -> String {
    serde_json::json!({
        "type": "command_ack",
        "command_key": cmd.command_key,
        "execution_id": cmd.execution_id,
        "duplicate": duplicate,
    })
    .to_string()
}

fn build_machine_channel_request(creds: &FleetCredentials) -> Result<Request<()>> {
    let mut request = machine_channel_url(&creds.fleet_endpoint)?
        .into_client_request()
        .context("Failed to build realtime channel request")?;
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {}", creds.machine_token)
            .parse()
            .context("Failed to encode realtime channel authorization header")?,
    );
    Ok(request)
}

#[derive(Debug, Deserialize)]
struct ChannelCommandEnvelope {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    command_key: Option<String>,
    command: ChannelCommandPayload,
}

#[derive(Debug, Deserialize)]
struct ChannelCommandPayload {
    #[serde(rename = "type")]
    kind: String,
    payload: serde_json::Value,
}

fn parse_channel_command_message(text: &str) -> Option<PendingCommand> {
    let envelope: ChannelCommandEnvelope = serde_json::from_str(text).ok()?;
    if envelope.kind != "command" {
        return None;
    }
    let execution_id = envelope
        .command
        .payload
        .get("execution_id")
        .and_then(|value| value.as_str())
        .map(ToString::to_string);
    Some(PendingCommand {
        execution_id,
        command_key: envelope.command_key,
        kind: envelope.command.kind,
        payload: envelope.command.payload,
    })
}

fn command_identity(cmd: &PendingCommand) -> Option<String> {
    cmd.command_key
        .clone()
        .or_else(|| cmd.execution_id.clone())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

struct MachineChannelClient {
    outbound_tx: tokio::sync::mpsc::UnboundedSender<String>,
    command_rx: tokio::sync::mpsc::UnboundedReceiver<PendingCommand>,
}

impl MachineChannelClient {
    async fn connect(creds: &FleetCredentials, state: &DaemonState) -> Result<Self> {
        let request = build_machine_channel_request(creds)?;
        let (socket, _response) = connect_async(request)
            .await
            .context("Failed to connect realtime machine channel")?;
        let (mut writer, mut reader) = socket.split();
        writer
            .send(Message::Text(build_channel_snapshot_message(
                "hello",
                &state.status,
                state.active_url.as_deref(),
                state.runtime_instance_id.as_deref(),
                false,
            )))
            .await
            .context("Failed to send realtime hello")?;

        let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let (command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel::<PendingCommand>();
        let last_inbound_activity_ms = Arc::new(AtomicU64::new(current_epoch_millis()));
        let reader_activity = Arc::clone(&last_inbound_activity_ms);
        let writer_activity = Arc::clone(&last_inbound_activity_ms);

        tokio::spawn(async move {
            let mut ping_tick =
                tokio::time::interval(std::time::Duration::from_secs(CHANNEL_PING_INTERVAL_SECS));
            ping_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    maybe_outbound = outbound_rx.recv() => {
                        let Some(payload) = maybe_outbound else {
                            let _ = writer.send(Message::Close(None)).await;
                            break;
                        };
                        if let Err(err) = writer.send(Message::Text(payload)).await {
                            eprintln!("  Fleet: realtime channel send failed: {err}");
                            break;
                        }
                    }
                    incoming = reader.next() => {
                        match incoming {
                            Some(Ok(Message::Text(text))) => {
                                reader_activity.store(current_epoch_millis(), Ordering::Relaxed);
                                if let Some(command) = parse_channel_command_message(&text) {
                                    let _ = command_tx.send(command);
                                }
                            }
                            Some(Ok(Message::Pong(_))) | Some(Ok(Message::Ping(_))) => {
                                reader_activity.store(current_epoch_millis(), Ordering::Relaxed);
                            }
                            Some(Ok(Message::Close(_))) | None => break,
                            Some(Ok(_)) => {
                                reader_activity.store(current_epoch_millis(), Ordering::Relaxed);
                            }
                            Some(Err(err)) => {
                                eprintln!("  Fleet: realtime channel receive failed: {err}");
                                break;
                            }
                        }
                    }
                    _ = ping_tick.tick() => {
                        let last_inbound = writer_activity.load(Ordering::Relaxed);
                        if current_epoch_millis().saturating_sub(last_inbound) >= CHANNEL_STALE_AFTER_MS {
                            eprintln!("  Fleet: realtime channel stale, forcing reconnect.");
                            let _ = writer.send(Message::Close(None)).await;
                            break;
                        }
                        if let Err(err) = writer.send(Message::Ping(Vec::<u8>::new())).await {
                            eprintln!("  Fleet: realtime channel ping failed: {err}");
                            break;
                        }
                    }
                }
            }
        });

        Ok(Self {
            outbound_tx,
            command_rx,
        })
    }

    fn send_message(&self, payload: String) -> Result<()> {
        self.outbound_tx
            .send(payload)
            .map_err(|_| anyhow::anyhow!("Realtime machine channel is closed"))
    }

    fn send_snapshot(&self, state: &DaemonState, skip_status_write: bool) -> Result<()> {
        self.send_message(build_channel_snapshot_message(
            "snapshot",
            &state.status,
            state.active_url.as_deref(),
            state.runtime_instance_id.as_deref(),
            skip_status_write,
        ))
    }

    fn send_report(&self, execution_id: &str, output: &str, success: bool) -> Result<()> {
        self.send_message(build_channel_report_message(execution_id, output, success))
    }

    fn send_command_ack(&self, cmd: &PendingCommand, duplicate: bool) -> Result<()> {
        self.send_message(build_channel_command_ack_message(cmd, duplicate))
    }

    async fn recv_command(&mut self) -> Option<PendingCommand> {
        self.command_rx.recv().await
    }
}

fn should_attempt_realtime_channel_connect(
    channel: &mut Option<MachineChannelClient>,
    next_retry_at: &mut std::time::Instant,
) -> bool {
    channel.is_none() && std::time::Instant::now() >= *next_retry_at
}

fn apply_realtime_channel_connect_result(
    channel: &mut Option<MachineChannelClient>,
    next_retry_at: &mut std::time::Instant,
    retry_interval: std::time::Duration,
    result: Result<MachineChannelClient>,
) -> bool {
    match result {
        Ok(client) => {
            eprintln!("  Fleet: realtime channel connected.");
            *channel = Some(client);
            true
        }
        Err(err) => {
            eprintln!("  Fleet: realtime channel unavailable: {err}");
            *next_retry_at = std::time::Instant::now() + retry_interval;
            false
        }
    }
}

async fn maybe_connect_realtime_channel(
    creds: &FleetCredentials,
    state: &DaemonState,
    channel: &mut Option<MachineChannelClient>,
    next_retry_at: &mut std::time::Instant,
    retry_interval: std::time::Duration,
) -> bool {
    if !should_attempt_realtime_channel_connect(channel, next_retry_at) {
        return false;
    }

    apply_realtime_channel_connect_result(
        channel,
        next_retry_at,
        retry_interval,
        MachineChannelClient::connect(creds, state).await,
    )
}

fn try_send_channel_snapshot(
    channel: &mut Option<MachineChannelClient>,
    state: &DaemonState,
    skip_status_write: bool,
) {
    let Some(client) = channel.as_ref() else {
        return;
    };
    if let Err(err) = client.send_snapshot(state, skip_status_write) {
        eprintln!("  Fleet: realtime snapshot send failed: {err}");
        *channel = None;
    }
}

struct RecentCommandTracker {
    seen: HashMap<String, std::time::Instant>,
}

impl RecentCommandTracker {
    fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    fn prune(&mut self) {
        let ttl = std::time::Duration::from_secs(RECENT_COMMAND_TTL_SECS);
        self.seen.retain(|_, seen_at| seen_at.elapsed() < ttl);
    }

    fn record_or_is_duplicate(&mut self, cmd: &PendingCommand) -> bool {
        let Some(key) = command_identity(cmd) else {
            return false;
        };
        self.prune();
        if let Some(previous) = self.seen.get(&key) {
            if previous.elapsed() < std::time::Duration::from_secs(RECENT_COMMAND_TTL_SECS) {
                return true;
            }
        }
        self.seen.insert(key, std::time::Instant::now());
        false
    }
}

fn acknowledge_realtime_command(
    channel: Option<&MachineChannelClient>,
    cmd: &PendingCommand,
    duplicate: bool,
) {
    let Some(client) = channel else {
        return;
    };
    if let Err(err) = client.send_command_ack(cmd, duplicate) {
        eprintln!("  Fleet: realtime command ack failed: {err}");
    }
}

async fn report_terminal_stopped_if_idle(
    channel: Option<&MachineChannelClient>,
    creds: &FleetCredentials,
    cmd: &PendingCommand,
) {
    let exec_id = cmd.execution_id.clone().unwrap_or_default();
    if exec_id.is_empty() {
        return;
    }
    if let Err(err) =
        report_result_via_channel_or_http(channel, creds, &exec_id, "stopped", true).await
    {
        eprintln!("  Fleet: failed to report already-stopped terminal: {err}");
    }
}

async fn decommission_self_and_exit(
    channel: Option<&MachineChannelClient>,
    creds: &FleetCredentials,
    cmd: &PendingCommand,
) -> ! {
    let exec_id = cmd.execution_id.clone().unwrap_or_default();
    if !exec_id.is_empty() {
        if let Err(err) =
            report_result_via_channel_or_http(channel, creds, &exec_id, "decommissioned", true)
                .await
        {
            eprintln!("  Fleet: failed to report decommission success: {err}");
        }
    }
    cleanup_local_fleet_state_and_exit("machine decommissioned locally");
}

#[derive(Debug, Deserialize)]
struct RotateTokenResponse {
    data: RotateTokenData,
}

#[derive(Debug, Deserialize)]
struct RotateTokenData {
    machine_token: String,
}

fn should_rotate_machine_token(creds: &FleetCredentials) -> bool {
    current_epoch_millis().saturating_sub(creds.machine_token_issued_at)
        >= MACHINE_TOKEN_ROTATE_INTERVAL_MS
}

async fn rotate_machine_token(creds: &mut FleetCredentials) -> Result<bool> {
    if !should_rotate_machine_token(creds) {
        return Ok(false);
    }

    let client = reqwest::Client::new();
    let response = client
        .post(format!(
            "{}/api/v1/agent/token/rotate",
            creds.fleet_endpoint
        ))
        .bearer_auth(&creds.machine_token)
        .json(&serde_json::json!({}))
        .send()
        .await?;

    if response.status() == reqwest::StatusCode::CONFLICT {
        return Ok(false);
    }
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        anyhow::bail!("Machine token rejected — machine may have been deleted from Dashboard.");
    }
    let payload = response
        .error_for_status()?
        .json::<RotateTokenResponse>()
        .await?;
    creds.machine_token = payload.data.machine_token;
    creds.machine_token_issued_at = current_epoch_millis();
    save_credentials(creds)?;
    Ok(true)
}

fn next_machine_token_rotation_at(creds: &FleetCredentials) -> std::time::Instant {
    let age_ms = current_epoch_millis().saturating_sub(creds.machine_token_issued_at);
    let remaining_ms = MACHINE_TOKEN_ROTATE_INTERVAL_MS.saturating_sub(age_ms);
    std::time::Instant::now() + std::time::Duration::from_millis(remaining_ms)
}

fn retry_machine_token_rotation_at() -> std::time::Instant {
    std::time::Instant::now()
        + std::time::Duration::from_secs(MACHINE_TOKEN_ROTATE_RETRY_INTERVAL_SECS)
}

fn next_connected_fallback_check_at(interval: std::time::Duration) -> std::time::Instant {
    std::time::Instant::now() + interval
}

// ─── Daemon state ──────────────────────────────────────────────────────────────

struct DaemonState {
    status: String,
    active_url: Option<String>,
    runtime_instance_id: Option<String>,
    last_d1_write: std::time::Instant,
}

impl DaemonState {
    fn new() -> Self {
        Self {
            status: "idle".to_string(),
            active_url: None,
            runtime_instance_id: None,
            // force write on first heartbeat
            last_d1_write: std::time::Instant::now() - std::time::Duration::from_secs(400),
        }
    }

    fn should_write(
        &self,
        new_status: &str,
        new_url: Option<&str>,
        new_runtime_instance_id: Option<&str>,
    ) -> bool {
        new_status != self.status
            || new_url != self.active_url.as_deref()
            || new_runtime_instance_id != self.runtime_instance_id.as_deref()
            || self.last_d1_write.elapsed() > std::time::Duration::from_secs(300)
    }
}

struct RunningRuntime {
    execution_id: String,
    access_token: String,
    runtime_instance_id: String,
    zrok_url_state: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    ready_reported: bool,
}

impl RunningRuntime {
    fn current_url(&self) -> Option<String> {
        self.zrok_url_state
            .lock()
            .ok()
            .and_then(|current| current.clone())
    }
}

async fn sync_runtime_ready(
    creds: &FleetCredentials,
    state: &mut DaemonState,
    runtime: &mut RunningRuntime,
    channel: Option<&MachineChannelClient>,
) {
    let latest_url = runtime.current_url();
    if latest_url != state.active_url {
        state.active_url = latest_url.clone();
        if latest_url.is_some() {
            state.last_d1_write = std::time::Instant::now() - std::time::Duration::from_secs(400);
        }
    }

    if runtime.ready_reported {
        return;
    }

    let Some(url) = latest_url.as_deref() else {
        return;
    };

    if runtime.execution_id.is_empty() {
        runtime.ready_reported = true;
        return;
    }

    let output = build_runtime_output(url, &runtime.access_token, &runtime.runtime_instance_id);
    match report_result_via_channel_or_http(channel, creds, &runtime.execution_id, &output, true)
        .await
    {
        Ok(_) => runtime.ready_reported = true,
        Err(e) => eprintln!("  Fleet: report failed: {e}"),
    }
}

async fn report_runtime_start_failed_if_needed(
    channel: Option<&MachineChannelClient>,
    creds: &FleetCredentials,
    runtime: &RunningRuntime,
    reason: &str,
) {
    if runtime.ready_reported || runtime.execution_id.is_empty() {
        return;
    }
    if let Err(e) =
        report_result_via_channel_or_http(channel, creds, &runtime.execution_id, reason, false)
            .await
    {
        eprintln!("  Fleet: failed to report runtime start failure: {e}");
    }
}

async fn write_status_now(creds: &FleetCredentials, state: &mut DaemonState, context: &str) {
    match send_heartbeat(
        creds,
        &state.status,
        state.active_url.as_deref(),
        state.runtime_instance_id.as_deref(),
        false,
    )
    .await
    {
        Ok(_) => {
            state.last_d1_write = std::time::Instant::now();
        }
        Err(e) => {
            if is_unauthorized(&e) {
                cleanup_local_fleet_state_and_exit("device deregistered (401)");
            }
            eprintln!("  Fleet: heartbeat error {context}: {e}");
        }
    }
}

// ─── Daemon loop ───────────────────────────────────────────────────────────────

pub async fn run_daemon(cfg: crate::config::Config) -> anyhow::Result<()> {
    let mut creds = load_credentials().context("Not enabled. Run: codewebway enable <token>")?;
    let mut pending_update_report = match load_pending_update_report() {
        Ok(report) => report,
        Err(err) => {
            eprintln!("  Fleet: ignoring malformed pending update report: {err}");
            let _ = clear_pending_update_report();
            None
        }
    };

    println!("  Fleet daemon starting for \"{}\"", creds.machine_name);
    println!("  Endpoint: {}", creds.fleet_endpoint);

    let mut state = DaemonState::new();
    let poll_interval = std::time::Duration::from_secs(30);
    let channel_retry_interval = std::time::Duration::from_secs(CHANNEL_RECONNECT_INTERVAL_SECS);
    let connected_idle_fallback_check_interval =
        std::time::Duration::from_secs(CONNECTED_IDLE_FALLBACK_CHECK_INTERVAL_SECS);
    let mut channel: Option<MachineChannelClient> = None;
    let mut next_channel_retry = std::time::Instant::now();
    let mut next_idle_token_rotation = next_machine_token_rotation_at(&creds);
    let mut next_connected_fallback_check =
        next_connected_fallback_check_at(connected_idle_fallback_check_interval);
    let mut recent_commands = RecentCommandTracker::new();
    flush_pending_update_report(&creds, &mut pending_update_report).await;

    loop {
        if maybe_connect_realtime_channel(
            &creds,
            &state,
            &mut channel,
            &mut next_channel_retry,
            channel_retry_interval,
        )
        .await
        {
            try_send_channel_snapshot(&mut channel, &state, true);
            flush_pending_update_report(&creds, &mut pending_update_report).await;
            next_connected_fallback_check =
                next_connected_fallback_check_at(connected_idle_fallback_check_interval);
        }

        enum IdleWaitResult {
            Command(PendingCommand),
            ChannelClosed,
            FallbackCheck,
            RotateToken,
            Reconcile,
        }

        let idle_wait = if let Some(channel_client) = channel.as_mut() {
            let token_rotation_sleep = tokio::time::sleep_until(next_idle_token_rotation.into());
            tokio::pin!(token_rotation_sleep);
            let fallback_check_sleep =
                tokio::time::sleep_until(next_connected_fallback_check.into());
            tokio::pin!(fallback_check_sleep);
            tokio::select! {
                command = channel_client.recv_command() => {
                    match command {
                        Some(cmd) => IdleWaitResult::Command(cmd),
                        None => IdleWaitResult::ChannelClosed,
                    }
                },
                _ = &mut fallback_check_sleep => IdleWaitResult::FallbackCheck,
                _ = &mut token_rotation_sleep => IdleWaitResult::RotateToken,
            }
        } else {
            tokio::time::sleep(poll_interval).await;
            IdleWaitResult::Reconcile
        };

        let realtime_command = match idle_wait {
            IdleWaitResult::Command(cmd) => Some(cmd),
            IdleWaitResult::ChannelClosed => {
                eprintln!("  Fleet: realtime channel disconnected.");
                channel = None;
                next_channel_retry = std::time::Instant::now() + channel_retry_interval;
                None
            }
            IdleWaitResult::FallbackCheck => None,
            IdleWaitResult::RotateToken => {
                match rotate_machine_token(&mut creds).await {
                    Ok(true) => {
                        eprintln!("  Fleet: rotated machine token during realtime idle window.");
                        next_idle_token_rotation = next_machine_token_rotation_at(&creds);
                    }
                    Ok(false) => {
                        next_idle_token_rotation = if should_rotate_machine_token(&creds) {
                            retry_machine_token_rotation_at()
                        } else {
                            next_machine_token_rotation_at(&creds)
                        };
                    }
                    Err(e) => {
                        eprintln!("  Fleet: token rotation skipped: {e}");
                        next_idle_token_rotation = retry_machine_token_rotation_at();
                    }
                }
                None
            }
            IdleWaitResult::Reconcile => None,
        };

        if let Some(cmd) = realtime_command {
            let duplicate = recent_commands.record_or_is_duplicate(&cmd);
            acknowledge_realtime_command(channel.as_ref(), &cmd, duplicate);
            if duplicate {
                eprintln!(
                    "  Fleet: duplicate realtime command ignored: {} {}",
                    cmd.kind,
                    cmd.execution_id.as_deref().unwrap_or("no-exec-id")
                );
                continue;
            }
            match cmd.kind.as_str() {
                "run_codewebway" => {}
                "update_codewebway" => {}
                "stop_codewebway" => {
                    eprintln!("  Fleet: stop received but no terminal running — reporting stopped");
                    report_terminal_stopped_if_idle(channel.as_ref(), &creds, &cmd).await;
                    continue;
                }
                "decommission_client" => {
                    eprintln!("  Fleet: decommission requested while idle.");
                    decommission_self_and_exit(channel.as_ref(), &creds, &cmd).await;
                }
                other => {
                    eprintln!("  Fleet: realtime channel unknown command type: {other}");
                    continue;
                }
            }
            match handle_realtime_command(
                &cfg,
                &mut creds,
                &mut state,
                &mut channel,
                &mut pending_update_report,
                &mut recent_commands,
                cmd,
                poll_interval,
            )
            .await
            {
                Ok(()) => {}
                Err(err) => eprintln!("  Fleet: realtime command handling failed: {err}"),
            }
            continue;
        }

        let connected_fallback_check_due = channel.is_some();
        let skip = if connected_fallback_check_due {
            true
        } else {
            !state.should_write(
                &state.status.clone(),
                state.active_url.as_deref(),
                state.runtime_instance_id.as_deref(),
            )
        };
        let hb = match send_heartbeat(
            &creds,
            &state.status,
            state.active_url.as_deref(),
            state.runtime_instance_id.as_deref(),
            skip,
        )
        .await
        {
            Ok(h) => {
                flush_pending_update_report(&creds, &mut pending_update_report).await;
                if connected_fallback_check_due {
                    next_connected_fallback_check =
                        next_connected_fallback_check_at(connected_idle_fallback_check_interval);
                } else if !skip {
                    state.last_d1_write = std::time::Instant::now();
                }
                if !connected_fallback_check_due {
                    try_send_channel_snapshot(&mut channel, &state, true);
                }
                if !connected_fallback_check_due && state.status != "running" {
                    match rotate_machine_token(&mut creds).await {
                        Ok(true) => {
                            eprintln!("  Fleet: rotated machine token during idle window.");
                            next_idle_token_rotation = next_machine_token_rotation_at(&creds);
                        }
                        Ok(false) => {
                            next_idle_token_rotation = if should_rotate_machine_token(&creds) {
                                retry_machine_token_rotation_at()
                            } else {
                                next_machine_token_rotation_at(&creds)
                            };
                        }
                        Err(e) => {
                            eprintln!("  Fleet: token rotation skipped: {e}");
                            next_idle_token_rotation = retry_machine_token_rotation_at();
                        }
                    }
                }
                h
            }
            Err(e) => {
                if is_unauthorized(&e) {
                    cleanup_local_fleet_state_and_exit("device deregistered (401)");
                }
                if connected_fallback_check_due {
                    eprintln!("  Fleet: connected fallback check failed: {e}");
                    next_connected_fallback_check = next_connected_fallback_check_at(poll_interval);
                } else {
                    eprintln!("  Fleet: heartbeat error (will retry): {e}");
                    tokio::time::sleep(poll_interval).await;
                }
                continue;
            }
        };

        if !hb.has_command {
            if channel.is_none() {
                tokio::time::sleep(poll_interval).await;
            }
            continue;
        }
        let cmd = match hb.command {
            Some(c) => c,
            None => {
                if channel.is_none() {
                    tokio::time::sleep(poll_interval).await;
                }
                continue;
            }
        };

        if recent_commands.record_or_is_duplicate(&cmd) {
            eprintln!(
                "  Fleet: duplicate fallback command ignored: {} {}",
                cmd.kind,
                cmd.execution_id.as_deref().unwrap_or("no-exec-id")
            );
            if channel.is_none() {
                tokio::time::sleep(poll_interval).await;
            }
            continue;
        }

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
                let runtime_instance_id = if exec_id.is_empty() {
                    rand::thread_rng()
                        .sample_iter(&Alphanumeric)
                        .take(16)
                        .map(char::from)
                        .collect::<String>()
                } else {
                    exec_id.clone()
                };
                fleet_cfg.password = Some(session_token);
                fleet_cfg.sso_shared_secret = Some(sha256_hex(&creds.machine_token));
                fleet_cfg.runtime_instance_id = Some(runtime_instance_id.clone());
                if let Some(ref pin) = creds.pin {
                    fleet_cfg.pin = Some(pin.clone());
                }
                fleet_cfg.dashboard_auth_machine_token = Some(creds.machine_token.clone());
                if let Some(api_base) = payload_str(&cmd.payload, "fleet_api_base") {
                    fleet_cfg.dashboard_auth_api_base = Some(api_base.to_string());
                }

                // Apply per-trigger config from command payload
                if let Some(cwd) = payload_str(&cmd.payload, "cwd") {
                    fleet_cfg.cwd = Some(cwd.to_string());
                }
                if let Some(terminal_only) = payload_bool(&cmd.payload, "terminal_only") {
                    fleet_cfg.terminal_only = terminal_only;
                }
                if let Some(shell) = payload_str(&cmd.payload, "shell") {
                    fleet_cfg.shell = Some(shell.to_string());
                }
                if let Some(scrollback) =
                    payload_u64_in_range(&cmd.payload, "scrollback", 16_384, 2_097_152)
                {
                    fleet_cfg.scrollback = scrollback as usize;
                }
                if let Some(max_connections) =
                    payload_u64_in_range(&cmd.payload, "max_connections", 1, 32)
                {
                    fleet_cfg.max_connections = max_connections as usize;
                }
                if let Some(temp_link) = payload_bool(&cmd.payload, "temp_link") {
                    fleet_cfg.temp_link = temp_link;
                }
                if let Some(ttl) =
                    payload_u64_in_range(&cmd.payload, "temp_link_ttl_minutes", 1, 120)
                {
                    if matches!(ttl, 5 | 15 | 60) {
                        fleet_cfg.temp_link_ttl_minutes = ttl;
                    }
                }
                if let Some(scope) = payload_str(&cmd.payload, "temp_link_scope") {
                    if scope == "read-only" || scope == "interactive" {
                        fleet_cfg.temp_link_scope = scope;
                    }
                }
                if let Some(max_uses) =
                    payload_u64_in_range(&cmd.payload, "temp_link_max_uses", 1, 100)
                {
                    fleet_cfg.temp_link_max_uses = max_uses as u32;
                }

                match crate::start_server(fleet_cfg).await {
                    Err(e) => {
                        eprintln!("  Fleet: failed to start server: {e}");
                        if !exec_id.is_empty() {
                            let _ = report_result_via_channel_or_http(
                                channel.as_ref(),
                                &creds,
                                &exec_id,
                                &e.to_string(),
                                false,
                            )
                            .await;
                        }
                    }
                    Ok(handle) => {
                        state.status = "running".to_string();
                        state.active_url = handle.current_zrok_url();
                        state.runtime_instance_id = Some(runtime_instance_id.clone());
                        state.last_d1_write =
                            std::time::Instant::now() - std::time::Duration::from_secs(400);
                        try_send_channel_snapshot(&mut channel, &state, false);

                        let mut runtime = RunningRuntime {
                            execution_id: exec_id,
                            access_token: handle.token.clone(),
                            runtime_instance_id,
                            zrok_url_state: handle.zrok_url_state.clone(),
                            ready_reported: false,
                        };
                        sync_runtime_ready(&creds, &mut state, &mut runtime, channel.as_ref())
                            .await;

                        let exit_action = wait_for_stop(
                            &creds,
                            &mut state,
                            &mut runtime,
                            &mut channel,
                            &mut recent_commands,
                            handle.shutdown_tx,
                            handle.server_done,
                            poll_interval,
                        )
                        .await;

                        state.status = "idle".to_string();
                        state.active_url = None;
                        state.runtime_instance_id = None;
                        try_send_channel_snapshot(&mut channel, &state, false);
                        write_status_now(&creds, &mut state, "after terminal stop").await;
                        if let RuntimeExitAction::ApplyClientUpdate(plan) = exit_action {
                            if let Err(err) = apply_client_update_plan(&plan).await {
                                report_client_update_failure(
                                    channel.as_ref(),
                                    &creds,
                                    &plan.execution_id,
                                    &err,
                                )
                                .await;
                                eprintln!(
                                    "  Fleet: client update failed after runtime stop: {err}"
                                );
                            }
                        }
                    }
                }
            }
            "stop_codewebway" => {
                eprintln!("  Fleet: stop received but no terminal running — reporting stopped");
                report_terminal_stopped_if_idle(channel.as_ref(), &creds, &cmd).await;
            }
            "decommission_client" => {
                eprintln!("  Fleet: decommission requested while idle.");
                decommission_self_and_exit(channel.as_ref(), &creds, &cmd).await;
            }
            "update_codewebway" => {
                if let Err(err) = perform_client_update(channel.as_ref(), &creds, &cmd).await {
                    eprintln!("  Fleet: client update failed: {err}");
                }
            }
            other => eprintln!("  Fleet: unknown command type: {other}"),
        }

        if channel.is_none() {
            tokio::time::sleep(poll_interval).await;
        }
    }
}

enum RuntimeExitAction {
    None,
    ApplyClientUpdate(ClientUpdatePlan),
}

#[allow(clippy::too_many_arguments)]
async fn wait_for_stop(
    creds: &FleetCredentials,
    state: &mut DaemonState,
    runtime: &mut RunningRuntime,
    channel: &mut Option<MachineChannelClient>,
    recent_commands: &mut RecentCommandTracker,
    shutdown_tx: tokio::sync::mpsc::UnboundedSender<()>,
    server_done: tokio::sync::oneshot::Receiver<()>,
    interval: std::time::Duration,
) -> RuntimeExitAction {
    tokio::pin!(server_done);
    let mut sync_tick =
        tokio::time::interval(std::time::Duration::from_secs(RUNTIME_SYNC_INTERVAL_SECS));
    sync_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let channel_retry_interval = std::time::Duration::from_secs(CHANNEL_RECONNECT_INTERVAL_SECS);
    let mut next_channel_retry = std::time::Instant::now();
    let mut next_heartbeat_at = tokio::time::Instant::now();

    loop {
        if maybe_connect_realtime_channel(
            creds,
            state,
            channel,
            &mut next_channel_retry,
            channel_retry_interval,
        )
        .await
        {
            try_send_channel_snapshot(channel, state, true);
        }

        if let Some(channel_client) = channel.as_mut() {
            tokio::select! {
                done = &mut server_done => {
                    if done.is_err() {
                        eprintln!("  Fleet: server stop signal dropped unexpectedly.");
                    }
                    report_runtime_start_failed_if_needed(
                        Some(channel_client),
                        creds,
                        runtime,
                        "Terminal stopped before public URL was ready",
                    )
                    .await;
                    return RuntimeExitAction::None;
                }
                maybe_cmd = channel_client.recv_command() => {
                    match maybe_cmd {
                        Some(cmd) if cmd.kind == "stop_codewebway" || cmd.kind == "decommission_client" || cmd.kind == "update_codewebway" => {
                            let duplicate = recent_commands.record_or_is_duplicate(&cmd);
                            acknowledge_realtime_command(Some(channel_client), &cmd, duplicate);
                            if duplicate {
                                continue;
                            }
                            if cmd.kind == "decommission_client" {
                                eprintln!("  Fleet: decommission requested during runtime.");
                                decommission_self_and_exit(Some(channel_client), creds, &cmd).await;
                            }
                            let update_plan = if cmd.kind == "update_codewebway" {
                                match resolve_client_update_plan(Some(channel_client), creds, &cmd).await {
                                    Ok(Some(plan)) => Some(plan),
                                    Ok(None) => None,
                                    Err(err) => {
                                        report_client_update_failure(
                                            Some(channel_client),
                                            creds,
                                            cmd.execution_id.as_deref().unwrap_or_default(),
                                            &err,
                                        )
                                        .await;
                                        eprintln!("  Fleet: client update preparation failed: {err}");
                                        continue;
                                    }
                                }
                            } else {
                                None
                            };
                            if cmd.kind == "update_codewebway" && update_plan.is_none() {
                                continue;
                            }
                            let exec_id = cmd.execution_id.unwrap_or_default();
                            let _ = shutdown_tx.send(());
                            report_runtime_start_failed_if_needed(
                                Some(channel_client),
                                creds,
                                runtime,
                                "Terminal stopped before public URL was ready",
                            )
                            .await;
                            if cmd.kind == "stop_codewebway" && !exec_id.is_empty() {
                                let _ = report_result_via_channel_or_http(
                                    Some(channel_client),
                                    creds,
                                    &exec_id,
                                    "stopped",
                                    true,
                                )
                                .await;
                            }
                            if let Some(plan) = update_plan {
                                return RuntimeExitAction::ApplyClientUpdate(plan);
                            }
                            return RuntimeExitAction::None;
                        }
                        Some(cmd) => {
                            let duplicate = recent_commands.record_or_is_duplicate(&cmd);
                            acknowledge_realtime_command(Some(channel_client), &cmd, duplicate);
                            if duplicate {
                                continue;
                            }
                        }
                        None => {
                            eprintln!("  Fleet: realtime channel disconnected during runtime.");
                            *channel = None;
                            next_channel_retry = std::time::Instant::now() + channel_retry_interval;
                            next_heartbeat_at = tokio::time::Instant::now();
                        }
                    }
                }
                _ = sync_tick.tick() => {
                    sync_runtime_ready(creds, state, runtime, Some(channel_client)).await;
                }
            }
        } else {
            let heartbeat_sleep = tokio::time::sleep_until(next_heartbeat_at);
            tokio::pin!(heartbeat_sleep);
            tokio::select! {
                done = &mut server_done => {
                    if done.is_err() {
                        eprintln!("  Fleet: server stop signal dropped unexpectedly.");
                    }
                    report_runtime_start_failed_if_needed(
                        channel.as_ref(),
                        creds,
                        runtime,
                        "Terminal stopped before public URL was ready",
                    )
                    .await;
                    return RuntimeExitAction::None;
                }
                _ = sync_tick.tick() => {
                    sync_runtime_ready(creds, state, runtime, channel.as_ref()).await;
                }
                _ = &mut heartbeat_sleep => {
                    let skip = !state.should_write(
                        &state.status,
                        state.active_url.as_deref(),
                        state.runtime_instance_id.as_deref(),
                    );
                    match send_heartbeat(
                        creds,
                        &state.status,
                        state.active_url.as_deref(),
                        state.runtime_instance_id.as_deref(),
                        skip,
                    ).await {
                        Ok(hb) => {
                            if !skip {
                                state.last_d1_write = std::time::Instant::now();
                            }
                            if let Some(cmd) = hb.command {
                                if recent_commands.record_or_is_duplicate(&cmd) {
                                    next_heartbeat_at = tokio::time::Instant::now() + interval;
                                    continue;
                                }
                                if cmd.kind == "decommission_client" {
                                    eprintln!("  Fleet: decommission requested during runtime.");
                                    decommission_self_and_exit(channel.as_ref(), creds, &cmd).await;
                                }
                                let update_plan = if cmd.kind == "update_codewebway" {
                                    match resolve_client_update_plan(channel.as_ref(), creds, &cmd).await {
                                        Ok(Some(plan)) => Some(plan),
                                        Ok(None) => None,
                                        Err(err) => {
                                            report_client_update_failure(
                                                channel.as_ref(),
                                                creds,
                                                cmd.execution_id.as_deref().unwrap_or_default(),
                                                &err,
                                            )
                                            .await;
                                            eprintln!("  Fleet: client update preparation failed: {err}");
                                            next_heartbeat_at = tokio::time::Instant::now() + interval;
                                            continue;
                                        }
                                    }
                                } else {
                                    None
                                };
                                if cmd.kind == "update_codewebway" && update_plan.is_none() {
                                    next_heartbeat_at = tokio::time::Instant::now() + interval;
                                    continue;
                                }
                                if cmd.kind == "stop_codewebway" {
                                    let exec_id = cmd.execution_id.unwrap_or_default();
                                    let _ = shutdown_tx.send(());
                                    report_runtime_start_failed_if_needed(
                                        channel.as_ref(),
                                        creds,
                                        runtime,
                                        "Terminal stopped before public URL was ready",
                                    )
                                    .await;
                                    if cmd.kind == "stop_codewebway" && !exec_id.is_empty() {
                                        let _ = report_result_via_channel_or_http(
                                            channel.as_ref(),
                                            creds,
                                            &exec_id,
                                            "stopped",
                                            true,
                                        )
                                        .await;
                                    }
                                    return RuntimeExitAction::None;
                                }
                                if let Some(plan) = update_plan {
                                    let _ = shutdown_tx.send(());
                                    report_runtime_start_failed_if_needed(
                                        channel.as_ref(),
                                        creds,
                                        runtime,
                                        "Terminal stopped before public URL was ready",
                                    )
                                    .await;
                                    return RuntimeExitAction::ApplyClientUpdate(plan);
                                }
                            }
                        }
                        Err(e) => {
                            if is_unauthorized(&e) {
                                cleanup_local_fleet_state_and_exit("device deregistered (401)");
                            }
                            eprintln!("  Fleet: heartbeat error during run: {e}");
                        }
                    }
                    next_heartbeat_at = tokio::time::Instant::now() + interval;
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_realtime_command(
    cfg: &crate::config::Config,
    creds: &mut FleetCredentials,
    state: &mut DaemonState,
    channel: &mut Option<MachineChannelClient>,
    _pending_update_report: &mut Option<PendingUpdateReport>,
    recent_commands: &mut RecentCommandTracker,
    cmd: PendingCommand,
    poll_interval: std::time::Duration,
) -> Result<()> {
    match cmd.kind.as_str() {
        "run_codewebway" => {
            let exec_id = cmd.execution_id.clone().unwrap_or_default();

            let mut fleet_cfg = cfg.clone();
            let session_token: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(24)
                .map(char::from)
                .collect();
            let runtime_instance_id = if exec_id.is_empty() {
                rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(16)
                    .map(char::from)
                    .collect::<String>()
            } else {
                exec_id.clone()
            };
            fleet_cfg.password = Some(session_token);
            fleet_cfg.sso_shared_secret = Some(sha256_hex(&creds.machine_token));
            fleet_cfg.runtime_instance_id = Some(runtime_instance_id.clone());
            if let Some(ref pin) = creds.pin {
                fleet_cfg.pin = Some(pin.clone());
            }
            fleet_cfg.dashboard_auth_machine_token = Some(creds.machine_token.clone());
            if let Some(api_base) = payload_str(&cmd.payload, "fleet_api_base") {
                fleet_cfg.dashboard_auth_api_base = Some(api_base.to_string());
            }
            if let Some(cwd) = payload_str(&cmd.payload, "cwd") {
                fleet_cfg.cwd = Some(cwd.to_string());
            }
            if let Some(terminal_only) = payload_bool(&cmd.payload, "terminal_only") {
                fleet_cfg.terminal_only = terminal_only;
            }
            if let Some(shell) = payload_str(&cmd.payload, "shell") {
                fleet_cfg.shell = Some(shell.to_string());
            }
            if let Some(scrollback) =
                payload_u64_in_range(&cmd.payload, "scrollback", 16_384, 2_097_152)
            {
                fleet_cfg.scrollback = scrollback as usize;
            }
            if let Some(max_connections) =
                payload_u64_in_range(&cmd.payload, "max_connections", 1, 32)
            {
                fleet_cfg.max_connections = max_connections as usize;
            }
            if let Some(temp_link) = payload_bool(&cmd.payload, "temp_link") {
                fleet_cfg.temp_link = temp_link;
            }
            if let Some(ttl) = payload_u64_in_range(&cmd.payload, "temp_link_ttl_minutes", 1, 120) {
                if matches!(ttl, 5 | 15 | 60) {
                    fleet_cfg.temp_link_ttl_minutes = ttl;
                }
            }
            if let Some(scope) = payload_str(&cmd.payload, "temp_link_scope") {
                if scope == "read-only" || scope == "interactive" {
                    fleet_cfg.temp_link_scope = scope;
                }
            }
            if let Some(max_uses) = payload_u64_in_range(&cmd.payload, "temp_link_max_uses", 1, 100)
            {
                fleet_cfg.temp_link_max_uses = max_uses as u32;
            }

            match crate::start_server(fleet_cfg).await {
                Err(e) => {
                    eprintln!("  Fleet: failed to start server: {e}");
                    if !exec_id.is_empty() {
                        let _ = report_result_via_channel_or_http(
                            channel.as_ref(),
                            creds,
                            &exec_id,
                            &e.to_string(),
                            false,
                        )
                        .await;
                    }
                }
                Ok(handle) => {
                    state.status = "running".to_string();
                    state.active_url = handle.current_zrok_url();
                    state.runtime_instance_id = Some(runtime_instance_id.clone());
                    state.last_d1_write =
                        std::time::Instant::now() - std::time::Duration::from_secs(400);
                    try_send_channel_snapshot(channel, state, false);

                    let mut runtime = RunningRuntime {
                        execution_id: exec_id,
                        access_token: handle.token.clone(),
                        runtime_instance_id,
                        zrok_url_state: handle.zrok_url_state.clone(),
                        ready_reported: false,
                    };
                    sync_runtime_ready(creds, state, &mut runtime, channel.as_ref()).await;

                    let exit_action = wait_for_stop(
                        creds,
                        state,
                        &mut runtime,
                        channel,
                        recent_commands,
                        handle.shutdown_tx,
                        handle.server_done,
                        poll_interval,
                    )
                    .await;

                    state.status = "idle".to_string();
                    state.active_url = None;
                    state.runtime_instance_id = None;
                    try_send_channel_snapshot(channel, state, false);
                    write_status_now(creds, state, "after terminal stop").await;
                    if let RuntimeExitAction::ApplyClientUpdate(plan) = exit_action {
                        if let Err(err) = apply_client_update_plan(&plan).await {
                            report_client_update_failure(
                                channel.as_ref(),
                                creds,
                                &plan.execution_id,
                                &err,
                            )
                            .await;
                            eprintln!("  Fleet: client update failed after runtime stop: {err}");
                        }
                    }
                }
            }
        }
        "update_codewebway" => {
            perform_client_update(channel.as_ref(), creds, &cmd).await?;
        }
        "decommission_client" => {
            eprintln!("  Fleet: decommission requested.");
            decommission_self_and_exit(channel.as_ref(), creds, &cmd).await;
        }
        other => {
            eprintln!("  Fleet: realtime channel unknown command type: {other}");
        }
    }
    Ok(())
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
    let bin = std::env::current_exe().context("Cannot determine current executable path")?;
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
        if uninstall_launchagent_at(&plist_path)? {
            println!("  ✓ Auto-start service removed.");
        } else {
            println!("  Auto-start service not installed.");
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        let svc_path = systemd_service_path();
        if uninstall_systemd_service_at(&svc_path)? {
            println!("  ✓ Auto-start service removed.");
        } else {
            println!("  Auto-start service not installed.");
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    anyhow::bail!("Auto-start service is not supported on this platform.")
}

// ─── Utility ───────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn uninstall_launchagent_at(plist_path: &Path) -> Result<bool> {
    if !plist_path.exists() {
        return Ok(false);
    }
    let _ = std::process::Command::new("launchctl")
        .args(["unload", "-w", &plist_path.to_string_lossy()])
        .status();
    remove_file_if_exists(plist_path)
}

#[cfg(target_os = "linux")]
fn uninstall_systemd_service_at(svc_path: &Path) -> Result<bool> {
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "--now", "codewebway-fleet"])
        .status();
    let removed = remove_file_if_exists(svc_path)?;
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    Ok(removed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocalFleetCleanupOutcome {
    service_removed: bool,
    credentials_removed: bool,
}

#[cfg(target_os = "macos")]
fn cleanup_local_fleet_state() -> Result<LocalFleetCleanupOutcome> {
    cleanup_local_fleet_state_at(&credentials_path(), &launchagent_plist_path())
}

#[cfg(target_os = "linux")]
fn cleanup_local_fleet_state() -> Result<LocalFleetCleanupOutcome> {
    cleanup_local_fleet_state_at(&credentials_path(), &systemd_service_path())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn cleanup_local_fleet_state() -> Result<LocalFleetCleanupOutcome> {
    Ok(LocalFleetCleanupOutcome {
        service_removed: false,
        credentials_removed: disable_at_path(&credentials_path())?,
    })
}

#[cfg(target_os = "macos")]
fn cleanup_local_fleet_state_at(
    credentials_path: &Path,
    service_path: &Path,
) -> Result<LocalFleetCleanupOutcome> {
    Ok(LocalFleetCleanupOutcome {
        service_removed: uninstall_launchagent_at(service_path)?,
        credentials_removed: disable_at_path(credentials_path)?,
    })
}

#[cfg(target_os = "linux")]
fn cleanup_local_fleet_state_at(
    credentials_path: &Path,
    service_path: &Path,
) -> Result<LocalFleetCleanupOutcome> {
    Ok(LocalFleetCleanupOutcome {
        service_removed: uninstall_systemd_service_at(service_path)?,
        credentials_removed: disable_at_path(credentials_path)?,
    })
}

fn cleanup_local_fleet_state_and_exit(reason: &str) -> ! {
    eprintln!("  Fleet: {reason} — cleaning up local fleet state.");
    match cleanup_local_fleet_state() {
        Ok(outcome) => {
            if outcome.service_removed {
                eprintln!("  Fleet: removed local auto-start service.");
            }
            if outcome.credentials_removed {
                eprintln!("  Fleet: removed local fleet credentials.");
            }
            if !outcome.service_removed && !outcome.credentials_removed {
                eprintln!("  Fleet: local fleet state was already absent.");
            }
            std::process::exit(0);
        }
        Err(err) => {
            eprintln!("  Fleet: failed to clean up local fleet state: {err}");
            std::process::exit(1);
        }
    }
}

fn is_unauthorized(e: &anyhow::Error) -> bool {
    e.downcast_ref::<reqwest::Error>()
        .and_then(|re| re.status())
        .map(|s| s == reqwest::StatusCode::UNAUTHORIZED)
        .unwrap_or(false)
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

// ─── QR / Device-code enable ───────────────────────────────────────────────────

#[derive(Deserialize)]
struct DeviceCodeResp {
    data: DeviceCodeData,
}
#[derive(Deserialize)]
struct DeviceCodeData {
    code: String,
    activate_url: String,
}

#[derive(Deserialize)]
struct DevicePollResp {
    data: DevicePollData,
}
#[derive(Deserialize)]
struct DevicePollData {
    status: String,
    enable_token: Option<String>,
}

/// Render a URL as a QR code using Unicode block characters.
pub fn render_qr(url: &str) {
    if let Ok(code) = QrCode::new(url) {
        // Use explicit ANSI background colors so QR remains scannable in both
        // light and dark terminal themes.
        let term = std::env::var("TERM").unwrap_or_default();
        let use_ansi = std::env::var_os("NO_COLOR").is_none() && term != "dumb";
        if use_ansi {
            let width = code.width();
            let colors = code.to_colors();
            let quiet = 2usize;
            for y in 0..(width + quiet * 2) {
                print!("  ");
                for x in 0..(width + quiet * 2) {
                    let module =
                        if x < quiet || y < quiet || x >= width + quiet || y >= width + quiet {
                            Color::Light
                        } else {
                            let idx = (y - quiet) * width + (x - quiet);
                            colors[idx]
                        };
                    match module {
                        Color::Dark => print!("\x1b[48;5;0m  \x1b[0m"),
                        Color::Light => print!("\x1b[48;5;15m  \x1b[0m"),
                    }
                }
                println!();
            }
        } else {
            let image = code
                .render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Dark)
                .light_color(unicode::Dense1x2::Light)
                .quiet_zone(true)
                .build();
            for line in image.lines() {
                println!("  {line}");
            }
        }
    }
}

/// Interactive QR-based enable: request a device code, show QR, poll for approval.
pub async fn enable_qr(fleet_endpoint: &str, pin: Option<String>) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    // 1. Request device code
    let resp = client
        .post(format!("{fleet_endpoint}/api/v1/device/request"))
        .json(&serde_json::json!({
            "machine_name": hostname(),
        }))
        .send()
        .await
        .context("Failed to reach fleet API")?
        .json::<DeviceCodeResp>()
        .await
        .context("Invalid response from fleet API")?;
    let code = resp.data.code;
    let activate_url = resp.data.activate_url;

    // 2. Show QR pointing to activate URL returned by API
    println!();
    render_qr(&activate_url);
    println!("  Or visit: {activate_url}");
    println!("  Code:     {code}");
    println!();
    println!("  Waiting for approval in the Dashboard… (Ctrl+C to cancel)");

    // 3. Poll until approved or expired (max 5 min)
    let poll_url = format!("{fleet_endpoint}/api/v1/device/poll?code={code}");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    let enable_token = loop {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        if std::time::Instant::now() > deadline {
            anyhow::bail!("Activation timed out. Please try again.");
        }
        let poll = match client.get(&poll_url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let data = match poll.json::<DevicePollResp>().await {
            Ok(d) => d.data,
            Err(_) => continue,
        };
        match data.status.as_str() {
            "approved" => {
                if let Some(token) = data.enable_token {
                    break token;
                }
            }
            "expired" => anyhow::bail!("Device code expired. Please try again."),
            _ => {
                eprint!(".");
            }
        }
    };
    eprintln!();
    eprintln!("  ✓ Approved!");

    // 4. Proceed with normal enable
    enable(fleet_endpoint, &enable_token, pin).await
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
            machine_id: Some("mid_test".to_string()),
            machine_token_issued_at: 1_700_000_000_000,
            pin: Some("123456".to_string()),
        }
    }

    fn tmp_path(dir: &TempDir) -> PathBuf {
        dir.path().join("fleet.toml")
    }

    fn tmp_service_path(dir: &TempDir) -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            dir.path().join("com.codewebway.fleet.plist")
        }

        #[cfg(target_os = "linux")]
        {
            dir.path().join("codewebway-fleet.service")
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            dir.path().join("service-placeholder")
        }
    }

    fn tmp_update_report_path(dir: &TempDir) -> PathBuf {
        dir.path().join("pending-update.json")
    }

    fn dummy_channel() -> MachineChannelClient {
        let (outbound_tx, _outbound_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let (_command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel::<PendingCommand>();
        MachineChannelClient {
            outbound_tx,
            command_rx,
        }
    }

    fn live_dummy_channel() -> (
        MachineChannelClient,
        tokio::sync::mpsc::UnboundedSender<PendingCommand>,
    ) {
        let (outbound_tx, _outbound_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let (command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel::<PendingCommand>();
        (
            MachineChannelClient {
                outbound_tx,
                command_rx,
            },
            command_tx,
        )
    }

    #[test]
    fn test_build_machine_channel_request_includes_websocket_headers_and_auth() {
        let creds = make_creds("https://webwayfleet.dev");
        let request = build_machine_channel_request(&creds).unwrap();

        assert_eq!(
            request.uri().to_string(),
            "wss://webwayfleet.dev/api/v1/agent/channel"
        );
        assert_eq!(
            request.headers().get("authorization").unwrap(),
            "Bearer mt_test"
        );
        assert_eq!(request.headers().get("upgrade").unwrap(), "websocket");
        assert_eq!(request.headers().get("connection").unwrap(), "Upgrade");
        assert_eq!(
            request.headers().get("sec-websocket-version").unwrap(),
            "13"
        );
        assert!(request.headers().get("sec-websocket-key").is_some());
    }

    #[test]
    fn test_build_channel_snapshot_message_omits_skip_status_write_by_default() {
        let payload: serde_json::Value = serde_json::from_str(&build_channel_snapshot_message(
            "snapshot", "idle", None, None, false,
        ))
        .unwrap();

        assert_eq!(
            payload.get("type").and_then(|v| v.as_str()),
            Some("snapshot")
        );
        assert_eq!(
            payload.get("agent_version").and_then(|v| v.as_str()),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert!(payload.get("skip_status_write").is_none());
    }

    #[test]
    fn test_build_channel_snapshot_message_includes_skip_status_write_when_requested() {
        let payload: serde_json::Value = serde_json::from_str(&build_channel_snapshot_message(
            "snapshot",
            "idle",
            Some("https://example.zrok.io"),
            Some("runtime-1"),
            true,
        ))
        .unwrap();

        assert_eq!(
            payload.get("skip_status_write").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            payload.get("agent_version").and_then(|v| v.as_str()),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(
            payload.get("active_url").and_then(|v| v.as_str()),
            Some("https://example.zrok.io")
        );
        assert_eq!(
            payload.get("runtime_instance_id").and_then(|v| v.as_str()),
            Some("runtime-1")
        );
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
        assert_eq!(loaded.machine_id.as_deref(), Some("mid_test"));
        assert_eq!(loaded.machine_token_issued_at, 1_700_000_000_000);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "fleet.toml must be owner-only (0o600)");
        }
    }

    #[test]
    fn test_load_missing_returns_error() {
        let dir = TempDir::new().unwrap();
        let path = tmp_path(&dir);
        let result = load_credentials_from(&path);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("codewebway enable"));
    }

    #[test]
    fn test_disable_removes_file() {
        let dir = TempDir::new().unwrap();
        let path = tmp_path(&dir);
        save_credentials_to(&make_creds("https://x"), &path).unwrap();
        assert!(path.exists());
        assert!(disable_at_path(&path).unwrap());
        assert!(!path.exists());
    }

    #[test]
    fn test_normalize_release_version_strips_v_prefix() {
        assert_eq!(normalize_release_version("v1.2.3"), "1.2.3");
        assert_eq!(normalize_release_version("1.2.3"), "1.2.3");
    }

    #[test]
    fn test_pending_update_report_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = tmp_update_report_path(&dir);
        let report = PendingUpdateReport {
            execution_id: "ex-update".to_string(),
            target_version: "1.2.3".to_string(),
        };

        save_pending_update_report_to(&report, &path).unwrap();
        let loaded = load_pending_update_report_from(&path).unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.execution_id, "ex-update");
        assert_eq!(loaded.target_version, "1.2.3");

        assert!(clear_pending_update_report_at(&path).unwrap());
        assert!(load_pending_update_report_from(&path).unwrap().is_none());
    }

    #[tokio::test]
    async fn test_fetch_latest_release_plan_from_selects_matching_asset() {
        let mut server = mockito::Server::new_async().await;
        let target = current_release_target().unwrap();
        let asset_url = format!("{}/download/{}", server.url(), target);
        let body = serde_json::json!({
            "tag_name": "v9.9.9",
            "assets": [
                {
                    "name": format!("codewebway-{}", target),
                    "browser_download_url": asset_url.clone(),
                },
                {
                    "name": "codewebway-unused",
                    "browser_download_url": format!("{}/download/unused", server.url()),
                }
            ]
        });
        let release = server
            .mock("GET", "/releases/latest")
            .match_header(
                "user-agent",
                mockito::Matcher::Regex("^codewebway/".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body.to_string())
            .create_async()
            .await;

        let plan = fetch_latest_release_plan_from(&server.url(), "ex-update")
            .await
            .unwrap();
        assert_eq!(plan.execution_id, "ex-update");
        assert_eq!(plan.target_version, "9.9.9");
        assert_eq!(plan.download_url, asset_url);
        release.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_release_plan_by_tag_from_selects_matching_asset() {
        let mut server = mockito::Server::new_async().await;
        let target = current_release_target().unwrap();
        let asset_url = format!("{}/download/tagged/{}", server.url(), target);
        let body = serde_json::json!({
            "tag_name": "v9.9.10-mock.1",
            "assets": [
                {
                    "name": format!("codewebway-{}", target),
                    "browser_download_url": asset_url.clone(),
                }
            ]
        });
        let release = server
            .mock("GET", "/releases/tags/v9.9.10-mock.1")
            .match_header(
                "user-agent",
                mockito::Matcher::Regex("^codewebway/".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body.to_string())
            .create_async()
            .await;

        let plan = fetch_release_plan_by_tag_from(&server.url(), "ex-update", "v9.9.10-mock.1")
            .await
            .unwrap();
        assert_eq!(plan.execution_id, "ex-update");
        assert_eq!(plan.target_version, "9.9.10-mock.1");
        assert_eq!(plan.download_url, asset_url);
        release.assert_async().await;
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_cleanup_local_fleet_state_at_removes_launchagent_and_credentials() {
        let dir = TempDir::new().unwrap();
        let credentials_path = tmp_path(&dir);
        let service_path = tmp_service_path(&dir);

        save_credentials_to(&make_creds("https://x"), &credentials_path).unwrap();
        std::fs::write(&service_path, "<plist />").unwrap();

        let outcome = cleanup_local_fleet_state_at(&credentials_path, &service_path).unwrap();

        assert_eq!(
            outcome,
            LocalFleetCleanupOutcome {
                service_removed: true,
                credentials_removed: true,
            }
        );
        assert!(!credentials_path.exists());
        assert!(!service_path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_cleanup_local_fleet_state_at_removes_systemd_unit_and_credentials() {
        let dir = TempDir::new().unwrap();
        let credentials_path = tmp_path(&dir);
        let service_path = tmp_service_path(&dir);

        save_credentials_to(&make_creds("https://x"), &credentials_path).unwrap();
        std::fs::write(&service_path, "[Unit]\nDescription=Test\n").unwrap();

        let outcome = cleanup_local_fleet_state_at(&credentials_path, &service_path).unwrap();

        assert_eq!(
            outcome,
            LocalFleetCleanupOutcome {
                service_removed: true,
                credentials_removed: true,
            }
        );
        assert!(!credentials_path.exists());
        assert!(!service_path.exists());
    }

    #[test]
    fn test_daemon_state_should_write_on_status_change() {
        let mut state = DaemonState::new();
        state.last_d1_write = std::time::Instant::now(); // reset to recent

        // same status — should NOT write
        assert!(!state.should_write("idle", None, None));
        // status changed — SHOULD write
        assert!(state.should_write("running", None, None));
    }

    #[test]
    fn test_daemon_state_should_write_on_url_change() {
        let mut state = DaemonState::new();
        state.last_d1_write = std::time::Instant::now();
        state.status = "running".to_string();
        state.active_url = Some("https://old.zrok.io".to_string());

        assert!(!state.should_write("running", Some("https://old.zrok.io"), None));
        assert!(state.should_write("running", Some("https://new.zrok.io"), None));
    }

    #[test]
    fn test_daemon_state_should_write_on_runtime_instance_change() {
        let mut state = DaemonState::new();
        state.last_d1_write = std::time::Instant::now();
        state.status = "running".to_string();
        state.active_url = Some("https://old.zrok.io".to_string());
        state.runtime_instance_id = Some("instance-old".to_string());

        assert!(!state.should_write("running", Some("https://old.zrok.io"), Some("instance-old")));
        assert!(state.should_write("running", Some("https://old.zrok.io"), Some("instance-new")));
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
        assert_eq!(creds.machine_id.as_deref(), Some("mid1"));
        // PIN should be auto-generated (6 digits)
        let pin = creds.pin.unwrap();
        assert_eq!(pin.len(), 6);
        assert!(pin.chars().all(|c| c.is_ascii_digit()));
        m.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_remote_status_returns_metadata() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("GET", "/api/v1/agent/status")
            .match_header("authorization", "Bearer mt_test")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"data":{"machine_id":"mid1","user_id":"user_123","project_id":"proj_123","project_name":"My Project","status":"running","transport_mode":"realtime","transport_connected":1,"last_seen":1700000000000,"last_channel_event_at":1700000001000,"agent_version":"1.1.0-beta.45","hostname":"pi-test"}}"#
            )
            .create_async()
            .await;

        let remote = fetch_remote_status(&make_creds(&server.url()))
            .await
            .unwrap();
        assert_eq!(remote.machine_id, "mid1");
        assert_eq!(remote.user_id, "user_123");
        assert_eq!(remote.project_name.as_deref(), Some("My Project"));
        assert_eq!(remote.transport_mode.as_deref(), Some("realtime"));
        assert_eq!(remote.transport_connected, Some(1));
        assert_eq!(remote.agent_version.as_deref(), Some("1.1.0-beta.45"));
        m.assert_async().await;
    }

    #[test]
    fn test_format_transport_status_prefers_realtime_connected_label() {
        assert_eq!(
            format_transport_status(Some("realtime"), Some(1), Some(current_epoch_millis())),
            "realtime connected"
        );
    }

    #[tokio::test]
    async fn test_heartbeat_no_command() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/api/v1/agent/heartbeat")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "status": "idle",
                "agent_version": env!("CARGO_PKG_VERSION"),
                "skip_status_write": false,
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"has_command":false}}"#)
            .create_async()
            .await;

        let creds = make_creds(&server.url());
        let hb = send_heartbeat(&creds, "idle", None, None, false)
            .await
            .unwrap();
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
        let hb = send_heartbeat(&creds, "idle", None, None, false)
            .await
            .unwrap();
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
        let result = send_heartbeat(&creds, "idle", None, None, false).await;
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

    #[tokio::test]
    async fn test_report_result_via_channel_uses_realtime_when_available() {
        let creds = make_creds("https://unused.example");
        let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let (_command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel::<PendingCommand>();
        let channel = MachineChannelClient {
            outbound_tx,
            command_rx,
        };

        report_result_via_channel_or_http(Some(&channel), &creds, "ex-report-1", "ready", true)
            .await
            .unwrap();

        let payload = outbound_rx.recv().await.expect("expected realtime report");
        let json: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(json.get("type").and_then(|v| v.as_str()), Some("report"));
        assert_eq!(
            json.get("execution_id").and_then(|v| v.as_str()),
            Some("ex-report-1")
        );
        assert_eq!(json.get("status").and_then(|v| v.as_str()), Some("success"));
        assert_eq!(json.get("output").and_then(|v| v.as_str()), Some("ready"));
    }

    #[test]
    fn test_parse_channel_command_message_reads_command_key() {
        let payload = r#"{"type":"command","command_key":"execution:ex-123","command":{"type":"run_codewebway","payload":{"execution_id":"ex-123","output_type":"codewebway_url"}}}"#;
        let command = parse_channel_command_message(payload).expect("expected realtime command");
        assert_eq!(command.command_key.as_deref(), Some("execution:ex-123"));
        assert_eq!(command.execution_id.as_deref(), Some("ex-123"));
        assert_eq!(command.kind, "run_codewebway");
    }

    #[test]
    fn test_recent_command_tracker_dedupes_by_command_key() {
        let mut tracker = RecentCommandTracker::new();
        let command = PendingCommand {
            execution_id: Some("ex-dup-1".to_string()),
            command_key: Some("execution:ex-dup-1".to_string()),
            kind: "run_codewebway".to_string(),
            payload: serde_json::json!({
                "execution_id": "ex-dup-1",
            }),
        };

        assert!(!tracker.record_or_is_duplicate(&command));
        assert!(tracker.record_or_is_duplicate(&command));
    }

    #[tokio::test]
    async fn test_report_result_via_channel_falls_back_to_http_when_closed() {
        let mut server = mockito::Server::new_async().await;
        let report = server
            .mock("POST", "/api/v1/agent/report")
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"ok":true}}"#)
            .create_async()
            .await;

        let creds = make_creds(&server.url());
        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        drop(outbound_rx);
        let (_command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel::<PendingCommand>();
        let channel = MachineChannelClient {
            outbound_tx,
            command_rx,
        };

        report_result_via_channel_or_http(Some(&channel), &creds, "ex-report-2", "fallback", false)
            .await
            .unwrap();

        report.assert_async().await;
    }

    #[tokio::test]
    async fn test_sync_runtime_ready_reports_late_zrok_url() {
        let mut server = mockito::Server::new_async().await;
        let report = server
            .mock("POST", "/api/v1/agent/report")
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"ok":true}}"#)
            .create_async()
            .await;

        let creds = make_creds(&server.url());
        let mut state = DaemonState::new();
        state.status = "running".to_string();
        state.runtime_instance_id = Some("runtime-1".to_string());
        let shared_url = std::sync::Arc::new(std::sync::Mutex::new(None));
        let mut runtime = RunningRuntime {
            execution_id: "ex-late".to_string(),
            access_token: "token-123".to_string(),
            runtime_instance_id: "runtime-1".to_string(),
            zrok_url_state: shared_url.clone(),
            ready_reported: false,
        };

        sync_runtime_ready(&creds, &mut state, &mut runtime, None).await;
        assert!(state.active_url.is_none());
        assert!(!runtime.ready_reported);

        *shared_url.lock().unwrap() = Some("https://late.share.zrok.io".to_string());
        sync_runtime_ready(&creds, &mut state, &mut runtime, None).await;

        assert_eq!(
            state.active_url.as_deref(),
            Some("https://late.share.zrok.io")
        );
        assert!(runtime.ready_reported);
        report.assert_async().await;
    }

    #[test]
    fn test_should_attempt_realtime_channel_connect_only_when_due() {
        let mut channel = None;
        let mut due_now = std::time::Instant::now();
        let mut future_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);

        assert!(should_attempt_realtime_channel_connect(
            &mut channel,
            &mut due_now
        ));
        assert!(!should_attempt_realtime_channel_connect(
            &mut channel,
            &mut future_deadline
        ));
    }

    #[test]
    fn test_apply_realtime_channel_connect_result_connects_when_successful() {
        let mut channel = None;
        let mut next_retry_at = std::time::Instant::now();

        let connected = apply_realtime_channel_connect_result(
            &mut channel,
            &mut next_retry_at,
            std::time::Duration::from_secs(10),
            Ok(dummy_channel()),
        );

        assert!(connected);
        assert!(channel.is_some());
    }

    #[test]
    fn test_apply_realtime_channel_connect_result_delays_retry_after_failure() {
        let mut channel = None;
        let mut next_retry_at = std::time::Instant::now();

        let connected = apply_realtime_channel_connect_result(
            &mut channel,
            &mut next_retry_at,
            std::time::Duration::from_secs(10),
            Err(anyhow::anyhow!("connect failed")),
        );

        assert!(!connected);
        assert!(channel.is_none());
        assert!(next_retry_at > std::time::Instant::now());
    }

    #[tokio::test]
    async fn test_wait_for_stop_returns_when_server_stops_locally() {
        let mut server = mockito::Server::new_async().await;
        let heartbeat = server
            .mock("POST", "/api/v1/agent/heartbeat")
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"has_command":false}}"#)
            .create_async()
            .await;

        let creds = make_creds(&server.url());
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let (server_done_tx, server_done_rx) = tokio::sync::oneshot::channel::<()>();

        let wait = tokio::spawn(async move {
            let mut state = DaemonState::new();
            state.status = "running".to_string();
            state.active_url = Some("https://live.zrok.io".to_string());
            state.runtime_instance_id = Some("runtime-live".to_string());
            state.last_d1_write = std::time::Instant::now();
            let mut runtime = RunningRuntime {
                execution_id: "ex-live".to_string(),
                access_token: "token-live".to_string(),
                runtime_instance_id: "runtime-live".to_string(),
                zrok_url_state: std::sync::Arc::new(std::sync::Mutex::new(Some(
                    "https://live.zrok.io".to_string(),
                ))),
                ready_reported: true,
            };
            let mut channel = None;
            let mut recent_commands = RecentCommandTracker::new();
            wait_for_stop(
                &creds,
                &mut state,
                &mut runtime,
                &mut channel,
                &mut recent_commands,
                shutdown_tx,
                server_done_rx,
                std::time::Duration::from_secs(5),
            )
            .await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        let _ = server_done_tx.send(());

        tokio::time::timeout(std::time::Duration::from_millis(250), wait)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            shutdown_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));
        heartbeat.assert_async().await;
    }

    #[tokio::test]
    async fn test_wait_for_stop_with_healthy_connected_channel_skips_running_heartbeat() {
        let mut server = mockito::Server::new_async().await;
        let heartbeat = server
            .mock("POST", "/api/v1/agent/heartbeat")
            .expect(0)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"has_command":false}}"#)
            .create_async()
            .await;

        let creds = make_creds(&server.url());
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let (server_done_tx, server_done_rx) = tokio::sync::oneshot::channel::<()>();
        let (healthy_channel, _command_tx) = live_dummy_channel();

        let wait = tokio::spawn(async move {
            let mut state = DaemonState::new();
            state.status = "running".to_string();
            state.active_url = Some("https://live.zrok.io".to_string());
            state.runtime_instance_id = Some("runtime-live".to_string());
            state.last_d1_write = std::time::Instant::now();
            let mut runtime = RunningRuntime {
                execution_id: "ex-live".to_string(),
                access_token: "token-live".to_string(),
                runtime_instance_id: "runtime-live".to_string(),
                zrok_url_state: std::sync::Arc::new(std::sync::Mutex::new(Some(
                    "https://live.zrok.io".to_string(),
                ))),
                ready_reported: true,
            };
            let mut channel = Some(healthy_channel);
            let mut recent_commands = RecentCommandTracker::new();
            wait_for_stop(
                &creds,
                &mut state,
                &mut runtime,
                &mut channel,
                &mut recent_commands,
                shutdown_tx,
                server_done_rx,
                std::time::Duration::from_secs(5),
            )
            .await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let _ = server_done_tx.send(());

        tokio::time::timeout(std::time::Duration::from_millis(250), wait)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            shutdown_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));
        heartbeat.assert_async().await;
    }

    #[tokio::test]
    async fn test_wait_for_stop_with_disconnected_channel_uses_heartbeat_fallback_immediately() {
        let mut server = mockito::Server::new_async().await;
        let heartbeat = server
            .mock("POST", "/api/v1/agent/heartbeat")
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"has_command":false}}"#)
            .create_async()
            .await;

        let creds = make_creds(&server.url());
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let (server_done_tx, server_done_rx) = tokio::sync::oneshot::channel::<()>();

        let wait = tokio::spawn(async move {
            let mut state = DaemonState::new();
            state.status = "running".to_string();
            state.active_url = Some("https://live.zrok.io".to_string());
            state.runtime_instance_id = Some("runtime-live".to_string());
            state.last_d1_write = std::time::Instant::now();
            let mut runtime = RunningRuntime {
                execution_id: "ex-live".to_string(),
                access_token: "token-live".to_string(),
                runtime_instance_id: "runtime-live".to_string(),
                zrok_url_state: std::sync::Arc::new(std::sync::Mutex::new(Some(
                    "https://live.zrok.io".to_string(),
                ))),
                ready_reported: true,
            };
            let mut channel = Some(dummy_channel());
            let mut recent_commands = RecentCommandTracker::new();
            wait_for_stop(
                &creds,
                &mut state,
                &mut runtime,
                &mut channel,
                &mut recent_commands,
                shutdown_tx,
                server_done_rx,
                std::time::Duration::from_secs(30),
            )
            .await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let _ = server_done_tx.send(());

        tokio::time::timeout(std::time::Duration::from_secs(1), wait)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            shutdown_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));
        heartbeat.assert_async().await;
    }
}
