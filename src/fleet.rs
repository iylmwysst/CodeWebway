use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use qrcode::render::unicode;
use qrcode::types::Color;
use qrcode::QrCode;
use rand::distributions::Alphanumeric;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
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
    #[serde(default = "current_epoch_millis")]
    pub machine_token_issued_at: u64,
    /// PIN stored during `enable`; used by the daemon so no flag is needed at runtime.
    pub pin: Option<String>,
}

const MACHINE_TOKEN_ROTATE_INTERVAL_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const CHANNEL_RECONCILE_INTERVAL_SECS: u64 = 5 * 60;
const CHANNEL_PING_INTERVAL_SECS: u64 = 30;
const CHANNEL_RECONNECT_INTERVAL_SECS: u64 = 10;
const RUNTIME_SYNC_INTERVAL_SECS: u64 = 1;
const RECENT_COMMAND_TTL_SECS: u64 = 30 * 60;

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
        machine_token_issued_at: current_epoch_millis(),
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
    #[serde(default)]
    pub command_key: Option<String>,
    #[serde(rename = "type")]
    pub kind: String,
    #[allow(dead_code)]
    pub payload: serde_json::Value,
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
) -> String {
    let mut payload = serde_json::json!({
        "type": kind,
        "status": status,
    });
    if let Some(url) = active_url {
        payload["active_url"] = serde_json::json!(url);
    }
    if let Some(runtime_instance_id) = runtime_instance_id {
        payload["runtime_instance_id"] = serde_json::json!(runtime_instance_id);
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
            )))
            .await
            .context("Failed to send realtime hello")?;

        let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let (command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel::<PendingCommand>();

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
                                if let Some(command) = parse_channel_command_message(&text) {
                                    let _ = command_tx.send(command);
                                }
                            }
                            Some(Ok(Message::Close(_))) | None => break,
                            Some(Ok(_)) => {}
                            Some(Err(err)) => {
                                eprintln!("  Fleet: realtime channel receive failed: {err}");
                                break;
                            }
                        }
                    }
                    _ = ping_tick.tick() => {
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

    fn send_snapshot(&self, state: &DaemonState) -> Result<()> {
        self.send_message(build_channel_snapshot_message(
            "snapshot",
            &state.status,
            state.active_url.as_deref(),
            state.runtime_instance_id.as_deref(),
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

fn try_send_channel_snapshot(channel: &mut Option<MachineChannelClient>, state: &DaemonState) {
    let Some(client) = channel.as_ref() else {
        return;
    };
    if let Err(err) = client.send_snapshot(state) {
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
                eprintln!("  Fleet: device deregistered (401) — daemon stopping.");
                eprintln!("  Run: codewebway disable");
                std::process::exit(1);
            }
            eprintln!("  Fleet: heartbeat error {context}: {e}");
        }
    }
}

// ─── Daemon loop ───────────────────────────────────────────────────────────────

pub async fn run_daemon(cfg: crate::config::Config) -> anyhow::Result<()> {
    let mut creds = load_credentials().context("Not enabled. Run: codewebway enable <token>")?;

    println!("  Fleet daemon starting for \"{}\"", creds.machine_name);
    println!("  Endpoint: {}", creds.fleet_endpoint);

    let mut state = DaemonState::new();
    let poll_interval = std::time::Duration::from_secs(30);
    let channel_reconcile_interval =
        std::time::Duration::from_secs(CHANNEL_RECONCILE_INTERVAL_SECS);
    let channel_retry_interval = std::time::Duration::from_secs(CHANNEL_RECONNECT_INTERVAL_SECS);
    let mut channel: Option<MachineChannelClient> = None;
    let mut next_channel_retry = std::time::Instant::now();
    let mut recent_commands = RecentCommandTracker::new();

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
            try_send_channel_snapshot(&mut channel, &state);
        }

        enum IdleWaitResult {
            Command(PendingCommand),
            ChannelClosed,
            Reconcile,
        }

        let idle_wait = if let Some(channel_client) = channel.as_mut() {
            tokio::select! {
                command = channel_client.recv_command() => {
                    match command {
                        Some(cmd) => IdleWaitResult::Command(cmd),
                        None => IdleWaitResult::ChannelClosed,
                    }
                },
                _ = tokio::time::sleep(channel_reconcile_interval) => IdleWaitResult::Reconcile,
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
                "stop_codewebway" => {
                    eprintln!("  Fleet: stop received but no terminal running — reporting stopped");
                    report_terminal_stopped_if_idle(channel.as_ref(), &creds, &cmd).await;
                    continue;
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

        let skip = !state.should_write(
            &state.status.clone(),
            state.active_url.as_deref(),
            state.runtime_instance_id.as_deref(),
        );
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
                if !skip {
                    state.last_d1_write = std::time::Instant::now();
                }
                try_send_channel_snapshot(&mut channel, &state);
                if state.status != "running" {
                    match rotate_machine_token(&mut creds).await {
                        Ok(true) => eprintln!("  Fleet: rotated machine token during idle window."),
                        Ok(false) => {}
                        Err(e) => eprintln!("  Fleet: token rotation skipped: {e}"),
                    }
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

        if recent_commands.record_or_is_duplicate(&cmd) {
            eprintln!(
                "  Fleet: duplicate fallback command ignored: {} {}",
                cmd.kind,
                cmd.execution_id.as_deref().unwrap_or("no-exec-id")
            );
            tokio::time::sleep(poll_interval).await;
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
                        try_send_channel_snapshot(&mut channel, &state);

                        let mut runtime = RunningRuntime {
                            execution_id: exec_id,
                            access_token: handle.token.clone(),
                            runtime_instance_id,
                            zrok_url_state: handle.zrok_url_state.clone(),
                            ready_reported: false,
                        };
                        sync_runtime_ready(&creds, &mut state, &mut runtime, channel.as_ref())
                            .await;

                        wait_for_stop(
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
                        try_send_channel_snapshot(&mut channel, &state);
                        write_status_now(&creds, &mut state, "after terminal stop").await;
                    }
                }
            }
            "stop_codewebway" => {
                eprintln!("  Fleet: stop received but no terminal running — reporting stopped");
                report_terminal_stopped_if_idle(channel.as_ref(), &creds, &cmd).await;
            }
            other => eprintln!("  Fleet: unknown command type: {other}"),
        }

        tokio::time::sleep(poll_interval).await;
    }
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
) {
    tokio::pin!(server_done);
    let mut sync_tick =
        tokio::time::interval(std::time::Duration::from_secs(RUNTIME_SYNC_INTERVAL_SECS));
    sync_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let channel_reconcile_interval =
        std::time::Duration::from_secs(CHANNEL_RECONCILE_INTERVAL_SECS);
    let channel_retry_interval = std::time::Duration::from_secs(CHANNEL_RECONNECT_INTERVAL_SECS);
    let mut next_channel_retry = std::time::Instant::now();
    let mut next_heartbeat_at = tokio::time::Instant::now()
        + if channel.is_some() {
            channel_reconcile_interval
        } else {
            std::time::Duration::from_secs(0)
        };

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
            try_send_channel_snapshot(channel, state);
            next_heartbeat_at = tokio::time::Instant::now() + channel_reconcile_interval;
        }

        let heartbeat_sleep = tokio::time::sleep_until(next_heartbeat_at);
        tokio::pin!(heartbeat_sleep);

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
                    return;
                }
                maybe_cmd = channel_client.recv_command() => {
                    match maybe_cmd {
                        Some(cmd) if cmd.kind == "stop_codewebway" => {
                            let duplicate = recent_commands.record_or_is_duplicate(&cmd);
                            acknowledge_realtime_command(Some(channel_client), &cmd, duplicate);
                            if duplicate {
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
                            if !exec_id.is_empty() {
                                let _ = report_result_via_channel_or_http(
                                    Some(channel_client),
                                    creds,
                                    &exec_id,
                                    "stopped",
                                    true,
                                )
                                .await;
                            }
                            return;
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
                            next_heartbeat_at = tokio::time::Instant::now() + interval;
                        }
                    }
                }
                _ = sync_tick.tick() => {
                    sync_runtime_ready(creds, state, runtime, Some(channel_client)).await;
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
                                    next_heartbeat_at = tokio::time::Instant::now() + if channel.is_some() {
                                        channel_reconcile_interval
                                    } else {
                                        interval
                                    };
                                    continue;
                                }
                                if cmd.kind == "stop_codewebway" {
                                    let exec_id = cmd.execution_id.unwrap_or_default();
                                    let _ = shutdown_tx.send(());
                                    report_runtime_start_failed_if_needed(
                                        Some(channel_client),
                                        creds,
                                        runtime,
                                        "Terminal stopped before public URL was ready",
                                    )
                                    .await;
                                    if !exec_id.is_empty() {
                                        let _ = report_result_via_channel_or_http(
                                            Some(channel_client),
                                            creds,
                                            &exec_id,
                                            "stopped",
                                            true,
                                        )
                                        .await;
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
                    next_heartbeat_at = tokio::time::Instant::now() + if channel.is_some() {
                        channel_reconcile_interval
                    } else {
                        interval
                    };
                }
            }
        } else {
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
                    return;
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
                                    if !exec_id.is_empty() {
                                        let _ = report_result_via_channel_or_http(
                                            channel.as_ref(),
                                            creds,
                                            &exec_id,
                                            "stopped",
                                            true,
                                        )
                                        .await;
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
                    next_heartbeat_at = tokio::time::Instant::now() + interval;
                }
            }
        }
    }
}

async fn handle_realtime_command(
    cfg: &crate::config::Config,
    creds: &mut FleetCredentials,
    state: &mut DaemonState,
    channel: &mut Option<MachineChannelClient>,
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
                    try_send_channel_snapshot(channel, state);

                    let mut runtime = RunningRuntime {
                        execution_id: exec_id,
                        access_token: handle.token.clone(),
                        runtime_instance_id,
                        zrok_url_state: handle.zrok_url_state.clone(),
                        ready_reported: false,
                    };
                    sync_runtime_ready(creds, state, &mut runtime, channel.as_ref()).await;

                    wait_for_stop(
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
                    try_send_channel_snapshot(channel, state);
                    write_status_now(creds, state, "after terminal stop").await;
                }
            }
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
            machine_token_issued_at: 1_700_000_000_000,
            pin: Some("123456".to_string()),
        }
    }

    fn tmp_path(dir: &TempDir) -> PathBuf {
        dir.path().join("fleet.toml")
    }

    fn dummy_channel() -> MachineChannelClient {
        let (outbound_tx, _outbound_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let (_command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel::<PendingCommand>();
        MachineChannelClient {
            outbound_tx,
            command_rx,
        }
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
    fn test_save_and_load_credentials() {
        let dir = TempDir::new().unwrap();
        let path = tmp_path(&dir);
        let creds = make_creds("https://webwayfleet.dev");
        save_credentials_to(&creds, &path).unwrap();
        let loaded = load_credentials_from(&path).unwrap();
        assert_eq!(loaded.machine_token, "mt_test");
        assert_eq!(loaded.machine_name, "pi-test");
        assert_eq!(loaded.fleet_endpoint, "https://webwayfleet.dev");
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
        std::fs::remove_file(&path).unwrap();
        assert!(!path.exists());
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
}
