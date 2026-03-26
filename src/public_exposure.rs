use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

const PUBLIC_OWNER_DIR: &str = "codewebway";
const CLOUDFLARE_ORIGIN_PORT: u16 = 8080;
const CLOUDFLARED_OVERRIDE_PATH_ENV: &str = "CODEWEBWAY_CLOUDFLARED_PATH";
const MANAGED_CLOUDFLARED_VERSION: &str = "2026.3.0";
const CLOUDFLARED_READY_TIMEOUT: Duration = Duration::from_secs(45);
const CLOUDFLARED_START_ATTEMPTS: u8 = 3;
const CLOUDFLARED_RETRY_DELAY: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicExposureProvider {
    Zrok,
    Cloudflare,
}

impl PublicExposureProvider {
    fn label(self) -> &'static str {
        match self {
            Self::Zrok => "zrok",
            Self::Cloudflare => "cloudflared",
        }
    }
}

struct ManagedChild {
    child: Child,
}

#[derive(Clone)]
pub struct PublicExposureHandle {
    provider: PublicExposureProvider,
    port: u16,
    initial_url: Option<String>,
    log_path: Option<PathBuf>,
    child: Arc<Mutex<Option<ManagedChild>>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CloudflareTunnelConfig {
    hostname: String,
    tunnel_token: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CloudflaredDownloadKind {
    RawBinary,
    TarGz,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CloudflaredDownloadSpec {
    version: &'static str,
    url: &'static str,
    expected_sha256: &'static str,
    kind: CloudflaredDownloadKind,
}

impl PublicExposureHandle {
    pub fn initial_url(&self) -> Option<String> {
        self.initial_url.clone()
    }

    pub fn log_path(&self) -> Option<PathBuf> {
        self.log_path.clone()
    }

    pub fn stop(&self, reason: &str) -> bool {
        let mut child = self.child.lock().unwrap();
        stop_public_child(&mut child, self.provider, self.port, reason)
    }
}

pub fn maybe_start(
    cfg: &crate::config::Config,
    shared_url_state: Arc<Mutex<Option<String>>>,
    shutdown_tx: mpsc::UnboundedSender<()>,
) -> anyhow::Result<Option<PublicExposureHandle>> {
    if !cfg.zrok {
        return Ok(None);
    }

    if let Some(cloudflare) = resolve_cloudflare_tunnel_config(cfg)? {
        return start_cloudflare_exposure(cfg.port, cloudflare, shared_url_state, shutdown_tx)
            .map(Some);
    }

    start_zrok_exposure(cfg, shared_url_state, shutdown_tx).map(Some)
}

fn start_zrok_exposure(
    cfg: &crate::config::Config,
    shared_url_state: Arc<Mutex<Option<String>>>,
    shutdown_tx: mpsc::UnboundedSender<()>,
) -> anyhow::Result<PublicExposureHandle> {
    check_zrok_ready()?;
    release_stale_owned_zrok_share(cfg.port);

    let child = Arc::new(Mutex::new(None));
    let mut process = spawn_zrok(cfg.port)?;
    write_owned_public_pid(PublicExposureProvider::Zrok, cfg.port, process.id());

    let (url_tx, url_rx) = std::sync::mpsc::channel::<String>();
    let log_path = process.stderr.take().map(|stderr| {
        log_zrok_stderr(
            cfg.port,
            stderr,
            Arc::clone(&shared_url_state),
            url_tx.clone(),
        )
    });
    if let Some(stdout) = process.stdout.take() {
        scan_zrok_stream_for_url(cfg.port, stdout, Arc::clone(&shared_url_state), url_tx);
    }

    let initial_url = url_rx.recv_timeout(Duration::from_secs(15)).ok();
    if initial_url.is_none() {
        if let Ok(Some(status)) = process.try_wait() {
            clear_owned_public_pid(PublicExposureProvider::Zrok, cfg.port);
            clear_owned_zrok_token(cfg.port);
            anyhow::bail!("zrok exited before a public URL was assigned ({status})");
        }
    }

    if let Some(url) = initial_url.clone() {
        if let Ok(mut current) = shared_url_state.lock() {
            *current = Some(url);
        }
    }

    *child.lock().unwrap() = Some(ManagedChild { child: process });
    monitor_public_child(
        Arc::clone(&child),
        PublicExposureProvider::Zrok,
        cfg.port,
        shutdown_tx,
    );

    Ok(PublicExposureHandle {
        provider: PublicExposureProvider::Zrok,
        port: cfg.port,
        initial_url,
        log_path,
        child,
    })
}

fn start_cloudflare_exposure(
    port: u16,
    config: CloudflareTunnelConfig,
    shared_url_state: Arc<Mutex<Option<String>>>,
    shutdown_tx: mpsc::UnboundedSender<()>,
) -> anyhow::Result<PublicExposureHandle> {
    let cloudflared_binary = check_cloudflared_ready()?;
    release_stale_owned_cloudflared(port);

    let log_path = cloudflared_log_path(port);
    let pid_path = cloudflared_pidfile_path(port);
    let initial_url = Some(format!("https://{}", config.hostname));

    let child = Arc::new(Mutex::new(None));
    let mut last_err: Option<anyhow::Error> = None;
    let mut ready_process = None;

    for attempt in 1..=CLOUDFLARED_START_ATTEMPTS {
        let mut process = spawn_cloudflared(
            &cloudflared_binary,
            &config.tunnel_token,
            &log_path,
            &pid_path,
        )?;
        write_owned_public_pid(PublicExposureProvider::Cloudflare, port, process.id());

        match wait_for_cloudflared_ready(
            &mut process,
            port,
            &log_path,
            &pid_path,
            CLOUDFLARED_READY_TIMEOUT,
        ) {
            Ok(()) => {
                ready_process = Some(process);
                break;
            }
            Err(err) => {
                eprintln!(
                    "  cloudflared: start attempt {attempt}/{CLOUDFLARED_START_ATTEMPTS} failed: {err}"
                );
                last_err = Some(err);
                if attempt < CLOUDFLARED_START_ATTEMPTS {
                    std::thread::sleep(CLOUDFLARED_RETRY_DELAY);
                    release_stale_owned_cloudflared(port);
                }
            }
        }
    }

    let process = ready_process.with_context(|| {
        last_err.unwrap_or_else(|| anyhow::anyhow!("cloudflared failed to start"))
    })?;

    if let Some(url) = initial_url.clone() {
        if let Ok(mut current) = shared_url_state.lock() {
            *current = Some(url);
        }
    }

    *child.lock().unwrap() = Some(ManagedChild { child: process });
    monitor_public_child(
        Arc::clone(&child),
        PublicExposureProvider::Cloudflare,
        port,
        shutdown_tx,
    );

    Ok(PublicExposureHandle {
        provider: PublicExposureProvider::Cloudflare,
        port,
        initial_url,
        log_path: Some(log_path),
        child,
    })
}

fn resolve_cloudflare_tunnel_config(
    cfg: &crate::config::Config,
) -> anyhow::Result<Option<CloudflareTunnelConfig>> {
    let Some(machine_token) = cfg.dashboard_auth_machine_token.as_deref() else {
        return Ok(None);
    };
    let creds = match crate::fleet::load_credentials() {
        Ok(creds) => creds,
        Err(_) => return Ok(None),
    };

    if creds.machine_token != machine_token {
        return Ok(None);
    }

    resolve_cloudflare_tunnel_config_for(cfg, Some(&creds))
}

fn resolve_cloudflare_tunnel_config_for(
    cfg: &crate::config::Config,
    creds: Option<&crate::fleet::FleetCredentials>,
) -> anyhow::Result<Option<CloudflareTunnelConfig>> {
    let Some(creds) = creds else {
        return Ok(None);
    };
    if creds.public_provider.as_deref() != Some("cloudflare") {
        return Ok(None);
    }
    if cfg.port != CLOUDFLARE_ORIGIN_PORT {
        anyhow::bail!(
            "cloudflare public ingress currently supports port {CLOUDFLARE_ORIGIN_PORT} in fleet mode; got {}",
            cfg.port
        );
    }

    let hostname = creds
        .public_hostname
        .clone()
        .filter(|value| !value.trim().is_empty())
        .context("cloudflare public ingress is missing a hostname")?;
    let tunnel_token = creds
        .cloudflare_tunnel_token
        .clone()
        .filter(|value| !value.trim().is_empty())
        .context("cloudflare public ingress is missing a tunnel token")?;

    Ok(Some(CloudflareTunnelConfig {
        hostname,
        tunnel_token,
    }))
}

fn check_zrok_ready() -> anyhow::Result<()> {
    let installed = Command::new("zrok")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok();
    if !installed {
        return Err(anyhow::anyhow!(
            "zrok not found in PATH.\n\n\
             Install zrok first:\n\
             \x20 macOS  : brew install openziti/ziti/zrok\n\
             \x20 Linux  : curl -sSf https://get.zrok.io | bash\n\
             \x20 Others : https://docs.zrok.io/docs/getting-started\n\n\
             Then enable your account:\n\
             \x20 zrok enable <token>   (token from https://zrok.io)"
        ));
    }

    let enabled = Command::new("zrok")
        .arg("status")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !enabled {
        return Err(anyhow::anyhow!(
            "zrok is installed but not enabled.\n\n\
             1. Create a free account at https://zrok.io\n\
             2. Copy your enable token from the dashboard\n\
             3. Run: zrok enable <token>"
        ));
    }
    Ok(())
}

fn check_cloudflared_ready() -> anyhow::Result<PathBuf> {
    resolve_cloudflared_binary()
}

fn spawn_zrok(port: u16) -> anyhow::Result<Child> {
    let target = port.to_string();
    let child = Command::new("zrok")
        .args(["share", "public", &target, "--headless"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            "failed to start zrok; install zrok and run `zrok enable <token>` first".to_string()
        })?;
    Ok(child)
}

fn spawn_cloudflared(
    cloudflared_binary: &Path,
    tunnel_token: &str,
    log_path: &Path,
    pid_path: &Path,
) -> anyhow::Result<Child> {
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create cloudflared log directory {}",
                parent.display()
            )
        })?;
    }
    let log_path_arg = log_path.display().to_string();
    let pid_path_arg = pid_path.display().to_string();
    let child = Command::new(cloudflared_binary)
        .arg("tunnel")
        .arg("--no-autoupdate")
        .arg("--loglevel")
        .arg("info")
        .arg("--logfile")
        .arg(log_path_arg)
        .arg("--pidfile")
        .arg(pid_path_arg)
        .arg("run")
        .arg("--token")
        .arg(tunnel_token)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| {
            format!(
                "failed to start cloudflared from {}",
                cloudflared_binary.display()
            )
        })?;
    Ok(child)
}

fn command_runs_successfully(binary: &Path, args: &[&str]) -> bool {
    Command::new(binary)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn wait_for_cloudflared_ready(
    process: &mut Child,
    port: u16,
    log_path: &Path,
    pid_path: &Path,
    timeout: Duration,
) -> anyhow::Result<()> {
    let start = std::time::Instant::now();
    loop {
        if pid_path.exists() || cloudflared_log_reports_ready(log_path) {
            return Ok(());
        }
        if let Ok(Some(status)) = process.try_wait() {
            clear_owned_public_pid(PublicExposureProvider::Cloudflare, port);
            let _ = fs::remove_file(pid_path);
            anyhow::bail!("cloudflared exited before the tunnel became ready ({status})");
        }
        if start.elapsed() >= timeout {
            terminate_failed_cloudflared_start(process);
            clear_owned_public_pid(PublicExposureProvider::Cloudflare, port);
            let _ = fs::remove_file(pid_path);
            anyhow::bail!(
                "cloudflared did not report readiness within {}s",
                timeout.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn cloudflared_log_reports_ready(log_path: &Path) -> bool {
    let Ok(contents) = fs::read_to_string(log_path) else {
        return false;
    };
    contents.contains("Registered tunnel connection")
        || contents.contains("Updated to new configuration")
}

fn terminate_failed_cloudflared_start(process: &mut Child) {
    #[cfg(unix)]
    let _ = Command::new("kill")
        .args(["-TERM", &process.id().to_string()])
        .status();

    for _ in 0..30 {
        if process.try_wait().ok().flatten().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let _ = process.kill();
    let _ = process.wait();
}

fn managed_cloudflared_path() -> PathBuf {
    let file_name = if cfg!(windows) {
        "cloudflared.exe"
    } else {
        "cloudflared"
    };
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("codewebway")
        .join("bin")
        .join(file_name)
}

fn cloudflared_download_spec(os: &str, arch: &str) -> anyhow::Result<CloudflaredDownloadSpec> {
    match (os, arch) {
        ("linux", "x86_64") => Ok(CloudflaredDownloadSpec {
            version: MANAGED_CLOUDFLARED_VERSION,
            url: "https://github.com/cloudflare/cloudflared/releases/download/2026.3.0/cloudflared-linux-amd64",
            expected_sha256: "4a9e50e6d6d798e90fcd01933151a90bf7edd99a0a55c28ad18f2e16263a5c30",
            kind: CloudflaredDownloadKind::RawBinary,
        }),
        ("linux", "aarch64") | ("linux", "arm64") => Ok(CloudflaredDownloadSpec {
            version: MANAGED_CLOUDFLARED_VERSION,
            url: "https://github.com/cloudflare/cloudflared/releases/download/2026.3.0/cloudflared-linux-arm64",
            expected_sha256: "0755ba4cbab59980e6148367fcf53a8f3ec85a97deefd63c2420cf7850769bee",
            kind: CloudflaredDownloadKind::RawBinary,
        }),
        ("macos", "x86_64") => Ok(CloudflaredDownloadSpec {
            version: MANAGED_CLOUDFLARED_VERSION,
            url: "https://github.com/cloudflare/cloudflared/releases/download/2026.3.0/cloudflared-darwin-amd64.tgz",
            expected_sha256: "b91dbec79a3e3809d5508b96d8b0bdfbf3ad7d51f858200228fa3e57100580d9",
            kind: CloudflaredDownloadKind::TarGz,
        }),
        ("macos", "aarch64") | ("macos", "arm64") => Ok(CloudflaredDownloadSpec {
            version: MANAGED_CLOUDFLARED_VERSION,
            url: "https://github.com/cloudflare/cloudflared/releases/download/2026.3.0/cloudflared-darwin-arm64.tgz",
            expected_sha256: "633cee0fd41fd2020e17498beecc54811bf4fc99f891c080dc9343eb0f449c60",
            kind: CloudflaredDownloadKind::TarGz,
        }),
        (target_os, target_arch) => anyhow::bail!(
            "Cloudflare public ingress is not yet auto-installable on {target_os}/{target_arch}"
        ),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn verify_cloudflared_download(bytes: &[u8], spec: &CloudflaredDownloadSpec) -> anyhow::Result<()> {
    let actual = sha256_hex(bytes);
    if actual != spec.expected_sha256 {
        anyhow::bail!(
            "cloudflared checksum mismatch for {}: expected {}, got {}",
            spec.url,
            spec.expected_sha256,
            actual
        );
    }
    Ok(())
}

fn command_stdout_trimmed(command: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new(command).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

fn cloudflared_version(command: &Path) -> Option<String> {
    let stdout = command_stdout_trimmed(command, &["version"])?;
    let mut parts = stdout.split_whitespace();
    while let Some(part) = parts.next() {
        if part.eq_ignore_ascii_case("version") {
            return parts.next().map(|value| value.trim().to_string());
        }
    }
    None
}

fn install_managed_cloudflared(destination: &Path) -> anyhow::Result<()> {
    let spec = cloudflared_download_spec(std::env::consts::OS, std::env::consts::ARCH)?;
    let client = reqwest::blocking::Client::new();
    let bytes = client
        .get(spec.url)
        .header(
            reqwest::header::USER_AGENT,
            format!("codewebway/{}", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .with_context(|| format!("failed to download cloudflared from {}", spec.url))?
        .error_for_status()
        .with_context(|| format!("cloudflared download failed for {}", spec.url))?
        .bytes()
        .context("failed to read downloaded cloudflared bytes")?;

    if bytes.is_empty() {
        anyhow::bail!("downloaded cloudflared asset was empty");
    }
    verify_cloudflared_download(&bytes, &spec)?;

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create managed cloudflared directory {}",
                parent.display()
            )
        })?;
    }

    let temp_path = destination.with_extension("download");
    let _ = fs::remove_file(&temp_path);

    match spec.kind {
        CloudflaredDownloadKind::RawBinary => {
            fs::write(&temp_path, &bytes)
                .with_context(|| format!("failed to write {}", temp_path.display()))?;
        }
        CloudflaredDownloadKind::TarGz => {
            let decoder = GzDecoder::new(Cursor::new(bytes));
            let mut archive = tar::Archive::new(decoder);
            let mut extracted = false;
            for entry in archive
                .entries()
                .context("failed to read cloudflared archive")?
            {
                let mut entry = entry.context("failed to read cloudflared archive entry")?;
                let entry_path = entry
                    .path()
                    .context("failed to resolve cloudflared archive entry path")?;
                if entry_path.file_name().and_then(|value| value.to_str()) == Some("cloudflared") {
                    entry
                        .unpack(&temp_path)
                        .with_context(|| format!("failed to unpack {}", temp_path.display()))?;
                    extracted = true;
                    break;
                }
            }
            if !extracted {
                anyhow::bail!("cloudflared archive did not contain the cloudflared binary");
            }
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&temp_path)
            .with_context(|| format!("failed to read {}", temp_path.display()))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&temp_path, perms)
            .with_context(|| format!("failed to chmod {}", temp_path.display()))?;
    }

    fs::rename(&temp_path, destination)
        .with_context(|| format!("failed to install {}", destination.display()))?;
    Ok(())
}

fn resolve_cloudflared_binary() -> anyhow::Result<PathBuf> {
    let managed_spec = cloudflared_download_spec(std::env::consts::OS, std::env::consts::ARCH)?;

    if let Ok(raw) = std::env::var(CLOUDFLARED_OVERRIDE_PATH_ENV) {
        let path = PathBuf::from(raw);
        if command_runs_successfully(&path, &["version"]) {
            return Ok(path);
        }
        anyhow::bail!("{CLOUDFLARED_OVERRIDE_PATH_ENV} points to a non-working cloudflared binary");
    }

    let managed = managed_cloudflared_path();
    if command_runs_successfully(&managed, &["version"]) {
        if cloudflared_version(&managed).as_deref() == Some(managed_spec.version) {
            return Ok(managed);
        }
        eprintln!(
            "  cloudflared: managed binary at {} is not the pinned version {}; reinstalling",
            managed.display(),
            managed_spec.version
        );
    }

    eprintln!(
        "  cloudflared: installing pinned managed version {} to {}",
        managed_spec.version,
        managed.display()
    );
    if let Err(err) = install_managed_cloudflared(&managed) {
        let path_binary = PathBuf::from("cloudflared");
        if command_runs_successfully(&path_binary, &["version"]) {
            eprintln!(
                "  cloudflared: failed to install pinned managed version {} ({err}); falling back to PATH binary {}",
                managed_spec.version,
                path_binary.display()
            );
            return Ok(path_binary);
        }
        return Err(err);
    }

    if !command_runs_successfully(&managed, &["version"]) {
        anyhow::bail!(
            "downloaded cloudflared binary did not start correctly from {}",
            managed.display()
        );
    }
    if cloudflared_version(&managed).as_deref() != Some(managed_spec.version) {
        anyhow::bail!(
            "installed managed cloudflared from {} but version did not match pinned release {}",
            managed.display(),
            managed_spec.version
        );
    }
    eprintln!(
        "  cloudflared: installed managed version {} at {}",
        managed_spec.version,
        managed.display()
    );

    Ok(managed)
}

fn public_owner_file(provider: PublicExposureProvider, port: u16) -> PathBuf {
    std::env::temp_dir()
        .join(PUBLIC_OWNER_DIR)
        .join(format!("{}-public-{port}.pid", provider.label()))
}

fn read_owned_public_pid(provider: PublicExposureProvider, port: u16) -> Option<u32> {
    let path = public_owner_file(provider, port);
    let raw = fs::read_to_string(path).ok()?;
    raw.trim().parse::<u32>().ok()
}

fn write_owned_public_pid(provider: PublicExposureProvider, port: u16, pid: u32) {
    let path = public_owner_file(provider, port);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(path, format!("{pid}\n"));
}

fn clear_owned_public_pid(provider: PublicExposureProvider, port: u16) {
    let _ = fs::remove_file(public_owner_file(provider, port));
}

fn zrok_token_file(port: u16) -> PathBuf {
    std::env::temp_dir()
        .join(PUBLIC_OWNER_DIR)
        .join(format!("zrok-public-{port}.token"))
}

fn read_owned_zrok_token(port: u16) -> Option<String> {
    let raw = fs::read_to_string(zrok_token_file(port)).ok()?;
    let s = raw.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn write_owned_zrok_token(port: u16, token: &str) {
    let path = zrok_token_file(port);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(path, format!("{token}\n"));
}

fn clear_owned_zrok_token(port: u16) {
    let _ = fs::remove_file(zrok_token_file(port));
}

fn release_owned_zrok_token(port: u16) {
    let Some(tok) = read_owned_zrok_token(port) else {
        return;
    };

    let still_active = Command::new("zrok")
        .args(["overview"])
        .output()
        .ok()
        .and_then(|out| serde_json::from_slice::<serde_json::Value>(&out.stdout).ok())
        .and_then(|json| {
            json["environments"].as_array().map(|envs| {
                envs.iter().any(|env| {
                    env["shares"]
                        .as_array()
                        .map(|shares| {
                            shares
                                .iter()
                                .any(|s| s["shareToken"].as_str() == Some(&tok))
                        })
                        .unwrap_or(false)
                })
            })
        })
        .unwrap_or(false);
    if still_active {
        eprintln!("  Public : releasing saved standalone share {tok}");
        let _ = Command::new("zrok").args(["release", &tok]).status();
    }
}

fn scan_zrok_stream_for_url<R: std::io::Read + Send + 'static>(
    port: u16,
    stream: R,
    shared_url: Arc<Mutex<Option<String>>>,
    tx: std::sync::mpsc::Sender<String>,
) {
    use std::io::{BufRead, BufReader};
    std::thread::spawn(move || {
        let reader = BufReader::new(stream);
        for line in reader.lines() {
            let Ok(line) = line else { break };
            if let Some(tok) = extract_zrok_token(&line) {
                write_owned_zrok_token(port, &tok);
                let url = format!("https://{tok}.share.zrok.io");
                if let Ok(mut current) = shared_url.lock() {
                    *current = Some(url.clone());
                }
                let _ = tx.send(url);
            }
        }
    });
}

fn log_zrok_stderr(
    port: u16,
    stderr: std::process::ChildStderr,
    shared_url: Arc<Mutex<Option<String>>>,
    url_tx: std::sync::mpsc::Sender<String>,
) -> PathBuf {
    use std::io::{BufRead, BufReader, Write};
    let log_path = std::env::temp_dir()
        .join(PUBLIC_OWNER_DIR)
        .join(format!("zrok-{port}.log"));
    let path = log_path.clone();
    std::thread::spawn(move || {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let Ok(mut file) = fs::File::create(&path) else {
            return;
        };
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            let Ok(line) = line else { break };
            if let Some(tok) = extract_zrok_token(&line) {
                write_owned_zrok_token(port, &tok);
                let url = format!("https://{tok}.share.zrok.io");
                if let Ok(mut current) = shared_url.lock() {
                    *current = Some(url.clone());
                }
                let _ = url_tx.send(url);
            }
            let _ = writeln!(file, "{line}");
        }
    });
    log_path
}

fn extract_zrok_token(line: &str) -> Option<String> {
    let marker = ".share.zrok.io";
    let idx = line.find(marker)?;
    let before = &line[..idx];
    let tok = before.split("://").last()?.trim().to_string();
    if tok.is_empty() {
        None
    } else {
        Some(tok)
    }
}

fn process_command_line(pid: u32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let cmd = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if cmd.is_empty() {
        None
    } else {
        Some(cmd)
    }
}

fn is_owned_zrok_process(pid: u32, port: u16) -> bool {
    let Some(cmd) = process_command_line(pid) else {
        return false;
    };
    let expected = format!("zrok share public {port}");
    cmd.contains(&expected)
}

fn is_owned_cloudflared_process(pid: u32, port: u16) -> bool {
    let Some(cmd) = process_command_line(pid) else {
        return false;
    };
    let expected_log = cloudflared_log_path(port).display().to_string();
    cmd.contains("cloudflared tunnel") && cmd.contains(&expected_log)
}

fn release_stale_owned_zrok_share(port: u16) {
    release_owned_zrok_token(port);
    clear_owned_zrok_token(port);

    let Some(pid) = read_owned_public_pid(PublicExposureProvider::Zrok, port) else {
        return;
    };

    if !is_owned_zrok_process(pid, port) {
        clear_owned_public_pid(PublicExposureProvider::Zrok, port);
        return;
    }

    eprintln!("  Public : found stale standalone ingress share (pid {pid}), releasing first");
    let _ = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    std::thread::sleep(Duration::from_secs(3));
    if is_owned_zrok_process(pid, port) {
        let _ = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status();
    }
    clear_owned_public_pid(PublicExposureProvider::Zrok, port);
}

fn release_stale_owned_cloudflared(port: u16) {
    let Some(pid) = read_owned_public_pid(PublicExposureProvider::Cloudflare, port) else {
        return;
    };

    if !is_owned_cloudflared_process(pid, port) {
        clear_owned_public_pid(PublicExposureProvider::Cloudflare, port);
        let _ = fs::remove_file(cloudflared_pidfile_path(port));
        return;
    }

    eprintln!("  cloudflared: found stale CodeWebway tunnel (pid {pid}), stopping first");
    let _ = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    std::thread::sleep(Duration::from_secs(3));
    if is_owned_cloudflared_process(pid, port) {
        let _ = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status();
    }
    clear_owned_public_pid(PublicExposureProvider::Cloudflare, port);
    let _ = fs::remove_file(cloudflared_pidfile_path(port));
}

fn cloudflared_log_path(port: u16) -> PathBuf {
    std::env::temp_dir()
        .join(PUBLIC_OWNER_DIR)
        .join(format!("cloudflared-{port}.log"))
}

fn cloudflared_pidfile_path(port: u16) -> PathBuf {
    std::env::temp_dir()
        .join(PUBLIC_OWNER_DIR)
        .join(format!("cloudflared-{port}.pidfile"))
}

fn stop_public_child(
    child: &mut Option<ManagedChild>,
    provider: PublicExposureProvider,
    port: u16,
    reason: &str,
) -> bool {
    match provider {
        PublicExposureProvider::Zrok => stop_zrok_child(child, port, reason),
        PublicExposureProvider::Cloudflare => stop_cloudflared_child(child, port, reason),
    }
}

fn stop_zrok_child(child: &mut Option<ManagedChild>, port: u16, reason: &str) -> bool {
    let Some(mut managed) = child.take() else {
        return false;
    };
    let process = &mut managed.child;
    if let Some(tok) = read_owned_zrok_token(port) {
        let _ = Command::new("zrok").args(["release", &tok]).status();
    }
    #[cfg(unix)]
    let _ = Command::new("kill")
        .args(["-TERM", &process.id().to_string()])
        .status();
    for _ in 0..30 {
        if process.try_wait().ok().flatten().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = process.kill();
    let _ = process.wait();
    clear_owned_public_pid(PublicExposureProvider::Zrok, port);
    clear_owned_zrok_token(port);
    eprintln!("  Public : {reason}");
    true
}

fn stop_cloudflared_child(child: &mut Option<ManagedChild>, port: u16, reason: &str) -> bool {
    let Some(mut managed) = child.take() else {
        return false;
    };
    let process = &mut managed.child;
    #[cfg(unix)]
    let _ = Command::new("kill")
        .args(["-TERM", &process.id().to_string()])
        .status();
    for _ in 0..30 {
        if process.try_wait().ok().flatten().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = process.kill();
    let _ = process.wait();
    clear_owned_public_pid(PublicExposureProvider::Cloudflare, port);
    let _ = fs::remove_file(cloudflared_pidfile_path(port));
    eprintln!("  cloudflared: {reason}");
    true
}

fn monitor_public_child(
    public_child: Arc<Mutex<Option<ManagedChild>>>,
    provider: PublicExposureProvider,
    port: u16,
    shutdown_tx: mpsc::UnboundedSender<()>,
) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(2));
        let mut child = public_child.lock().unwrap();
        let Some(managed) = child.as_mut() else {
            break;
        };
        match managed.child.try_wait() {
            Ok(Some(status)) => {
                eprintln!("  {}: exited ({status})", provider.label());
                *child = None;
                clear_owned_public_pid(provider, port);
                if provider == PublicExposureProvider::Zrok {
                    clear_owned_zrok_token(port);
                } else {
                    let _ = fs::remove_file(cloudflared_pidfile_path(port));
                }
                let _ = shutdown_tx.send(());
                break;
            }
            Ok(None) => {}
            Err(err) => {
                eprintln!(
                    "  {}: failed to poll process status ({err})",
                    provider.label()
                );
                break;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{
        cloudflared_download_spec, cloudflared_log_reports_ready,
        resolve_cloudflare_tunnel_config_for, sha256_hex, verify_cloudflared_download,
        CloudflareTunnelConfig, CloudflaredDownloadKind, CloudflaredDownloadSpec,
    };
    use crate::config::Config;
    use crate::fleet::FleetCredentials;
    use clap::Parser;
    use std::fs;
    use tempfile::TempDir;

    fn base_config() -> Config {
        Config::parse_from(["codewebway", "--zrok"])
    }

    fn fleet_creds() -> FleetCredentials {
        FleetCredentials {
            machine_token: "machine-token-1".to_string(),
            machine_name: "machine-1".to_string(),
            fleet_endpoint: "https://fleet.example.com".to_string(),
            machine_id: Some("machine-1".to_string()),
            machine_token_issued_at: 0,
            pin: Some("123456".to_string()),
            public_provider: Some("cloudflare".to_string()),
            public_hostname: Some("m-machine-1.codewebway.com".to_string()),
            public_runtime_instance_id: Some("runtime-1".to_string()),
            cloudflare_tunnel_id: Some("tunnel-1".to_string()),
            cloudflare_tunnel_token: Some("token-1".to_string()),
        }
    }

    #[test]
    fn test_resolve_cloudflare_tunnel_config_uses_fleet_hostname_and_token() {
        let cfg = base_config();
        let creds = fleet_creds();

        let result = resolve_cloudflare_tunnel_config_for(&cfg, Some(&creds)).unwrap();

        assert_eq!(
            result,
            Some(CloudflareTunnelConfig {
                hostname: "m-machine-1.codewebway.com".to_string(),
                tunnel_token: "token-1".to_string(),
            })
        );
    }

    #[test]
    fn test_resolve_cloudflare_tunnel_config_returns_none_for_other_provider() {
        let cfg = base_config();
        let mut creds = fleet_creds();
        creds.public_provider = Some("zrok".to_string());

        let result = resolve_cloudflare_tunnel_config_for(&cfg, Some(&creds)).unwrap();

        assert_eq!(result, None);
    }

    #[test]
    fn test_resolve_cloudflare_tunnel_config_rejects_non_default_port() {
        let mut cfg = base_config();
        cfg.port = 9090;
        let creds = fleet_creds();

        let err = resolve_cloudflare_tunnel_config_for(&cfg, Some(&creds)).unwrap_err();

        assert!(err
            .to_string()
            .contains("cloudflare public ingress currently supports port 8080"));
    }

    #[test]
    fn test_cloudflared_download_spec_linux_amd64_uses_direct_binary() {
        let spec = cloudflared_download_spec("linux", "x86_64").unwrap();

        assert_eq!(
            spec,
            CloudflaredDownloadSpec {
                version: "2026.3.0",
                url: "https://github.com/cloudflare/cloudflared/releases/download/2026.3.0/cloudflared-linux-amd64",
                expected_sha256: "4a9e50e6d6d798e90fcd01933151a90bf7edd99a0a55c28ad18f2e16263a5c30",
                kind: CloudflaredDownloadKind::RawBinary,
            }
        );
    }

    #[test]
    fn test_cloudflared_download_spec_macos_arm64_uses_tgz() {
        let spec = cloudflared_download_spec("macos", "aarch64").unwrap();

        assert_eq!(
            spec,
            CloudflaredDownloadSpec {
                version: "2026.3.0",
                url: "https://github.com/cloudflare/cloudflared/releases/download/2026.3.0/cloudflared-darwin-arm64.tgz",
                expected_sha256: "633cee0fd41fd2020e17498beecc54811bf4fc99f891c080dc9343eb0f449c60",
                kind: CloudflaredDownloadKind::TarGz,
            }
        );
    }

    #[test]
    fn test_sha256_hex_matches_known_value() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_verify_cloudflared_download_rejects_checksum_mismatch() {
        let spec = cloudflared_download_spec("linux", "x86_64").unwrap();

        let err = verify_cloudflared_download(b"not-the-real-binary", &spec).unwrap_err();

        assert!(err.to_string().contains("cloudflared checksum mismatch"));
    }

    #[test]
    fn test_cloudflared_log_reports_ready_from_registered_connection() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("cloudflared.log");
        fs::write(
            &log_path,
            "{\"message\":\"Registered tunnel connection\"}\n",
        )
        .unwrap();

        assert!(cloudflared_log_reports_ready(&log_path));
    }

    #[test]
    fn test_cloudflared_log_reports_ready_from_updated_configuration() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("cloudflared.log");
        fs::write(
            &log_path,
            "{\"message\":\"Updated to new configuration\"}\n",
        )
        .unwrap();

        assert!(cloudflared_log_reports_ready(&log_path));
    }
}
