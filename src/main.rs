mod assets;
mod config;
mod server;
mod session;

use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{io, io::IsTerminal};

use anyhow::Context;
use clap::Parser;
use config::Config;
use rand::distributions::Alphanumeric;
use rand::Rng;
use server::AppState;
use server::FailedLoginTracker;
use server::TempLinkScope;
use server::TerminalManager;
use tokio::sync::mpsc;

const ZROK_OWNER_DIR: &str = "codewebway";

fn generate_token(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn validate_pin(pin: &str) -> anyhow::Result<()> {
    if pin.len() < 6 || !pin.chars().all(|c| c.is_ascii_digit()) {
        anyhow::bail!("PIN must be at least 6 digits.");
    }
    Ok(())
}

fn validate_token(token: &str) -> anyhow::Result<()> {
    if token.chars().count() < 16 {
        anyhow::bail!("Token is too short. Use at least 16 characters (~80+ bits).");
    }
    Ok(())
}

fn resolve_pin(config_pin: Option<String>) -> anyhow::Result<String> {
    if let Some(pin) = config_pin {
        validate_pin(&pin)?;
        return Ok(pin);
    }
    if !io::stdin().is_terminal() {
        anyhow::bail!("PIN is required. Run in an interactive terminal or pass --pin.");
    }

    let pin = rpassword::prompt_password("Set PIN (required): ")?;
    validate_pin(&pin)?;
    let confirm = rpassword::prompt_password("Confirm PIN: ")?;
    if pin != confirm {
        anyhow::bail!("PIN confirmation does not match.");
    }
    Ok(pin)
}

fn normalized_args() -> Vec<String> {
    std::env::args()
        .map(|arg| {
            if arg == "-zrok" {
                "--zrok".to_string()
            } else {
                arg
            }
        })
        .collect()
}

fn spawn_zrok(port: u16) -> anyhow::Result<Child> {
    let target = port.to_string();
    let child = Command::new("zrok")
        .args(["share", "public", &target, "--headless"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| {
            "failed to start zrok; install zrok and run `zrok enable <token>` first".to_string()
        })?;
    Ok(child)
}

fn zrok_owner_file(port: u16) -> PathBuf {
    std::env::temp_dir()
        .join(ZROK_OWNER_DIR)
        .join(format!("zrok-public-{port}.pid"))
}

fn read_owned_zrok_pid(port: u16) -> Option<u32> {
    let path = zrok_owner_file(port);
    let raw = fs::read_to_string(path).ok()?;
    raw.trim().parse::<u32>().ok()
}

fn write_owned_zrok_pid(port: u16, pid: u32) {
    let path = zrok_owner_file(port);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(path, format!("{pid}\n"));
}

fn clear_owned_zrok_pid(port: u16) {
    let _ = fs::remove_file(zrok_owner_file(port));
}

fn zrok_token_file(port: u16) -> PathBuf {
    std::env::temp_dir()
        .join(ZROK_OWNER_DIR)
        .join(format!("zrok-public-{port}.token"))
}

fn read_owned_zrok_token(port: u16) -> Option<String> {
    let raw = fs::read_to_string(zrok_token_file(port)).ok()?;
    let s = raw.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
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

/// Release the share token we previously saved, if it still appears in zrok overview.
/// Only touches the exact token we own — never affects other services' shares.
fn release_owned_zrok_token(port: u16) {
    let Some(tok) = read_owned_zrok_token(port) else { return };
    // Verify the token still exists in overview before releasing.
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
                        .map(|shares| shares.iter().any(|s| s["shareToken"].as_str() == Some(&tok)))
                        .unwrap_or(false)
                })
            })
        })
        .unwrap_or(false);
    if still_active {
        eprintln!("  zrok   : releasing saved share {tok}");
        let _ = Command::new("zrok").args(["release", &tok]).status();
    }
}

/// Read zrok's stdout to capture the share URL and extract our token.
/// This is the only reliable way to identify our share — we read directly from
/// the process we spawned, so there is no confusion with other services.
/// Returns a Receiver that fires once with the full share URL.
fn watch_zrok_stdout(port: u16, stdout: std::process::ChildStdout) -> std::sync::mpsc::Receiver<String> {
    use std::io::{BufRead, BufReader};
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            let Ok(line) = line else { break };
            // Extract token from URL: https://<token>.share.zrok.io
            if let Some(tok) = extract_zrok_token(&line) {
                write_owned_zrok_token(port, &tok);
                let _ = tx.send(format!("https://{tok}.share.zrok.io"));
            }
        }
    });
    rx
}

fn extract_zrok_token(line: &str) -> Option<String> {
    // Match https://<token>.share.zrok.io anywhere in the line.
    let marker = ".share.zrok.io";
    let idx = line.find(marker)?;
    let before = &line[..idx];
    let tok = before.split("://").last()?.trim().to_string();
    if tok.is_empty() { None } else { Some(tok) }
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

fn is_owned_public_share_process(pid: u32, port: u16) -> bool {
    let Some(cmd) = process_command_line(pid) else {
        return false;
    };
    let expected = format!("zrok share public {port}");
    cmd.contains(&expected)
}

fn release_stale_owned_zrok_share(port: u16) {
    // Release only the exact token we own — never touches other services' shares.
    release_owned_zrok_token(port);
    clear_owned_zrok_token(port);

    let Some(pid) = read_owned_zrok_pid(port) else {
        return;
    };

    if !is_owned_public_share_process(pid, port) {
        clear_owned_zrok_pid(port);
        return;
    }

    eprintln!("  zrok   : found stale CodeWebway public share (pid {pid}), releasing first");
    let _ = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    // Give zrok time to send a graceful release to the service.
    std::thread::sleep(Duration::from_secs(3));
    if is_owned_public_share_process(pid, port) {
        let _ = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status();
    }
    clear_owned_zrok_pid(port);
}

fn resolve_working_dir(config_cwd: Option<String>) -> anyhow::Result<PathBuf> {
    match config_cwd {
        Some(cwd) => Ok(PathBuf::from(cwd)),
        None => std::env::current_dir().context("failed to resolve current working directory"),
    }
}

fn stop_zrok_child(child: &mut Option<Child>, port: u16, reason: &str) -> bool {
    let Some(mut process) = child.take() else {
        return false;
    };
    // Release share via API before killing process, so zrok service cleans up.
    if let Some(tok) = read_owned_zrok_token(port) {
        let _ = Command::new("zrok").args(["release", &tok]).status();
    }
    // SIGTERM first — lets zrok handshake a graceful release with the service.
    #[cfg(unix)]
    let _ = Command::new("kill")
        .args(["-TERM", &process.id().to_string()])
        .status();
    // Wait up to 3 s for graceful exit.
    for _ in 0..30 {
        if process.try_wait().ok().flatten().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // Force-kill if still running.
    let _ = process.kill();
    let _ = process.wait();
    clear_owned_zrok_token(port);
    eprintln!("  zrok   : {reason}");
    true
}

fn monitor_zrok_child(zrok_child: Arc<Mutex<Option<Child>>>, port: u16) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(2));
        let mut child = zrok_child.lock().unwrap();
        let Some(process) = child.as_mut() else {
            break;
        };
        match process.try_wait() {
            Ok(Some(status)) => {
                eprintln!("  zrok   : exited ({status})");
                *child = None;
                clear_owned_zrok_pid(port);
                break;
            }
            Ok(None) => {}
            Err(err) => {
                eprintln!("  zrok   : failed to poll process status ({err})");
                break;
            }
        }
    });
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cfg = Config::parse_from(normalized_args());

    let token = cfg.password.clone().unwrap_or_else(|| generate_token(16));
    validate_token(&token)?;
    let pin = resolve_pin(cfg.pin.clone())?;
    let working_dir = resolve_working_dir(cfg.cwd.clone())?;

    let idle_timeout = Duration::from_secs(30 * 60);
    let absolute_timeout = Duration::from_secs(12 * 60 * 60);
    let shutdown_grace = Duration::from_secs(3 * 60 * 60);
    let warning_window = Duration::from_secs(2 * 60);
    let auto_shutdown_disabled = cfg.zrok && cfg.public_no_expiry;
    let now = std::time::Instant::now();
    let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel::<()>();

    let state = AppState {
        password: token.clone(),
        pin: Some(pin),
        failed_logins: Mutex::new(FailedLoginTracker::new(3, Duration::from_secs(300))),
        sessions: Mutex::new(server::SessionStore::new(idle_timeout, absolute_timeout)),
        access_locked: Mutex::new(false),
        terminals: Mutex::new(TerminalManager::new(8)),
        default_shell: cfg.shell_path(),
        root_dir: working_dir.clone(),
        scrollback: cfg.scrollback,
        usage: Mutex::new(server::UsageTracker::new()),
        ws_connections: Mutex::new(0),
        max_ws_connections: cfg.max_connections,
        idle_timeout,
        shutdown_grace,
        warning_window,
        shutdown_deadline: Mutex::new(now + shutdown_grace),
        shutdown_tx: shutdown_tx.clone(),
        temp_links: Mutex::new(server::TempLinkStore::new()),
        temp_grants: Mutex::new(std::collections::HashMap::new()),
        temp_link_signing_key: generate_token(48),
        auto_shutdown_disabled,
        terminal_only: cfg.terminal_only,
    };

    state.terminals.lock().unwrap().create(
        "main".to_string(),
        working_dir.clone(),
        cfg.shell_path(),
        cfg.scrollback,
    )?;

    let state = Arc::new(state);
    let app = server::router(Arc::clone(&state));
    let addr = format!("{}:{}", cfg.host, cfg.port);
    let url = format!("http://localhost:{}", cfg.port);

    println!();
    println!("  CodeWebway  ");
    println!("  ─────────────────────────────────");
    println!("  Token  : {}", token);
    println!("  PIN    : configured (hidden)");
    println!("  Open   : {}", url);
    println!("  Bind   : {}", addr);
    println!("  Dir    : {}", working_dir.display());
    println!("  Login  : use this Token + your PIN on the web login page");
    println!("  Stop   : press q + Enter, or Ctrl+C twice to confirm shutdown");
    println!("  ─────────────────────────────────");
    println!();

    if cfg.temp_link {
        let scope =
            TempLinkScope::from_input(&cfg.temp_link_scope).unwrap_or(TempLinkScope::ReadOnly);
        match server::create_temp_link_for_host(
            &state,
            cfg.temp_link_ttl_minutes,
            scope,
            cfg.temp_link_max_uses,
            None,
        ) {
            Ok(link) => {
                println!("  TempLink : {}{}", url, link.url);
                println!(
                    "  TempInfo : ttl={}m scope={} uses={}",
                    cfg.temp_link_ttl_minutes, cfg.temp_link_scope, cfg.temp_link_max_uses
                );
                println!(
                    "             grace={}s after expiry for clock skew/network delay",
                    120
                );
                println!();
            }
            Err(err) => {
                eprintln!("  TempLink : failed to create ({err})");
            }
        }
    }

    let zrok_child = if cfg.zrok {
        release_stale_owned_zrok_share(cfg.port);
        println!("  zrok   : starting public share on port {}", cfg.port);
        println!("  WARNING: Public mode exposes this host to the internet.");
        println!("           Keep Token + PIN secret.");
        println!("           End exposure with lockout + shutdown.");
        let mut child = spawn_zrok(cfg.port)?;
        write_owned_zrok_pid(cfg.port, child.id());
        let url_rx = child.stdout.take().map(|s| watch_zrok_stdout(cfg.port, s));
        {
            use std::io::Write;
            print!("  zrok   : กำลังเชื่อมต่อ โปรดรอ...");
            let _ = std::io::stdout().flush();
        }
        let zrok_url = url_rx.and_then(|rx| rx.recv_timeout(Duration::from_secs(15)).ok());
        match &zrok_url {
            Some(url) => {
                println!("\r\x1b[K  zrok   : {url}");
                println!("  Access : {url}  Token={} + PIN", token);
            }
            None => {
                println!("\r\x1b[K  zrok   : URL pending");
                println!("  Access : URL from zrok + Token={} + your PIN", token);
            }
        }
        Some(child)
    } else {
        None
    };
    let zrok_child = Arc::new(Mutex::new(zrok_child));
    if cfg.zrok {
        monitor_zrok_child(Arc::clone(&zrok_child), cfg.port);
    }

    if cfg.zrok {
        if cfg.public_no_expiry {
            println!("  Public : no automatic expiry (operator accepts risk)");
            println!("           stays active until lockout + shutdown.");
        } else if let Some(minutes) = cfg.public_timeout_minutes {
            println!("  Public : auto-disable after {} minute(s)", minutes);
            let zrok_child_ref = Arc::clone(&zrok_child);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(minutes.saturating_mul(60)));
                let mut child = zrok_child_ref.lock().unwrap();
                let _ = stop_zrok_child(&mut child, cfg.port, "public share auto-disabled");
                clear_owned_zrok_pid(cfg.port);
            });
        } else {
            println!("  Tip    : set --public-timeout-minutes <N> for auto-disable.");
            println!("           or --public-no-expiry to keep it until lockout + shutdown.");
        }
    } else if cfg.public_timeout_minutes.is_some() || cfg.public_no_expiry {
        println!("  Note   : public share flags are ignored without --zrok.");
    }

    if io::stdin().is_terminal() {
        let tx = shutdown_tx.clone();
        std::thread::spawn(move || {
            let stdin = io::stdin();
            let mut line = String::new();
            loop {
                line.clear();
                match stdin.read_line(&mut line) {
                    Ok(0) => {
                        eprintln!("Console input closed. Initiating shutdown.");
                        let _ = tx.send(());
                        break;
                    }
                    Ok(_) => {
                        let cmd = line.trim().to_ascii_lowercase();
                        match cmd.as_str() {
                            "q" | "quit" | "exit" | "stop" => {
                                eprintln!("Shutdown requested from console command.");
                                let _ = tx.send(());
                                break;
                            }
                            "" => {}
                            _ => eprintln!("Type 'q' then Enter to stop."),
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }

    #[cfg(unix)]
    {
        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(stream) => stream,
                Err(_) => return,
            };
            let mut sighup = match signal(SignalKind::hangup()) {
                Ok(stream) => stream,
                Err(_) => return,
            };
            tokio::select! {
                _ = sigterm.recv() => {
                    eprintln!("Shutdown requested by SIGTERM.");
                    let _ = tx.send(());
                }
                _ = sighup.recv() => {
                    eprintln!("Shutdown requested by SIGHUP.");
                    let _ = tx.send(());
                }
            }
        });
    }

    {
        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            let mut press_count = 0usize;
            loop {
                if tokio::signal::ctrl_c().await.is_err() {
                    let _ = tx.send(());
                    break;
                }
                press_count += 1;
                if press_count == 1 {
                    eprintln!("Press Ctrl+C again to confirm shutdown.");
                    continue;
                }
                eprintln!("Shutdown confirmed by Ctrl+C.");
                let _ = tx.send(());
                break;
            }
        });
    }

    if !auto_shutdown_disabled {
        let tx = shutdown_tx.clone();
        let state_ref = Arc::clone(&state);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            loop {
                tick.tick().await;
                if server::shutdown_remaining_secs(&state_ref, std::time::Instant::now()) == 0 {
                    eprintln!("Auto-shutdown: no authenticated activity in grace window.");
                    let _ = tx.send(());
                    break;
                }
            }
        });
    }

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.recv().await;
        })
        .await?;

    let mut child = zrok_child.lock().unwrap();
    let _ = stop_zrok_child(&mut child, cfg.port, "stopped");
    clear_owned_zrok_pid(cfg.port);
    Ok(())
}
