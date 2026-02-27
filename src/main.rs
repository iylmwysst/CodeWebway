mod assets;
mod config;
mod server;
mod session;

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
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
    let mut child = Command::new("zrok")
        .args(["share", "public", &target])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            "failed to start zrok; install zrok and run `zrok enable <token>` first".to_string()
        })?;
    attach_zrok_logs(&mut child);
    Ok(child)
}

fn extract_https_token(line: &str) -> Option<String> {
    for raw in line.split_whitespace() {
        let trimmed = raw.trim_matches(|c: char| matches!(c, '"' | '\'' | '(' | ')' | '[' | ']'));
        if let Some(idx) = trimmed.find("https://") {
            let candidate = trimmed[idx..]
                .trim_end_matches(|c: char| matches!(c, ',' | ';' | '.' | ')' | ']' | '"' | '\''));
            if candidate.starts_with("https://") && candidate.len() > "https://".len() {
                return Some(candidate.to_string());
            }
        }
    }
    None
}

fn attach_zrok_logs(child: &mut Child) {
    let seen_public_url = Arc::new(AtomicBool::new(false));

    if let Some(stdout) = child.stdout.take() {
        let seen_public_url_ref = Arc::clone(&seen_public_url);
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                println!("  zrok   : {line}");
                if !seen_public_url_ref.load(Ordering::Relaxed) {
                    if let Some(url) = extract_https_token(&line) {
                        println!("  Public : {}", url);
                        seen_public_url_ref.store(true, Ordering::Relaxed);
                    }
                }
            }
        });
    }

    if let Some(stderr) = child.stderr.take() {
        let seen_public_url_ref = Arc::clone(&seen_public_url);
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                eprintln!("  zrok   : {line}");
                if !seen_public_url_ref.load(Ordering::Relaxed) {
                    if let Some(url) = extract_https_token(&line) {
                        println!("  Public : {}", url);
                        seen_public_url_ref.store(true, Ordering::Relaxed);
                    }
                }
            }
        });
    }
}

fn resolve_working_dir(config_cwd: Option<String>) -> anyhow::Result<PathBuf> {
    match config_cwd {
        Some(cwd) => Ok(PathBuf::from(cwd)),
        None => std::env::current_dir().context("failed to resolve current working directory"),
    }
}

fn stop_zrok_child(child: &mut Option<Child>, reason: &str) -> bool {
    let Some(mut process) = child.take() else {
        return false;
    };
    let _ = process.kill();
    let _ = process.wait();
    eprintln!("  zrok   : {reason}");
    true
}

fn monitor_zrok_child(zrok_child: Arc<Mutex<Option<Child>>>) {
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
        println!("  zrok   : starting public share on port {}", cfg.port);
        println!("  WARNING: Public mode exposes this host to the internet.");
        println!("           Keep Token + PIN secret and stop when not needed.");
        Some(spawn_zrok(cfg.port)?)
    } else {
        None
    };
    let zrok_child = Arc::new(Mutex::new(zrok_child));
    if cfg.zrok {
        monitor_zrok_child(Arc::clone(&zrok_child));
    }

    if cfg.zrok {
        if let Some(minutes) = cfg.public_timeout_minutes {
            println!("  Public : auto-disable after {} minute(s)", minutes);
            let zrok_child_ref = Arc::clone(&zrok_child);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(minutes.saturating_mul(60)));
                let mut child = zrok_child_ref.lock().unwrap();
                let _ = stop_zrok_child(&mut child, "public share auto-disabled");
            });
        } else {
            println!("  Tip    : set --public-timeout-minutes <N> to auto-disable public mode.");
        }
    } else if cfg.public_timeout_minutes.is_some() {
        println!("  Note   : --public-timeout-minutes is ignored without --zrok.");
    }

    if io::stdin().is_terminal() {
        let tx = shutdown_tx.clone();
        std::thread::spawn(move || {
            let stdin = io::stdin();
            let mut line = String::new();
            loop {
                line.clear();
                match stdin.read_line(&mut line) {
                    Ok(0) => break,
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

    {
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
    let _ = stop_zrok_child(&mut child, "stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::extract_https_token;

    #[test]
    fn test_extract_https_token_with_plain_url() {
        let line = "your share is live at https://example.share.zrok.io";
        assert_eq!(
            extract_https_token(line),
            Some("https://example.share.zrok.io".to_string())
        );
    }

    #[test]
    fn test_extract_https_token_with_equals_prefix() {
        let line = "endpoint=https://abc123.zrok.io ready";
        assert_eq!(
            extract_https_token(line),
            Some("https://abc123.zrok.io".to_string())
        );
    }

    #[test]
    fn test_extract_https_token_missing() {
        let line = "listening on localhost only";
        assert_eq!(extract_https_token(line), None);
    }
}
