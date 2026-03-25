mod assets;
mod config;
mod fleet;
mod public_exposure;
mod server;
mod session;

use std::io::{self, BufRead as _, IsTerminal, Write as _};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use config::Config;
use rand::distributions::Alphanumeric;
use rand::Rng;
use server::AppState;
use server::AuthAttemptTracker;
use server::TempLinkScope;
use server::TerminalManager;
use tokio::sync::mpsc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EnableConnectChoice {
    ScanQrCode,
    EnterToken,
}

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

fn prompt_secret(prompt: &str) -> anyhow::Result<String> {
    Ok(rpassword::prompt_password(prompt)?)
}

fn prompt_line(prompt: &str) -> anyhow::Result<String> {
    eprint!("{prompt}");
    io::stderr().flush()?;

    let mut value = String::new();
    let bytes_read = io::stdin().lock().read_line(&mut value)?;
    if bytes_read == 0 {
        anyhow::bail!("Input cancelled.");
    }
    Ok(value.trim().to_string())
}

fn parse_enable_connect_choice(choice: &str) -> anyhow::Result<EnableConnectChoice> {
    match choice.trim() {
        "1" => Ok(EnableConnectChoice::ScanQrCode),
        "2" => Ok(EnableConnectChoice::EnterToken),
        _ => anyhow::bail!("Please enter 1 or 2."),
    }
}

fn prompt_enable_connect_choice() -> anyhow::Result<EnableConnectChoice> {
    loop {
        let choice = prompt_line("  Choice [1/2]: ")?;
        match parse_enable_connect_choice(&choice) {
            Ok(choice) => return Ok(choice),
            Err(err) => eprintln!("  {err}"),
        }
    }
}

fn parse_yes_no(answer: &str, default_yes: bool) -> anyhow::Result<bool> {
    let answer = answer.trim();
    if answer.is_empty() {
        return Ok(default_yes);
    }
    if answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes") {
        return Ok(true);
    }
    if answer.eq_ignore_ascii_case("n") || answer.eq_ignore_ascii_case("no") {
        return Ok(false);
    }
    anyhow::bail!("Please enter Y or N.")
}

fn prompt_yes_no(prompt: &str, default_yes: bool) -> anyhow::Result<bool> {
    loop {
        let answer = prompt_line(prompt)?;
        match parse_yes_no(&answer, default_yes) {
            Ok(answer) => return Ok(answer),
            Err(err) => eprintln!("  {err}"),
        }
    }
}

fn resolve_pin(config_pin: Option<String>) -> anyhow::Result<String> {
    if let Some(pin) = config_pin {
        validate_pin(&pin)?;
        return Ok(pin);
    }
    if !io::stdin().is_terminal() {
        anyhow::bail!("PIN is required. Run in an interactive terminal or pass --pin.");
    }

    let pin = prompt_secret("Set PIN (required): ")?;
    validate_pin(&pin)?;
    let confirm = prompt_secret("Confirm PIN: ")?;
    if pin != confirm {
        anyhow::bail!("PIN confirmation does not match.");
    }
    Ok(pin)
}

fn arg_value(raw_args: &[String], flag: &str) -> Option<String> {
    raw_args
        .windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].clone())
}

fn resolve_enable_pin(raw_args: &[String]) -> anyhow::Result<Option<String>> {
    if let Some(pin) = arg_value(raw_args, "--pin") {
        validate_pin(&pin)?;
        return Ok(Some(pin));
    }
    if !io::stdin().is_terminal() {
        return Ok(None);
    }

    loop {
        let pin = prompt_secret("  Set terminal PIN (6 digits): ")?;
        if pin.trim().is_empty() {
            eprintln!("  PIN cannot be empty.");
            continue;
        }
        if let Err(err) = validate_pin(&pin) {
            eprintln!("  {err}");
            continue;
        }
        let confirm = prompt_secret("  Confirm terminal PIN: ")?;
        if pin != confirm {
            eprintln!("  PIN confirmation does not match.");
            continue;
        }
        return Ok(Some(pin));
    }
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

fn resolve_working_dir(config_cwd: Option<String>) -> anyhow::Result<PathBuf> {
    match config_cwd {
        Some(cwd) => {
            let path = PathBuf::from(&cwd);
            if !path.exists() {
                anyhow::bail!("--cwd directory does not exist: {cwd}");
            }
            if !path.is_dir() {
                anyhow::bail!("--cwd path is not a directory: {cwd}");
            }
            Ok(path)
        }
        None => std::env::current_dir().context("failed to resolve current working directory"),
    }
}

pub struct ServerHandle {
    pub token: String,
    pub pin: String,
    pub public_url: Option<String>,
    pub public_url_state: Arc<Mutex<Option<String>>>,
    pub public_log_path: Option<PathBuf>,
    pub working_dir: PathBuf,
    pub shutdown_tx: mpsc::UnboundedSender<()>,
    pub server_done: tokio::sync::oneshot::Receiver<()>,
    pub state: Arc<AppState>,
}

impl ServerHandle {
    pub fn current_public_url(&self) -> Option<String> {
        self.public_url_state
            .lock()
            .ok()
            .and_then(|current| current.clone())
            .or_else(|| self.public_url.clone())
    }
}

pub async fn start_server(cfg: Config) -> anyhow::Result<ServerHandle> {
    if let Some(secret) = cfg.sso_shared_secret.as_deref() {
        if secret.len() < 16 {
            anyhow::bail!("--sso-shared-secret must be at least 16 characters.");
        }
    }

    let token = cfg.password.clone().unwrap_or_else(|| generate_token(16));
    validate_token(&token)?;

    let pin = if cfg.pin.is_some() || io::stdin().is_terminal() {
        resolve_pin(cfg.pin.clone())?
    } else {
        // Non-interactive (daemon mode): auto-generate 6-digit PIN
        (0..6)
            .map(|_| char::from(rand::thread_rng().gen_range(b'0'..=b'9')))
            .collect()
    };

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
        pin: Some(pin.clone()),
        auth_attempts: Mutex::new(AuthAttemptTracker::new()),
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
        dashboard_pending_logins: Mutex::new(server::DashboardPendingLoginStore::new(
            Duration::from_secs(server::DASHBOARD_PENDING_LOGIN_TTL_SECS),
            server::DASHBOARD_PENDING_LOGIN_MAX_PIN_ATTEMPTS,
        )),
        temp_link_signing_key: generate_token(48),
        auto_shutdown_disabled,
        terminal_only: cfg.terminal_only,
        runtime_instance_id: cfg.runtime_instance_id.clone(),
        sso_shared_secret: cfg.sso_shared_secret.clone(),
        used_sso_nonces: Mutex::new(std::collections::HashMap::new()),
        dashboard_auth: match (
            cfg.dashboard_auth_api_base.clone(),
            cfg.dashboard_auth_machine_token.clone(),
        ) {
            (Some(api_base), Some(machine_token))
                if !api_base.trim().is_empty() && !machine_token.trim().is_empty() =>
            {
                Some(server::DashboardAuthConfig {
                    api_base,
                    machine_token,
                })
            }
            _ => None,
        },
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
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    let (server_done_tx, server_done_rx) = tokio::sync::oneshot::channel::<()>();
    let public_url_state = Arc::new(Mutex::new(None));
    let public_url_state_for_handle = Arc::clone(&public_url_state);
    let (public_url, public_log_path, public_exposure) = match public_exposure::maybe_start(
        &cfg,
        Arc::clone(&public_url_state),
        shutdown_tx.clone(),
    ) {
        Ok(Some(handle)) => (handle.initial_url(), handle.log_path(), Some(handle)),
        Ok(None) => (None, None, None),
        Err(err) => {
            let _ = shutdown_tx.send(());
            let _ = server_done_rx.await;
            return Err(err);
        }
    };
    let public_exposure_inner = public_exposure.clone();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.recv().await;
            })
            .await
            .ok();
        if let Some(exposure) = public_exposure_inner.as_ref() {
            let _ = exposure.stop("stopped");
        }
        let _ = server_done_tx.send(());
    });

    if cfg.zrok {
        if let Some(minutes) = cfg.public_timeout_minutes {
            let public_exposure_ref = public_exposure.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(minutes.saturating_mul(60)));
                if let Some(exposure) = public_exposure_ref.as_ref() {
                    let _ = exposure.stop("public share auto-disabled");
                }
            });
        }
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

    Ok(ServerHandle {
        token,
        pin,
        public_url,
        public_url_state: public_url_state_for_handle,
        public_log_path,
        working_dir,
        shutdown_tx,
        server_done: server_done_rx,
        state,
    })
}

// ─── Entry point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // Route fleet subcommands before clap parsing.
    let raw_args: Vec<String> = std::env::args().collect();
    match raw_args.get(1).map(String::as_str) {
        Some("enable") => {
            let token_arg = raw_args.get(2).filter(|a| !a.starts_with('-')).cloned();
            let endpoint = raw_args
                .windows(2)
                .find(|w| w[0] == "--endpoint")
                .map(|w| w[1].clone())
                .unwrap_or_else(|| "https://webwayfleet-api.webwayfleet.workers.dev".to_string());

            // Determine token — either from arg, QR flow, or prompt
            let token = if let Some(t) = token_arg {
                // ── classic path: codewebway enable <token> ──────────────────
                t
            } else if io::stdin().is_terminal() {
                // ── interactive mode: show menu ───────────────────────────────
                println!();
                println!("  How would you like to connect to WebWayFleet?");
                println!();
                println!(
                    "  [1] Scan QR Code   — use your phone (recommended for headless servers)"
                );
                println!("  [2] Enter Token    — paste the token from the Dashboard");
                println!();
                if prompt_enable_connect_choice()? == EnableConnectChoice::ScanQrCode {
                    // ── QR path ───────────────────────────────────────────────
                    let pin = resolve_enable_pin(&raw_args)?;
                    fleet::enable_qr(&endpoint, pin).await?;

                    // service install prompt (same as token path below)
                    let force_service = raw_args.iter().any(|a| a == "--service");
                    let force_no_service = raw_args.iter().any(|a| a == "--no-service");
                    let install = if force_service {
                        true
                    } else if force_no_service {
                        false
                    } else if io::stdin().is_terminal() {
                        prompt_yes_no("  Install auto-start service? [Y/n]: ", true)?
                    } else {
                        false
                    };
                    if install {
                        return fleet::install_service();
                    }
                    let mut cfg = Config::parse_from(vec!["codewebway"]);
                    cfg.zrok = true;
                    cfg.public_no_expiry = true;
                    if let Ok(creds) = fleet::load_credentials() {
                        cfg.pin = creds.pin;
                    }
                    return fleet::run_daemon(cfg).await;
                } else {
                    // ── manual token prompt ───────────────────────────────────
                    let t = prompt_line("  Enable token from Dashboard: ")?;
                    if t.is_empty() {
                        anyhow::bail!("No token entered.");
                    }
                    t
                }
            } else {
                anyhow::bail!("Usage: codewebway enable <token>");
            };

            // ── shared path after token is known ─────────────────────────────
            let pin = resolve_enable_pin(&raw_args)?;

            fleet::enable(&endpoint, &token, pin).await?;

            // Decide whether to install OS service or start daemon in foreground.
            let force_service = raw_args.iter().any(|a| a == "--service");
            let force_no_service = raw_args.iter().any(|a| a == "--no-service");

            let install = if force_service {
                true
            } else if force_no_service {
                false
            } else if io::stdin().is_terminal() {
                prompt_yes_no("  Install auto-start service? [Y/n]: ", true)?
            } else {
                false
            };

            if install {
                return fleet::install_service();
            }

            // No service → start daemon in foreground.
            let mut cfg = Config::parse_from(vec!["codewebway"]);
            cfg.zrok = true;
            cfg.public_no_expiry = true;
            if let Ok(creds) = fleet::load_credentials() {
                cfg.pin = creds.pin;
            }
            return fleet::run_daemon(cfg).await;
        }
        Some("status") => return fleet::print_status().await,
        Some("disable") => return fleet::disable(),
        Some("uninstall-service") => return fleet::uninstall_service(),
        Some("fleet") => {
            let mut fleet_args = raw_args.clone();
            fleet_args.remove(1); // strip "fleet" so Config::parse_from works normally
            let mut cfg = Config::parse_from(fleet_args);
            // Fleet mode always uses zrok with no expiry — no flags needed.
            cfg.zrok = true;
            cfg.public_no_expiry = true;
            // Use stored PIN from fleet.toml unless overridden on the CLI.
            if cfg.pin.is_none() {
                if let Ok(creds) = fleet::load_credentials() {
                    cfg.pin = creds.pin;
                }
            }
            return fleet::run_daemon(cfg).await;
        }
        _ => {}
    }

    let cfg = Config::parse_from(normalized_args());
    let handle = start_server(cfg.clone()).await?;

    let local_url = format!("http://localhost:{}", cfg.port);
    let addr = format!("{}:{}", cfg.host, cfg.port);

    // Print the startup banner.
    println!();
    println!("  CodeWebway  ");
    println!("  ─────────────────────────────────");
    if let Some(ref zu) = handle.public_url {
        println!("  zrok   : {zu}");
    } else if cfg.zrok {
        println!("  zrok   : (URL pending — see Log below)");
    }
    println!("  Token  : {}", handle.token);
    println!("  PIN    : configured (hidden)");
    println!("  Open   : {}", local_url);
    println!("  Bind   : {}", addr);
    println!("  Dir    : {}", handle.working_dir.display());
    println!("  Login  : Token + PIN on the web login page");
    println!("  Stop   : press q + Enter, or Ctrl+C twice");
    println!("  ─────────────────────────────────");
    println!();

    if cfg.zrok {
        println!("  WARNING: This host is now publicly accessible via zrok.");
        println!("           Anyone with the URL can attempt to log in.");
        println!("           Keep Token + PIN secret — do not share them.");
        println!("           To end exposure: lock out all sessions, then shutdown.");
        println!();
        if let Some(ref lp) = handle.public_log_path {
            if !lp.as_os_str().is_empty() {
                println!("  Log    : {} (tail -f to debug)", lp.display());
                println!();
            }
        }
    }

    if cfg.temp_link {
        let scope =
            TempLinkScope::from_input(&cfg.temp_link_scope).unwrap_or(TempLinkScope::ReadOnly);
        match server::create_temp_link_for_host(
            &handle.state,
            cfg.temp_link_ttl_minutes,
            scope,
            cfg.temp_link_max_uses,
            None,
        ) {
            Ok(link) => {
                let base = handle.public_url.as_deref().unwrap_or(&local_url);
                println!("  TempLink : {}{}", base, link.url);
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

    if cfg.zrok {
        if cfg.public_no_expiry {
            // no extra output needed; noted in banner
        } else if let Some(minutes) = cfg.public_timeout_minutes {
            println!("  Public : auto-disable after {} minute(s)", minutes);
        } else {
            println!("  Tip    : use --public-timeout-minutes <N> or --public-no-expiry");
        }
    } else if cfg.public_timeout_minutes.is_some() || cfg.public_no_expiry {
        println!("  Note   : public share flags are ignored without --zrok.");
    }

    if io::stdin().is_terminal() {
        let tx = handle.shutdown_tx.clone();
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
        let tx = handle.shutdown_tx.clone();
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
        let tx = handle.shutdown_tx.clone();
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

    let _ = handle.server_done.await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse_enable_connect_choice, parse_yes_no, EnableConnectChoice};

    #[test]
    fn test_parse_enable_connect_choice_accepts_qr() {
        assert_eq!(
            parse_enable_connect_choice("1").unwrap(),
            EnableConnectChoice::ScanQrCode
        );
    }

    #[test]
    fn test_parse_enable_connect_choice_accepts_token() {
        assert_eq!(
            parse_enable_connect_choice("2").unwrap(),
            EnableConnectChoice::EnterToken
        );
    }

    #[test]
    fn test_parse_enable_connect_choice_rejects_invalid_input() {
        assert!(parse_enable_connect_choice("abc").is_err());
        assert!(parse_enable_connect_choice("").is_err());
    }

    #[test]
    fn test_parse_yes_no_defaults_and_validates() {
        assert!(parse_yes_no("", true).unwrap());
        assert!(!parse_yes_no("", false).unwrap());
        assert!(parse_yes_no("yes", false).unwrap());
        assert!(!parse_yes_no("n", true).unwrap());
        assert!(parse_yes_no("maybe", true).is_err());
    }
}
