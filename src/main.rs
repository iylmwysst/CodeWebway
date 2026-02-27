mod assets;
mod config;
mod server;
mod session;

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;
use std::{io, io::IsTerminal};

use anyhow::Context;
use clap::Parser;
use config::Config;
use rand::distributions::Alphanumeric;
use rand::Rng;
use server::AppState;
use server::FailedLoginTracker;
use server::TerminalManager;

fn generate_token(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn resolve_pin(config_pin: Option<String>) -> anyhow::Result<String> {
    if let Some(pin) = config_pin {
        return Ok(pin);
    }
    if !io::stdin().is_terminal() {
        anyhow::bail!("PIN is required. Run in an interactive terminal or pass --pin.");
    }

    let pin = rpassword::prompt_password("Set PIN (required): ")?;
    if pin.trim().is_empty() {
        anyhow::bail!("PIN cannot be empty.");
    }
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
        .args(["share", "public", &target])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| {
            "failed to start zrok; install zrok and run `zrok enable <token>` first".to_string()
        })?;
    Ok(child)
}

fn resolve_working_dir(config_cwd: Option<String>) -> anyhow::Result<PathBuf> {
    match config_cwd {
        Some(cwd) => Ok(PathBuf::from(cwd)),
        None => std::env::current_dir().context("failed to resolve current working directory"),
    }
}

fn stop_zrok_child(child: &mut Option<Child>) {
    let Some(mut process) = child.take() else {
        return;
    };
    let _ = process.kill();
    let _ = process.wait();
    eprintln!("  zrok   : stopped");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cfg = Config::parse_from(normalized_args());

    let token = cfg.password.clone().unwrap_or_else(|| generate_token(16));
    let pin = resolve_pin(cfg.pin.clone())?;
    let working_dir = resolve_working_dir(cfg.cwd.clone())?;

    let state = AppState {
        password: token.clone(),
        pin: Some(pin),
        failed_logins: Mutex::new(FailedLoginTracker::new(3, Duration::from_secs(300))),
        sessions: Mutex::new(server::SessionStore::new(Duration::from_secs(1800))),
        access_locked: Mutex::new(false),
        terminals: Mutex::new(TerminalManager::new(8)),
        default_shell: cfg.shell_path(),
        root_dir: working_dir.clone(),
        scrollback: cfg.scrollback,
        usage: Mutex::new(server::UsageTracker::new()),
    };

    state.terminals.lock().unwrap().create(
        "main".to_string(),
        working_dir.clone(),
        cfg.shell_path(),
        cfg.scrollback,
    )?;

    let app = server::router(state);
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

    let mut zrok_child = if cfg.zrok {
        println!("  zrok   : starting public share on port {}", cfg.port);
        Some(spawn_zrok(cfg.port)?)
    } else {
        None
    };

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
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

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.recv().await;
        })
        .await?;

    stop_zrok_child(&mut zrok_child);
    Ok(())
}
