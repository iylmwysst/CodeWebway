mod assets;
mod config;
mod server;
mod session;

use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use config::Config;
use rand::distributions::Alphanumeric;
use rand::Rng;
use server::AppState;
use server::FailedLoginTracker;

fn generate_token(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn generate_session_cookie() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(48)
        .map(char::from)
        .collect()
}

fn normalized_args() -> Vec<String> {
    std::env::args()
        .map(|arg| if arg == "-zrok" { "--zrok".to_string() } else { arg })
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cfg = Config::parse_from(normalized_args());

    let token = cfg.password.clone().unwrap_or_else(|| generate_token(16));

    let session = session::spawn_session(&cfg.shell_path(), cfg.scrollback)?;

    let state = AppState {
        session,
        password: token.clone(),
        session_cookie: generate_session_cookie(),
        failed_logins: Mutex::new(FailedLoginTracker::new(3, Duration::from_secs(300))),
    };

    let app = server::router(state);
    let addr = format!("0.0.0.0:{}", cfg.port);
    let url = format!("http://localhost:{}", cfg.port);

    println!();
    println!("  rust-webtty  ");
    println!("  ─────────────────────────────────");
    println!("  Token  : {}", token);
    println!("  Open   : {}", url);
    println!("  ─────────────────────────────────");
    println!();

    let mut zrok_child = if cfg.zrok {
        println!("  zrok   : starting public share on port {}", cfg.port);
        Some(spawn_zrok(cfg.port)?)
    } else {
        None
    };

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;

    if let Some(mut child) = zrok_child.take() {
        let _ = child.kill();
    }
    Ok(())
}
