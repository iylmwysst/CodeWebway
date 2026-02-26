mod assets;
mod config;
mod server;
mod session;

use clap::Parser;
use config::Config;
use rand::distributions::Alphanumeric;
use rand::Rng;
use server::AppState;

fn generate_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cfg = Config::parse();

    let token = cfg.password.clone().unwrap_or_else(generate_token);

    let session = session::spawn_session(&cfg.shell_path(), cfg.scrollback)?;

    let state = AppState {
        session,
        password: token.clone(),
    };

    let app = server::router(state);
    let addr = format!("0.0.0.0:{}", cfg.port);
    let url = format!("http://localhost:{}/?token={}", cfg.port, token);

    println!();
    println!("  rust-webtty  ");
    println!("  ─────────────────────────────────");
    println!("  Token  : {}", token);
    println!("  Open   : {}", url);
    println!("  ─────────────────────────────────");
    println!();

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
