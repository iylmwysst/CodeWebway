mod assets;
mod config;
mod server;
mod session;

use clap::Parser;
use config::Config;
use server::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cfg = Config::parse();

    if cfg.password.is_empty() {
        eprintln!("Error: --password is required and cannot be empty");
        std::process::exit(1);
    }

    let session = session::spawn_session(&cfg.shell_path(), cfg.scrollback)?;

    let state = AppState {
        session,
        password: cfg.password.clone(),
    };

    let app = server::router(state);
    let addr = format!("0.0.0.0:{}", cfg.port);
    println!("rust-webtty listening on http://{}", addr);
    println!("Connect: http://localhost:{}/?token={}", cfg.port, cfg.password);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
