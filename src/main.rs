mod config;
mod session;
mod server;
mod assets;

use clap::Parser;
use config::Config;

#[tokio::main]
async fn main() {
    let cfg = Config::parse();
    println!("Listening on port {} with shell {}", cfg.port, cfg.shell_path());
}
