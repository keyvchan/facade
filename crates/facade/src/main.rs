mod config;

use tracing::debug;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = tracing_subscriber::fmt()
        .with_file(true)
        .with_env_filter(EnvFilter::from_default_env())
        .with_line_number(true)
        .with_target(true)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    debug!("Logging works!");

    // load config

    let mut socks_server = socks::SocksServer::new("127.0.0.1:1080").await?;
    socks_server.serve().await?;

    Ok(())
}
