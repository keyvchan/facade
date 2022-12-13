mod config;

use tracing::{debug, Level};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = tracing_subscriber::fmt()
        .with_file(true)
        .with_max_level(Level::TRACE)
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
