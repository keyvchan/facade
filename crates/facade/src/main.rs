mod config;

use log::debug;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    debug!("Logging works!");

    // load config

    let mut socks_server = socks::SocksServer::new("127.0.0.1:1080").await?;
    socks_server.serve().await?;

    Ok(())
}
