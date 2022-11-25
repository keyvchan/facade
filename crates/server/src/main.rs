use flexi_logger::Logger;
use log::debug;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    Logger::try_with_str("debug")?.start()?;

    debug!("Logging works!");

    let mut socks_server = socks::SocksServer::new("127.0.0.1:1080").await?;
    socks_server.serve().await;

    Ok(())
}
