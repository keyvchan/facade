use log::{error, info, warn};
use std::io::Result;
use tokio::net::TcpListener;

use crate::{client::SocksClient, AddressType, SocksVersion};

pub struct SocksServer {
    pub listener: TcpListener,
}

impl SocksServer {
    pub async fn new(addr: &str) -> Result<Self> {
        info!("Starting socks server on {}", addr);
        Ok(Self {
            listener: TcpListener::bind(addr).await?,
        })
    }

    pub async fn serve(&mut self) -> Result<()> {
        info!("Serving socks server");
        loop {
            let (stream, client_addr) = self.listener.accept().await?;
            info!("Accepted connection from {}", client_addr);
            tokio::spawn(async move {
                let mut client = SocksClient::new(stream, SocksVersion::Socks5).await;
                match client.init().await {
                    Ok(_) => {}
                    Err(_) => {
                        error!("Failed to initialize client");
                        // shutdown
                        if let Err(e) = client.shutdown().await {
                            warn!("Failed to shutdown client: {}", e);
                        };
                    }
                }
            });
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
#[allow(dead_code)]
pub enum Reply {
    Succeeded = 0,
    GeneralFailure = 1,
    ConnectionNotAllowed = 2,
    NetworkUnreachable = 3,
    HostUnreachable = 4,
    ConnectionRefused = 5,
    TTLExpired = 6,
    CommandNotSupported = 7,
    AddressTypeNotSupported = 8,
}

impl Default for Reply {
    fn default() -> Self {
        Self::Succeeded
    }
}

#[derive(Debug, Clone, Default)]
pub struct ServerResponse {
    pub version: SocksVersion,
    pub reply: Reply,
    pub reserved: u8,
    pub address_type: AddressType,
    pub address: Vec<u8>,
    pub port: u16,
}

impl ServerResponse {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 4];
        buf[0] = self.version as u8;
        buf[1] = self.reply as u8;
        buf[2] = self.reserved;
        buf[3] = self.address_type as u8;
        buf.extend(self.address.clone());
        buf.extend(self.port.to_be_bytes().to_vec());
        buf
    }
}
