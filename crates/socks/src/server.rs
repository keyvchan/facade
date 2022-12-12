use log::{error, info, warn};
use std::{
    fmt::{Display, Formatter},
    io::{self, ErrorKind, Result},
    net::SocketAddr,
};
use tokio::net::{TcpListener, TcpStream};

use crate::socks5::Socks5TcpHandler;

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
            let (stream, peer_addr) = self.listener.accept().await?;
            info!("Accepted connection from {}", peer_addr);
            tokio::spawn(async move {
                if let Err(e) = SocksServer::handle_tcp_client(stream, peer_addr).await {
                    error!("Error handling client: {}", e);
                }
            });
        }
    }

    pub async fn handle_tcp_client(stream: TcpStream, peer: SocketAddr) -> io::Result<()> {
        let mut version_buf = [0u8; 1];
        let n = stream.peek(&mut version_buf).await?;
        if n == 0 {
            return Err(io::Error::new(ErrorKind::UnexpectedEof, "EOF"));
        }

        match version_buf[0] {
            0x04 => {
                warn!("Socks4 is not supported");
                Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "Socks4 is not supported",
                ))
            }
            0x05 => {
                let mut handler = Socks5TcpHandler::new();
                handler.handle_socks5_client(stream, peer).await
            }
            version => {
                warn!("Unknown socks version: {}", version);
                Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!("Unknown socks version: {version}"),
                ))
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
#[allow(dead_code)]
pub enum Reply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TTLExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

impl Default for Reply {
    fn default() -> Self {
        Self::Succeeded
    }
}

impl Display for Reply {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Succeeded => write!(f, "succeeded"),
            Self::GeneralFailure => write!(f, "general failure"),
            Self::ConnectionNotAllowed => write!(f, "connection not allowed"),
            Self::NetworkUnreachable => write!(f, "network unreachable"),
            Self::HostUnreachable => write!(f, "host unreachable"),
            Self::ConnectionRefused => write!(f, "connection refused"),
            Self::TTLExpired => write!(f, "ttl expired"),
            Self::CommandNotSupported => write!(f, "command not supported"),
            Self::AddressTypeNotSupported => write!(f, "address type not supported"),
        }
    }
}
