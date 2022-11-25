use bincode::{DefaultOptions, Options};
use log::{debug, info};
use std::io::{Error, ErrorKind::InvalidData, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    auth::AuthResponse,
    server::{Reply::Succeeded, ServerResponse},
    AddressType, SocksCommand, SocksVersion,
};

pub struct SocksClient {
    stream: TcpStream,
    version: SocksVersion,
    auth_nmethods: u8,
}

#[derive(Debug, Clone)]
struct ClientRequest {
    version: SocksVersion,
    command: SocksCommand,
    reserved: u8,
    address_type: AddressType,
    address: String,
    port: u16,
}

impl ClientRequest {
    pub async fn from_stream(stream: &mut TcpStream) -> Result<ClientRequest> {
        // we have the request
        let mut req_buf = [0u8; 4];
        stream.read_exact(&mut req_buf).await?;

        debug!("Request: {:?}", req_buf);

        let version = SocksVersion::from(req_buf[0]);

        let command = SocksCommand::from(req_buf[1]);

        let reserved = req_buf[2];

        let address_type = AddressType::from(req_buf[3]);

        // read address by address type
        let address = match address_type {
            AddressType::Ipv4 => {
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await?;
                format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3])
            }
            AddressType::Ipv6 => {
                let mut buf = [0u8; 16];
                stream.read_exact(&mut buf).await?;
                format!(
                    "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]
                )
            }
            AddressType::DomainName => {
                let mut buf = [0u8; 1];
                stream.read_exact(&mut buf).await?;
                let len = buf[0] as usize;
                let mut buf = vec![0u8; len];
                stream.read_exact(&mut buf).await?;
                match String::from_utf8(buf) {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(Error::new(
                            InvalidData,
                            format!("Invalid domain name: {}", e),
                        ));
                    }
                }
            }
        };

        // read port
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        let port = u16::from_be_bytes(buf);

        Ok(ClientRequest {
            version,
            command,
            reserved,
            address_type,
            address,
            port,
        })
    }
}

impl SocksClient {
    pub async fn new(stream: TcpStream, version: SocksVersion) -> Self {
        Self {
            stream,
            version,
            auth_nmethods: 0,
        }
    }

    pub async fn init(&mut self) -> Result<()> {
        info!("Initializing client");

        // init bincode
        let bincode = DefaultOptions::new();
        bincode.with_varint_encoding();

        // read the first byte to determine the version
        let version = self.stream.read_u8().await?;
        self.version = match version {
            4 => SocksVersion::Socks4,
            5 => SocksVersion::Socks5,
            _ => {
                info!("Invalid version: {}", version);
                return Err(Error::new(InvalidData, "Invalid version"));
            }
        };
        self.auth_nmethods = self.stream.read_u8().await?;
        match self.version {
            SocksVersion::Socks4 => {
                todo!()
            }
            SocksVersion::Socks5 => {
                self.authenticate().await?;
                self.handle_request().await?;
            }
        }
        Ok(())
    }

    pub async fn authenticate(&mut self) -> Result<()> {
        info!("Authenticating client");

        // read the methods
        for _ in 0..self.auth_nmethods {
            _ = self.stream.read_u8().await?;
        }
        // the version default is 5
        let response = AuthResponse::default();
        debug!("Sending response: {:?}", response.to_bytes());
        self.stream.write_all(&response.to_bytes()).await?;

        Ok(())
    }

    pub async fn handle_request(&mut self) -> Result<()> {
        info!("Handling request");

        let request = ClientRequest::from_stream(&mut self.stream).await?;
        debug!("Request: {:?}", request);

        // respond to the client
        match request.command {
            SocksCommand::Connect => {
                let address = format!("{}:{}", request.address, request.port);
                info!("Connecting to {:?}", address);

                let mut target = TcpStream::connect(&address).await?;
                info!("Connected to {:?}", address);

                let response = ServerResponse {
                    version: self.version,
                    reply: Succeeded,
                    reserved: 0,
                    address_type: request.address_type,
                    address: vec![0, 0, 0, 0],
                    port: 0,
                };
                self.stream.write_all(&response.to_bytes()).await?;

                match tokio::io::copy_bidirectional(&mut self.stream, &mut target).await {
                    Ok(_) => {
                        info!("Connection closed");
                    }
                    Err(e) => {
                        info!("Connection closed with error: {}", e);
                    }
                }
            }
            SocksCommand::Bind => {}
            SocksCommand::UdpAssociate => {}
        }

        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.stream.shutdown().await?;
        Ok(())
    }
}
