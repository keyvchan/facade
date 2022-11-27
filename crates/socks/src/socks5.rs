use std::{
    fmt::Display,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use common::proxy::AutoProxyClientStream;
use log::{debug, trace};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use vmess::stream::VMESSStream;

use crate::{
    auth::{AuthMethod, HandshakeResponse},
    relay::copy_bidirectional,
    server::Reply,
    AddressType, Version,
};

pub struct Socks5TcpHandler {}

impl Socks5TcpHandler {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn handle_socks5_client(
        &mut self,
        mut stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> io::Result<()> {
        // 1. handshake
        let mut handshake_request = HandshakeRequest::new();
        handshake_request.read_from(&mut stream).await?;

        // here we have the handshake request
        trace!("Handshake request: {:?}", handshake_request);

        // 2. auth
        self.handle_auth(&mut stream, &handshake_request).await?;

        // here we have the request
        // 3. request
        let header = TcpRequestHeader::from_stream(&mut stream).await?;

        trace!("Request header: {:?}", header);

        // respond to the client
        match header.command {
            Command::Connect => {
                self.handle_tcp_connect(&mut stream, header.address).await?;
            }
            Command::Bind => {
                todo!()
            }
            Command::UdpAssociate => {
                todo!()
            }
        }

        Ok(())
    }

    pub async fn handle_tcp_connect(
        &mut self,
        stream: &mut TcpStream,
        target: Address,
    ) -> io::Result<()> {
        let outbound = "DIRECT";

        let mut target = match outbound {
            "DIRECT" => {
                AutoProxyClientStream::Direct(TcpStream::connect(target.to_string()).await?)
            }
            "vmess" => {
                AutoProxyClientStream::VMESS(VMESSStream::connect(target.to_string()).await?)
            }
            _ => {
                todo!()
            }
        };
        let response =
            TcpResponseHeader::new(Reply::Succeeded, Address::SocketAddr(target.local_addr()?));
        stream.write_all(&response.to_bytes()).await?;

        match copy_bidirectional(stream, &mut target).await {
            Ok(_) => {
                debug!("TCP connection closed");
            }
            Err(e) => {
                debug!("TCP connection closed with error: {}", e);
            }
        }

        Ok(())
    }

    pub async fn handle_auth(
        &mut self,
        stream: &mut TcpStream,
        handshake_request: &HandshakeRequest,
    ) -> io::Result<()> {
        debug!("Handling auth");
        let handshake_response = HandshakeResponse {
            version: Version::Socks5,
            method: AuthMethod::NoAuth,
        };
        trace!("Handshake response: {}", handshake_response);
        stream.write_all(&handshake_response.to_bytes()).await?;
        Ok(())
    }
}

/// client handshake request
#[derive(Debug, Clone)]
pub struct HandshakeRequest {
    version: Version,
    nmethods: u8,
    methods: Vec<u8>,
}

impl HandshakeRequest {
    fn new() -> Self {
        Self {
            version: Version::Socks5,
            nmethods: 0,
            methods: Vec::new(),
        }
    }

    pub async fn read_from(&mut self, stream: &mut TcpStream) -> io::Result<()> {
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        self.version = Version::from(buf[0]);
        if self.version != Version::Socks5 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid version: {:?}", self.version),
            ));
        }
        self.nmethods = buf[1];
        self.methods = vec![0u8; self.nmethods as usize];
        stream.read_exact(&mut self.methods).await?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
enum Command {
    Connect,
    Bind,
    UdpAssociate,
}

impl Display for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::Connect => write!(f, "CONNECT"),
            Command::Bind => write!(f, "BIND"),
            Command::UdpAssociate => write!(f, "UDP_ASSOCIATE"),
        }
    }
}

impl From<u8> for Command {
    fn from(b: u8) -> Self {
        match b {
            0x01 => Command::Connect,
            0x02 => Command::Bind,
            0x03 => Command::UdpAssociate,
            _ => panic!("Invalid command: {}", b),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Address {
    SocketAddr(SocketAddr),
    DomainName(String, u16),
}

impl Address {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Address::SocketAddr(addr) => match addr {
                SocketAddr::V4(addr) => {
                    buf.push(AddressType::Ipv4 as u8);
                    buf.extend_from_slice(&addr.ip().octets());
                    buf.extend_from_slice(&addr.port().to_be_bytes());
                }
                SocketAddr::V6(addr) => {
                    buf.push(AddressType::Ipv6 as u8);
                    buf.extend_from_slice(&addr.ip().octets());
                    buf.extend_from_slice(&addr.port().to_be_bytes());
                }
            },
            Address::DomainName(domain, port) => {
                buf.push(AddressType::DomainName as u8);
                buf.push(domain.len() as u8);
                buf.extend_from_slice(domain.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
        buf
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::SocketAddr(addr) => write!(f, "{}", addr),
            Address::DomainName(domain, port) => write!(f, "{}:{}", domain, port),
        }
    }
}
/// tcp request header after auth
#[derive(Debug, Clone)]
pub struct TcpRequestHeader {
    command: Command,
    address: Address,
}

impl Display for TcpRequestHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.command, self.address)
    }
}

impl TcpRequestHeader {
    pub async fn from_stream(stream: &mut TcpStream) -> io::Result<TcpRequestHeader> {
        // we have the request
        let mut req_buf = [0u8; 4];
        stream.read_exact(&mut req_buf).await?;

        let version = Version::from(req_buf[0]);
        if version != Version::Socks5 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid version: {:?}", version),
            ));
        }

        let command = Command::from(req_buf[1]);

        let reserved = req_buf[2];

        let address_type = AddressType::from(req_buf[3]);

        // read address by address type
        let address = match address_type {
            AddressType::Ipv4 => {
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await?;

                let port = stream.read_u16().await?;

                Address::SocketAddr(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(buf), port)))
            }
            AddressType::Ipv6 => {
                let mut buf = [0u8; 16];
                stream.read_exact(&mut buf).await?;

                let port = stream.read_u16().await?;
                Address::SocketAddr(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(buf),
                    port,
                    0,
                    0,
                )))
            }
            AddressType::DomainName => {
                let mut buf = [0u8; 1];
                stream.read_exact(&mut buf).await?;
                let len = buf[0] as usize;
                let mut buf = vec![0u8; len];
                stream.read_exact(&mut buf).await?;
                let domain = match String::from_utf8(buf) {
                    Ok(domain) => domain,
                    Err(e) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Invalid domain name: {}", e),
                        ))
                    }
                };
                let port = stream.read_u16().await?;
                Address::DomainName(domain, port)
            }
        };

        Ok(TcpRequestHeader { command, address })
    }
}

pub struct TcpResponseHeader {
    reply: Reply,
    address: Address,
}

impl TcpResponseHeader {
    pub fn new(reply: Reply, address: Address) -> Self {
        Self { reply, address }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(Version::Socks5 as u8);
        buf.push(self.reply as u8);
        buf.push(0x00);
        buf.extend_from_slice(&self.address.to_bytes());
        buf
    }
}

impl Display for TcpResponseHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.reply, self.address)
    }
}
