use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub enum NetworkAddress {
    SocketAddr(SocketAddr),
    DomainName(String, u16),
}

impl NetworkAddress {
    pub fn address(&self) -> Vec<u8> {
        match self {
            NetworkAddress::SocketAddr(addr) => {
                let mut buf = Vec::new();
                match addr {
                    SocketAddr::V4(addr) => {
                        buf.extend_from_slice(&addr.ip().octets());
                    }
                    SocketAddr::V6(addr) => {
                        buf.extend_from_slice(&addr.ip().octets());
                    }
                }
                buf
            }
            NetworkAddress::DomainName(domain, _) => {
                let mut buf = Vec::new();
                buf.extend_from_slice(domain.as_bytes());
                buf
            }
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            NetworkAddress::SocketAddr(addr) => addr.port(),
            NetworkAddress::DomainName(_, port) => *port,
        }
    }
}
