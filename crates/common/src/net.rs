use std::{
    fmt::{Display, Formatter},
    net::SocketAddr,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServerAddr {
    SocketAddr(SocketAddr),
    DomainName(String, u16),
}

impl Display for ServerAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerAddr::SocketAddr(addr) => write!(f, "{}", addr),
            ServerAddr::DomainName(domain, port) => write!(f, "{}:{}", domain, port),
        }
    }
}
