#![feature(allocator_api)]
mod auth;
mod client;
mod server;
mod socks5;

pub use server::SocksServer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Version {
    Socks4 = 4,
    Socks5 = 5,
}

impl Default for Version {
    fn default() -> Self {
        Self::Socks5
    }
}

impl From<u8> for Version {
    fn from(version: u8) -> Self {
        match version {
            4 => Self::Socks4,
            5 => Self::Socks5,
            _ => panic!("Invalid version: {}", version),
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum SocksCommand {
    Connect = 1,
    Bind = 2,
    UdpAssociate = 3,
}

impl Default for SocksCommand {
    fn default() -> Self {
        Self::Connect
    }
}

impl From<u8> for SocksCommand {
    fn from(command: u8) -> Self {
        match command {
            1 => Self::Connect,
            2 => Self::Bind,
            3 => Self::UdpAssociate,
            _ => panic!("Invalid command: {}", command),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AddressType {
    Ipv4 = 0x01,
    DomainName = 0x03,
    Ipv6 = 0x04,
}

impl Default for AddressType {
    fn default() -> Self {
        Self::Ipv4
    }
}

impl From<u8> for AddressType {
    fn from(address_type: u8) -> Self {
        match address_type {
            1 => Self::Ipv4,
            3 => Self::DomainName,
            4 => Self::Ipv6,
            _ => panic!("Invalid address type: {}", address_type),
        }
    }
}
