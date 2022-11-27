pub mod stream;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClientRequest {
    pub auth: [u8; 16],
    pub command: Command,
    pub data: Vec<u8>,
}

impl ClientRequest {
    pub fn new(auth: [u8; 16], command: Command, data: Vec<u8>) -> Self {
        Self {
            auth,
            command,
            data,
        }
    }
}

pub enum VMESSOptions {
    S = 0x01, // default

    #[deprecated]
    R = 0x02, // deprecated in 2.23+

    M = 0x04, // metadata obfuscation
    P = 0x08, // padding
    A = 0x10, // authentication
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Encryption {
    AES128CFB = 0x01,
    AES128GCM = 0x03,
    CHACHA20POLY1305 = 0x04,
    NONE = 0x05,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CMD {
    TCP = 0x01,
    UDP = 0x02,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AddressType {
    IPv4 = 0x01,
    Domain = 0x02,
    IPv6 = 0x03,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Command {
    pub version: u8,
    pub data_encryption_iv: [u8; 16],  // random bytes
    pub data_encryption_key: [u8; 16], // random bytes
    pub v: u8,                         // random byte
    pub opt: u8,                       // random byte
    pub p: [u8; 4],                    // padding
    pub encryption: Encryption,
    pub cmd: CMD,
    pub port: [u8; 2], // big endian
    pub address_type: AddressType,
    pub address: Vec<u8>, // variable length depending on address_type
    pub fnv1a_hash: [u8; 4],
}
