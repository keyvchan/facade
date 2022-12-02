pub mod aead;
pub mod protocol;
pub mod stream;

pub enum VMESSOptions {
    S = 0x01, // default

    #[deprecated]
    R = 0x02, // deprecated in 2.23+

    M = 0x04, // metadata obfuscation
    P = 0x08, // padding
    A = 0x10, // authentication
}
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub enum Encryption {
    AES128CFB = 0x01,
    AES128GCM = 0x03,
    CHACHA20POLY1305 = 0x04,
    #[default]
    NONE = 0x05,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub enum CMD {
    #[default]
    TCP = 0x01,
    UDP = 0x02,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub enum AddressType {
    #[default]
    IPv4 = 0x01,
    Domain = 0x02,
    IPv6 = 0x03,
}
