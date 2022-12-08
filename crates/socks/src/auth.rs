use std::fmt::Display;

use crate::Version;

/// handshake response after auth
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct HandshakeResponse {
    pub(crate) version: Version,
    pub(crate) method: AuthMethod,
}

impl HandshakeResponse {
    pub(crate) fn to_bytes(self) -> [u8; 2] {
        [self.version as u8, self.method as u8]
    }
}

impl Display for HandshakeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AuthResponse {{ version: {:?}, method: {:?} }}",
            self.version, self.method
        )
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
#[allow(dead_code)]
pub(crate) enum AuthMethod {
    NoAuth = 0,
    GssApi = 1,
    UserPass = 2,
    Iana = 3,
    Reserved = 4,
    NoAcceptable = 255,
}

impl Default for AuthMethod {
    fn default() -> Self {
        Self::NoAuth
    }
}
