use crate::SocksVersion;

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct AuthResponse {
    pub(crate) version: SocksVersion,
    pub(crate) method: AuthMethod,
}

impl AuthResponse {
    pub(crate) fn new(version: SocksVersion, method: AuthMethod) -> Self {
        Self { version, method }
    }

    pub(crate) fn to_bytes(self) -> [u8; 2] {
        [self.version as u8, self.method as u8]
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
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
