pub(crate) const VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
#[allow(dead_code)]
pub(crate) enum RequestCommand {
    #[default]
    Tcp = 0x01,
    Udp = 0x02,
    Mux = 0x03,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
#[allow(dead_code)]
pub(crate) enum RequestOption {
    None = 0x00,
    #[default]
    ChunkStream = 0x01,
    ConnectionReuse = 0x02,
    ChunkMasking = 0x04,
    GlobalPadding = 0x08,
    AuthenticatedLength = 0x10,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
#[allow(dead_code)]
pub(crate) enum RequestSecurity {
    Unknown = 0,
    Legacy = 1,
    Auto = 2,
    AES128GCM = 3,
    CHACHA20POLY1305 = 4,
    #[default]
    None = 5,
    Zero = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub(crate) struct RequestHeader {
    pub(crate) version: u8,
    pub(crate) command: RequestCommand,
    pub(crate) option: RequestOption,
    pub(crate) security: RequestSecurity,
    pub(crate) port: u16,
    pub(crate) address: [u8; 16],
}

impl RequestHeader {
    #[allow(dead_code)]
    fn encode(&self, buf: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(32);
        v.push(self.version);
        v.push(self.command as u8);
        v.push(self.option as u8);
        v.push(self.security as u8);
        v.extend_from_slice(&self.port.to_be_bytes());
        v.extend_from_slice(&self.address);
        v.extend_from_slice(buf);
        v
    }
}
