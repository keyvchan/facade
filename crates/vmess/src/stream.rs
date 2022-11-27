use std::{io, net::SocketAddr};

use tokio::net::{TcpStream, ToSocketAddrs};

pub struct VMESSStream {
    pub stream: TcpStream,
}

impl VMESSStream {
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    pub async fn connect<A>(addr: A) -> io::Result<VMESSStream>
    where
        A: ToSocketAddrs,
    {
        let stream = TcpStream::connect(addr).await?;
        Ok(VMESSStream { stream })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }
}
