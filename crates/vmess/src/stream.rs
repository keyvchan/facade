use std::{io, net::SocketAddr, task::Poll};

use tokio::{
    io::AsyncWrite,
    net::{TcpStream, ToSocketAddrs},
};

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

    pub fn buffer_size(&self) -> usize {
        1 << 14
    }
}

impl AsyncWrite for VMESSStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // the default crypto method is none, so we can just pass the data through

        let mut buf = buf.to_vec();

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Other,
            "VMESSStream::poll_flush not implemented",
        )))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Other,
            "VMESSStream::poll_shutdown not implemented",
        )))
    }
}
