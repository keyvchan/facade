use std::{io, net::SocketAddr, pin::Pin, task};

/// Taken from shadowsocks-rust
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use vmess::stream::VMESSStream;

pub enum ProxyClientStream {
    Direct(TcpStream),
    VMESS(VMESSStream),
}
impl ProxyClientStream {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            ProxyClientStream::Direct(stream) => stream.local_addr(),
            ProxyClientStream::VMESS(stream) => stream.local_addr(),
        }
    }
}

impl AsyncWrite for ProxyClientStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<io::Result<usize>> {
        match self.get_mut() {
            ProxyClientStream::Direct(stream) => Pin::new(stream).poll_write(cx, buf),
            ProxyClientStream::VMESS(stream) => {
                todo!()
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        match self.get_mut() {
            ProxyClientStream::Direct(stream) => Pin::new(stream).poll_flush(cx),
            ProxyClientStream::VMESS(stream) => {
                todo!()
            }
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        match self.get_mut() {
            ProxyClientStream::Direct(stream) => Pin::new(stream).poll_shutdown(cx),
            ProxyClientStream::VMESS(stream) => {
                todo!()
            }
        }
    }
}

impl AsyncRead for ProxyClientStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        match self.get_mut() {
            ProxyClientStream::Direct(stream) => Pin::new(stream).poll_read(cx, buf),
            ProxyClientStream::VMESS(stream) => {
                todo!()
            }
        }
    }
}
