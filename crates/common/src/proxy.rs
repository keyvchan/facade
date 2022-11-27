use std::{io, net::SocketAddr, pin::Pin, task};

/// Taken from shadowsocks-rust
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use vmess::stream::VMESSStream;

pub enum AutoProxyClientStream {
    Direct(TcpStream),
    VMESS(VMESSStream),
}
impl AutoProxyClientStream {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            AutoProxyClientStream::Direct(stream) => stream.local_addr(),
            AutoProxyClientStream::VMESS(stream) => stream.local_addr(),
        }
    }
}

impl AsyncWrite for AutoProxyClientStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<io::Result<usize>> {
        match self.get_mut() {
            AutoProxyClientStream::Direct(stream) => Pin::new(stream).poll_write(cx, buf),
            AutoProxyClientStream::VMESS(stream) => {
                todo!()
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        match self.get_mut() {
            AutoProxyClientStream::Direct(stream) => Pin::new(stream).poll_flush(cx),
            AutoProxyClientStream::VMESS(stream) => {
                todo!()
            }
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        match self.get_mut() {
            AutoProxyClientStream::Direct(stream) => Pin::new(stream).poll_shutdown(cx),
            AutoProxyClientStream::VMESS(stream) => {
                todo!()
            }
        }
    }
}

impl AsyncRead for AutoProxyClientStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        match self.get_mut() {
            AutoProxyClientStream::Direct(stream) => Pin::new(stream).poll_read(cx, buf),
            AutoProxyClientStream::VMESS(stream) => {
                todo!()
            }
        }
    }
}
