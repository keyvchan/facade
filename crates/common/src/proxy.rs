use std::{io, net::SocketAddr, pin::Pin, task};

/// Taken from shadowsocks-rust
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use vmess::stream::VMESSStream;

pub enum ProxyClientStream {
    DIRECT(TcpStream),
    VMESS(VMESSStream),
}
impl ProxyClientStream {
    /// local address of the stream client
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            ProxyClientStream::DIRECT(stream) => stream.local_addr(),
            ProxyClientStream::VMESS(stream) => stream.local_addr(),
        }
    }

    /// return the buffer size should allocated for this stream
    pub fn buffer_size(&self) -> usize {
        match self {
            ProxyClientStream::DIRECT(_) => 1 << 14,
            ProxyClientStream::VMESS(vmess_stream) => vmess_stream.buffer_size(),
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
            ProxyClientStream::DIRECT(direct_stream) => Pin::new(direct_stream).poll_write(cx, buf),
            ProxyClientStream::VMESS(vmess_stream) => Pin::new(vmess_stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        match self.get_mut() {
            ProxyClientStream::DIRECT(direct_stream) => Pin::new(direct_stream).poll_flush(cx),
            ProxyClientStream::VMESS(vmess_stream) => {
                todo!()
            }
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        match self.get_mut() {
            ProxyClientStream::DIRECT(direct_stream) => Pin::new(direct_stream).poll_shutdown(cx),
            ProxyClientStream::VMESS(vmess_stream) => {
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
            ProxyClientStream::DIRECT(direct_stream) => Pin::new(direct_stream).poll_read(cx, buf),
            ProxyClientStream::VMESS(vmess_stream) => {
                todo!()
            }
        }
    }
}
