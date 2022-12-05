use std::fmt::Display;
use std::hash::Hasher;
use std::pin::Pin;
use std::result::Result;
use std::task;
use std::{io, net::SocketAddr, task::Poll};

use log::{info, trace};
use md5::Digest;
use rand::Rng;
use sha2::Sha256;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::{
    io::AsyncWrite,
    net::{TcpStream, ToSocketAddrs},
};
use uuid::uuid;

use crate::aead::{AEADHeader, ID};
use crate::protocol::{RequestCommand, RequestHeader, RequestOption, RequestSecurity, VERSION};

#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct Session {
    request_body_key: [u8; 16],
    request_body_iv: [u8; 16],
    response_body_key: [u8; 16],
    response_body_iv: [u8; 16],
    response_header: u8,
}

pub struct VMESSStream {
    pub stream: TcpStream,
    pub session: Session,
}

impl VMESSStream {
    pub async fn connect<A>(addr: A) -> io::Result<VMESSStream>
    where
        A: ToSocketAddrs + Display,
    {
        info!("Connecting to {}", addr);
        let stream = TcpStream::connect(addr).await?;
        Ok(VMESSStream {
            stream,
            session: Session::default(),
        })
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
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // create a request
        let mut request = RequestHeader {
            version: VERSION,
            ..Default::default()
        };
        request.command = RequestCommand::Tcp;
        request.option = RequestOption::None;
        request.security = RequestSecurity::Zero;

        let mut random: Vec<u8> = vec![0; 33];
        let mut rng = rand::thread_rng();
        rng.fill(&mut random[..]);

        trace!("random: {:?}", random);
        let request_body_key: [u8; 16] = random[0..16]
            .to_vec()
            .try_into()
            .expect("slice with incorrect length");
        let request_body_iv: [u8; 16] = random[16..32]
            .to_vec()
            .try_into()
            .expect("slice with incorrect length");
        // calculate crc
        let mut sha = Sha256::new();

        sha.update(&random[0..16]);

        // encode request header
        let mut header_buffer = Vec::new();
        header_buffer.push(request.version);
        header_buffer.extend_from_slice(&request_body_iv);
        header_buffer.extend_from_slice(&request_body_key);
        header_buffer.push(random[32]);
        header_buffer.push(request.option as u8);

        let padding_len: u8 = rng.gen_range(0..16);
        let security = padding_len << 4 | 5_u8;
        header_buffer.push(security);
        header_buffer.push(0);
        header_buffer.push(request.command as u8);

        // write address and port

        // address is a 4 byte array
        let address: [u8; 4] = [127, 0, 0, 1];
        header_buffer.extend_from_slice(&address);
        header_buffer.extend_from_slice(&443_u16.to_be_bytes());

        // read padding
        let mut random: [u8; 16] = [0; 16];
        rng.fill(&mut random);
        header_buffer.extend_from_slice(&random[0..padding_len as usize]);

        let mut fnv = fnv::FnvHasher::default();
        fnv.write(&header_buffer);
        let hash = fnv.finish().to_be_bytes();
        header_buffer.push(hash.len() as u8);
        header_buffer.extend_from_slice(&hash);

        let uuid = uuid!("231c2fc0-f8c4-4248-b098-21f0dd78c810");
        let id = ID::new(uuid);
        let aead_header = AEADHeader::new();
        trace!("aead_header: {:?}", aead_header);

        let mut vmess_out = aead_header.seal(id, &header_buffer);
        vmess_out.extend_from_slice(buf);

        // write vmess_out

        Pin::new(&mut self.get_mut().stream).poll_write(cx, &vmess_out)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Other,
            "VMESSStream::poll_flush not implemented",
        )))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Other,
            "VMESSStream::poll_shutdown not implemented",
        )))
    }
}

impl AsyncRead for VMESSStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> task::Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}
