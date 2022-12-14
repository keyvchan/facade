use std::fmt::Display;
use std::pin::Pin;
use std::result::Result;
use std::task;
use std::{io, net::SocketAddr, task::Poll};

use md5::Digest;
use rand::{Rng, RngCore};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio::{
    io::AsyncWrite,
    net::{TcpStream, ToSocketAddrs},
};
use tracing::{info, trace};
use types::net::NetworkAddress;
use uuid::uuid;

use crate::aead::{AEADHeader, ID};
use crate::crypto::fnv::fnv;
use crate::protocol::{RequestCommand, RequestHeader, RequestOption, RequestSecurity, VERSION};

#[derive(Debug)]
#[allow(dead_code)]
pub struct ClientSession {
    address: NetworkAddress,
    request_body_key: [u8; 16],
    request_body_iv: [u8; 16],
    response_body_key: [u8; 16],
    response_body_iv: [u8; 16],
    response_header: u8,
}

impl ClientSession {
    fn new(address: NetworkAddress) -> Self {
        let mut rng = rand::thread_rng();
        let mut request_body_key = [0u8; 16];
        let mut request_body_iv = [0u8; 16];
        let mut response_body_key = [0u8; 16];
        let mut response_body_iv = [0u8; 16];
        rng.fill_bytes(&mut request_body_key);
        rng.fill_bytes(&mut request_body_iv);
        rng.fill_bytes(&mut response_body_key);
        rng.fill_bytes(&mut response_body_iv);

        ClientSession {
            address,
            request_body_key,
            request_body_iv,
            response_body_key,
            response_body_iv,
            response_header: 0,
        }
    }
}

pub struct VMESSStream {
    pub stream: TcpStream,
    pub session: ClientSession,
}

impl VMESSStream {
    pub async fn connect<A>(addr: A, address: NetworkAddress) -> io::Result<VMESSStream>
    where
        A: ToSocketAddrs + Display,
    {
        info!("Connecting to {}", addr);
        let stream = TcpStream::connect(addr).await?;
        Ok(VMESSStream {
            stream,
            session: ClientSession::new(address),
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

        let network_address = self.session.address.clone();

        // NOTE: port first, then address
        // write address family
        header_buffer.extend_from_slice(&network_address.port().to_be_bytes());
        header_buffer.push(1_u8);
        // address is a 4 byte array
        let address: [u8; 4] = network_address
            .address()
            .try_into()
            .expect("slice with incorrect length, should be 4 bytes for ipv4 address");
        header_buffer.extend_from_slice(&address);

        // read padding
        let mut random = [0; 16];
        rng.fill(&mut random);
        header_buffer.extend_from_slice(&random[0..padding_len as usize]);

        // calculate fnv has
        let fnv_hash = fnv(&header_buffer);
        header_buffer.extend_from_slice(&fnv_hash.to_be_bytes());

        let uuid = uuid!("231c2fc0-f8c4-4248-b098-21f0dd78c810");
        let id = ID::new(uuid);
        let aead_header = AEADHeader::new();

        let mut vmess_out = aead_header.seal(id, &header_buffer);
        vmess_out.extend_from_slice(buf);

        Pin::new(&mut self.get_mut().stream).poll_write(cx, &vmess_out)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        trace!("poll_flush");
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Other,
            "VMESSStream::poll_flush not implemented",
        )))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        trace!("poll_shutdown");
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
        info!("VMESSStream::poll_read, {buf:?}");

        let mut buffer = vec![0; 1 << 14];
        let mut read_buf = ReadBuf::new(&mut buffer);

        let mut stream = unsafe { self.get_unchecked_mut() };

        println!("before poll_read");
        let result = stream.stream.read(&mut buffer);
        println!("after poll_read");
        println!("returned");
        // match result {
        //     Poll::Ready(Ok(n)) => {
        //         println!("read inside vmess stream, ready");
        //         // print the buf
        //         println!("buf: {:?}", read_buf.filled());
        //         Poll::Ready(Ok(n))
        //     }
        //     Poll::Ready(Err(e)) => {
        //         println!("read inside vmess stream, error");
        //         Poll::Ready(Err(e))
        //     }
        //     Poll::Pending => {
        //         println!("read inside vmess stream, pending");
        //         Poll::Pending
        //     }
        // }
        Poll::Ready(Ok(()))
    }
}
