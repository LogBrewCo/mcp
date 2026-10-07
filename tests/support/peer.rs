//! Bounded HTTP/2 frames over certificate-verified, ALPN-negotiated TLS.

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use rustls::pki_types::{ServerName, pem::PemObject as _};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    time::timeout,
};

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Stream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

/// Connect with the fixture certificate and optional ALPN protocol.
///
/// # Errors
/// Propagates certificate, root-store, TLS configuration, TCP connection,
/// server-name and TLS negotiation failures, including the negotiation timeout.
pub async fn tls(address: SocketAddr, pem: &[u8], protocol: Option<&[u8]>) -> TestResult<Stream> {
    let certificate = rustls::pki_types::CertificateDer::from_pem_slice(pem)?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate)?;
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = protocol.map(<[u8]>::to_vec).into_iter().collect();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let stream = tokio::net::TcpStream::connect(address).await?;
    Ok(timeout(
        Duration::from_secs(2),
        connector.connect(ServerName::try_from("localhost")?, stream),
    )
    .await??)
}

pub struct Frame {
    pub kind: u8,
    pub flags: u8,
    pub stream: u32,
    pub payload: Vec<u8>,
}

pub struct Peer<S = Stream>(S);

impl Peer {
    /// Send the HTTP/2 preface and optionally exchange fixture SETTINGS.
    ///
    /// # Errors
    /// Rejects missing HTTP/2 ALPN or the expected server SETTINGS and propagates
    /// bounded preface/frame transport failures or deadlines.
    pub async fn connect(mut stream: Stream, settings: bool) -> TestResult<Self> {
        if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
            return Err(io::Error::other("HTTP/2 ALPN not negotiated").into());
        }
        timeout(
            Duration::from_secs(2),
            stream.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
        )
        .await??;
        let mut peer = Self::new(stream);
        if settings {
            peer.send(0, 4, 0, &[]).await?;
        }
        let first = timeout(Duration::from_secs(2), peer.next()).await??;
        if !first.is_some_and(|frame| frame.kind == 4 && frame.flags == 0 && frame.stream == 0) {
            return Err(io::Error::other("missing server SETTINGS").into());
        }
        if settings {
            peer.send(0, 4, 1, &[]).await?;
        }
        Ok(peer)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Peer<S> {
    pub const fn new(stream: S) -> Self {
        Self(stream)
    }

    /// Send one frame under the fixture payload, stream-ID and write bounds.
    ///
    /// # Errors
    /// Rejects an oversized payload or stream ID and propagates length conversion,
    /// write, flush and two-second deadline failures.
    pub async fn send(
        &mut self,
        stream: u32,
        kind: u8,
        flags: u8,
        payload: &[u8],
    ) -> TestResult<()> {
        if payload.len() > 16 << 10_i32 || stream > 0x7fff_ffff {
            return Err(io::Error::other("frame exceeds test bound").into());
        }
        let [_, high, middle, low] = u32::try_from(payload.len())?.to_be_bytes();
        let [a, b, c, d] = stream.to_be_bytes();
        timeout(Duration::from_secs(2), async {
            self.0
                .write_all(&[high, middle, low, kind, flags, a, b, c, d])
                .await?;
            self.0.write_all(payload).await?;
            self.0.flush().await
        })
        .await??;
        Ok(())
    }

    /// Read one bounded frame, treating a closed or reset peer as the end of input.
    ///
    /// # Errors
    /// Rejects a payload length above 16 KiB and propagates other header or
    /// payload read failures.
    pub async fn next(&mut self) -> TestResult<Option<Frame>> {
        let mut header = [0; 9];
        match self.0.read_exact(&mut header).await {
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        }
        let [high, middle, low, kind, flags, a, b, c, d] = header;
        let length =
            (usize::from(high) << 16_i32) | (usize::from(middle) << 8_i32) | usize::from(low);
        if length > 16 << 10_i32 {
            return Err(io::Error::other("received frame exceeds test bound").into());
        }
        let mut payload = vec![0; length];
        let _: usize = self.0.read_exact(&mut payload).await?;
        Ok(Some(Frame {
            kind,
            flags,
            stream: u32::from_be_bytes([a, b, c, d]) & 0x7fff_ffff,
            payload,
        }))
    }

    /// Send the fixture PING and wait for its matching acknowledgement.
    ///
    /// # Errors
    /// Propagates send, frame-read, premature closure and frame-count failures.
    pub async fn probe(&mut self) -> TestResult<()> {
        self.send(0, 6, 0, b"TESTPING").await?;
        probe_frames(self).await
    }
}

/// Find the fixture PING acknowledgement within sixteen control frames.
///
/// # Errors
/// Propagates frame-read failures and rejects premature closure or an unmatched
/// acknowledgement beyond the frame-count bound.
async fn probe_frames<S>(peer: &mut Peer<S>) -> TestResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    for _ in 0_i32..16_i32 {
        let frame = peer
            .next()
            .await?
            .ok_or_else(|| io::Error::other("responsive peer closed"))?;
        if frame.kind == 6 && frame.flags == 1 && frame.stream == 0 && frame.payload == b"TESTPING"
        {
            return Ok(());
        }
    }
    Err(io::Error::other("control frame count exceeds test bound").into())
}
