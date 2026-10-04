//! Observe outbound TLS lifetime and script response bytes without an HTTP parser.

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use logbrew_mcp::{
    clients::ClientAllowlist,
    upstream::{MachineCredential, Upstream, UpstreamOptions},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};
use zeroize::Zeroizing;

use super::peer::Peer;

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Stream = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;

enum Plan {
    Http {
        path: &'static str,
        headers: Vec<u8>,
        body: Option<Vec<u8>>,
    },
    Http2 {
        headers: Vec<u8>,
        body: Option<Vec<u8>>,
    },
    StalledTls(oneshot::Sender<()>),
}

struct Exchange {
    plan: Plan,
    done: oneshot::Sender<TestResult<()>>,
}

pub struct StalledHandshake {
    pub started: oneshot::Receiver<()>,
    pub closed: oneshot::Receiver<TestResult<()>>,
}

#[derive(Clone, Copy)]
enum Trust {
    Matching,
    Untrusted,
    Mismatched,
}

pub struct Raw {
    pub upstream: Upstream,
    pub handshakes: Arc<AtomicUsize>,
    pub requests: Arc<AtomicUsize>,
    sender: Option<mpsc::Sender<Exchange>>,
    task: JoinHandle<TestResult<()>>,
}

impl Drop for Raw {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Raw {
    pub fn new() -> TestResult<Self> {
        Self::build(Trust::Matching, b"http/1.1")
    }

    pub fn http2() -> TestResult<Self> {
        Self::build(Trust::Matching, b"h2")
    }

    pub fn untrusted_certificate() -> TestResult<Self> {
        Self::build(Trust::Untrusted, b"http/1.1")
    }

    pub fn mismatched_hostname() -> TestResult<Self> {
        Self::build(Trust::Mismatched, b"http/1.1")
    }

    fn build(trust: Trust, protocol: &'static [u8]) -> TestResult<Self> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let listener = tokio::net::TcpListener::from_std(listener)?;
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
        let pem = certificate.cert.pem();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from_pem_slice(pem.as_bytes())?],
            PrivateKeyDer::from_pem_slice(certificate.signing_key.serialize_pem().as_bytes())?,
        )?;
        tls.alpn_protocols = vec![protocol.to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let host = match trust {
            Trust::Matching | Trust::Untrusted => "localhost",
            Trust::Mismatched => "127.0.0.1",
        };
        let endpoint = format!("https://{host}:{}", address.port());
        let credential = || {
            MachineCredential::new(
                "synthetic-client".to_owned(),
                Zeroizing::new("SYNTHETIC_MACHINE_SECRET".to_owned()),
            )
        };
        let root = match trust {
            Trust::Untrusted => None,
            Trust::Matching | Trust::Mismatched => {
                Some(CertificateDer::from_pem_slice(pem.as_bytes())?)
            }
        };
        let upstream = Upstream::with_certificate(
            UpstreamOptions {
                introspection_endpoint: format!("{endpoint}/introspect"),
                execution_endpoint: format!("{endpoint}/execute"),
                issuer: "https://issuer.example".to_owned(),
                resource: "https://resource.example/mcp".to_owned(),
                required_scope: "mcp:read".to_owned(),
                introspection_credential: credential()?,
                execution_credential: credential()?,
            },
            root,
        )?
        .with_client_allowlist(ClientAllowlist::decode(
            br#"{"version":"1","clients":["synthetic-client"]}"#,
        )?);
        let (sender, mut receiver) = mpsc::channel::<Exchange>(1);
        let handshakes = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::clone(&handshakes);
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            while let Some(exchange) = receiver.recv().await {
                let deadline = match &exchange.plan {
                    Plan::Http { .. } | Plan::Http2 { .. } => Duration::from_secs(3),
                    Plan::StalledTls(_) => Duration::from_secs(12),
                };
                let acceptor = acceptor.clone();
                let accepted = Arc::clone(&accepted);
                let observed = Arc::clone(&observed);
                let receiving = &listener;
                let result = timeout(deadline, async move {
                    let (stream, _) = receiving.accept().await?;
                    run_exchange(exchange.plan, stream, acceptor, accepted, observed).await
                })
                .await
                .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { Box::new(error) })
                .and_then(std::convert::identity);
                exchange
                    .done
                    .send(result)
                    .map_err(|_| io::Error::other("exchange observer dropped"))?;
            }
            Ok(())
        });
        Ok(Self {
            upstream,
            handshakes,
            requests,
            sender: Some(sender),
            task,
        })
    }

    pub async fn queue(
        &self,
        path: &'static str,
        headers: Vec<u8>,
        body: Option<Vec<u8>>,
    ) -> TestResult<oneshot::Receiver<TestResult<()>>> {
        if headers.len() > 600 << 10 || body.as_ref().is_some_and(|body| body.len() > 64 << 10) {
            return Err(io::Error::other("response fixture exceeds bound").into());
        }
        let (done, receipt) = oneshot::channel();
        self.sender
            .as_ref()
            .ok_or_else(|| io::Error::other("fixture stopped"))?
            .send(Exchange {
                plan: Plan::Http {
                    path,
                    headers,
                    body,
                },
                done,
            })
            .await?;
        Ok(receipt)
    }

    pub async fn stall_handshake(&self) -> TestResult<StalledHandshake> {
        let (started, observed) = oneshot::channel();
        let (done, closed) = oneshot::channel();
        self.sender
            .as_ref()
            .ok_or_else(|| io::Error::other("fixture stopped"))?
            .send(Exchange {
                plan: Plan::StalledTls(started),
                done,
            })
            .await?;
        Ok(StalledHandshake {
            started: observed,
            closed,
        })
    }

    pub async fn queue_http2(
        &self,
        headers: Vec<u8>,
        body: Option<Vec<u8>>,
    ) -> TestResult<oneshot::Receiver<TestResult<()>>> {
        if headers.is_empty()
            || headers.len() > 64 << 10
            || body.as_ref().is_some_and(|body| body.len() > 64 << 10)
        {
            return Err(io::Error::other("HTTP/2 response fixture exceeds bound").into());
        }
        let (done, receipt) = oneshot::channel();
        self.sender
            .as_ref()
            .ok_or_else(|| io::Error::other("fixture stopped"))?
            .send(Exchange {
                plan: Plan::Http2 { headers, body },
                done,
            })
            .await?;
        Ok(receipt)
    }

    pub async fn finish(&mut self) -> TestResult<()> {
        drop(self.sender.take());
        timeout(Duration::from_secs(2), &mut self.task).await???;
        Ok(())
    }
}

async fn run_exchange(
    plan: Plan,
    stream: tokio::net::TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
    accepted: Arc<AtomicUsize>,
    observed: Arc<AtomicUsize>,
) -> TestResult<()> {
    match plan {
        Plan::Http {
            path,
            headers,
            body,
        } => {
            let mut stream = acceptor.accept(stream).await?;
            let _ = accepted.fetch_add(1, Ordering::SeqCst);
            if stream.get_ref().1.alpn_protocol() != Some(b"http/1.1") {
                return Err(io::Error::other("HTTP/1 ALPN not negotiated").into());
            }
            request(&mut stream, path).await?;
            let _ = observed.fetch_add(1, Ordering::SeqCst);
            reply(&mut stream, &headers, body.as_deref()).await
        }
        Plan::StalledTls(started) => stalled_handshake(stream, started).await,
        Plan::Http2 { headers, body } => {
            let mut stream = acceptor.accept(stream).await?;
            let _ = accepted.fetch_add(1, Ordering::SeqCst);
            if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
                return Err(io::Error::other("HTTP/2 ALPN not negotiated").into());
            }
            let mut preface = [0; 24];
            let _ = stream.read_exact(&mut preface).await?;
            if &preface != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
                return Err(io::Error::other("invalid HTTP/2 preface").into());
            }
            let mut peer = Peer::new(stream);
            peer.send(0, 4, 0, &[]).await?;
            let request = http2_request(&mut peer).await?;
            let _ = observed.fetch_add(1, Ordering::SeqCst);
            http2_reply(&mut peer, request, &headers, body.as_deref()).await
        }
    }
}

async fn http2_request(peer: &mut Peer<Stream>) -> TestResult<u32> {
    let mut stream = None;
    let mut bounded_headers = false;
    let mut remaining: usize = 8192;
    for _ in 0..64 {
        let frame = peer.next().await?.ok_or("HTTP/2 request closed")?;
        match frame.kind {
            4 if frame.stream == 0 && frame.flags == 0 => {
                let (settings, remainder) = frame.payload.as_chunks::<6>();
                if !remainder.is_empty() {
                    return Err(io::Error::other("invalid HTTP/2 SETTINGS length").into());
                }
                bounded_headers |= settings.contains(&[0, 6, 0, 0, 0x40, 0]);
                peer.send(0, 4, 1, &[]).await?;
            }
            1 | 0 | 9 if frame.stream > 0 => {
                if frame.kind == 1 {
                    if stream.replace(frame.stream).is_some() || frame.stream % 2 == 0 {
                        return Err(io::Error::other("unexpected HTTP/2 request stream").into());
                    }
                } else if stream != Some(frame.stream) {
                    return Err(io::Error::other("HTTP/2 request stream mismatch").into());
                }
                remaining = remaining
                    .checked_sub(frame.payload.len())
                    .ok_or_else(|| io::Error::other("HTTP/2 request exceeds byte bound"))?;
                if frame.kind != 9 && frame.flags & 1 != 0 {
                    if !bounded_headers {
                        return Err(io::Error::other("missing 16 KiB header-list setting").into());
                    }
                    return Ok(frame.stream);
                }
            }
            4 | 8 if frame.stream == 0 => {}
            _ => return Err(io::Error::other("unexpected HTTP/2 request frame").into()),
        }
    }
    Err(io::Error::other("HTTP/2 request frame count exceeds bound").into())
}

async fn http2_reply(
    peer: &mut Peer<Stream>,
    stream: u32,
    headers: &[u8],
    body: Option<&[u8]>,
) -> TestResult<()> {
    // Each queued exchange owns one connection. Graceful GOAWAY preserves
    // this accepted stream while preventing reuse of its closing fixture.
    let [a, b, c, d] = stream.to_be_bytes();
    peer.send(0, 7, 0, &[a, b, c, d, 0, 0, 0, 0]).await?;
    // A split field block exercises CONTINUATION as well as decoded size.
    let mut sent = 0;
    let mut kind = 1;
    while sent < headers.len() {
        let size = if sent == 0 { 1024 } else { 16 << 10 };
        let end = sent.saturating_add(size).min(headers.len());
        let chunk = headers.get(sent..end).ok_or("invalid header chunk")?;
        peer.send(
            stream,
            kind,
            if end == headers.len() { 4 } else { 0 },
            chunk,
        )
        .await?;
        sent = end;
        kind = 9;
    }
    if let Some(body) = body {
        if body.is_empty() {
            peer.send(stream, 0, 1, &[]).await?;
        } else {
            let mut sent = 0;
            while sent < body.len() {
                let end = sent.saturating_add(16 << 10).min(body.len());
                let chunk = body.get(sent..end).ok_or("invalid body chunk")?;
                peer.send(stream, 0, u8::from(end == body.len()), chunk)
                    .await?;
                sent = end;
            }
        }
        return Ok(());
    }
    // No DATA or END_STREAM: only header rejection can finish promptly.
    for _ in 0..64 {
        let Some(frame) = peer.next().await? else {
            return Ok(());
        };
        if frame.kind == 3 && frame.stream == stream {
            if frame.payload.len() != 4 {
                return Err(io::Error::other("invalid HTTP/2 reset").into());
            }
            return Ok(());
        }
        if frame.kind == 7 && frame.stream == 0 {
            return Ok(());
        }
        if !matches!(frame.kind, 4 | 8) {
            return Err(io::Error::other("unexpected HTTP/2 rejection frame").into());
        }
    }
    Err(io::Error::other("HTTP/2 rejection frame count exceeds bound").into())
}

async fn stalled_handshake(
    mut stream: tokio::net::TcpStream,
    started: oneshot::Sender<()>,
) -> TestResult<()> {
    let mut header = [0; 5];
    let _ = stream.read_exact(&mut header).await?;
    let [content_type, major, minor, high, low] = header;
    let length = usize::from(u16::from_be_bytes([high, low]));
    if content_type != 22
        || major != 3
        || !matches!(minor, 1..=3)
        || !(1..=16 << 10).contains(&length)
    {
        return Err(io::Error::other("bounded TLS handshake record required").into());
    }
    let mut hello = vec![0; length];
    let _ = stream.read_exact(&mut hello).await?;
    if hello.first() != Some(&1) {
        return Err(io::Error::other("TLS ClientHello required").into());
    }
    drop(hello);
    started
        .send(())
        .map_err(|()| io::Error::other("handshake observer dropped"))?;
    let mut buffer = [0; 1024];
    let mut remaining: usize = 64 << 10;
    loop {
        let count = match stream.read(&mut buffer).await {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if count == 0 {
            return Ok(());
        }
        remaining = remaining
            .checked_sub(count)
            .ok_or_else(|| io::Error::other("pending handshake fixture exceeds bound"))?;
    }
}

async fn request(stream: &mut Stream, path: &str) -> TestResult<()> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0
            || bytes
                .len()
                .checked_add(count)
                .is_none_or(|size| size > 8192)
        {
            return Err(io::Error::other("request fixture exceeds bound or closed").into());
        }
        bytes.extend_from_slice(
            buffer
                .get(..count)
                .ok_or_else(|| io::Error::other("request read length"))?,
        );
        if let Some(end) = bytes.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            let head = std::str::from_utf8(
                bytes
                    .get(..end)
                    .ok_or_else(|| io::Error::other("request header boundary"))?,
            )?;
            if !head.starts_with(&format!("POST {path} HTTP/1.1\r\n")) {
                return Err(io::Error::other("unexpected fixture endpoint").into());
            }
            let length = head
                .split("\r\n")
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .ok_or_else(|| io::Error::other("missing request length"))?
                .1
                .trim()
                .parse::<usize>()?;
            let length = end
                .checked_add(4)
                .and_then(|end| end.checked_add(length))
                .filter(|length| *length <= 8192)
                .ok_or_else(|| io::Error::other("request body exceeds bound"))?;
            if bytes.len() >= length {
                return Ok(());
            }
        }
    }
}

fn closed(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

async fn reply(stream: &mut Stream, headers: &[u8], body: Option<&[u8]>) -> TestResult<()> {
    if let Err(error) = stream.write_all(headers).await {
        return if body.is_none() && closed(&error) {
            Ok(())
        } else {
            Err(error.into())
        };
    }
    if let Some(body) = body {
        stream.write_all(body).await?;
        stream.shutdown().await?;
        return Ok(());
    }
    // Withhold the declared JSON body. Only parser rejection can finish promptly.
    match stream.read(&mut [0]).await {
        Ok(0) => Ok(()),
        Err(error) if closed(&error) => Ok(()),
        Ok(_) => Err(io::Error::other("unexpected bytes after complete request").into()),
        Err(error) => Err(error.into()),
    }
}
