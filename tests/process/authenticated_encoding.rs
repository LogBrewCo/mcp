//! Standalone executable request-coding rejection, privacy and recovery.

use core::{
    convert::Infallible,
    pin::Pin,
    sync::atomic::Ordering,
    task::{Context, Poll},
    time::Duration,
};

use axum::body::Bytes;
use http_body::{Frame, SizeHint};
use http_body_util::BodyExt as _;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustix::process::Signal;
use serde_json::json;
use tokio::time::timeout;

use super::{Fixture, Process, TestResult, backend, client, configure, envelope, message};

fn execution() -> serde_json::Value {
    json!({"name":"execute","arguments":{"operation":"logs.read.v1","input":{}}})
}

/// # Errors
/// Returns a JSON encoding error.
fn coded_request(
    http: &reqwest::Client,
    resource: &str,
    codings: &[&str],
) -> TestResult<reqwest::RequestBuilder> {
    let request = http
        .post(resource)
        .bearer_auth(backend::TOKEN)
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "execute")
        .json(&message("tools/call", execution())?);
    Ok(codings.iter().fold(request, |request, coding| {
        request.header("Content-Encoding", *coding)
    }))
}

struct UnsentBody;

impl http_body::Body for UnsentBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Pending
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(1024)
    }
}

struct Driver(tokio::task::JoinHandle<Result<(), hyper::Error>>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

type Reply = (reqwest::StatusCode, reqwest::header::HeaderMap, Bytes);

/// # Errors
/// Returns a response body or bounded body-read error.
async fn read(response: hyper::Response<hyper::body::Incoming>) -> TestResult<Reply> {
    let (parts, body) = response.into_parts();
    let bytes = timeout(Duration::from_secs(2), body.collect()).await??;
    Ok((parts.status, parts.headers, bytes.to_bytes()))
}

/// # Errors
/// Returns a TLS, handshake, request, response or two-second observation timeout.
async fn stalled(fixture: &Fixture, resource: &str, http2: bool) -> TestResult<Reply> {
    let authority = format!("localhost:{}", fixture.address.port());
    let request = hyper::Request::post(resource)
        .header("Host", authority)
        .header("Authorization", format!("Bearer {}", backend::TOKEN))
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json")
        .header("Content-Encoding", "gzip")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "execute")
        .body(UnsentBody)?;
    let io = TokioIo::new(
        fixture
            .tls_protocol(if http2 { Some(b"h2") } else { None })
            .await?,
    );
    if http2 {
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await?;
        let _driver = Driver(tokio::spawn(connection));
        let response = timeout(Duration::from_secs(2), sender.send_request(request)).await??;
        read(response).await
    } else {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await?;
        let _driver = Driver(tokio::spawn(connection));
        let response = timeout(Duration::from_secs(2), sender.send_request(request)).await??;
        read(response).await
    }
}

/// # Panics
/// Fails if the fixed rejection discloses input or changes its cache or session policy.
fn rejection(status: reqwest::StatusCode, headers: &reqwest::header::HeaderMap, bytes: &[u8]) {
    assert_eq!(status, reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        headers
            .get("Accept-Encoding")
            .map(reqwest::header::HeaderValue::as_bytes),
        Some(b"identity".as_slice())
    );
    assert_eq!(
        headers
            .get("Cache-Control")
            .map(reqwest::header::HeaderValue::as_bytes),
        Some(b"no-store".as_slice())
    );
    assert!(!headers.contains_key("Mcp-Session-Id"));
    assert_eq!(bytes, b"unsupported content encoding");
}

/// # Errors
/// Returns a request or response-body error.
///
/// # Panics
/// Fails if coding rejection changes its transport, body or response policy.
async fn rejected(http: &reqwest::Client, resource: &str, http2: bool) -> TestResult<()> {
    let rejected: &[(&[&str], Option<&[u8]>)] = &[
        (&["gzip"], None),
        (&["br"], None),
        (&["identity, gzip"], None),
        (&["gzip", "identity"], None),
        (&["identity;q=1"], None),
        (&["private-coding-marker"], None),
        (&["gzip"], Some(b"private-request-body-marker")),
        (&["gzip"], Some(b"\x1f\x8b\x08\x00")),
        (&["gzip"], Some(b"not JSON")),
    ];
    for &(codings, body) in rejected {
        let request = coded_request(http, resource, codings)?;
        let request = match body {
            Some(body) => request.body(body.to_vec()),
            None => request,
        };
        let response = request.send().await?;
        assert_eq!(
            response.version(),
            if http2 {
                reqwest::Version::HTTP_2
            } else {
                reqwest::Version::HTTP_11
            }
        );
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;
        rejection(status, &headers, &bytes);
    }
    Ok(())
}

/// # Errors
/// Returns a header, request or response-body error.
///
/// # Panics
/// Fails if coding validation bypasses credentials or origin policy or repeats private input.
async fn authorization(http: &reqwest::Client, resource: &str) -> TestResult<()> {
    for foreign_origin in [false, true] {
        let mut request = coded_request(http, resource, &["gzip"])?
            .body("private-unauthorized-body")
            .build()?;
        if foreign_origin {
            drop(
                request
                    .headers_mut()
                    .insert("Origin", "https://other.example".parse()?),
            );
        } else {
            drop(request.headers_mut().remove("Authorization"));
        }
        let response = http.execute(request).await?;
        assert_eq!(
            response.status(),
            if foreign_origin {
                reqwest::StatusCode::FORBIDDEN
            } else {
                reqwest::StatusCode::UNAUTHORIZED
            }
        );
        assert!(!response.headers().contains_key("Accept-Encoding"));
        let bytes = response.bytes().await?;
        assert!(!String::from_utf8_lossy(&bytes).contains("private-unauthorized-body"));
    }
    Ok(())
}

/// # Errors
/// Returns a request, response-body or result decoding error.
///
/// # Panics
/// Fails if supported coding changes transport, data, response policy or upstream counts.
async fn recovery(
    http: &reqwest::Client,
    resource: &str,
    http2: bool,
    upstream: &backend::Backend,
) -> TestResult<()> {
    for (index, codings) in [&[][..], &["IDENTITY"][..], &["identity", "IDENTITY"][..]]
        .into_iter()
        .enumerate()
    {
        let response = coded_request(http, resource, codings)?.send().await?;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            response.version(),
            if http2 {
                reqwest::Version::HTTP_2
            } else {
                reqwest::Version::HTTP_11
            }
        );
        assert!(!response.headers().contains_key("Accept-Encoding"));
        let reply: serde_json::Value = response.json().await?;
        assert_eq!(
            envelope(&reply, None)?.pointer("/data/count"),
            Some(&json!(3_i32))
        );
        assert_eq!(
            Some(upstream.observations.executes.load(Ordering::SeqCst)),
            index.checked_add(1)
        );
        assert_eq!(
            Some(upstream.observations.verifies.load(Ordering::SeqCst)),
            index.checked_add(11)
        );
    }
    Ok(())
}

/// # Errors
/// Returns a fixture, TLS, process, request, result or cleanup error.
///
/// # Panics
/// Fails if coding reaches execution, bypasses authorization, waits for stalled input,
/// prevents recovery, leaves upstream work pending or prevents silent shutdown.
async fn contracts(http2: bool) -> TestResult<()> {
    let fixture = Fixture::new()?;
    let resource = format!("https://localhost:{}/mcp", fixture.address.port());
    let mut upstream = backend::Backend::start(resource.clone()).await?;
    configure(&fixture, &upstream.endpoint)?;
    let roots =
        fixture
            .directory
            .write("upstream-root.pem", upstream.certificate.as_bytes(), 0o600)?;
    let mut process = Process::start_with_roots(&fixture.config, Some(&roots))?;
    fixture.ready(&mut process).await?;
    let http = client(&fixture, http2)?;
    rejected(&http, &resource, http2).await?;
    assert_eq!(upstream.observations.verifies.load(Ordering::SeqCst), 9);
    assert_eq!(upstream.observations.executes.load(Ordering::SeqCst), 0);
    authorization(&http, &resource).await?;
    assert_eq!(upstream.observations.verifies.load(Ordering::SeqCst), 9);
    let (status, headers, bytes) = stalled(&fixture, &resource, http2).await?;
    rejection(status, &headers, &bytes);
    assert_eq!(upstream.observations.verifies.load(Ordering::SeqCst), 10);
    assert_eq!(upstream.observations.executes.load(Ordering::SeqCst), 0);
    recovery(&http, &resource, http2, &upstream).await?;
    for stage in [
        backend::PendingStage::Verification,
        backend::PendingStage::Execution,
    ] {
        assert_eq!(upstream.observations.pending_count(stage), 0);
    }
    fixture.ready(&mut process).await?;
    process.signal(Signal::TERM)?;
    assert!(process.wait().await?.success());
    drop(std::net::TcpListener::bind(fixture.address)?);
    upstream.finish().await?;
    Ok(())
}

#[tokio::test]
/// # Errors
/// Returns an HTTP/1 executable fixture error or an outer timeout.
///
/// # Panics
/// Fails if coding rejection, authentication, stalled-body rejection or recovery changes.
async fn normal_linux_http1_request_encoding_rejection_and_recovery() -> TestResult<()> {
    timeout(Duration::from_secs(20), contracts(false)).await?
}

#[tokio::test]
/// # Errors
/// Returns an HTTP/2 executable fixture error or an outer timeout.
///
/// # Panics
/// Fails if coding rejection, authentication, stalled-body rejection or recovery changes.
async fn normal_linux_http2_request_encoding_rejection_and_recovery() -> TestResult<()> {
    timeout(Duration::from_secs(20), contracts(true)).await?
}
