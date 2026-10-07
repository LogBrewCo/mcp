//! Authority equivalence and malformed Host rejection over actual TLS.

use core::{sync::atomic::Ordering, time::Duration};
use std::io;

use axum::{
    body::{Body, to_bytes},
    http::{HeaderValue, Request, StatusCode, header},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    time::timeout,
};

use super::{
    http::{Fixture, TOKEN, request_message},
    runtime::Running,
};

type TestResult<T> = Result<T, Box<dyn core::error::Error + Send + Sync>>;

/// # Errors
///
/// Returns a TLS, HTTP/2 handshake, request, body-read or timeout error, or an
/// error if the connection ends before its response.
///
/// # Panics
///
/// Panics if the response cache policy differs from no-store.
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::integer_division_remainder_used,
    reason = "Tokio select wraps its branch polling index with remainder; this is not cryptographic arithmetic."
)]
async fn http2(running: &Running, request: Request<Body>) -> TestResult<(StatusCode, Vec<u8>)> {
    let stream = running.tls(Some(b"h2")).await?;
    let (mut sender, connection) = timeout(
        Duration::from_secs(2),
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)),
    )
    .await??;
    let exchange = async move {
        let response = sender.send_request(request).await?;
        let status = response.status();
        assert_eq!(
            response.headers().get("Cache-Control"),
            Some(&HeaderValue::from_static("no-store"))
        );
        let bytes = to_bytes(Body::new(response.into_body()), 4096)
            .await?
            .to_vec();
        Ok((status, bytes))
    };
    timeout(Duration::from_secs(2), async {
        tokio::select! {
            biased;
            result = exchange => result,
            result = connection => {
                result?;
                Err(io::Error::other("connection ended before response").into())
            }
        }
    })
    .await?
}

#[tokio::test]
/// # Errors
///
/// Returns a fixture, request construction, TLS exchange, JSON or shutdown error.
///
/// # Panics
///
/// Panics if conflicting hosts are accepted or start upstream work, default-port
/// recovery fails, execution counts change, or private markers are returned.
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
async fn tls_http2_accepts_default_ports_and_rejects_conflicting_host_before_auth() -> TestResult<()>
{
    let fixture = Fixture::new().await?;
    let mut running = Running::start(fixture.router.clone()).await?;
    for host in [
        b"\xff".as_slice(),
        b"foreign.example",
        b"resource.example:444",
    ] {
        let mut request = request_message(1, "tools/list", json!({}), TOKEN)?;
        *request.uri_mut() = "https://resource.example:443/mcp".parse()?;
        drop(
            request
                .headers_mut()
                .insert(header::HOST, HeaderValue::from_bytes(host)?),
        );
        let (status, bytes) = http2(&running, request).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(bytes, b"invalid host or origin");
        assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    }
    let mut request = request_message(
        1,
        "tools/call",
        json!({"name":"execute","arguments":{"operation":"logs.read.v1","input":{}}}),
        TOKEN,
    )?;
    *request.uri_mut() = "https://resource.example:443/mcp".parse()?;
    drop(request.headers_mut().insert(
        header::ORIGIN,
        HeaderValue::from_static("https://resource.example:443"),
    ));
    let (status, bytes) = http2(&running, request).await?;
    assert_eq!(status, StatusCode::OK);
    let response: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        response.pointer("/result/structuredContent/data/count"),
        Some(&json!(3_i32))
    );
    assert!(!String::from_utf8_lossy(&bytes).contains("SYNTHETIC_"));
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);
    running.stop.cancel();
    running.wait().await?;
    Ok(())
}

/// # Errors
///
/// Returns a TLS, write, read or timeout error during the bounded HTTP/1 exchange.
async fn http1(running: &Running, request: &[u8]) -> TestResult<Vec<u8>> {
    let mut stream = running.tls(Some(b"http/1.1")).await?;
    stream.write_all(request).await?;
    let mut response = Vec::new();
    let _: usize = timeout(
        Duration::from_secs(2),
        stream.take(4096).read_to_end(&mut response),
    )
    .await??;
    Ok(response)
}

#[tokio::test]
/// # Errors
///
/// Returns a fixture, TLS exchange or shutdown error.
///
/// # Panics
///
/// Panics if malformed Host rejection or default-port metadata recovery changes,
/// or public metadata starts introspection or execution.
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
async fn tls_http1_metadata_rejects_malformed_host_and_recovers_with_default_port() -> TestResult<()>
{
    let fixture = Fixture::new().await?;
    let mut running = Running::start(fixture.router.clone()).await?;
    let invalid = b"GET https://resource.example/.well-known/oauth-protected-resource/mcp HTTP/1.1\r\nHost: \xff\r\nConnection: close\r\n\r\n";
    let denied = http1(&running, invalid).await?;
    assert!(denied.starts_with(b"HTTP/1.1 403 "));
    assert!(String::from_utf8_lossy(&denied).contains("invalid host or origin"));
    let valid = b"GET /.well-known/oauth-protected-resource/mcp HTTP/1.1\r\nHost: resource.example:443\r\nOrigin: https://resource.example:443\r\nConnection: close\r\n\r\n";
    let allowed = http1(&running, valid).await?;
    assert!(allowed.starts_with(b"HTTP/1.1 200 "));
    assert!(String::from_utf8_lossy(&allowed).contains("https://resource.example/mcp"));
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    running.stop.cancel();
    running.wait().await?;
    Ok(())
}
