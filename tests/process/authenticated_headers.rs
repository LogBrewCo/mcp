//! Normal executable header-error privacy, correlation and recovery.

use std::{sync::atomic::Ordering, time::Duration};

use rustix::process::Signal;
use serde_json::{Value, json};
use tokio::time::timeout;

use super::{Fixture, Process, TestResult, backend, client, configure, envelope, request};

/// # Errors
///
/// Returns a header, request, body-read or JSON parsing error.
///
/// # Panics
///
/// Panics if rejected headers alter correlation, status, transport, cache policy,
/// session isolation or private-field redaction.
async fn rejected(http: &reqwest::Client, resource: &str, http2: bool) -> TestResult<()> {
    let marker = "SYNTHETIC_REJECTED_PRIVATE_FIELD";
    for id in [
        json!(1_i32),
        json!("correlation"),
        serde_json::from_str("18446744073709551616")?,
    ] {
        for name in ["Mcp-Method", "Mcp-Name"] {
            let mut headers = reqwest::header::HeaderMap::new();
            drop(headers.insert("mcp-method", "tools/call".parse()?));
            drop(headers.insert("mcp-name", "execute".parse()?));
            drop(headers.insert(
                reqwest::header::HeaderName::from_bytes(name.as_bytes())?,
                marker.parse()?,
            ));
            let response = http
                .post(resource)
                .bearer_auth(backend::TOKEN)
                .header("Accept", "application/json, text/event-stream")
                .header("MCP-Protocol-Version", "2026-07-28")
                .headers(headers)
                .json(
                    &json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
                    "name":"execute","arguments":{"operation":"logs.read.v1","input":{}},
                    "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities":{}}}}),
                )
                .send()
                .await?;
            assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
            assert_eq!(
                response.version(),
                if http2 {
                    reqwest::Version::HTTP_2
                } else {
                    reqwest::Version::HTTP_11
                }
            );
            assert_eq!(
                response
                    .headers()
                    .get("Cache-Control")
                    .and_then(|value| value.to_str().ok()),
                Some("no-store")
            );
            assert!(!response.headers().contains_key("Mcp-Session-Id"));
            let bytes = response.bytes().await?;
            assert!(!String::from_utf8_lossy(&bytes).contains(marker));
            let error: Value = serde_json::from_slice(&bytes)?;
            assert_eq!(error.get("id"), Some(&id));
            assert_eq!(error.pointer("/error/code"), Some(&json!(-32_020_i32)));
            assert_eq!(
                error.pointer("/error/message"),
                Some(&json!("invalid request headers"))
            );
        }
    }
    Ok(())
}

/// # Errors
///
/// Returns a fixture, file, process, request, timeout or shutdown error.
///
/// # Panics
///
/// Panics if header rejection reaches execution, recovery changes the result or
/// call counts, upstream work remains or executable shutdown fails.
async fn privacy_and_recovery(http2: bool) -> TestResult<()> {
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
    assert_eq!(upstream.observations.verifies.load(Ordering::SeqCst), 6);
    assert_eq!(upstream.observations.executes.load(Ordering::SeqCst), 0);
    let execution = json!({"name":"execute","arguments":{"operation":"logs.read.v1","input":{}}});
    let (status, result) = request(&http, &resource, "tools/call", execution, http2).await?;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(
        envelope(&result, None)?.pointer("/data/count"),
        Some(&json!(3_i32))
    );
    assert_eq!(upstream.observations.verifies.load(Ordering::SeqCst), 7);
    assert_eq!(upstream.observations.executes.load(Ordering::SeqCst), 1);
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
///
/// Returns an HTTP/1 header fixture error or an outer timeout.
///
/// # Panics
///
/// Panics if header privacy, rejection or recovery fails its assertions.
async fn normal_linux_http1_header_error_privacy_and_recovery() -> TestResult<()> {
    timeout(Duration::from_secs(20), privacy_and_recovery(false)).await?
}

#[tokio::test]
/// # Errors
///
/// Returns an HTTP/2 header fixture error or an outer timeout.
///
/// # Panics
///
/// Panics if header privacy, rejection or recovery fails its assertions.
async fn normal_linux_http2_header_error_privacy_and_recovery() -> TestResult<()> {
    timeout(Duration::from_secs(20), privacy_and_recovery(true)).await?
}
