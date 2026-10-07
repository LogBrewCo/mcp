//! Reject unsupported request coding before interpreting or polling its body.

use alloc::sync::Arc;
use core::{
    convert::Infallible,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
    time::Duration,
};
use std::net::TcpListener;

use axum::{
    body::{Body, Bytes, to_bytes},
    http::{HeaderValue, header},
};
use http_body::Frame;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::{
    http::{Fixture, TOKEN, request_message},
    runtime::Running,
};

fn params() -> Value {
    json!({"name":"execute","arguments":{"operation":"logs.read.v1","input":{}}})
}

fn wire_request(
    client: &reqwest::Client,
    resource: &str,
    codings: &[&str],
) -> reqwest::RequestBuilder {
    let request = client
        .post(resource)
        .header("Authorization", format!("Bearer {TOKEN}"))
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "execute")
        .json(
            &json!({"jsonrpc":"2.0","id":1_i32,"method":"tools/call","params":{
            "name":"execute","arguments":{"operation":"logs.read.v1","input":{}},"_meta":{
                "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                "io.modelcontextprotocol/clientCapabilities":{}}}}),
        );
    codings.iter().fold(request, |request, coding| {
        request.header(header::CONTENT_ENCODING, *coding)
    })
}

/// # Errors
/// Returns an error if the isolated HTTP/2 client cannot be constructed.
fn wire_cases(
    running: &Running,
    resource: &str,
    codings: &[&[&str]],
) -> super::TestResult<Vec<(reqwest::Version, reqwest::RequestBuilder)>> {
    Ok([
        (reqwest::Version::HTTP_11, running.http1_client()),
        (reqwest::Version::HTTP_2, running.http2_client()?),
    ]
    .into_iter()
    .flat_map(|(version, client)| {
        codings
            .iter()
            .map(move |coding| (version, wire_request(&client, resource, coding)))
    })
    .collect())
}

#[tokio::test]
/// # Panics
/// Fails if unsupported coding executes, rejection discloses request values,
/// supported coding loses results, either HTTP version changes, or drain fails.
async fn http1_and_http2_reject_coding_and_recover_with_unencoded_json() {
    let address = TcpListener::bind("127.0.0.1:0")
        .expect("frontend address")
        .local_addr()
        .expect("address");
    let authority = format!("localhost:{}", address.port());
    let resource = format!("https://{authority}/mcp");
    let fixture = Fixture::for_resource(resource.clone())
        .await
        .expect("fixture");
    let mut running = Running::at(address, fixture.router.clone(), &authority)
        .await
        .expect("HTTPS runtime");
    let rejected: &[&[&str]] = &[
        &["gzip"],
        &["br"],
        &["deflate"],
        &["compress"],
        &["*"],
        &["identity, gzip"],
        &["gzip", "identity"],
        &["identity", "br"],
        &["identity;q=1"],
        &["\"identity\""],
        &["iden tity"],
        &["private-coding-marker"],
    ];
    let accepted: &[&[&str]] = &[
        &[],
        &["identity"],
        &["IDENTITY"],
        &[" \tidentity\t "],
        &["identity, identity"],
        &["identity", "IDENTITY"],
        &[""],
        &[", , identity, ,"],
        &["", "identity"],
    ];
    let mut executions = fixture.state.calls.load(Ordering::SeqCst);
    for (version, request) in wire_cases(&running, &resource, rejected).expect("rejected cases") {
        let response = request.send().await.expect("coding rejection");
        assert_eq!(response.version(), version);
        assert_eq!(
            response.status(),
            reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported coding; backend calls {}",
            fixture.state.calls.load(Ordering::SeqCst)
        );
        assert_eq!(
            response
                .headers()
                .get(header::ACCEPT_ENCODING)
                .expect("accepted request coding"),
            "identity"
        );
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .expect("cache control"),
            "no-store"
        );
        assert!(response.headers().get("Mcp-Session-Id").is_none());
        assert_eq!(
            response.text().await.expect("fixed error"),
            "unsupported content encoding"
        );
        assert_eq!(fixture.state.calls.load(Ordering::SeqCst), executions);
    }
    for (version, request) in wire_cases(&running, &resource, accepted).expect("accepted cases") {
        let response = request.send().await.expect("unencoded recovery");
        assert_eq!(response.version(), version);
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert!(response.headers().get(header::ACCEPT_ENCODING).is_none());
        let value: Value = response.json().await.expect("complete result");
        assert_eq!(
            value.pointer("/result/structuredContent/data/count"),
            Some(&json!(3_i32))
        );
        executions = executions.checked_add(1).expect("execution count");
        assert_eq!(fixture.state.calls.load(Ordering::SeqCst), executions);
    }
    running.stop.cancel();
    running.wait().await.expect("runtime drain");
}

struct UnreadBody(Arc<AtomicBool>);

impl http_body::Body for UnreadBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.store(true, Ordering::SeqCst);
        Poll::Pending
    }
}

#[tokio::test]
/// # Panics
/// Fails if rejecting unsupported coding waits for or polls its body, executes,
/// or prevents a later authenticated request from returning complete data.
async fn coding_rejection_does_not_poll_a_stalled_request_body() {
    let fixture = Fixture::new().await.expect("fixture");
    let polled = Arc::new(AtomicBool::new(false));
    let mut request = request_message(1, "tools/call", params(), TOKEN).expect("request");
    drop(
        request
            .headers_mut()
            .insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip")),
    );
    *request.body_mut() = Body::new(UnreadBody(Arc::clone(&polled)));
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        fixture.router.clone().oneshot(request),
    )
    .await
    .expect("rejection without body input")
    .expect("response");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    assert!(!polled.load(Ordering::SeqCst));
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    let (status, value) = fixture
        .request("tools/call", params(), TOKEN)
        .await
        .expect("recovery");
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(
        value.pointer("/result/structuredContent/data/count"),
        Some(&json!(3_i32))
    );
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
/// # Panics
/// Fails if coding checks bypass authority, credential or media validation,
/// inspect malformed body data, repeat private values, or execute rejected work.
async fn coding_rejection_preserves_authentication_and_media_error_boundaries() {
    let fixture = Fixture::new().await.expect("fixture");
    for (coding, bytes) in [
        (
            HeaderValue::from_static("gzip"),
            b"private-request-body-marker".as_slice(),
        ),
        (
            HeaderValue::from_bytes(&[0xff]).expect("opaque header"),
            b"invalid JSON".as_slice(),
        ),
        (
            HeaderValue::from_static("gzip"),
            b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                .as_slice(),
        ),
    ] {
        let mut request = request_message(1, "tools/call", params(), TOKEN).expect("request");
        drop(
            request
                .headers_mut()
                .insert(header::CONTENT_ENCODING, coding),
        );
        *request.body_mut() = Body::from(bytes);
        let response = fixture
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("rejection");
        assert_eq!(
            response.status(),
            reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            to_bytes(response.into_body(), 1024)
                .await
                .expect("fixed body")
                .as_ref(),
            b"unsupported content encoding"
        );
    }
    let mut missing = request_message(1, "tools/call", params(), TOKEN).expect("request");
    drop(missing.headers_mut().remove(header::AUTHORIZATION));
    let mut foreign = request_message(1, "tools/call", params(), TOKEN).expect("request");
    drop(foreign.headers_mut().insert(
        header::ORIGIN,
        HeaderValue::from_static("https://other.example"),
    ));
    for (mut request, expected) in [
        (missing, reqwest::StatusCode::UNAUTHORIZED),
        (foreign, reqwest::StatusCode::FORBIDDEN),
    ] {
        drop(
            request
                .headers_mut()
                .insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip")),
        );
        let response = fixture
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("authorization rejection");
        assert_eq!(response.status(), expected);
        assert!(response.headers().get(header::ACCEPT_ENCODING).is_none());
    }
    let mut request = request_message(1, "tools/call", params(), TOKEN).expect("request");
    drop(
        request
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain")),
    );
    let response = fixture
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("media rejection");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    assert!(response.headers().get(header::ACCEPT_ENCODING).is_none());
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 4);
}
