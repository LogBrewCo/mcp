//! Clients that speak MCP 2025-06-18 or 2025-11-25: the `initialize` handshake,
//! then stateless requests without sessions, under the same authorization.

use core::sync::atomic::Ordering;

use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, HeaderValue, Request, StatusCode},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::http::{Fixture, TOKEN};

type TestResult<T> = Result<T, Box<dyn core::error::Error + Send + Sync>>;

/// Send a request as a legacy client does: no per-request metadata, and the
/// negotiated version header after `initialize`.
///
/// # Errors
/// Returns a request construction, router or bounded response-body read error.
///
/// # Panics
/// Fails if the response repeats the synthetic delegated credential.
async fn send(
    fixture: &Fixture,
    version: Option<&str>,
    token: Option<&str>,
    message: &Value,
) -> TestResult<(StatusCode, Value, HeaderMap)> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Host", "resource.example")
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream");
    if let Some(version) = version {
        builder = builder.header("MCP-Protocol-Version", version);
    }
    if let Some(token) = token {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    let request = builder.body(Body::from(message.to_string()))?;
    let response = fixture.router().clone().oneshot(request).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 5 << 20).await?;
    assert!(!String::from_utf8_lossy(&bytes).contains(TOKEN));
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Ok((status, value, headers))
}

fn initialize(version: &str) -> Value {
    json!({"jsonrpc":"2.0","id":1_u32,"method":"initialize","params":{
        "protocolVersion":version,"capabilities":{},
        "clientInfo":{"name":"synthetic-legacy","version":"1"}}})
}

fn execute() -> Value {
    json!({"jsonrpc":"2.0","id":3_u32,"method":"tools/call","params":{
        "name":"execute","arguments":{"operation":"logs.read.v1","input":{}}}})
}

#[tokio::test]
/// # Panics
///
/// Panics if a 2025-06-18 or 2025-11-25 client cannot initialize, list the two
/// tools and execute a read without a session, or if the server creates a session.
async fn legacy_clients_initialize_list_and_execute_without_sessions() {
    for version in ["2025-06-18", "2025-11-25"] {
        let fixture = Fixture::new().await.expect("fixture");
        let (init_status, init, init_headers) =
            send(&fixture, None, Some(TOKEN), &initialize(version))
                .await
                .expect("initialize");
        assert_eq!(init_status, StatusCode::OK, "{version}: {init}");
        assert_eq!(
            init.pointer("/result/protocolVersion"),
            Some(&json!(version))
        );
        assert!(init.pointer("/result/capabilities/tools").is_some());
        assert!(init_headers.get("Mcp-Session-Id").is_none());
        assert_eq!(
            init_headers.get("Cache-Control").map(HeaderValue::as_bytes),
            Some(b"no-store".as_slice())
        );

        let initialized = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        let (notified, _, _) = send(&fixture, Some(version), Some(TOKEN), &initialized)
            .await
            .expect("initialized");
        assert_eq!(notified, StatusCode::ACCEPTED, "{version}");

        let list = json!({"jsonrpc":"2.0","id":2_u32,"method":"tools/list","params":{}});
        let (list_status, tools, _) = send(&fixture, Some(version), Some(TOKEN), &list)
            .await
            .expect("tools/list");
        assert_eq!(list_status, StatusCode::OK, "{version}: {tools}");
        let names: Vec<&Value> = tools
            .pointer("/result/tools")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(|tool| tool.get("name")).collect())
            .unwrap_or_default();
        assert_eq!(names, [&json!("search"), &json!("execute")]);

        let (call_status, result, _) = send(&fixture, Some(version), Some(TOKEN), &execute())
            .await
            .expect("tools/call");
        assert_eq!(call_status, StatusCode::OK, "{version}: {result}");
        assert_eq!(
            result.pointer("/result/structuredContent/data/count"),
            Some(&json!(3_i32))
        );
        assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
/// # Panics
///
/// Panics if a legacy request without a token reaches the handler or is answered
/// without the OAuth challenge.
async fn legacy_requests_need_the_same_authorization() {
    let fixture = Fixture::new().await.expect("fixture");
    for message in [initialize("2025-11-25"), execute()] {
        let (status, _, headers) = send(&fixture, Some("2025-11-25"), None, &message)
            .await
            .expect("response");
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{message}");
        assert!(headers.get("WWW-Authenticate").is_some());
    }
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
}

#[tokio::test]
/// # Panics
///
/// Panics if versions older than 2025-06-18, which lack the OAuth resource
/// indicator and structured tool results, start being accepted.
async fn versions_before_2025_06_18_are_refused() {
    let fixture = Fixture::new().await.expect("fixture");
    for version in ["2024-11-05", "2025-03-26"] {
        let (status, response, _) = send(&fixture, None, Some(TOKEN), &initialize(version))
            .await
            .expect("initialize");
        let negotiated = response.pointer("/result/protocolVersion");
        assert!(
            status != StatusCode::OK || negotiated != Some(&json!(version)),
            "{version} was accepted: {response}"
        );
    }
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
}
