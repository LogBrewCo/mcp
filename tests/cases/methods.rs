//! Method errors preserve request IDs without returning rejected method values.

use std::{io, net::TcpListener, sync::atomic::Ordering};

use axum::{
    body::{Body, to_bytes},
    http::{HeaderValue, Request, StatusCode, Version},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::{
    http::{Fixture, TOKEN, request_message},
    runtime::Running,
};

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const PRIVATE_METHOD: &str = "SYNTHETIC_PRIVATE_METHOD";

fn malformed() -> Vec<(&'static str, Value)> {
    vec![
        (
            "tools/call",
            json!({"name":"execute","arguments":"SYNTHETIC_PRIVATE_ARGUMENTS"}),
        ),
        (
            "tools/call",
            json!({"name":"execute","arguments":["SYNTHETIC_PRIVATE_ARGUMENTS"]}),
        ),
        ("tools/list", json!({"cursor":["SYNTHETIC_PRIVATE_CURSOR"]})),
        (
            "tools/list",
            json!({"cursor":{"SYNTHETIC_PRIVATE_CURSOR":true}}),
        ),
        ("tools/list", json!({"cursor":"SYNTHETIC_PRIVATE_CURSOR"})),
        ("tools/list", json!({"cursor":""})),
        ("tools/list", json!({"cursor":null})),
        ("tools/list", json!({"cursor":true})),
        ("tools/list", json!({"cursor":1})),
    ]
}

async fn packet(method: &str, params: Value, id: &Value) -> TestResult<Request<Body>> {
    let mut request = request_message(0, method, params, TOKEN)?;
    let bytes = to_bytes(std::mem::take(request.body_mut()), 4096).await?;
    let mut value: Value = serde_json::from_slice(&bytes)?;
    drop(
        value
            .as_object_mut()
            .ok_or_else(|| io::Error::other("invalid fixture message"))?
            .insert("id".to_owned(), id.clone()),
    );
    *request.body_mut() = Body::from(serde_json::to_vec(&value)?);
    Ok(request)
}

fn assert_error(status: StatusCode, bytes: &[u8], id: &Value, code: i32) -> TestResult<()> {
    let expected = if code == -32_601_i32 {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::BAD_REQUEST
    };
    assert_eq!(status, expected);
    assert!(!String::from_utf8_lossy(bytes).contains("SYNTHETIC_PRIVATE_"));
    let error: Value = serde_json::from_slice(bytes)?;
    assert_eq!(error.get("id"), Some(id));
    assert_eq!(error.pointer("/error/code"), Some(&json!(code)));
    assert!(error.get("result").is_none());
    assert!(error.pointer("/error/data").is_none());
    Ok(())
}

#[tokio::test]
async fn unknown_method_errors_do_not_echo_the_method_and_preserve_exact_ids() -> TestResult<()> {
    let fixture = Fixture::new().await?;
    for id in [
        json!(1_i32),
        json!("opaque-request"),
        serde_json::from_str("184467440737095516160")?,
    ] {
        let response = fixture
            .router
            .clone()
            .oneshot(packet(PRIVATE_METHOD, json!({}), &id).await?)
            .await?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 4096).await?;
        assert_error(status, &bytes, &id, -32601)?;
    }
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn malformed_known_methods_return_invalid_params_without_execution() -> TestResult<()> {
    let fixture = Fixture::new().await?;
    for (method, params) in malformed() {
        let response = fixture
            .router
            .clone()
            .oneshot(packet(method, params, &json!(1_i32)).await?)
            .await?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 4096).await?;
        assert_error(status, &bytes, &json!(1_i32), -32602)?;
    }
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn absent_cursor_and_discovery_extensions_remain_valid() -> TestResult<()> {
    let fixture = Fixture::new().await?;
    for (method, params) in [
        ("tools/list", json!({})),
        (
            "server/discover",
            json!({"SYNTHETIC_PRIVATE_FIELD":"SYNTHETIC_PRIVATE_VALUE"}),
        ),
    ] {
        let response = fixture
            .router
            .clone()
            .oneshot(packet(method, params, &json!(1_i32)).await?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 32_768).await?;
        assert!(!String::from_utf8_lossy(&bytes).contains("SYNTHETIC_PRIVATE_"));
        let result: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(result.get("id"), Some(&json!(1_i32)));
        assert!(result.get("error").is_none());
        if method == "tools/list" {
            let tools = result
                .pointer("/result/tools")
                .and_then(Value::as_array)
                .ok_or_else(|| io::Error::other("missing tool inventory"))?;
            assert_eq!(tools.len(), 2);
            assert_eq!(
                tools.first().and_then(|tool| tool.get("name")),
                Some(&json!("search"))
            );
            assert_eq!(
                tools.get(1).and_then(|tool| tool.get("name")),
                Some(&json!("execute"))
            );
        }
    }
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

async fn wire(http2: bool) -> TestResult<()> {
    let address = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let authority = format!("localhost:{}", address.port());
    let fixture = Fixture::for_resource(format!("https://{authority}/mcp")).await?;
    let mut running = Running::at(address, fixture.router.clone(), &authority).await?;
    let (client, version) = if http2 {
        (running.http2_client()?, Version::HTTP_2)
    } else {
        (running.http1_client(), Version::HTTP_11)
    };
    let id: Value = serde_json::from_str("184467440737095516160")?;
    let mut cases = vec![(PRIVATE_METHOD, json!({}), -32_601_i32)];
    cases.extend(
        malformed()
            .into_iter()
            .map(|(method, params)| (method, params, -32_602_i32)),
    );
    for (method, params, code) in cases {
        let request = packet(method, params, &id).await?;
        let response = send(&client, &running, &authority, request).await?;
        assert_eq!(response.version(), version);
        assert_eq!(
            response.headers().get("Cache-Control"),
            Some(&HeaderValue::from_static("no-store"))
        );
        let status = response.status();
        let bytes = response.bytes().await?;
        assert_error(status, &bytes, &id, code)?;
        assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    }
    let request = packet(
        "tools/call",
        json!({"name":"execute","arguments":{"operation":"logs.read.v1","input":{}}}),
        &json!(1_i32),
    )
    .await?;
    let response = send(&client, &running, &authority, request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), version);
    let result: Value = response.json().await?;
    assert_eq!(
        result.pointer("/result/structuredContent/data/count"),
        Some(&json!(3_i32))
    );
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);
    running.stop.cancel();
    running.wait().await
}

async fn send(
    client: &reqwest::Client,
    running: &Running,
    authority: &str,
    request: Request<Body>,
) -> TestResult<reqwest::Response> {
    let (mut parts, body) = request.into_parts();
    drop(
        parts
            .headers
            .insert("Host", HeaderValue::from_str(authority)?),
    );
    Ok(client
        .post(format!("https://localhost:{}/mcp", running.address.port()))
        .headers(parts.headers)
        .body(to_bytes(body, 4096).await?)
        .send()
        .await?)
}

#[tokio::test]
async fn tls_http1_method_errors_are_private_and_execution_recovers() -> TestResult<()> {
    wire(false).await
}

#[tokio::test]
async fn tls_http2_method_errors_are_private_and_execution_recovers() -> TestResult<()> {
    wire(true).await
}
