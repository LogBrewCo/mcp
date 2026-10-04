//! Exact request/response correlation across the bounded JSON integer range.

use std::{net::TcpListener, sync::atomic::Ordering, time::Duration};

use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::{
    http::{Fixture, TOKEN, request_message},
    runtime::Running,
};

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn payload(id: &str, method: &str) -> TestResult<Value> {
    let id: Value = serde_json::from_str(id)?;
    let meta = json!({
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientCapabilities":{}});
    let params = if method == "tools/call" {
        json!({"_meta":meta,"name":"execute","arguments":{"operation":"logs.read.v1","input":{}}})
    } else {
        json!({"_meta":meta})
    };
    Ok(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
}

fn request(value: &Value) -> TestResult<Request<Body>> {
    let method = value
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| std::io::Error::other("missing method"))?;
    let mut request = request_message(1, method, json!({}), TOKEN)?;
    drop(
        request.headers_mut().insert(
            "mcp-name",
            value
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .parse()?,
        ),
    );
    *request.body_mut() = Body::from(value.to_string());
    Ok(request)
}

async fn reply(fixture: &Fixture, request: Request<Body>) -> TestResult<(StatusCode, Value)> {
    let response = fixture.router.clone().oneshot(request).await?;
    let status = response.status();
    assert_eq!(
        response
            .headers()
            .get("Cache-Control")
            .map(axum::http::HeaderValue::as_bytes),
        Some(b"no-store".as_slice())
    );
    let bytes = to_bytes(response.into_body(), 8 << 20).await?;
    assert!(!String::from_utf8_lossy(&bytes).contains(TOKEN));
    Ok((status, serde_json::from_slice(&bytes)?))
}

async fn succeeds(fixture: &Fixture, raw: &str, method: &str) -> TestResult<()> {
    let body = payload(raw, method)?;
    let (status, response) = reply(fixture, request(&body)?).await?;
    assert_eq!(status, StatusCode::OK, "identifier {raw}");
    assert_eq!(response.get("id"), body.get("id"));
    assert_eq!(
        response.pointer("/result/resultType"),
        Some(&json!("complete"))
    );
    if method == "tools/call" {
        assert_eq!(
            response.pointer("/result/structuredContent/data/count"),
            Some(&json!(3_i32))
        );
    }
    Ok(())
}

#[tokio::test]
async fn signed_integers_and_string_ids_preserve_their_type_and_value() -> TestResult<()> {
    let fixture = Fixture::new().await?;
    for raw in [
        "-9223372036854775808",
        "-9007199254740991",
        "-1",
        "0",
        "9223372036854775807",
        r#""-1""#,
        r#""""#,
        "\"client-\u{3bb}\"",
    ] {
        succeeds(&fixture, raw, "tools/call").await?;
    }
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 8);
    Ok(())
}

#[tokio::test]
async fn large_integer_ids_round_trip_through_discovery_and_execution() -> TestResult<()> {
    let fixture = Fixture::new().await?;
    let maximum = format!("1{}", "0".repeat(255));
    let minimum = format!("-1{}", "0".repeat(254));
    for raw in [
        "9223372036854775808",
        "18446744073709551615",
        "18446744073709551616",
        "-9223372036854775809",
        maximum.as_str(),
        minimum.as_str(),
    ] {
        succeeds(&fixture, raw, "server/discover").await?;
        succeeds(&fixture, raw, "tools/call").await?;
    }
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 12);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 6);
    Ok(())
}

#[tokio::test]
async fn exact_integral_decimal_and_exponent_ids_round_trip() -> TestResult<()> {
    let fixture = Fixture::new().await?;
    for raw in [
        "1.0",
        "-0.0",
        "1e3",
        "1200e-2",
        "0.0100e2",
        "-1e1024",
        "0e-1024",
        "9007199254740993.000",
    ] {
        succeeds(&fixture, raw, "tools/call").await?;
    }
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 8);
    Ok(())
}

#[tokio::test]
async fn protocol_errors_echo_large_integer_ids_without_changing_their_type() -> TestResult<()> {
    let fixture = Fixture::new().await?;
    for raw in [
        "9223372036854775808",
        "18446744073709551616",
        "-9223372036854775809",
    ] {
        let mut body = payload(raw, "tools/call")?;
        *body
            .pointer_mut("/params/_meta/io.modelcontextprotocol~1protocolVersion")
            .ok_or_else(|| std::io::Error::other("missing protocol version"))? =
            json!("1900-01-01");
        let mut call = request(&body)?;
        drop(
            call.headers_mut()
                .insert("mcp-protocol-version", "1900-01-01".parse()?),
        );
        let (status, response) = reply(&fixture, call).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response.pointer("/error/code"), Some(&json!(-32_022_i32)));
        assert_eq!(response.get("id"), body.get("id"));
        let body = payload(raw, "unknown/method")?;
        let (status, response) = reply(&fixture, request(&body)?).await?;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(response.pointer("/error/code"), Some(&json!(-32_601_i32)));
        assert_eq!(response.get("id"), body.get("id"));
    }
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn fractional_ids_are_not_rounded_into_integer_ids_before_execution() -> TestResult<()> {
    let fixture = Fixture::new().await?;
    for raw in [
        "1.5",
        "1e-1024",
        "100e-3",
        "9007199254740992.5",
        "1.0000000000000000000000000000000000000000000000000000000000001",
    ] {
        let body = payload(raw, "tools/call")?;
        let (status, response) = reply(&fixture, request(&body)?).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response.pointer("/error/code"), Some(&json!(-32_600_i32)));
        assert!(response.get("id").is_none());
    }
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 5);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

async fn wire_reply(
    client: &reqwest::Client,
    resource: &str,
    body: Value,
    version: reqwest::Version,
) -> TestResult<()> {
    let response = client
        .post(resource)
        .header("Authorization", format!("Bearer {TOKEN}"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "execute")
        .body(body.to_string())
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), version);
    assert!(response.headers().get("Mcp-Session-Id").is_none());
    assert_eq!(
        response
            .headers()
            .get("Cache-Control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let bytes = response.bytes().await?;
    assert!(!String::from_utf8_lossy(&bytes).contains("SYNTHETIC_"));
    let reply: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(reply.get("id"), body.get("id"));
    assert_eq!(
        reply.pointer("/result/structuredContent/data/count"),
        Some(&json!(3_i32))
    );
    Ok(())
}

#[tokio::test]
async fn simultaneous_tls_http1_and_http2_requests_keep_independent_numeric_ids() -> TestResult<()>
{
    let address = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let authority = format!("localhost:{}", address.port());
    let resource = format!("https://{authority}/mcp");
    let fixture = Fixture::for_resource(resource.clone()).await?;
    fixture.state.pause.store(true, Ordering::SeqCst);
    let mut running = Running::at(address, fixture.router.clone(), &authority).await?;
    let http1 = running.http1_client();
    let http2 = running.http2_client()?;
    let release = async {
        super::runtime::wait_executions(&fixture, 4, Duration::from_secs(2)).await?;
        fixture.state.release.notify_waiters();
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    };
    tokio::try_join!(
        wire_reply(
            &http1,
            &resource,
            payload("18446744073709551616", "tools/call")?,
            reqwest::Version::HTTP_11
        ),
        wire_reply(
            &http2,
            &resource,
            payload("-9223372036854775809", "tools/call")?,
            reqwest::Version::HTTP_2
        ),
        wire_reply(
            &http1,
            &resource,
            payload("1e1024", "tools/call")?,
            reqwest::Version::HTTP_11
        ),
        wire_reply(
            &http2,
            &resource,
            payload(r#""logbrew-integer-id""#, "tools/call")?,
            reqwest::Version::HTTP_2
        ),
        release,
    )?;
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 4);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 4);
    assert_eq!(fixture.state.active_executions.load(Ordering::SeqCst), 0);
    running.stop.cancel();
    running.wait().await?;
    Ok(())
}

#[tokio::test]
async fn adapted_ids_preserve_maximum_escaped_output_and_reject_one_more_byte() -> TestResult<()> {
    let fixture = Fixture::new().await?;
    let empty = json!({"blob":"","count":3_i32}).to_string();
    for size in [logbrew_mcp::OUTPUT_BYTES, logbrew_mcp::OUTPUT_BYTES + 1] {
        let remaining = size - empty.len();
        let mut blob = "\"".repeat(remaining / 2);
        blob.extend(std::iter::repeat_n('x', remaining % 2));
        let body = json!({"blob":blob,"count":3_i32}).to_string();
        assert_eq!(body.len(), size);
        fixture.reply(StatusCode::OK, body, HeaderMap::new())?;
        let call = payload("18446744073709551616", "tools/call")?;
        let (status, response) = reply(&fixture, request(&call)?).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response.get("id"), call.get("id"));
        let content = response
            .pointer("/result/structuredContent")
            .ok_or_else(|| std::io::Error::other("missing structured result"))?;
        let text = response
            .pointer("/result/content/0/text")
            .and_then(Value::as_str)
            .ok_or_else(|| std::io::Error::other("missing text result"))?;
        assert_eq!(
            &logbrew_mcp::json::object(text.as_bytes(), logbrew_mcp::ENVELOPE_BYTES)?,
            content
        );
        super::http::assert_output_budget(content, size)?;
    }
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 2);
    Ok(())
}
