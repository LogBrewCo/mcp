//! Current protocol metadata, HTTP errors and rejected-payload privacy.

use core::sync::atomic::Ordering;

use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::http::{Fixture, TOKEN};

type TestResult<T> = Result<T, Box<dyn core::error::Error + Send + Sync>>;

fn body() -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        "name":"execute","arguments":{"operation":"logs.read.v1","input":{}},"_meta":{
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientInfo":{"name":"synthetic","version":"1"},
            "io.modelcontextprotocol/clientCapabilities":{}}}})
}

/// # Errors
///
/// Returns an HTTP request construction error.
fn request(value: &Value) -> Result<Request<Body>, axum::http::Error> {
    Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Host", "resource.example")
        .header("Authorization", format!("Bearer {TOKEN}"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "execute")
        .body(Body::from(value.to_string()))
}

/// # Errors
///
/// Returns a router or bounded response-body read error.
async fn response(
    fixture: &Fixture,
    request: Request<Body>,
) -> TestResult<(StatusCode, Value, Vec<u8>, HeaderMap)> {
    let response = fixture.router().clone().oneshot(request).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 5 << 20).await?.to_vec();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Ok((status, value, bytes, headers))
}

#[tokio::test]
/// # Panics
///
/// Panics if unsupported versions change their negotiation status, code, requested
/// or supported versions, start execution, or prevent supported-version recovery.
async fn unsupported_versions_return_modern_negotiation_errors() {
    let fixture = Fixture::new().await.expect("fixture");
    for version in [
        "1900-01-01",
        "2024-11-05",
        "2025-03-26",
        "2025-06-18",
        "2025-11-25",
    ] {
        let mut value = body();
        *value
            .pointer_mut("/params/_meta/io.modelcontextprotocol~1protocolVersion")
            .expect("version") = json!(version);
        let mut request = request(&value).expect("request");
        drop(request.headers_mut().insert(
            "mcp-protocol-version",
            version.parse().expect("version header"),
        ));
        let (status, response, _, _) = response(&fixture, request)
            .await
            .expect("negotiation response");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response.pointer("/error/code"), Some(&json!(-32_022_i32)));
        assert_eq!(
            response.pointer("/error/data/requested"),
            Some(&json!(version))
        );
        assert_eq!(
            response.pointer("/error/data/supported"),
            Some(&json!(["2026-07-28"]))
        );
        assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
    }
    let (status, response) = fixture
        .request(
            "tools/call",
            json!({"name":"execute","arguments":{"operation":"logs.read.v1","input":{}}}),
            TOKEN,
        )
        .await
        .expect("supported version recovery");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response.pointer("/result/structuredContent/data/count"),
        Some(&json!(3_i32))
    );
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 1);
}

#[tokio::test]
/// # Panics
///
/// Panics if missing, conflicting or duplicate routing headers change their error
/// contract or start execution.
async fn missing_mismatched_and_duplicate_routing_headers_fail_before_execution() {
    let fixture = Fixture::new().await.expect("fixture");
    for (name, value, append) in [
        ("mcp-protocol-version", None, false),
        ("mcp-method", None, false),
        ("mcp-name", None, false),
        ("mcp-protocol-version", Some("2025-11-25"), false),
        ("mcp-method", Some("tools/list"), false),
        ("mcp-name", Some("search"), false),
        ("mcp-method", Some("tools/call"), true),
        ("mcp-name", Some("execute"), true),
        ("mcp-protocol-version", Some("2025-11-25"), true),
        ("mcp-protocol-version", Some("2026-07-28"), true),
    ] {
        let mut request = request(&body()).expect("request");
        modify_header(&mut request, name, value, append).expect("header value");
        let (status, response, _, _) = response(&fixture, request)
            .await
            .expect("header validation");
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}: {value:?}");
        assert_eq!(response.pointer("/error/code"), Some(&json!(-32_020_i32)));
    }
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
}

#[tokio::test]
/// # Errors
///
/// Returns a fixture, JSON, request, header, router or body-read error.
///
/// # Panics
///
/// Panics if header mismatch loses exact correlation, reflects rejected values,
/// starts execution, or prevents valid-request recovery.
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
async fn header_mismatch_errors_preserve_correlation_without_echoing_rejected_fields()
-> TestResult<()> {
    let fixture = Fixture::new().await?;
    let marker = "SYNTHETIC_REJECTED_PRIVATE_FIELD";
    let mut reflected = Vec::new();
    for id in [
        json!(1_i32),
        json!("correlation"),
        serde_json::from_str("18446744073709551616")?,
    ] {
        reflected.extend(reflected_headers(&fixture, &id, marker).await?);
    }
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
    let (status, result, _, _) = response(&fixture, request(&body())?).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        result.pointer("/result/structuredContent/data/count"),
        Some(&json!(3_i32))
    );
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 1);
    assert!(
        reflected.is_empty(),
        "rejected fields reflected: {reflected:?}"
    );
    Ok(())
}

/// # Errors
///
/// Returns a request, header, router or body-read error, or an error if the fixture ID is absent.
///
/// # Panics
///
/// Panics if mismatched routing headers change their status, error code or exact ID.
async fn reflected_headers(
    fixture: &Fixture,
    id: &Value,
    marker: &str,
) -> TestResult<Vec<&'static str>> {
    let mut reflected = Vec::new();
    for name in ["mcp-method", "mcp-name"] {
        let mut value = body();
        *value.get_mut("id").ok_or("missing request ID")? = id.clone();
        let mut request = request(&value)?;
        drop(
            request
                .headers_mut()
                .insert(axum::http::HeaderName::from_static(name), marker.parse()?),
        );
        let (status, error, bytes, _) = response(fixture, request).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error.pointer("/error/code"), Some(&json!(-32_020_i32)));
        assert_eq!(error.get("id"), Some(id));
        if String::from_utf8_lossy(&bytes).contains(marker) {
            reflected.push(name);
        }
    }
    Ok(reflected)
}

#[tokio::test]
/// # Panics
///
/// Panics if incomplete required client metadata changes its rejection contract or starts execution.
async fn every_current_request_requires_complete_client_metadata() {
    let fixture = Fixture::new().await.expect("fixture");
    for field in [
        "io.modelcontextprotocol/protocolVersion",
        "io.modelcontextprotocol/clientCapabilities",
    ] {
        let mut value = body();
        drop(
            value
                .pointer_mut("/params/_meta")
                .and_then(Value::as_object_mut)
                .expect("metadata")
                .remove(field),
        );
        let (status, response, _, _) = response(&fixture, request(&value).expect("request"))
            .await
            .expect("metadata validation");
        assert_eq!(status, StatusCode::BAD_REQUEST, "{field}");
        assert_eq!(response.pointer("/error/code"), Some(&json!(-32_602_i32)));
    }
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
}

#[tokio::test]
/// # Panics
///
/// Panics if omission of optional client identity prevents an authorized execution.
async fn optional_client_identity_is_not_required_for_authorized_execution() {
    let fixture = Fixture::new().await.expect("fixture");
    let mut value = body();
    drop(
        value
            .pointer_mut("/params/_meta")
            .and_then(Value::as_object_mut)
            .expect("metadata")
            .remove("io.modelcontextprotocol/clientInfo"),
    );
    let (status, result, _, _) = response(&fixture, request(&value).expect("request"))
        .await
        .expect("optional client identity");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        result.pointer("/result/structuredContent/data/count"),
        Some(&json!(3_i32))
    );
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 1);
}

#[tokio::test]
/// # Panics
///
/// Panics if unknown methods change their status or error code, or start execution.
async fn unknown_methods_return_a_modern_error_without_extra_capabilities() {
    let fixture = Fixture::new().await.expect("fixture");
    let mut value = body();
    *value.get_mut("method").expect("method") = json!("unknown/method");
    let mut request = request(&value).expect("request");
    drop(request.headers_mut().insert(
        "mcp-method",
        "unknown/method".parse().expect("method header"),
    ));
    let (status, response, _, _) = response(&fixture, request).await.expect("unknown method");
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(response.pointer("/error/code"), Some(&json!(-32_601_i32)));
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
}

#[tokio::test]
/// # Panics
///
/// Panics if invalid media or Accept fields change their rejection status or start execution.
async fn invalid_media_types_and_accept_values_do_not_reach_execution() {
    let fixture = Fixture::new().await.expect("fixture");
    for (name, value, expected) in [
        (
            "content-type",
            "text/plain",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            "content-type",
            "application/json-invalid",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            "content-type",
            "application/json; broken",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            "content-type",
            "application/json; profile=\"unterminated",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            "content-type",
            "application/json; profile=\"good\"junk",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            "content-type",
            "application/json; profile=bad value",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            "content-type",
            "application/json; =missing",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        ("accept", "application/json", StatusCode::NOT_ACCEPTABLE),
        ("accept", "text/event-stream", StatusCode::NOT_ACCEPTABLE),
        ("accept", "*/*", StatusCode::NOT_ACCEPTABLE),
        (
            "accept",
            "application/json-invalid, text/event-stream",
            StatusCode::NOT_ACCEPTABLE,
        ),
        (
            "accept",
            "application/json, text/event-stream-invalid",
            StatusCode::NOT_ACCEPTABLE,
        ),
        (
            "accept",
            "application/json;q=0, text/event-stream",
            StatusCode::NOT_ACCEPTABLE,
        ),
        (
            "accept",
            "application/json, text/event-stream;q=0",
            StatusCode::NOT_ACCEPTABLE,
        ),
        (
            "accept",
            "application/json;q=2, text/event-stream",
            StatusCode::NOT_ACCEPTABLE,
        ),
        (
            "accept",
            "application/json;q=0.0001, text/event-stream",
            StatusCode::NOT_ACCEPTABLE,
        ),
        (
            "accept",
            "application/json;q=1;q=0, text/event-stream",
            StatusCode::NOT_ACCEPTABLE,
        ),
    ] {
        let mut request = request(&body()).expect("request");
        drop(request.headers_mut().insert(
            axum::http::HeaderName::from_static(name),
            value.parse().expect("header value"),
        ));
        let (status, _, _, _) = response(&fixture, request).await.expect("media validation");
        assert_eq!(status, expected, "{name}: {value}");
    }
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
}

#[tokio::test]
/// # Panics
///
/// Panics if absent or duplicate Content-Type, or absent Accept, is accepted or starts execution.
async fn absent_or_duplicate_content_type_and_absent_accept_are_rejected() {
    let fixture = Fixture::new().await.expect("fixture");
    for (name, duplicate, expected) in [
        ("content-type", false, StatusCode::UNSUPPORTED_MEDIA_TYPE),
        ("content-type", true, StatusCode::UNSUPPORTED_MEDIA_TYPE),
        ("accept", false, StatusCode::NOT_ACCEPTABLE),
    ] {
        let mut request = request(&body()).expect("request");
        modify_header(
            &mut request,
            name,
            duplicate.then_some("application/json"),
            duplicate,
        )
        .expect("header value");
        let (status, _, _, _) = response(&fixture, request).await.expect("media validation");
        assert_eq!(status, expected);
    }
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
}

#[tokio::test]
/// # Panics
///
/// Panics if legacy methods are accepted, the allowed method changes, session state
/// is returned, rejected legacy values leak, or a stateless execution fails.
async fn current_transport_ignores_legacy_session_and_resume_headers() {
    let fixture = Fixture::new().await.expect("fixture");
    for method in ["GET", "DELETE"] {
        let mut request = request(&body()).expect("request");
        *request.method_mut() = method.parse().expect("HTTP method");
        let (status, _, _, headers) = response(&fixture, request).await.expect("legacy method");
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(headers.get("Allow").expect("allowed method"), "POST");
        assert!(headers.get("Mcp-Session-Id").is_none());
    }
    let mut request = request(&body()).expect("request");
    drop(request.headers_mut().insert(
        "mcp-session-id",
        "SYNTHETIC_OLD_SESSION".parse().expect("session"),
    ));
    drop(request.headers_mut().insert(
        "last-event-id",
        "SYNTHETIC_OLD_EVENT".parse().expect("event"),
    ));
    let (status, _, bytes, headers) = response(&fixture, request)
        .await
        .expect("stateless request");
    assert_eq!(status, StatusCode::OK);
    assert!(headers.get("Mcp-Session-Id").is_none());
    assert!(!String::from_utf8_lossy(&bytes).contains("SYNTHETIC_OLD_"));
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 1);
}

#[tokio::test]
/// # Panics
///
/// Panics if encoded tool-name validation changes its status, error code or execution total.
async fn encoded_tool_names_are_decoded_before_matching_the_body() {
    let fixture = Fixture::new().await.expect("fixture");
    for (name, expected) in [
        ("=?base64?ZXhlY3V0ZQ==?=", StatusCode::OK),
        ("=?base64?%%%?=", StatusCode::BAD_REQUEST),
        ("=?BASE64?ZXhlY3V0ZQ==?=", StatusCode::BAD_REQUEST),
        ("Execute", StatusCode::BAD_REQUEST),
    ] {
        let mut request = request(&body()).expect("request");
        drop(
            request
                .headers_mut()
                .insert("mcp-name", name.parse().expect("name")),
        );
        let (status, value, _, _) = response(&fixture, request).await.expect("encoded header");
        assert_eq!(status, expected, "{name}");
        assert_header_result(status, &value);
    }
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 1);
}

#[tokio::test]
/// # Panics
///
/// Panics if malformed message shapes are accepted, disclose private values or start execution.
async fn malformed_message_shapes_never_reach_execution_or_echo_private_values() {
    let fixture = Fixture::new().await.expect("fixture");
    for value in [
        json!([body()]),
        json!({"jsonrpc":"2.0","id":1_i32,"result":{"private":"SYNTHETIC_PRIVATE_MARKER"}}),
        json!({"jsonrpc":"2.0","id":1_i32,"error":{"code":-32_603_i32,"message":"SYNTHETIC_PRIVATE_MARKER"}}),
        json!("SYNTHETIC_PRIVATE_MARKER"),
        {
            let mut value = body();
            *value.get_mut("id").expect("id") = Value::Null;
            value
        },
        {
            let mut value = body();
            *value.get_mut("id").expect("id") = json!(1.5_f64);
            value
        },
    ] {
        let (status, _, bytes, _) = response(&fixture, request(&value).expect("request"))
            .await
            .expect("invalid message");
        assert!(status.is_client_error(), "{status}");
        assert!(!String::from_utf8_lossy(&bytes).contains("SYNTHETIC_PRIVATE_MARKER"));
    }
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
}

#[tokio::test]
/// # Panics
///
/// Panics if valid media casing, parameters or separate Accept fields prevent execution.
async fn valid_media_types_support_case_parameters_and_multiple_accept_fields() {
    let fixture = Fixture::new().await.expect("fixture");
    for (content_type, accepts) in [
        (
            "Application/JSON; Charset=\"utf-8\"",
            vec!["Application/JSON, Text/Event-Stream"],
        ),
        (
            "application/json; profile=\"synthetic,profile\"",
            vec!["application/json", "text/event-stream"],
        ),
        (
            "application/json",
            vec!["application/json;q=0.5, text/event-stream;q=1.000"],
        ),
        (
            "application/json",
            vec!["application/json;profile=\"a,b\", text/event-stream"],
        ),
        (
            "application/json \t;\tcharset=utf-8",
            vec!["application/json, text/event-stream"],
        ),
        (
            "application/json; profile=\"a;\\\"b\"",
            vec!["application/json, text/event-stream"],
        ),
        (
            "application/json;; charset=\"\"",
            vec!["application/json, text/event-stream"],
        ),
    ] {
        let mut request = request(&body()).expect("request");
        drop(
            request
                .headers_mut()
                .insert("content-type", content_type.parse().expect("content type")),
        );
        drop(request.headers_mut().remove("accept"));
        append_values(request.headers_mut(), "accept", accepts).expect("accept fields");
        let (status, result, _, _) = response(&fixture, request).await.expect("media request");
        assert_eq!(status, StatusCode::OK, "{content_type}");
        assert_eq!(
            result.pointer("/result/structuredContent/data/count"),
            Some(&json!(3_i32))
        );
    }
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 7);
}

/// # Errors
///
/// Returns a header-value parse error when inserting or appending a value.
fn modify_header(
    request: &mut Request<Body>,
    name: &'static str,
    value: Option<&str>,
    append: bool,
) -> TestResult<()> {
    let name = axum::http::HeaderName::from_static(name);
    if let Some(value) = value {
        let value = value.parse()?;
        if append {
            let _: bool = request.headers_mut().append(name, value);
        } else {
            drop(request.headers_mut().insert(name, value));
        }
    } else {
        drop(request.headers_mut().remove(&name));
    }
    Ok(())
}

/// # Panics
///
/// Panics if a client-error response has a different routing-header error code.
fn assert_header_result(status: StatusCode, value: &Value) {
    if status.is_client_error() {
        assert_eq!(value.pointer("/error/code"), Some(&json!(-32_020_i32)));
    }
}

/// # Errors
///
/// Returns a header-value parse error when appending a field.
fn append_values(headers: &mut HeaderMap, name: &'static str, values: Vec<&str>) -> TestResult<()> {
    for value in values {
        let _: bool = headers.append(name, value.parse()?);
    }
    Ok(())
}

#[tokio::test]
/// # Panics
///
/// Panics if invalid protocol fields are accepted, echoed in the response or start execution.
async fn invalid_protocol_fields_do_not_echo_rejected_private_values() {
    let fixture = Fixture::new().await.expect("fixture");
    for (path, expected) in [
        ("/params/arguments", StatusCode::OK),
        (
            "/params/_meta/io.modelcontextprotocol~1clientCapabilities",
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let mut value = body();
        *value.pointer_mut(path).expect("field") = json!("SYNTHETIC_PRIVATE_MARKER");
        let (status, error, bytes, _) = response(&fixture, request(&value).expect("request"))
            .await
            .expect("malformed request");
        assert_eq!(status, expected, "{path}");
        assert_eq!(error.pointer("/error/code"), Some(&json!(-32_602_i32)));
        assert!(error.get("result").is_none());
        assert!(!String::from_utf8_lossy(&bytes).contains("SYNTHETIC_PRIVATE_MARKER"));
    }
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
}
