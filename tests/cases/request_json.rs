//! Unreadable messages keep protocol errors private and allow valid recovery.

use core::sync::atomic::Ordering;

use axum::{
    body::{Body, to_bytes},
    http::{StatusCode, header},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::http::{Fixture, TOKEN, request_message};

fn params() -> Value {
    json!({"name":"execute","arguments":{"operation":"logs.read.v1","input":{}}})
}

#[tokio::test]
/// # Panics
/// Fails if unreadable JSON loses its error code, reveals private bytes, starts
/// execution, changes response bounds, or prevents valid-request recovery.
async fn unreadable_json_returns_protocol_errors_and_recovers() {
    let fixture = Fixture::new().await.expect("fixture");
    for (bytes, code) in [
        (b"".as_slice(), -32_700_i32),
        (b" \r\n\t".as_slice(), -32_700_i32),
        (
            b"{\"private\":\"SYNTHETIC_PRIVATE_MARKER\"".as_slice(),
            -32_700_i32,
        ),
        (b"{\"private\":\"\xff\"}".as_slice(), -32_700_i32),
        (b"{} {}".as_slice(), -32_700_i32),
        (b"[]".as_slice(), -32_600_i32),
        (b"[{},{}]".as_slice(), -32_600_i32),
        (b"\"SYNTHETIC_PRIVATE_MARKER\"".as_slice(), -32_600_i32),
        (b"null".as_slice(), -32_600_i32),
        (
            b"{\"private\":1,\"priv\\u0061te\":2}".as_slice(),
            -32_600_i32,
        ),
    ] {
        let mut request = request_message(1, "tools/call", params(), TOKEN).expect("request");
        *request.body_mut() = Body::from(bytes.to_vec());
        let response = fixture
            .router()
            .clone()
            .oneshot(request)
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).expect("type"),
            "application/json"
        );
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .expect("cache"),
            "no-store"
        );
        let response_bytes = to_bytes(response.into_body(), 256)
            .await
            .expect("bounded error");
        let value: Value = serde_json::from_slice(&response_bytes).expect("protocol error");
        assert_eq!(value.get("jsonrpc"), Some(&json!("2.0")));
        assert_eq!(value.pointer("/error/code"), Some(&json!(code)));
        assert!(value.get("id").is_none());
        assert!(value.get("result").is_none());
        assert!(value.pointer("/error/data").is_none());
        assert!(!String::from_utf8_lossy(&response_bytes).contains("SYNTHETIC_PRIVATE_MARKER"));
        assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
    }
    let (status, result) = fixture
        .request("tools/call", params(), TOKEN)
        .await
        .expect("recovery");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        result.pointer("/result/structuredContent/data/count"),
        Some(&json!(3_i32))
    );
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 1);
}
