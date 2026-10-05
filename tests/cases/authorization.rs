//! Fail closed on invalid, unavailable, and mismatched delegated authority.

use std::sync::atomic::Ordering;

use axum::http::{HeaderMap, StatusCode};
use logbrew_mcp::clients::ClientAllowlist;
use serde_json::json;

use super::http::{Fixture, RESOURCE, TOKEN};

#[tokio::test]
/// # Panics
///
/// Panics if fixture construction or introspection fails, invalid authority has
/// the wrong rejection status, or any rejected claim reaches execution.
async fn invalid_authority_claims_fail_closed_before_execution() {
    let clients = ClientAllowlist::decode(br#"{"version":"1","clients":["synthetic-client"]}"#)
        .expect("trusted client policy");
    let fixture = Fixture::with_clients(clients).await.expect("fixture");
    let base = fixture.authority().expect("valid synthetic authority");
    for (field, value, expected) in [
        ("active", json!(false), StatusCode::UNAUTHORIZED),
        ("active", json!("true"), StatusCode::SERVICE_UNAVAILABLE),
        ("exp", json!(0_i32), StatusCode::UNAUTHORIZED),
        ("exp", json!("invalid"), StatusCode::SERVICE_UNAVAILABLE),
        ("iat", json!(u64::MAX), StatusCode::UNAUTHORIZED),
        ("nbf", json!(u64::MAX), StatusCode::UNAUTHORIZED),
        (
            "iss",
            json!("https://foreign.example"),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "aud",
            json!("https://foreign.example/mcp"),
            StatusCode::UNAUTHORIZED,
        ),
        ("aud", json!([RESOURCE, 42_i32]), StatusCode::UNAUTHORIZED),
        ("scope", json!("different:scope"), StatusCode::FORBIDDEN),
        (
            "scope",
            json!("mcp:read  extra:scope"),
            StatusCode::UNAUTHORIZED,
        ),
        ("token_type", json!("different"), StatusCode::UNAUTHORIZED),
        (
            "jti",
            json!("invalid credential reference"),
            StatusCode::UNAUTHORIZED,
        ),
        ("client_id", json!(""), StatusCode::UNAUTHORIZED),
    ] {
        let mut claims = base.clone();
        drop(
            claims
                .as_object_mut()
                .expect("claim fields")
                .insert(field.to_owned(), value),
        );
        fixture
            .introspection_reply(StatusCode::OK, claims.to_string(), HeaderMap::new())
            .expect("authority reply");
        let (status, _) = fixture
            .request(
                "tools/call",
                json!({"name":"execute",
            "arguments":{"operation":"logs.read.v1","input":{}}}),
                TOKEN,
            )
            .await
            .expect("authorization result");
        assert_eq!(status, expected, "claim {field}");
    }
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 14);
}

#[tokio::test]
/// # Panics
///
/// Panics if setup fails, missing or unavailable authority permits execution,
/// introspection counts change, or a private upstream marker is returned.
async fn missing_or_unavailable_introspection_cannot_authorize_execution() {
    let fixture = Fixture::new().await.expect("fixture");
    let base = fixture.authority().expect("synthetic authority");
    for field in [
        "active",
        "exp",
        "iss",
        "aud",
        "scope",
        "token_type",
        "jti",
        "client_id",
    ] {
        let mut claims = base.clone();
        drop(claims.as_object_mut().expect("claims").remove(field));
        fixture
            .introspection_reply(StatusCode::OK, claims.to_string(), HeaderMap::new())
            .expect("incomplete authority");
        let (status, _) = fixture
            .request(
                "tools/call",
                json!({"name":"execute",
            "arguments":{"operation":"logs.read.v1","input":{}}}),
                TOKEN,
            )
            .await
            .expect("authorization result");
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "missing {field}");
    }
    for (status, body) in [
        (StatusCode::SERVICE_UNAVAILABLE, "SYNTHETIC_PRIVATE_MARKER"),
        (StatusCode::OK, "{\"active\":true,\"active\":false}"),
        (StatusCode::OK, "[true]"),
        (StatusCode::OK, "{\"active\":true} trailing"),
    ] {
        fixture
            .introspection_reply(status, body.to_owned(), HeaderMap::new())
            .expect("failed authority");
        let (status, response) = fixture
            .request(
                "tools/call",
                json!({"name":"execute",
            "arguments":{"operation":"logs.read.v1","input":{}}}),
                TOKEN,
            )
            .await
            .expect("authorization result");
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(!response.to_string().contains("SYNTHETIC_PRIVATE_MARKER"));
    }
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 12);
}

#[tokio::test]
/// # Panics
///
/// Panics if setup fails, valid audience and scope claims are rejected, or the
/// authorized result and execution count differ from the expected contract.
async fn bounded_audience_lists_and_explicit_scopes_allow_valid_authority() {
    let fixture = Fixture::new().await.expect("fixture");
    let mut claims = fixture.authority().expect("synthetic authority");
    drop(claims.as_object_mut().expect("claims").insert(
        "aud".to_owned(),
        json!(["https://other.example/mcp", RESOURCE]),
    ));
    drop(
        claims
            .as_object_mut()
            .expect("claims")
            .insert("scope".to_owned(), json!("extra:scope mcp:read")),
    );
    fixture
        .introspection_reply(StatusCode::OK, claims.to_string(), HeaderMap::new())
        .expect("valid authority");
    let (status, response) = fixture
        .request(
            "tools/call",
            json!({"name":"execute",
        "arguments":{"operation":"logs.read.v1","input":{}}}),
            TOKEN,
        )
        .await
        .expect("authorized execution");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response.pointer("/result/structuredContent/data/count"),
        Some(&json!(3_i32))
    );
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
/// # Panics
///
/// Panics if fixture construction fails, invalid introspection size, headers or
/// media type is accepted, or the rejected authority starts execution.
async fn introspection_payload_headers_and_media_type_are_bounded_before_authorization() {
    let fixture = Fixture::new().await.expect("fixture");
    let authority = fixture.authority().expect("valid authority");
    for mode in 0_i32..3_i32 {
        let (body, headers) =
            invalid_authority_response(&authority, mode).expect("invalid authority fixture");
        fixture
            .introspection_reply(StatusCode::OK, body.to_string(), headers)
            .expect("oversized authority response");
        let (status, _) = fixture
            .request(
                "tools/call",
                json!({"name":"execute",
            "arguments":{"operation":"logs.read.v1","input":{}}}),
                TOKEN,
            )
            .await
            .expect("authorization result");
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 3);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
}

/// # Errors
///
/// Returns an error if the fixture has no claim object or a synthetic response
/// header cannot be constructed.
fn invalid_authority_response(
    authority: &serde_json::Value,
    mode: i32,
) -> Result<(serde_json::Value, HeaderMap), Box<dyn std::error::Error + Send + Sync>> {
    let mut body = authority.clone();
    let mut headers = HeaderMap::new();
    match mode {
        0_i32 => {
            drop(
                body.as_object_mut()
                    .ok_or("claims")?
                    .insert("filler".to_owned(), json!("x".repeat(64 << 10))),
            );
        }
        1_i32 => {
            drop(headers.insert("x-synthetic-large", "x".repeat(17 << 10).parse()?));
        }
        _ => {
            drop(headers.insert(axum::http::header::CONTENT_TYPE, "text/plain".parse()?));
        }
    }
    Ok((body, headers))
}
