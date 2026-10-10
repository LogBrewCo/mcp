//! Fail closed on invalid, unavailable, and mismatched delegated authority.

use core::sync::atomic::Ordering;

use axum::http::{HeaderMap, StatusCode};
use logbrew_mcp::clients::ClientAllowlist;
use serde_json::json;

use super::http::{Fixture, RESOURCE, TOKEN};

fn issuer_type_case(pattern: u8) -> String {
    b"Bearer"
        .iter()
        .zip([1_u8, 2, 4, 8, 16, 32])
        .map(|(byte, mask)| {
            char::from(if pattern & mask == 0 {
                byte.to_ascii_lowercase()
            } else {
                byte.to_ascii_uppercase()
            })
        })
        .collect()
}

#[tokio::test]
/// # Panics
///
/// Panics if a Bearer case variant fails, another token type permits execution,
/// recovery or revocation fails, or telemetry discloses private authority.
async fn issuer_token_type_case_variants_preserve_authorization() {
    let fixture = Fixture::new().await.expect("fixture");
    let base = fixture.authority().expect("issuer authority");
    let params = json!({"name":"execute",
        "arguments":{"operation":"logs.read.v1","input":{}}});
    // RFC 6749 section 5.1 makes token_type case insensitive; RFC 7662 uses it.
    for pattern in 0_u8..64_u8 {
        let token_type = issuer_type_case(pattern);
        let mut accepted = base.clone();
        *accepted.get_mut("token_type").expect("token type") = json!(token_type);
        fixture
            .introspection_reply(StatusCode::OK, accepted.to_string(), HeaderMap::new())
            .expect("issuer case variant");
        let (status, result) = fixture
            .request("tools/call", params.clone(), TOKEN)
            .await
            .expect("authorized case variant");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            result.pointer("/result/structuredContent/data/count"),
            Some(&json!(3_i32))
        );
    }
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 64);
    for token_type in [
        "",
        " Bearer",
        "Bearer ",
        "Bear er",
        "Bearer\t",
        "Bearer\n",
        "Bearer,DPoP",
        "Bearer token",
        "DPoP",
        "Beare\u{212a}",
        "Beare\u{0280}",
        "SYNTHETIC_PRIVATE_TOKEN_TYPE",
    ] {
        let mut rejected = base.clone();
        *rejected.get_mut("token_type").expect("token type") = json!(token_type);
        fixture
            .introspection_reply(StatusCode::OK, rejected.to_string(), HeaderMap::new())
            .expect("unaccepted issuer token type");
        assert_eq!(
            fixture
                .request("tools/call", params.clone(), TOKEN)
                .await
                .expect("type rejection")
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 64);
    }
    fixture
        .introspection_reply(StatusCode::OK, base.to_string(), HeaderMap::new())
        .expect("issuer type restored");
    assert_eq!(
        fixture
            .request("tools/call", params.clone(), TOKEN)
            .await
            .expect("recovery")
            .0,
        StatusCode::OK
    );
    let mut revoked = base;
    *revoked.get_mut("active").expect("active claim") = json!(false);
    fixture
        .introspection_reply(StatusCode::OK, revoked.to_string(), HeaderMap::new())
        .expect("revoked authority");
    assert_eq!(
        fixture
            .request("tools/call", params, TOKEN)
            .await
            .expect("revocation")
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 65);
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 78);
    let observations =
        serde_json::to_string(&fixture.telemetry().snapshot().expect("observations"))
            .expect("telemetry JSON");
    assert!(!observations.contains(TOKEN));
    assert!(!observations.contains("SYNTHETIC_PRIVATE"));
}

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
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 14);
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
    for (upstream_status, body) in [
        (StatusCode::SERVICE_UNAVAILABLE, "SYNTHETIC_PRIVATE_MARKER"),
        (StatusCode::OK, "{\"active\":true,\"active\":false}"),
        (StatusCode::OK, "[true]"),
        (StatusCode::OK, "{\"active\":true} trailing"),
    ] {
        fixture
            .introspection_reply(upstream_status, body.to_owned(), HeaderMap::new())
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
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 12);
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
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 1);
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
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 3);
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
}

/// # Errors
///
/// Returns an error if the fixture has no claim object or a synthetic response
/// header cannot be constructed.
fn invalid_authority_response(
    authority: &serde_json::Value,
    mode: i32,
) -> Result<(serde_json::Value, HeaderMap), Box<dyn core::error::Error + Send + Sync>> {
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
