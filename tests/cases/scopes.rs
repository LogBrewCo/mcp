//! Scope challenges guide recovery without overriding token or client validation.

use core::{sync::atomic::Ordering, time::Duration};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode},
};
use logbrew_mcp::{
    error::Kind,
    telemetry::{Outcome, Stage},
};
use serde_json::{Value, json};
use tokio::time::timeout;
use tower::ServiceExt as _;

use super::{
    http::{Fixture, TOKEN, request_message},
    raw_upstream::Raw,
};

type TestResult<T> = Result<T, Box<dyn core::error::Error + Send + Sync>>;
const METADATA: &str = "https://resource.example/.well-known/oauth-protected-resource/mcp";

#[tokio::test]
/// # Panics
///
/// Panics if the initial challenge or the protected resource metadata differs
/// from the exact RFC 9728 document naming the issuer and the `read` scope, or
/// if either starts upstream work.
async fn initial_challenge_and_metadata_name_the_issuer_and_read_scope() {
    let fixture = Fixture::new().await.expect("fixture");
    let challenge_request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Host", "resource.example")
        .body(Body::empty())
        .expect("unauthenticated request");
    let challenge_response = fixture
        .router()
        .clone()
        .oneshot(challenge_request)
        .await
        .expect("challenge");
    assert_eq!(challenge_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        challenge_response
            .headers()
            .get("WWW-Authenticate")
            .expect("challenge"),
        format!("Bearer resource_metadata=\"{METADATA}\", scope=\"read\"").as_str()
    );
    drop(challenge_response);
    let request = Request::builder()
        .uri("/.well-known/oauth-protected-resource/mcp")
        .header("Host", "resource.example")
        .body(Body::empty())
        .expect("metadata request");
    let response = fixture
        .router()
        .clone()
        .oneshot(request)
        .await
        .expect("public metadata");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 16 << 10)
        .await
        .expect("bounded metadata");
    let value: Value = serde_json::from_slice(&bytes).expect("metadata JSON");
    let claims = fixture.authority().expect("issuer claims");
    let issuer = claims.get("iss").expect("issuer");
    assert_eq!(
        value,
        json!({"resource":"https://resource.example/mcp","authorization_servers":[issuer],
            "bearer_methods_supported":["header"],"scopes_supported":["read"]})
    );
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
}

#[tokio::test]
/// # Panics
///
/// Panics if insufficient scope changes its status or challenge, starts execution,
/// fails recovery, changes upstream totals or leaks private telemetry.
async fn insufficient_scope_is_forbidden_with_a_complete_challenge_and_recovery() {
    let fixture = Fixture::new().await.expect("fixture");
    let base = fixture.authority().expect("issuer claims");
    let mut claims = base.clone();
    *claims.get_mut("scope").expect("scope claim") = json!("SYNTHETIC_PRIVATE_SCOPE");
    for (method, params) in [
        ("server/discover", json!({})),
        ("tools/list", json!({})),
        (
            "tools/call",
            json!({"name":"search","arguments":{"operation":"logs.read.v1"}}),
        ),
        (
            "tools/call",
            json!({"name":"execute","arguments":{"operation":"logs.read.v1","input":{}}}),
        ),
    ] {
        fixture
            .introspection_reply(StatusCode::OK, claims.to_string(), HeaderMap::new())
            .expect("insufficient grant");
        let request = request_message(1, method, params.clone(), TOKEN).expect("request");
        let response = fixture
            .router()
            .clone()
            .oneshot(request)
            .await
            .expect("scope challenge");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response
                .headers()
                .get_all("WWW-Authenticate")
                .iter()
                .count(),
            1
        );
        assert_eq!(
            response
                .headers()
                .get("WWW-Authenticate")
                .expect("challenge"),
            format!(
                "Bearer resource_metadata=\"{METADATA}\", scope=\"read\", error=\"insufficient_scope\""
            )
            .as_str()
        );
        assert_eq!(
            response
                .headers()
                .get("Cache-Control")
                .expect("cache bound"),
            "no-store"
        );
        let bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("bounded private denial");
        assert_eq!(bytes.as_ref(), b"insufficient scope");
        assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
        fixture
            .introspection_reply(StatusCode::OK, base.to_string(), HeaderMap::new())
            .expect("repaired grant");
        assert_eq!(
            fixture
                .request(method, params, TOKEN)
                .await
                .expect("recovery")
                .0,
            StatusCode::OK
        );
    }
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 1);
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 8);
    scope_observations(&fixture).expect("complete private observations");
}

/// # Errors
///
/// Returns a serialization error or an error if required stage and outcome observations are absent.
///
/// # Panics
///
/// Panics if stage totals, pending work, scope-denial counts or telemetry privacy changes.
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
fn scope_observations(fixture: &Fixture) -> TestResult<()> {
    let snapshot = fixture
        .telemetry()
        .snapshot()
        .ok_or("missing observations")?;
    for stage in [Stage::RequestPrepared, Stage::Introspection] {
        let stats = snapshot
            .stages
            .iter()
            .find(|stats| stats.stage == stage)
            .ok_or("missing stage")?;
        assert_eq!(stats.started, 8);
        assert_eq!(stats.finished, 8);
        assert_eq!(stats.pending, Some(0));
        assert_eq!(
            stats
                .outcomes
                .iter()
                .find(|count| count.outcome == Outcome::PermissionDenied)
                .ok_or("missing scope denials")?
                .count,
            4
        );
    }
    let text = serde_json::to_string(&snapshot)?;
    assert!(!text.contains("SYNTHETIC_PRIVATE_SCOPE"));
    assert!(!text.contains(TOKEN));
    Ok(())
}

#[tokio::test]
/// # Panics
///
/// Panics if missing scope overrides credential or client ID denials, changes
/// their challenge and body contracts, or permits execution.
async fn missing_scope_does_not_mask_invalid_credentials_or_client_ids() {
    let fixture = Fixture::new().await.expect("fixture");
    let mut claims = fixture.authority().expect("valid claims");
    *claims.get_mut("scope").expect("scope") = json!("other:scope");
    for (field, value) in [
        ("exp", json!(0_i32)),
        ("iss", json!("https://foreign.example")),
        ("aud", json!("https://foreign.example/mcp")),
        ("client_id", json!("SYNTHETIC_PRIVATE_CLIENT\t")),
    ] {
        let mut invalid = claims.clone();
        *invalid.get_mut(field).expect("claim") = value;
        fixture
            .introspection_reply(StatusCode::OK, invalid.to_string(), HeaderMap::new())
            .expect("denied claims");
        let response = fixture
            .router()
            .clone()
            .oneshot(request_message(1, "tools/list", json!({}), TOKEN).expect("request"))
            .await
            .expect("denial");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_invalid_token_challenge(response.headers()).expect("denial challenge");
        assert_eq!(
            to_bytes(response.into_body(), 1024)
                .await
                .expect("denial body")
                .as_ref(),
            b"unauthorized"
        );
    }
    drop(claims.as_object_mut().expect("claims").remove("scope"));
    fixture
        .introspection_reply(StatusCode::OK, claims.to_string(), HeaderMap::new())
        .expect("incomplete claim");
    assert_eq!(
        fixture
            .request("tools/list", json!({}), TOKEN)
            .await
            .expect("unavailable issuer")
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 5);
}

#[tokio::test]
/// # Errors
///
/// Returns a raw fixture, clock, JSON, queued exchange, token verification,
/// observation timeout or fixture shutdown error.
///
/// # Panics
///
/// Panics if allowed client identity, denied scope classification or retry guidance changes.
async fn direct_token_verification_classifies_scope_denial_and_recovers() -> TestResult<()> {
    let mut raw = Raw::new()?;
    let base = json!({"active":true,"exp":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 300,
        "iss":"https://issuer.example","aud":"https://resource.example/mcp","scope":"read",
        "token_type":"Bearer","jti":"synthetic-credential","client_id":"synthetic-client"});
    for scope in ["other:scope", "read"] {
        let mut claims = base.clone();
        *claims.get_mut("scope").ok_or("missing synthetic scope")? = json!(scope);
        let bytes = serde_json::to_vec(&claims)?;
        let headers = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).into_bytes();
        let done = raw.queue("/introspect", headers, Some(bytes)).await?;
        let result = timeout(Duration::from_secs(2), raw.upstream().verify(TOKEN)).await?;
        assert_verified_scope(scope, result)?;
        timeout(Duration::from_secs(2), done).await???;
    }
    raw.finish().await?;
    Ok(())
}

/// # Errors
///
/// Returns an error if the invalid-token challenge is absent or contains invalid header text.
///
/// # Panics
///
/// Panics if credential denial advertises insufficient scope or omits `invalid_token`.
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
fn assert_invalid_token_challenge(headers: &HeaderMap) -> TestResult<()> {
    let challenge = headers
        .get("WWW-Authenticate")
        .ok_or("challenge")?
        .to_str()?;
    assert!(!challenge.contains("insufficient_scope"));
    assert!(challenge.contains("error=\"invalid_token\""));
    Ok(())
}

/// # Errors
///
/// Returns a verification failure for the allowed scope or an error if a denied scope succeeds.
///
/// # Panics
///
/// Panics if allowed client identity, denied scope classification or retry guidance changes.
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
fn assert_verified_scope(
    scope: &str,
    result: Result<logbrew_mcp::upstream::Principal, logbrew_mcp::Failure>,
) -> TestResult<()> {
    if scope == "read" {
        assert_eq!(result?.client_id, "synthetic-client");
    } else {
        let failure = result.err().ok_or("insufficient grant accepted")?;
        assert_eq!(failure.kind, Kind::PermissionDenied);
        assert_eq!(failure.retry_after_ms, None);
    }
    Ok(())
}
