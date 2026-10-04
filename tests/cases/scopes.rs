//! Scope challenges guide recovery without overriding token or client validation.

use std::{
    sync::atomic::Ordering,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode},
};
use logbrew_mcp::{
    clients::ClientAllowlist,
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

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const METADATA: &str = "https://resource.example/.well-known/oauth-protected-resource/mcp";

#[tokio::test]
async fn initial_challenge_and_metadata_advertise_only_the_configured_resource_scope() {
    for scope in [
        "mcp:read".to_owned(),
        "logs:read,extra=!$&'()*+[]{}".to_owned(),
        "s".repeat(8192),
    ] {
        let fixture = Fixture::with_scope(scope.clone()).await.expect("fixture");
        let request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("Host", "resource.example")
            .body(Body::empty())
            .expect("unauthenticated request");
        let response = fixture
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("challenge");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get("WWW-Authenticate")
                .expect("challenge"),
            format!("Bearer resource_metadata=\"{METADATA}\", scope=\"{scope}\"").as_str()
        );
        assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 0);
        drop(response);
        let request = Request::builder()
            .uri("/.well-known/oauth-protected-resource/mcp")
            .header("Host", "resource.example")
            .body(Body::empty())
            .expect("metadata request");
        let response = fixture
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("public metadata");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 16 << 10)
            .await
            .expect("bounded metadata");
        let value: Value = serde_json::from_slice(&bytes).expect("metadata JSON");
        assert_eq!(value.get("scopes_supported"), Some(&json!([scope])));
        assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    }
    assert!(
        Fixture::with_scope("offline_access".to_owned())
            .await
            .is_err()
    );
}

#[tokio::test]
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
            .router
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
                "Bearer resource_metadata=\"{METADATA}\", scope=\"mcp:read\", error=\"insufficient_scope\""
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
        assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
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
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 8);
    scope_observations(&fixture).expect("complete private observations");
}

fn scope_observations(fixture: &Fixture) -> TestResult<()> {
    let snapshot = fixture.telemetry.snapshot().ok_or("missing observations")?;
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
async fn missing_scope_does_not_mask_invalid_credentials_or_client_policy_denials() {
    let policy = ClientAllowlist::decode(br#"{"version":"1","clients":["synthetic-client"]}"#)
        .expect("policy");
    let fixture = Fixture::with_clients(policy).await.expect("fixture");
    let mut claims = fixture.authority().expect("valid claims");
    *claims.get_mut("scope").expect("scope") = json!("other:scope");
    for (field, value, expected, body) in [
        (
            "exp",
            json!(0_i32),
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        ),
        (
            "iss",
            json!("https://foreign.example"),
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        ),
        (
            "aud",
            json!("https://foreign.example/mcp"),
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        ),
        (
            "client_id",
            json!("SYNTHETIC_PRIVATE_CLIENT"),
            StatusCode::FORBIDDEN,
            "client access denied",
        ),
    ] {
        let mut invalid = claims.clone();
        *invalid.get_mut(field).expect("claim") = value;
        fixture
            .introspection_reply(StatusCode::OK, invalid.to_string(), HeaderMap::new())
            .expect("denied claims");
        let response = fixture
            .router
            .clone()
            .oneshot(request_message(1, "tools/list", json!({}), TOKEN).expect("request"))
            .await
            .expect("denial");
        assert_eq!(response.status(), expected);
        if expected == StatusCode::UNAUTHORIZED {
            assert!(
                !response
                    .headers()
                    .get("WWW-Authenticate")
                    .expect("challenge")
                    .to_str()
                    .expect("text")
                    .contains("insufficient_scope")
            );
            assert!(
                response
                    .headers()
                    .get("WWW-Authenticate")
                    .expect("challenge")
                    .to_str()
                    .expect("text")
                    .contains("error=\"invalid_token\"")
            );
        } else {
            assert!(response.headers().get("WWW-Authenticate").is_none());
        }
        assert_eq!(
            to_bytes(response.into_body(), 1024)
                .await
                .expect("denial body")
                .as_ref(),
            body.as_bytes()
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
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn direct_token_verification_classifies_scope_denial_and_recovers() -> TestResult<()> {
    let mut raw = Raw::new()?;
    let base = json!({"active":true,"exp":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 300,
        "iss":"https://issuer.example","aud":"https://resource.example/mcp","scope":"mcp:read",
        "token_type":"Bearer","jti":"synthetic-credential","client_id":"synthetic-client"});
    for scope in ["other:scope", "mcp:read"] {
        let mut claims = base.clone();
        *claims.get_mut("scope").ok_or("missing synthetic scope")? = json!(scope);
        let bytes = serde_json::to_vec(&claims)?;
        let headers = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).into_bytes();
        let done = raw.queue("/introspect", headers, Some(bytes)).await?;
        let result = timeout(Duration::from_secs(2), raw.upstream.verify(TOKEN)).await?;
        if scope == "mcp:read" {
            assert_eq!(result?.client_id, "synthetic-client");
        } else {
            let failure = result.err().ok_or("insufficient grant accepted")?;
            assert_eq!(failure.kind, Kind::PermissionDenied);
            assert_eq!(failure.retry_after_ms, None);
        }
        timeout(Duration::from_secs(2), done).await???;
    }
    raw.finish().await?;
    Ok(())
}
