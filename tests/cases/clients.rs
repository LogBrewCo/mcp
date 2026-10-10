//! Client authorization uses issuer claims, with no caller-controlled overrides.

use core::sync::atomic::Ordering;

use axum::{
    body::to_bytes,
    http::{HeaderMap, StatusCode},
};
use logbrew_mcp::{
    clients::ClientAllowlist,
    telemetry::{Outcome, Snapshot, Stage},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::http::{Fixture, TOKEN, request_message};

#[tokio::test]
/// # Panics
///
/// Panics if printable client IDs fail authorization, an alias or caller identity
/// grants access, exact recovery or revocation fails, or telemetry discloses an ID.
async fn printable_client_ids_require_exact_issuer_and_allowlist_matches() {
    const CLIENT: &str = "SYNTHETIC_PRIVATE_CLIENT, one";
    let policy =
        serde_json::to_vec(&json!({"version":"1","clients":[CLIENT]})).expect("client policy JSON");
    let clients = ClientAllowlist::decode(&policy).expect("trusted printable client policy");
    let fixture = Fixture::with_client_id(clients, CLIENT)
        .await
        .expect("fixture");
    let base = fixture.authority().expect("issuer claims");
    let params = json!({"name":"execute","arguments":{"operation":"logs.read.v1",
        "input":{"context":{"client_id":"CALLER_CLIENT_OVERRIDE",
        "$serde_json::private::Number":"123","context":"preserved"}}}});
    let (status, result) = fixture
        .request("tools/call", params.clone(), TOKEN)
        .await
        .expect("exact authorized client");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        result.pointer("/result/structuredContent/data/count"),
        Some(&json!(3_i32))
    );
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 1);
    for alias in [
        "SYNTHETIC_PRIVATE_CLIENT,one",
        "synthetic_private_client, one",
        "SYNTHETIC_PRIVATE_CLIENT,%20one",
        "SYNTHETIC_PRIVATE_CLIENT,+one",
        "SYNTHETIC_PRIVATE_CLIENT, one ",
        " SYNTHETIC_PRIVATE_CLIENT, one",
    ] {
        let mut claims = base.clone();
        *claims.get_mut("client_id").expect("client claim") = json!(alias);
        fixture
            .introspection_reply(StatusCode::OK, claims.to_string(), HeaderMap::new())
            .expect("unlisted issuer client");
        let mut request = request_message(2, "tools/call", params.clone(), TOKEN).expect("request");
        drop(
            request
                .headers_mut()
                .insert("X-Client-Id", CLIENT.parse().expect("caller ID")),
        );
        let response = fixture
            .router()
            .clone()
            .oneshot(request)
            .await
            .expect("client denial");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers().get("Cache-Control").expect("no-store"),
            "no-store"
        );
        assert!(response.headers().get("WWW-Authenticate").is_none());
        let bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("bounded denial");
        assert_eq!(bytes.as_ref(), b"client access denied");
        assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 1);
    }
    fixture
        .introspection_reply(StatusCode::OK, base.to_string(), HeaderMap::new())
        .expect("exact issuer client restored");
    let (recovered_status, recovered_result) = fixture
        .request("tools/call", params.clone(), TOKEN)
        .await
        .expect("recovery");
    assert_eq!(recovered_status, StatusCode::OK);
    assert_eq!(
        recovered_result.pointer("/result/structuredContent/data/count"),
        Some(&json!(3_i32))
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
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 2);
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 9);
    let text = serde_json::to_string(&fixture.telemetry().snapshot().expect("observations"))
        .expect("telemetry JSON");
    for prohibited in [CLIENT, TOKEN, "CALLER_CLIENT_OVERRIDE", "SYNTHETIC_PRIVATE"] {
        assert!(!text.contains(prohibited));
    }
}

fn no_operation_work(snapshot: &Snapshot) -> bool {
    snapshot.operations.as_ref().is_some_and(|catalog| {
        catalog.executions.len() == 1
            && catalog.executions.first().is_some_and(|entry| {
                entry.operation == "logs.read.v1"
                    && entry.execution.started == 0
                    && entry.execution.finished == 0
                    && entry.execution.timed == 0
                    && entry.execution.pending == Some(0)
                    && entry.execution.dropped_updates == 0
                    && entry
                        .execution
                        .outcomes
                        .iter()
                        .all(|outcome| outcome.count == 0)
                    && entry
                        .execution
                        .latency_buckets
                        .iter()
                        .all(|bucket| bucket.count == 0)
                    && entry.execution.p99_upper_ns.is_none()
            })
    })
}

#[tokio::test]
/// # Panics
///
/// Panics if setup or requests fail, default denial or explicit-policy recovery
/// changes, revocation fails, or telemetry counts, outcomes or privacy change.
async fn missing_client_policy_denies_valid_authority_and_explicit_policy_recovers() {
    let fixture = Fixture::without_clients()
        .await
        .expect("unconfigured policy");
    let approved = Fixture::new().await.expect("explicit synthetic policy");
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
        let response = fixture
            .router()
            .clone()
            .oneshot(request_message(1, method, params.clone(), TOKEN).expect("request"))
            .await
            .expect("default denial");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.headers().get("WWW-Authenticate").is_none());
        assert_eq!(
            response.headers().get("Cache-Control").expect("no-store"),
            "no-store"
        );
        let bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("bounded denial");
        assert_eq!(bytes.as_ref(), b"client access denied");
        assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
        assert_eq!(
            approved
                .request(method, params, TOKEN)
                .await
                .expect("explicit policy recovery")
                .0,
            StatusCode::OK
        );
    }
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 4);
    assert_eq!(approved.state().verifies().load(Ordering::SeqCst), 4);
    assert_eq!(approved.state().calls().load(Ordering::SeqCst), 1);
    fixture.state().active().store(false, Ordering::SeqCst);
    let response = fixture
        .router()
        .clone()
        .oneshot(request_message(5, "tools/list", json!({}), TOKEN).expect("revoked request"))
        .await
        .expect("fresh credential rejection");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        response
            .headers()
            .get("WWW-Authenticate")
            .expect("challenge")
            .to_str()
            .expect("ASCII challenge")
            .contains("invalid_token")
    );
    drop(response);
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 5);
    let snapshot = fixture
        .telemetry()
        .snapshot()
        .expect("default denial observations");
    for stage in [Stage::RequestPrepared, Stage::Introspection] {
        let stats = snapshot
            .stages
            .iter()
            .find(|stats| stats.stage == stage)
            .expect("stage");
        assert_eq!(stats.started, 5);
        assert_eq!(stats.finished, 5);
        assert_eq!(stats.pending, Some(0));
        assert_denial_outcomes(stats).expect("denial outcomes");
    }
    assert!(no_operation_work(&snapshot));
    let text = serde_json::to_string(&snapshot).expect("private-safe observations");
    for prohibited in [TOKEN, "synthetic-client", "resource.example"] {
        assert!(!text.contains(prohibited));
    }
}

/// # Errors
///
/// Returns an error if either required denial outcome is absent from telemetry.
///
/// # Panics
///
/// Panics if permission-denied or unauthorized counts differ from the expected
/// four client denials and one revoked credential.
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
fn assert_denial_outcomes(
    stats: &logbrew_mcp::telemetry::StageSnapshot,
) -> Result<(), &'static str> {
    for (outcome, expected) in [(Outcome::PermissionDenied, 4), (Outcome::Unauthorized, 1)] {
        assert_eq!(
            stats
                .outcomes
                .iter()
                .find(|count| count.outcome == outcome)
                .ok_or("denial outcome")?
                .count,
            expected
        );
    }
    Ok(())
}

#[tokio::test]
/// # Panics
///
/// Panics if setup fails, unlisted clients bypass denial or start execution,
/// approved clients fail recovery, or telemetry counts, outcomes or privacy change.
async fn client_allowlist_rejects_discovery_search_and_execution_and_recovers() {
    let clients = ClientAllowlist::decode(br#"{"version":"1","clients":["synthetic-client"]}"#)
        .expect("trusted policy");
    let fixture = Fixture::with_clients(clients).await.expect("fixture");
    let base = fixture.authority().expect("issuer claims");
    let mut denied = base.clone();
    *denied.get_mut("client_id").expect("client claim") = json!("SYNTHETIC_PRIVATE_CLIENT");
    fixture
        .introspection_reply(StatusCode::OK, denied.to_string(), HeaderMap::new())
        .expect("unlisted client");
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
        let mut request = request_message(1, method, params.clone(), TOKEN).expect("request");
        drop(request.headers_mut().insert(
            "X-Client-Id",
            "synthetic-client".parse().expect("caller ID"),
        ));
        // The request advertises a client identity, but only issuer claims authorize it.
        let response = fixture
            .router()
            .clone()
            .oneshot(request)
            .await
            .expect("denial");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers().get("Cache-Control").expect("no-store"),
            "no-store"
        );
        assert!(response.headers().get("WWW-Authenticate").is_none());
        let bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("bounded denial");
        assert_eq!(bytes.as_ref(), b"client access denied");
        assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
        fixture
            .introspection_reply(StatusCode::OK, base.to_string(), HeaderMap::new())
            .expect("approved client");
        assert_eq!(
            fixture
                .request(method, params, TOKEN)
                .await
                .expect("recovery")
                .0,
            StatusCode::OK
        );
        fixture
            .introspection_reply(StatusCode::OK, denied.to_string(), HeaderMap::new())
            .expect("restore denied claims");
    }
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 1);
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 8);
    let snapshot = fixture.telemetry().snapshot().expect("observations");
    for stage in [Stage::RequestPrepared, Stage::Introspection] {
        let stats = snapshot
            .stages
            .iter()
            .find(|stats| stats.stage == stage)
            .expect("stage");
        assert_eq!(stats.started, 8);
        assert_eq!(stats.finished, 8);
        assert_eq!(stats.pending, Some(0));
        assert_eq!(
            stats
                .outcomes
                .iter()
                .find(|count| count.outcome == Outcome::PermissionDenied)
                .expect("denials")
                .count,
            4
        );
    }
    let text = serde_json::to_string(&snapshot).expect("privacy observation");
    assert!(!text.contains("SYNTHETIC_PRIVATE_CLIENT"));
    assert!(!text.contains(TOKEN));
}

#[tokio::test]
/// # Panics
///
/// Panics if setup fails, empty, wildcard or inexact client policies grant access,
/// a denial returns data, or upstream work counts change.
async fn client_allowlist_uses_exact_ids_and_never_interprets_wildcards() {
    for policy in [
        br#"{"version":"1","clients":[]}"#.as_slice(),
        br#"{"version":"1","clients":["*"]}"#,
        br#"{"version":"1","clients":["SYNTHETIC-CLIENT","synthetic-client/","synthetic-client.evil","https://synthetic-client"]}"#,
    ] {
        let fixture = Fixture::with_clients(ClientAllowlist::decode(policy).expect("policy"))
            .await.expect("fixture");
        let (status, result) = fixture.request("tools/list", json!({}), TOKEN).await.expect("denial");
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(result, Value::Null);
        assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
        assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 1);
    }
}
