//! Introspection alone decides which clients connect; client ID syntax is still checked.

use core::sync::atomic::Ordering;

use axum::http::{HeaderMap, StatusCode};
use serde_json::json;

use super::http::{Fixture, TOKEN};

type TestResult<T> = Result<T, Box<dyn core::error::Error + Send + Sync>>;

#[tokio::test]
/// # Panics
///
/// Panics if a previously unknown client ID that introspection confirms is
/// refused at discovery, search or execution, if execution forwards a
/// caller-supplied client identity, or if telemetry discloses the client ID.
async fn any_issuer_confirmed_client_reaches_discovery_and_execution() {
    for client in [
        "https://SYNTHETIC-METADATA-CLIENT.example/oauth/client.json",
        "SYNTHETIC_REGISTERED_CLIENT, one",
    ] {
        confirmed_client_reaches_execution(client)
            .await
            .expect("confirmed client");
    }
}

/// # Errors
///
/// Returns a fixture, request or telemetry encoding error, or an error if
/// telemetry observations are absent.
///
/// # Panics
///
/// Panics if a request for the confirmed client differs from the expected
/// result or telemetry discloses an identity.
async fn confirmed_client_reaches_execution(client: &str) -> TestResult<()> {
    let fixture = Fixture::with_client_id(client).await?;
    for (method, params) in [
        ("server/discover", json!({})),
        ("tools/list", json!({})),
        (
            "tools/call",
            json!({"name":"search","arguments":{"operation":"logs.read.v1"}}),
        ),
    ] {
        let (status, result) = fixture.request(method, params, TOKEN).await?;
        assert_eq!(status, StatusCode::OK, "{method}");
        assert!(result.get("result").is_some(), "{method}");
    }
    // The fixture execution endpoint checks that the confirmed client ID arrives.
    let params = json!({"name":"execute","arguments":{"operation":"logs.read.v1",
        "input":{"context":{"client_id":"CALLER_CLIENT_OVERRIDE",
        "$serde_json::private::Number":"123","context":"preserved"}}}});
    let (status, result) = fixture.request("tools/call", params, TOKEN).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        result.pointer("/result/structuredContent/data/count"),
        Some(&json!(3_i32))
    );
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 1);
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 4);
    let snapshot = fixture
        .telemetry()
        .snapshot()
        .ok_or("missing observations")?;
    let text = serde_json::to_string(&snapshot)?;
    for prohibited in [client, TOKEN, "CALLER_CLIENT_OVERRIDE", "SYNTHETIC"] {
        assert!(!text.contains(prohibited));
    }
    Ok(())
}

#[tokio::test]
/// # Panics
///
/// Panics if an introspected client ID outside bounded printable ASCII reaches
/// execution or gets a status other than 401, or a valid ID then fails to recover.
async fn introspected_client_id_with_invalid_syntax_is_refused() {
    let fixture = Fixture::new().await.expect("fixture");
    let base = fixture.authority().expect("issuer claims");
    let params = json!({"name":"execute","arguments":{"operation":"logs.read.v1","input":{}}});
    for invalid in [
        String::new(),
        "synthetic-client\t".to_owned(),
        "synthetic-client\n".to_owned(),
        "synthetic-client\u{7f}".to_owned(),
        "synthetic-client\u{e9}".to_owned(),
        "x".repeat(2049),
    ] {
        let mut claims = base.clone();
        *claims.get_mut("client_id").expect("client claim") = json!(invalid);
        fixture
            .introspection_reply(StatusCode::OK, claims.to_string(), HeaderMap::new())
            .expect("invalid client claim");
        let (status, _) = fixture
            .request("tools/call", params.clone(), TOKEN)
            .await
            .expect("refusal");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let mut longest = base.clone();
    *longest.get_mut("client_id").expect("client claim") = json!("x".repeat(2048));
    fixture
        .introspection_reply(StatusCode::OK, longest.to_string(), HeaderMap::new())
        .expect("longest client claim");
    let (longest_status, _) = fixture
        .request("tools/list", json!({}), TOKEN)
        .await
        .expect("longest client ID");
    assert_eq!(longest_status, StatusCode::OK);
    fixture
        .introspection_reply(StatusCode::OK, base.to_string(), HeaderMap::new())
        .expect("valid client claim");
    let (recovered_status, _) = fixture
        .request("tools/call", params, TOKEN)
        .await
        .expect("recovery");
    assert_eq!(recovered_status, StatusCode::OK);
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 1);
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 8);
}
