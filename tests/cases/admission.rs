//! Unauthenticated requests spend a bounded per-client budget before introspection.

use core::sync::atomic::Ordering;

use axum::http::{HeaderMap, StatusCode};
use logbrew_mcp::admission::Admission;
use serde_json::json;

use super::{
    http::{Fixture, OPEN, TOKEN},
    runtime::Running,
};

type TestResult<T> = Result<T, Box<dyn core::error::Error + Send + Sync>>;

/// Send one execute call through the HTTPS runtime as the named proxied client.
///
/// # Errors
/// Returns an error if the request cannot be sent.
async fn call(
    running: &Running,
    client: &str,
    authorization: Option<&str>,
) -> TestResult<reqwest::Response> {
    let mut request = running
        .http1_client()
        .post(format!(
            "https://localhost:{}/mcp",
            running.address().port()
        ))
        .header("Host", "resource.example")
        .header("X-Real-IP", client)
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "execute")
        .json(
            &json!({"jsonrpc":"2.0","id":1_i32,"method":"tools/call","params":{
            "name":"execute","arguments":{"operation":"logs.read.v1","input":{}},"_meta":{
                "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                "io.modelcontextprotocol/clientCapabilities":{}}}}),
        );
    if let Some(token) = authorization {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    Ok(request.send().await?)
}

#[tokio::test]
/// # Panics
///
/// Panics if verified requests spend the budget, a client exceeds its burst of
/// failed requests, a throttled request reaches introspection, the 429 changes,
/// or one client's failures throttle another client behind the trusted proxy.
///
/// # Errors
///
/// Returns a fixture, runtime, request or response error.
// Reviewed 2026-10-14; review by 2026-11-14 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
async fn failed_requests_are_throttled_per_client_before_introspection() -> TestResult<()> {
    let fixture = Fixture::with_admission(Admission {
        burst: 2,
        per_minute: 1,
        trusted_proxy: Some("127.0.0.1".parse()?),
        ..OPEN
    })
    .await?;
    let running = Running::start(fixture.router().clone()).await?;
    for _ in 0_i32..4_i32 {
        let response = call(&running, "203.0.113.1", Some(TOKEN)).await?;
        assert_eq!(response.status(), StatusCode::OK);
    }
    fixture.state().active().store(false, Ordering::SeqCst);
    for _ in 0_i32..2_i32 {
        let response = call(&running, "203.0.113.1", Some(TOKEN)).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let verifies = fixture.state().verifies().load(Ordering::SeqCst);
    for authorization in [Some(TOKEN), None] {
        let response = call(&running, "203.0.113.1", authorization).await?;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let headers: &HeaderMap = response.headers();
        let retry: u64 = headers
            .get("Retry-After")
            .ok_or("missing Retry-After")?
            .to_str()?
            .parse()?;
        assert!((1..=60).contains(&retry));
        assert_eq!(response.text().await?, "too many unauthenticated requests");
    }
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), verifies);
    let other = call(&running, "203.0.113.2", Some(TOKEN)).await?;
    assert_eq!(other.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 4);
    Ok(())
}

#[tokio::test]
/// # Panics
///
/// Panics if a rejected token is introspected again within the window, or an
/// unavailable introspection result is remembered.
///
/// # Errors
///
/// Returns a fixture or request error.
async fn rejected_tokens_are_refused_without_repeated_introspection() -> TestResult<()> {
    let fixture = Fixture::with_admission(Admission {
        rejected_token_seconds: 30,
        ..OPEN
    })
    .await?;
    for (reply, expected, verifies) in [
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::SERVICE_UNAVAILABLE,
            [1_usize, 2, 3],
        ),
        (StatusCode::OK, StatusCode::UNAUTHORIZED, [4, 4, 4]),
    ] {
        fixture.introspection_reply(reply, r#"{"active":false}"#.to_owned(), HeaderMap::new())?;
        expect_statuses(&fixture, expected, verifies).await?;
    }
    Ok(())
}

/// Send one execute call per expected introspection count and check each result.
///
/// # Errors
///
/// Returns a request error.
///
/// # Panics
///
/// Panics if a status or the introspection count differs.
async fn expect_statuses(
    fixture: &Fixture,
    expected: StatusCode,
    verifies: [usize; 3],
) -> TestResult<()> {
    let arguments = json!({"name":"execute","arguments":{"operation":"logs.read.v1","input":{}}});
    for count in verifies {
        let (status, _) = fixture
            .request("tools/call", arguments.clone(), TOKEN)
            .await?;
        assert_eq!(status, expected);
        assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), count);
    }
    Ok(())
}
