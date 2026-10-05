//! Bearer field grammar, rejection before backend work, and credential privacy.

use std::{net::TcpListener, sync::atomic::Ordering, time::Duration};

use axum::{
    body::to_bytes,
    http::{HeaderValue, StatusCode, header},
};
use logbrew_mcp::{clients::ClientAllowlist, error::Kind, upstream::Principal};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::http::{Fixture, TOKEN, request_message};
use super::raw_upstream::Raw;
use super::runtime::Running;

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// # Errors
///
/// Returns a request construction or bounded body-read error, or an error if a
/// required authentication challenge is missing or invalid header text.
///
/// # Panics
///
/// Panics if cache, session or challenge contracts change, or the response
/// contains the bearer token or a synthetic private marker.
async fn call(fixture: &Fixture, authorization: &[HeaderValue]) -> TestResult<StatusCode> {
    let mut request = request_message(
        1,
        "tools/call",
        json!({"name":"execute",
        "arguments":{"operation":"logs.read.v1","input":{}}}),
        TOKEN,
    )?;
    drop(request.headers_mut().remove(header::AUTHORIZATION));
    for value in authorization {
        let _: bool = request
            .headers_mut()
            .append(header::AUTHORIZATION, value.clone());
    }
    let response = fixture.router.clone().oneshot(request).await?;
    let status = response.status();
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    assert!(response.headers().get("Mcp-Session-Id").is_none());
    if status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED {
        let challenge = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .ok_or("missing challenge")?
            .to_str()?;
        assert!(challenge.contains("resource_metadata=\"https://resource.example/.well-known/oauth-protected-resource/mcp\""));
        assert!(challenge.contains("scope=\"mcp:read\""));
        assert_eq!(
            challenge.contains("error=\"invalid_request\""),
            status == StatusCode::BAD_REQUEST
        );
    }
    let body = to_bytes(response.into_body(), 5 << 20).await?;
    assert!(!String::from_utf8_lossy(&body).contains(TOKEN));
    assert!(!String::from_utf8_lossy(&body).contains("SYNTHETIC_PRIVATE"));
    Ok(status)
}

#[tokio::test]
/// # Errors
///
/// Returns a fixture, header construction or request error.
///
/// # Panics
///
/// Panics if valid scheme case or spacing is rejected, response privacy changes,
/// or introspection and execution counts differ from three.
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
async fn valid_scheme_case_spacing_and_field_edges_preserve_token() -> TestResult<()> {
    let fixture = Fixture::new().await?;
    for value in [
        format!("Bearer {TOKEN}"),
        format!("bEaReR  {TOKEN}"),
        format!("\t  BEARER    {TOKEN} \t"),
    ] {
        assert_eq!(
            call(&fixture, &[HeaderValue::from_str(&value)?]).await?,
            StatusCode::OK
        );
    }
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 3);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 3);
    Ok(())
}

#[tokio::test]
/// # Errors
///
/// Returns a fixture, header construction or request error.
///
/// # Panics
///
/// Panics if an invalid bearer character is accepted, upstream work starts, or
/// response privacy and authentication challenge contracts change.
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
async fn malformed_token_characters_never_reach_introspection_or_execution() -> TestResult<()> {
    for suffix in [
        ":", ";", "!", "@", "#", "$", "%", "&", "'", "(", ")", "*", ",", "?", "[", "]", "\\", "\"",
        "{", "}", "^", "`", "|", "=Z", "===Z", " Z", "\tZ",
    ] {
        let token = format!("SYNTHETIC_PRIVATE_BEARER{suffix}");
        let fixture = Fixture::with_token(&token).await?;
        assert_eq!(
            call(
                &fixture,
                &[HeaderValue::from_str(&format!("Bearer {token}"))?]
            )
            .await?,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[tokio::test]
/// # Errors
///
/// Returns a fixture, header, request or telemetry snapshot/serialization error.
///
/// # Panics
///
/// Panics if malformed or duplicate credentials start upstream work, recovery
/// fails, response contracts change, or credentials enter telemetry.
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
async fn malformed_fields_and_duplicate_credentials_reject_without_backend_work() -> TestResult<()>
{
    let fixture = Fixture::new().await?;
    let good = HeaderValue::from_str(&format!("Bearer {TOKEN}"))?;
    for values in [
        vec![good.clone(), good.clone()],
        vec![good, HeaderValue::from_static("Basic synthetic")],
        vec![HeaderValue::from_bytes(b"Bearer synthetic\x80")?],
        vec![HeaderValue::from_static("")],
    ] {
        assert_eq!(call(&fixture, &values).await?, StatusCode::BAD_REQUEST);
    }
    for value in [
        "Bearer",
        "Bearer ",
        "Bearer\tsynthetic",
        "Bearer \tsynthetic",
        "Bearer =",
        "Bearer ===",
    ] {
        assert_eq!(
            call(&fixture, &[HeaderValue::from_str(value)?]).await?,
            StatusCode::BAD_REQUEST
        );
    }
    let oversized = format!("Bearer {}", "A".repeat(8193));
    assert_eq!(
        call(&fixture, &[HeaderValue::from_str(&oversized)?]).await?,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(call(&fixture, &[]).await?, StatusCode::UNAUTHORIZED);
    for value in ["Basic synthetic", "DPoP synthetic", "Unknown"] {
        assert_eq!(
            call(&fixture, &[HeaderValue::from_str(value)?]).await?,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    let observations =
        serde_json::to_string(&fixture.telemetry.snapshot().ok_or("missing observations")?)?;
    assert!(!observations.contains(TOKEN));
    assert!(!observations.contains("synthetic"));
    assert_eq!(
        call(
            &fixture,
            &[HeaderValue::from_str(&format!("Bearer {TOKEN}"))?]
        )
        .await?,
        StatusCode::OK
    );
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
/// # Errors
///
/// Returns a fixture, header construction or request error.
///
/// # Panics
///
/// Panics if a legal opaque token changes or is rejected, upstream work counts
/// differ from one, or response privacy and challenge contracts change.
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
async fn legal_opaque_tokens_preserve_bytes_through_both_fixed_upstreams() -> TestResult<()> {
    for token in ["AZaz09-._~+/=", "A", "A===", ".~", &"A".repeat(8192)] {
        let fixture = Fixture::with_token(token).await?;
        assert_eq!(
            call(
                &fixture,
                &[HeaderValue::from_str(&format!("bEaReR  {token}"))?]
            )
            .await?,
            StatusCode::OK
        );
        assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[tokio::test]
/// # Errors
///
/// Returns a fixture, queue, timeout, serialization, missing-claim or request
/// error, or an error if rejected work unexpectedly returns a result.
///
/// # Panics
///
/// Panics if malformed bearer rejection changes or starts network work, or valid
/// credential references and client identifiers fail without execution.
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
async fn direct_upstream_calls_reject_malformed_bearers_and_preserve_identity_rules()
-> TestResult<()> {
    let raw = Raw::new()?;
    let _observer = raw
        .queue(
            "/introspect",
            b"HTTP/1.1 400 Fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
            Some(Vec::new()),
        )
        .await?;
    let principal = Principal {
        credential_id: "synthetic-credential-reference".to_owned(),
        client_id: "synthetic-client".to_owned(),
    };
    for token in ["synthetic:token", "A=Z", "=", "", "A Z", "A\tZ", "\u{e9}"] {
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(200), raw.upstream.verify(token))
                .await?
                .err()
                .ok_or("unexpected principal")?
                .kind,
            Kind::Unauthorized
        );
        assert_eq!(
            tokio::time::timeout(
                Duration::from_millis(200),
                raw.upstream
                    .execute(&principal, token, "logs.read.v1", &json!({}))
            )
            .await?
            .err()
            .ok_or("unexpected execution")?
            .kind,
            Kind::Unavailable
        );
    }
    assert_eq!(raw.handshakes.load(Ordering::SeqCst), 0);
    assert_eq!(raw.requests.load(Ordering::SeqCst), 0);
    let client_id = "https://client.example/mcp?key=a:b+c";
    let clients = ClientAllowlist::decode(&serde_json::to_vec(
        &json!({"version":"1","clients":[client_id]}),
    )?)?;
    let references = Fixture::with_clients(clients).await?;
    let mut claims = references.authority()?;
    *claims.get_mut("client_id").ok_or("missing client")? = json!(client_id);
    *claims
        .get_mut("jti")
        .ok_or("missing credential reference")? = json!("reference:one+two");
    references.introspection_reply(
        StatusCode::OK,
        claims.to_string(),
        axum::http::HeaderMap::new(),
    )?;
    assert_eq!(
        references.request("tools/list", json!({}), TOKEN).await?.0,
        StatusCode::OK
    );
    assert_eq!(references.state.verifies.load(Ordering::SeqCst), 1);
    assert_eq!(references.state.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
/// # Errors
///
/// Returns a listener, fixture, HTTP client, TLS exchange or shutdown error.
///
/// # Panics
///
/// Panics if HTTP/1 or HTTP/2 bearer grammar, revocation or recovery changes,
/// response privacy fails, or upstream work counts differ from the expected runs.
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
async fn tls_http1_and_http2_preserve_spacing_rejection_revocation_and_recovery() -> TestResult<()>
{
    let address = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let authority = format!("localhost:{}", address.port());
    let resource = format!("https://{authority}/mcp");
    let fixture = Fixture::for_resource(resource.clone()).await?;
    let mut running = Running::at(address, fixture.router.clone(), &authority).await?;
    let body = json!({"jsonrpc":"2.0","id":1_i32,"method":"tools/call","params":{
        "name":"execute","arguments":{"operation":"logs.read.v1","input":{}},"_meta":{
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":{}}}});
    for (version, client) in [
        (reqwest::Version::HTTP_11, running.http1_client()),
        (reqwest::Version::HTTP_2, running.http2_client()?),
    ] {
        wire_authorization_cases(&fixture, &client, version, &resource, &body).await?;
    }
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 6);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 4);
    running.stop.cancel();
    running.wait().await?;
    Ok(())
}

/// # Errors
///
/// Returns a request or body-read error, or an error if a required wire
/// authentication challenge is missing or invalid header text.
///
/// # Panics
///
/// Panics if the HTTP version, authorization status or challenge differs from
/// the expected case, or the response contains the bearer token.
async fn wire_authorization_cases(
    fixture: &Fixture,
    client: &reqwest::Client,
    version: reqwest::Version,
    resource: &str,
    body: &Value,
) -> TestResult<()> {
    for (authorization, expected, active) in [
        (format!("bEaReR   {TOKEN}"), reqwest::StatusCode::OK, true),
        (
            format!("Bearer\t{TOKEN}"),
            reqwest::StatusCode::BAD_REQUEST,
            true,
        ),
        (
            format!("Bearer {TOKEN},other"),
            reqwest::StatusCode::BAD_REQUEST,
            true,
        ),
        (
            format!("Bearer {TOKEN}"),
            reqwest::StatusCode::UNAUTHORIZED,
            false,
        ),
        (format!("Bearer {TOKEN}"), reqwest::StatusCode::OK, true),
    ] {
        fixture.state.active.store(active, Ordering::SeqCst);
        let response = client
            .post(resource)
            .header("Authorization", authorization)
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", "execute")
            .json(body)
            .send()
            .await?;
        assert_eq!(response.version(), version);
        assert_eq!(response.status(), expected);
        if expected == reqwest::StatusCode::BAD_REQUEST {
            assert!(
                response
                    .headers()
                    .get("WWW-Authenticate")
                    .ok_or("missing wire challenge")?
                    .to_str()?
                    .contains("error=\"invalid_request\"")
            );
        }
        if expected == reqwest::StatusCode::UNAUTHORIZED {
            assert!(
                response
                    .headers()
                    .get("WWW-Authenticate")
                    .ok_or("missing revocation challenge")?
                    .to_str()?
                    .contains("error=\"invalid_token\"")
            );
        }
        let bytes = response.bytes().await?;
        assert!(!String::from_utf8_lossy(&bytes).contains(TOKEN));
    }
    Ok(())
}
