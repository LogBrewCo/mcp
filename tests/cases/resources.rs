//! Several protected resources on one server: each host advertises its own
//! metadata, and a token works only at the resource its audience names.

use core::sync::atomic::Ordering;
use std::net::TcpListener;

use axum::http::{HeaderMap, StatusCode};
use logbrew_mcp::admission::Admission;
use serde_json::{Value, json};

use super::{
    http::{Fixture, OPEN, TOKEN},
    runtime::Running,
};

type TestResult<T> = Result<T, Box<dyn core::error::Error + Send + Sync>>;

/// Send one authenticated execution to `/mcp` through the HTTPS runtime with
/// the selected `Host`, as the edge proxy forwards it.
///
/// # Errors
/// Propagates request or body-read failures.
async fn execute(running: &Running, host: &str) -> TestResult<(StatusCode, Option<String>)> {
    let response = running
        .http1_client()
        .post(format!(
            "https://localhost:{}/mcp",
            running.address().port()
        ))
        .header("Host", host)
        .header("Authorization", format!("Bearer {TOKEN}"))
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "execute")
        .json(
            &json!({"jsonrpc":"2.0","id":1_i32,"method":"tools/call","params":{
            "name":"execute","arguments":{"operation":"logs.read.v1","input":{}},"_meta":{
                "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                "io.modelcontextprotocol/clientCapabilities":{}}}}),
        )
        .send()
        .await?;
    let status = StatusCode::from_u16(response.status().as_u16())?;
    let challenge = response
        .headers()
        .get("WWW-Authenticate")
        .map(|value| value.to_str().map(str::to_owned))
        .transpose()?;
    Ok((status, challenge))
}

/// Start two resources on one listener, the canonical one first.
///
/// # Errors
/// Propagates fixture or runtime setup failures.
async fn serve(admission: Admission) -> TestResult<(Fixture, Running, String, String)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let canonical = format!("localhost:{port}");
    let legacy = format!("legacy.localhost:{port}");
    let fixture = Fixture::for_resources(
        vec![
            format!("https://{canonical}/mcp"),
            format!("https://{legacy}/mcp"),
        ],
        admission,
    )
    .await?;
    let running = Running::at(listener, fixture.router().clone(), &legacy).await?;
    Ok((fixture, running, canonical, legacy))
}

/// Make the synthetic authorization server name `audience` in its claims.
///
/// # Errors
/// Propagates clock or reply-slot failures.
fn issue_for(fixture: &Fixture, audience: &Value) -> TestResult<()> {
    let mut claims = fixture.authority()?;
    *claims.get_mut("aud").ok_or("audience claim")? = audience.clone();
    fixture.introspection_reply(StatusCode::OK, claims.to_string(), HeaderMap::new())
}

fn invalid_token(host: &str) -> String {
    format!(
        "Bearer resource_metadata=\"https://{host}/.well-known/oauth-protected-resource/mcp\", \
         scope=\"read\", error=\"invalid_token\""
    )
}

#[tokio::test]
/// # Panics
///
/// Panics if a token is accepted at a resource its audience does not name, a
/// rejection does not challenge with that host's own metadata, a token naming
/// both resources is refused at either, or execution runs for a rejected token.
async fn a_token_works_only_at_the_resource_its_audience_names() {
    let (fixture, running, canonical, legacy) = serve(OPEN).await.expect("two resources");
    for (audience, accepted, refused) in [
        (&canonical, &canonical, &legacy),
        (&legacy, &legacy, &canonical),
    ] {
        issue_for(&fixture, &json!(format!("https://{audience}/mcp"))).expect("audience");
        let before = fixture.state().calls().load(Ordering::SeqCst);
        assert_eq!(
            execute(&running, accepted).await.expect("accepted"),
            (StatusCode::OK, None)
        );
        assert_eq!(
            execute(&running, refused).await.expect("refused"),
            (StatusCode::UNAUTHORIZED, Some(invalid_token(refused)))
        );
        assert_eq!(fixture.state().calls().load(Ordering::SeqCst), before + 1);
    }
    issue_for(
        &fixture,
        &json!([
            format!("https://{canonical}/mcp"),
            format!("https://{legacy}/mcp")
        ]),
    )
    .expect("both audiences");
    for host in [&canonical, &legacy] {
        assert_eq!(
            execute(&running, host).await.expect("either resource"),
            (StatusCode::OK, None)
        );
    }
}

#[tokio::test]
/// # Panics
///
/// Panics if a token remembered as rejected at one resource is refused at the
/// resource its audience names, or a repeated rejection is introspected again.
async fn a_rejection_at_one_resource_does_not_carry_over_to_another() {
    let admission = Admission {
        rejected_token_seconds: 30,
        ..OPEN
    };
    let (fixture, running, canonical, legacy) = serve(admission).await.expect("two resources");
    for _ in 0..2_u8 {
        assert_eq!(
            execute(&running, &legacy).await.expect("legacy").0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 1);
    assert_eq!(
        execute(&running, &canonical).await.expect("canonical"),
        (StatusCode::OK, None)
    );
}

#[tokio::test]
/// # Panics
///
/// Panics if an empty resource list, resources on different paths, or two
/// resources on the same host and port start a router.
async fn ambiguous_resource_lists_fail_at_startup() {
    for resources in [
        vec![],
        vec![
            "https://resource.example/mcp".to_owned(),
            "https://alias.example/other".to_owned(),
        ],
        vec![
            "https://resource.example/mcp".to_owned(),
            "https://resource.example/mcp".to_owned(),
        ],
    ] {
        let failure = Fixture::for_resources(resources, OPEN)
            .await
            .err()
            .expect("rejected resource list");
        assert_eq!(
            failure
                .downcast_ref::<logbrew_mcp::Failure>()
                .map(|failure| failure.kind),
            Some(logbrew_mcp::error::Kind::Configuration)
        );
    }
}
