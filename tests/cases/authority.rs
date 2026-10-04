//! Same-origin authority equivalence and rejection before backend work.

use std::sync::atomic::Ordering;

use axum::{
    body::{Body, to_bytes},
    http::{HeaderValue, Request, StatusCode, header},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::http::{Fixture, TOKEN, request_message};

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn execution(uri: &str, host: Option<&[u8]>, origin: Option<&[u8]>) -> TestResult<Request<Body>> {
    let mut request = request_message(
        1,
        "tools/call",
        json!({"name":"execute","arguments":{"operation":"logs.read.v1","input":{}}}),
        TOKEN,
    )?;
    *request.uri_mut() = uri.parse()?;
    drop(request.headers_mut().remove(header::HOST));
    if let Some(host) = host {
        drop(
            request
                .headers_mut()
                .insert(header::HOST, HeaderValue::from_bytes(host)?),
        );
    }
    if let Some(origin) = origin {
        drop(
            request
                .headers_mut()
                .insert(header::ORIGIN, HeaderValue::from_bytes(origin)?),
        );
    }
    Ok(request)
}

async fn check(fixture: &Fixture, request: Request<Body>, expected: StatusCode) -> TestResult<()> {
    let response = fixture.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), expected);
    assert_eq!(
        response.headers().get("Cache-Control"),
        Some(&HeaderValue::from_static("no-store"))
    );
    let bytes = to_bytes(response.into_body(), 5 << 20).await?;
    assert!(!String::from_utf8_lossy(&bytes).contains("SYNTHETIC_"));
    if expected == StatusCode::OK {
        let body: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(
            body.pointer("/result/structuredContent/data/count"),
            Some(&json!(3))
        );
    }
    Ok(())
}

fn backend_work(fixture: &Fixture, count: usize) {
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), count);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), count);
}

#[tokio::test]
async fn explicit_default_https_ports_match_the_configured_authority() -> TestResult<()> {
    let fixture = Fixture::new().await?;
    for (uri, host, origin) in [
        ("/mcp", Some(b"resource.example:443".as_slice()), None),
        (
            "/mcp",
            Some(b"resource.example".as_slice()),
            Some(b"https://resource.example:443".as_slice()),
        ),
        (
            "https://resource.example:443/mcp",
            None,
            Some(b"https://resource.example".as_slice()),
        ),
        (
            "https://RESOURCE.EXAMPLE:443/mcp",
            Some(b"Resource.Example".as_slice()),
            Some(b"HTTPS://RESOURCE.EXAMPLE:443".as_slice()),
        ),
        (
            "https://resource.example:0443/mcp",
            Some(b"resource.example:0443".as_slice()),
            Some(b"https://resource.example:0443".as_slice()),
        ),
    ] {
        check(&fixture, execution(uri, host, origin)?, StatusCode::OK).await?;
    }
    backend_work(&fixture, 5);
    Ok(())
}

#[tokio::test]
async fn malformed_host_cannot_hide_behind_a_valid_uri_authority() -> TestResult<()> {
    let fixture = Fixture::new().await?;
    for host in [
        b"\xff".as_slice(),
        b"",
        b"resource.example:",
        b"resource.example:abc",
        b"resource.example:+443",
        b"resource.example:65536",
        b"user@resource.example",
        b"resource.example/path",
    ] {
        let metadata = Request::builder()
            .uri("https://resource.example/.well-known/oauth-protected-resource/mcp")
            .header(header::HOST, HeaderValue::from_bytes(host)?)
            .body(Body::empty())?;
        check(&fixture, metadata, StatusCode::FORBIDDEN).await?;
        check(
            &fixture,
            execution("https://resource.example/mcp", Some(host), None)?,
            StatusCode::FORBIDDEN,
        )
        .await?;
        backend_work(&fixture, 0);
    }
    check(
        &fixture,
        execution("https://resource.example/mcp", None, None)?,
        StatusCode::OK,
    )
    .await?;
    backend_work(&fixture, 1);
    Ok(())
}

#[tokio::test]
async fn uri_and_host_must_each_match_without_accepting_a_foreign_port() -> TestResult<()> {
    let fixture = Fixture::new().await?;
    for (uri, host) in [
        (
            "https://foreign.example/mcp",
            Some(b"resource.example".as_slice()),
        ),
        (
            "https://resource.example/mcp",
            Some(b"foreign.example".as_slice()),
        ),
        (
            "https://resource.example:444/mcp",
            Some(b"resource.example".as_slice()),
        ),
        (
            "https://resource.example/mcp",
            Some(b"resource.example:444".as_slice()),
        ),
        ("/mcp", None),
    ] {
        check(&fixture, execution(uri, host, None)?, StatusCode::FORBIDDEN).await?;
    }
    let mut duplicate = execution(
        "https://resource.example/mcp",
        Some(b"resource.example"),
        None,
    )?;
    let _ = duplicate
        .headers_mut()
        .append(header::HOST, HeaderValue::from_static("resource.example"));
    check(&fixture, duplicate, StatusCode::FORBIDDEN).await?;
    backend_work(&fixture, 0);
    check(
        &fixture,
        execution(
            "https://resource.example:443/mcp",
            Some(b"resource.example"),
            None,
        )?,
        StatusCode::OK,
    )
    .await?;
    backend_work(&fixture, 1);
    Ok(())
}

#[tokio::test]
async fn origin_equivalence_preserves_strict_syntax_and_https_scope() -> TestResult<()> {
    let fixture = Fixture::new().await?;
    for origin in [
        b"\xff".as_slice(),
        b"",
        b"null",
        b"http://resource.example",
        b"https://foreign.example",
        b"https://resource.example:444",
        b"https://resource.example:",
        b"https://resource.example:abc",
        b"https://resource.example:+443",
        b"https://resource.example:65536",
        b"https://user@resource.example",
        b"https://resource.example/",
        b"https://resource.example?query",
        b"https://resource.example#fragment",
        b"https://resource.example https://resource.example",
    ] {
        check(
            &fixture,
            execution("/mcp", Some(b"resource.example"), Some(origin))?,
            StatusCode::FORBIDDEN,
        )
        .await?;
    }
    let mut duplicate = execution(
        "/mcp",
        Some(b"resource.example"),
        Some(b"https://resource.example"),
    )?;
    let _ = duplicate.headers_mut().append(
        header::ORIGIN,
        HeaderValue::from_static("https://resource.example:443"),
    );
    check(&fixture, duplicate, StatusCode::FORBIDDEN).await?;
    backend_work(&fixture, 0);
    check(
        &fixture,
        execution(
            "/mcp",
            Some(b"resource.example"),
            Some(b"https://resource.example:443"),
        )?,
        StatusCode::OK,
    )
    .await?;
    backend_work(&fixture, 1);
    Ok(())
}

#[tokio::test]
async fn nondefault_ports_remain_required_for_host_and_origin() -> TestResult<()> {
    let fixture = Fixture::for_resource("https://resource.example:8443/mcp".to_owned()).await?;
    for (host, origin) in [
        (
            b"resource.example".as_slice(),
            b"https://resource.example:8443".as_slice(),
        ),
        (
            b"resource.example:443".as_slice(),
            b"https://resource.example:8443".as_slice(),
        ),
        (
            b"resource.example:8443".as_slice(),
            b"https://resource.example".as_slice(),
        ),
        (
            b"resource.example:8443".as_slice(),
            b"https://resource.example:443".as_slice(),
        ),
    ] {
        check(
            &fixture,
            execution("/mcp", Some(host), Some(origin))?,
            StatusCode::FORBIDDEN,
        )
        .await?;
    }
    backend_work(&fixture, 0);
    check(
        &fixture,
        execution(
            "https://resource.example:8443/mcp",
            Some(b"resource.example:8443"),
            Some(b"https://resource.example:8443"),
        )?,
        StatusCode::OK,
    )
    .await?;
    backend_work(&fixture, 1);
    Ok(())
}

#[tokio::test]
async fn bracketed_ipv6_authorities_preserve_default_port_equivalence() -> TestResult<()> {
    let fixture = Fixture::for_resource("https://[2001:db8::1]/mcp".to_owned()).await?;
    check(
        &fixture,
        execution(
            "https://[2001:db8::1]:443/mcp",
            Some(b"[2001:db8::1]"),
            Some(b"https://[2001:db8::1]:443"),
        )?,
        StatusCode::OK,
    )
    .await?;
    check(
        &fixture,
        execution("/mcp", Some(b"[2001:db8::1]:444"), None)?,
        StatusCode::FORBIDDEN,
    )
    .await?;
    backend_work(&fixture, 1);
    Ok(())
}
