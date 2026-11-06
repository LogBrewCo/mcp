//! Crawler-facing answers over actual TLS beside the unchanged MCP endpoint.

use core::sync::atomic::Ordering;

use reqwest::{Method, StatusCode, header};

use super::{http::Fixture, runtime::Running};

type TestResult<T> = Result<T, Box<dyn core::error::Error + Send + Sync>>;

/// # Errors
///
/// Returns a request or body-read error.
async fn send(
    running: &Running,
    method: Method,
    path: &str,
) -> TestResult<(StatusCode, Option<String>, String)> {
    let response = running
        .http1_client()
        .request(
            method,
            format!("https://localhost:{}{path}", running.address().port()),
        )
        .header("Host", "resource.example")
        .send()
        .await?;
    let status = response.status();
    let media = response
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|value| value.to_str().map(str::to_owned))
        .transpose()?;
    Ok((status, media, response.text().await?))
}

#[tokio::test]
/// # Panics
///
/// Panics if setup or requests fail, robots.txt stops refusing every crawler,
/// an unknown path loses its plain-text 404, the MCP endpoint changes its
/// unauthenticated answer, or a crawler request starts introspection.
async fn crawlers_get_robots_txt_and_plain_not_found_while_mcp_is_unchanged() {
    let fixture = Fixture::new().await.expect("fixture");
    let running = Running::start(fixture.router().clone())
        .await
        .expect("runtime");
    let plain = Some("text/plain; charset=utf-8".to_owned());
    for (method, path, status, body) in [
        (
            Method::GET,
            "/robots.txt",
            StatusCode::OK,
            "User-agent: *\nDisallow: /\n",
        ),
        (Method::HEAD, "/robots.txt", StatusCode::OK, ""),
        (Method::GET, "/nope", StatusCode::NOT_FOUND, "not found"),
        (Method::POST, "/nope", StatusCode::NOT_FOUND, "not found"),
        (
            Method::GET,
            "/.well-known/oauth-protected-resource",
            StatusCode::NOT_FOUND,
            "not found",
        ),
    ] {
        let answer = send(&running, method.clone(), path)
            .await
            .expect("crawler request");
        assert_eq!(
            answer,
            (status, plain.clone(), body.to_owned()),
            "{method} {path}"
        );
    }
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 0);
    let response = running
        .http1_client()
        .post(format!(
            "https://localhost:{}/mcp",
            running.address().port()
        ))
        .header("Host", "resource.example")
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("MCP request");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .map(reqwest::header::HeaderValue::as_bytes),
        Some(
            b"Bearer resource_metadata=\"https://resource.example/.well-known/oauth-protected-resource/mcp\", scope=\"read\""
                .as_slice()
        )
    );
    assert_eq!(response.text().await.expect("MCP body"), "unauthorized");
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 0);
}

#[tokio::test]
/// # Panics
///
/// Panics if a resource path that would shadow robots.txt is accepted.
async fn resource_path_cannot_shadow_robots_txt() {
    let failure = Fixture::for_resource("https://resource.example/robots.txt".to_owned())
        .await
        .err()
        .expect("rejected resource");
    assert_eq!(
        failure
            .downcast_ref::<logbrew_mcp::Failure>()
            .map(|failure| failure.kind),
        Some(logbrew_mcp::error::Kind::Configuration)
    );
}
