//! Complete upstream field budgets include headers and separate trailer fields.

use std::time::Duration;

use logbrew_mcp::error::Kind;
use tokio::time::timeout;

use super::{
    hpack::literal,
    raw_upstream::Raw,
    upstream_transport::{body, healthy_exchange, operation},
};

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const MARKER: &str = "SYNTHETIC_PRIVATE_TRAILER_MARKER";

/// Observe a complete response and its fixture receipt under a two-second bound.
///
/// # Errors
/// Returns a timeout, operation or receipt error, or an error if excessive fields
/// are accepted.
///
/// # Panics
/// Panics if failure classification, retry guidance or diagnostic privacy changes.
async fn check_complete_response(
    raw: &Raw,
    execute: bool,
    budget: usize,
    done: tokio::sync::oneshot::Receiver<TestResult<()>>,
) -> TestResult<()> {
    let result = timeout(Duration::from_secs(2), operation(&raw.upstream, execute)).await?;
    if budget > 16_384 {
        let failure = result.err().ok_or("aggregate response fields accepted")?;
        assert_eq!(failure.kind, Kind::Unavailable);
        assert_eq!(failure.retry_after_ms, None);
        for prohibited in [MARKER, super::http::TOKEN, "SYNTHETIC_MACHINE_SECRET"] {
            assert!(!format!("{failure:?} {failure}").contains(prohibited));
        }
    } else {
        result?;
    }
    timeout(Duration::from_secs(2), done).await???;
    Ok(())
}

/// Run complete chunked responses below, at and above the aggregate field limit.
///
/// # Errors
/// Returns a fixture, clock, formatting, queue, operation, observation or shutdown
/// error, or an error if an oversized complete response is accepted.
///
/// # Panics
/// Panics if the stable failure classification or diagnostic privacy changes.
async fn http1_trailers(execute: bool) -> TestResult<()> {
    let mut raw = Raw::new()?;
    let path = if execute { "/execute" } else { "/introspect" };
    let body = body(execute)?;
    let fields = format!(
        "Content-Type: application/json\r\nTransfer-Encoding: chunked\r\nTrailer: X-Control\r\nConnection: close\r\nX-Padding: {}\r\n",
        "a".repeat(8000)
    );
    let overhead = fields
        .len()
        .checked_add("X-Control: \r\n".len())
        .and_then(|size| size.checked_add(MARKER.len()))
        .ok_or("trailer fixture size overflow")?;
    for budget in [16_383_usize, 16_384, 16_385] {
        let filler = budget
            .checked_sub(overhead)
            .ok_or("trailer fixture budget too small")?;
        let wire = format!(
            "{:X}\r\n{}\r\n0\r\nX-Control: {}{MARKER}\r\n\r\n",
            body.len(),
            std::str::from_utf8(&body)?,
            "b".repeat(filler)
        );
        let done = raw
            .queue(
                path,
                format!("HTTP/1.1 200 Fixture\r\n{fields}\r\n").into_bytes(),
                Some(wire.into_bytes()),
            )
            .await?;
        check_complete_response(&raw, execute, budget, done).await?;
    }
    healthy_exchange(&raw, execute).await?;
    raw.finish().await
}

/// Run HTTP/2 `DATA` followed by split `HEADERS` and `CONTINUATION` trailer frames.
///
/// # Errors
/// Returns a fixture, clock, field encoding, queue, operation, observation or
/// shutdown error, or an error if excessive complete response fields are accepted.
async fn http2_trailers(execute: bool) -> TestResult<()> {
    let mut raw = Raw::http2()?;
    let body = body(execute)?;
    let padding = "a".repeat(8000);
    let mut headers = vec![0x88]; // Static HPACK status 200.
    literal(&mut headers, b"content-type", b"application/json", false)?;
    literal(&mut headers, b"x-padding", padding.as_bytes(), false)?;
    let fields = format!("Content-Type: application/json\r\nX-Padding: {padding}\r\n");
    let overhead = fields
        .len()
        .checked_add("X-Control: \r\n".len())
        .and_then(|size| size.checked_add(MARKER.len()))
        .ok_or("trailer fixture size overflow")?;
    for budget in [16_383_usize, 16_384, 16_385] {
        let filler = budget
            .checked_sub(overhead)
            .ok_or("trailer fixture budget too small")?;
        let mut trailers = Vec::new();
        literal(
            &mut trailers,
            b"x-control",
            format!("{}{MARKER}", "b".repeat(filler)).as_bytes(),
            false,
        )?;
        let done = raw
            .queue_http2_trailers(headers.clone(), body.clone(), trailers)
            .await?;
        check_complete_response(&raw, execute, budget, done).await?;
    }
    let done = raw.queue_http2(headers, Some(body)).await?;
    check_complete_response(&raw, execute, 0, done).await?;
    raw.finish().await
}

#[tokio::test]
/// # Panics
/// Panics if HTTP/1 introspection accepts excessive trailer fields or fails recovery.
async fn introspection_http1_trailers_share_the_response_field_budget_and_recover() {
    http1_trailers(false)
        .await
        .expect("introspection trailer budget and recovery");
}

#[tokio::test]
/// # Panics
/// Panics if HTTP/1 execution accepts excessive trailer fields or fails recovery.
async fn execution_http1_trailers_share_the_response_field_budget_and_recover() {
    http1_trailers(true)
        .await
        .expect("execution trailer budget and recovery");
}

#[tokio::test]
/// # Panics
/// Panics if HTTP/2 introspection accepts excessive trailer fields or fails recovery.
async fn introspection_http2_trailers_share_the_response_field_budget_and_recover() {
    http2_trailers(false)
        .await
        .expect("introspection HTTP/2 trailer budget and recovery");
}

#[tokio::test]
/// # Panics
/// Panics if HTTP/2 execution accepts excessive trailer fields or fails recovery.
async fn execution_http2_trailers_share_the_response_field_budget_and_recover() {
    http2_trailers(true)
        .await
        .expect("execution HTTP/2 trailer budget and recovery");
}
