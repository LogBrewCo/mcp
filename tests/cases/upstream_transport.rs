//! Outbound parsing and TLS verification, cancellation, deadlines and recovery.

use std::{
    fmt::Write as _,
    sync::atomic::Ordering,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use logbrew_mcp::{
    Failure,
    error::Kind,
    telemetry::{Outcome, Stage},
    upstream::{Principal, Upstream},
};
use serde_json::json;
use tokio::time::timeout;

use super::{hpack::literal, http::TOKEN, raw_upstream::Raw};

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const MARKER: &str = "SYNTHETIC_PRIVATE_RESPONSE_MARKER";

fn headers(status: u16, body_length: usize, count: usize, filler: usize) -> TestResult<Vec<u8>> {
    let mut text = format!(
        "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {body_length}\r\nConnection: close\r\n"
    );
    for _ in 0..count.checked_sub(4).ok_or("invalid fixture header count")? {
        text.push_str("X-Count: a\r\n");
    }
    write!(text, "X-Control: {}{MARKER}\r\n\r\n", "a".repeat(filler))?;
    Ok(text.into_bytes())
}

async fn operation(upstream: &Upstream, execute: bool) -> Result<(), Failure> {
    if execute {
        let principal = Principal {
            credential_id: "synthetic-credential".to_owned(),
            client_id: "synthetic-client".to_owned(),
        };
        let value = upstream
            .execute(&principal, TOKEN, "logs.read.v1", &json!({}))
            .await?;
        assert_eq!(value, json!({"count":3_i32}));
    } else {
        let principal = upstream.verify(TOKEN).await?;
        assert_eq!(principal.credential_id, "synthetic-credential");
        assert_eq!(principal.client_id, "synthetic-client");
    }
    Ok(())
}

fn body(execute: bool) -> TestResult<Vec<u8>> {
    Ok(if execute {
        json!({"count":3})
    } else {
        json!({
            "active":true,"exp":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs().checked_add(300).ok_or("fixture expiry overflow")?,
            "iss":"https://issuer.example","aud":"https://resource.example/mcp",
            "scope":"mcp:read","token_type":"Bearer",
            "jti":"synthetic-credential","client_id":"synthetic-client"
        })
    }
    .to_string()
    .into_bytes())
}

async fn exercise(execute: bool) -> TestResult<()> {
    let mut raw = Raw::new()?;
    let path = if execute { "/execute" } else { "/introspect" };
    let body = body(execute)?;

    // Exactly 100 fields remain valid below the aggregate header byte limit.
    let control = headers(200, body.len(), 100, 14_000)?;
    assert!(control.len() > 15_000 && control.len() < 16 << 10_i32);
    let done = raw.queue(path, control, Some(body.clone())).await?;
    timeout(Duration::from_secs(2), operation(&raw.upstream, execute)).await??;
    timeout(Duration::from_secs(2), done).await???;

    let mut partial = b"HTTP/1.1 200 Fixture\r\nX-Incomplete: ".to_vec();
    partial.extend(std::iter::repeat_n(b'a', 512 << 10));
    // Reject at the configured budget, before Hyper's much larger default fills.
    let mut budget_partial = b"HTTP/1.1 200 Fixture\r\nX-Incomplete: ".to_vec();
    budget_partial.resize((16 << 10) + 1, b'a');
    for (case, bytes) in [
        (
            "complete oversized header",
            headers(200, body.len(), 4, 17 << 10)?,
        ),
        ("101 fields", headers(200, body.len(), 101, 0)?),
        ("incomplete 16385-byte header", budget_partial),
        ("incomplete 512 KiB header", partial),
    ] {
        let done = raw.queue(path, bytes, None).await?;
        let failure = timeout(Duration::from_secs(2), operation(&raw.upstream, execute))
            .await
            .map_err(|_| std::io::Error::other(format!("header rejection deadline: {case}")))?
            .err()
            .ok_or("oversized headers accepted")?;
        assert_eq!(failure.kind, Kind::Unavailable);
        assert_eq!(failure.retry_after_ms, None);
        assert!(!format!("{failure:?} {failure}").contains(MARKER));
        assert!(!format!("{failure:?} {failure}").contains(TOKEN));
        timeout(Duration::from_secs(2), done).await???;
    }

    let done = raw
        .queue(path, headers(200, body.len(), 4, 0)?, Some(body))
        .await?;
    timeout(Duration::from_secs(2), operation(&raw.upstream, execute)).await??;
    timeout(Duration::from_secs(2), done).await???;
    header_observations(&raw.upstream, execute, 6, 4, false)?;
    raw.finish().await
}

#[tokio::test]
async fn introspection_http1_headers_fail_before_body_read_and_recover() {
    exercise(false)
        .await
        .expect("introspection header boundaries and recovery");
}

#[tokio::test]
async fn execution_http1_headers_fail_before_body_read_and_recover() {
    exercise(true)
        .await
        .expect("execution header boundaries and recovery");
}

fn http2_headers(decoded_bytes: usize, compressed: bool) -> TestResult<Vec<u8>> {
    // Static index 8 is :status 200. Field sizes include the RFC 9113 overhead.
    let mut block = vec![0x88];
    literal(&mut block, b"content-type", b"application/json", false)?;
    let fixed = (7 + 3 + 32) + (12 + 16 + 32);
    let budget = decoded_bytes
        .checked_sub(fixed)
        .ok_or("invalid decoded fixture budget")?;
    let field = if compressed { 1024 } else { budget };
    let overhead = b"x-control"
        .len()
        .checked_add(32)
        .and_then(|size| size.checked_add(MARKER.len()))
        .ok_or("invalid HTTP/2 field overhead")?;
    let length = field
        .checked_sub(overhead)
        .ok_or("invalid HTTP/2 fixture size")?;
    let mut value = vec![b'a'; length];
    value.extend_from_slice(MARKER.as_bytes());
    literal(&mut block, b"x-control", &value, compressed)?;
    if compressed {
        // The new entry is dynamic index 62. Repeated indexed fields still
        // consume their complete decoded size, including duplicate names.
        let repetitions = budget.div_ceil(field);
        if !(2..=64).contains(&repetitions) {
            return Err("invalid compressed fixture repetition count".into());
        }
        block.extend(std::iter::repeat_n(
            0xbe,
            repetitions
                .checked_sub(1)
                .ok_or("invalid fixture repetition count")?,
        ));
        assert!(
            field
                .checked_mul(repetitions)
                .and_then(|size| fixed.checked_add(size))
                .is_some_and(|size| size > 16 << 10_i32)
        );
        assert!(block.len() < 2048);
    }
    Ok(block)
}

async fn http2_header_limits(execute: bool) -> TestResult<()> {
    let mut raw = Raw::http2()?;
    let body = body(execute)?;
    // h2 0.4.19 rejects a decoded list at or above the configured budget.
    let done = raw
        .queue_http2(http2_headers((16 << 10) - 1, false)?, Some(body.clone()))
        .await?;
    timeout(Duration::from_secs(2), operation(&raw.upstream, execute)).await??;
    timeout(Duration::from_secs(2), done).await???;

    for (case, headers) in [
        ("exact decoded budget", http2_headers(16 << 10, false)?),
        (
            "one byte above decoded budget",
            http2_headers((16 << 10) + 1, false)?,
        ),
        ("compressed repeated fields", http2_headers(17 << 10, true)?),
    ] {
        let done = raw.queue_http2(headers, None).await?;
        let failure = timeout(Duration::from_secs(2), operation(&raw.upstream, execute))
            .await
            .map_err(|_| std::io::Error::other(format!("HTTP/2 rejection deadline: {case}")))?
            .err()
            .ok_or("oversized HTTP/2 headers accepted")?;
        assert_eq!(failure.kind, Kind::Unavailable);
        assert_eq!(failure.retry_after_ms, None);
        for prohibited in [MARKER, TOKEN, "SYNTHETIC_MACHINE_SECRET"] {
            assert!(!format!("{failure:?} {failure}").contains(prohibited));
        }
        timeout(Duration::from_secs(2), done).await???;
    }

    let done = raw
        .queue_http2(http2_headers(1024, false)?, Some(body))
        .await?;
    timeout(Duration::from_secs(2), operation(&raw.upstream, execute)).await??;
    timeout(Duration::from_secs(2), done).await???;
    assert_eq!(raw.handshakes.load(Ordering::SeqCst), 5);
    assert_eq!(raw.requests.load(Ordering::SeqCst), 5);
    header_observations(&raw.upstream, execute, 5, 3, true)?;
    raw.finish().await
}

fn header_observations(
    upstream: &Upstream,
    execute: bool,
    total: u64,
    unavailable: u64,
    check_timing: bool,
) -> TestResult<()> {
    let snapshot = upstream
        .telemetry()
        .snapshot()
        .ok_or("missing upstream observations")?;
    let selected = if execute {
        Stage::UpstreamExecute
    } else {
        Stage::Introspection
    };
    let stage = snapshot
        .stages
        .iter()
        .find(|stage| stage.stage == selected)
        .ok_or("missing upstream stage")?;
    assert_eq!(stage.started, total);
    assert_eq!(stage.finished, total);
    assert_eq!(stage.pending, Some(0));
    if check_timing {
        assert_eq!(stage.timed, total);
        assert_eq!(stage.dropped_updates, 0);
        assert!(!stage.saturated);
        assert!(!stage.timing_unavailable);
    }
    let completed = total
        .checked_sub(unavailable)
        .ok_or("invalid fixture outcome counts")?;
    for (outcome, expected) in [
        (Outcome::Completed, completed),
        (Outcome::Unavailable, unavailable),
    ] {
        assert_eq!(
            stage
                .outcomes
                .iter()
                .find(|entry| entry.outcome == outcome)
                .map(|entry| entry.count),
            Some(expected)
        );
    }
    assert_private(
        &serde_json::to_string(&snapshot)?,
        &[MARKER, TOKEN, "SYNTHETIC_MACHINE_SECRET", "localhost"],
    );
    Ok(())
}

fn assert_private(text: &str, prohibited: &[&str]) {
    for word in prohibited {
        assert!(!text.contains(word));
    }
}

fn assert_unavailable(failure: &Failure) {
    assert_eq!(failure.kind, Kind::Unavailable);
    assert_eq!(failure.retry_after_ms, None);
    assert_private(
        &format!("{failure:?} {failure}"),
        &[MARKER, TOKEN, "SYNTHETIC_MACHINE_SECRET", "localhost"],
    );
}

#[tokio::test]
async fn introspection_http2_headers_enforce_decoded_limits_and_recover() {
    http2_header_limits(false)
        .await
        .expect("introspection HTTP/2 header bounds and recovery");
}

#[tokio::test]
async fn execution_http2_headers_enforce_decoded_limits_and_recover() {
    http2_header_limits(true)
        .await
        .expect("execution HTTP/2 header bounds and recovery");
}

#[tokio::test]
async fn upstream_tls_rejects_untrusted_and_mismatched_peers_before_http_and_recovers() {
    for mut raw in [
        Raw::untrusted_certificate().expect("untrusted TLS peer"),
        Raw::mismatched_hostname().expect("mismatched TLS hostname"),
    ] {
        rejected_tls(&mut raw).await.expect("rejected peer stopped");
    }
    let mut raw = Raw::new().expect("trusted matching TLS peer");
    for execute in [false, true] {
        healthy_exchange(&raw, execute)
            .await
            .expect("trusted matching authority");
    }
    assert_eq!(raw.handshakes.load(Ordering::SeqCst), 2);
    assert_eq!(raw.requests.load(Ordering::SeqCst), 2);
    raw.finish().await.expect("healthy peer stopped");
}

async fn rejected_tls(raw: &mut Raw) -> TestResult<()> {
    for execute in [false, true] {
        let path = if execute { "/execute" } else { "/introspect" };
        let body = body(execute)?;
        let done = raw
            .queue(path, headers(200, body.len(), 4, 0)?, Some(body))
            .await?;
        let failure = timeout(Duration::from_secs(2), operation(&raw.upstream, execute))
            .await?
            .err()
            .ok_or("unapproved TLS authority accepted")?;
        assert_unavailable(&failure);
        let receipt = timeout(Duration::from_secs(2), done).await??;
        assert!(receipt.is_err(), "TLS handshake unexpectedly completed");
    }
    assert_eq!(raw.handshakes.load(Ordering::SeqCst), 0);
    assert_eq!(raw.requests.load(Ordering::SeqCst), 0);
    let snapshot = raw.upstream.telemetry().snapshot().ok_or("observations")?;
    for selected in [Stage::Introspection, Stage::UpstreamExecute] {
        let stage = snapshot
            .stages
            .iter()
            .find(|stage| stage.stage == selected)
            .ok_or("outbound stage")?;
        assert_eq!(stage.started, 1);
        assert_eq!(stage.finished, 1);
        assert_eq!(stage.pending, Some(0));
        assert_eq!(
            stage
                .outcomes
                .iter()
                .find(|entry| entry.outcome == Outcome::Unavailable)
                .ok_or("TLS failure")?
                .count,
            1
        );
    }
    assert_private(
        &serde_json::to_string(&snapshot)?,
        &[
            MARKER,
            TOKEN,
            "SYNTHETIC_MACHINE_SECRET",
            "localhost",
            "127.0.0.1",
        ],
    );
    raw.finish().await
}

async fn healthy_exchange(raw: &Raw, execute: bool) -> TestResult<()> {
    let path = if execute { "/execute" } else { "/introspect" };
    let body = body(execute)?;
    let done = raw
        .queue(path, headers(200, body.len(), 4, 0)?, Some(body))
        .await?;
    timeout(Duration::from_secs(2), operation(&raw.upstream, execute)).await??;
    timeout(Duration::from_secs(2), done).await???;
    Ok(())
}

async fn tls_lifecycle(cancel: bool) -> TestResult<()> {
    let mut raw = Raw::new()?;
    for execute in [false, true] {
        let waiting = raw.stall_handshake().await?;
        let mut request = Box::pin(operation(&raw.upstream, execute));
        tokio::select! {
            result = request.as_mut() => {
                return Err(std::io::Error::other(format!(
                    "operation ended before pending TLS was observed: {result:?}"
                )).into());
            }
            observed = timeout(Duration::from_secs(2), waiting.started) => {
                observed??;
            }
        }
        // The peer has consumed a real ClientHello and sends no TLS response.
        assert!(
            timeout(Duration::from_millis(100), request.as_mut())
                .await
                .is_err(),
            "pending TLS operation completed without a peer response"
        );
        let stage = if execute {
            Stage::UpstreamExecute
        } else {
            Stage::Introspection
        };
        tls_observations(&raw.upstream, stage, 1, 0, 1, None)?;
        if !cancel {
            // Execution's complete ten-second deadline cannot mask a missing
            // five-second connector deadline in this six-second check.
            let failure = timeout(Duration::from_secs(6), request.as_mut())
                .await?
                .err()
                .ok_or("pending TLS operation unexpectedly succeeded")?;
            assert_unavailable(&failure);
        }
        drop(request);
        timeout(Duration::from_secs(2), waiting.closed).await???;
        assert_eq!(raw.handshakes.load(Ordering::SeqCst), usize::from(execute));
        assert_eq!(raw.requests.load(Ordering::SeqCst), usize::from(execute));
        let outcome = if cancel {
            Outcome::Cancelled
        } else {
            Outcome::Unavailable
        };
        tls_observations(&raw.upstream, stage, 1, 1, 0, Some(outcome))?;

        let path = if execute { "/execute" } else { "/introspect" };
        let body = body(execute)?;
        let done = raw
            .queue(path, headers(200, body.len(), 4, 0)?, Some(body))
            .await?;
        timeout(Duration::from_secs(2), operation(&raw.upstream, execute)).await??;
        timeout(Duration::from_secs(2), done).await???;
        tls_observations(&raw.upstream, stage, 2, 2, 0, Some(outcome))?;
        let snapshot = raw.upstream.telemetry().snapshot().ok_or("observations")?;
        assert_eq!(
            snapshot
                .stages
                .iter()
                .find(|entry| entry.stage == stage)
                .and_then(|entry| {
                    entry
                        .outcomes
                        .iter()
                        .find(|entry| entry.outcome == Outcome::Completed)
                })
                .map(|entry| entry.count),
            Some(1)
        );
    }
    assert_eq!(raw.handshakes.load(Ordering::SeqCst), 2);
    assert_eq!(raw.requests.load(Ordering::SeqCst), 2);
    raw.finish().await
}

fn tls_observations(
    upstream: &Upstream,
    selected: Stage,
    started: u64,
    finished: u64,
    pending: u64,
    outcome: Option<Outcome>,
) -> TestResult<()> {
    let snapshot = upstream.telemetry().snapshot().ok_or("observations")?;
    let stage = snapshot
        .stages
        .iter()
        .find(|stage| stage.stage == selected)
        .ok_or("outbound stage")?;
    assert_eq!(stage.started, started);
    assert_eq!(stage.finished, finished);
    assert_eq!(stage.pending, Some(pending));
    assert_eq!(stage.timed, finished);
    assert_eq!(stage.dropped_updates, 0);
    assert!(!stage.saturated);
    assert!(!stage.timing_unavailable);
    if let Some(outcome) = outcome {
        assert_eq!(
            stage
                .outcomes
                .iter()
                .find(|entry| entry.outcome == outcome)
                .map(|entry| entry.count),
            Some(1)
        );
    }
    let observations = serde_json::to_string(&snapshot)?;
    for prohibited in [
        MARKER,
        TOKEN,
        "SYNTHETIC_MACHINE_SECRET",
        "localhost",
        "127.0.0.1",
    ] {
        assert!(!observations.contains(prohibited));
    }
    Ok(())
}

#[tokio::test]
async fn outbound_tls_cancellation_closes_pending_socket_and_records_cancellation() {
    tls_lifecycle(true)
        .await
        .expect("outbound TLS cancellation and recovery");
}

#[tokio::test]
async fn outbound_tls_connect_deadline_closes_pending_socket_and_records_failure() {
    tls_lifecycle(false)
        .await
        .expect("outbound TLS connect deadline and recovery");
}

#[tokio::test]
async fn upstream_json_types_accept_case_and_parameters_and_reject_ambiguous_fields() {
    for execute in [false, true] {
        json_media_types(execute)
            .await
            .expect("JSON media cases and recovery");
    }
}

async fn json_media_types(execute: bool) -> TestResult<()> {
    let mut raw = Raw::new()?;
    let path = if execute { "/execute" } else { "/introspect" };
    let body = body(execute)?;
    for content_type in [
        "Application/JSON",
        "application/json; charset=utf-8",
        "application/json ; charset=utf-8",
        "Application/Json; Charset=\"UTF-8\"",
        "application/json\t;\tcharset=utf-8",
        "application/json; profile=\"a;\\\"b\"",
        "application/json;; charset=\"\"",
    ] {
        let headers = format!(
            "HTTP/1.1 200 Fixture\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let done = raw
            .queue(path, headers.into_bytes(), Some(body.clone()))
            .await?;
        timeout(Duration::from_secs(2), operation(&raw.upstream, execute)).await??;
        timeout(Duration::from_secs(2), done).await???;
    }
    for values in [
        vec![],
        vec!["text/plain"],
        vec!["application/jsonjunk"],
        vec!["application/json; charset"],
        vec!["application/json; profile=\"unterminated"],
        vec!["application/json; profile=\"good\"junk"],
        vec!["application/json; profile=bad value"],
        vec!["application/json; =missing"],
        vec!["application/json", "text/plain"],
        vec!["application/json", "application/json"],
    ] {
        let mut headers = format!(
            "HTTP/1.1 200 Fixture\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        for value in values {
            write!(headers, "Content-Type: {value}\r\n")?;
        }
        headers.push_str("\r\n");
        let done = raw.queue(path, headers.into_bytes(), None).await?;
        let failure = timeout(Duration::from_secs(2), operation(&raw.upstream, execute))
            .await?
            .err()
            .ok_or("invalid media type accepted")?;
        assert_eq!(failure.kind, Kind::Unavailable);
        timeout(Duration::from_secs(2), done).await???;
    }
    healthy_exchange(&raw, execute).await?;
    raw.finish().await
}
