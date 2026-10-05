//! Correlation restoration preserves payload bytes and bounds failed bodies.

use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use axum::body::Bytes;
use http_body::Frame;
use tokio::time::timeout;

use super::*;

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Parse the exact numeric identifier used by correlation-restoration fixtures.
///
/// # Errors
/// Returns an error if the controlled numeric fixture cannot be parsed as JSON.
fn original() -> TestResult<Value> {
    Ok(serde_json::from_str("18446744073709551616")?)
}

/// Restore correlation while preserving exact result and error payload bytes.
///
/// # Errors
/// Returns an error if identifier parsing, restoration or UTF-8 decoding fails.
///
/// # Panics
/// Panics if restoring correlation changes the result or error payload.
#[test]
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
fn restoration_preserves_result_and_error_json_verbatim() -> TestResult<()> {
    let id = original()?;
    for field in ["result", "error"] {
        let payload = r#"{ "value":9007199254740993.000, "huge":1e1024, "$serde_json::private::Number":"ordinary", "nested":[true,null,{"x":"\\\""}] }"#;
        let reply = format!(r#"{{"jsonrpc":"2.0","id":"{INTERNAL_ID}","{field}":{payload}}}"#);
        let restored = restore(reply.as_bytes(), &id)
            .ok_or_else(|| io::Error::other("valid reply rejected"))?;
        assert_eq!(
            String::from_utf8(restored)?,
            format!(r#"{{"jsonrpc":"2.0","id":{id},"{field}":{payload}}}"#)
        );
    }
    Ok(())
}

/// Reject malformed, ambiguous or unrelated replies before correlation restoration.
///
/// # Errors
/// Returns an error if the controlled numeric identifier cannot be parsed.
///
/// # Panics
/// Panics if any rejected reply is reassigned to the original request.
#[test]
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
fn malformed_or_uncorrelated_replies_cannot_be_reassigned() -> TestResult<()> {
    let id = original()?;
    for fields in [
        r#""id":"foreign","result":{}"#,
        r#""id":null,"error":{}"#,
        r#""id":1,"result":{}"#,
        r#""result":{}"#,
        r#""id":"logbrew-integer-id""#,
        r#""id":"logbrew-integer-id","result":{},"error":{}"#,
        r#""id":"logbrew-integer-id","result":null,"error":{}"#,
        r#""id":"logbrew-integer-id","result":{},"error":null"#,
        r#""id":"logbrew-integer-id","result":null"#,
        r#""id":"logbrew-integer-id","error":[]"#,
        r#""id":"logbrew-integer-id","result":3"#,
        r#""id":"logbrew-integer-id","result":{},"extra":true"#,
        r#""id":"logbrew-integer-id","id":"logbrew-integer-id","result":{}"#,
        r#""id":"logbrew-integer-id","result":{},"result":{}"#,
    ] {
        let reply = format!(r#"{{"jsonrpc":"2.0",{fields}}}"#);
        assert!(restore(reply.as_bytes(), &id).is_none(), "reply {reply}");
    }
    let wrong_version = format!(r#"{{"jsonrpc":"1.0","id":"{INTERNAL_ID}","result":{{}}}}"#);
    assert!(restore(wrong_version.as_bytes(), &id).is_none());
    assert!(restore(b"not JSON SYNTHETIC_PRIVATE_MARKER", &id).is_none());
    Ok(())
}

/// Recover a missing identifier only for the request-scoped SDK parse error.
///
/// # Errors
/// Returns an error if identifier parsing, restoration or response parsing fails.
///
/// # Panics
/// Panics if the recovered identifier or parse-error code is incorrect.
#[test]
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
fn a_request_scoped_sdk_parse_error_can_recover_its_missing_id() -> TestResult<()> {
    let id = original()?;
    let bytes = restore(
        br#"{"jsonrpc":"2.0","error":{"code":-32600,"message":"invalid request"}}"#,
        &id,
    )
    .ok_or_else(|| io::Error::other("SDK error rejected"))?;
    let reply: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(reply.get("id"), Some(&id));
    assert_eq!(reply.pointer("/error/code"), Some(&json!(-32_600_i32)));
    Ok(())
}

/// Wrap a fixture body with JSON media type and deliberately stale length metadata.
///
/// # Errors
/// Returns an error if the fixture HTTP response cannot be constructed.
fn response(body: Body) -> TestResult<Response> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, "1")
        .header("cache-control", "no-store")
        .body(body)?)
}

/// Remove stale length metadata after restoration while preserving other headers.
///
/// # Errors
/// Returns an error if fixture construction, body reading or JSON parsing fails.
///
/// # Panics
/// Panics if the status, restored identifier or retained/removed headers are wrong.
#[tokio::test]
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
async fn restored_replies_remove_stale_lengths_and_preserve_other_headers() -> TestResult<()> {
    let id = original()?;
    let bytes = format!(r#"{{"jsonrpc":"2.0","id":"{INTERNAL_ID}","result":{{}}}}"#);
    let reply = restore_id(Some(NumericId(id.clone())), response(Body::from(bytes))?).await;
    assert_eq!(reply.status(), StatusCode::OK);
    assert!(reply.headers().get(header::CONTENT_LENGTH).is_none());
    assert_eq!(
        reply
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let body: Value = serde_json::from_slice(&to_bytes(reply.into_body(), 4096).await?)?;
    assert_eq!(body.get("id"), Some(&id));
    Ok(())
}

/// Preserve bodies and headers when correlation restoration does not apply.
///
/// # Errors
/// Returns an error if fixture construction, identifier parsing or body reading fails.
///
/// # Panics
/// Panics if unchanged replies lose their status, original body or length metadata.
#[tokio::test]
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
async fn untouched_ids_and_plain_http_errors_keep_their_original_body() -> TestResult<()> {
    let id = original()?;
    let bytes = "SYNTHETIC_BODY";
    let uncorrelated = restore_id(None, response(Body::from(bytes))?).await;
    assert_eq!(
        uncorrelated
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("1")
    );
    assert_eq!(to_bytes(uncorrelated.into_body(), 4096).await?, bytes);
    let plain = (StatusCode::SERVICE_UNAVAILABLE, bytes).into_response();
    let unchanged = restore_id(Some(NumericId(id)), plain).await;
    assert_eq!(unchanged.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(to_bytes(unchanged.into_body(), 4096).await?, bytes);
    Ok(())
}

struct Probe {
    frame: Option<Result<Frame<Bytes>, io::Error>>,
    pending: bool,
    dropped: Arc<AtomicBool>,
}

impl Drop for Probe {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

impl http_body::Body for Probe {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.pending {
            Poll::Pending
        } else {
            Poll::Ready(self.frame.take())
        }
    }
}

/// Drop rejected bodies and return a correlated error without their private bytes.
///
/// # Errors
/// Returns an error if fixture construction, body reading or JSON parsing fails.
///
/// # Panics
/// Panics if rejected bytes leak, correlation or the fixed error changes,
/// or a rejected body remains owned.
#[tokio::test]
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
async fn oversized_broken_and_invalid_bodies_drop_and_hide_rejected_bytes() -> TestResult<()> {
    let id = original()?;
    for frame in [
        Ok(Frame::data(Bytes::from(vec![b'x'; REPLY_BYTES + 1]))),
        Err(io::Error::other("SYNTHETIC_PRIVATE_MARKER")),
        Ok(Frame::data(Bytes::from_static(b"SYNTHETIC_PRIVATE_MARKER"))),
    ] {
        let dropped = Arc::new(AtomicBool::new(false));
        let body = Body::new(Probe {
            frame: Some(frame),
            pending: false,
            dropped: Arc::clone(&dropped),
        });
        let reply = restore_id(Some(NumericId(id.clone())), response(body)?).await;
        assert_eq!(reply.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = to_bytes(reply.into_body(), 4096).await?;
        assert!(!String::from_utf8_lossy(&bytes).contains("SYNTHETIC_"));
        let envelope: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(envelope.get("id"), Some(&id));
        assert_eq!(envelope.pointer("/error/code"), Some(&json!(-32_603_i32)));
        assert!(dropped.load(Ordering::SeqCst));
    }
    Ok(())
}

/// Drop a pending response body when correlation restoration is cancelled.
///
/// # Errors
/// Returns an error if identifier parsing or fixture response construction fails.
///
/// # Panics
/// Panics if restoration unexpectedly completes or cancellation retains the body.
#[tokio::test]
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
async fn cancelling_restoration_drops_the_pending_body() -> TestResult<()> {
    let dropped = Arc::new(AtomicBool::new(false));
    let body = Body::new(Probe {
        frame: None,
        pending: true,
        dropped: Arc::clone(&dropped),
    });
    let _: tokio::time::error::Elapsed = timeout(
        Duration::from_millis(20),
        restore_id(Some(NumericId(original()?)), response(body)?),
    )
    .await
    .unwrap_err();
    assert!(dropped.load(Ordering::SeqCst));
    Ok(())
}
