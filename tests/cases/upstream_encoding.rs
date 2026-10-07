//! Declared upstream content coding controls JSON interpretation.

use core::time::Duration;
use std::io::Write as _;

use logbrew_mcp::error::Kind;
use tokio::{sync::oneshot, time::timeout};

use super::{
    hpack::literal,
    raw_upstream::Raw,
    upstream_transport::{body, operation},
};

type TestResult<T> = Result<T, Box<dyn core::error::Error + Send + Sync>>;
const MARKER: &str = "SYNTHETIC_PRIVATE_CODING_MARKER";

/// Queue a synthetic response with complete headers and optional body data.
///
/// # Errors
/// Returns a formatting, HPACK encoding or fixture queue error.
async fn queue(
    raw: &Raw,
    http2: bool,
    execute: bool,
    codings: &[&[u8]],
    bytes: Option<Vec<u8>>,
    length: usize,
) -> TestResult<oneshot::Receiver<TestResult<()>>> {
    if http2 {
        let mut fields = vec![0x88]; // Static HPACK status 200.
        literal(&mut fields, b"content-type", b"application/json", false)?;
        literal(
            &mut fields,
            b"content-length",
            length.to_string().as_bytes(),
            false,
        )?;
        for coding in codings {
            literal(&mut fields, b"content-encoding", coding, false)?;
        }
        raw.queue_http2(fields, bytes).await
    } else {
        let mut fields = format!(
            "HTTP/1.1 200 Fixture\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n"
        )
        .into_bytes();
        for coding in codings {
            write!(fields, "Content-Encoding: ")?;
            fields.extend_from_slice(coding);
            fields.extend_from_slice(b"\r\n");
        }
        fields.extend_from_slice(b"\r\n");
        raw.queue(
            if execute { "/execute" } else { "/introspect" },
            fields,
            bytes,
        )
        .await
    }
}

/// Read one operation and its fixture completion under separate observation bounds.
///
/// # Errors
/// Returns an operation, timeout or fixture receipt error, or an error if coding
/// that requires decoding is accepted.
///
/// # Panics
/// Panics if failure classification, retry guidance or diagnostic privacy changes.
async fn observe(
    raw: &Raw,
    execute: bool,
    rejected: bool,
    done: oneshot::Receiver<TestResult<()>>,
) -> TestResult<()> {
    let result = timeout(Duration::from_secs(2), operation(&raw.upstream, execute)).await?;
    timeout(Duration::from_secs(2), done).await???;
    if rejected {
        let failure = result.err().ok_or("unsupported upstream coding accepted")?;
        assert_eq!(failure.kind, Kind::Unavailable);
        assert_eq!(failure.retry_after_ms, None);
        for prohibited in [
            MARKER,
            "SYNTHETIC_PRIVATE_BODY_MARKER",
            super::http::TOKEN,
            "SYNTHETIC_MACHINE_SECRET",
        ] {
            assert!(!format!("{failure:?} {failure}").contains(prohibited));
        }
    } else {
        result?;
    }
    Ok(())
}

/// Verify successful unencoded JSON after rejected or supported coding.
///
/// # Errors
/// Returns a fixture, clock, operation or completion error.
///
/// # Panics
/// Panics if recovered execution data or verified identity changes.
async fn healthy(raw: &Raw, http2: bool, execute: bool, codings: &[&[u8]]) -> TestResult<()> {
    let bytes = body(execute)?;
    let length = bytes.len();
    let done = queue(raw, http2, execute, codings, Some(bytes), length).await?;
    observe(raw, execute, false, done).await
}

/// Verify rejection before interpreting complete, malformed or stalled data.
///
/// # Errors
/// Returns a fixture, clock, operation, timeout or completion error.
///
/// # Panics
/// Panics if failure classification, diagnostic privacy or recovery changes.
async fn rejected(raw: &Raw, http2: bool, execute: bool) -> TestResult<()> {
    let valid = body(execute)?;
    let codings: &[&[&[u8]]] = &[
        &[b"gzip"],
        &[b"br"],
        &[b"deflate"],
        &[b"identity, gzip"],
        &[b"gzip", b"identity"],
        &[b"identity", b"br"],
        &[b"identity;q=1"],
        &[b"\"identity\""],
        &[MARKER.as_bytes()],
        &[&[0xff]],
    ];
    for (index, coding) in codings.iter().enumerate() {
        let done = queue(
            raw,
            http2,
            execute,
            coding,
            Some(valid.clone()),
            valid.len(),
        )
        .await?;
        observe(raw, execute, true, done)
            .await
            .map_err(|error| std::io::Error::other(format!("coding rejection {index}: {error}")))?;
        healthy(raw, http2, execute, &[])
            .await
            .map_err(|error| std::io::Error::other(format!("coding recovery {index}: {error}")))?;
    }
    for bytes in [
        Some(b"SYNTHETIC_PRIVATE_BODY_MARKER".to_vec()),
        Some(vec![0x1f, 0x8b, 0x08, 0x00]),
        None,
    ] {
        let length = bytes.as_ref().map_or(1024, Vec::len);
        let done = queue(raw, http2, execute, &[b"gzip"], bytes, length).await?;
        observe(raw, execute, true, done).await?;
        healthy(raw, http2, execute, &[]).await?;
    }
    Ok(())
}

/// Run supported coding, rejection and healthy recovery through an actual TLS peer.
///
/// # Errors
/// Returns a fixture, clock, coding, operation, timeout or shutdown error.
///
/// # Panics
/// Panics if failure classification, diagnostic privacy, verified identity or data changes.
async fn exercise(http2: bool, execute: bool) -> TestResult<()> {
    let mut raw = if http2 { Raw::http2()? } else { Raw::new()? };
    for (index, coding) in [
        &[][..],
        &[b"identity".as_slice()][..],
        &[b"IDENTITY".as_slice()][..],
        &[b"identity".as_slice(), b"IDENTITY".as_slice()][..],
        &[b", , identity, ,".as_slice()][..],
    ]
    .into_iter()
    .enumerate()
    {
        healthy(&raw, http2, execute, coding)
            .await
            .map_err(|error| std::io::Error::other(format!("supported coding {index}: {error}")))?;
    }
    rejected(&raw, http2, execute).await?;
    raw.finish().await
}

#[tokio::test]
/// # Errors
/// Fails if HTTP/1 authorization accepts unsupported coding or loses recovery.
///
/// # Panics
/// Panics if verified identity, failure classification or diagnostic privacy changes.
async fn introspection_http1_coding_rejection_and_recovery() -> TestResult<()> {
    exercise(false, false).await
}

#[tokio::test]
/// # Errors
/// Fails if HTTP/1 execution accepts unsupported coding or loses recovery.
///
/// # Panics
/// Panics if execution data, failure classification or diagnostic privacy changes.
async fn execution_http1_coding_rejection_and_recovery() -> TestResult<()> {
    exercise(false, true).await
}

#[tokio::test]
/// # Errors
/// Fails if HTTP/2 authorization accepts unsupported coding or loses recovery.
///
/// # Panics
/// Panics if verified identity, failure classification or diagnostic privacy changes.
async fn introspection_http2_coding_rejection_and_recovery() -> TestResult<()> {
    exercise(true, false).await
}

#[tokio::test]
/// # Errors
/// Fails if HTTP/2 execution accepts unsupported coding or loses recovery.
///
/// # Panics
/// Panics if execution data, failure classification or diagnostic privacy changes.
async fn execution_http2_coding_rejection_and_recovery() -> TestResult<()> {
    exercise(true, true).await
}
