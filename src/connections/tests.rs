//! Protocol detection completion, byte preservation and admission ownership.

use alloc::sync::Arc;
use core::{
    future::poll_fn,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
    time::Duration,
};
use std::io;

use tokio::{
    io::{AsyncRead, ReadBuf},
    sync::Semaphore,
    time::sleep,
};
use tokio_util::sync::CancellationToken;

use super::{HTTP2_PREFACE, LimitedStream, PrefixDeadline};

type TestResult<T> = Result<T, Box<dyn core::error::Error>>;

struct ControlledRead {
    bytes: &'static [u8],
    delay: Duration,
    polls: Arc<AtomicUsize>,
}

impl AsyncRead for ControlledRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let _previous = self.polls.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        if self.bytes.len() > buf.remaining() {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        buf.put_slice(self.bytes);
        self.bytes = b"";
        Poll::Ready(Ok(()))
    }
}

/// Construct one admitted reader with a controlled protocol deadline.
///
/// # Errors
/// Returns an error if its initial admission permit cannot be acquired.
fn stream(
    bytes: &'static [u8],
    delay: Duration,
    budget: Duration,
    matched: usize,
) -> TestResult<(LimitedStream<ControlledRead>, Arc<Semaphore>)> {
    let slots = Arc::new(Semaphore::new(1));
    let permit = Arc::clone(&slots).try_acquire_owned()?;
    let cancelled = CancellationToken::new();
    Ok((
        LimitedStream {
            inner: ControlledRead {
                bytes,
                delay,
                polls: Arc::new(AtomicUsize::new(0)),
            },
            _permit: permit,
            prefix: Some(PrefixDeadline {
                matched,
                timer: Box::pin(sleep(budget)),
            }),
            expired: Box::pin(cancelled.cancelled_owned()),
        },
        slots,
    ))
}

/// Reject late HTTP/1 selection, HTTP/2 selection and final preface bytes.
///
/// # Errors
/// Returns an error if the controlled admission permit cannot be acquired.
///
/// # Panics
/// Fails if a late read supplies bytes, selects a protocol or retains capacity.
#[tokio::test]
// Reviewed 2026-10-08; review by 2026-11-08 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
async fn late_protocol_selection_rejects_bytes_and_releases_capacity() -> TestResult<()> {
    for (bytes, matched) in [
        (b"G".as_slice(), 0),
        (HTTP2_PREFACE, 0),
        (b"\n".as_slice(), 23),
    ] {
        let (mut connection, slots) = stream(
            bytes,
            Duration::from_millis(20),
            Duration::from_millis(5),
            matched,
        )?;
        let mut storage = [0; 32];
        let mut buffer = ReadBuf::new(&mut storage);
        buffer.put_slice(b"old");
        let result =
            poll_fn(|context| Pin::new(&mut connection).poll_read(context, &mut buffer)).await;
        assert_eq!(
            result.map_err(|error| error.kind()),
            Err(io::ErrorKind::TimedOut)
        );
        assert_eq!(buffer.filled(), b"old");
        assert_eq!(
            connection.prefix.as_ref().map(|prefix| prefix.matched),
            Some(matched)
        );
        assert_eq!(connection.inner.polls.load(Ordering::SeqCst), 1);
        assert_eq!(slots.available_permits(), 0);
        drop(connection);
        assert_eq!(slots.available_permits(), 1);
        let _recovered = slots.try_acquire()?;
    }
    Ok(())
}

/// Preserve timely protocol bytes and permit later reads after selection.
///
/// # Errors
/// Returns an error if admission or a promptly completed read fails.
///
/// # Panics
/// Fails if protocol selection changes bytes or continues the prefix timer.
#[tokio::test]
// Reviewed 2026-10-08; review by 2026-11-08 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
async fn timely_protocol_selection_preserves_bytes_and_later_reads() -> TestResult<()> {
    for bytes in [b"G".as_slice(), HTTP2_PREFACE] {
        let (mut connection, slots) = stream(bytes, Duration::ZERO, Duration::from_secs(1), 0)?;
        let mut storage = [0; 32];
        let mut buffer = ReadBuf::new(&mut storage);
        poll_fn(|context| Pin::new(&mut connection).poll_read(context, &mut buffer)).await?;
        assert_eq!(buffer.filled(), bytes);
        assert!(connection.prefix.is_none());
        connection.inner.bytes = b"body";
        connection.inner.delay = Duration::from_millis(20);
        buffer.clear();
        poll_fn(|context| Pin::new(&mut connection).poll_read(context, &mut buffer)).await?;
        assert_eq!(buffer.filled(), b"body");
        drop(connection);
        assert_eq!(slots.available_permits(), 1);
    }
    Ok(())
}

/// Reject an already expired prefix without polling its reader or changing bytes.
///
/// # Errors
/// Returns an error if the controlled admission permit cannot be acquired.
///
/// # Panics
/// Fails if expiration reads data, alters existing bytes or retains capacity.
#[tokio::test]
// Reviewed 2026-10-08; review by 2026-11-08 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
async fn expired_protocol_detection_does_not_poll_or_change_bytes() -> TestResult<()> {
    let (mut connection, slots) = stream(b"G", Duration::ZERO, Duration::ZERO, 0)?;
    let mut storage = [0; 32];
    let mut buffer = ReadBuf::new(&mut storage);
    buffer.put_slice(b"old");
    let result = poll_fn(|context| Pin::new(&mut connection).poll_read(context, &mut buffer)).await;
    assert_eq!(
        result.map_err(|error| error.kind()),
        Err(io::ErrorKind::TimedOut)
    );
    assert_eq!(buffer.filled(), b"old");
    assert_eq!(connection.inner.polls.load(Ordering::SeqCst), 0);
    drop(connection);
    assert_eq!(slots.available_permits(), 1);
    Ok(())
}
