//! Bound connection admission and HTTP protocol detection without a waiting queue.

use std::{
    future::Future,
    io::{self, IoSlice},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use axum::http::Request;
use axum_server::accept::Accept;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{Sleep, sleep},
};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};
use tower_service::Service;

use crate::delivery::Connection;

const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

struct PrefixDeadline {
    matched: usize,
    timer: Pin<Box<Sleep>>,
}

#[derive(Clone)]
pub struct ConnectionLimit<A> {
    inner: A,
    slots: Arc<Semaphore>,
}

impl<A> ConnectionLimit<A> {
    pub(super) fn new(inner: A, limit: usize) -> Self {
        Self {
            inner,
            slots: Arc::new(Semaphore::new(limit)),
        }
    }
}

pub struct LimitedStream<S> {
    inner: S,
    _permit: OwnedSemaphorePermit,
    prefix: Option<PrefixDeadline>,
    expired: Pin<Box<WaitForCancellationFutureOwned>>,
}

#[derive(Clone)]
pub struct ConnectedService<S> {
    inner: S,
    connection: Connection,
}

impl<S, B> Service<Request<B>> for ConnectedService<S>
where
    S: Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        drop(request.extensions_mut().insert(self.connection.clone()));
        self.inner.call(request)
    }
}

impl<S> LimitedStream<S> {
    fn check_delivery(&mut self, context: &mut Context<'_>) -> io::Result<()> {
        if self.expired.as_mut().poll(context).is_ready() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "response delivery deadline exceeded",
            ));
        }
        Ok(())
    }
}

impl<A, I, S> Accept<I, S> for ConnectionLimit<A>
where
    A: Accept<I, S>,
    A::Future: Send + 'static,
    A::Stream: Send + 'static,
    A::Service: Send + 'static,
{
    type Stream = LimitedStream<A::Stream>;
    type Service = ConnectedService<A::Service>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let Ok(permit) = Arc::clone(&self.slots).try_acquire_owned() else {
            return Box::pin(std::future::ready(Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "connection capacity reached",
            ))));
        };
        let future = self.inner.accept(stream, service);
        Box::pin(async move {
            let (inner, service) = future.await?;
            let cancelled = CancellationToken::new();
            Ok((
                LimitedStream {
                    inner,
                    _permit: permit,
                    // Hyper's HTTP/1 header timer starts after protocol detection.
                    prefix: Some(PrefixDeadline {
                        matched: 0,
                        timer: Box::pin(sleep(Duration::from_secs(5))),
                    }),
                    expired: Box::pin(cancelled.clone().cancelled_owned()),
                },
                ConnectedService {
                    inner: service,
                    connection: Connection(cancelled),
                },
            ))
        })
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for LimitedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.as_mut().get_mut().check_delivery(context)?;
        let Self { inner, prefix, .. } = self.get_mut();
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if prefix
            .as_mut()
            .is_some_and(|prefix| prefix.timer.as_mut().poll(context).is_ready())
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "protocol detection deadline exceeded",
            )));
        }
        let filled = buffer.filled().len();
        let result = Pin::new(inner).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(())))
            && let Some(pending) = prefix.as_mut()
        {
            for byte in buffer.filled().get(filled..).unwrap_or_default() {
                // A mismatch selects HTTP/1; the full preface selects HTTP/2.
                // Neither path keeps this deadline during authenticated work.
                if HTTP2_PREFACE.get(pending.matched) != Some(byte) {
                    *prefix = None;
                    break;
                }
                let Some(matched) = pending.matched.checked_add(1) else {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid protocol detection state",
                    )));
                };
                pending.matched = matched;
                if pending.matched == HTTP2_PREFACE.len() {
                    *prefix = None;
                    break;
                }
            }
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for LimitedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.check_delivery(context)?;
        Pin::new(&mut this.inner).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check_delivery(context)?;
        Pin::new(&mut this.inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.check_delivery(context)?;
        Pin::new(&mut this.inner).poll_write_vectored(context, buffers)
    }
}
