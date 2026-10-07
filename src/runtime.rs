//! Bounded HTTPS serving shared by the standalone process and runtime regressions.

use core::{future::Future, net::SocketAddr, time::Duration};

use hyper_util::{
    rt::TokioExecutor,
    server::conn::auto::{Http1Builder, Http2Builder},
};

use crate::{Failure, connections::ConnectionLimit, error::Kind, startup::Service};

struct Stop(axum_server::Handle<SocketAddr>);

impl Drop for Stop {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

/// Serve validated configuration until termination, preserving active request drain.
///
/// # Errors
/// Returns a fixed failure for listener errors, shutdown-source failure or
/// incomplete connection drain. Cancelling this future stops admitted connections.
#[expect(
    clippy::integer_division_remainder_used,
    reason = "Tokio select uses remainder for fair branch polling; this is not cryptographic arithmetic."
)]
pub async fn serve<Shutdown>(service: Service, shutdown: Shutdown) -> Result<(), Failure>
where
    Shutdown: Future<Output = Result<(), Failure>>,
{
    let handle = axum_server::Handle::new();
    let _stop = Stop(handle.clone());
    let acceptor = axum_server::tls_rustls::RustlsAcceptor::new(service.tls)
        .handshake_timeout(Duration::from_secs(5));
    let mut server = axum_server::bind(service.address)
        .acceptor(ConnectionLimit::new(acceptor, 64))
        .handle(handle.clone());
    let _: &mut Http1Builder<'_, TokioExecutor> = server
        .http_builder()
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(5))
        .max_buf_size(16 << 10)
        .max_headers(100);
    let _: &mut Http2Builder<'_, TokioExecutor> = server
        .http_builder()
        .http2()
        .timer(hyper_util::rt::TokioTimer::new())
        .keep_alive_interval(Duration::from_secs(5))
        .keep_alive_timeout(Duration::from_secs(5))
        .max_header_list_size(16 << 10)
        .max_concurrent_streams(64);
    let future = server.serve(service.router.into_make_service());
    tokio::pin!(future);
    tokio::select! {
        result = &mut future => result.map_err(Failure::redact(Kind::Unavailable)),
        result = shutdown => {
            result?;
            handle.graceful_shutdown(Some(Duration::from_secs(12)));
            future.await.map_err(Failure::redact(Kind::Unavailable))?;
            if handle.connection_count() != 0 {
                return Err(Kind::Unavailable.into());
            }
            Ok(())
        }
    }
}
