//! HTTPS transport with bounded response parsing and connection establishment.

use std::{
    error::Error,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    body::Bytes,
    http::{HeaderValue, Request, Uri, header},
};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioTimer},
};
use rustls::pki_types::CertificateDer;
use tower_service::Service;

use crate::{Failure, error::Kind};

pub type Response = axum::http::Response<Incoming>;
type Connector = HttpsConnector<HttpConnector>;
type ConnectError = Box<dyn Error + Send + Sync>;
type ConnectFuture = Pin<
    Box<dyn Future<Output = Result<<Connector as Service<Uri>>::Response, ConnectError>> + Send>,
>;

#[derive(Clone)]
struct ConnectDeadline(Connector);

impl Service<Uri> for ConnectDeadline {
    type Response = <Connector as Service<Uri>>::Response;
    type Error = ConnectError;
    type Future = ConnectFuture;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        let connecting = self.0.call(req);
        Box::pin(async move { tokio::time::timeout(Duration::from_secs(5), connecting).await? })
    }
}

pub struct Outbound {
    client: Client<ConnectDeadline, Full<Bytes>>,
}

impl Outbound {
    /// Construct the fixed HTTPS client with system trust and bounded connections.
    ///
    /// # Errors
    /// Rejects an empty or oversized extra certificate and TLS verifier or
    /// protocol configuration failures.
    pub(super) fn new(certificate: Option<CertificateDer<'static>>) -> Result<Self, Failure> {
        if certificate.as_ref().is_some_and(|certificate| {
            certificate.as_ref().is_empty() || certificate.as_ref().len() > 256 << 10_u32
        }) {
            return Err(Kind::Configuration.into());
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier = certificate
            .map_or_else(
                || rustls_platform_verifier::Verifier::new(Arc::clone(&provider)),
                |certificate| {
                    rustls_platform_verifier::Verifier::new_with_extra_roots(
                        vec![certificate],
                        Arc::clone(&provider),
                    )
                },
            )
            .map_err(Failure::redact(Kind::Configuration))?;
        // The platform verifier retains system trust and checks names and signatures.
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(Failure::redact(Kind::Configuration))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(Some(Duration::from_secs(5)));
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_only()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http);
        let client = Client::builder(TokioExecutor::new())
            .timer(TokioTimer::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(64)
            .http1_max_buf_size(16 << 10)
            .http1_max_headers(100)
            .http2_max_header_list_size(16 << 10)
            .retry_canceled_requests(false)
            .build(ConnectDeadline(connector));
        Ok(Self { client })
    }

    /// Send one authenticated POST through the configured HTTPS connector.
    ///
    /// # Errors
    /// Returns Unavailable if the request cannot be built or the exchange fails.
    pub(super) async fn post(
        &self,
        endpoint: &str,
        authorization: HeaderValue,
        content_type: &'static str,
        bytes: Vec<u8>,
    ) -> Result<Response, Failure> {
        let request = Request::builder()
            .method("POST")
            .uri(endpoint)
            .header(header::AUTHORIZATION, authorization)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::ACCEPT, "application/json")
            .header(header::CACHE_CONTROL, "no-store")
            .body(Full::new(Bytes::from(bytes)))
            .map_err(Failure::redact(Kind::Unavailable))?;
        self.client
            .request(request)
            .await
            .map_err(Failure::redact(Kind::Unavailable))
    }
}
