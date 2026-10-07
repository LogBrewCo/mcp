//! Every request uses one certificate-verified HTTP/2 connection without reconnects.

use core::time::Duration;
use std::io;

use axum::{
    body::Bytes,
    http::{Request, StatusCode, Version},
};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::client::conn::http2::{SendRequest, handshake};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::Value;
use tokio::{task::JoinHandle, time::timeout};

use super::{Fixture, TestResult, decode_response, message};

pub(super) struct Connection {
    sender: SendRequest<Full<Bytes>>,
    driver: JoinHandle<Result<(), hyper::Error>>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl Connection {
    /// # Errors
    ///
    /// Returns a TLS, HTTP/2 handshake or timeout error.
    ///
    /// # Panics
    ///
    /// Panics if the connection does not negotiate HTTP/2.
    pub async fn open(fixture: &Fixture) -> TestResult<Self> {
        let tls = fixture.tls_protocol(Some(b"h2")).await?;
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let (sender, connection) = timeout(
            Duration::from_secs(2),
            handshake(TokioExecutor::new(), TokioIo::new(tls)),
        )
        .await??;
        Ok(Self {
            sender,
            driver: tokio::spawn(connection),
        })
    }

    /// # Errors
    ///
    /// Returns an authority, request, JSON, HTTP/2 exchange, body-read, response
    /// decoding or timeout error.
    ///
    /// # Panics
    ///
    /// Panics if response transport, cache policy, session isolation, rejection
    /// body or private-field redaction changes.
    pub async fn execute(
        &self,
        resource: &str,
        params: Value,
        token: &str,
    ) -> TestResult<(StatusCode, Value)> {
        let uri = resource.parse::<axum::http::Uri>()?;
        let authority = uri
            .authority()
            .ok_or_else(|| io::Error::other("missing test authority"))?;
        let request = Request::builder()
            .method("POST")
            .uri(&uri)
            .version(Version::HTTP_2)
            .header("Host", authority.as_str())
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", "execute")
            .body(Full::new(Bytes::from(serde_json::to_vec(&message(
                "tools/call",
                params,
            )?)?)))?;
        let mut sender = self.sender.clone();
        timeout(Duration::from_secs(3), async {
            sender.ready().await?;
            let response = sender.send_request(request).await?;
            assert_eq!(response.version(), Version::HTTP_2);
            let (parts, body) = response.into_parts();
            let bytes = Limited::new(body, 64 << 10_i32).collect().await?.to_bytes();
            Ok((
                parts.status,
                decode_response(parts.status, &parts.headers, &bytes)?,
            ))
        })
        .await?
    }

    /// # Errors
    ///
    /// Returns a driver timeout, unexpected task join or HTTP/2 connection error.
    pub async fn close(&mut self) -> TestResult<()> {
        self.driver.abort();
        match timeout(Duration::from_secs(2), &mut self.driver).await? {
            Ok(result) => result?,
            Err(error) if error.is_cancelled() => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
}
