//! Run the production HTTPS serving function with an isolated authenticated router.

use core::{net::SocketAddr, sync::atomic::Ordering, time::Duration};
use std::net::TcpListener;

use axum::Router;
use logbrew_mcp::{Failure, runtime, startup::Service};
use serde_json::{Value, json};
use tokio::{
    task::JoinHandle,
    time::{Instant, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

use super::http::{Fixture, TOKEN};

type TestResult<T> = Result<T, Box<dyn core::error::Error + Send + Sync>>;

pub struct Running {
    address: SocketAddr,
    client: reqwest::Client,
    certificate: Vec<u8>,
    stop: CancellationToken,
    task: JoinHandle<Result<(), Failure>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.cancel();
        self.task.abort();
    }
}

impl Running {
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    pub const fn stop(&self) -> &CancellationToken {
        &self.stop
    }

    /// Start the production serving function at a temporary loopback address.
    ///
    /// # Errors
    /// Returns an error if address selection, TLS setup or readiness fails.
    pub async fn start(router: Router) -> TestResult<Self> {
        let address = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
        Self::at(address, router, "resource.example").await
    }

    /// Start an isolated HTTPS service and wait for its resource metadata.
    ///
    /// # Errors
    /// Returns an error if certificate generation, TLS or client construction,
    /// or the bounded readiness check fails.
    pub async fn at(address: SocketAddr, router: Router, authority: &str) -> TestResult<Self> {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
        let pem = certificate.cert.pem();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            pem.as_bytes().to_vec(),
            certificate.signing_key.serialize_pem().as_bytes().to_vec(),
        )
        .await?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .http1_only()
            .pool_max_idle_per_host(0)
            .timeout(Duration::from_secs(3))
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes())?)
            .build()?;
        let stop = CancellationToken::new();
        let shutdown = stop.clone();
        let service = Service {
            address,
            router,
            tls,
        };
        let task = tokio::spawn(runtime::serve(service, async move {
            shutdown.cancelled().await;
            Ok(())
        }));
        let running = Self {
            address,
            client,
            certificate: pem.into_bytes(),
            stop,
            task,
        };
        ready(&running, authority).await?;
        Ok(running)
    }

    pub fn http1_client(&self) -> reqwest::Client {
        self.client.clone()
    }

    /// Connect with fixture certificate trust and the selected ALPN protocol.
    ///
    /// # Errors
    /// Returns an error if trust setup, the TCP connection or TLS negotiation fails.
    pub async fn tls(
        &self,
        protocol: Option<&[u8]>,
    ) -> TestResult<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
        super::peer::tls(self.address, &self.certificate, protocol).await
    }

    /// Build an HTTP/2 client with fixture certificate trust and a request deadline.
    ///
    /// # Errors
    /// Returns an error if the certificate cannot be parsed or client setup fails.
    pub fn http2_client(&self) -> TestResult<reqwest::Client> {
        Ok(reqwest::Client::builder()
            .no_proxy()
            .http2_prior_knowledge()
            .pool_max_idle_per_host(0)
            .timeout(Duration::from_secs(3))
            .add_root_certificate(reqwest::Certificate::from_pem(&self.certificate)?)
            .build()?)
    }

    /// Execute the synthetic read through the production HTTPS service.
    ///
    /// # Errors
    /// Returns an error if the request fails, its HTTP status is unsuccessful,
    /// or its response body cannot be read as JSON.
    pub async fn execute(&self) -> TestResult<Value> {
        Ok(self
            .client
            .post(format!("https://localhost:{}/mcp", self.address.port()))
            .header("Host", "resource.example")
            .header("Authorization", format!("Bearer {TOKEN}"))
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", "execute")
            .json(
                &json!({"jsonrpc":"2.0","id":1_i32,"method":"tools/call","params":{
                "name":"execute","arguments":{"operation":"logs.read.v1","input":{}},"_meta":{
                    "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                    "io.modelcontextprotocol/clientInfo":{"name":"synthetic","version":"1"},
                    "io.modelcontextprotocol/clientCapabilities":{}}}}),
            )
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Wait up to three seconds for successful serving-task completion.
    ///
    /// # Errors
    /// Returns an error if the wait expires, the task fails to join,
    /// or the serving function returns a failure.
    pub async fn wait(&mut self) -> TestResult<()> {
        timeout(Duration::from_secs(3), &mut self.task).await???;
        Ok(())
    }

    pub fn abort(&self) {
        self.task.abort();
    }
}

/// Poll resource metadata until the service answers or readiness fails.
///
/// # Errors
/// Returns an error if the deadline cannot be represented, the serving task
/// finishes before readiness, or no successful response arrives before the deadline.
async fn ready(running: &Running, authority: &str) -> TestResult<()> {
    let end = Instant::now()
        .checked_add(Duration::from_secs(3))
        .ok_or("fixture deadline overflow")?;
    loop {
        let metadata = running
            .client
            .get(format!(
                "https://localhost:{}/.well-known/oauth-protected-resource/mcp",
                running.address.port()
            ))
            .header("Host", authority)
            .timeout(Duration::from_millis(200))
            .send()
            .await;
        if metadata.is_ok_and(|response| response.status() == reqwest::StatusCode::OK) {
            return Ok(());
        }
        if running.task.is_finished() || Instant::now() >= end {
            return Err(std::io::Error::other("runtime readiness failed").into());
        }
        sleep(Duration::from_millis(5)).await;
    }
}

/// Poll a condition at the supplied interval within a bounded wait.
///
/// # Errors
/// Returns an elapsed error if the condition is not met before the wait expires.
pub async fn wait_until<Ready>(
    limit: Duration,
    interval: Duration,
    ready: Ready,
) -> Result<(), tokio::time::error::Elapsed>
where
    Ready: FnMut() -> bool,
{
    timeout(limit, poll_until(interval, ready)).await
}

/// Wait until the fixture has exactly the expected active execution count.
///
/// # Errors
/// Returns an elapsed error if the expected count is not observed within the limit.
pub async fn wait_executions(
    fixture: &Fixture,
    expected: usize,
    limit: Duration,
) -> Result<(), tokio::time::error::Elapsed> {
    wait_until(limit, Duration::from_millis(5), || {
        fixture.state().active_executions().load(Ordering::SeqCst) == expected
    })
    .await
}

async fn poll_until<Ready>(interval: Duration, mut ready: Ready)
where
    Ready: FnMut() -> bool,
{
    while !ready() {
        sleep(interval).await;
    }
}
