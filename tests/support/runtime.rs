//! Run the production HTTPS serving function with an isolated authenticated router.

use std::{
    net::{SocketAddr, TcpListener},
    time::Duration,
};

use axum::Router;
use logbrew_mcp::{Failure, runtime, startup::Service};
use serde_json::{Value, json};
use tokio::{
    task::JoinHandle,
    time::{Instant, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

use super::http::TOKEN;

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub struct Running {
    pub address: SocketAddr,
    client: reqwest::Client,
    certificate: Vec<u8>,
    pub stop: CancellationToken,
    task: JoinHandle<Result<(), Failure>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.cancel();
        self.task.abort();
    }
}

impl Running {
    pub async fn start(router: Router) -> TestResult<Self> {
        let address = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
        Self::at(address, router, "resource.example").await
    }

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
        let end = Instant::now()
            .checked_add(Duration::from_secs(3))
            .ok_or("fixture deadline overflow")?;
        loop {
            let metadata = running
                .client
                .get(format!(
                    "https://localhost:{}/.well-known/oauth-protected-resource/mcp",
                    address.port()
                ))
                .header("Host", authority)
                .timeout(Duration::from_millis(200))
                .send()
                .await;
            if metadata.is_ok_and(|response| response.status() == reqwest::StatusCode::OK) {
                return Ok(running);
            }
            if running.task.is_finished() || Instant::now() >= end {
                return Err(std::io::Error::other("runtime readiness failed").into());
            }
            sleep(Duration::from_millis(5)).await;
        }
    }

    pub fn http1_client(&self) -> reqwest::Client {
        self.client.clone()
    }

    pub async fn tls(
        &self,
        protocol: Option<&[u8]>,
    ) -> TestResult<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
        super::peer::tls(self.address, &self.certificate, protocol).await
    }

    pub fn http2_client(&self) -> TestResult<reqwest::Client> {
        Ok(reqwest::Client::builder()
            .no_proxy()
            .http2_prior_knowledge()
            .pool_max_idle_per_host(0)
            .timeout(Duration::from_secs(3))
            .add_root_certificate(reqwest::Certificate::from_pem(&self.certificate)?)
            .build()?)
    }

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
                &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
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

    pub async fn wait(&mut self) -> TestResult<()> {
        timeout(Duration::from_secs(3), &mut self.task).await???;
        Ok(())
    }

    pub fn abort(&self) {
        self.task.abort();
    }
}
