//! Synthetic issuer and execution service for normal executable tests.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode, header},
    routing::post,
};
use base64::Engine as _;
use serde_json::{Value, json};
use tokio::time::timeout;

use super::{super::count::discard_count, TestResult};

pub(super) const TOKEN: &str = "SYNTHETIC_DELEGATED_CREDENTIAL";
const SECRET: &str = "SYNTHETIC_MACHINE_SECRET";

#[derive(Clone, Copy)]
pub(super) enum PendingStage {
    Verification,
    Execution,
}

pub(super) struct Observations {
    pub active: AtomicBool,
    pub verifies: AtomicUsize,
    pub executes: AtomicUsize,
    pause: AtomicBool,
    pending: Arc<AtomicUsize>,
    verification_pause: AtomicBool,
    verification_pending: Arc<AtomicUsize>,
    issuer: String,
    resource: String,
}

struct PendingGuard(Arc<AtomicUsize>);

impl Drop for PendingGuard {
    fn drop(&mut self) {
        discard_count(self.0.fetch_sub(1, Ordering::SeqCst));
    }
}

impl Observations {
    const fn stage(&self, stage: PendingStage) -> (&AtomicBool, &Arc<AtomicUsize>) {
        match stage {
            PendingStage::Verification => (&self.verification_pause, &self.verification_pending),
            PendingStage::Execution => (&self.pause, &self.pending),
        }
    }

    pub fn set_pause(&self, stage: PendingStage, paused: bool) {
        self.stage(stage).0.store(paused, Ordering::SeqCst);
    }

    pub fn pending_count(&self, stage: PendingStage) -> usize {
        self.stage(stage).1.load(Ordering::SeqCst)
    }

    async fn enter(&self, stage: PendingStage) -> PendingGuard {
        let (paused, pending) = self.stage(stage);
        discard_count(pending.fetch_add(1, Ordering::SeqCst));
        let active = PendingGuard(Arc::clone(pending));
        if paused.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        active
    }

    /// # Errors
    ///
    /// Returns a timeout if the pending request count does not reach `count`.
    pub async fn wait_for_pending(&self, stage: PendingStage, count: usize) -> TestResult<()> {
        timeout(Duration::from_secs(2), pending_count(self, stage, count)).await?;
        Ok(())
    }
}

async fn pending_count(observed: &Observations, stage: PendingStage, count: usize) {
    while observed.pending_count(stage) != count {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

pub(super) struct Backend {
    pub endpoint: String,
    pub certificate: String,
    pub observations: Arc<Observations>,
    handle: axum_server::Handle<SocketAddr>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.handle.shutdown();
        self.task.abort();
    }
}

impl Backend {
    /// # Errors
    ///
    /// Returns a listener, certificate, TLS configuration or startup timeout error.
    pub async fn start(resource: String) -> TestResult<Self> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let endpoint = format!("https://localhost:{}", address.port());
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
        let pem = certificate.cert.pem();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            pem.as_bytes().to_vec(),
            certificate.signing_key.serialize_pem().as_bytes().to_vec(),
        )
        .await?;
        let observations = Arc::new(Observations {
            active: AtomicBool::new(true),
            verifies: AtomicUsize::new(0),
            executes: AtomicUsize::new(0),
            pause: AtomicBool::new(false),
            pending: Arc::new(AtomicUsize::new(0)),
            verification_pause: AtomicBool::new(false),
            verification_pending: Arc::new(AtomicUsize::new(0)),
            issuer: endpoint.clone(),
            resource,
        });
        let router = Router::new()
            .route("/introspect", post(introspect))
            .route("/execute", post(execute))
            .layer(DefaultBodyLimit::max(64 << 10))
            .with_state(Arc::clone(&observations));
        let handle = axum_server::Handle::new();
        let future = axum_server::from_tcp_rustls(listener, tls)?
            .handle(handle.clone())
            .serve(router.into_make_service());
        let task = tokio::spawn(future);
        let _: SocketAddr = timeout(Duration::from_secs(3), handle.listening())
            .await?
            .ok_or_else(|| std::io::Error::other("backend listener unavailable"))?;
        Ok(Self {
            endpoint,
            certificate: pem,
            observations,
            handle,
            task,
        })
    }

    /// # Errors
    ///
    /// Returns a shutdown timeout, task join or listener service error.
    pub async fn finish(&mut self) -> TestResult<()> {
        self.handle.shutdown();
        timeout(Duration::from_secs(3), &mut self.task).await???;
        Ok(())
    }
}

/// # Panics
///
/// Panics if the machine credential or content type differs from the fixture.
pub(super) fn machine(headers: &HeaderMap, client: &str, content_type: &str) {
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client}:{SECRET}"))
    );
    assert_eq!(
        headers
            .get(header::AUTHORIZATION)
            .map(axum::http::HeaderValue::as_bytes),
        Some(expected.as_bytes())
    );
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .map(axum::http::HeaderValue::as_bytes),
        Some(content_type.as_bytes())
    );
}

/// # Errors
///
/// Returns service unavailable if the system clock precedes the Unix epoch.
///
/// # Panics
///
/// Panics if machine authentication, the introspection body or its call limit fails.
#[expect(
    clippy::map_err_ignore,
    reason = "The synthetic authority returns a status-only clock failure; executable authorization regressions cover fail-closed responses. Reviewed 2026-10-05; review by 2026-11-05 or on fixture change."
)]
async fn introspect(
    State(observed): State<Arc<Observations>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<axum::Json<Value>, StatusCode> {
    machine(
        &headers,
        "synthetic-introspection",
        "application/x-www-form-urlencoded",
    );
    let expected = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("token", TOKEN)
        .append_pair("token_type_hint", "access_token")
        .finish();
    assert_eq!(bytes.as_ref(), expected.as_bytes());
    assert!(observed.verifies.fetch_add(1, Ordering::SeqCst) < 16);
    let _active = observed.enter(PendingStage::Verification).await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .as_secs();
    Ok(axum::Json(
        json!({"active":observed.active.load(Ordering::SeqCst),
        "iss":observed.issuer,"aud":observed.resource,"exp":now.saturating_add(60),
        "iat":now,"token_type":"Bearer","scope":"mcp:read",
        "jti":"synthetic-credential-reference","client_id":"synthetic-client"}),
    ))
}

/// # Errors
///
/// Returns bad request if the execution body is not valid JSON.
///
/// # Panics
///
/// Panics if machine authentication, delegated identity, operation, input or
/// the execution call limit differs from the fixture.
#[expect(
    clippy::map_err_ignore,
    reason = "Synthetic invalid JSON returns a status-only response without retaining credential diagnostics; executable privacy regressions cover the fixture. Reviewed 2026-10-05; review by 2026-11-05 or on fixture change."
)]
async fn execute(
    State(observed): State<Arc<Observations>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<axum::Json<Value>, StatusCode> {
    machine(&headers, "synthetic-execution", "application/json");
    let input: Value = serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    assert_eq!(input.get("token"), Some(&json!(TOKEN)));
    assert_eq!(
        input.get("credential_id"),
        Some(&json!("synthetic-credential-reference"))
    );
    assert_eq!(input.get("client_id"), Some(&json!("synthetic-client")));
    assert_eq!(
        input.pointer("/request/operation"),
        Some(&json!("logs.read.v1"))
    );
    assert_eq!(input.pointer("/request/input"), Some(&json!({})));
    assert!(observed.executes.fetch_add(1, Ordering::SeqCst) < 4);
    let _active = observed.enter(PendingStage::Execution).await;
    Ok(axum::Json(json!({"count":3_i32})))
}
