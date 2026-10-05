//! Bounded synthetic project policy; production tenant policy belongs to the backend.

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
    http::{HeaderMap, StatusCode},
    routing::post,
};
use serde_json::{Value, json};
use tokio::{sync::Notify, time::timeout};

use super::{TestResult, backend::machine};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Identity {
    Alpha,
    Beta,
    Rejected,
}

impl Identity {
    pub const fn token(self) -> &'static str {
        match self {
            Self::Alpha => "SYNTHETIC_ALPHA_TOKEN",
            Self::Beta => "SYNTHETIC_BETA_TOKEN",
            Self::Rejected => "SYNTHETIC_REJECTED_TOKEN",
        }
    }

    const fn client(self) -> &'static str {
        match self {
            Self::Alpha => "synthetic-alpha-client",
            Self::Beta => "synthetic-beta-client",
            Self::Rejected => "synthetic-rejected-client",
        }
    }

    const fn credential(self) -> &'static str {
        match self {
            Self::Alpha => "synthetic-alpha-credential",
            Self::Beta => "synthetic-beta-credential",
            Self::Rejected => "synthetic-rejected-credential",
        }
    }

    const fn project(self) -> &'static str {
        match self {
            Self::Alpha => "alpha",
            Self::Beta => "beta",
            Self::Rejected => "rejected",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Alpha => 0,
            Self::Beta => 1,
            Self::Rejected => 2,
        }
    }
}

pub(super) struct Observations {
    pub alpha_active: AtomicBool,
    pub alpha_entered: Notify,
    pub alpha_release: Notify,
    pub verifies: [AtomicUsize; 3],
    pub executes: [AtomicUsize; 3],
    pause_alpha: AtomicBool,
    issuer: String,
    resource: String,
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
        let endpoint = format!("https://localhost:{}", listener.local_addr()?.port());
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
        let pem = certificate.cert.pem();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            pem.as_bytes().to_vec(),
            certificate.signing_key.serialize_pem().as_bytes().to_vec(),
        )
        .await?;
        let observations = Arc::new(Observations {
            alpha_active: AtomicBool::new(true),
            alpha_entered: Notify::new(),
            alpha_release: Notify::new(),
            verifies: std::array::from_fn(|_| AtomicUsize::new(0)),
            executes: std::array::from_fn(|_| AtomicUsize::new(0)),
            pause_alpha: AtomicBool::new(true),
            issuer: endpoint.clone(),
            resource,
        });
        let router = Router::new()
            .route("/introspect", post(introspect))
            .route("/execute", post(execute))
            .layer(DefaultBodyLimit::max(16 << 10))
            .with_state(Arc::clone(&observations));
        let handle = axum_server::Handle::new();
        let future = axum_server::from_tcp_rustls(listener, tls)?
            .handle(handle.clone())
            .serve(router.into_make_service());
        let task = tokio::spawn(future);
        let _: SocketAddr = timeout(Duration::from_secs(3), handle.listening())
            .await?
            .ok_or_else(|| std::io::Error::other("synthetic tenant listener unavailable"))?;
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

const fn identities() -> [Identity; 3] {
    [Identity::Alpha, Identity::Beta, Identity::Rejected]
}

/// # Errors
///
/// Returns bad request for an unknown token or missing identity counter, or
/// internal server error if the system clock precedes the Unix epoch.
///
/// # Panics
///
/// Panics if machine authentication or the verification call limit fails.
#[expect(
    clippy::map_err_ignore,
    reason = "The synthetic authority returns a status-only clock failure; executable tenant regressions cover fail-closed responses. Reviewed 2026-10-05; review by 2026-11-05 or on fixture change."
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
    let identity = identities()
        .into_iter()
        .find(|identity| {
            bytes.as_ref()
                == format!("token={}&token_type_hint=access_token", identity.token()).as_bytes()
        })
        .ok_or(StatusCode::BAD_REQUEST)?;
    let counter = observed
        .verifies
        .get(identity.index())
        .ok_or(StatusCode::BAD_REQUEST)?;
    assert!(counter.fetch_add(1, Ordering::SeqCst) < 8);
    if identity == Identity::Alpha && observed.pause_alpha.swap(false, Ordering::SeqCst) {
        observed.alpha_entered.notify_one();
        observed.alpha_release.notified().await;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .as_secs();
    Ok(axum::Json(json!({
        "active": identity != Identity::Alpha || observed.alpha_active.load(Ordering::SeqCst),
        "iss": observed.issuer,
        "aud": observed.resource,
        "exp": now.saturating_add(60),
        "iat": now,
        "token_type": "Bearer",
        "scope": "mcp:read",
        "jti": identity.credential(),
        "client_id": identity.client()
    })))
}

/// # Errors
///
/// Returns forbidden if JSON, identity, its counter or project access is invalid.
///
/// # Panics
///
/// Panics if machine authentication, delegated identity, operation or the
/// execution call limit differs from the fixture.
#[expect(
    clippy::map_err_ignore,
    reason = "Synthetic invalid JSON returns a fixed denial without retaining credential diagnostics; executable tenant regressions cover the fixture. Reviewed 2026-10-05; review by 2026-11-05 or on fixture change."
)]
async fn execute(
    State(observed): State<Arc<Observations>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<axum::Json<Value>, (StatusCode, &'static str)> {
    machine(&headers, "synthetic-execution", "application/json");
    let denied = (StatusCode::FORBIDDEN, "SYNTHETIC_FOREIGN_PRIVATE_RESULT");
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| denied)?;
    let identity = identities()
        .into_iter()
        .find(|identity| value.get("token").and_then(Value::as_str) == Some(identity.token()))
        .ok_or(denied)?;
    assert_eq!(
        value.get("credential_id"),
        Some(&json!(identity.credential()))
    );
    assert_eq!(value.get("client_id"), Some(&json!(identity.client())));
    assert_eq!(
        value.pointer("/request/operation"),
        Some(&json!("logs.read.v1"))
    );
    let counter = observed.executes.get(identity.index()).ok_or(denied)?;
    assert!(counter.fetch_add(1, Ordering::SeqCst) < 4);
    if value
        .pointer("/request/input/project")
        .and_then(Value::as_str)
        != Some(identity.project())
    {
        return Err(denied);
    }
    Ok(axum::Json(json!({
        "project": identity.project(),
        "record": format!("{}-result", identity.project())
    })))
}
