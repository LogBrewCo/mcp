//! Shared synthetic HTTPS backend and authenticated protocol request fixtures.

use std::{
    net::{SocketAddr, TcpListener},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, Request, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::post,
};
use logbrew_mcp::{
    catalog::Catalog,
    clients::ClientAllowlist,
    protocol,
    telemetry::Telemetry,
    upstream::{MachineCredential, Upstream, UpstreamOptions},
};
use rustls::pki_types::{CertificateDer, pem::PemObject as _};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tower::ServiceExt as _;
use zeroize::Zeroizing;

pub const RESOURCE: &str = "https://resource.example/mcp";
pub const TOKEN: &str = "SYNTHETIC_DELEGATED_CREDENTIAL";
const MACHINE_SECRET: &str = "SYNTHETIC_MACHINE_SECRET +:%&\n";
// RFC 6749 section 2.3.1 encodes each component before HTTP Basic encoding.
const INTROSPECTION_AUTH: &str =
    "Basic aW50cm9zcGVjdGlvbiUyQmNsaWVudDpTWU5USEVUSUNfTUFDSElORV9TRUNSRVQrJTJCJTNBJTI1JTI2JTBB";
const EXECUTION_AUTH: &str =
    "Basic ZXhlY3V0aW9uJTNBY2xpZW50OlNZTlRIRVRJQ19NQUNISU5FX1NFQ1JFVCslMkIlM0ElMjUlMjYlMEE=";

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub struct StateData {
    pub active: AtomicBool,
    pub calls: AtomicUsize,
    pub verifies: AtomicUsize,
    issuer: String,
    resource: String,
    scope: String,
    token: String,
    reply: Mutex<Option<Reply>>,
    introspection_reply: Mutex<Option<Reply>>,
    pub pause: AtomicBool,
    pub active_executions: Arc<AtomicUsize>,
    pub release: tokio::sync::Notify,
}

struct ExecutionGuard(Arc<AtomicUsize>);

impl Drop for ExecutionGuard {
    fn drop(&mut self) {
        let _: usize = self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone)]
struct Reply {
    status: StatusCode,
    body: String,
    headers: HeaderMap,
}

impl axum::response::IntoResponse for Reply {
    fn into_response(self) -> Response {
        let mut response = (self.status, self.body).into_response();
        drop(response.headers_mut().insert(
            header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        ));
        response.headers_mut().extend(self.headers);
        response
    }
}

pub struct Fixture {
    pub state: Arc<StateData>,
    pub router: Router,
    pub telemetry: Telemetry,
    handle: axum_server::Handle<std::net::SocketAddr>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.handle.shutdown();
        self.task.abort();
    }
}

impl Fixture {
    pub async fn new() -> TestResult<Self> {
        Self::for_resource(RESOURCE.to_owned()).await
    }

    pub async fn for_resource(resource: String) -> TestResult<Self> {
        let clients =
            ClientAllowlist::decode(br#"{"version":"1","clients":["synthetic-client"]}"#)?;
        Self::build(resource, Some(clients), "mcp:read".to_owned(), None, TOKEN).await
    }

    pub async fn without_clients() -> TestResult<Self> {
        Self::build(
            RESOURCE.to_owned(),
            None,
            "mcp:read".to_owned(),
            None,
            TOKEN,
        )
        .await
    }

    pub async fn with_clients(clients: ClientAllowlist) -> TestResult<Self> {
        Self::build(
            RESOURCE.to_owned(),
            Some(clients),
            "mcp:read".to_owned(),
            None,
            TOKEN,
        )
        .await
    }

    pub async fn with_scope(scope: String) -> TestResult<Self> {
        let clients =
            ClientAllowlist::decode(br#"{"version":"1","clients":["synthetic-client"]}"#)?;
        Self::build(RESOURCE.to_owned(), Some(clients), scope, None, TOKEN).await
    }

    pub async fn with_catalog(artifact: Vec<u8>) -> TestResult<Self> {
        let clients =
            ClientAllowlist::decode(br#"{"version":"1","clients":["synthetic-client"]}"#)?;
        Self::build(
            RESOURCE.to_owned(),
            Some(clients),
            "mcp:read".to_owned(),
            Some(artifact),
            TOKEN,
        )
        .await
    }

    pub async fn with_token(token: &str) -> TestResult<Self> {
        let clients =
            ClientAllowlist::decode(br#"{"version":"1","clients":["synthetic-client"]}"#)?;
        Self::build(
            RESOURCE.to_owned(),
            Some(clients),
            "mcp:read".to_owned(),
            None,
            token,
        )
        .await
    }

    async fn build(
        resource: String,
        clients: Option<ClientAllowlist>,
        scope: String,
        artifact: Option<Vec<u8>>,
        token: &str,
    ) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let issuer = format!("https://localhost:{}/", address.port());
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
        let pem = certificate.cert.pem();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            pem.as_bytes().to_vec(),
            certificate.signing_key.serialize_pem().as_bytes().to_vec(),
        )
        .await?;
        let state = Arc::new(StateData {
            active: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
            verifies: AtomicUsize::new(0),
            issuer: issuer.clone(),
            resource: resource.clone(),
            scope: scope.clone(),
            token: token.to_owned(),
            reply: Mutex::new(None),
            introspection_reply: Mutex::new(None),
            pause: AtomicBool::new(false),
            active_executions: Arc::new(AtomicUsize::new(0)),
            release: tokio::sync::Notify::new(),
        });
        let backend = Router::new()
            .route("/introspect", post(introspect))
            .route("/execute", post(execute))
            .with_state(Arc::clone(&state));
        let handle = axum_server::Handle::new();
        let credential = |id: &str| {
            MachineCredential::new(id.to_owned(), Zeroizing::new(MACHINE_SECRET.to_owned()))
        };
        let mut upstream = Upstream::with_certificate(
            UpstreamOptions {
                introspection_endpoint: format!("{issuer}introspect"),
                execution_endpoint: format!("{issuer}execute"),
                issuer: issuer.clone(),
                resource: resource.clone(),
                required_scope: scope,
                introspection_credential: credential("introspection+client")?,
                execution_credential: credential("execution:client")?,
            },
            Some(CertificateDer::from_pem_slice(pem.as_bytes())?),
        )?;
        if let Some(clients) = clients {
            upstream = upstream.with_client_allowlist(clients);
        }
        let artifact = match artifact {
            Some(artifact) => artifact,
            None => serde_json::to_vec(&json!({"format_version":1_i32,"operations":[{
                "id":"logs.read.v1","info":{"summary":"Read logs","permission":"logs:read","documentation":"https://docs.example/logs",
                    "stability":"stable","cost":"one read","safety":"read_only"},
                "input_schema":{"type":"object","additionalProperties":false,
                    "properties":{"context":{"type":"object"}}},
                "output_schema":{"type":"object","additionalProperties":false,"required":["count"],
                    "properties":{"count":{"type":"integer"},"blob":{"type":"string"}}}
            }]}))?,
        };
        let catalog = Catalog::load(&artifact, &Sha256::digest(&artifact).into())?;
        let telemetry = upstream.telemetry();
        let router = protocol::router(catalog, upstream, resource, issuer)?;
        let future = axum_server::from_tcp_rustls(listener, tls)?
            .handle(handle.clone())
            .serve(backend.into_make_service());
        let task = tokio::spawn(future);
        let fixture = Self {
            state,
            router,
            telemetry,
            handle,
            task,
        };
        let _: SocketAddr = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            fixture.handle.listening(),
        )
        .await?
        .ok_or_else(|| std::io::Error::other("fixture listener unavailable"))?;
        Ok(fixture)
    }

    pub fn reply(&self, status: StatusCode, body: String, headers: HeaderMap) -> TestResult<()> {
        set_reply(
            &self.state.reply,
            Reply {
                status,
                body,
                headers,
            },
        )
    }

    pub fn introspection_reply(
        &self,
        status: StatusCode,
        body: String,
        headers: HeaderMap,
    ) -> TestResult<()> {
        set_reply(
            &self.state.introspection_reply,
            Reply {
                status,
                body,
                headers,
            },
        )
    }

    pub fn authority(&self) -> TestResult<Value> {
        claims(&self.state)
            .map_err(|_| std::io::Error::other("fixture authority unavailable").into())
    }

    pub async fn request(
        &self,
        method: &str,
        params: Value,
        token: &str,
    ) -> TestResult<(StatusCode, Value)> {
        let request = request_message(1, method, params, token)?;
        let response = self.router.clone().oneshot(request).await?;
        assert_eq!(
            response
                .headers()
                .get("Cache-Control")
                .map(axum::http::HeaderValue::as_bytes),
            Some(b"no-store".as_slice())
        );
        assert!(response.headers().get("Mcp-Session-Id").is_none());
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 5 << 20).await?;
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        assert!(!String::from_utf8_lossy(&bytes).contains(TOKEN));
        Ok((status, value))
    }
}

pub fn request_message(
    id: u64,
    method: &str,
    mut params: Value,
    token: &str,
) -> TestResult<Request<Body>> {
    drop(
        params
            .as_object_mut()
            .ok_or_else(|| std::io::Error::other("invalid fixture parameters"))?
            .insert(
                "_meta".to_owned(),
                json!({
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientInfo":{"name":"synthetic","version":"1"},
            "io.modelcontextprotocol/clientCapabilities":{}}),
            ),
    );
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    Ok(Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Host", "resource.example")
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", method)
        .header("Mcp-Name", name)
        .body(Body::from(
            json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}).to_string(),
        ))?)
}

fn set_reply(slot: &Mutex<Option<Reply>>, reply: Reply) -> TestResult<()> {
    *slot
        .lock()
        .map_err(|_| std::io::Error::other("fixture reply unavailable"))? = Some(reply);
    Ok(())
}

async fn introspect(
    State(state): State<Arc<StateData>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, StatusCode> {
    assert_eq!(
        headers
            .get(header::AUTHORIZATION)
            .map(axum::http::HeaderValue::as_bytes),
        Some(INTROSPECTION_AUTH.as_bytes())
    );
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .map(axum::http::HeaderValue::as_bytes),
        Some(b"application/x-www-form-urlencoded".as_slice())
    );
    let expected = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("token", &state.token)
        .append_pair("token_type_hint", "access_token")
        .finish();
    assert_eq!(body.as_ref(), expected.as_bytes());
    let _: usize = state.verifies.fetch_add(1, Ordering::SeqCst);
    let reply = state
        .introspection_reply
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .clone();
    if let Some(reply) = reply {
        return Ok(reply.into_response());
    }
    Ok(axum::Json(claims(&state)?).into_response())
}

fn claims(state: &StateData) -> Result<Value, StatusCode> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .as_secs();
    Ok(
        json!({"active":state.active.load(Ordering::SeqCst),"iss":state.issuer,
        "aud":state.resource,"exp":now.saturating_add(60),"iat":now,"token_type":"Bearer",
        "scope":state.scope,"jti":"synthetic-credential-reference","client_id":"synthetic-client"}),
    )
}

async fn execute(
    State(state): State<Arc<StateData>>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Result<Response, StatusCode> {
    assert_eq!(
        headers
            .get(header::AUTHORIZATION)
            .map(axum::http::HeaderValue::as_bytes),
        Some(EXECUTION_AUTH.as_bytes())
    );
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .map(axum::http::HeaderValue::as_bytes),
        Some(b"application/json".as_slice())
    );
    let input = logbrew_mcp::json::object(&bytes, 64 << 10).map_err(|_| StatusCode::BAD_REQUEST)?;
    assert_eq!(
        input.get("token").and_then(Value::as_str),
        Some(state.token.as_str())
    );
    assert_eq!(
        input.get("credential_id").and_then(Value::as_str),
        Some("synthetic-credential-reference")
    );
    assert_eq!(
        input.get("client_id").and_then(Value::as_str),
        Some("synthetic-client")
    );
    let _: usize = state.calls.fetch_add(1, Ordering::SeqCst);
    let _: usize = state.active_executions.fetch_add(1, Ordering::SeqCst);
    let _active = ExecutionGuard(Arc::clone(&state.active_executions));
    if state.pause.load(Ordering::SeqCst) {
        state.release.notified().await;
    }
    if let Some(context) = input.pointer("/request/input/context") {
        assert_eq!(
            context.get("$serde_json::private::Number"),
            Some(&json!("123"))
        );
        assert_eq!(context.get("context"), Some(&json!("preserved")));
    }
    let reply = state
        .reply
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .clone();
    Ok(reply.map_or_else(
        || axum::Json(json!({"count":3_i32})).into_response(),
        Reply::into_response,
    ))
}

pub fn assert_output_budget(content: &Value, size: usize) -> TestResult<()> {
    if size == logbrew_mcp::OUTPUT_BYTES {
        assert_eq!(
            content
                .get("data")
                .ok_or("missing output data")?
                .to_string()
                .len(),
            size
        );
        assert_eq!(content.get("error"), Some(&Value::Null));
    } else {
        assert_eq!(content.get("data"), Some(&Value::Null));
        assert_eq!(content.pointer("/error/code"), Some(&json!("unavailable")));
    }
    Ok(())
}
