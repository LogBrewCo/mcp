//! Exactly two tools behind request-bound authorization and host checks.

use alloc::{borrow::Cow, sync::Arc};

use axum::{
    Router,
    extract::{Request, State},
    http::{StatusCode, header},
    middleware,
    response::{IntoResponse as _, Response},
    routing::any,
};
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CustomRequest, CustomResult, ErrorCode,
        ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerConfig,
        Tool,
    },
    service::RequestContext,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use serde_json::{Value, json};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

mod authority;
mod boundary;
mod tools;

use boundary::boundary;
use tools::{definition, envelope};

use crate::{
    Failure, REQUEST_BYTES,
    admission::{Admission, Limiter},
    catalog::Catalog,
    error::Kind,
    telemetry::{Outcome, Stage, Telemetry},
    upstream::{Principal, READ_SCOPE, Upstream, WRITE_SCOPE, canonical_https},
};

// 2025-06-18 and 2025-11-25 clients use the `initialize` handshake and are served
// statelessly, without sessions. Older versions lack the OAuth resource indicator
// and structured tool results, so they stay unsupported.
const SUPPORTED_PROTOCOL_VERSIONS: &[ProtocolVersion] = &[
    ProtocolVersion::V_2026_07_28,
    ProtocolVersion::V_2025_11_25,
    ProtocolVersion::V_2025_06_18,
];

// Request extensions are cloned while the SDK dispatches a request, so every
// clone shares the one zeroized token buffer instead of copying the secret.
#[derive(Clone)]
struct Authority {
    principal: Principal,
    token: Arc<Zeroizing<String>>,
}

#[derive(Clone)]
struct OriginalArguments(Value);

#[derive(Clone)]
struct ToolCursorSupplied;

struct Shared {
    catalog: Arc<Catalog>,
    upstream: Upstream,
    resource: String,
    issuer: String,
    authority: authority::HttpsAuthority,
    path: String,
    challenge: header::HeaderValue,
    invalid_token_challenge: header::HeaderValue,
    invalid_request_challenge: header::HeaderValue,
    insufficient_scope_challenge: header::HeaderValue,
    write_scope_challenge: header::HeaderValue,
    slots: Arc<Semaphore>,
    limiter: Limiter,
    telemetry: Telemetry,
}

#[derive(Clone)]
struct Tools(Arc<Shared>);

enum ToolKind {
    Search,
    Execute,
}

impl ServerHandler for Tools {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(SUPPORTED_PROTOCOL_VERSIONS)
    }

    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(
            rmcp::model::Implementation::new("logbrew-mcp", "development"),
        )
    }

    fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl core::future::Future<Output = Result<ListToolsResult, ErrorData>>
    + rmcp::service::MaybeSendFuture
    + '_ {
        let cursor_supplied = context
            .extensions
            .get::<axum::http::request::Parts>()
            .is_some_and(|parts| parts.extensions.get::<ToolCursorSupplied>().is_some());
        if cursor_supplied || request.is_some_and(|request| request.cursor.is_some()) {
            return core::future::ready(Err(ErrorData::invalid_params(
                "invalid tool cursor",
                None,
            )));
        }
        let effects = self.0.catalog.effects();
        core::future::ready(Ok(ListToolsResult::with_all_items(vec![
            definition("search", effects),
            definition("execute", effects),
        ])))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        matches!(name, "search" | "execute").then(|| definition(name, self.0.catalog.effects()))
    }

    fn on_custom_request(
        &self,
        request: CustomRequest,
        _context: RequestContext<RoleServer>,
    ) -> impl core::future::Future<Output = Result<CustomResult, ErrorData>>
    + rmcp::service::MaybeSendFuture
    + '_ {
        // The SDK routes malformed typed requests through this fallback too.
        let error = if matches!(
            request.method.as_str(),
            "server/discover" | "tools/list" | "tools/call" | "ping"
        ) {
            ErrorData::invalid_params("invalid method parameters", None)
        } else {
            ErrorData::new(ErrorCode::METHOD_NOT_FOUND, "unknown method", None)
        };
        core::future::ready(Err(error))
    }

    #[expect(
        clippy::integer_division_remainder_used,
        reason = "Tokio select uses remainder for fair branch polling; this is not cryptographic arithmetic."
    )]
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let tool = match request.name.as_ref() {
            "search" => ToolKind::Search,
            "execute" => ToolKind::Execute,
            _ => return Err(ErrorData::invalid_params("unknown tool", None)),
        };
        let stage = match tool {
            ToolKind::Search => Stage::Search,
            ToolKind::Execute => Stage::Execute,
        };
        let mut measurement = self.0.telemetry.begin(stage);
        let arguments = context
            .extensions
            .get::<axum::http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<OriginalArguments>())
            .map_or_else(
                || Value::Object(request.arguments.unwrap_or_default()),
                |arguments| arguments.0.clone(),
            );
        let operation_measurement = arguments
            .get("operation")
            .and_then(Value::as_str)
            .and_then(|id| measurement.operation(id));
        let mut cancelled = false;
        let result = match tool {
            ToolKind::Execute => {
                tokio::select! {
                    result = self.execute(&arguments, &context) => result,
                    () = context.ct.cancelled() => {
                        cancelled = true;
                        Err(Kind::Unavailable.into())
                    },
                }
            }
            ToolKind::Search => self.0.catalog.search(&arguments),
        };
        let outcome = if cancelled {
            Outcome::Cancelled
        } else {
            Outcome::result(&result)
        };
        let response = envelope(result, Some(&self.0.catalog.provenance()));
        let outcome = if outcome == Outcome::Completed && response.is_error == Some(true) {
            Outcome::Unavailable
        } else {
            outcome
        };
        if let Some(operation_measurement) = operation_measurement {
            operation_measurement.finish(outcome);
        }
        measurement.finish(outcome);
        Ok(response.into())
    }
}

impl Tools {
    /// Execute one discovered contract with current-request authority.
    ///
    /// # Errors
    /// Rejects invalid arguments, unknown operations, missing authority, upstream
    /// failures and results that violate the operation's output contract.
    async fn execute(
        &self,
        arguments: &Value,
        context: &RequestContext<RoleServer>,
    ) -> Result<Value, Failure> {
        let fields = arguments.as_object().ok_or(Kind::InvalidInput)?;
        if fields.len() != 2 {
            return Err(Kind::InvalidInput.into());
        }
        let operation = fields
            .get("operation")
            .and_then(Value::as_str)
            .ok_or(Kind::InvalidInput)?;
        let input = fields.get("input").ok_or(Kind::InvalidInput)?;
        self.0.catalog.input(operation, input)?;
        let authority = context
            .extensions
            .get::<axum::http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<Authority>())
            .ok_or(Kind::Unavailable)?;
        // The HTTP boundary already answers this with a scope challenge; keep the
        // check beside the API call so no other path can run a write operation.
        if self.0.catalog.needs_write(operation) && !authority.principal.write {
            return Err(Kind::PermissionDenied.into());
        }
        let data = self
            .0
            .upstream
            .execute(&authority.principal, &authority.token, operation, input)
            .await?;
        self.0.catalog.output(operation, &data)?;
        Ok(data)
    }
}

/// Construct a stateless router without contacting any service or opening a listener.
///
/// # Errors
/// Rejects invalid resource locations, root resource paths, issuers with a
/// trailing slash and admission limits outside their ranges.
pub fn router(
    catalog: Arc<Catalog>,
    upstream: Upstream,
    resource: String,
    issuer: String,
    admission: Admission,
) -> Result<Router, Failure> {
    let limiter = Limiter::new(admission)?;
    let upstream = upstream.with_rejected_token_ttl(admission.rejected_token_ttl());
    let url = canonical_https(&resource)?;
    drop(canonical_https(&issuer)?);
    // Introspection compares `iss` byte for byte, and issuers omit the slash.
    if url.path() == "/" || issuer.ends_with('/') {
        return Err(Kind::Configuration.into());
    }
    let host = resource
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .ok_or(Kind::Configuration)?
        .to_owned();
    let path = url.path().to_owned();
    let authority = authority::HttpsAuthority::parse(&host).ok_or(Kind::Configuration)?;
    let metadata_path = format!("/.well-known/oauth-protected-resource{path}");
    let metadata_url = format!("https://{host}{metadata_path}");
    // Clients start with least privilege: only `read` is requested up front.
    let challenge = format!("Bearer resource_metadata=\"{metadata_url}\", scope=\"{READ_SCOPE}\"");
    let value = |text: &str| {
        header::HeaderValue::from_str(text).map_err(Failure::redact(Kind::Configuration))
    };
    let invalid_token_challenge = value(&format!("{challenge}, error=\"invalid_token\""))?;
    let invalid_request_challenge = value(&format!("{challenge}, error=\"invalid_request\""))?;
    let insufficient_scope_challenge =
        value(&format!("{challenge}, error=\"insufficient_scope\""))?;
    let write_scope_challenge = value(&format!(
        "Bearer error=\"insufficient_scope\", scope=\"{READ_SCOPE} {WRITE_SCOPE}\", \
         resource_metadata=\"{metadata_url}\", \
         error_description=\"This operation needs the {WRITE_SCOPE} scope.\""
    ))?;
    let challenge = value(&challenge)?;
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_max_request_body_bytes(REQUEST_BYTES)
        .with_allowed_hosts(vec![host.clone()])
        .with_allowed_origins(vec![format!("https://{host}")]);
    let telemetry = upstream.telemetry();
    telemetry.register_catalog(&catalog);
    let shared = Arc::new(Shared {
        catalog,
        upstream,
        resource,
        issuer,
        authority,
        path: path.clone(),
        challenge,
        invalid_token_challenge,
        invalid_request_challenge,
        insufficient_scope_challenge,
        write_scope_challenge,
        slots: Arc::new(Semaphore::new(64)),
        limiter,
        telemetry,
    });
    let captured = Arc::clone(&shared);
    let service = StreamableHttpService::new(
        move || Ok(Tools(Arc::clone(&captured))),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    Ok(Router::new()
        .route_service(&path, service)
        .route(&metadata_path, any(metadata))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&shared),
            boundary,
        ))
        .with_state(shared))
}

async fn metadata(State(shared): State<Arc<Shared>>, request: Request) -> Response {
    if request.method() != axum::http::Method::GET || request.uri().query().is_some() {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, "GET")],
            "method not allowed",
        )
            .into_response();
    }
    axum::Json(
        json!({"resource":shared.resource,"authorization_servers":[shared.issuer],
        "bearer_methods_supported":["header"],"scopes_supported":[READ_SCOPE,WRITE_SCOPE]}),
    )
    .into_response()
}
