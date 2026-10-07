//! Exactly two tools behind request-bound authorization and host checks.

use alloc::sync::Arc;
use core::time::Duration;

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse as _, Response},
    routing::any,
};
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, CustomRequest, CustomResult,
        ErrorCode, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
        ToolAnnotations,
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

use crate::{
    ENVELOPE_BYTES, Failure, REQUEST_BYTES, bearer,
    catalog::Catalog,
    deadline,
    error::Kind,
    json as strict_json, responses,
    telemetry::{Outcome, Stage, Telemetry},
    transport,
    upstream::{AuthorizationFailure, Principal, Upstream, canonical_https},
};

#[derive(Clone)]
struct Authority {
    principal: Principal,
    token: Zeroizing<String>,
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
    slots: Arc<Semaphore>,
    telemetry: Telemetry,
}

#[derive(Clone)]
struct Tools(Arc<Shared>);

enum ToolKind {
    Search,
    Execute,
}

impl ServerHandler for Tools {
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
        core::future::ready(Ok(ListToolsResult::with_all_items(vec![
            definition("search"),
            definition("execute"),
        ])))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        matches!(name, "search" | "execute").then(|| definition(name))
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
        let measurement = self.0.telemetry.begin(stage);
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
/// Rejects invalid resource locations and root resource paths.
pub fn router(
    catalog: Arc<Catalog>,
    upstream: Upstream,
    resource: String,
    issuer: String,
) -> Result<Router, Failure> {
    let url = canonical_https(&resource)?;
    drop(canonical_https(&issuer)?);
    if url.path() == "/" {
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
    let challenge = format!(
        "Bearer resource_metadata=\"https://{host}{metadata_path}\", scope=\"{}\"",
        upstream.required_scope()
    );
    let value = |text: &str| {
        header::HeaderValue::from_str(text).map_err(Failure::redact(Kind::Configuration))
    };
    let invalid_token_challenge = value(&format!("{challenge}, error=\"invalid_token\""))?;
    let invalid_request_challenge = value(&format!("{challenge}, error=\"invalid_request\""))?;
    let insufficient_scope_challenge =
        value(&format!("{challenge}, error=\"insufficient_scope\""))?;
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
        slots: Arc::new(Semaphore::new(64)),
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
        "bearer_methods_supported":["header"],"scopes_supported":[shared.upstream.required_scope()]}),
    )
    .into_response()
}

async fn boundary(State(shared): State<Arc<Shared>>, request: Request, next: Next) -> Response {
    let measurement = shared.telemetry.begin(Stage::RequestPrepared);
    let mut response = guarded(&shared, request, next).await;
    drop(response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    ));
    drop(response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    ));
    measurement.finish(Outcome::status(response.status().as_u16()));
    response
}

async fn guarded(shared: &Shared, request: Request, next: Next) -> Response {
    if !valid_host_origin(shared, &request) {
        return (StatusCode::FORBIDDEN, "invalid host or origin").into_response();
    }
    if request.uri().path() != shared.path {
        return next.run(request).await;
    }
    if request.uri().query().is_some() {
        return (StatusCode::BAD_REQUEST, "query parameters are not accepted").into_response();
    }
    let Ok(permit) = Arc::clone(&shared.slots).try_acquire_owned() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "1")],
            "request capacity reached",
        )
            .into_response();
    };
    let connection = request
        .extensions()
        .get::<crate::delivery::Connection>()
        .cloned();
    let response = authorized(shared, request, next).await;
    responses::hold(response, permit, connection, &shared.telemetry)
}

async fn authorized(shared: &Shared, mut request: Request, next: Next) -> Response {
    let token = match bearer::parse(request.headers()) {
        Ok(token) => Zeroizing::new(token.to_owned()),
        Err(bearer::Rejection::Missing) => return unauthorized(shared),
        Err(bearer::Rejection::Malformed) => {
            return (
                StatusCode::BAD_REQUEST,
                [(
                    header::WWW_AUTHENTICATE,
                    shared.invalid_request_challenge.clone(),
                )],
                "invalid authorization request",
            )
                .into_response();
        }
    };
    let work = async {
        let principal = match shared.upstream.verify_request(&token).await {
            Ok(principal) if principal.valid() => principal,
            Err(failure) => return authorization_failure(shared, failure),
            _ => {
                return (StatusCode::SERVICE_UNAVAILABLE, "authorization unavailable")
                    .into_response();
            }
        };
        drop(
            request
                .extensions_mut()
                .insert(Authority { principal, token }),
        );
        prepared_request(request, next).await
    };
    deadline::within(Duration::from_secs(10), work)
        .await
        .unwrap_or_else(|| {
            (StatusCode::GATEWAY_TIMEOUT, "request deadline exceeded").into_response()
        })
}

async fn prepared_request(mut request: Request, next: Next) -> Response {
    let mut original_id = None;
    if request.method() == axum::http::Method::POST {
        if !crate::media::unencoded(request.headers()) {
            return (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                [(header::ACCEPT_ENCODING, "identity")],
                "unsupported content encoding",
            )
                .into_response();
        }
        let (mut parts, body) = request.into_parts();
        let Ok(bytes) = to_bytes(body, REQUEST_BYTES).await else {
            return (StatusCode::PAYLOAD_TOO_LARGE, "request body rejected").into_response();
        };
        let Ok(mut value) = strict_json::object(&bytes, REQUEST_BYTES) else {
            return (StatusCode::BAD_REQUEST, "invalid JSON request").into_response();
        };
        if let Some(response) = transport::prepare(&mut parts.headers, &value) {
            return response;
        }
        original_id = transport::prepare_id(&mut value);
        // Keep cursor presence when the SDK drops a malformed optional value.
        if value.get("method").and_then(Value::as_str) == Some("tools/list")
            && value.pointer("/params/cursor").is_some()
        {
            let _previous_cursor = parts.extensions.insert(ToolCursorSupplied);
        }
        // The SDK deserializes tool data through serde's internal value
        // representation. Bind the exact validated arguments separately so
        // ordinary object keys cannot become private serializer records.
        if value.get("method").and_then(Value::as_str) == Some("tools/call")
            && matches!(
                value.pointer("/params/name").and_then(Value::as_str),
                Some("search" | "execute")
            )
            && let Some(arguments) = value.pointer_mut("/params/arguments")
            && arguments.is_object()
        {
            drop(
                parts
                    .extensions
                    .insert(OriginalArguments(arguments.clone())),
            );
            *arguments = json!({});
        }
        request = Request::from_parts(parts, Body::from(value.to_string()));
    }
    let response = transport::restore_id(original_id, next.run(request).await).await;
    transport::fixed_header_error(response).await
}

fn valid_host_origin(shared: &Shared, request: &Request) -> bool {
    if !matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD
    ) && request
        .headers()
        .get_all("Sec-Fetch-Site")
        .iter()
        .any(|value| value == "cross-site")
    {
        return false;
    }
    shared.authority.allows(request)
}

fn unauthorized(shared: &Shared) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, shared.challenge.clone())],
        "unauthorized",
    )
        .into_response()
}

fn authorization_failure(shared: &Shared, failure: AuthorizationFailure) -> Response {
    match failure {
        AuthorizationFailure::InsufficientScope => (
            StatusCode::FORBIDDEN,
            [(
                header::WWW_AUTHENTICATE,
                shared.insufficient_scope_challenge.clone(),
            )],
            "insufficient scope",
        )
            .into_response(),
        AuthorizationFailure::Rejected(failure) if failure.kind == Kind::Unauthorized => (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                shared.invalid_token_challenge.clone(),
            )],
            "unauthorized",
        )
            .into_response(),
        AuthorizationFailure::Rejected(failure) if failure.kind == Kind::PermissionDenied => {
            (StatusCode::FORBIDDEN, "client access denied").into_response()
        }
        AuthorizationFailure::Rejected(_) => {
            (StatusCode::SERVICE_UNAVAILABLE, "authorization unavailable").into_response()
        }
    }
}

fn envelope(result: Result<Value, Failure>, provenance: Option<&Value>) -> CallToolResult {
    let (data, error) = match result {
        Ok(data) => (data, Value::Null),
        Err(failure) => (
            Value::Null,
            json!({"code":failure.kind.code(),
            "next_action":failure.kind.next_action(),"retry_after_ms":failure.retry_after_ms}),
        ),
    };
    let value = json!({"data":data,"error":error,"provenance":provenance});
    if value.to_string().len() > ENVELOPE_BYTES {
        return CallToolResult::structured_error(json!({"data":null,"provenance":null,
            "error":{"code":"unavailable","next_action":"check_operation_status","retry_after_ms":null}}));
    }
    if value.get("error").is_some_and(Value::is_null) {
        CallToolResult::structured(value)
    } else {
        CallToolResult::structured_error(value)
    }
}

fn definition(name: &str) -> Tool {
    let (description, schema) = if name == "search" {
        (
            "Find operation contracts.",
            json!({"type":"object","additionalProperties":false,
            "properties":{"operation":{"type":"string","minLength":1_u32,"maxLength":128_u32},
                "query":{"type":"string","maxLength":256_u32},"after":{"type":"string","maxLength":128_u32},
                "limit":{"type":"integer","minimum":1_u32,"maximum":10_u32}},
            "oneOf":[{"required":["operation"],"not":{"anyOf":[{"required":["query"]},
                {"required":["after"]},{"required":["limit"]}]}},{"required":["query"],"not":{"required":["operation"]}}]}),
        )
    } else {
        (
            "Run a discovered operation.",
            json!({"type":"object","additionalProperties":false,
            "required":["operation","input"],"properties":{"operation":{"type":"string","minLength":1_u32,"maxLength":128_u32},
                "input":{"type":"object"}}}),
        )
    };
    let object = schema.as_object().cloned().unwrap_or_default();
    let tool = Tool::new(name.to_owned(), description, Arc::new(object)).with_raw_output_schema(
        Arc::new(output_schema().as_object().cloned().unwrap_or_default()),
    );
    if name == "search" {
        tool.with_annotations(ToolAnnotations::new().read_only(true).open_world(false))
    } else {
        tool
    }
}

fn output_schema() -> Value {
    let errors: Vec<_> = [
        Kind::Configuration,
        Kind::UnknownOperation,
        Kind::Unauthorized,
        Kind::PermissionDenied,
        Kind::InvalidInput,
        Kind::InvalidOutput,
        Kind::Throttled,
        Kind::NotFound,
        Kind::Unavailable,
    ]
    .into_iter()
    .map(|kind| {
        json!({"properties":{
        "code":{"const":kind.code()},"next_action":{"const":kind.next_action()}}})
    })
    .collect();
    json!({"$schema":"https://json-schema.org/draft/2020-12/schema",
        "type":"object","required":["data","error","provenance"],"additionalProperties":false,
        "properties":{"data":{},"error":{},"provenance":{}},
    "$defs":{
        "provenance":{"type":"object","required":["definition_sha256"],"additionalProperties":false,
            "properties":{"definition_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}}},
        "error":{"type":"object","required":["code","next_action","retry_after_ms"],
            "additionalProperties":false,"properties":{"code":{"type":"string"},
                "next_action":{"type":"string"},"retry_after_ms":{"type":["integer","null"],
                        "minimum":0,"maximum":2_147_483_647_000_u64}},"oneOf":errors}
    },
    "oneOf":[
        {"properties":{"data":{"type":"object"},"error":{"type":"null"},
            "provenance":{"$ref":"#/$defs/provenance"}}},
        {"properties":{"data":{"type":"null"},"error":{"$ref":"#/$defs/error"},
            "provenance":{"anyOf":[{"$ref":"#/$defs/provenance"},{"type":"null"}]}}}
    ]})
}
