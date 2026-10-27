//! HTTP admission, authorization and request preparation before SDK dispatch.

use alloc::sync::Arc;
use core::{net::SocketAddr, time::Duration};

use axum::{
    body::{Body, to_bytes},
    extract::{ConnectInfo, Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse as _, Response},
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{Authority, OriginalArguments, Shared, ToolCursorSupplied};
use crate::{
    REQUEST_BYTES,
    admission::Ticket,
    bearer, deadline,
    error::Kind,
    json as strict_json, responses,
    telemetry::{Outcome, Stage},
    transport,
    upstream::AuthorizationFailure,
};

pub(super) async fn boundary(
    State(shared): State<Arc<Shared>>,
    request: Request,
    next: Next,
) -> Response {
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
    // Admission comes before a request slot or introspection is spent.
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    let client = shared.limiter.client(peer, request.headers());
    let ticket = match shared.limiter.reserve(client) {
        Ok(ticket) => ticket,
        Err(wait) => return throttled(wait),
    };
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
    let response = authorized(shared, request, next, ticket).await;
    responses::hold(response, permit, connection, &shared.telemetry)
}

async fn authorized(shared: &Shared, mut request: Request, next: Next, ticket: Ticket) -> Response {
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
            Ok(principal) if principal.valid() => {
                shared.limiter.refund(ticket);
                principal
            }
            Err(failure) => return authorization_failure(shared, failure),
            _ => {
                return (StatusCode::SERVICE_UNAVAILABLE, "authorization unavailable")
                    .into_response();
            }
        };
        let write = principal.write;
        drop(request.extensions_mut().insert(Authority {
            principal,
            token: Arc::new(token),
        }));
        prepared_request(shared, write, request, next).await
    };
    deadline::within(Duration::from_secs(10), work)
        .await
        .unwrap_or_else(|| {
            (StatusCode::GATEWAY_TIMEOUT, "request deadline exceeded").into_response()
        })
}

/// Validate and bind a request body before SDK dispatch. `write` says whether
/// the verified token carries the `write` scope.
async fn prepared_request(
    shared: &Shared,
    write: bool,
    mut request: Request,
    next: Next,
) -> Response {
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
        if let Some(response) = transport::prepare_media(&mut parts.headers) {
            return response;
        }
        let Ok(bytes) = to_bytes(body, REQUEST_BYTES).await else {
            return (StatusCode::PAYLOAD_TOO_LARGE, "request body rejected").into_response();
        };
        let Ok(mut value) = strict_json::object(&bytes, REQUEST_BYTES) else {
            return transport::rejected_json(&bytes);
        };
        if let Some(response) = transport::prepare(&parts.headers, &value) {
            return response;
        }
        // MCP runtime insufficient-scope handling: refuse a write operation
        // without the `write` scope before the tool runs or the API is contacted.
        if !write
            && value.get("method").and_then(Value::as_str) == Some("tools/call")
            && value.pointer("/params/name").and_then(Value::as_str) == Some("execute")
            && value
                .pointer("/params/arguments/operation")
                .and_then(Value::as_str)
                .is_some_and(|operation| shared.catalog.needs_write(operation))
        {
            return (
                StatusCode::FORBIDDEN,
                [(
                    header::WWW_AUTHENTICATE,
                    shared.write_scope_challenge.clone(),
                )],
                "insufficient scope",
            )
                .into_response();
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

/// A stable 429 for a client that spent its unauthenticated budget.
fn throttled(wait: Duration) -> Response {
    let seconds = wait
        .as_secs()
        .saturating_add(u64::from(wait.subsec_nanos() > 0))
        .max(1);
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, seconds.to_string())],
        "too many unauthenticated requests",
    )
        .into_response()
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
        AuthorizationFailure::Rejected(_) => {
            (StatusCode::SERVICE_UNAVAILABLE, "authorization unavailable").into_response()
        }
    }
}
