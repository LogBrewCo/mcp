//! Fixed HTTPS upstreams with fresh introspection and no automatic retries.

use alloc::collections::BTreeMap;
use core::{fmt, time::Duration};
use std::{
    sync::{Mutex, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::http::{HeaderMap, HeaderValue, header};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http_body::Body as _;
use http_body_util::BodyExt as _;
use rustls::pki_types::CertificateDer;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::time::Instant;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    Failure, INPUT_BYTES, OUTPUT_BYTES, bearer, deadline,
    error::Kind,
    json as strict_json,
    outbound::{Outbound, Response},
    telemetry::{Outcome, Stage, Telemetry},
};

/// The only delegated scope. It grants reads of every catalog operation.
pub const SCOPE: &str = "read";

const TOKEN_BYTES: usize = 8 << 10;
/// Accepted issuer clock lead for `iat` and `nbf`, in seconds.
const CLOCK_SKEW_SECONDS: u64 = 60;
const CLAIM_BYTES: usize = 64 << 10;
const HEADER_BYTES: usize = 16 << 10;
/// Most rejected tokens remembered at once.
const REJECTED_TOKENS: usize = 4096;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy)]
pub(crate) enum AuthorizationFailure {
    Rejected(Failure),
    InsufficientScope,
}

impl AuthorizationFailure {
    const fn failure(self) -> Failure {
        match self {
            Self::Rejected(failure) => failure,
            Self::InsufficientScope => Failure {
                kind: Kind::PermissionDenied,
                retry_after_ms: None,
            },
        }
    }
}

impl From<Failure> for AuthorizationFailure {
    fn from(failure: Failure) -> Self {
        Self::Rejected(failure)
    }
}

impl From<Kind> for AuthorizationFailure {
    fn from(kind: Kind) -> Self {
        Self::Rejected(kind.into())
    }
}

struct Verified {
    principal: Principal,
    scope_allowed: bool,
}

/// Verified identity references. These are not bearer credentials.
#[derive(Clone)]
pub struct Principal {
    /// Issuer credential reference.
    pub credential_id: String,
    /// Delegated client identifier.
    pub client_id: String,
}

impl Principal {
    /// Identity limits are enforced again before execution.
    #[must_use]
    pub fn valid(&self) -> bool {
        valid_token(&self.credential_id)
            && self.credential_id.len() <= 256
            && valid_client_id(&self.client_id, 2048)
    }
}

impl fmt::Debug for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("verified principal [redacted]")
    }
}

/// The service login for the fixed introspection and execution endpoints.
#[derive(Clone)]
pub struct MachineCredential {
    id: String,
    secret: Zeroizing<String>,
}

impl MachineCredential {
    /// Construct a bounded machine credential without diagnostic disclosure.
    ///
    /// # Errors
    /// Rejects empty or oversized secrets and credentials outside printable ASCII.
    pub fn new(id: String, secret: Zeroizing<String>) -> Result<Self, Failure> {
        // RFC 6749 Appendix A.2 defines client-secret using VSCHAR (%x20-7E).
        if !valid_client_id(&id, TOKEN_BYTES)
            || secret.is_empty()
            || secret.len() > TOKEN_BYTES
            || !secret.bytes().all(|byte| (b' '..=b'~').contains(&byte))
        {
            return Err(Kind::Configuration.into());
        }
        Ok(Self { id, secret })
    }
}

impl fmt::Debug for MachineCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("machine credential [redacted]")
    }
}

/// Trusted authority locations and the service login used at both.
pub struct UpstreamOptions {
    /// Fixed RFC 7662 endpoint.
    pub introspection_endpoint: String,
    /// Fixed operation execution endpoint.
    pub execution_endpoint: String,
    /// Expected issuer identifier.
    pub issuer: String,
    /// Expected audience identifier.
    pub resource: String,
    /// Service login shared by introspection and execution.
    pub service_credential: MachineCredential,
}

/// Outbound clients do not inherit proxy, cookies, or caller-selected destinations.
pub struct Upstream {
    client: Outbound,
    options: UpstreamOptions,
    telemetry: Telemetry,
    rejected_ttl: Duration,
    /// SHA-256 of recently rejected tokens, never the tokens themselves.
    rejected: Mutex<BTreeMap<[u8; 32], (Instant, AuthorizationFailure)>>,
}

impl Upstream {
    /// Construct TLS-verified clients without opening a connection.
    ///
    /// # Errors
    /// Rejects invalid authority URLs or TLS client configuration.
    pub fn new(options: UpstreamOptions) -> Result<Self, Failure> {
        Self::with_certificate(options, None)
    }

    /// Add one explicitly trusted certificate, for isolated local HTTPS tests.
    /// The certificate must use DER encoding and contain at most 256 KiB.
    ///
    /// # Errors
    /// Rejects invalid configuration. This does not disable certificate validation.
    pub fn with_certificate(
        options: UpstreamOptions,
        certificate: Option<CertificateDer<'static>>,
    ) -> Result<Self, Failure> {
        for value in [
            &options.introspection_endpoint,
            &options.execution_endpoint,
            &options.issuer,
            &options.resource,
        ] {
            drop(canonical_https(value)?);
        }
        let client = Outbound::new(certificate)?;
        Ok(Self {
            client,
            options,
            telemetry: Telemetry::default(),
            rejected_ttl: Duration::ZERO,
            rejected: Mutex::new(BTreeMap::new()),
        })
    }

    /// Refuse a token for `ttl` after introspection rejected it, without asking
    /// again. Only definite denials are kept; `Duration::ZERO` disables this.
    #[must_use]
    pub(crate) const fn with_rejected_token_ttl(mut self, ttl: Duration) -> Self {
        self.rejected_ttl = ttl;
        self
    }

    /// Retain an operator observer without exposing a protocol tool or endpoint.
    #[must_use]
    pub fn telemetry(&self) -> Telemetry {
        self.telemetry.clone()
    }

    /// Introspect each request. No positive authorization cache exists;
    /// recent definite rejections may be answered without introspection.
    ///
    /// # Errors
    /// Distinguishes rejected credentials, insufficient scope, and unavailable authorization.
    pub async fn verify(&self, token: &str) -> Result<Principal, Failure> {
        self.verify_request(token)
            .await
            .map_err(AuthorizationFailure::failure)
    }

    /// Measure bounded per-request introspection. A token rejected within the
    /// configured window is refused again without introspection.
    ///
    /// # Errors
    /// Preserves credential and scope denials; returns Unavailable for
    /// authorization service failures or an exceeded introspection deadline.
    pub(crate) async fn verify_request(
        &self,
        token: &str,
    ) -> Result<Principal, AuthorizationFailure> {
        let key: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        if let Some(failure) = self.recently_rejected(&key) {
            return Err(failure);
        }
        let result = self.introspect(token).await;
        if let Err(failure) = result {
            self.remember_rejection(key, failure);
        }
        result
    }

    /// Return a rejection remembered for this token digest and still current.
    fn recently_rejected(&self, key: &[u8; 32]) -> Option<AuthorizationFailure> {
        let (until, failure) = *self
            .rejected
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)?;
        (Instant::now() < until).then_some(failure)
    }

    /// Remember a definite denial; unavailable outcomes are always retried.
    /// When full, expired entries are dropped first, and a new rejection is
    /// not kept if none expired.
    fn remember_rejection(&self, key: [u8; 32], failure: AuthorizationFailure) {
        let now = Instant::now();
        let Some(until) = now.checked_add(self.rejected_ttl) else {
            return;
        };
        if until <= now
            || !matches!(
                failure.failure().kind,
                Kind::Unauthorized | Kind::PermissionDenied
            )
        {
            return;
        }
        let mut rejected = self.rejected.lock().unwrap_or_else(PoisonError::into_inner);
        if rejected.len() >= REJECTED_TOKENS {
            rejected.retain(|_, entry| entry.0 > now);
        }
        if rejected.len() < REJECTED_TOKENS || rejected.contains_key(&key) {
            let _previous: Option<(Instant, AuthorizationFailure)> =
                rejected.insert(key, (until, failure));
        }
    }

    /// Introspect once within the deadline and record the outcome.
    ///
    /// # Errors
    /// Same as [`Self::verify_request`].
    async fn introspect(&self, token: &str) -> Result<Principal, AuthorizationFailure> {
        let measurement = self.telemetry.begin(Stage::Introspection);
        let result = deadline::within(Duration::from_secs(5), self.verify_inner(token))
            .await
            .unwrap_or_else(|| Err(Kind::Unavailable.into()));
        measurement.finish(result.as_ref().map_or_else(
            |failure| Outcome::failure(failure.failure().kind),
            |_| Outcome::Completed,
        ));
        result
    }

    /// Introspect an opaque token and validate its claims. Any client the
    /// authorization server confirms is accepted; no local client policy applies.
    ///
    /// # Errors
    /// Rejects invalid tokens, claims, client IDs and insufficient scopes; fails
    /// closed on transport, header, body or introspection response errors.
    async fn verify_inner(&self, token: &str) -> Result<Principal, AuthorizationFailure> {
        if !bearer::valid(token) {
            return Err(Kind::Unauthorized.into());
        }
        let response = self
            .client
            .post(
                &self.options.introspection_endpoint,
                authorization(&self.options.service_credential)?,
                "application/x-www-form-urlencoded",
                format!(
                    "token={}&token_type_hint=access_token",
                    form_component(token)
                )
                .into_bytes(),
            )
            .await
            .map_err(Failure::redact(Kind::Unavailable))?;
        if !bounded_headers(&response) || response.status() != 200 {
            return Err(Kind::Unavailable.into());
        }
        let bytes = bounded_response(response, CLAIM_BYTES).await?;
        let value =
            strict_json::object(&bytes, CLAIM_BYTES).map_err(Failure::redact(Kind::Unavailable))?;
        let verified = claims(&value, &self.options)?;
        if !verified.scope_allowed {
            return Err(AuthorizationFailure::InsufficientScope);
        }
        Ok(verified.principal)
    }

    /// Execute using only freshly bound delegated authority and a fixed endpoint.
    ///
    /// # Errors
    /// Returns stable status categories, bounded retry advice, and no upstream body.
    pub async fn execute(
        &self,
        principal: &Principal,
        token: &str,
        operation: &str,
        input: &Value,
    ) -> Result<Value, Failure> {
        let measurement = self.telemetry.begin(Stage::UpstreamExecute);
        let result = deadline::within(
            Duration::from_secs(10),
            self.execute_inner(principal, token, operation, input),
        )
        .await
        .unwrap_or_else(|| Err(Kind::Unavailable.into()));
        measurement.finish(Outcome::result(&result));
        result
    }

    /// Send bounded operation input with validated delegated authority.
    ///
    /// # Errors
    /// Rejects invalid authority or input, transport failures,
    /// invalid response framing and output outside the exact JSON budget.
    async fn execute_inner(
        &self,
        principal: &Principal,
        token: &str,
        operation: &str,
        input: &Value,
    ) -> Result<Value, Failure> {
        if !principal.valid()
            || !bearer::valid(token)
            || !valid_token(operation)
            || operation.len() > 128
        {
            return Err(Kind::Unavailable.into());
        }
        let input_bytes = serde_json::to_vec(input).map_err(Failure::redact(Kind::InvalidInput))?;
        drop(strict_json::object(&input_bytes, INPUT_BYTES)?);
        let response = self
            .client
            .post(
                &self.options.execution_endpoint,
                authorization(&self.options.service_credential)?,
                "application/json",
                serde_json::to_vec(
                    &json!({"token":token,"credential_id":principal.credential_id,
                    "client_id":principal.client_id,"request":{"operation":operation,"input":input}}),
                )
                .map_err(Failure::redact(Kind::Unavailable))?,
            )
            .await
            .map_err(Failure::redact(Kind::Unavailable))?;
        if !bounded_headers(&response) {
            return Err(Kind::Unavailable.into());
        }
        if response.status() != 200 {
            return Err(response_failure(&response));
        }
        let bytes = bounded_response(response, OUTPUT_BYTES).await?;
        strict_json::object(&bytes, OUTPUT_BYTES).map_err(Failure::redact(Kind::InvalidOutput))
    }
}

/// Check bounded printable ASCII without normalizing an OAuth client ID.
fn valid_client_id(id: &str, maximum: usize) -> bool {
    // RFC 6749 Appendix A.1 uses VSCHAR, including space and comma.
    !id.is_empty() && id.len() <= maximum && id.bytes().all(|byte| (b' '..=b'~').contains(&byte))
}

pub(crate) fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= TOKEN_BYTES
        && value
            .bytes()
            .all(|byte| (b'!'..=b'~').contains(&byte) && byte != b',')
}

fn valid_scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= TOKEN_BYTES
        && value
            .bytes()
            .all(|byte| (b'!'..=b'~').contains(&byte) && !matches!(byte, b'"' | b'\\'))
}

/// Validate a canonical HTTPS authority without credentials, queries, or fragments.
///
/// # Errors
/// Rejects unsupported, ambiguous, or oversized service locations.
pub fn canonical_https(value: &str) -> Result<Url, Failure> {
    let url = Url::parse(value).map_err(Failure::redact(Kind::Configuration))?;
    let root_identifier = url.path() == "/" && url.as_str().strip_suffix('/') == Some(value);
    if value.len() > 2048
        || url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.as_str() != value && !root_identifier)
        || url.path().contains('%')
    {
        return Err(Kind::Configuration.into());
    }
    Ok(url)
}

/// Validate introspection identity, time, issuer, audience and scope syntax.
///
/// # Errors
/// Returns Unauthorized for inactive or invalid credentials. Returns
/// Unavailable for malformed claims or an unavailable local time source.
fn claims(value: &Value, options: &UpstreamOptions) -> Result<Verified, Failure> {
    let fields = value.as_object().ok_or(Kind::Unavailable)?;
    if fields.len() > 128 {
        return Err(Kind::Unavailable.into());
    }
    match value.get("active").and_then(Value::as_bool) {
        Some(false) => return Err(Kind::Unauthorized.into()),
        Some(true) => {}
        None => return Err(Kind::Unavailable.into()),
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(Failure::redact(Kind::Unavailable))?
        .as_secs();
    let text = |key| {
        value
            .get(key)
            .and_then(Value::as_str)
            .ok_or(Kind::Unavailable)
    };
    let expires = value
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or(Kind::Unavailable)?;
    for key in ["iat", "nbf"] {
        if let Some(field) = value.get(key)
            && field.as_u64().ok_or(Kind::Unavailable)? > now.saturating_add(CLOCK_SKEW_SECONDS)
        {
            return Err(Kind::Unauthorized.into());
        }
    }
    let principal = Principal {
        credential_id: text("jti")?.to_owned(),
        client_id: text("client_id")?.to_owned(),
    };
    let audience = value.get("aud").ok_or(Kind::Unavailable)?;
    let audience_matches = if let Some(single) = audience.as_str() {
        single == options.resource
    } else if let Some(multiple) = audience.as_array() {
        multiple.iter().all(Value::is_string)
            && multiple
                .iter()
                .any(|entry| entry.as_str() == Some(&options.resource))
    } else {
        return Err(Kind::Unavailable.into());
    };
    let scope = text("scope")?;
    if expires <= now
        || !principal.valid()
        || text("iss")? != options.issuer
        || !audience_matches
        || !text("token_type")?.eq_ignore_ascii_case("Bearer")
        || !scope.split(' ').all(valid_scope)
    {
        return Err(Kind::Unauthorized.into());
    }
    Ok(Verified {
        principal,
        scope_allowed: scope.split(' ').any(|entry| entry == SCOPE),
    })
}

fn bounded_headers(response: &Response) -> bool {
    remaining_header_budget(response.headers(), HEADER_BYTES).is_some()
}

fn remaining_header_budget(headers: &HeaderMap, budget: usize) -> Option<usize> {
    headers.iter().try_fold(budget, |remaining, (key, value)| {
        remaining
            .checked_sub(key.as_str().len())?
            .checked_sub(value.len())?
            .checked_sub(4)
    })
}

/// Read JSON response data under the header and body budgets.
///
/// # Errors
/// Rejects invalid headers, media type or coding, excessive size and body errors.
async fn bounded_response(mut response: Response, limit: usize) -> Result<Vec<u8>, Failure> {
    let mut remaining_headers =
        remaining_header_budget(response.headers(), HEADER_BYTES).ok_or(Kind::Unavailable)?;
    if response
        .body()
        .size_hint()
        .exact()
        .is_some_and(|size| size > u64::try_from(limit).unwrap_or(u64::MAX))
        || !crate::media::json(response.headers())
        || !crate::media::unencoded(response.headers())
    {
        return Err(Kind::Unavailable.into());
    }
    let mut bytes = Vec::new();
    while let Some(frame) = response.body_mut().frame().await {
        let frame = frame.map_err(Failure::redact(Kind::Unavailable))?;
        let chunk = match frame.into_data() {
            Ok(chunk) => chunk,
            Err(frame) => {
                let trailers = frame
                    .into_trailers()
                    .map_err(Failure::redact(Kind::Unavailable))?;
                // Count both sections without changing initial header semantics.
                remaining_headers = remaining_header_budget(&trailers, remaining_headers)
                    .ok_or(Kind::Unavailable)?;
                continue;
            }
        };
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(Kind::Unavailable.into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn response_failure(response: &Response) -> Failure {
    let status = response.status().as_u16();
    let kind = match status {
        401 => Kind::Unauthorized,
        403 => Kind::PermissionDenied,
        400 | 413 | 422 => Kind::InvalidInput,
        429 => Kind::Throttled,
        404 => Kind::NotFound,
        _ => Kind::Unavailable,
    };
    let values: Vec<_> = response
        .headers()
        .get_all(header::RETRY_AFTER)
        .iter()
        .collect();
    let delay = if matches!(status, 429 | 503) && values.len() == 1 {
        values
            .first()
            .and_then(|value| value.to_str().ok())
            .and_then(retry_after)
    } else {
        None
    };
    Failure {
        kind,
        retry_after_ms: delay,
    }
}

fn retry_after(value: &str) -> Option<u64> {
    retry_after_at(value, SystemTime::now())
}

fn retry_after_at(value: &str, now: SystemTime) -> Option<u64> {
    if value.is_empty() || value.len() > 128 {
        return None;
    }
    let milliseconds = if value.bytes().all(|byte| byte.is_ascii_digit()) {
        value.parse::<u64>().ok()?.checked_mul(1000)?
    } else {
        let remaining = httpdate::parse_http_date(value)
            .ok()?
            .duration_since(now)
            .unwrap_or_default();
        // Round up so the advice never shortens the server's requested wait.
        let rounded = remaining
            .checked_add(Duration::from_nanos(999_999))?
            .as_millis();
        u64::try_from(rounded).ok()?
    };
    (milliseconds <= 2_147_483_647_000).then_some(milliseconds)
}

/// Encode one sensitive Basic field from the configured machine credential.
///
/// # Errors
/// Returns Unavailable if the encoded field cannot form a valid HTTP header.
fn authorization(credential: &MachineCredential) -> Result<HeaderValue, Failure> {
    let id = Zeroizing::new(form_component(&credential.id));
    let secret = Zeroizing::new(form_component(&credential.secret));
    let components = Zeroizing::new(format!("{}:{}", id.as_str(), secret.as_str()));
    let encoded = Zeroizing::new(STANDARD.encode(components.as_bytes()));
    let header = Zeroizing::new(format!("Basic {}", encoded.as_str()));
    let mut value =
        HeaderValue::from_str(header.as_str()).map_err(Failure::redact(Kind::Unavailable))?;
    value.set_sensitive(true);
    Ok(value)
}

fn form_component(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
