//! Fixed HTTPS upstreams with fresh introspection and no automatic retries.

use std::{
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::http::{HeaderValue, header};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http_body::Body as _;
use http_body_util::BodyExt as _;
use rustls::pki_types::CertificateDer;
use serde_json::{Value, json};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    Failure, INPUT_BYTES, OUTPUT_BYTES, bearer,
    clients::ClientAllowlist,
    deadline,
    error::Kind,
    json as strict_json,
    outbound::{Outbound, Response},
    telemetry::{Outcome, Stage, Telemetry},
};

const TOKEN_BYTES: usize = 8 << 10;
const CLAIM_BYTES: usize = 64 << 10;
const HEADER_BYTES: usize = 16 << 10;

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
            && valid_token(&self.client_id)
            && self.client_id.len() <= 2048
    }
}

impl fmt::Debug for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("verified principal [redacted]")
    }
}

/// Separate machine credentials for a fixed trusted endpoint.
#[derive(Clone)]
pub struct MachineCredential {
    id: String,
    secret: Zeroizing<String>,
}

impl MachineCredential {
    /// Construct a bounded machine credential without diagnostic disclosure.
    ///
    /// # Errors
    /// Rejects empty or oversized secrets and invalid client identifiers.
    pub fn new(id: String, secret: Zeroizing<String>) -> Result<Self, Failure> {
        if !valid_token(&id) || secret.is_empty() || secret.len() > TOKEN_BYTES {
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

/// Trusted authority locations and independently scoped machine identities.
pub struct UpstreamOptions {
    /// Fixed RFC 7662 endpoint.
    pub introspection_endpoint: String,
    /// Fixed operation execution endpoint.
    pub execution_endpoint: String,
    /// Expected issuer identifier.
    pub issuer: String,
    /// Expected audience identifier.
    pub resource: String,
    /// Required delegated scope.
    pub required_scope: String,
    /// Introspection machine identity.
    pub introspection_credential: MachineCredential,
    /// Execution machine identity.
    pub execution_credential: MachineCredential,
}

/// Outbound clients do not inherit proxy, cookies, or caller-selected destinations.
pub struct Upstream {
    client: Outbound,
    options: UpstreamOptions,
    telemetry: Telemetry,
    clients: ClientAllowlist,
}

impl Upstream {
    /// Construct TLS-verified clients without opening a connection.
    /// No client is authorized until an explicit allowlist is supplied.
    ///
    /// # Errors
    /// Rejects invalid authority URLs, scope, or TLS client configuration.
    pub fn new(options: UpstreamOptions) -> Result<Self, Failure> {
        Self::with_certificate(options, None)
    }

    /// Add one explicitly trusted certificate, for isolated local HTTPS tests.
    /// The certificate must use DER encoding and contain at most 256 KiB.
    /// No client is authorized until an explicit allowlist is supplied.
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
        if !valid_scope(&options.required_scope) || options.required_scope == "offline_access" {
            return Err(Kind::Configuration.into());
        }
        let client = Outbound::new(certificate)?;
        Ok(Self {
            client,
            options,
            telemetry: Telemetry::default(),
            clients: ClientAllowlist::default(),
        })
    }

    /// Restrict issuer-confirmed client IDs before discovery or execution.
    /// This policy adds to token validation and does not grant scopes or permissions.
    #[must_use]
    pub fn with_client_allowlist(mut self, clients: ClientAllowlist) -> Self {
        self.clients = clients;
        self
    }

    /// Check the issuer-confirmed client against the configured exact allowlist.
    ///
    /// # Errors
    /// Returns `PermissionDenied` when the client is absent from the allowlist.
    fn authorize_client(&self, principal: &Principal) -> Result<(), Failure> {
        if !self.clients.contains(&principal.client_id) {
            return Err(Kind::PermissionDenied.into());
        }
        Ok(())
    }

    /// Retain an operator observer without exposing a protocol tool or endpoint.
    #[must_use]
    pub fn telemetry(&self) -> Telemetry {
        self.telemetry.clone()
    }

    pub(crate) fn required_scope(&self) -> &str {
        &self.options.required_scope
    }

    /// Introspect each request. No positive or negative authorization cache exists.
    ///
    /// # Errors
    /// Distinguishes rejected credentials, insufficient scope, and unavailable authorization.
    pub async fn verify(&self, token: &str) -> Result<Principal, Failure> {
        self.verify_request(token)
            .await
            .map_err(AuthorizationFailure::failure)
    }

    /// Measure bounded per-request introspection without an authorization cache.
    ///
    /// # Errors
    /// Preserves credential, scope and client denials; returns Unavailable for
    /// authorization service failures or an exceeded introspection deadline.
    pub(crate) async fn verify_request(
        &self,
        token: &str,
    ) -> Result<Principal, AuthorizationFailure> {
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

    /// Introspect an opaque token and validate its claims and client authority.
    ///
    /// # Errors
    /// Rejects invalid tokens, claims, clients and insufficient scopes; fails
    /// closed on transport, header, body or introspection response errors.
    async fn verify_inner(&self, token: &str) -> Result<Principal, AuthorizationFailure> {
        if !bearer::valid(token) {
            return Err(Kind::Unauthorized.into());
        }
        let credential = &self.options.introspection_credential;
        let response = self
            .client
            .post(
                &self.options.introspection_endpoint,
                authorization(credential)?,
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
        self.authorize_client(&verified.principal)?;
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
    /// Rejects invalid authority or input, denied clients, transport failures,
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
        self.authorize_client(principal)?;
        let bytes = serde_json::to_vec(input).map_err(Failure::redact(Kind::InvalidInput))?;
        drop(strict_json::object(&bytes, INPUT_BYTES)?);
        let credential = &self.options.execution_credential;
        let response = self
            .client
            .post(
                &self.options.execution_endpoint,
                authorization(credential)?,
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
            && field.as_u64().ok_or(Kind::Unavailable)? > now
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
        scope_allowed: scope
            .split(' ')
            .any(|entry| entry == options.required_scope),
    })
}

fn bounded_headers(response: &Response) -> bool {
    let header_bytes = response
        .headers()
        .iter()
        .try_fold(0_usize, |size, (key, value)| {
            let size = size
                .checked_add(key.as_str().len())?
                .checked_add(value.len())?;
            size.checked_add(4)
        });
    header_bytes.is_some_and(|size| size <= HEADER_BYTES)
}

/// Read JSON response data under the header and body budgets.
///
/// # Errors
/// Rejects invalid headers or media type, excessive body size and body errors.
async fn bounded_response(mut response: Response, limit: usize) -> Result<Vec<u8>, Failure> {
    if !bounded_headers(&response)
        || response
            .body()
            .size_hint()
            .exact()
            .is_some_and(|size| size > u64::try_from(limit).unwrap_or(u64::MAX))
        || !crate::media::json(response.headers())
    {
        return Err(Kind::Unavailable.into());
    }
    let mut bytes = Vec::new();
    while let Some(frame) = response.body_mut().frame().await {
        let frame = frame.map_err(Failure::redact(Kind::Unavailable))?;
        let Ok(chunk) = frame.into_data() else {
            continue;
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
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                char::from(byte).to_string()
            }
            b' ' => "+".to_owned(),
            _ => format!("%{byte:02X}"),
        })
        .collect()
}
