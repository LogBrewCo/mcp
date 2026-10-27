//! Introspection claims and the identifier syntax they must satisfy.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use super::{
    CLOCK_SKEW_SECONDS, Principal, READ_SCOPE, TOKEN_BYTES, UpstreamOptions, Verified, WRITE_SCOPE,
};
use crate::{Failure, error::Kind};

/// Check bounded printable ASCII without normalizing an OAuth client ID.
pub(super) fn valid_client_id(id: &str, maximum: usize) -> bool {
    // RFC 6749 Appendix A.1 uses VSCHAR, including space and comma.
    !id.is_empty() && id.len() <= maximum && id.bytes().all(|byte| (b' '..=b'~').contains(&byte))
}

pub(super) fn valid_token(value: &str) -> bool {
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

/// Validate introspection identity, time, issuer, audience and scope syntax.
///
/// # Errors
/// Returns Unauthorized for inactive or invalid credentials. Returns
/// Unavailable for malformed claims or an unavailable local time source.
pub(super) fn claims(value: &Value, options: &UpstreamOptions) -> Result<Verified, Failure> {
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
    let scope = text("scope")?;
    let principal = Principal {
        credential_id: text("jti")?.to_owned(),
        client_id: text("client_id")?.to_owned(),
        write: scope.split(' ').any(|entry| entry == WRITE_SCOPE),
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
        scope_allowed: scope.split(' ').any(|entry| entry == READ_SCOPE),
    })
}
