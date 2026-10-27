//! Bounded upstream responses, failure mapping and the service login header.

use core::time::Duration;
use std::time::SystemTime;

use axum::http::{HeaderMap, HeaderValue, header};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http_body::Body as _;
use http_body_util::BodyExt as _;
use zeroize::Zeroizing;

use super::{HEADER_BYTES, MachineCredential};
use crate::{Failure, error::Kind, outbound::Response};

pub(super) fn bounded_headers(response: &Response) -> bool {
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
pub(super) async fn bounded_response(
    mut response: Response,
    limit: usize,
) -> Result<Vec<u8>, Failure> {
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

pub(super) fn response_failure(response: &Response) -> Failure {
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

pub(super) fn retry_after_at(value: &str, now: SystemTime) -> Option<u64> {
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
pub(super) fn authorization(credential: &MachineCredential) -> Result<HeaderValue, Failure> {
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

pub(super) fn form_component(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
