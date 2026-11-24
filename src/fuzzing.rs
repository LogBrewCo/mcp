//! Entry points for the fuzz targets in `fuzz/`. The crate builds this module
//! only with `--cfg fuzzing`, which `cargo fuzz` sets.

use axum::http::{HeaderMap, HeaderValue, header};

/// Read the Bearer token from Authorization fields with these values.
#[must_use]
pub fn bearer_token(values: &[&[u8]]) -> Option<String> {
    let headers = values
        .iter()
        .map(|value| Some((header::AUTHORIZATION, HeaderValue::from_bytes(value).ok()?)))
        .collect::<Option<HeaderMap>>()?;
    crate::bearer::parse(&headers).ok().map(str::to_owned)
}

/// Check a token the way the upstream calls do.
#[must_use]
pub fn valid_token(token: &str) -> bool {
    crate::bearer::valid(token)
}

/// Parse a request body, replace its numeric ID, and restore that ID into a
/// reply. Returns the original and the restored ID as JSON text.
#[must_use]
pub fn request_id(bytes: &[u8]) -> Option<(String, Option<String>)> {
    let mut body = crate::json::object(bytes, crate::REQUEST_BYTES).ok()?;
    let (original, restored) = crate::transport::round_trip_id(&mut body)?;
    Some((original.to_string(), restored.map(|id| id.to_string())))
}
