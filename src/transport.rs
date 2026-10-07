//! HTTP validation before SDK dispatch, preserving legacy protocol support.

use axum::{
    Json,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use serde_json::{Value, json, value::RawValue};

mod errors;
pub use errors::fixed_header_error;
mod identifiers;
pub use identifiers::{prepare_id, restore_id};

pub fn prepare(headers: &mut HeaderMap, body: &Value) -> Option<Response> {
    if !crate::media::json(headers) {
        return Some((StatusCode::UNSUPPORTED_MEDIA_TYPE, "invalid content type").into_response());
    }
    // Media type tokens are case-insensitive. Normalize only after parsing;
    // the SDK's prefix check otherwise accepts unrelated JSON-like subtypes.
    drop(headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    ));
    if !acceptable(headers) {
        return Some((StatusCode::NOT_ACCEPTABLE, "invalid accept types").into_response());
    }
    drop(headers.insert(
        header::ACCEPT,
        HeaderValue::from_static("application/json, text/event-stream"),
    ));
    if body.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || body.get("method").and_then(Value::as_str).is_none()
        || body.get("result").is_some()
        || body.get("error").is_some()
        || body.get("id").is_some_and(|id| !valid_id(id))
    {
        return Some(rpc_error(body, -32600, "invalid client request"));
    }
    if headers.get_all("mcp-protocol-version").iter().count() > 1 {
        return Some(rpc_error(body, -32020, "duplicate protocol version header"));
    }
    None
}

fn valid_id(id: &Value) -> bool {
    identifiers::valid(id)
}

// Syntax validation borrows the bounded body without accepting duplicate keys,
// wrong roots or values outside the strict parser's budgets for dispatch.
pub fn rejected_json(bytes: &[u8]) -> Response {
    let (code, message) = if serde_json::from_slice::<&RawValue>(bytes).is_ok() {
        (-32_600_i32, "invalid client request")
    } else {
        (-32_700_i32, "invalid JSON request")
    };
    rpc_error(&Value::Null, code, message)
}

fn rpc_error(body: &Value, code: i32, message: &str) -> Response {
    let mut error = json!({"jsonrpc":"2.0","error":{"code":code,"message":message}});
    if let Some(id) = body.get("id").filter(|id| valid_id(id))
        && let Some(fields) = error.as_object_mut()
    {
        drop(fields.insert("id".to_owned(), id.clone()));
    }
    (StatusCode::BAD_REQUEST, Json(error)).into_response()
}

fn acceptable(headers: &HeaderMap) -> bool {
    let mut json = false;
    let mut events = false;
    for field in headers.get_all(header::ACCEPT) {
        let Ok(field) = field.to_str() else {
            return false;
        };
        let Some((field_json, field_events)) = acceptable_field(field) else {
            return false;
        };
        json |= field_json;
        events |= field_events;
    }
    json && events
}

fn acceptable_field(field: &str) -> Option<(bool, bool)> {
    let mut json = false;
    let mut events = false;
    let mut quoted = false;
    let mut escaped = false;
    for media_field in
        field.split(|character| media_separator(character, &mut quoted, &mut escaped))
    {
        if media_field.trim().is_empty() {
            continue;
        }
        let media = media_field.trim().parse::<mime::Mime>().ok()?;
        let mut quality = media.params().filter(|parameter| parameter.0 == "q");
        let weight = quality.next().map(|(_, value)| value);
        if quality.next().is_some() {
            return None;
        }
        let enabled = weight.map_or(Some(true), |weight| positive_quality(weight.as_str()))?;
        json |= enabled && media.essence_str() == "application/json";
        events |= enabled && media.essence_str() == "text/event-stream";
    }
    Some((json, events))
}

const fn media_separator(character: char, quoted: &mut bool, escaped: &mut bool) -> bool {
    if *escaped {
        *escaped = false;
        return false;
    }
    match character {
        '\\' if *quoted => *escaped = true,
        '"' => *quoted = !*quoted,
        ',' if !*quoted => return true,
        _ => {}
    }
    false
}

fn positive_quality(value: &str) -> Option<bool> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    match whole {
        "0" => Some(fraction.bytes().any(|byte| byte != b'0')),
        "1" if fraction.bytes().all(|byte| byte == b'0') => Some(true),
        _ => None,
    }
}
