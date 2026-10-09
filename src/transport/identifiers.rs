//! Preserve bounded JSON integer identifiers across the SDK's i64 model.

use axum::{
    Json,
    body::{Body, to_bytes},
    http::{StatusCode, header},
    response::{IntoResponse as _, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json, value::RawValue};

use crate::{ENVELOPE_BYTES, REQUEST_BYTES, media};

// A tool reply contains the envelope once as structured data and once as text.
// JSON escaping can double the text's encoded bytes. The request allowance also
// covers correlation and fixed JSON-RPC fields. No expanded integer is stored.
const REPLY_BYTES: usize = 3 * ENVELOPE_BYTES + REQUEST_BYTES;
const INTERNAL_ID: &str = "logbrew-integer-id";

pub struct NumericId(Value);

pub fn valid(id: &Value) -> bool {
    id.is_string()
        || id.as_i64().is_some()
        || id
            .as_number()
            .is_some_and(|number| integral(&number.to_string()))
}

fn integral(raw: &str) -> bool {
    let raw = raw.strip_prefix('-').unwrap_or(raw);
    let (coefficient, exponent) = raw.split_once(['e', 'E']).unwrap_or((raw, "0"));
    let Ok(exponent) = exponent.parse::<i64>() else {
        return false;
    };
    let (whole, fraction) = coefficient.split_once('.').unwrap_or((coefficient, ""));
    let Ok(scale) = i64::try_from(fraction.len()) else {
        return false;
    };
    let digits = whole.bytes().chain(fraction.bytes());
    if exponent >= scale || digits.clone().all(|byte| byte == b'0') {
        return true;
    }
    let Some(required) = scale
        .checked_sub(exponent)
        .and_then(|value| usize::try_from(value).ok())
    else {
        return false;
    };
    digits.rev().take_while(|byte| *byte == b'0').count() >= required
}

pub fn prepare_id(body: &mut Value) -> Option<NumericId> {
    let id = body.get_mut("id")?;
    if !id.is_number() || id.as_i64().is_some() || !valid(id) {
        return None;
    }
    let original = id.clone();
    // Stateless JSON replies belong to this request's future. The internal ID
    // never becomes a shared map key, client identity or public response ID.
    *id = Value::String(INTERNAL_ID.to_owned());
    Some(NumericId(original))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reply<'response> {
    jsonrpc: &'response str,
    #[serde(default, borrow, deserialize_with = "present_raw")]
    id: Option<&'response RawValue>,
    #[serde(default, borrow, deserialize_with = "present_raw")]
    result: Option<&'response RawValue>,
    #[serde(default, borrow, deserialize_with = "present_raw")]
    error: Option<&'response RawValue>,
}

impl Reply<'_> {
    pub(super) const fn jsonrpc(&self) -> &str {
        self.jsonrpc
    }

    pub(super) const fn id(&self) -> Option<&RawValue> {
        self.id
    }

    pub(super) const fn result(&self) -> Option<&RawValue> {
        self.result
    }

    pub(super) const fn error(&self) -> Option<&RawValue> {
        self.error
    }
}

// A present null must remain distinct from a missing JSON-RPC field.
/// Preserve a present JSON-RPC value, including null.
///
/// # Errors
/// Propagates the deserializer's raw-value decoding failure.
fn present_raw<'de, D>(deserializer: D) -> Result<Option<&'de RawValue>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    <&RawValue>::deserialize(deserializer).map(Some)
}

#[derive(Serialize)]
struct Restored<'reply> {
    jsonrpc: &'reply str,
    id: &'reply Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<&'reply RawValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'reply RawValue>,
}

pub async fn restore_id(original: Option<NumericId>, response: Response) -> Response {
    let Some(NumericId(id)) = original else {
        return response;
    };
    if !media::json(response.headers()) {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = to_bytes(body, REPLY_BYTES).await else {
        return unavailable(&id);
    };
    let Some(encoded) = restore(&bytes, &id) else {
        return unavailable(&id);
    };
    drop(parts.headers.remove(header::CONTENT_LENGTH));
    Response::from_parts(parts, Body::from(encoded))
}

fn restore(bytes: &[u8], id: &Value) -> Option<Vec<u8>> {
    let reply: Reply<'_> = serde_json::from_slice(bytes).ok()?;
    let matches = reply.id.is_some_and(|value| {
        serde_json::from_str::<String>(value.get()).is_ok_and(|value| value == INTERNAL_ID)
    });
    if reply.jsonrpc != "2.0"
        || reply.result.is_some() == reply.error.is_some()
        || !reply
            .result
            .or(reply.error)
            .is_some_and(|value| value.get().starts_with('{'))
        || !(matches || reply.id.is_none() && reply.error.is_some())
    {
        return None;
    }
    // Borrow the result/error JSON verbatim so adapting correlation cannot
    // round numbers, reinterpret object keys or re-encode domain evidence.
    let encoded = serde_json::to_vec(&Restored {
        jsonrpc: reply.jsonrpc,
        id,
        result: reply.result,
        error: reply.error,
    })
    .ok()?;
    (encoded.len() <= REPLY_BYTES).then_some(encoded)
}

fn unavailable(id: &Value) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({
            "jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":"response unavailable"}
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
