//! Strict object-rooted JSON with decoded-key uniqueness and numeric bounds.

use alloc::collections::BTreeMap;
use core::fmt;

use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, Visitor},
};
use serde_json::{Value, value::RawValue};

use crate::{Failure, error::Kind};

const DEPTH: usize = 64;
const NUMBER_BYTES: usize = 256;
const EXPONENT: i64 = 1024;

// Convert the exact decimal value without rounding or expanding its exponent.
pub(crate) fn unsigned_integer(document: &Value) -> Option<u64> {
    let number = document.as_number()?;
    if let Some(value) = number.as_u64() {
        return Some(value);
    }
    let encoded = number.to_string();
    let raw = encoded.strip_prefix('-').unwrap_or(&encoded);
    let (coefficient, exponent) = raw.split_once(['e', 'E']).unwrap_or((raw, "0"));
    let exponent = exponent.parse::<i64>().ok()?;
    let (whole, fraction) = coefficient.split_once('.').unwrap_or((coefficient, ""));
    let digits: Vec<_> = whole.bytes().chain(fraction.bytes()).collect();
    if digits.iter().all(|byte| *byte == b'0') {
        return Some(0);
    }
    if encoded.starts_with('-') {
        return None;
    }
    let shift = exponent.checked_sub(i64::try_from(fraction.len()).ok()?)?;
    let retained = if shift < 0 {
        let removed = usize::try_from(shift.checked_neg()?).ok()?;
        let retained = digits.len().checked_sub(removed)?;
        if digits.iter().skip(retained).any(|byte| *byte != b'0') {
            return None;
        }
        retained
    } else {
        digits.len()
    };
    let integer = digits
        .iter()
        .take(retained)
        .try_fold(0_u64, |value, byte| {
            value
                .checked_mul(10)?
                .checked_add(u64::from(byte.checked_sub(b'0')?))
        })?;
    let multiplier = if shift > 0 {
        10_u64.checked_pow(u32::try_from(shift).ok()?)?
    } else {
        1
    };
    integer.checked_mul(multiplier)
}

struct UniqueObject(BTreeMap<String, Box<RawValue>>);

struct ObjectVisitor;

impl<'de> Visitor<'de> for ObjectVisitor {
    type Value = UniqueObject;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object with unique decoded keys")
    }

    fn visit_map<M>(self, map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        unique_fields(map).map(UniqueObject)
    }
}

/// Collect raw object fields without reinterpreting ordinary property names.
///
/// # Errors
/// Propagates field decoding failures and rejects duplicate decoded keys.
fn unique_fields<'de, M>(mut map: M) -> Result<BTreeMap<String, Box<RawValue>>, M::Error>
where
    M: MapAccess<'de>,
{
    let mut fields = BTreeMap::new();
    while let Some((key, value)) = map.next_entry::<String, Box<RawValue>>()? {
        if fields.insert(key, value).is_some() {
            return Err(de::Error::custom("duplicate object key"));
        }
    }
    Ok(fields)
}

impl<'de> Deserialize<'de> for UniqueObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ObjectVisitor)
    }
}

/// Parse an object before handing it to schemas, authentication, or protocol code.
///
/// # Errors
/// Rejects oversized, malformed, duplicate-key, or out-of-budget JSON.
pub fn object(bytes: &[u8], limit: usize) -> Result<Value, Failure> {
    if bytes.len() > limit || core::str::from_utf8(bytes).is_err() {
        return Err(Kind::InvalidInput.into());
    }
    let raw: Box<RawValue> =
        serde_json::from_slice(bytes).map_err(Failure::redact(Kind::InvalidInput))?;
    if !raw.get().starts_with('{') {
        return Err(Kind::InvalidInput.into());
    }
    decode(raw.get(), 0)
}

/// Decode exact values recursively within the container and number budgets.
///
/// # Errors
/// Rejects malformed values, duplicate decoded keys and exceeded budgets.
fn decode(raw: &str, depth: usize) -> Result<Value, Failure> {
    if depth > DEPTH
        || (depth == DEPTH && matches!(raw.as_bytes().first().copied(), Some(b'{' | b'[')))
    {
        return Err(Kind::InvalidInput.into());
    }
    match raw.as_bytes().first().copied() {
        Some(b'{') => {
            let fields: UniqueObject =
                serde_json::from_str(raw).map_err(Failure::redact(Kind::InvalidInput))?;
            let mut object = serde_json::Map::new();
            for (key, value) in fields.0 {
                drop(object.insert(key, decode(value.get(), depth.saturating_add(1))?));
            }
            Ok(Value::Object(object))
        }
        Some(b'[') => {
            let elements: Vec<Box<RawValue>> =
                serde_json::from_str(raw).map_err(Failure::redact(Kind::InvalidInput))?;
            let values = elements
                .iter()
                .map(|value| decode(value.get(), depth.saturating_add(1)))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Value::Array(values))
        }
        Some(b'-' | b'0'..=b'9') => {
            number(raw)?;
            let value = serde_json::from_str::<serde_json::Number>(raw)
                .map_err(Failure::redact(Kind::InvalidInput))?;
            Ok(Value::Number(value))
        }
        _ => serde_json::from_str(raw).map_err(Failure::redact(Kind::InvalidInput)),
    }
}

/// Check a number's text length and optional decimal exponent.
///
/// # Errors
/// Rejects oversized text, invalid exponents and exponents outside the budget.
fn number(raw: &str) -> Result<(), Failure> {
    if raw.len() > NUMBER_BYTES {
        return Err(Kind::InvalidInput.into());
    }
    if let Some((_, exponent)) = raw.split_once(['e', 'E']) {
        let value = exponent
            .parse::<i64>()
            .map_err(Failure::redact(Kind::InvalidInput))?;
        if !(-EXPONENT..=EXPONENT).contains(&value) {
            return Err(Kind::InvalidInput.into());
        }
    }
    Ok(())
}
