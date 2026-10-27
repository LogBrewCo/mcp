//! Catalog decoding and the operation and schema contracts it must satisfy.

use alloc::collections::BTreeMap;

use serde_json::Value;

use super::{Entry, Operation, SCHEMA_BYTES};
use crate::{
    Failure,
    error::Kind,
    json as strict_json,
    upstream::{READ_SCOPE, WRITE_SCOPE},
};

/// Compile validated operation contracts into a deterministic lookup.
///
/// # Errors
/// Rejects duplicate identifiers, invalid metadata or schemas that cannot be compiled.
pub(super) fn compile_entries(
    operations: Vec<Operation>,
) -> Result<BTreeMap<String, Entry>, Failure> {
    let mut entries = BTreeMap::new();
    for operation in operations {
        validate_operation(&operation)?;
        let entry = Entry {
            input: compile(&operation.input_schema)?,
            output: compile(&operation.output_schema)?,
            operation,
        };
        if entries.insert(entry.operation.id.clone(), entry).is_some() {
            return Err(Kind::Configuration.into());
        }
    }
    Ok(entries)
}

/// Decode catalog records while preserving already parsed schema values.
///
/// # Errors
/// Rejects unsupported versions, missing or extra fields, invalid metadata
/// types and operation counts outside the catalog limit.
pub(super) fn decode_operations(document: &Value) -> Result<Vec<Operation>, Failure> {
    let catalog_fields = document.as_object().ok_or(Kind::Configuration)?;
    if catalog_fields.len() != 2
        || catalog_fields.get("format_version").and_then(Value::as_u64) != Some(1)
    {
        return Err(Kind::Configuration.into());
    }
    let operations = catalog_fields
        .get("operations")
        .and_then(Value::as_array)
        .filter(|operations| (1..=256).contains(&operations.len()))
        .ok_or(Kind::Configuration)?;
    operations
        .iter()
        .map(|value| {
            let fields = value.as_object().ok_or(Kind::Configuration)?;
            if fields.len() != 4 {
                return Err(Kind::Configuration.into());
            }
            // Keep schemas as already-decoded values: deserializing them again
            // can reinterpret ordinary property names as serializer records.
            Ok(Operation {
                id: fields
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or(Kind::Configuration)?
                    .to_owned(),
                info: serde_json::from_value(
                    fields.get("info").ok_or(Kind::Configuration)?.clone(),
                )
                .map_err(Failure::redact(Kind::Configuration))?,
                input_schema: fields
                    .get("input_schema")
                    .ok_or(Kind::Configuration)?
                    .clone(),
                output_schema: fields
                    .get("output_schema")
                    .ok_or(Kind::Configuration)?
                    .clone(),
            })
        })
        .collect()
}

/// Read an optional string without changing its contents.
///
/// # Errors
/// Rejects a supplied value that is not a string.
pub(super) fn optional_text(value: Option<&Value>) -> Result<&str, Failure> {
    value.map_or(Ok(""), |value| {
        value.as_str().ok_or_else(|| Kind::InvalidInput.into())
    })
}

/// Check exact JSON and its declared schema within the supplied byte limit.
///
/// # Errors
/// Rejects encoding errors, invalid or out-of-budget JSON and schema violations.
pub(super) fn validate(
    schema: &jsonschema::Validator,
    value: &Value,
    limit: usize,
) -> Result<(), Failure> {
    let bytes = serde_json::to_vec(value).map_err(Failure::redact(Kind::InvalidInput))?;
    drop(strict_json::object(&bytes, limit)?);
    if !schema.is_valid(value) {
        return Err(Kind::InvalidInput.into());
    }
    Ok(())
}

/// Compile a bounded schema with format assertions and no external retrieval.
///
/// # Errors
/// Rejects encoding or JSON limits, unsupported dialects and invalid schemas,
/// including references that require external retrieval.
fn compile(value: &Value) -> Result<jsonschema::Validator, Failure> {
    let bytes = serde_json::to_vec(value).map_err(Failure::redact(Kind::Configuration))?;
    drop(strict_json::object(&bytes, SCHEMA_BYTES).map_err(Failure::redact(Kind::Configuration))?);
    validate_dialects(value, jsonschema::Draft::Draft202012)?;
    jsonschema::options()
        .with_retriever(DenyRetrieval)
        .should_validate_formats(true)
        .build(value)
        .map_err(Failure::redact(Kind::Configuration))
}

/// Check dialects recursively at schema locations.
///
/// # Errors
/// Rejects an unknown dialect at this location or any schema subresource.
fn validate_dialects(value: &Value, inherited: jsonschema::Draft) -> Result<(), Failure> {
    let draft = inherited.detect(value);
    if draft == jsonschema::Draft::Unknown {
        return Err(Kind::Configuration.into());
    }
    // Visit schema locations, not examples, constants or instance property names.
    for schema in draft.subresources_of(value) {
        validate_dialects(schema, draft)?;
    }
    Ok(())
}

struct DenyRetrieval;

impl jsonschema::Retrieve for DenyRetrieval {
    fn retrieve(
        &self,
        _uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn core::error::Error + Send + Sync>> {
        Err(Box::new(Failure::from(Kind::Configuration)))
    }
}

/// Check the identifier and public discovery metadata.
///
/// # Errors
/// Rejects invalid text, a permission other than `read` or `write`, safety
/// that does not match the permission, a write operation without a title and
/// write hints, invalid stability values and documentation URLs outside the
/// accepted HTTPS contract.
fn validate_operation(operation: &Operation) -> Result<(), Failure> {
    let info = &operation.info;
    let write = info.permission == WRITE_SCOPE;
    let effects_match = if write {
        info.safety == "write"
            && info.title.is_some()
            && info.hints.is_some_and(|hints| !hints.read_only_hint)
    } else {
        info.permission == READ_SCOPE
            && info.safety == "read_only"
            && info
                .hints
                .is_none_or(|hints| hints.read_only_hint && !hints.destructive_hint)
    };
    if !effects_match
        || info
            .title
            .as_deref()
            .is_some_and(|title| !valid_text(title) || title.len() > 64)
    {
        return Err(Kind::Configuration.into());
    }
    if !valid_id(&operation.id)
        || [
            &info.summary,
            &info.permission,
            &info.documentation,
            &info.stability,
            &info.cost,
            &info.safety,
        ]
        .iter()
        .any(|text| !valid_text(text))
        || !matches!(
            info.stability.as_str(),
            "experimental" | "stable" | "deprecated"
        )
    {
        return Err(Kind::Configuration.into());
    }
    let mut url =
        url::Url::parse(&info.documentation).map_err(Failure::redact(Kind::Configuration))?;
    url.set_fragment(None);
    drop(crate::upstream::canonical_https(url.as_str())?);
    Ok(())
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_id(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    if value.len() > 128 || parts.len() < 3 {
        return false;
    }
    let Some(version) = parts.last().and_then(|part| part.strip_prefix('v')) else {
        return false;
    };
    !version.starts_with('0')
        && !version.is_empty()
        && version.bytes().all(|byte| byte.is_ascii_digit())
        && parts
            .iter()
            .take(parts.len().saturating_sub(1))
            .all(|part| {
                part.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                    && part.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    })
            })
}
