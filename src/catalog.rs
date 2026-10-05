//! Immutable, verified operation discovery and declared JSON Schema contracts.

use std::{collections::BTreeMap, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::{Failure, INPUT_BYTES, OUTPUT_BYTES, error::Kind, json as strict_json};

const CATALOG_BYTES: usize = 8 << 20;
const SCHEMA_BYTES: usize = 256 << 10;

/// Public operation semantics, independent of the caller's authorization.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationInfo {
    /// Public operation purpose.
    pub summary: String,
    /// Required permission, not a grant of access.
    pub permission: String,
    /// Public documentation URL.
    pub documentation: String,
    /// Experimental, stable, or deprecated status.
    pub stability: String,
    /// Public cost description.
    pub cost: String,
    /// Read-only, write, or destructive semantics.
    pub safety: String,
}

/// One versioned operation and its self-contained schemas.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    /// Stable versioned operation identifier.
    pub id: String,
    /// Public semantics and requirements.
    pub info: OperationInfo,
    /// Object-rooted input schema.
    pub input_schema: Value,
    /// Object-rooted output schema.
    pub output_schema: Value,
}

struct Entry {
    operation: Operation,
    input: jsonschema::Validator,
    output: jsonschema::Validator,
}

/// Catalog definitions and compiled validators cannot change while serving.
pub struct Catalog {
    entries: BTreeMap<String, Entry>,
    digest: String,
}

impl Catalog {
    /// Check artifact integrity and compile bounded schemas without file or HTTP loading.
    /// Schemas default to 2020-12. Declared drafts 4, 6, 7, 2019-09 and 2020-12
    /// use their own semantics; unsupported declarations are rejected.
    ///
    /// # Errors
    /// Rejects an invalid digest, artifact, metadata, or schema.
    pub fn load(bytes: &[u8], expected: &[u8; 32]) -> Result<Arc<Self>, Failure> {
        if bytes.len() > CATALOG_BYTES || Sha256::digest(bytes).as_slice() != expected {
            return Err(Kind::Configuration.into());
        }
        let value = strict_json::object(bytes, CATALOG_BYTES)
            .map_err(Failure::redact(Kind::Configuration))?;
        let entries = compile_entries(decode_operations(&value)?)?;
        let definitions: Vec<&Operation> = entries.values().map(|entry| &entry.operation).collect();
        let encoded = serde_json::to_vec(&json!({"operations":definitions,"format_version":1_u32}))
            .map_err(Failure::redact(Kind::Configuration))?;
        let mut digest = String::with_capacity(64);
        for byte in Sha256::digest(encoded) {
            use std::fmt::Write as _;
            write!(digest, "{byte:02x}").map_err(Failure::redact(Kind::Configuration))?;
        }
        Ok(Arc::new(Self { entries, digest }))
    }

    /// Definition digest, distinct from artifact integrity and telemetry freshness.
    #[must_use]
    pub fn provenance(&self) -> Value {
        json!({"definition_sha256":self.digest})
    }

    pub(crate) fn operation_ids(&self) -> impl ExactSizeIterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    pub(crate) fn definition_digest(&self) -> &str {
        &self.digest
    }

    /// Return one exact definition or a small deterministic discovery page.
    ///
    /// # Errors
    /// Rejects invalid search arguments, cursors, or unknown selected operations.
    pub fn search(&self, arguments: &Value) -> Result<Value, Failure> {
        let fields = arguments.as_object().ok_or(Kind::InvalidInput)?;
        if fields.contains_key("operation") && fields.len() != 1 {
            return Err(Kind::InvalidInput.into());
        }
        if fields.contains_key("operation") {
            let id = arguments
                .get("operation")
                .and_then(Value::as_str)
                .ok_or(Kind::InvalidInput)?;
            let entry = self.entries.get(id).ok_or(Kind::UnknownOperation)?;
            return serde_json::to_value(&entry.operation)
                .map_err(Failure::redact(Kind::Unavailable));
        }
        if fields
            .keys()
            .any(|key| !matches!(key.as_str(), "query" | "after" | "limit"))
        {
            return Err(Kind::InvalidInput.into());
        }
        let query = fields
            .get("query")
            .and_then(Value::as_str)
            .ok_or(Kind::InvalidInput)?;
        let after = optional_text(fields.get("after"))?;
        let limit = fields.get("limit").map_or(Ok(10), |value| {
            strict_json::unsigned_integer(value).ok_or(Kind::InvalidInput)
        })?;
        if query.chars().take(257).count() > 256
            || !(1..=10).contains(&limit)
            || (!after.is_empty() && !self.entries.contains_key(after))
        {
            return Err(Kind::InvalidInput.into());
        }
        let words: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
        let mut matches = self.entries.values().filter(|entry| {
            let text =
                format!("{} {}", entry.operation.id, entry.operation.info.summary).to_lowercase();
            entry.operation.id.as_str() > after && words.iter().all(|word| text.contains(word))
        });
        let operations: Vec<Value> = matches
            .by_ref()
            .take(usize::try_from(limit).map_err(Failure::redact(Kind::InvalidInput))?)
            .map(|entry| json!({"id":entry.operation.id,"info":entry.operation.info}))
            .collect();
        let cursor = if matches.next().is_some() {
            operations
                .last()
                .and_then(|value| value.get("id"))
                .and_then(Value::as_str)
                .unwrap_or_default()
        } else {
            ""
        };
        Ok(json!({"operations":operations,"next_cursor":cursor}))
    }

    /// Validate the operation before any upstream request.
    ///
    /// # Errors
    /// Rejects unknown operations or input outside the declared contract and budget.
    pub fn input(&self, id: &str, value: &Value) -> Result<(), Failure> {
        let entry = self.entries.get(id).ok_or(Kind::UnknownOperation)?;
        validate(&entry.input, value, INPUT_BYTES).map_err(Failure::redact(Kind::InvalidInput))
    }

    /// Validate output before returning evidence to the caller.
    ///
    /// # Errors
    /// Rejects absent operations or invalid, oversized output.
    pub fn output(&self, id: &str, value: &Value) -> Result<(), Failure> {
        let entry = self.entries.get(id).ok_or(Kind::UnknownOperation)?;
        validate(&entry.output, value, OUTPUT_BYTES).map_err(Failure::redact(Kind::InvalidOutput))
    }
}

/// Compile validated operation contracts into a deterministic lookup.
///
/// # Errors
/// Rejects duplicate identifiers, invalid metadata or schemas that cannot be compiled.
fn compile_entries(operations: Vec<Operation>) -> Result<BTreeMap<String, Entry>, Failure> {
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
fn decode_operations(document: &Value) -> Result<Vec<Operation>, Failure> {
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
fn optional_text(value: Option<&Value>) -> Result<&str, Failure> {
    value.map_or(Ok(""), |value| {
        value.as_str().ok_or_else(|| Kind::InvalidInput.into())
    })
}

/// Check exact JSON and its declared schema within the supplied byte limit.
///
/// # Errors
/// Rejects encoding errors, invalid or out-of-budget JSON and schema violations.
fn validate(schema: &jsonschema::Validator, value: &Value, limit: usize) -> Result<(), Failure> {
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
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        Err(Box::new(Failure::from(Kind::Configuration)))
    }
}

/// Check the identifier and public discovery metadata.
///
/// # Errors
/// Rejects invalid text, permission tokens, stability or safety values and
/// documentation URLs outside the accepted HTTPS contract.
fn validate_operation(operation: &Operation) -> Result<(), Failure> {
    let info = &operation.info;
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
        || !crate::upstream::valid_token(&info.permission)
        || !matches!(
            info.stability.as_str(),
            "experimental" | "stable" | "deprecated"
        )
        || !matches!(info.safety.as_str(), "read_only" | "write" | "destructive")
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
