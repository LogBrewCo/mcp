//! Immutable, verified operation discovery and declared JSON Schema contracts.

use alloc::{collections::BTreeMap, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::{
    Failure, INPUT_BYTES, OUTPUT_BYTES, error::Kind, json as strict_json, upstream::WRITE_SCOPE,
};

mod contracts;

use contracts::{compile_entries, decode_operations, discovery_order, optional_text, problems, validate};

const CATALOG_BYTES: usize = 8 << 20;
const SCHEMA_BYTES: usize = 256 << 10;

/// Public operation semantics, independent of the caller's authorization.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationInfo {
    /// Public operation purpose.
    pub summary: String,
    /// Required delegated scope, not a grant of access: `read`, or `write`
    /// for an operation that changes data.
    pub permission: String,
    /// Public documentation URL.
    pub documentation: String,
    /// Experimental, stable, or deprecated status.
    pub stability: String,
    /// Public cost description.
    pub cost: String,
    /// Operation semantics: `read_only`, or `write` with the `write` permission.
    pub safety: String,
    /// Human-readable title. Required for write operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Behavior hints with MCP tool annotation names. Required for write operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hints: Option<OperationHints>,
}

/// Behavior hints for one operation, named like MCP tool annotations.
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OperationHints {
    /// The operation changes nothing.
    pub read_only_hint: bool,
    /// The operation may delete or overwrite data.
    pub destructive_hint: bool,
    /// Repeating the operation with the same input has no further effect.
    pub idempotent_hint: bool,
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

/// One input field that fails its operation's contract, named for the caller that sent it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FieldProblem {
    /// JSON Pointer to the field inside the operation input.
    pub field: String,
    /// `unknown_field`, `missing`, `wrong_type` or `invalid_value`.
    pub problem: &'static str,
}

struct Entry {
    operation: Operation,
    input: jsonschema::Validator,
    output: jsonschema::Validator,
}

/// Catalog definitions and compiled validators cannot change while serving.
pub struct Catalog {
    entries: BTreeMap<String, Entry>,
    /// Discovery order: families by name, each newest version first, with
    /// whether the operation is its family's newest version.
    order: Vec<(String, bool)>,
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
            use core::fmt::Write as _;
            write!(digest, "{byte:02x}").map_err(Failure::redact(Kind::Configuration))?;
        }
        let order = discovery_order(entries.keys());
        Ok(Arc::new(Self {
            entries,
            order,
            digest,
        }))
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

    /// Whether any operation writes, and whether any may delete or overwrite data.
    pub(crate) fn effects(&self) -> (bool, bool) {
        self.entries
            .values()
            .filter_map(|entry| entry.operation.info.hints)
            .fold((false, false), |(writes, destroys), hints| {
                (
                    writes || !hints.read_only_hint,
                    destroys || hints.destructive_hint,
                )
            })
    }

    /// Return one exact definition or a small deterministic discovery page.
    /// A page lists each family's newest version first and hides older versions
    /// unless `all_versions` is true or a query word names a version, such as `v5`.
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
            let entry = self.selected(id)?;
            return serde_json::to_value(&entry.operation)
                .map_err(Failure::redact(Kind::Unavailable));
        }
        if fields
            .keys()
            .any(|key| !matches!(key.as_str(), "query" | "after" | "limit" | "all_versions"))
        {
            return Err(Kind::InvalidInput.into());
        }
        let query = optional_text(fields.get("query"))?;
        let all_versions = match fields.get("all_versions") {
            None => false,
            Some(value) => value.as_bool().ok_or(Kind::InvalidInput)?,
        };
        let after = optional_text(fields.get("after"))?;
        let limit = fields.get("limit").map_or(Ok(10), |value| {
            strict_json::unsigned_integer(value).ok_or(Kind::InvalidInput)
        })?;
        if query.chars().take(257).count() > 256 || !(1..=10).contains(&limit) {
            return Err(Kind::InvalidInput.into());
        }
        let start = if after.is_empty() {
            0
        } else {
            self.order
                .iter()
                .position(|(id, _)| id == after)
                .ok_or(Kind::InvalidInput)?
                .saturating_add(1)
        };
        let words: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
        let every_version = all_versions || words.iter().any(|word| names_version(word));
        let mut matches = self
            .order
            .iter()
            .skip(start)
            .filter(|(_, newest)| every_version || *newest)
            .filter_map(|(id, _)| self.entries.get(id))
            .filter(|entry| {
                let text = format!("{} {}", entry.operation.id, entry.operation.info.summary)
                    .to_lowercase();
                words.iter().all(|word| text.contains(word))
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

    /// Whether a known operation needs the `write` scope.
    pub(crate) fn needs_write(&self, id: &str) -> bool {
        self.entries
            .get(id)
            .is_some_and(|entry| entry.operation.info.permission == WRITE_SCOPE)
    }

    /// Validate the operation before any upstream request.
    ///
    /// # Errors
    /// Rejects unknown operations or input outside the declared contract and budget.
    pub fn input(&self, id: &str, value: &Value) -> Result<(), Failure> {
        let entry = self.selected(id)?;
        validate(&entry.input, value, INPUT_BYTES).map_err(Failure::redact(Kind::InvalidInput))
    }

    /// Name the input fields of execute `arguments` that fail the selected
    /// operation's input contract, at most 8. Empty for an unknown operation or
    /// input that meets its contract.
    #[must_use]
    pub fn input_problems(&self, arguments: &Value) -> Vec<FieldProblem> {
        let entry = arguments
            .get("operation")
            .and_then(Value::as_str)
            .and_then(|id| self.entries.get(id));
        match (entry, arguments.get("input")) {
            (Some(entry), Some(input)) => problems(&entry.input, input),
            _ => Vec::new(),
        }
    }

    /// Validate output before returning evidence to the caller.
    ///
    /// # Errors
    /// Rejects invalid identifiers, absent operations or invalid, oversized output.
    pub fn output(&self, id: &str, value: &Value) -> Result<(), Failure> {
        let entry = self.selected(id)?;
        validate(&entry.output, value, OUTPUT_BYTES).map_err(Failure::redact(Kind::InvalidOutput))
    }

    /// Select an exact identifier after checking the caller's string contract.
    ///
    /// # Errors
    /// Rejects identifiers outside the tool schema or absent from the catalog.
    fn selected(&self, id: &str) -> Result<&Entry, Failure> {
        if id.is_empty() || id.chars().take(129).count() > 128 {
            return Err(Kind::InvalidInput.into());
        }
        self.entries
            .get(id)
            .ok_or_else(|| Kind::UnknownOperation.into())
    }
}

/// Whether a query word names an operation version, such as `v5` or `issues.list.v5`.
fn names_version(word: &str) -> bool {
    let last = word.rsplit('.').next().unwrap_or(word);
    last.strip_prefix('v').is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}
