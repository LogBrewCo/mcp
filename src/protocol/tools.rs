//! The two tool definitions, their shared result schema and result envelope.

use alloc::sync::Arc;

use rmcp::model::{CallToolResult, Tool, ToolAnnotations};
use serde_json::{Value, json};

use crate::{ENVELOPE_BYTES, Failure, catalog::FieldProblem, error::Kind};

/// `fields` names the input fields that failed their contract; an error lists
/// them only when there are any.
pub(super) fn envelope(
    result: Result<Value, Failure>,
    fields: &[FieldProblem],
    provenance: Option<&Value>,
) -> CallToolResult {
    let (data, error) = match result {
        Ok(data) => (data, Value::Null),
        Err(failure) => (Value::Null, error(failure, fields)),
    };
    let value = json!({"data":data,"error":error,"provenance":provenance});
    if value.to_string().len() > ENVELOPE_BYTES {
        return CallToolResult::structured_error(json!({"data":null,"provenance":null,
            "error":{"code":"unavailable","next_action":"check_operation_status",
                "message":Kind::Unavailable.message(),"retry_after_ms":null}}));
    }
    if value.get("error").is_some_and(Value::is_null) {
        CallToolResult::structured(value)
    } else {
        CallToolResult::structured_error(value)
    }
}

/// The error object, with `fields` only when there are any.
fn error(failure: Failure, fields: &[FieldProblem]) -> Value {
    let mut error = serde_json::Map::new();
    for (name, value) in [
        ("code", json!(failure.kind.code())),
        ("next_action", json!(failure.kind.next_action())),
        ("message", json!(failure.kind.message())),
        ("retry_after_ms", json!(failure.retry_after_ms)),
    ] {
        let _previous: Option<Value> = error.insert(name.to_owned(), value);
    }
    if !fields.is_empty() {
        let listed = fields
            .iter()
            .map(|field| json!({"field":field.field,"problem":field.problem}))
            .collect();
        let _previous: Option<Value> = error.insert("fields".to_owned(), listed);
    }
    Value::Object(error)
}

/// One tool definition. `effects` says whether any catalog operation writes,
/// and whether any may delete or overwrite data; `execute` declares them.
pub(super) fn definition(name: &str, (writes, destroys): (bool, bool)) -> Tool {
    let (title, description, schema) = if name == "search" {
        (
            "Search LogBrew Operations",
            "Find the LogBrew operations that execute runs. Use this before execute; it never \
             changes data. Send query, with optional after and limit, to list matching \
             operations with their summary, permission, safety, cost and stability; leave \
             query out to list all of them. Send operation to get one operation's contract with \
             its input_schema; add output_schema: true to get its output_schema too.",
            // No top-level oneOf, anyOf or allOf: some clients drop tools whose input
            // schema has them. The search handler enforces the two argument forms.
            json!({"type":"object","additionalProperties":false,
            "properties":{"operation":{"type":"string","minLength":1_u32,"maxLength":128_u32,
                    "description":"Exact operation name. Returns its contract with its input_schema. Send no other field with it except output_schema."},
                "output_schema":{"type":"boolean",
                    "description":"With operation only: true also returns the operation's output_schema. Defaults to false."},
                "query":{"type":"string","maxLength":256_u32,
                    "description":"Words to find in operation names and summaries, ignoring case. Every word must match; leave it out or send empty text to list all operations."},
                "after":{"type":"string","maxLength":128_u32,
                    "description":"next_cursor from the previous page. Leave out for the first page; an empty next_cursor means the last page."},
                "limit":{"type":"integer","minimum":1_u32,"maximum":10_u32,
                    "description":"Operations per page, from 1 to 10. Defaults to 10."},
                "all_versions":{"type":"boolean",
                    "description":"true lists every version of each operation, newest first. Defaults to false: a page lists only the newest version, unless a query word names a version such as v5."}}}),
        )
    } else {
        (
            "Run a LogBrew Operation",
            "Run one LogBrew operation that search returned. Call search first for the operation \
             name and its input contract, then send that name as operation and a matching object \
             as input. Read operations return projects, issues, logs, traces, spans, metrics, \
             releases and product analytics. A connection reads only the projects approved for \
             it: run the projects list operation first and send one of its ids as project_id, \
             or, where project_id is optional, leave project_id out to read all of them. Write \
             operations (resolve, reopen, archive, prioritize or assign issues, create projects \
             or keys, revoke keys, send a test event, load or remove sample data) need the write \
             scope, which a project read key never has, and act as the signed-in user within that \
             user's permissions. When a write operation answers that the connection lacks the \
             write scope, do not retry it: ask the user to reconnect LogBrew and allow changes. \
             Archiving, key revocation and sample-data removal change nothing \
             until a second call sends, within 5 minutes, the confirmation the first call \
             returned. Repeating an issue change, a revocation or a sample-data change gives the \
             same result. A create repeats safely only with the same idempotency_key, and each \
             test event call sends a new event. Returns data and provenance, or an error with a \
             stable code, next_action, a message that says how to fix the call, and \
             retry_after_ms.",
            json!({"type":"object","additionalProperties":false,
            "required":["operation","input"],"properties":{"operation":{"type":"string","minLength":1_u32,"maxLength":128_u32,
                    "description":"Operation name exactly as search returned it."},
                "input":{"type":"object",
                    "description":"Arguments matching that operation's input_schema from search; {} when it takes none."}}}),
        )
    };
    let object = schema.as_object().cloned().unwrap_or_default();
    // search only reads; execute writes when the catalog has write operations.
    let annotations = ToolAnnotations::with_title(title).open_world(false);
    let annotations = if name == "execute" && writes {
        annotations
            .read_only(false)
            .destructive(destroys)
            .idempotent(false)
    } else {
        annotations.read_only(true)
    };
    Tool::new(name.to_owned(), description, Arc::new(object))
        .with_title(title)
        .with_raw_output_schema(Arc::new(
            output_schema().as_object().cloned().unwrap_or_default(),
        ))
        .with_annotations(annotations)
}

fn output_schema() -> Value {
    let errors: Vec<_> = [
        Kind::Configuration,
        Kind::UnknownOperation,
        Kind::Unauthorized,
        Kind::PermissionDenied,
        Kind::InvalidInput,
        Kind::InvalidOutput,
        Kind::Throttled,
        Kind::NotFound,
        Kind::Unavailable,
    ]
    .into_iter()
    .map(|kind| {
        json!({"properties":{"code":{"const":kind.code()},
        "next_action":{"const":kind.next_action()},"message":{"const":kind.message()}}})
    })
    .collect();
    json!({"$schema":"https://json-schema.org/draft/2020-12/schema",
        "type":"object","required":["data","error","provenance"],"additionalProperties":false,
        "properties":{"data":{},"error":{},"provenance":{}},
    "$defs":{
        "provenance":{"type":"object","required":["definition_sha256"],"additionalProperties":false,
            "properties":{"definition_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}}},
        "error":{"type":"object","required":["code","next_action","message","retry_after_ms"],
            "additionalProperties":false,"properties":{"code":{"type":"string"},
                "next_action":{"type":"string"},"message":{"type":"string"},
                "retry_after_ms":{"type":["integer","null"],
                        "minimum":0,"maximum":2_147_483_647_000_u64},
                "fields":{"type":"array","minItems":1,"maxItems":8,"items":{"type":"object",
                    "required":["field","problem"],"additionalProperties":false,
                    "properties":{"field":{"type":"string"},"problem":{"enum":
                        ["unknown_field","missing","wrong_type","invalid_value"]}}}}},
            "oneOf":errors}
    },
    "oneOf":[
        {"properties":{"data":{"type":"object"},"error":{"type":"null"},
            "provenance":{"$ref":"#/$defs/provenance"}}},
        {"properties":{"data":{"type":"null"},"error":{"$ref":"#/$defs/error"},
            "provenance":{"anyOf":[{"$ref":"#/$defs/provenance"},{"type":"null"}]}}}
    ]})
}
