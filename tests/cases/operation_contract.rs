//! Operation selection follows the advertised string contract before lookup.

use alloc::collections::BTreeMap;
use core::sync::atomic::Ordering;
use std::io;

use axum::http::StatusCode;
use logbrew_mcp::error::Kind;
use serde_json::{Value, json};

use super::http::{Fixture, TOKEN};

type TestResult<T> = Result<T, Box<dyn core::error::Error + Send + Sync>>;

/// # Errors
///
/// Returns discovery, schema compilation or missing-schema errors.
async fn schema(fixture: &Fixture, name: &str) -> TestResult<jsonschema::Validator> {
    let (status, reply) = fixture.request("tools/list", json!({}), TOKEN).await?;
    if status != StatusCode::OK {
        return Err(io::Error::other("tool inventory failed").into());
    }
    let advertised = reply
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .and_then(|tools| {
            tools
                .iter()
                .find(|tool| tool.get("name").and_then(Value::as_str) == Some(name))
        })
        .and_then(|tool| tool.get("inputSchema"))
        .ok_or_else(|| io::Error::other("missing advertised input schema"))?;
    Ok(jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(advertised)?)
}

fn arguments(name: &str, operation: &Value) -> Value {
    if name == "execute" {
        json!({"operation":operation,"input":{}})
    } else {
        json!({"operation":operation})
    }
}

/// # Errors
///
/// Returns request errors or absent or invalid encoded result content.
async fn rejected(
    fixture: &Fixture,
    name: &str,
    input: Value,
) -> TestResult<(StatusCode, Value, Value)> {
    let (status, reply) = fixture
        .request("tools/call", json!({"name":name,"arguments":input}), TOKEN)
        .await?;
    let text = reply
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::other("missing text result"))?;
    let encoded = serde_json::from_str(text)?;
    Ok((status, reply, encoded))
}

/// # Panics
///
/// Panics if error classification, privacy or result encoding changes.
fn check_rejected(response: &(StatusCode, Value, Value), valid: bool) {
    let reply = &response.1;
    assert_eq!(response.0, StatusCode::OK);
    assert_eq!(reply.pointer("/result/isError"), Some(&json!(true)));
    assert_eq!(
        reply.pointer("/result/structuredContent/data"),
        Some(&Value::Null)
    );
    let kind = if valid {
        Kind::UnknownOperation
    } else {
        Kind::InvalidInput
    };
    assert_eq!(
        reply.pointer("/result/structuredContent/error"),
        Some(&json!({"code":kind.code(),"next_action":kind.next_action(),
            "message":kind.message(),"retry_after_ms":null}))
    );
    assert_eq!(
        Some(&response.2),
        reply.pointer("/result/structuredContent")
    );
    assert!(reply.to_string().len() < 1024);
    assert!(!reply.to_string().contains("SYNTHETIC_PRIVATE_MARKER"));
}

fn selections(cases: Vec<(Value, bool)>) -> Vec<(&'static str, Value, bool)> {
    let mut selected = Vec::new();
    for (operation, valid) in cases {
        selected.push(("search", operation.clone(), valid));
        selected.push(("execute", operation, valid));
    }
    selected
}

#[tokio::test]
/// # Panics
///
/// Panics if identifier bounds or exact matching disagree with either tool's
/// schema, rejected selections start execution, or known operations fail.
async fn operation_identifiers_match_schema_bounds_and_remain_exact() {
    let fixture = Fixture::new().await.expect("fixture");
    let validators = BTreeMap::from([
        (
            "search",
            schema(&fixture, "search").await.expect("search schema"),
        ),
        (
            "execute",
            schema(&fixture, "execute").await.expect("execute schema"),
        ),
    ]);
    let cases = [
        (String::new(), false),
        ("a".repeat(129), false),
        ("\u{1f980}".repeat(129), false),
        ("e\u{301}".repeat(65), false),
        ("a".to_owned(), true),
        ("a".repeat(128), true),
        ("\u{1f980}".repeat(128), true),
        ("e\u{301}".repeat(64), true),
        (" logs.read.v1 ".to_owned(), true),
        ("LOGS.READ.V1".to_owned(), true),
        ("SYNTHETIC_PRIVATE_MARKER".to_owned(), true),
    ]
    .map(|(id, valid)| (json!(id), valid))
    .to_vec();
    for (name, operation, valid) in selections(cases) {
        let validator = validators.get(name).expect("tool schema");
        let input = arguments(name, &operation);
        assert_eq!(validator.is_valid(&input), valid);
        let response = rejected(&fixture, name, input).await.expect("selection");
        check_rejected(&response, valid);
    }
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
    for name in ["search", "execute"] {
        let (status, reply) = fixture
            .request(
                "tools/call",
                json!({"name":name,"arguments":arguments(name, &json!("logs.read.v1"))}),
                TOKEN,
            )
            .await
            .expect("known operation");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            reply.pointer("/result/structuredContent/error"),
            Some(&Value::Null)
        );
        assert!(
            reply
                .pointer("/result/structuredContent/data")
                .is_some_and(|data| !data.is_null())
        );
    }
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 1);
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 26);
}

#[tokio::test]
/// # Panics
///
/// Panics if a nonstring identifier passes a tool schema or reaches execution.
async fn nonstring_operation_identifiers_are_input_errors() {
    let fixture = Fixture::new().await.expect("fixture");
    let validators = BTreeMap::from([
        (
            "search",
            schema(&fixture, "search").await.expect("search schema"),
        ),
        (
            "execute",
            schema(&fixture, "execute").await.expect("execute schema"),
        ),
    ]);
    let cases = [json!(null), json!(true), json!(1_i32), json!({}), json!([])]
        .map(|operation| (operation, false))
        .to_vec();
    for (name, operation, valid) in selections(cases) {
        let validator = validators.get(name).expect("tool schema");
        let input = arguments(name, &operation);
        assert!(!validator.is_valid(&input));
        let response = rejected(&fixture, name, input).await.expect("selection");
        check_rejected(&response, valid);
    }
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 12);
}

#[tokio::test]
/// # Panics
///
/// Panics if a tool input schema has a top-level combinator, which clients that
/// pass tool schemas to a model can reject (they then drop the tool), or if search
/// accepts arguments outside its two forms.
async fn tool_input_schemas_have_no_top_level_combinators() {
    let fixture = Fixture::new().await.expect("fixture");
    let (status, reply) = fixture
        .request("tools/list", json!({}), TOKEN)
        .await
        .expect("tool inventory");
    assert_eq!(status, StatusCode::OK);
    let tools = reply
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .expect("tools");
    assert_eq!(tools.len(), 2);
    for tool in tools {
        let schema = tool
            .get("inputSchema")
            .and_then(Value::as_object)
            .expect("input schema");
        assert_eq!(schema.get("type"), Some(&json!("object")));
        let combinators: Vec<_> = ["oneOf", "anyOf", "allOf", "not", "if", "enum", "const"]
            .into_iter()
            .filter(|keyword| schema.contains_key(*keyword))
            .collect();
        assert!(combinators.is_empty(), "top-level {combinators:?}");
    }
    for arguments in [
        json!({"operation":"logs.read.v1","query":"logs"}),
        json!({"operation":"logs.read.v1","after":"logs.read.v1"}),
        json!({"operation":"logs.read.v1","limit":1_i32}),
        json!({"operation":"logs.read.v1","output_schema":"true"}),
        json!({"query":"logs","output_schema":true}),
    ] {
        let response = rejected(&fixture, "search", arguments)
            .await
            .expect("search");
        check_rejected(&response, false);
    }
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
}

#[tokio::test]
/// # Panics
///
/// Panics if an input error stops naming its failing fields, returns a field
/// name outside the safe character set, or reaches the upstream API.
async fn input_errors_name_each_failing_field() {
    let fixture = Fixture::new().await.expect("fixture");
    let input = json!({"context":"text","unexpected":1_i32,"bad key/~":2_i32});
    let response = rejected(
        &fixture,
        "execute",
        json!({"operation":"logs.read.v1","input":input}),
    )
    .await
    .expect("execute");
    assert_eq!(
        response.1.pointer("/result/structuredContent/error/code"),
        Some(&json!("invalid_input"))
    );
    assert_eq!(
        Some(&response.2),
        response.1.pointer("/result/structuredContent")
    );
    assert_eq!(
        response.1.pointer("/result/structuredContent/error/fields"),
        Some(&json!([
            {"field":"/context","problem":"wrong_type"},
            {"field":"/unexpected","problem":"unknown_field"}
        ]))
    );
    let listed = rejected(
        &fixture,
        "execute",
        json!({"operation":"logs.read.v1","input":[]}),
    )
    .await
    .expect("execute");
    assert_eq!(
        listed.1.pointer("/result/structuredContent/error/fields"),
        Some(&json!([{"field":"","problem":"wrong_type"}]))
    );
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
}
