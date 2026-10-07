//! Operation selection follows the advertised string contract before lookup.

use alloc::collections::BTreeMap;
use core::sync::atomic::Ordering;
use std::io;

use axum::http::StatusCode;
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
    let (code, action) = if valid {
        ("unknown_operation", "search_operations")
    } else {
        ("invalid_input", "review_input_contract")
    };
    assert_eq!(
        reply.pointer("/result/structuredContent/error"),
        Some(&json!({"code":code,"next_action":action,"retry_after_ms":null}))
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
