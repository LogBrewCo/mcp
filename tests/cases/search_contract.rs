//! Discovery accepts its advertised Unicode and exact integer input contract.

use std::{io, sync::atomic::Ordering};

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::http::{Fixture, TOKEN};

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

async fn schema(fixture: &Fixture) -> TestResult<jsonschema::Validator> {
    let (status, reply) = fixture.request("tools/list", json!({}), TOKEN).await?;
    assert_eq!(status, StatusCode::OK);
    let schema = reply
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .and_then(|tools| {
            tools
                .iter()
                .find(|tool| tool.get("name") == Some(&json!("search")))
        })
        .and_then(|tool| tool.get("inputSchema"))
        .ok_or_else(|| io::Error::other("missing advertised search schema"))?;
    Ok(jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .build(schema)?)
}

async fn search(fixture: &Fixture, arguments: Value, valid: bool) -> TestResult<Value> {
    let description = arguments.to_string();
    let (status, reply) = fixture
        .request(
            "tools/call",
            json!({"name":"search","arguments":arguments}),
            TOKEN,
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(!reply.to_string().contains("SYNTHETIC_"));
    if valid {
        assert_eq!(
            reply.pointer("/result/structuredContent/error"),
            Some(&Value::Null),
            "arguments {description}"
        );
        reply
            .pointer("/result/structuredContent/data")
            .cloned()
            .ok_or_else(|| io::Error::other("missing search data").into())
    } else {
        assert_eq!(
            reply.pointer("/result/structuredContent/data"),
            Some(&Value::Null),
            "arguments {description}"
        );
        assert_eq!(
            reply.pointer("/result/structuredContent/error/code"),
            Some(&json!("invalid_input"))
        );
        assert_eq!(
            reply.pointer("/result/structuredContent/error/next_action"),
            Some(&json!("review_input_contract"))
        );
        Ok(Value::Null)
    }
}

#[tokio::test]
async fn unicode_queries_use_the_advertised_character_limit() -> TestResult<()> {
    let fixture = Fixture::new().await?;
    let validator = schema(&fixture).await?;
    let queries = [
        "a".repeat(256),
        "\u{e9}".repeat(256),
        "\u{1f980}".repeat(256),
        "e\u{301}".repeat(128),
    ];
    for query in queries {
        assert_eq!(query.chars().count(), 256);
        let arguments = json!({"query":query});
        assert!(validator.is_valid(&arguments));
        let data = search(&fixture, arguments, true).await?;
        assert_eq!(data.get("operations"), Some(&json!([])));
    }
    for query in [
        "a".repeat(257),
        "\u{e9}".repeat(257),
        "\u{1f980}".repeat(257),
        "e\u{301}".repeat(129),
    ] {
        let arguments = json!({"query":query});
        assert!(!validator.is_valid(&arguments));
        drop(search(&fixture, arguments, false).await?);
    }
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 9);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn valid_query_whitespace_and_control_characters_keep_their_search_meaning() -> TestResult<()>
{
    let fixture = Fixture::new().await?;
    let validator = schema(&fixture).await?;
    for (query, matches) in [
        (" logs ", true),
        ("\tread\nlogs\r", true),
        ("\u{2003}READ\u{a0}logs\u{2003}", true),
        ("\t\n", true),
        ("", true),
        ("\0", false),
        ("logs\0", false),
    ] {
        let arguments = json!({"query":query});
        assert!(validator.is_valid(&arguments));
        let data = search(&fixture, arguments, true).await?;
        let ids: Vec<_> = data
            .get("operations")
            .and_then(Value::as_array)
            .ok_or_else(|| io::Error::other("missing operations"))?
            .iter()
            .filter_map(|operation| operation.get("id").and_then(Value::as_str))
            .collect();
        assert_eq!(
            ids,
            if matches {
                vec!["logs.read.v1"]
            } else {
                vec![]
            }
        );
    }
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 8);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn exact_integral_limit_representations_match_the_advertised_schema() -> TestResult<()> {
    let fixture = Fixture::new().await?;
    let validator = schema(&fixture).await?;
    for raw in [
        "1",
        "10",
        "1.0",
        "10.000",
        "1e1",
        "100e-1",
        "0.01e3",
        "1.000000000000000000000000000000",
        "100000000000000000000000000000000000000000000000000000000000e-59",
        "100000000000000000000000000000000000000000000000000000000000e-58",
    ] {
        let limit: Value = serde_json::from_str(raw)?;
        let arguments = json!({"query":"logs","limit":limit});
        assert!(validator.is_valid(&arguments), "limit {raw}");
        let data = search(&fixture, arguments, true).await?;
        assert_eq!(
            data.get("operations")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );
    }
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 11);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn fractional_and_out_of_range_limits_cannot_round_into_an_accepted_page() -> TestResult<()> {
    let fixture = Fixture::new().await?;
    let validator = schema(&fixture).await?;
    for raw in [
        "0",
        "11",
        "-1",
        "1e1024",
        "1e-1024",
        "0e-1024",
        "1.5",
        "1.000000000000000000000000000000000000000000000000000000001",
        "9.999999999999999999999999999999999999999999999999999999999",
        "10.000000000000000000000000000000000000000000000000000000001",
    ] {
        let limit: Value = serde_json::from_str(raw)?;
        let arguments = json!({"query":"logs","limit":limit});
        assert!(!validator.is_valid(&arguments), "limit {raw}");
        drop(search(&fixture, arguments, false).await?);
    }
    for limit in [
        json!("1"),
        json!(true),
        Value::Null,
        json!([1_i32]),
        json!({"$serde_json::private::Number":"1"}),
        json!({"$serde_json::private::RawValue":"1"}),
    ] {
        let arguments = json!({"query":"logs","limit":limit});
        assert!(!validator.is_valid(&arguments));
        drop(search(&fixture, arguments, false).await?);
    }
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 17);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

fn catalog() -> TestResult<Vec<u8>> {
    let operations: Vec<_> = (1_i32..=23_i32)
        .map(|version| {
            let summary = if version % 2_i32 == 1_i32 {
                "Read selected \u{63}\u{61}\u{66}\u{e9} logs"
            } else {
                "Read unrelated traces"
            };
            json!({"id":format!("signals.read.v{version}"), "info":{"summary":summary,
            "permission":"logs:read","documentation":"https://docs.example/logs",
            "stability":"stable","cost":"one read","safety":"read_only"},
            "input_schema":{"type":"object"},"output_schema":{"type":"object"}})
        })
        .collect();
    Ok(serde_json::to_vec(
        &json!({"format_version":1,"operations":operations}),
    )?)
}

#[tokio::test]
async fn filtered_pages_preserve_every_matching_contract_once_and_keep_the_limit() -> TestResult<()>
{
    let fixture = Fixture::with_catalog(catalog()?).await?;
    let validator = schema(&fixture).await?;
    let mut expected: Vec<_> = (1_i32..=23_i32)
        .filter(|version| version % 2_i32 == 1_i32)
        .map(|version| format!("signals.read.v{version}"))
        .collect();
    expected.sort_unstable();
    for raw in ["1", "4", "10", "1.0", "4.000", "1e1"] {
        let limit: Value = serde_json::from_str(raw)?;
        let maximum = match raw {
            "1" | "1.0" => 1,
            "4" | "4.000" => 4,
            _ => 10,
        };
        let collected =
            collected_pages(&fixture, &validator, &limit, maximum, expected.len()).await?;
        assert_eq!(collected, expected);
    }
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

async fn collected_pages(
    fixture: &Fixture,
    validator: &jsonschema::Validator,
    limit: &Value,
    maximum: usize,
    expected: usize,
) -> TestResult<Vec<String>> {
    let mut cursor = String::new();
    let mut collected = Vec::new();
    for _ in 0..=expected {
        let arguments =
            json!({"query":" \u{43}\u{41}\u{46}\u{c9}\tselected\n", "limit":limit, "after":cursor});
        assert!(validator.is_valid(&arguments));
        let data = search(fixture, arguments, true).await?;
        let page = data
            .get("operations")
            .and_then(Value::as_array)
            .ok_or_else(|| io::Error::other("missing page"))?;
        assert!(!page.is_empty() && page.len() <= maximum);
        for operation in page {
            assert!(operation.get("input_schema").is_none());
            let id = operation
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| io::Error::other("missing operation ID"))?;
            collected.push(id.to_owned());
        }
        data.get("next_cursor")
            .and_then(Value::as_str)
            .ok_or_else(|| io::Error::other("missing cursor"))?
            .clone_into(&mut cursor);
        if cursor.is_empty() {
            break;
        }
        assert_eq!(collected.last().map(String::as_str), Some(cursor.as_str()));
    }
    assert_eq!(cursor, "");
    Ok(collected)
}
