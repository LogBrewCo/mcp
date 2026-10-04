//! Protocol fixtures prove HTTP contracts, not compatibility with real clients.

#[path = "cases/authority.rs"]
mod authority;
#[path = "cases/authority_wire.rs"]
mod authority_wire;
#[path = "cases/authorization.rs"]
mod authorization;
#[path = "cases/bearer.rs"]
mod bearer;
#[path = "cases/clients.rs"]
mod clients;
#[path = "cases/headers.rs"]
mod headers;
#[path = "support/hpack.rs"]
mod hpack;
#[path = "support/http.rs"]
mod http;
#[path = "cases/http2.rs"]
mod http2;
#[path = "cases/http2_stalls.rs"]
mod http2_stalls;
#[path = "cases/identifiers.rs"]
mod identifiers;
#[path = "cases/lifecycle.rs"]
mod lifecycle;
#[path = "cases/methods.rs"]
mod methods;
#[path = "cases/notifications.rs"]
mod notifications;
#[path = "support/peer.rs"]
mod peer;
#[path = "support/raw_upstream.rs"]
mod raw_upstream;
#[path = "support/runtime.rs"]
mod runtime;
#[path = "cases/scopes.rs"]
mod scopes;
#[path = "cases/search_contract.rs"]
mod search_contract;
#[path = "cases/telemetry.rs"]
mod telemetry;
#[path = "cases/transport.rs"]
mod transport;
#[path = "cases/upstream_transport.rs"]
mod upstream_transport;

use std::sync::{Arc, atomic::Ordering};

use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use http::{Fixture, RESOURCE, TOKEN};

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn discovery_and_tool_inventory_are_self_contained() {
    let fixture = Fixture::new().await.expect("fixture");
    let (status, response) = fixture
        .request("server/discover", json!({}), TOKEN)
        .await
        .expect("discovery");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response.pointer("/result/capabilities"),
        Some(&json!({"tools":{}}))
    );
    assert_eq!(
        response.pointer("/result/resultType"),
        Some(&json!("complete"))
    );
    let (status, response) = fixture
        .request("tools/list", json!({}), TOKEN)
        .await
        .expect("inventory");
    assert_eq!(status, StatusCode::OK);
    let tools = response
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .expect("tool inventory");
    let names: Vec<_> = tools
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .collect();
    assert_eq!(names, ["search", "execute"]);
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn execution_carries_verified_identity_and_rechecks_revocation() {
    let fixture = Fixture::new().await.expect("fixture");
    let arguments = json!({"name":"execute","arguments":{"operation":"logs.read.v1","input":{}}});
    let (status, response) = fixture
        .request("tools/call", arguments.clone(), TOKEN)
        .await
        .expect("execution");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response.pointer("/result/structuredContent/data/count"),
        Some(&json!(3_i32))
    );
    assert_eq!(
        response.pointer("/result/structuredContent/error"),
        Some(&Value::Null)
    );
    let text = response
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .expect("text content");
    assert_eq!(
        serde_json::from_str::<Value>(text).expect("structured text"),
        response
            .pointer("/result/structuredContent")
            .expect("structured content")
            .clone()
    );
    fixture.state.active.store(false, Ordering::SeqCst);
    let (status, _) = fixture
        .request("tools/call", arguments, TOKEN)
        .await
        .expect("revocation");
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn invalid_operations_and_inputs_never_reach_execution() {
    let fixture = Fixture::new().await.expect("fixture");
    for (operation, input, expected) in [
        ("unknown.read.v1", json!({}), "unknown_operation"),
        (
            "logs.read.v1",
            json!({"token":"SYNTHETIC_PRIVATE_MARKER"}),
            "invalid_input",
        ),
    ] {
        let (status, response) = fixture
            .request(
                "tools/call",
                json!({"name":"execute",
            "arguments":{"operation":operation,"input":input}}),
                TOKEN,
            )
            .await
            .expect("invalid operation");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            response.pointer("/result/structuredContent/error/code"),
            Some(&json!(expected))
        );
        assert_eq!(
            response.pointer("/result/structuredContent/data"),
            Some(&Value::Null)
        );
        assert!(!response.to_string().contains("SYNTHETIC_PRIVATE_MARKER"));
    }
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn host_origin_and_credential_boundaries_reject_before_introspection() {
    let fixture = Fixture::new().await.expect("fixture");
    for (host, origins, authorization, expected) in [
        ("foreign.example", vec![], vec![], StatusCode::FORBIDDEN),
        (
            "resource.example",
            vec!["https://foreign.example"],
            vec![],
            StatusCode::FORBIDDEN,
        ),
        (
            "resource.example",
            vec!["null"],
            vec![],
            StatusCode::FORBIDDEN,
        ),
        (
            "resource.example",
            vec!["https://resource.example", "https://resource.example"],
            vec![],
            StatusCode::FORBIDDEN,
        ),
        ("resource.example", vec![], vec![], StatusCode::UNAUTHORIZED),
        (
            "resource.example",
            vec![],
            vec!["Bearer synthetic", "Bearer synthetic"],
            StatusCode::BAD_REQUEST,
        ),
        (
            "resource.example",
            vec![],
            vec!["Bearer synthetic,other"],
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let request = boundary_request(host, &origins, &authorization).expect("request");
        let response = fixture
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("boundary response");
        assert_auth_boundary(&response, expected).expect("boundary response");
    }
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Host", "resource.example")
        .header("Sec-Fetch-Site", "cross-site")
        .header("Authorization", format!("Bearer {TOKEN}"))
        .body(Body::from("{}"))
        .expect("cross-site request");
    let response = fixture
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("cross-site response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn metadata_is_public_and_has_an_explicit_read_only_method() {
    let fixture = Fixture::new().await.expect("fixture");
    for (method, path, expected) in [
        (
            "GET",
            "/.well-known/oauth-protected-resource/mcp",
            StatusCode::OK,
        ),
        (
            "POST",
            "/.well-known/oauth-protected-resource/mcp",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            "GET",
            "/.well-known/oauth-protected-resource/mcp?private=synthetic",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("Host", "resource.example")
            .body(Body::empty())
            .expect("metadata request");
        let response = fixture
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("metadata response");
        assert_resource_metadata(response, expected)
            .await
            .expect("metadata response");
    }
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn operation_object_keys_keep_their_meaning_through_the_sdk() {
    let fixture = Fixture::new().await.expect("fixture");
    let arguments = json!({"name":"execute","arguments":{"operation":"logs.read.v1","input":{
        "context":{"$serde_json::private::Number":"123","context":"preserved"}}}});
    let (status, response) = fixture
        .request("tools/call", arguments, TOKEN)
        .await
        .expect("operation request");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response.pointer("/result/structuredContent/data/count"),
        Some(&json!(3_i32))
    );
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn maximum_output_survives_both_content_forms_and_one_more_byte_is_rejected() {
    let fixture = Fixture::new().await.expect("fixture");
    let empty = json!({"blob":"","count":3_i32}).to_string();
    let arguments = json!({"name":"execute","arguments":{"operation":"logs.read.v1","input":{}}});
    for size in [logbrew_mcp::OUTPUT_BYTES, logbrew_mcp::OUTPUT_BYTES + 1] {
        let blob = "x".repeat(size - empty.len());
        let body = json!({"blob":blob,"count":3_i32}).to_string();
        assert_eq!(body.len(), size);
        fixture
            .reply(StatusCode::OK, body, HeaderMap::new())
            .expect("bounded reply");
        let (status, response) = fixture
            .request("tools/call", arguments.clone(), TOKEN)
            .await
            .expect("execution");
        assert_eq!(status, StatusCode::OK);
        let content = response
            .pointer("/result/structuredContent")
            .expect("structured result");
        let text = response
            .pointer("/result/content/0/text")
            .and_then(Value::as_str)
            .expect("text result");
        assert_eq!(
            &logbrew_mcp::json::object(text.as_bytes(), logbrew_mcp::ENVELOPE_BYTES)
                .expect("bounded text"),
            content
        );
        http::assert_output_budget(content, size).expect("output budget");
    }
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn invalid_upstream_json_and_output_contracts_return_no_rejected_data() {
    let fixture = Fixture::new().await.expect("fixture");
    for body in [
        "{\"count\":\"SYNTHETIC_PRIVATE_MARKER\"}",
        "{\"count\":3,\"count\":4,\"marker\":\"SYNTHETIC_PRIVATE_MARKER\"}",
    ] {
        fixture
            .reply(StatusCode::OK, body.to_owned(), HeaderMap::new())
            .expect("invalid reply");
        let (_, response) = fixture
            .request(
                "tools/call",
                json!({"name":"execute",
            "arguments":{"operation":"logs.read.v1","input":{}}}),
                TOKEN,
            )
            .await
            .expect("execution");
        assert_eq!(
            response.pointer("/result/structuredContent/error/code"),
            Some(&json!("invalid_output"))
        );
        assert_eq!(
            response.pointer("/result/structuredContent/data"),
            Some(&Value::Null)
        );
        assert!(!response.to_string().contains("SYNTHETIC_PRIVATE_MARKER"));
    }
}

#[tokio::test]
async fn upstream_errors_have_stable_retry_advice_and_are_not_retried() {
    let fixture = Fixture::new().await.expect("fixture");
    for (status, delay, code, expected) in [
        (
            StatusCode::TOO_MANY_REQUESTS,
            "0",
            "throttled",
            json!(0_i32),
        ),
        (
            StatusCode::TOO_MANY_REQUESTS,
            "2",
            "throttled",
            json!(2_000_i32),
        ),
        (
            StatusCode::TOO_MANY_REQUESTS,
            "invalid",
            "throttled",
            Value::Null,
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "2147483648",
            "unavailable",
            Value::Null,
        ),
        (StatusCode::FORBIDDEN, "2", "permission_denied", Value::Null),
    ] {
        let before = fixture.state.calls.load(Ordering::SeqCst);
        let mut headers = HeaderMap::new();
        drop(headers.insert(header::RETRY_AFTER, delay.parse().expect("retry header")));
        fixture
            .reply(status, "SYNTHETIC_PRIVATE_MARKER".to_owned(), headers)
            .expect("error reply");
        let (_, response) = fixture
            .request(
                "tools/call",
                json!({"name":"execute",
            "arguments":{"operation":"logs.read.v1","input":{}}}),
                TOKEN,
            )
            .await
            .expect("execution");
        assert_eq!(
            response.pointer("/result/structuredContent/error/code"),
            Some(&json!(code))
        );
        assert_eq!(
            response.pointer("/result/structuredContent/error/retry_after_ms"),
            Some(&expected)
        );
        assert!(!response.to_string().contains("SYNTHETIC_PRIVATE_MARKER"));
        assert_eq!(fixture.state.calls.load(Ordering::SeqCst), before + 1);
    }
}

#[tokio::test]
async fn advertised_output_contract_rejects_inconsistent_or_unbounded_metadata() {
    let fixture = Fixture::new().await.expect("fixture");
    let (_, response) = fixture
        .request("tools/list", json!({}), TOKEN)
        .await
        .expect("inventory");
    let tools = response
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .expect("tools");
    for tool in tools {
        assert_output_contract(tool).expect("output contract");
    }
}

fn boundary_request(
    host: &str,
    origins: &[&str],
    authorization: &[&str],
) -> TestResult<Request<Body>> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Host", host);
    for origin in origins {
        request = request.header("Origin", *origin);
    }
    for value in authorization {
        request = request.header("Authorization", *value);
    }
    Ok(request.body(Body::from("{}"))?)
}

fn assert_auth_boundary(
    response: &axum::response::Response,
    expected: StatusCode,
) -> TestResult<()> {
    assert_eq!(response.status(), expected);
    assert_eq!(
        response
            .headers()
            .get("Cache-Control")
            .ok_or("cache policy")?,
        "no-store"
    );
    if expected == StatusCode::UNAUTHORIZED {
        assert!(
            response
                .headers()
                .get("WWW-Authenticate")
                .ok_or("metadata challenge")?
                .to_str()?
                .contains("/.well-known/oauth-protected-resource/mcp")
        );
    }
    Ok(())
}

async fn assert_resource_metadata(
    response: axum::response::Response,
    expected: StatusCode,
) -> TestResult<()> {
    assert_eq!(response.status(), expected);
    if expected == StatusCode::OK {
        let bytes = to_bytes(response.into_body(), 4096).await?;
        let metadata: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(metadata.get("resource"), Some(&json!(RESOURCE)));
        assert_eq!(
            metadata.get("bearer_methods_supported"),
            Some(&json!(["header"]))
        );
    }
    Ok(())
}

fn assert_output_contract(tool: &Value) -> TestResult<()> {
    let schema = tool.get("outputSchema").ok_or("output contract")?;
    let validator = jsonschema::validator_for(schema)?;
    let provenance = json!({"definition_sha256":"a".repeat(64)});
    assert!(validator.is_valid(&json!({"data":{},"error":null,"provenance":provenance})));
    let error =
        json!({"code":"invalid_input","next_action":"review_input_contract","retry_after_ms":null});
    assert!(validator.is_valid(&json!({"data":null,"error":error,"provenance":null})));
    for invalid in [
        json!({"data":{},"error":error,"provenance":provenance}),
        json!({"data":null,"error":null,"provenance":provenance}),
        json!({"data":{},"error":null,"provenance":{"definition_sha256":"bad"}}),
        json!({"data":null,"error":{"code":"invalid_input","next_action":"retry","retry_after_ms":-1_i32},"provenance":null}),
    ] {
        assert!(!validator.is_valid(&invalid));
    }
    Ok(())
}

#[tokio::test]
async fn disconnect_cancels_pending_upstream_execution_without_retrying_it() {
    let fixture = Arc::new(Fixture::new().await.expect("fixture"));
    fixture.state.pause.store(true, Ordering::SeqCst);
    let running_fixture = Arc::clone(&fixture);
    let request = tokio::spawn(async move {
        running_fixture
            .request(
                "tools/call",
                json!({"name":"execute",
            "arguments":{"operation":"logs.read.v1","input":{}}}),
                TOKEN,
            )
            .await
    });
    runtime::wait_executions(&fixture, 1, std::time::Duration::from_secs(2))
        .await
        .expect("execution reached backend");
    request.abort();
    assert!(
        request
            .await
            .expect_err("request disconnected")
            .is_cancelled()
    );
    runtime::wait_executions(&fixture, 0, std::time::Duration::from_secs(2))
        .await
        .expect("upstream request cancelled");
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn oversized_upstream_headers_are_rejected_on_success_and_error_statuses() {
    let fixture = Fixture::new().await.expect("fixture");
    for status in [StatusCode::OK, StatusCode::FORBIDDEN] {
        let mut headers = HeaderMap::new();
        drop(headers.insert(
            "x-synthetic-large",
            "x".repeat(17 << 10).parse().expect("oversized header"),
        ));
        fixture
            .reply(status, "{\"count\":3}".to_owned(), headers)
            .expect("header reply");
        let (_, response) = fixture
            .request(
                "tools/call",
                json!({"name":"execute",
            "arguments":{"operation":"logs.read.v1","input":{}}}),
                TOKEN,
            )
            .await
            .expect("execution");
        assert_eq!(
            response.pointer("/result/structuredContent/error/code"),
            Some(&json!("unavailable"))
        );
        assert_eq!(
            response.pointer("/result/structuredContent/data"),
            Some(&Value::Null)
        );
        assert!(!response.to_string().contains("x-synthetic-large"));
    }
}
