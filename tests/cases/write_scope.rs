//! Operations that change data run only with the separately granted `write` scope.

use core::sync::atomic::Ordering;

use axum::{
    body::to_bytes,
    http::{HeaderMap, StatusCode},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::http::{Fixture, TOKEN, request_message};

type TestResult<T> = Result<T, Box<dyn core::error::Error + Send + Sync>>;

const METADATA: &str = "https://resource.example/.well-known/oauth-protected-resource/mcp";
const WRITE_CHALLENGE: &str = "Bearer error=\"insufficient_scope\", scope=\"read write\", \
     resource_metadata=\"https://resource.example/.well-known/oauth-protected-resource/mcp\", \
     error_description=\"This operation needs the write scope.\"";

/// One `read` and one `write` operation with the same synthetic contract.
///
/// # Errors
/// Returns a JSON serialization error for the synthetic catalog.
fn catalog() -> TestResult<Vec<u8>> {
    let operation = |id: &str, permission: &str| {
        json!({"id":id,"info":{"summary":"Synthetic operation","permission":permission,
            "documentation":"https://docs.example/operations","stability":"stable",
            "cost":"one request","safety":"read_only"},
        "input_schema":{"type":"object","additionalProperties":false},
        "output_schema":{"type":"object","additionalProperties":false,"required":["count"],
            "properties":{"count":{"type":"integer"}}}})
    };
    Ok(serde_json::to_vec(
        &json!({"format_version":1_i32,"operations":[
            operation("logs.read.v1", "read"),
            operation("issues.update.v1", "write"),
        ]}),
    )?)
}

fn execute(operation: &str) -> Value {
    json!({"name":"execute","arguments":{"operation":operation,"input":{}}})
}

/// Grant the supplied scope list on the next introspections.
///
/// # Errors
/// Returns an error if the fixture claims or introspection reply are unavailable.
fn grant(fixture: &Fixture, scope: &str) -> TestResult<()> {
    let mut claims = fixture.authority()?;
    *claims.get_mut("scope").ok_or("scope claim")? = json!(scope);
    fixture.introspection_reply(StatusCode::OK, claims.to_string(), HeaderMap::new())
}

#[tokio::test]
/// # Panics
///
/// Panics if a token without `write` runs a write operation, reaches the API,
/// gets a challenge other than the MCP runtime insufficient-scope form, or
/// loses its read access or operation discovery.
async fn write_operations_need_the_write_scope_and_reads_do_not() {
    let fixture = Fixture::with_catalog(catalog().expect("catalog"))
        .await
        .expect("fixture");
    for scope in ["read", "read extra:scope", "read WRITE", "read writer"] {
        grant(&fixture, scope).expect("grant");
        let calls = fixture.state().calls().load(Ordering::SeqCst);
        let response = fixture
            .router()
            .clone()
            .oneshot(
                request_message(1, "tools/call", execute("issues.update.v1"), TOKEN)
                    .expect("request"),
            )
            .await
            .expect("scope challenge");
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{scope}");
        let challenges: Vec<_> = response
            .headers()
            .get_all("WWW-Authenticate")
            .iter()
            .collect();
        assert_eq!(challenges, [WRITE_CHALLENGE]);
        assert_eq!(
            response.headers().get("Cache-Control").expect("cache"),
            "no-store"
        );
        let body = to_bytes(response.into_body(), 1024).await.expect("body");
        assert_eq!(body.as_ref(), b"insufficient scope");
        assert_eq!(fixture.state().calls().load(Ordering::SeqCst), calls);
        let (read_status, read) = fixture
            .request("tools/call", execute("logs.read.v1"), TOKEN)
            .await
            .expect("read execution");
        assert_eq!(read_status, StatusCode::OK);
        assert_eq!(
            read.pointer("/result/structuredContent/data/count"),
            Some(&json!(3_i32))
        );
        let (search_status, contract) = fixture
            .request(
                "tools/call",
                json!({"name":"search","arguments":{"operation":"issues.update.v1"}}),
                TOKEN,
            )
            .await
            .expect("write discovery");
        assert_eq!(search_status, StatusCode::OK);
        assert_eq!(
            contract.pointer("/result/structuredContent/data/info/permission"),
            Some(&json!("write"))
        );
    }
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 4);
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 12);
}

#[tokio::test]
/// # Panics
///
/// Panics if a token with `read` and `write` cannot run both operations, or a
/// token with `write` but not `read` is accepted.
async fn read_and_write_grant_runs_both_operations_and_write_alone_is_refused() {
    let fixture = Fixture::with_catalog(catalog().expect("catalog"))
        .await
        .expect("fixture");
    for (scope, operation) in [
        ("read write", "issues.update.v1"),
        ("read write", "logs.read.v1"),
        ("write read", "issues.update.v1"),
        ("extra:scope write read", "issues.update.v1"),
    ] {
        grant(&fixture, scope).expect("grant");
        let (status, result) = fixture
            .request("tools/call", execute(operation), TOKEN)
            .await
            .expect("execution");
        assert_eq!(status, StatusCode::OK, "{scope} {operation}");
        assert_eq!(
            result.pointer("/result/structuredContent/data/count"),
            Some(&json!(3_i32))
        );
    }
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 4);
    grant(&fixture, "write").expect("grant");
    let response = fixture
        .router()
        .clone()
        .oneshot(
            request_message(1, "tools/call", execute("issues.update.v1"), TOKEN).expect("request"),
        )
        .await
        .expect("read scope challenge");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response
            .headers()
            .get("WWW-Authenticate")
            .expect("challenge"),
        format!(
            "Bearer resource_metadata=\"{METADATA}\", scope=\"read\", error=\"insufficient_scope\""
        )
        .as_str()
    );
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 4);
}
