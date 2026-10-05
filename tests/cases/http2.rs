//! Actual TLS HTTP/2 authority, authorization, validation and disconnect behavior.

use std::{net::TcpListener, sync::atomic::Ordering, time::Duration};

use serde_json::{Value, json};
use tokio::time::sleep;

use super::{
    http::{Fixture, TOKEN},
    runtime::Running,
};

fn body() -> Value {
    json!({"jsonrpc":"2.0","id":"http2-check","method":"tools/call","params":{
        "name":"execute","arguments":{"operation":"logs.read.v1","input":{}},"_meta":{
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":{}}}})
}

fn request(client: &reqwest::Client, resource: &str) -> reqwest::RequestBuilder {
    client
        .post(resource)
        .header("Authorization", format!("Bearer {TOKEN}"))
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "execute")
        .json(&body())
}

#[tokio::test]
/// # Panics
///
/// Panics if setup fails, authenticated requests finish before backend release,
/// response version, correlation or data changes, or work counts and drain fail.
async fn protocol_detection_deadline_does_not_truncate_authenticated_http1_or_http2_work() {
    let address = TcpListener::bind("127.0.0.1:0")
        .expect("frontend address")
        .local_addr()
        .expect("address");
    let authority = format!("localhost:{}", address.port());
    let resource = format!("https://{authority}/mcp");
    let fixture = Fixture::for_resource(resource.clone())
        .await
        .expect("fixture");
    fixture.state.pause.store(true, Ordering::SeqCst);
    let mut running = Running::at(address, fixture.router.clone(), &authority)
        .await
        .expect("HTTPS runtime");
    let clients = [
        (reqwest::Version::HTTP_11, running.http1_client()),
        (
            reqwest::Version::HTTP_2,
            running.http2_client().expect("HTTP/2 client"),
        ),
    ];
    let mut calls = Vec::new();
    for (version, client) in clients {
        let request = request(&client, &resource).timeout(Duration::from_secs(8));
        calls.push((version, tokio::spawn(request.send())));
    }
    super::runtime::wait_executions(&fixture, 2, Duration::from_secs(2))
        .await
        .expect("both authenticated requests reached the backend");
    sleep(Duration::from_millis(5250)).await;
    for (_, call) in &calls {
        assert!(!call.is_finished());
    }
    fixture.state.release.notify_waiters();
    for (version, call) in calls {
        let response = call
            .await
            .expect("request task")
            .expect("complete response");
        assert_eq!(response.version(), version);
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let value: Value = response.json().await.expect("complete JSON result");
        assert_eq!(value.get("id"), Some(&json!("http2-check")));
        assert_eq!(
            value.pointer("/result/structuredContent/data/count"),
            Some(&json!(3_i32))
        );
    }
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.state.active_executions.load(Ordering::SeqCst), 0);
    running.stop.cancel();
    running.wait().await.expect("runtime drain");
}

#[tokio::test]
/// # Panics
///
/// Panics if setup fails, HTTP/2 result, authority or routing checks change,
/// cancellation fails to stop execution, or work counts and drain fail.
async fn real_http2_preserves_authority_checks_and_cancels_authenticated_execution() {
    let address = TcpListener::bind("127.0.0.1:0")
        .expect("frontend address")
        .local_addr()
        .expect("address");
    let authority = format!("localhost:{}", address.port());
    let resource = format!("https://{authority}/mcp");
    let fixture = Fixture::for_resource(resource.clone())
        .await
        .expect("fixture");
    let mut running = Running::at(address, fixture.router.clone(), &authority)
        .await
        .expect("HTTPS runtime");
    let client = running.http2_client().expect("HTTP/2 client");

    let execution_response = request(&client, &resource).send().await.expect("execution");
    assert_eq!(execution_response.version(), reqwest::Version::HTTP_2);
    assert_eq!(execution_response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        execution_response
            .headers()
            .get("Cache-Control")
            .expect("cache control"),
        "no-store"
    );
    assert!(execution_response.headers().get("Mcp-Session-Id").is_none());
    let result: Value = execution_response.json().await.expect("JSON result");
    assert_eq!(result.get("id"), Some(&json!("http2-check")));
    assert_eq!(
        result.pointer("/result/structuredContent/data/count"),
        Some(&json!(3_i32))
    );

    let authority_response = request(&client, &resource)
        .header("Host", "wrong.example")
        .send()
        .await
        .expect("authority rejection");
    assert_eq!(authority_response.status(), reqwest::StatusCode::FORBIDDEN);
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 1);

    let response = request(&client, &resource)
        .header("Mcp-Name", "search")
        .send()
        .await
        .expect("header rejection");
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let value: Value = response.json().await.expect("JSON error");
    assert_eq!(value.pointer("/error/code"), Some(&json!(-32_020_i32)));
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);

    fixture.state.pause.store(true, Ordering::SeqCst);
    let active = request(&client, &resource);
    let call = tokio::spawn(async move { active.send().await });
    super::runtime::wait_executions(&fixture, 1, Duration::from_secs(2))
        .await
        .expect("active authenticated execution");
    call.abort();
    assert!(
        call.await
            .expect_err("aborted HTTP/2 request")
            .is_cancelled()
    );
    super::runtime::wait_executions(&fixture, 0, Duration::from_secs(2))
        .await
        .expect("upstream cancellation");
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 3);
    drop(client);
    running.stop.cancel();
    running.wait().await.expect("runtime drain");
}
