//! Exercise authenticated cancellation and drain through the production HTTPS runtime.

use std::sync::{Arc, atomic::Ordering};

use serde_json::json;
use tower::ServiceExt as _;

use super::{
    http::{Fixture, TOKEN},
    runtime::Running,
};

#[tokio::test]
async fn shutdown_drains_an_authenticated_execution_and_closes_the_listener_first() {
    let fixture = Fixture::new().await.expect("fixture");
    fixture.state.pause.store(true, Ordering::SeqCst);
    let mut running = Arc::new(
        Running::start(fixture.router.clone())
            .await
            .expect("HTTPS runtime"),
    );
    let request_server = Arc::clone(&running);
    let request = tokio::spawn(async move { request_server.execute().await });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while fixture.state.active_executions.load(Ordering::SeqCst) != 1 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("authenticated request reached backend");
    running.stop.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if let Ok(listener) = std::net::TcpListener::bind(running.address) {
                drop(listener);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("listener stops admitting new connections before drain");
    assert!(!request.is_finished());
    fixture.state.release.notify_one();
    let response = request
        .await
        .expect("request task")
        .expect("drained response");
    assert_eq!(
        response.pointer("/result/structuredContent/data/count"),
        Some(&json!(3))
    );
    Arc::get_mut(&mut running)
        .expect("request references released")
        .wait()
        .await
        .expect("complete drain");
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.state.active_executions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancelling_the_serving_future_closes_active_requests_and_the_listener() {
    let fixture = Fixture::new().await.expect("fixture");
    fixture.state.pause.store(true, Ordering::SeqCst);
    let running = Arc::new(
        Running::start(fixture.router.clone())
            .await
            .expect("HTTPS runtime"),
    );
    let request_server = Arc::clone(&running);
    let request = tokio::spawn(async move { request_server.execute().await });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while fixture.state.active_executions.load(Ordering::SeqCst) != 1 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("execution reached backend");
    running.abort();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(2), request)
            .await
            .expect("request stopped")
            .expect("request task")
            .is_err()
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while fixture.state.active_executions.load(Ordering::SeqCst) != 0 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("backend work stopped");
    drop(std::net::TcpListener::bind(running.address).expect("listener released"));
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn active_request_capacity_rejects_excess_work_and_recovers_after_cancellation() {
    let fixture = Arc::new(Fixture::new().await.expect("fixture"));
    fixture.state.pause.store(true, Ordering::SeqCst);
    let mut requests = Vec::new();
    for _ in 0..64 {
        let request_fixture = Arc::clone(&fixture);
        requests.push(tokio::spawn(async move {
            request_fixture
                .request(
                    "tools/call",
                    json!({"name":"execute",
                "arguments":{"operation":"logs.read.v1","input":{}}}),
                    TOKEN,
                )
                .await
        }));
    }
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while fixture.state.active_executions.load(Ordering::SeqCst) != 64 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("capacity reached");
    let (status, _) = fixture
        .request("tools/list", json!({}), TOKEN)
        .await
        .expect("capacity response");
    assert_eq!(status, axum::http::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 64);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 64);
    for request in &requests {
        request.abort();
    }
    for request in requests {
        assert!(request.await.expect_err("cancelled request").is_cancelled());
    }
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while fixture.state.active_executions.load(Ordering::SeqCst) != 0 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("backend capacity released");
    fixture.state.pause.store(false, Ordering::SeqCst);
    let (status, _) = fixture
        .request("tools/list", json!({}), TOKEN)
        .await
        .expect("capacity recovered");
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 65);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 64);
}

#[tokio::test]
async fn response_body_capacity_is_held_until_completion_or_drop() -> Result<(), &'static str> {
    let fixture = Fixture::new().await.expect("fixture");
    let mut responses = Vec::new();
    for id in 0..64 {
        let response = fixture
            .router
            .clone()
            .oneshot(
                super::http::request_message(id, "tools/list", json!({}), TOKEN).expect("request"),
            )
            .await
            .expect("response headers");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        responses.push(response);
    }
    retention(&fixture, 64, 64, 0)?;
    let (status, _) = fixture
        .request("tools/list", json!({}), TOKEN)
        .await
        .expect("capacity response");
    assert_eq!(status, axum::http::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 64);
    let complete = responses.pop().expect("pending response");
    let bytes = axum::body::to_bytes(complete.into_body(), logbrew_mcp::ENVELOPE_BYTES)
        .await
        .expect("complete body");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("valid response");
    assert_eq!(value.get("id"), Some(&json!(63)));
    retention(&fixture, 64, 64, 0)?;
    let (status, _) = fixture
        .request("tools/list", json!({}), TOKEN)
        .await
        .expect("retained output capacity");
    assert_eq!(status, axum::http::StatusCode::TOO_MANY_REQUESTS);
    let retained_copy = bytes.clone();
    drop(bytes);
    retention(&fixture, 64, 64, 0)?;
    let (status, _) = fixture
        .request("tools/list", json!({}), TOKEN)
        .await
        .expect("cloned output capacity");
    assert_eq!(status, axum::http::StatusCode::TOO_MANY_REQUESTS);
    drop(retained_copy);
    retention(&fixture, 64, 63, 1)?;
    let (status, _) = fixture
        .request("tools/list", json!({}), TOKEN)
        .await
        .expect("slot recovered after body completion");
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 65);
    drop(responses.pop().expect("pending response"));
    let (status, _) = fixture
        .request("tools/list", json!({}), TOKEN)
        .await
        .expect("slot recovered after body cancellation");
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 66);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    retention(&fixture, 66, 62, 4)?;
    drop(responses);
    retention(&fixture, 66, 0, 66)?;
    let snapshot = fixture.telemetry.snapshot().expect("capacity snapshot");
    let prepared = snapshot
        .stages
        .iter()
        .find(|stage| stage.stage == logbrew_mcp::telemetry::Stage::RequestPrepared)
        .expect("request stage");
    assert_eq!(prepared.started, 69);
    assert_eq!(prepared.finished, 69);
    assert_eq!(prepared.dropped_updates, 0);
    assert_eq!(
        prepared
            .outcomes
            .iter()
            .find(|outcome| outcome.outcome == logbrew_mcp::telemetry::Outcome::Throttled)
            .expect("capacity outcome")
            .count,
        3
    );
    Ok(())
}

fn retention(
    fixture: &Fixture,
    started: u64,
    pending: u64,
    released: u64,
) -> Result<(), &'static str> {
    let snapshot = fixture.telemetry.snapshot().ok_or("retention snapshot")?;
    let retained = snapshot
        .stages
        .iter()
        .find(|stage| stage.stage == logbrew_mcp::telemetry::Stage::ResponseRetained)
        .ok_or("response retention stage")?;
    assert_eq!(retained.started, started);
    assert_eq!(retained.pending, Some(pending));
    assert_eq!(retained.finished, started - pending);
    assert_eq!(retained.dropped_updates, 0);
    assert_eq!(retained.p99_upper_ns.is_some(), pending == 0);
    for (outcome, expected) in [
        (logbrew_mcp::telemetry::Outcome::Released, released),
        (logbrew_mcp::telemetry::Outcome::Completed, 0),
    ] {
        assert_eq!(
            retained
                .outcomes
                .iter()
                .find(|entry| entry.outcome == outcome)
                .ok_or("retention outcome")?
                .count,
            expected
        );
    }
    Ok(())
}
