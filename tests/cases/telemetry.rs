//! Synthetic local measurements cannot prove centralized or hosted telemetry.

use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use logbrew_mcp::telemetry::{CatalogSnapshot, Outcome, Snapshot, Stage, StageSnapshot};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use crate::http::{Fixture, TOKEN};
use crate::runtime::Running;

fn stage(snapshot: &Snapshot, stage: Stage) -> Option<&StageSnapshot> {
    snapshot.stages.iter().find(|entry| entry.stage == stage)
}

fn count(snapshot: &Snapshot, selected: Stage, outcome: Outcome) -> Option<u64> {
    stage(snapshot, selected)?
        .outcomes
        .iter()
        .find(|entry| entry.outcome == outcome)
        .map(|entry| entry.count)
}

fn operation(snapshot: &Snapshot) -> Option<&StageSnapshot> {
    snapshot
        .operations
        .as_ref()?
        .executions
        .iter()
        .find(|entry| entry.operation == "logs.read.v1")
        .map(|entry| &entry.execution)
}

fn complete(snapshot: &Snapshot) -> bool {
    snapshot.stages.iter().all(|stage| {
        stage.started == stage.finished
            && stage.timed == stage.finished
            && stage.pending == Some(0)
            && stage.dropped_updates == 0
            && !stage.saturated
            && !stage.timing_unavailable
            && stage
                .latency_buckets
                .iter()
                .map(|bucket| bucket.count)
                .sum::<u64>()
                == stage.finished
            && stage
                .outcomes
                .iter()
                .map(|outcome| outcome.count)
                .sum::<u64>()
                == stage.finished
            && stage.p99_upper_ns.is_some()
    })
}

fn assert_unobserved_catalog(snapshot: &Snapshot) -> Result<&CatalogSnapshot, &'static str> {
    assert_eq!(snapshot.format_version, 3);
    assert_eq!(snapshot.stages.len(), 6);
    assert!(
        snapshot
            .stages
            .iter()
            .all(|stage| stage.p99_upper_ns.is_none())
    );
    let catalog = snapshot
        .operations
        .as_ref()
        .ok_or("verified catalog inventory")?;
    assert_eq!(catalog.executions.len(), 1);
    assert_eq!(
        catalog
            .executions
            .first()
            .map(|entry| entry.operation.as_str()),
        Some("logs.read.v1")
    );
    let execution = operation(snapshot).ok_or("unobserved operation")?;
    assert_eq!(execution.started, 0);
    assert_eq!(execution.finished, 0);
    assert_eq!(execution.p99_upper_ns, None);
    Ok(catalog)
}

fn assert_known_execution(snapshot: &Snapshot, digest: &str) -> Result<(), &'static str> {
    let operations = snapshot.operations.as_ref().ok_or("catalog inventory")?;
    assert_eq!(operations.definition_sha256, digest);
    assert_eq!(operations.executions.len(), 1);
    let execution = operation(snapshot).ok_or("operation observations")?;
    assert_eq!(execution.started, 2);
    assert_eq!(execution.finished, 2);
    assert_eq!(execution.timed, 2);
    assert_eq!(execution.pending, Some(0));
    assert_eq!(execution.dropped_updates, 0);
    assert!(execution.p99_upper_ns.is_some());
    for (outcome, expected) in [
        (Outcome::Completed, 1),
        (Outcome::InvalidInput, 1),
        (Outcome::UnknownOperation, 0),
    ] {
        assert_eq!(
            execution
                .outcomes
                .iter()
                .find(|entry| entry.outcome == outcome)
                .map(|entry| entry.count),
            Some(expected)
        );
    }
    Ok(())
}

fn assert_cancelled_operation(
    snapshot: &Snapshot,
    before: &StageSnapshot,
) -> Result<(), &'static str> {
    let cancelled = operation(snapshot).ok_or("cancelled operation")?;
    assert_eq!(Some(cancelled.started), before.started.checked_add(1));
    assert_eq!(Some(cancelled.finished), before.finished.checked_add(1));
    assert_eq!(Some(cancelled.timed), before.timed.checked_add(1));
    assert_eq!(cancelled.pending, Some(0));
    assert_eq!(cancelled.dropped_updates, 0);
    assert_eq!(
        cancelled
            .outcomes
            .iter()
            .find(|entry| entry.outcome == Outcome::Cancelled)
            .map(|entry| entry.count),
        Some(1)
    );
    assert_eq!(
        cancelled
            .outcomes
            .iter()
            .find(|entry| entry.outcome == Outcome::Completed)
            .map(|entry| entry.count),
        Some(before.finished)
    );
    Ok(())
}

#[tokio::test]
async fn http_success_does_not_hide_tool_errors_or_disclose_request_content() {
    let fixture = Fixture::new().await.expect("fixture");
    let empty = fixture.telemetry.snapshot().expect("empty snapshot");
    let catalog = assert_unobserved_catalog(&empty).expect("unobserved catalog proof");

    let calls = [
        json!({"name":"search","arguments":{"query":"SYNTHETIC_PRIVATE_QUERY"}}),
        json!({"name":"execute","arguments":{"operation":"logs.read.v1","input":{}}}),
        json!({"name":"execute","arguments":{"operation":"logs.read.v1","input":{
            "SYNTHETIC_PRIVATE_INPUT":"SYNTHETIC_PRIVATE_VALUE"}}}),
        json!({"name":"execute","arguments":{"operation":"SYNTHETIC_PRIVATE_OPERATION","input":{}}}),
    ];
    for params in calls {
        let (status, response) = fixture
            .request("tools/call", params, TOKEN)
            .await
            .expect("tool call");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            response
                .pointer("/result/structuredContent/provenance/definition_sha256")
                .and_then(Value::as_str),
            Some(catalog.definition_sha256.as_str())
        );
    }
    fixture.state.active.store(false, Ordering::SeqCst);
    let (status, _) = fixture
        .request("tools/list", json!({}), TOKEN)
        .await
        .expect("revoked");
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let response = fixture
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("Host", "SYNTHETIC_PRIVATE_HOST.example")
                .body(Body::from("SYNTHETIC_PRIVATE_BODY"))
                .expect("denied request"),
        )
        .await
        .expect("denied response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    drop(response);

    let snapshot = fixture.telemetry.snapshot().expect("snapshot");
    for (stage, outcome, expected) in [
        (Stage::RequestPrepared, Outcome::Completed, 4),
        (Stage::RequestPrepared, Outcome::Unauthorized, 1),
        (Stage::RequestPrepared, Outcome::PermissionDenied, 1),
        (Stage::Introspection, Outcome::Completed, 4),
        (Stage::Introspection, Outcome::Unauthorized, 1),
        (Stage::Search, Outcome::Completed, 1),
        (Stage::Execute, Outcome::Completed, 1),
        (Stage::Execute, Outcome::InvalidInput, 1),
        (Stage::Execute, Outcome::UnknownOperation, 1),
        (Stage::UpstreamExecute, Outcome::Completed, 1),
        (Stage::ResponseRetained, Outcome::Released, 5),
    ] {
        assert_eq!(count(&snapshot, stage, outcome), Some(expected));
    }
    assert_eq!(
        count(&snapshot, Stage::ResponseRetained, Outcome::Completed),
        Some(0)
    );
    assert!(complete(&snapshot), "{snapshot:?}");
    assert_known_execution(&snapshot, &catalog.definition_sha256).expect("catalog execution proof");
    let value: Value = serde_json::to_value(snapshot).expect("snapshot JSON");
    let text = value.to_string();
    for prohibited in [
        "SYNTHETIC_",
        "synthetic-client",
        "credential",
        "resource.example",
    ] {
        assert!(!text.contains(prohibited));
    }
}

#[tokio::test]
async fn cancelling_https_work_records_each_started_stage_without_a_success() {
    let fixture = Fixture::new().await.expect("fixture");
    fixture.state.pause.store(true, Ordering::SeqCst);
    let running = Arc::new(
        Running::start(fixture.router.clone())
            .await
            .expect("HTTPS runtime"),
    );
    let baseline = fixture.telemetry.snapshot().expect("readiness snapshot");
    let server = Arc::clone(&running);
    let request = tokio::spawn(async move { server.execute().await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.state.active_executions.load(Ordering::SeqCst) != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("execution reached backend");
    let snapshot = fixture.telemetry.snapshot().expect("pending snapshot");
    let pending = operation(&snapshot).expect("pending operation");
    let before = operation(&baseline).expect("baseline operation");
    assert_eq!(pending.started, before.started + 1);
    assert_eq!(pending.finished, before.finished);
    assert_eq!(pending.pending, Some(1));
    assert_eq!(pending.p99_upper_ns, None);
    for selected in [
        Stage::RequestPrepared,
        Stage::Execute,
        Stage::UpstreamExecute,
    ] {
        let stage = stage(&snapshot, selected).expect("pending stage");
        let before = self::stage(&baseline, selected).expect("baseline stage");
        assert_eq!(stage.started, before.started + 1);
        assert_eq!(stage.finished, before.finished);
        assert_eq!(stage.pending, Some(1));
        assert_eq!(stage.p99_upper_ns, None);
    }
    running.abort();
    drop(
        tokio::time::timeout(Duration::from_secs(2), request)
            .await
            .expect("request stopped")
            .expect("request task")
            .unwrap_err(),
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(snapshot) = fixture.telemetry.snapshot()
                && snapshot.stages.iter().all(|stage| stage.pending == Some(0))
                && operation(&snapshot).is_some_and(|stage| stage.pending == Some(0))
                && fixture.state.active_executions.load(Ordering::SeqCst) == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("cancelled stages finished");
    let snapshot = fixture.telemetry.snapshot().expect("cancelled snapshot");
    assert_cancelled_operation(&snapshot, before).expect("catalog cancellation proof");
    for selected in [
        Stage::RequestPrepared,
        Stage::Execute,
        Stage::UpstreamExecute,
    ] {
        assert_eq!(count(&snapshot, selected, Outcome::Cancelled), Some(1));
        assert_eq!(
            count(&snapshot, selected, Outcome::Completed),
            count(&baseline, selected, Outcome::Completed)
        );
        let stage = stage(&snapshot, selected).expect("cancelled stage");
        assert_eq!(stage.started, stage.finished);
        assert_eq!(stage.dropped_updates, 0);
        assert_eq!(
            stage.timed,
            self::stage(&baseline, selected)
                .expect("baseline stage")
                .timed
                + 1
        );
    }
    assert_eq!(
        count(&snapshot, Stage::Introspection, Outcome::Completed),
        Some(1)
    );
}
