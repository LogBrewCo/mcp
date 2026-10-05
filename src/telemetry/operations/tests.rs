//! Exact distributions and bounded labels, independent of performance targets.

use serde_json::json;
use sha2::{Digest as _, Sha256};

use super::*;

/// Build a verified synthetic catalog from the supplied operation identifiers.
///
/// # Panics
/// Panics if controlled JSON encoding or catalog verification fails.
fn catalog(ids: &[String]) -> std::sync::Arc<Catalog> {
    let operations: Vec<_> = ids
        .iter()
        .map(|id| {
            json!({
                "id":id,
                "info":{"summary":"Read logs","permission":"logs:read",
                    "documentation":"https://docs.example/logs","stability":"stable",
                    "cost":"one read","safety":"read_only"},
                "input_schema":{"type":"object"},
                "output_schema":{"type":"object"}
            })
        })
        .collect();
    let bytes = serde_json::to_vec(&json!({"format_version":1_i32,"operations":operations}))
        .expect("controlled catalog JSON");
    Catalog::load(&bytes, &Sha256::digest(&bytes).into()).expect("verified catalog")
}

fn observer() -> Telemetry {
    let telemetry = Telemetry::default();
    telemetry.register_catalog(&catalog(&[
        "logs.fast.v1".to_owned(),
        "logs.slow.v1".to_owned(),
        "logs.unused.v1".to_owned(),
    ]));
    telemetry
}

/// Select one catalog operation's execution snapshot.
///
/// # Panics
/// Panics if the requested operation is absent from the supplied snapshot.
fn execution<'a>(snapshot: &'a CatalogSnapshot, id: &str) -> &'a StageSnapshot {
    &snapshot
        .executions
        .iter()
        .find(|entry| entry.operation == id)
        .expect("catalog operation")
        .execution
}

/// Freeze measurement labels to the verified catalog and reject private identifiers.
///
/// # Panics
/// Panics if fixture setup fails, labels or provenance change, unknown operations
/// acquire measurements, or private/replacement identifiers appear in the snapshot.
#[test]
fn labels_are_frozen_to_the_verified_bounded_inventory() {
    let telemetry = Telemetry::default();
    assert!(
        telemetry
            .snapshot()
            .expect("empty snapshot")
            .operations
            .is_none()
    );
    let ids: Vec<_> = (0_i32..256_i32)
        .map(|n| format!("logs.read{n}.v1"))
        .collect();
    let catalog = catalog(&ids);
    telemetry.register_catalog(&catalog);
    let measurement = telemetry.begin(Stage::Execute);
    for n in 0_i32..2_048_i32 {
        assert!(
            measurement
                .operation(&format!("SYNTHETIC_PRIVATE_{n}"))
                .is_none()
        );
    }
    measurement.finish(Outcome::UnknownOperation);
    assert!(
        telemetry
            .begin(Stage::Search)
            .operation("logs.read0.v1")
            .is_none()
    );
    telemetry.register_catalog(&self::catalog(&["logs.replacement.v1".to_owned()]));

    let snapshot = telemetry.snapshot().expect("bounded snapshot");
    let operations = snapshot.operations.as_ref().expect("registered catalog");
    assert_eq!(operations.definition_sha256, catalog.definition_digest());
    let mut expected = ids;
    expected.sort();
    assert_eq!(
        operations
            .executions
            .iter()
            .map(|entry| entry.operation.as_str())
            .collect::<Vec<_>>(),
        expected.iter().map(String::as_str).collect::<Vec<_>>()
    );
    assert!(operations.executions.iter().all(|entry| {
        entry.execution.started == 0
            && entry.execution.finished == 0
            && entry.execution.p99_upper_ns.is_none()
    }));
    let encoded = serde_json::to_string(&snapshot).expect("snapshot JSON");
    assert!(!encoded.contains("SYNTHETIC_PRIVATE_"));
    assert!(!encoded.contains("logs.replacement.v1"));
}

/// Preserve a slow operation's distribution when aggregate p99 hides its latency.
///
/// # Panics
/// Panics if fixture state is unavailable, per-operation values or outcomes change,
/// or retained latency/outcome counts fail to reconcile with completion counts.
#[test]
fn operation_distributions_preserve_a_slow_operation_hidden_by_aggregate_p99() {
    let telemetry = observer();
    let inventory = telemetry.0.operations.get().expect("catalog inventory");
    let mut stats = inventory.stats.lock().expect("controlled counts");
    let fast = stats
        .get_mut(*inventory.slots.get("logs.fast.v1").expect("fast slot"))
        .expect("fast counts");
    fast.started = 100;
    for _ in 0_i32..100_i32 {
        fast.finish(Outcome::Completed, Some(100));
    }
    let slow = stats
        .get_mut(*inventory.slots.get("logs.slow.v1").expect("slow slot"))
        .expect("slow counts");
    slow.started = 1;
    slow.finish(Outcome::InvalidOutput, Some(1_000_000));
    drop(stats);
    let snapshot = telemetry.snapshot().expect("distribution snapshot");
    let operations = snapshot.operations.expect("catalog distributions");
    let fast = execution(&operations, "logs.fast.v1");
    let slow = execution(&operations, "logs.slow.v1");
    assert_eq!(fast.p99_upper_ns, Some(128));
    assert_eq!(slow.p99_upper_ns, Some(1_048_576));
    assert_eq!(slow.maximum_ns, Some(1_000_000));
    assert_eq!(
        slow.outcomes
            .iter()
            .find(|entry| entry.outcome == Outcome::InvalidOutput)
            .expect("invalid output count")
            .count,
        1
    );
    let mut aggregate = Stats::EMPTY;
    aggregate.started = 101;
    for _ in 0_i32..100_i32 {
        aggregate.finish(Outcome::Completed, Some(100));
    }
    aggregate.finish(Outcome::InvalidOutput, Some(1_000_000));
    assert_eq!(
        StageSnapshot::new(Stage::Execute, &aggregate, 0, false).p99_upper_ns,
        Some(128)
    );
    assert_eq!(execution(&operations, "logs.unused.v1").p99_upper_ns, None);
    for entry in operations.executions {
        assert_eq!(
            entry
                .execution
                .latency_buckets
                .iter()
                .map(|bucket| bucket.count)
                .sum::<u64>(),
            entry.execution.finished
        );
        assert_eq!(
            entry
                .execution
                .outcomes
                .iter()
                .map(|outcome| outcome.count)
                .sum::<u64>(),
            entry.execution.finished
        );
    }
}

/// Retain operation-specific measurement loss across contention and recovery.
///
/// # Panics
/// Panics if fixture state is unavailable, contention changes availability,
/// or recovered counts, pending work, loss or unsupported percentiles are wrong.
#[test]
fn contention_is_nonblocking_and_loss_stays_with_the_selected_operation() {
    let telemetry = observer();
    let inventory = telemetry.0.operations.get().expect("catalog inventory");
    let parent = telemetry.begin(Stage::Execute);
    let stats = inventory.stats.lock().expect("controlled lock");
    parent
        .operation("logs.fast.v1")
        .expect("known operation")
        .finish(Outcome::Completed);
    let busy = telemetry.snapshot().expect("fixed stages remain available");
    assert!(busy.operations.is_none());
    drop(stats);
    parent
        .operation("logs.fast.v1")
        .expect("recovered operation")
        .finish(Outcome::Completed);
    let slow = parent.operation("logs.slow.v1").expect("slow operation");
    let stats = inventory.stats.lock().expect("controlled finish lock");
    slow.finish(Outcome::Completed);
    drop(stats);
    parent.finish(Outcome::Completed);
    let snapshot = telemetry.snapshot().expect("recovered snapshot");
    let operations = snapshot.operations.expect("catalog recovered");
    let fast = execution(&operations, "logs.fast.v1");
    assert_eq!(fast.started, 1);
    assert_eq!(fast.finished, 1);
    assert_eq!(fast.dropped_updates, 1);
    assert_eq!(fast.p99_upper_ns, None);
    let slow = execution(&operations, "logs.slow.v1");
    assert_eq!(slow.pending, Some(1));
    assert_eq!(slow.dropped_updates, 1);
    assert_eq!(slow.p99_upper_ns, None);
    assert_eq!(execution(&operations, "logs.unused.v1").dropped_updates, 0);
}

/// Start operation timing at handler entry and record cancellation on drop.
///
/// # Panics
/// Panics if fixture state or controlled clock setup fails, timing starts late,
/// or pending, cancellation, completion or maximum-duration values are incorrect.
#[test]
fn operation_timing_starts_at_handler_entry_and_drop_records_cancellation() {
    let telemetry = observer();
    let mut parent = telemetry.begin(Stage::Execute);
    parent.start = Instant::now()
        .checked_sub(std::time::Duration::from_millis(10))
        .expect("controlled earlier entry");
    let operation = parent
        .operation("logs.fast.v1")
        .expect("operation measurement");
    assert_eq!(operation.start, parent.start);
    let snapshot = telemetry.snapshot().expect("pending snapshot");
    let operations = snapshot.operations.expect("pending operations");
    assert_eq!(execution(&operations, "logs.fast.v1").pending, Some(1));
    assert_eq!(execution(&operations, "logs.fast.v1").p99_upper_ns, None);
    drop(operation);
    drop(parent);
    let snapshot = telemetry.snapshot().expect("cancelled snapshot");
    let operations = snapshot.operations.expect("cancelled operations");
    let fast = execution(&operations, "logs.fast.v1");
    assert_eq!(fast.pending, Some(0));
    assert_eq!(fast.finished, 1);
    assert_eq!(
        fast.outcomes
            .iter()
            .find(|entry| entry.outcome == Outcome::Cancelled)
            .expect("cancelled outcome")
            .count,
        1
    );
    assert!(
        fast.maximum_ns
            .is_some_and(|duration| duration >= 10_000_000)
    );
}

/// Keep unavailable operation timing distinct from measured zero latency.
///
/// # Panics
/// Panics if fixture state or controlled clock setup fails, unavailable timing
/// produces percentiles or duration values, or retained completion counts change.
#[test]
fn an_unknown_duration_suppresses_operation_percentiles() {
    let telemetry = observer();
    let mut parent = telemetry.begin(Stage::Execute);
    parent.start = Instant::now()
        .checked_add(std::time::Duration::from_secs(60))
        .expect("controlled future clock");
    parent
        .operation("logs.fast.v1")
        .expect("operation measurement")
        .finish(Outcome::Unavailable);
    parent.finish(Outcome::Unavailable);
    let snapshot = telemetry.snapshot().expect("unknown duration snapshot");
    let operations = snapshot.operations.expect("catalog measurements");
    let fast = execution(&operations, "logs.fast.v1");
    assert_eq!(fast.finished, 1);
    assert_eq!(fast.timed, 0);
    assert!(fast.timing_unavailable);
    assert_eq!(fast.p99_upper_ns, None);
    assert_eq!(fast.maximum_ns, None);
    assert!(fast.latency_buckets.iter().all(|bucket| bucket.count == 0));
}
