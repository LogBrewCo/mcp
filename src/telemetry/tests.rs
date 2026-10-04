//! Controlled distributions and collector loss are exact tests, not benchmarks.

use super::*;

#[test]
fn p99_replays_a_mergeable_distribution_and_keeps_the_slow_tail() {
    let mut stats = Stats::EMPTY;
    stats.started = 100;
    for duration in 1..100 {
        stats.finish(Outcome::Completed, Some(duration));
    }
    stats.finish(Outcome::Cancelled, Some(1_000_000));
    let snapshot = StageSnapshot::new(Stage::Execute, &stats, 0, false);
    assert_eq!(snapshot.finished, 100);
    assert_eq!(snapshot.timed, 100);
    assert_eq!(snapshot.p99_upper_ns, Some(128));
    assert_eq!(snapshot.maximum_ns, Some(1_000_000));
    assert_eq!(snapshot.pending, Some(0));
    assert_eq!(
        snapshot
            .outcomes
            .iter()
            .find(|n| n.outcome == Outcome::Cancelled)
            .expect("cancelled outcome")
            .count,
        1
    );
    assert_eq!(percentile(&snapshot.latency_buckets, 100), Some(128));
    assert_eq!(percentile(&snapshot.latency_buckets, 99), None);
}

#[test]
fn latency_buckets_bound_zero_power_edges_and_the_full_integer_range() {
    for (duration, expected) in [
        (0, 0),
        (1, 1),
        (2, 2),
        (3, 4),
        (4, 4),
        (5, 8),
        (1 << 63_i32, 1 << 63_i32),
        (u64::MAX, u64::MAX),
    ] {
        let mut stats = Stats::EMPTY;
        stats.started = 1;
        stats.finish(Outcome::Completed, Some(duration));
        let snapshot = StageSnapshot::new(Stage::Search, &stats, 0, false);
        assert_eq!(snapshot.p99_upper_ns, Some(expected));
        assert_eq!(snapshot.maximum_ns, Some(duration));
        assert_eq!(
            snapshot
                .latency_buckets
                .iter()
                .map(|n| n.count)
                .sum::<u64>(),
            1
        );
        assert!(!snapshot.saturated);
    }
}

#[test]
fn pending_dropped_and_overflowed_measurements_cannot_produce_a_p99() {
    let mut stats = Stats::EMPTY;
    let empty = StageSnapshot::new(Stage::Search, &stats, 0, false);
    assert_eq!(empty.p99_upper_ns, None);
    assert_eq!(empty.maximum_ns, None);
    stats.started = 2;
    stats.finish(Outcome::Completed, Some(1));
    assert_eq!(
        StageSnapshot::new(Stage::Search, &stats, 0, false).p99_upper_ns,
        None
    );
    stats.started = 1;
    assert_eq!(
        StageSnapshot::new(Stage::Search, &stats, 1, false).p99_upper_ns,
        None
    );
    assert_eq!(
        StageSnapshot::new(Stage::Search, &stats, 0, true).p99_upper_ns,
        None
    );
    stats.finished = u64::MAX;
    stats.finish(Outcome::Unavailable, Some(2));
    let overflow = StageSnapshot::new(Stage::Search, &stats, 0, false);
    assert!(overflow.saturated);
    assert_eq!(overflow.pending, None);
    assert_eq!(overflow.p99_upper_ns, None);
}

#[test]
fn unavailable_clock_timing_is_not_recorded_as_zero_latency() {
    let mut stats = Stats::EMPTY;
    stats.started = 1;
    stats.finish(Outcome::Unavailable, None);
    let snapshot = StageSnapshot::new(Stage::Introspection, &stats, 0, false);
    assert_eq!(snapshot.finished, 1);
    assert_eq!(snapshot.timed, 0);
    assert!(snapshot.timing_unavailable);
    assert_eq!(snapshot.p99_upper_ns, None);
    assert_eq!(snapshot.maximum_ns, None);
    assert!(snapshot.latency_buckets.iter().all(|n| n.count == 0));
    let future = Instant::now()
        .checked_add(std::time::Duration::from_secs(60))
        .expect("future instant");
    assert_eq!(elapsed_since(future), None);
}

#[test]
fn contention_drops_measurements_without_waiting_and_recovery_keeps_the_loss() {
    let telemetry = Telemetry::default();
    let stats = telemetry.0.stats.lock().expect("controlled lock");
    let dropped = telemetry.begin(Stage::Search);
    dropped.finish(Outcome::Completed);
    assert!(telemetry.snapshot().is_none());
    drop(stats);
    telemetry.begin(Stage::Search).finish(Outcome::Completed);
    let snapshot = telemetry.snapshot().expect("recovered snapshot");
    let search = snapshot
        .stages
        .iter()
        .find(|s| s.stage == Stage::Search)
        .expect("search stage");
    assert_eq!(search.started, 1);
    assert_eq!(search.finished, 1);
    assert_eq!(search.dropped_updates, 1);
    assert_eq!(search.p99_upper_ns, None);

    let measurement = telemetry.begin(Stage::Execute);
    let stats = telemetry.0.stats.lock().expect("controlled lock");
    measurement.finish(Outcome::Completed);
    drop(stats);
    let snapshot = telemetry.snapshot().expect("recovered snapshot");
    let execute = snapshot
        .stages
        .iter()
        .find(|s| s.stage == Stage::Execute)
        .expect("execute stage");
    assert_eq!(execute.pending, Some(1));
    assert_eq!(execute.dropped_updates, 1);
    assert_eq!(execute.p99_upper_ns, None);
}

#[test]
fn dropped_work_is_cancelled_and_visible_while_pending() {
    let telemetry = Telemetry::default();
    let measurement = telemetry.begin(Stage::Execute);
    let snapshot = telemetry.snapshot().expect("pending snapshot");
    let execute = snapshot
        .stages
        .iter()
        .find(|s| s.stage == Stage::Execute)
        .expect("execute stage");
    assert_eq!(execute.pending, Some(1));
    assert_eq!(execute.p99_upper_ns, None);
    drop(measurement);
    let snapshot = telemetry.snapshot().expect("cancelled snapshot");
    let execute = snapshot
        .stages
        .iter()
        .find(|s| s.stage == Stage::Execute)
        .expect("execute stage");
    assert_eq!(execute.pending, Some(0));
    assert_eq!(execute.finished, 1);
    assert_eq!(
        execute
            .outcomes
            .iter()
            .find(|n| n.outcome == Outcome::Cancelled)
            .expect("cancelled outcome")
            .count,
        1
    );
}
