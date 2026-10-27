//! Serializable snapshots and the latency summary derived from recorded stages.

use serde::Serialize;

use super::{CatalogSnapshot, OUTCOMES, Outcome, Stage, Stats};

/// Draft process-local snapshot without tenant, identity, or request content.
#[derive(Debug, Serialize)]
pub struct Snapshot {
    /// Snapshot encoding version, separate from the centralized contract.
    /// Version 3 adds execution observations for the verified catalog inventory.
    pub format_version: u8,
    /// Monotonic observation window, unknown on a clock anomaly or overflow.
    pub window_ns: Option<u64>,
    /// The complete fixed stage inventory, including stages with no observations.
    pub stages: Vec<StageSnapshot>,
    /// Verified catalog inventory and execution observations. Absent before
    /// router construction or while its collector is busy or poisoned.
    pub operations: Option<CatalogSnapshot>,
}

/// One fixed stage with explicitly incomplete or saturated observations.
#[derive(Debug, Serialize)]
pub struct StageSnapshot {
    /// Timing boundary identifier.
    pub stage: Stage,
    /// Successfully recorded stage starts.
    pub started: u64,
    /// Successfully recorded finishes, including errors and cancellation.
    pub finished: u64,
    /// Finishes with a valid recorded duration.
    pub timed: u64,
    /// Starts without a recorded finish; may include a dropped finish update.
    pub pending: Option<u64>,
    /// Collector updates dropped because it could not acquire its lock.
    pub dropped_updates: u64,
    /// Counter overflow makes these observations incomplete.
    pub saturated: bool,
    /// At least one duration was unknown because of clock behavior or overflow.
    pub timing_unavailable: bool,
    /// Conservative p99 bucket upper bound, absent for incomplete or empty work.
    pub p99_upper_ns: Option<u64>,
    /// Maximum observed duration, absent when no finish was recorded.
    pub maximum_ns: Option<u64>,
    /// Fixed disjoint buckets that can be merged before calculating p99.
    pub latency_buckets: Vec<LatencyBucket>,
    /// Complete fixed outcome inventory, without caller-selected labels.
    pub outcomes: Vec<OutcomeCount>,
}

impl StageSnapshot {
    pub(super) fn new(
        stage: Stage,
        stats: &Stats,
        dropped_updates: u64,
        lost_overflow: bool,
    ) -> Self {
        let pending = stats.started.checked_sub(stats.finished);
        let saturated = stats.saturated || lost_overflow;
        let latency_buckets: Vec<_> = stats
            .histogram
            .into_iter()
            .enumerate()
            .map(|(index, count)| LatencyBucket {
                upper_ns: upper_bound(index),
                count,
            })
            .collect();
        let p99_upper_ns = if !saturated
            && !stats.timing_unavailable
            && stats.timed == stats.finished
            && dropped_updates == 0
            && pending == Some(0)
        {
            percentile(&latency_buckets, stats.finished)
        } else {
            None
        };
        Self {
            stage,
            started: stats.started,
            finished: stats.finished,
            timed: stats.timed,
            pending,
            dropped_updates,
            saturated,
            timing_unavailable: stats.timing_unavailable,
            p99_upper_ns,
            maximum_ns: (stats.timed > 0).then_some(stats.maximum_ns),
            latency_buckets,
            outcomes: OUTCOMES
                .into_iter()
                .zip(stats.outcomes)
                .map(|(outcome, count)| OutcomeCount { outcome, count })
                .collect(),
        }
    }
}

fn upper_bound(index: usize) -> u64 {
    if index == 0 {
        0
    } else {
        index
            .checked_sub(1)
            .and_then(|n| u32::try_from(n).ok())
            .and_then(|n| 1_u64.checked_shl(n))
            .unwrap_or(u64::MAX)
    }
}

pub(super) fn percentile(buckets: &[LatencyBucket], finished: u64) -> Option<u64> {
    if finished == 0
        || buckets
            .iter()
            .try_fold(0_u64, |n, bucket| n.checked_add(bucket.count))?
            != finished
    {
        return None;
    }
    let rank = finished.checked_sub(finished.checked_div(100)?)?;
    let mut cumulative = 0_u64;
    for bucket in buckets {
        cumulative = cumulative.checked_add(bucket.count)?;
        if cumulative >= rank {
            return Some(bucket.upper_ns);
        }
    }
    None
}

/// One disjoint latency bucket with a fixed inclusive upper bound.
#[derive(Debug, Serialize)]
pub struct LatencyBucket {
    /// Inclusive nanosecond upper bound; the last bucket ends at `u64::MAX`.
    pub upper_ns: u64,
    /// Observations in this bucket, rather than a cumulative count.
    pub count: u64,
}

/// Count for a fixed outcome.
#[derive(Debug, Serialize)]
pub struct OutcomeCount {
    /// Stable outcome category.
    pub outcome: Outcome,
    /// Recorded finishes with this outcome.
    pub count: u64,
}
