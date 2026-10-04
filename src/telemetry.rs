//! Bounded process-local observations without request content or identity labels.
//!
//! These snapshots are not a delivery receipt or the centralized performance
//! contract. Callers must retain measurement loss and pending work when using them.

use std::{
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant,
};

use serde::Serialize;

use crate::{Failure, catalog::Catalog, error::Kind};

mod operations;
pub use operations::{CatalogSnapshot, OperationSnapshot};

#[cfg(test)]
mod tests;

const STAGES: [Stage; 6] = [
    Stage::RequestPrepared,
    Stage::Introspection,
    Stage::Search,
    Stage::Execute,
    Stage::UpstreamExecute,
    Stage::ResponseRetained,
];
const OUTCOMES: [Outcome; 14] = [
    Outcome::Completed,
    Outcome::Cancelled,
    Outcome::Deadline,
    Outcome::Rejected,
    Outcome::Configuration,
    Outcome::UnknownOperation,
    Outcome::Unauthorized,
    Outcome::PermissionDenied,
    Outcome::InvalidInput,
    Outcome::InvalidOutput,
    Outcome::Throttled,
    Outcome::NotFound,
    Outcome::Unavailable,
    Outcome::Released,
];

/// Fixed timing boundaries, independent of catalog operation identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Router entry until response headers and body are prepared, before delivery.
    RequestPrepared,
    /// Introspection entry through claim validation or failure.
    Introspection,
    /// Search handler entry through the bounded result envelope.
    Search,
    /// Execute handler entry through output validation and the bounded envelope.
    Execute,
    /// Upstream execution entry through bounded response parsing or failure.
    UpstreamExecute,
    /// Prepared response until its last admitted body or output-buffer owner drops.
    /// This boundary does not establish socket delivery or client receipt.
    ResponseRetained,
}

impl Stage {
    const fn index(self) -> usize {
        match self {
            Self::RequestPrepared => 0,
            Self::Introspection => 1,
            Self::Search => 2,
            Self::Execute => 3,
            Self::UpstreamExecute => 4,
            Self::ResponseRetained => 5,
        }
    }
}

/// Fixed outcomes with no error messages, credentials, or payload fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The measured stage completed successfully; this does not imply delivery.
    Completed,
    /// The future was dropped or explicit cancellation ended the stage.
    Cancelled,
    /// The measured stage's request or output-retention deadline expired.
    Deadline,
    /// A request failed a protocol or route check.
    Rejected,
    /// Operator configuration was invalid.
    Configuration,
    /// The operation was absent from the catalog.
    UnknownOperation,
    /// Credentials were rejected.
    Unauthorized,
    /// Authority did not permit access.
    PermissionDenied,
    /// Input violated its contract.
    InvalidInput,
    /// Output violated its contract.
    InvalidOutput,
    /// Capacity or quota was exhausted.
    Throttled,
    /// The selected resource was absent.
    NotFound,
    /// Availability or the operation outcome was unknown.
    Unavailable,
    /// Local output ownership ended; socket delivery and client receipt are unknown.
    Released,
}

impl Outcome {
    const fn index(self) -> usize {
        match self {
            Self::Completed => 0,
            Self::Cancelled => 1,
            Self::Deadline => 2,
            Self::Rejected => 3,
            Self::Configuration => 4,
            Self::UnknownOperation => 5,
            Self::Unauthorized => 6,
            Self::PermissionDenied => 7,
            Self::InvalidInput => 8,
            Self::InvalidOutput => 9,
            Self::Throttled => 10,
            Self::NotFound => 11,
            Self::Unavailable => 12,
            Self::Released => 13,
        }
    }

    pub(crate) const fn failure(kind: Kind) -> Self {
        match kind {
            Kind::Configuration => Self::Configuration,
            Kind::UnknownOperation => Self::UnknownOperation,
            Kind::Unauthorized => Self::Unauthorized,
            Kind::PermissionDenied => Self::PermissionDenied,
            Kind::InvalidInput => Self::InvalidInput,
            Kind::InvalidOutput => Self::InvalidOutput,
            Kind::Throttled => Self::Throttled,
            Kind::NotFound => Self::NotFound,
            Kind::Unavailable => Self::Unavailable,
        }
    }

    pub(crate) fn result<T>(result: &Result<T, Failure>) -> Self {
        result
            .as_ref()
            .map_or_else(|failure| Self::failure(failure.kind), |_| Self::Completed)
    }

    pub(crate) const fn status(status: u16) -> Self {
        match status {
            200..=299 => Self::Completed,
            401 => Self::Unauthorized,
            403 => Self::PermissionDenied,
            404 => Self::NotFound,
            429 => Self::Throttled,
            504 => Self::Deadline,
            500..=599 => Self::Unavailable,
            _ => Self::Rejected,
        }
    }
}

#[derive(Clone, Copy)]
struct Stats {
    started: u64,
    finished: u64,
    timed: u64,
    outcomes: [u64; OUTCOMES.len()],
    histogram: [u64; 66],
    maximum_ns: u64,
    saturated: bool,
    timing_unavailable: bool,
}

impl Stats {
    const EMPTY: Self = Self {
        started: 0,
        finished: 0,
        timed: 0,
        outcomes: [0; OUTCOMES.len()],
        histogram: [0; 66],
        maximum_ns: 0,
        saturated: false,
        timing_unavailable: false,
    };

    const fn begin(&mut self) {
        increment(&mut self.started, &mut self.saturated);
    }

    fn finish(&mut self, outcome: Outcome, elapsed: Option<u64>) {
        increment(&mut self.finished, &mut self.saturated);
        if let Some(count) = self.outcomes.get_mut(outcome.index()) {
            increment(count, &mut self.saturated);
        }
        let Some(elapsed) = elapsed else {
            self.timing_unavailable = true;
            return;
        };
        increment(&mut self.timed, &mut self.saturated);
        self.maximum_ns = self.maximum_ns.max(elapsed);
        let exponent = elapsed.saturating_sub(1).bit_width();
        let index = if elapsed == 0 {
            Some(0)
        } else {
            usize::try_from(exponent)
                .ok()
                .and_then(|n| n.checked_add(1))
        };
        if let Some(count) = index.and_then(|index| self.histogram.get_mut(index)) {
            increment(count, &mut self.saturated);
        } else {
            self.saturated = true;
        }
    }
}

const fn increment(count: &mut u64, saturated: &mut bool) {
    if let Some(next) = count.checked_add(1) {
        *count = next;
    } else {
        *saturated = true;
    }
}

fn elapsed_since(start: Instant) -> Option<u64> {
    let duration = Instant::now().checked_duration_since(start)?;
    u64::try_from(duration.as_nanos()).ok()
}

#[derive(Default)]
struct Loss {
    updates: AtomicU64,
    saturated: AtomicBool,
}

impl Loss {
    fn record(&self) {
        if self
            .updates
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .is_err()
        {
            self.saturated.store(true, Ordering::Relaxed);
        }
    }
}

struct Inner {
    epoch: Instant,
    stats: Mutex<[Stats; STAGES.len()]>,
    losses: [Loss; STAGES.len()],
    operations: OnceLock<operations::Inventory>,
}

/// A bounded observer. Updates never wait for a lock or reject customer work.
#[derive(Clone)]
pub struct Telemetry(Arc<Inner>);

impl Default for Telemetry {
    fn default() -> Self {
        Self(Arc::new(Inner {
            epoch: Instant::now(),
            stats: Mutex::new([Stats::EMPTY; STAGES.len()]),
            losses: std::array::from_fn(|_| Loss::default()),
            operations: OnceLock::new(),
        }))
    }
}

impl Telemetry {
    pub(crate) fn register_catalog(&self, catalog: &Catalog) {
        let _: &operations::Inventory = self
            .0
            .operations
            .get_or_init(|| operations::Inventory::new(catalog));
    }

    pub(crate) fn begin(&self, stage: Stage) -> Measurement {
        let start = Instant::now();
        let recorded = self
            .0
            .stats
            .try_lock()
            .is_ok_and(|mut stats| stats.get_mut(stage.index()).map(Stats::begin).is_some());
        if !recorded {
            self.loss(stage);
        }
        Measurement {
            telemetry: self.clone(),
            stage,
            start,
            recorded,
            outcome: Outcome::Cancelled,
        }
    }

    fn loss(&self, stage: Stage) {
        if let Some(loss) = self.0.losses.get(stage.index()) {
            loss.record();
        }
    }

    /// Copy bounded counts and mergeable latency buckets without waiting.
    ///
    /// Returns `None` when the collector is busy or poisoned. Pending work,
    /// dropped updates, and overflow suppress the p99 estimate. Buckets include
    /// failures and cancellations and never establish an end-to-end target pass.
    #[must_use]
    pub fn snapshot(&self) -> Option<Snapshot> {
        let (stats, window_ns) = {
            let stats = self.0.stats.try_lock().ok()?;
            (*stats, elapsed_since(self.0.epoch))
        };
        let stages = STAGES
            .into_iter()
            .zip(stats.iter())
            .filter_map(|(stage, stats)| {
                let loss = self.0.losses.get(stage.index())?;
                Some(StageSnapshot::new(
                    stage,
                    stats,
                    loss.updates.load(Ordering::Relaxed),
                    loss.saturated.load(Ordering::Relaxed),
                ))
            })
            .collect();
        Some(Snapshot {
            format_version: 3,
            window_ns,
            stages,
            operations: self
                .0
                .operations
                .get()
                .and_then(operations::Inventory::snapshot),
        })
    }
}

pub(crate) struct Measurement {
    telemetry: Telemetry,
    stage: Stage,
    start: Instant,
    recorded: bool,
    outcome: Outcome,
}

impl Measurement {
    pub(crate) fn operation(&self, id: &str) -> Option<operations::Measurement> {
        if self.stage != Stage::Execute {
            return None;
        }
        self.telemetry
            .0
            .operations
            .get()?
            .begin(&self.telemetry, id, self.start)
    }

    pub(crate) fn finish(mut self, outcome: Outcome) {
        self.outcome = outcome;
    }
}

impl Drop for Measurement {
    fn drop(&mut self) {
        if !self.recorded {
            return;
        }
        if let Ok(mut stats) = self.telemetry.0.stats.try_lock()
            && let Some(stats) = stats.get_mut(self.stage.index())
        {
            stats.finish(self.outcome, elapsed_since(self.start));
        } else {
            self.telemetry.loss(self.stage);
        }
    }
}

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
    fn new(stage: Stage, stats: &Stats, dropped_updates: u64, lost_overflow: bool) -> Self {
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

fn percentile(buckets: &[LatencyBucket], finished: u64) -> Option<u64> {
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
