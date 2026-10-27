//! Bounded process-local observations without request content or identity labels.
//!
//! These snapshots are not a delivery receipt or the centralized performance
//! contract. Callers must retain measurement loss and pending work when using them.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::{
    sync::{Mutex, OnceLock},
    time::{Instant, SystemTime},
};

use rustls::pki_types::CertificateDer;
use serde::Serialize;

use crate::{Failure, catalog::Catalog, error::Kind};

mod export;
mod operations;
mod snapshot;
pub use export::Exporter;
pub use operations::{CatalogSnapshot, OperationSnapshot};
pub use snapshot::{LatencyBucket, OutcomeCount, Snapshot, StageSnapshot};

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
    export: OnceLock<export::Sender>,
}

/// A bounded observer. Updates never wait for a lock or reject customer work.
#[derive(Clone)]
pub struct Telemetry(Arc<Inner>);

impl Default for Telemetry {
    fn default() -> Self {
        Self(Arc::new(Inner {
            epoch: Instant::now(),
            stats: Mutex::new([Stats::EMPTY; STAGES.len()]),
            losses: core::array::from_fn(|_| Loss::default()),
            operations: OnceLock::new(),
            export: OnceLock::new(),
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

    /// Also send each finished request, search, and execution to a `LogBrew`
    /// ingest endpoint. Run the returned exporter on the serving runtime.
    ///
    /// # Errors
    /// Rejects a second exporter, a non-canonical HTTPS endpoint, an unusable
    /// key, and TLS client configuration failures.
    pub fn export(
        &self,
        endpoint: &str,
        key: &[u8],
        certificate: Option<CertificateDer<'static>>,
    ) -> Result<Exporter, Failure> {
        let (sender, exporter) = export::channel(endpoint, key, certificate)?;
        self.0
            .export
            .set(sender)
            .map_err(|_unused| Failure::from(Kind::Configuration))?;
        Ok(exporter)
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
            operation: None,
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
    /// Verified catalog identifier of an execution.
    operation: Option<String>,
}

impl Measurement {
    pub(crate) fn operation(&mut self, id: &str) -> Option<operations::Measurement> {
        if self.stage != Stage::Execute {
            return None;
        }
        let measurement =
            self.telemetry
                .0
                .operations
                .get()?
                .begin(&self.telemetry, id, self.start)?;
        self.operation = Some(id.to_owned());
        Some(measurement)
    }

    pub(crate) fn finish(mut self, outcome: Outcome) {
        self.outcome = outcome;
    }
}

impl Drop for Measurement {
    fn drop(&mut self) {
        let elapsed = elapsed_since(self.start);
        if let Some(sender) = self.telemetry.0.export.get() {
            sender.send(export::Record::new(
                self.stage,
                self.operation.take(),
                self.outcome,
                elapsed,
                SystemTime::now(),
            ));
        }
        if !self.recorded {
            return;
        }
        if let Ok(mut stats) = self.telemetry.0.stats.try_lock()
            && let Some(stats) = stats.get_mut(self.stage.index())
        {
            stats.finish(self.outcome, elapsed);
        } else {
            self.telemetry.loss(self.stage);
        }
    }
}
