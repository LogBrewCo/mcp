//! Execution observations whose labels come only from the verified catalog.

use std::{collections::BTreeMap, iter, sync::Mutex, time::Instant};

use serde::Serialize;

use super::{
    Loss, Ordering, Outcome, Stage, StageSnapshot, Stats, Telemetry, elapsed_since, increment,
};
use crate::catalog::Catalog;

#[cfg(test)]
mod tests;

pub(super) struct Inventory {
    digest: String,
    slots: BTreeMap<String, usize>,
    stats: Mutex<Vec<Stats>>,
    losses: Vec<Loss>,
}

impl Inventory {
    pub(super) fn new(catalog: &Catalog) -> Self {
        let slots: BTreeMap<_, _> = catalog
            .operation_ids()
            .enumerate()
            .map(|(index, id)| (id.to_owned(), index))
            .collect();
        Self {
            digest: catalog.definition_digest().to_owned(),
            stats: Mutex::new(vec![Stats::EMPTY; slots.len()]),
            losses: iter::repeat_with(Loss::default).take(slots.len()).collect(),
            slots,
        }
    }

    pub(super) fn begin(
        &self,
        telemetry: &Telemetry,
        id: &str,
        start: Instant,
    ) -> Option<Measurement> {
        // Unknown request strings never allocate storage or become labels.
        let index = *self.slots.get(id)?;
        let recorded = self.stats.try_lock().is_ok_and(|mut stats| {
            stats.get_mut(index).is_some_and(|stats| {
                increment(&mut stats.started, &mut stats.saturated);
                true
            })
        });
        if !recorded {
            self.loss(index);
        }
        Some(Measurement {
            telemetry: telemetry.clone(),
            index,
            start,
            recorded,
            outcome: Outcome::Cancelled,
        })
    }

    fn loss(&self, index: usize) {
        if let Some(loss) = self.losses.get(index) {
            loss.record();
        }
    }

    pub(super) fn snapshot(&self) -> Option<CatalogSnapshot> {
        let stats = self.stats.try_lock().ok()?.clone();
        let executions = self
            .slots
            .iter()
            .filter_map(|(id, index)| {
                let stats = stats.get(*index)?;
                let loss = self.losses.get(*index)?;
                Some(OperationSnapshot {
                    operation: id.clone(),
                    execution: StageSnapshot::new(
                        Stage::Execute,
                        stats,
                        loss.updates.load(Ordering::Relaxed),
                        loss.saturated.load(Ordering::Relaxed),
                    ),
                })
            })
            .collect();
        Some(CatalogSnapshot {
            definition_sha256: self.digest.clone(),
            executions,
        })
    }
}

pub struct Measurement {
    telemetry: Telemetry,
    index: usize,
    start: Instant,
    recorded: bool,
    outcome: Outcome,
}

impl Measurement {
    pub(crate) fn finish(mut self, outcome: Outcome) {
        self.outcome = outcome;
    }
}

impl Drop for Measurement {
    fn drop(&mut self) {
        if !self.recorded {
            return;
        }
        let Some(inventory) = self.telemetry.0.operations.get() else {
            return;
        };
        if let Ok(mut stats) = inventory.stats.try_lock()
            && let Some(stats) = stats.get_mut(self.index)
        {
            stats.finish(self.outcome, elapsed_since(self.start));
        } else {
            inventory.loss(self.index);
        }
    }
}

/// Complete immutable catalog inventory with process-local execution observations.
#[derive(Debug, Serialize)]
pub struct CatalogSnapshot {
    /// Definition digest of the verified catalog used by this router.
    pub definition_sha256: String,
    /// Every catalog operation, including operations with no observations.
    pub executions: Vec<OperationSnapshot>,
}

/// Execution observations for one identifier from the verified catalog.
#[derive(Debug, Serialize)]
pub struct OperationSnapshot {
    /// Stable public catalog identifier. Arbitrary request labels are excluded.
    pub operation: String,
    /// Execute handler entry through validation and the bounded result envelope.
    /// Outcomes, losses, and pending work follow the fixed stage contract.
    pub execution: StageSnapshot,
}
