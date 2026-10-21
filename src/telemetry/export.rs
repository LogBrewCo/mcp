//! Optional delivery of request outcomes to a `LogBrew` project.
//!
//! A record holds a fixed stage, a verified catalog operation identifier, a
//! fixed outcome, and timing. It never holds tool arguments, results, tokens,
//! client identity, or error text.

use alloc::sync::Arc;
use core::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::HeaderValue;
use rustls::pki_types::CertificateDer;
use serde_json::{Map, Value, json};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::{Outcome, Stage};
use crate::{Failure, deadline, error::Kind, outbound::Outbound, upstream::canonical_https};

#[cfg(test)]
mod tests;

/// Records waiting for delivery; a full queue drops and counts new records.
const QUEUE: usize = 1024;
/// Events in one ingest request.
const BATCH: usize = 100;
/// Pause after each delivery, so one request carries every record of that time.
const PAUSE: Duration = Duration::from_secs(1);
/// Budget for one delivery, connection included.
const DELIVERY: Duration = Duration::from_secs(10);

/// One finished stage without request content.
#[derive(Debug)]
pub struct Record {
    stage: Stage,
    /// Identifier from the verified catalog, never a caller-supplied label.
    operation: Option<String>,
    outcome: Outcome,
    duration_ns: Option<u64>,
    ended: SystemTime,
}

impl Record {
    /// A stage that ended at `ended`, after `duration_ns` when its timing is known.
    pub const fn new(
        stage: Stage,
        operation: Option<String>,
        outcome: Outcome,
        duration_ns: Option<u64>,
        ended: SystemTime,
    ) -> Self {
        Self {
            stage,
            operation,
            outcome,
            duration_ns,
            ended,
        }
    }
}

/// Sending side kept by the observer. Sends never wait.
#[derive(Debug)]
pub(super) struct Sender {
    records: mpsc::Sender<Record>,
    dropped: Arc<AtomicU64>,
}

impl Sender {
    pub(super) fn send(&self, record: Record) {
        if self.records.try_send(record).is_err() {
            let _previous = self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Delivers records in batches until the observer is dropped.
pub struct Exporter {
    records: mpsc::Receiver<Record>,
    dropped: Arc<AtomicU64>,
    client: Outbound,
    endpoint: String,
    authorization: HeaderValue,
    boot: u64,
    sequence: u64,
}

impl core::fmt::Debug for Exporter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("telemetry exporter [redacted]")
    }
}

/// Build the sending and delivering sides for one HTTPS ingest endpoint.
///
/// # Errors
/// Rejects a non-canonical HTTPS endpoint, a key that is empty or not a valid
/// header value, and TLS client configuration failures.
pub(super) fn channel(
    endpoint: &str,
    key: &[u8],
    certificate: Option<CertificateDer<'static>>,
) -> Result<(Sender, Exporter), Failure> {
    drop(canonical_https(endpoint)?);
    let key = core::str::from_utf8(key).map_err(Failure::redact(Kind::Configuration))?;
    if key.is_empty() || key.bytes().any(|byte| !byte.is_ascii_graphic()) {
        return Err(Kind::Configuration.into());
    }
    let header = Zeroizing::new(format!("Bearer {key}"));
    let mut authorization =
        HeaderValue::from_str(&header).map_err(Failure::redact(Kind::Configuration))?;
    authorization.set_sensitive(true);
    let (records, receiver) = mpsc::channel(QUEUE);
    let dropped = Arc::new(AtomicU64::new(0));
    let boot = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok())
        .unwrap_or_default();
    Ok((
        Sender {
            records,
            dropped: Arc::clone(&dropped),
        },
        Exporter {
            records: receiver,
            dropped,
            client: Outbound::new(certificate)?,
            endpoint: endpoint.to_owned(),
            authorization,
            boot,
            sequence: 0,
        },
    ))
}

impl Exporter {
    /// Send waiting records, at most one request per second, until the
    /// observer closes. A failed request drops its records and counts them;
    /// the next request reports the count.
    pub async fn run(mut self) {
        let mut batch = Vec::with_capacity(BATCH);
        while self.records.recv_many(&mut batch, BATCH).await > 0 {
            let dropped = self.dropped.swap(0, Ordering::Relaxed);
            let body = self.encode(&batch, dropped);
            let count = u64::try_from(batch.len()).unwrap_or(u64::MAX);
            batch.clear();
            let lost = self.deliver(body, dropped.saturating_add(count)).await;
            let _previous = self.dropped.fetch_add(lost, Ordering::Relaxed);
            tokio::time::sleep(PAUSE).await;
        }
    }

    /// One bounded request. Returns `lost` unless the endpoint accepted it.
    async fn deliver(&self, body: Vec<u8>, lost: u64) -> u64 {
        let sending = self.client.post(
            &self.endpoint,
            self.authorization.clone(),
            "application/json",
            body,
        );
        let accepted = deadline::within(DELIVERY, sending)
            .await
            .and_then(Result::ok)
            .is_some_and(|response| response.status().is_success());
        if accepted { 0 } else { lost }
    }

    fn encode(&mut self, batch: &[Record], dropped: u64) -> Vec<u8> {
        let events: Vec<Value> = batch
            .iter()
            .flat_map(|record| {
                self.sequence = self.sequence.wrapping_add(1);
                events(record, self.boot, self.sequence)
            })
            .collect();
        let report = (dropped > 0).then(|| json!({"dropped_events": {"telemetry_lost": dropped}}));
        let document = json!({
            "sdk": {"name": "logbrew-mcp", "language": "rust", "version": env!("CARGO_PKG_VERSION")},
            "events": events,
            "client_report": report,
        });
        serde_json::to_vec(&document).unwrap_or_default()
    }
}

/// Outcomes caused by this service or what it depends on, not by the caller.
const fn fault(outcome: Outcome) -> bool {
    matches!(
        outcome,
        Outcome::Configuration | Outcome::InvalidOutput | Outcome::Unavailable | Outcome::Deadline
    )
}

/// A span for each record, and an issue for a service fault.
pub fn events(record: &Record, boot: u64, sequence: u64) -> Vec<Value> {
    let (kind, name) = match record.stage {
        Stage::RequestPrepared => ("request", "mcp request".to_owned()),
        Stage::Search => ("search", "mcp search".to_owned()),
        Stage::Execute => (
            "execute",
            record.operation.as_ref().map_or_else(
                || "mcp execute".to_owned(),
                |operation| format!("mcp execute {operation}"),
            ),
        ),
        Stage::Introspection | Stage::UpstreamExecute | Stage::ResponseRetained => {
            return Vec::new();
        }
    };
    let outcome = serde_json::to_value(record.outcome).unwrap_or(Value::Null);
    let duration = record.duration_ns.unwrap_or_default();
    let started = record
        .ended
        .checked_sub(Duration::from_nanos(duration))
        .unwrap_or(record.ended);
    let trace = format!("{boot:016x}{sequence:016x}");
    let span = format!("{:016x}", sequence.max(1));
    let mut metadata = Map::new();
    drop(metadata.insert("operation".to_owned(), json!(format!("mcp.{kind}"))));
    drop(metadata.insert("mcp.outcome".to_owned(), outcome.clone()));
    if let Some(operation) = record.operation.as_ref() {
        drop(metadata.insert("mcp.operation".to_owned(), json!(operation)));
    }
    if record.duration_ns.is_none() {
        drop(metadata.insert("mcp.timing".to_owned(), json!("unavailable")));
    }
    let context = json!({
        "schemaVersion": 1_u8,
        "resource": {"service": {"name": "logbrew-mcp"}, "runtime": {"name": "rust"},
            "deployment": {"environment": "production",
                "release": concat!("logbrew-mcp@", env!("CARGO_PKG_VERSION"))}},
        "trace": {"traceId": trace, "spanId": span, "sampled": true},
    });
    let failed = fault(record.outcome);
    let mut events = vec![json!({
        "type": "span",
        "id": format!("mcp-{trace}"),
        "timestamp": rfc3339(started),
        "attributes": {
            "traceId": trace, "spanId": span, "name": name,
            "durationMs": duration.checked_div(1_000_000).unwrap_or_default(),
            "status": if failed { "error" } else { "ok" },
            "metadata": metadata, "context": context,
        },
    })];
    if failed {
        let title = format!("{name} {}", outcome.as_str().unwrap_or("failed"));
        events.push(json!({
            "type": "issue",
            "id": format!("mcp-{trace}-issue"),
            "timestamp": rfc3339(record.ended),
            "attributes": {
                "level": "error", "title": title, "message": title,
                "exception": {"type": "McpRequestFailed"},
                "metadata": metadata, "context": context,
            },
        }));
    }
    events
}

/// UTC RFC 3339 with milliseconds; times before 1970 become the epoch.
pub fn rfc3339(time: SystemTime) -> String {
    let elapsed = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let seconds = elapsed.as_secs();
    let days = seconds.wrapping_div(86_400);
    let day_seconds = seconds.wrapping_rem(86_400);
    // Civil date from days since 1970-01-01 (proleptic Gregorian).
    let shifted = days.wrapping_add(719_468);
    let era = shifted.wrapping_div(146_097);
    let day_of_era = shifted.wrapping_sub(era.wrapping_mul(146_097));
    let year_of_era = day_of_era
        .wrapping_sub(day_of_era.wrapping_div(1_460))
        .wrapping_add(day_of_era.wrapping_div(36_524))
        .wrapping_sub(day_of_era.wrapping_div(146_096))
        .wrapping_div(365);
    let day_of_year = day_of_era.wrapping_sub(
        year_of_era
            .wrapping_mul(365)
            .wrapping_add(year_of_era.wrapping_div(4))
            .wrapping_sub(year_of_era.wrapping_div(100)),
    );
    let month_index = day_of_year
        .wrapping_mul(5)
        .wrapping_add(2)
        .wrapping_div(153);
    let day = day_of_year
        .wrapping_sub(
            month_index
                .wrapping_mul(153)
                .wrapping_add(2)
                .wrapping_div(5),
        )
        .wrapping_add(1);
    let month = if month_index < 10 {
        month_index.wrapping_add(3)
    } else {
        month_index.wrapping_sub(9)
    };
    let year = year_of_era
        .wrapping_add(era.wrapping_mul(400))
        .wrapping_add(u64::from(month <= 2));
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        day_seconds.wrapping_div(3_600),
        day_seconds.wrapping_rem(3_600).wrapping_div(60),
        day_seconds.wrapping_rem(60),
        elapsed.subsec_millis(),
    )
}
