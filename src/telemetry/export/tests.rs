//! Exported events hold fixed labels, catalog identifiers, outcomes, and timing only.

use core::time::Duration;
use std::time::UNIX_EPOCH;

use serde_json::{Value, json};

use super::{Record, channel, events, rfc3339};
use crate::{
    error::Kind,
    telemetry::{Outcome, Stage, Telemetry},
};

/// # Panics
/// Panics if a known UTC instant, a leap day, or a century boundary formats differently.
#[test]
fn timestamps_use_utc_rfc3339_with_milliseconds() {
    for (seconds, millis, expected) in [
        (0, 0, "1970-01-01T00:00:00.000Z"),
        (951_868_799, 999, "2000-02-29T23:59:59.999Z"),
        (1_709_164_800, 0, "2024-02-29T00:00:00.000Z"),
        (1_792_356_702, 120, "2026-10-18T20:51:42.120Z"),
        (4_102_444_800, 5, "2100-01-01T00:00:00.005Z"),
    ] {
        let time = UNIX_EPOCH + Duration::from_secs(seconds) + Duration::from_millis(millis);
        assert_eq!(rfc3339(time), expected);
    }
}

/// # Panics
/// Panics if a span, its timing, or its labels change, or a caller fault opens an issue.
#[test]
fn a_request_is_one_span_and_a_caller_fault_is_not_an_issue() {
    let ended = UNIX_EPOCH + Duration::from_secs(1_792_356_702);
    let record = Record::new(
        Stage::RequestPrepared,
        None,
        Outcome::Unauthorized,
        Some(1_500_000_000),
        ended,
    );
    let events = events(&record, 0x1234, 7);
    assert_eq!(events.len(), 1);
    let span = events.first().expect("span");
    assert_eq!(
        span,
        &json!({"type":"span","id":"mcp-00000000000012340000000000000007",
            "timestamp":"2026-10-18T20:51:40.500Z","attributes":{
            "traceId":"00000000000012340000000000000007","spanId":"0000000000000007",
            "name":"mcp request","durationMs":1_500_u64,"status":"ok",
            "metadata":{"operation":"mcp.request","mcp.outcome":"unauthorized"},
            "context":{"schemaVersion":1_u8,"resource":{"service":{"name":"logbrew-mcp"},
                "runtime":{"name":"rust"},"deployment":{"environment":"production",
                "release":concat!("logbrew-mcp@", env!("CARGO_PKG_VERSION"))}},
                "trace":{"traceId":"00000000000012340000000000000007",
                    "spanId":"0000000000000007","sampled":true}}}})
    );
}

/// # Panics
/// Panics if a service fault loses its error span, its issue, or its catalog label.
#[test]
fn a_service_fault_is_an_error_span_and_an_issue_named_by_operation() {
    let record = Record::new(
        Stage::Execute,
        Some("logs.read.v1".to_owned()),
        Outcome::Unavailable,
        None,
        UNIX_EPOCH,
    );
    let events = events(&record, 1, 2);
    let kinds: Vec<_> = events
        .iter()
        .filter_map(|event| event.get("type"))
        .collect();
    assert_eq!(kinds, [&json!("span"), &json!("issue")]);
    let span = events.first().expect("span");
    assert_eq!(
        span.pointer("/attributes/status").and_then(Value::as_str),
        Some("error")
    );
    assert_eq!(
        span.pointer("/attributes/metadata"),
        Some(
            &json!({"operation":"mcp.execute","mcp.outcome":"unavailable",
            "mcp.operation":"logs.read.v1","mcp.timing":"unavailable"})
        )
    );
    let issue = events.get(1).expect("issue");
    assert_eq!(
        issue.pointer("/attributes/title").and_then(Value::as_str),
        Some("mcp execute logs.read.v1 unavailable")
    );
    assert_eq!(
        issue
            .pointer("/attributes/exception/type")
            .and_then(Value::as_str),
        Some("McpRequestFailed")
    );
}

/// # Panics
/// Panics if internal stages are exported.
#[test]
fn internal_stages_are_not_exported() {
    for stage in [
        Stage::Introspection,
        Stage::UpstreamExecute,
        Stage::ResponseRetained,
    ] {
        let record = Record::new(stage, None, Outcome::Unavailable, Some(1), UNIX_EPOCH);
        assert_eq!(events(&record, 1, 1), Vec::<Value>::new());
    }
}

/// # Panics
/// Panics if an unusable endpoint or key, or a second exporter, is accepted.
#[test]
fn exporters_need_an_https_endpoint_a_printable_key_and_one_owner() {
    for (endpoint, key) in [
        (
            "http://localhost/v1/events",
            b"SYNTHETIC_INGEST_KEY".as_slice(),
        ),
        ("https://localhost/v1/events", b"".as_slice()),
        ("https://localhost/v1/events", b"SYNTHETIC KEY".as_slice()),
        ("https://localhost/v1/events", b"SYNTHETIC_KEY\n".as_slice()),
    ] {
        let failure = channel(endpoint, key, None).expect_err("rejected exporter");
        assert_eq!(failure.kind, Kind::Configuration);
    }
    let telemetry = Telemetry::default();
    let exporter = telemetry
        .export("https://localhost/v1/events", b"SYNTHETIC_INGEST_KEY", None)
        .expect("exporter");
    assert_eq!(format!("{exporter:?}"), "telemetry exporter [redacted]");
    let failure = telemetry
        .export("https://localhost/v1/events", b"SYNTHETIC_INGEST_KEY", None)
        .expect_err("second exporter");
    assert_eq!(failure.kind, Kind::Configuration);
}
