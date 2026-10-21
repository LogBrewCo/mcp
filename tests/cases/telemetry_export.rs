//! Exported request telemetry reaches an HTTPS ingest endpoint without request content.

use alloc::sync::Arc;
use core::time::Duration;
use std::{net::TcpListener, sync::Mutex};

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use rustls::pki_types::{CertificateDer, pem::PemObject as _};
use serde_json::{Value, json};

use crate::http::{Fixture, TOKEN};

const INGEST_KEY: &str = "SYNTHETIC_INGEST_KEY";

type Received = Arc<Mutex<Vec<(String, Value)>>>;

async fn receive(State(received): State<Received>, headers: HeaderMap, body: Bytes) -> StatusCode {
    let authorization = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let Ok(mut batches) = received.lock() else {
        return StatusCode::INTERNAL_SERVER_ERROR;
    };
    batches.push((authorization, value));
    StatusCode::ACCEPTED
}

fn events(received: &Received) -> Vec<Value> {
    received
        .lock()
        .map(|batches| {
            batches
                .iter()
                .filter_map(|entry| entry.1.get("events").and_then(Value::as_array))
                .flatten()
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

fn names(events: &[Value], kind: &str, field: &str) -> Vec<String> {
    let mut names: Vec<String> = events
        .iter()
        .filter(|event| event.get("type").and_then(Value::as_str) == Some(kind))
        .filter_map(|event| event.pointer(field).and_then(Value::as_str))
        .map(str::to_owned)
        .collect();
    names.sort();
    names
}

#[tokio::test]
/// # Panics
///
/// Panics if the exporter misses a request, an execution, or a service fault,
/// sends without its key, or sends request arguments, tokens, or client identity.
async fn exported_requests_carry_outcomes_and_catalog_operations_only() {
    let fixture = Fixture::new().await.expect("fixture");
    let listener = TcpListener::bind("127.0.0.1:0").expect("ingest listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let port = listener.local_addr().expect("ingest address").port();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("ingest certificate");
    let pem = certificate.cert.pem();
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        pem.as_bytes().to_vec(),
        certificate.signing_key.serialize_pem().as_bytes().to_vec(),
    )
    .await
    .expect("ingest TLS");
    let received = Received::default();
    let ingest = Router::new()
        .route("/v1/events", post(receive))
        .with_state(Arc::clone(&received));
    let server = tokio::spawn(
        axum_server::from_tcp_rustls(listener, tls)
            .expect("ingest server")
            .serve(ingest.into_make_service()),
    );
    let exporter = fixture
        .telemetry()
        .export(
            &format!("https://localhost:{port}/v1/events"),
            INGEST_KEY.as_bytes(),
            Some(CertificateDer::from_pem_slice(pem.as_bytes()).expect("certificate DER")),
        )
        .expect("exporter");
    let exporting = tokio::spawn(exporter.run());

    for params in [
        json!({"name":"execute","arguments":{"operation":"logs.read.v1","input":{
            "SYNTHETIC_PRIVATE_INPUT":"SYNTHETIC_PRIVATE_VALUE"}}}),
        json!({"name":"execute","arguments":{"operation":"SYNTHETIC_PRIVATE_OPERATION","input":{}}}),
    ] {
        let (status, _) = fixture
            .request("tools/call", params, TOKEN)
            .await
            .expect("tool call");
        assert_eq!(status, StatusCode::OK);
    }
    fixture
        .reply(
            StatusCode::SERVICE_UNAVAILABLE,
            String::new(),
            HeaderMap::new(),
        )
        .expect("failing upstream");
    let (status, _) = fixture
        .request(
            "tools/call",
            json!({"name":"execute","arguments":{"operation":"logs.read.v1","input":{}}}),
            TOKEN,
        )
        .await
        .expect("failed tool call");
    assert_eq!(status, StatusCode::OK);

    let mut waited = Duration::ZERO;
    while events(&received).len() < 7 && waited < Duration::from_secs(10) {
        tokio::time::sleep(Duration::from_millis(50)).await;
        waited += Duration::from_millis(50);
    }
    exporting.abort();
    server.abort();
    let events = events(&received);
    assert_eq!(
        names(&events, "span", "/attributes/name"),
        [
            "mcp execute",
            "mcp execute logs.read.v1",
            "mcp execute logs.read.v1",
            "mcp request",
            "mcp request",
            "mcp request",
        ]
    );
    assert_eq!(
        names(&events, "issue", "/attributes/title"),
        ["mcp execute logs.read.v1 unavailable"]
    );
    let batches = received.lock().expect("received batches").clone();
    assert!(
        batches
            .iter()
            .all(|entry| entry.0 == format!("Bearer {INGEST_KEY}"))
    );
    let text = Value::from(events).to_string();
    for prohibited in ["SYNTHETIC_", TOKEN, "synthetic-client", "resource.example"] {
        assert!(!text.contains(prohibited), "{prohibited} was exported");
    }
}
