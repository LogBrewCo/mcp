//! Notification and invalid-ID isolation on a single real TLS connection.

use std::{future::Future, io, pin::Pin, sync::atomic::Ordering, time::Duration};

use axum::{
    body::{Body, to_bytes},
    http::{HeaderValue, Request, Response, StatusCode, Version},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Value, json};
use tokio::time::timeout;

use super::{
    http::{Fixture, TOKEN, request_message},
    runtime::Running,
};

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Connection = Pin<Box<dyn Future<Output = Result<(), hyper::Error>> + Send>>;

enum Sender {
    Http1(hyper::client::conn::http1::SendRequest<Body>),
    Http2(hyper::client::conn::http2::SendRequest<Body>),
}

impl Sender {
    async fn send(&mut self, request: Request<Body>) -> TestResult<Response<Body>> {
        let (response, version) = match self {
            Self::Http1(sender) => (sender.send_request(request).await?, Version::HTTP_11),
            Self::Http2(sender) => (sender.send_request(request).await?, Version::HTTP_2),
        };
        assert_eq!(response.version(), version);
        assert_eq!(
            response.headers().get("Cache-Control"),
            Some(&HeaderValue::from_static("no-store"))
        );
        assert!(response.headers().get("Mcp-Session-Id").is_none());
        Ok(response.map(Body::new))
    }
}

fn arguments() -> Value {
    json!({"name":"execute","arguments":{"operation":"logs.read.v1","input":{}}})
}

fn candidate(id: Option<Value>) -> TestResult<Request<Body>> {
    let mut request = request_message(0, "tools/call", arguments(), TOKEN)?;
    let mut params = arguments();
    drop(
        params
            .as_object_mut()
            .ok_or_else(|| io::Error::other("invalid fixture parameters"))?
            .insert(
                "_meta".to_owned(),
                json!({
                    "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities":{},
                    "org.example/marker":"SYNTHETIC_PRIVATE_MARKER"
                }),
            ),
    );
    let mut value = json!({"jsonrpc":"2.0","method":"tools/call","params":params});
    if let Some(id) = id {
        drop(
            value
                .as_object_mut()
                .ok_or_else(|| io::Error::other("invalid fixture message"))?
                .insert("id".to_owned(), id),
        );
    }
    *request.body_mut() = Body::from(serde_json::to_vec(&value)?);
    Ok(request)
}

async fn control(sender: &mut Sender, fixture: &Fixture, id: u64) -> TestResult<()> {
    let before = fixture.state.calls.load(Ordering::SeqCst);
    let response = sender
        .send(request_message(id, "tools/call", arguments(), TOKEN)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 4096).await?;
    let value: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(value.get("id"), Some(&json!(id)));
    assert_eq!(
        value.pointer("/result/structuredContent/data/count"),
        Some(&json!(3))
    );
    assert!(!String::from_utf8_lossy(&bytes).contains("SYNTHETIC_"));
    assert_eq!(
        Some(fixture.state.calls.load(Ordering::SeqCst)),
        before.checked_add(1)
    );
    Ok(())
}

async fn exercise(sender: &mut Sender, fixture: &Fixture) -> TestResult<()> {
    let cases = [
        None,
        Some(Value::Null),
        Some(json!(true)),
        Some(json!(false)),
        Some(json!(1.5)),
        Some(json!([])),
        Some(json!({})),
    ];
    let mut control_id = 1_u64;
    for id in cases {
        let notification = id.is_none();
        let calls = fixture.state.calls.load(Ordering::SeqCst);
        let verifies = fixture.state.verifies.load(Ordering::SeqCst);
        let response = sender.send(candidate(id)?).await?;
        let expected = if notification {
            StatusCode::ACCEPTED
        } else {
            StatusCode::BAD_REQUEST
        };
        assert_eq!(response.status(), expected);
        let bytes = to_bytes(response.into_body(), 4096).await?;
        if notification {
            assert!(bytes.is_empty());
        } else {
            let error: Value = serde_json::from_slice(&bytes)?;
            assert_eq!(error.pointer("/error/code"), Some(&json!(-32600)));
            assert!(error.get("id").is_none());
        }
        assert!(!String::from_utf8_lossy(&bytes).contains("SYNTHETIC_"));
        assert_eq!(fixture.state.calls.load(Ordering::SeqCst), calls);
        assert_eq!(
            Some(fixture.state.verifies.load(Ordering::SeqCst)),
            verifies.checked_add(1)
        );
        control(sender, fixture, control_id).await?;
        control_id = control_id
            .checked_add(1)
            .ok_or("fixture control ID overflow")?;
    }
    fixture.state.active.store(false, Ordering::SeqCst);
    let calls = fixture.state.calls.load(Ordering::SeqCst);
    let verifies = fixture.state.verifies.load(Ordering::SeqCst);
    let response = sender.send(candidate(None)?).await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get("WWW-Authenticate").is_some());
    let bytes = to_bytes(response.into_body(), 4096).await?;
    assert!(!String::from_utf8_lossy(&bytes).contains("SYNTHETIC_"));
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), calls);
    assert_eq!(
        Some(fixture.state.verifies.load(Ordering::SeqCst)),
        verifies.checked_add(1)
    );
    fixture.state.active.store(true, Ordering::SeqCst);
    control(sender, fixture, control_id).await
}

async fn verify(http2: bool) -> TestResult<()> {
    let fixture = Fixture::new().await?;
    let mut running = Running::start(fixture.router.clone()).await?;
    let protocol = if http2 { b"h2".as_slice() } else { b"http/1.1" };
    let stream = running.tls(Some(protocol)).await?;
    let (mut sender, connection): (Sender, Connection) = if http2 {
        let (sender, connection) = timeout(
            Duration::from_secs(2),
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)),
        )
        .await??;
        (Sender::Http2(sender), Box::pin(connection))
    } else {
        let (sender, connection) = timeout(
            Duration::from_secs(2),
            hyper::client::conn::http1::handshake(TokioIo::new(stream)),
        )
        .await??;
        (Sender::Http1(sender), Box::pin(connection))
    };
    timeout(Duration::from_secs(5), async {
        tokio::select! {
            biased;
            result = exercise(&mut sender, &fixture) => result,
            result = connection => {
                result?;
                Err(io::Error::other("connection ended before exchanges completed").into())
            }
        }
    })
    .await??;
    running.stop.cancel();
    running.wait().await
}

#[tokio::test]
async fn tls_http1_notifications_and_invalid_ids_never_execute_and_recover() -> TestResult<()> {
    verify(false).await
}

#[tokio::test]
async fn tls_http2_notifications_and_invalid_ids_never_execute_and_recover() -> TestResult<()> {
    verify(true).await
}
