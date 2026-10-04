//! Observe upstream termination after an authenticated HTTP request disconnects.

use std::{sync::atomic::Ordering, time::Duration};

use rustix::process::Signal;
use serde_json::json;
use tokio::time::timeout;

use super::backend::PendingStage;

use super::{Fixture, Process, TestResult, backend, client, configure, envelope, request};

async fn contracts(http2: bool, stage: PendingStage) -> TestResult<()> {
    let fixture = Fixture::new()?;
    let resource = format!("https://localhost:{}/mcp", fixture.address.port());
    let mut upstream = backend::Backend::start(resource.clone()).await?;
    configure(&fixture, &upstream.endpoint)?;
    let roots =
        fixture
            .directory
            .write("upstream-root.pem", upstream.certificate.as_bytes(), 0o600)?;
    let mut process = Process::start_with_roots(&fixture.config, Some(&roots))?;
    fixture.ready(&mut process).await?;
    let http = client(&fixture, http2)?;
    let execution = json!({"name":"execute", "arguments":{"operation":"logs.read.v1","input":{}}});
    upstream.observations.set_pause(stage, true);
    let pending = tokio::spawn({
        let http = http.clone();
        let resource = resource.clone();
        let execution = execution.clone();
        async move { request(&http, &resource, "tools/call", execution, http2).await }
    });
    upstream.observations.wait_for_pending(stage, 1).await?;
    pending.abort();
    assert!(pending.await.is_err_and(|error| error.is_cancelled()));
    upstream.observations.wait_for_pending(stage, 0).await?;
    let executions = usize::from(matches!(stage, PendingStage::Execution));
    assert_eq!(upstream.observations.verifies.load(Ordering::SeqCst), 1);
    assert_eq!(
        upstream.observations.executes.load(Ordering::SeqCst),
        executions
    );
    upstream.observations.set_pause(stage, false);
    let (status, reply) = request(&http, &resource, "tools/call", execution, http2).await?;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(
        envelope(&reply, None)?.pointer("/data/count"),
        Some(&json!(3_i32))
    );
    assert_eq!(upstream.observations.verifies.load(Ordering::SeqCst), 2);
    assert_eq!(
        Some(upstream.observations.executes.load(Ordering::SeqCst)),
        executions.checked_add(1)
    );
    assert_eq!(
        upstream
            .observations
            .pending_count(PendingStage::Verification),
        0
    );
    assert_eq!(
        upstream.observations.pending_count(PendingStage::Execution),
        0
    );
    fixture.ready(&mut process).await?;
    process.signal(Signal::TERM)?;
    assert!(process.wait().await?.success());
    drop(std::net::TcpListener::bind(fixture.address)?);
    upstream.finish().await?;
    Ok(())
}

#[tokio::test]
async fn normal_linux_http1_authenticated_cancellation_and_recovery() -> TestResult<()> {
    timeout(
        Duration::from_secs(20),
        contracts(false, PendingStage::Execution),
    )
    .await?
}

#[tokio::test]
async fn normal_linux_http2_authenticated_cancellation_and_recovery() -> TestResult<()> {
    timeout(
        Duration::from_secs(20),
        contracts(true, PendingStage::Execution),
    )
    .await?
}

#[tokio::test]
async fn normal_linux_http1_pending_verification_cancellation_and_recovery() -> TestResult<()> {
    timeout(
        Duration::from_secs(20),
        contracts(false, PendingStage::Verification),
    )
    .await?
}

#[tokio::test]
async fn normal_linux_http2_pending_verification_cancellation_and_recovery() -> TestResult<()> {
    timeout(
        Duration::from_secs(20),
        contracts(true, PendingStage::Verification),
    )
    .await?
}
