//! Exercise the normal executable through the stock Rust SDK's HTTP client.

use core::{sync::atomic::Ordering, time::Duration};
use std::io;

use rmcp::{
    ClientLifecycleMode, ClientServiceExt as _,
    model::{
        CallToolRequest, CallToolRequestParams, CallToolResult, ClientConfig, ClientRequest,
        ProtocolVersion,
    },
    service::{PeerRequestOptions, RoleClient, RunningService},
    transport::{
        StreamableHttpClientTransport, streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use rustix::process::Signal;
use serde_json::{Value, json};
use tokio::time::timeout;

use super::{
    Fixture, Process, TestResult,
    backend::{self, PendingStage},
    client, configure, envelope,
};

type Client = RunningService<RoleClient, ClientConfig>;

struct Connected {
    fixture: Fixture,
    process: Process,
    upstream: backend::Backend,
    sdk: Client,
}

/// # Errors
///
/// Returns a fixture, configuration, process, client, SDK discovery or missing
/// peer-information error.
///
/// # Panics
///
/// Panics if the stock SDK discovers a different protocol version.
async fn connect(http2: bool) -> TestResult<Connected> {
    let fixture = Fixture::new()?;
    let resource = format!("https://localhost:{}/mcp", fixture.address.port());
    let upstream = backend::Backend::start(resource.clone()).await?;
    configure(&fixture, upstream.endpoint())?;
    let roots = fixture.directory.write(
        "upstream-root.pem",
        upstream.certificate().as_bytes(),
        0o600,
    )?;
    let mut process = Process::start_with_roots(&fixture.config, Some(&roots))?;
    fixture.ready(&mut process).await?;
    let config = StreamableHttpClientTransportConfig::with_uri(resource)
        .auth_header(backend::TOKEN)
        .max_concurrent_requests(2)
        .control_request_timeout(Duration::from_secs(1))
        .reinit_on_expired_session(false);
    let transport = StreamableHttpClientTransport::with_client(client(&fixture, http2)?, config);
    let sdk = ClientConfig::default()
        .serve_with_lifecycle(
            transport,
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await?;
    assert_eq!(
        sdk.peer_info()
            .ok_or_else(|| io::Error::other("missing peer discovery"))?
            .protocol_version,
        ProtocolVersion::V_2026_07_28
    );
    Ok(Connected {
        fixture,
        process,
        upstream,
        sdk,
    })
}

impl Connected {
    /// # Errors
    ///
    /// Returns an SDK cancellation, process signal, wait, port-bind or upstream
    /// shutdown error.
    ///
    /// # Panics
    ///
    /// Panics if the normal executable exits unsuccessfully.
    async fn finish(self) -> TestResult<()> {
        let Self {
            fixture,
            mut process,
            mut upstream,
            sdk,
        } = self;
        drop(sdk.cancel().await?);
        process.signal(Signal::TERM)?;
        assert!(process.wait().await?.success());
        drop(std::net::TcpListener::bind(fixture.address)?);
        upstream.finish().await?;
        Ok(())
    }
}

/// # Errors
///
/// Returns an error if the tool arguments are not a JSON object.
fn tool(name: &'static str, arguments: Value) -> TestResult<CallToolRequestParams> {
    let Value::Object(arguments) = arguments else {
        return Err(io::Error::other("expected tool arguments").into());
    };
    Ok(CallToolRequestParams::new(name).with_arguments(arguments))
}

/// # Errors
///
/// Returns an error if the tool envelope lacks required fields or has invalid JSON.
///
/// # Panics
///
/// Panics if the result exposes a synthetic private marker or its error, text,
/// structured content or provenance contract changes.
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
fn result(reply: &CallToolResult, error: Option<&str>) -> TestResult<Value> {
    let reply = json!({"result":reply});
    assert!(!reply.to_string().contains("SYNTHETIC"));
    envelope(&reply, error)
}

/// # Errors
///
/// Returns a connection, SDK request, tool argument, envelope, revocation or
/// shutdown error.
///
/// # Panics
///
/// Panics if tool discovery, search, execution, input rejection, revocation,
/// private-field redaction or recovery changes.
async fn contracts(http2: bool) -> TestResult<()> {
    let connected = connect(http2).await?;
    let inventory = connected.sdk.list_tools(None).await?;
    let names: Vec<_> = inventory
        .tools
        .iter()
        .map(|tool| tool.name.as_ref())
        .collect();
    assert_eq!(names, ["search", "execute"]);
    assert_eq!(
        inventory
            .tools
            .first()
            .and_then(|tool| tool.annotations.as_ref())
            .map(|hints| (hints.read_only_hint, hints.open_world_hint)),
        Some((Some(true), Some(false)))
    );
    assert!(
        inventory
            .tools
            .get(1)
            .and_then(|tool| tool.annotations.as_ref())
            .is_none()
    );
    let search = connected
        .sdk
        .call_tool(tool("search", json!({"query":"logs","limit":1_i32}))?)
        .await?;
    assert_eq!(
        result(&search, None)?.pointer("/data/operations/0/id"),
        Some(&json!("logs.read.v1"))
    );
    let execution = tool("execute", json!({"operation":"logs.read.v1","input":{}}))?;
    let reply = connected.sdk.call_tool(execution.clone()).await?;
    assert_eq!(
        result(&reply, None)?.pointer("/data/count"),
        Some(&json!(3_i32))
    );
    let rejected = connected
        .sdk
        .call_tool(tool(
            "execute",
            json!({"operation":"logs.read.v1","input":{"token":"SYNTHETIC_PRIVATE_MARKER"}}),
        )?)
        .await?;
    drop(result(&rejected, Some("invalid_input"))?);
    connected
        .upstream
        .observations()
        .active()
        .store(false, Ordering::SeqCst);
    let _rejected = connected
        .sdk
        .call_tool(execution.clone())
        .await
        .err()
        .ok_or("revoked credential unexpectedly accepted")?;
    assert_eq!(
        connected
            .upstream
            .observations()
            .executes()
            .load(Ordering::SeqCst),
        1
    );
    connected
        .upstream
        .observations()
        .active()
        .store(true, Ordering::SeqCst);
    let recovered = connected.sdk.call_tool(execution).await?;
    assert_eq!(
        result(&recovered, None)?.pointer("/data/count"),
        Some(&json!(3_i32))
    );
    assert_eq!(
        connected
            .upstream
            .observations()
            .verifies()
            .load(Ordering::SeqCst),
        7
    );
    assert_eq!(
        connected
            .upstream
            .observations()
            .executes()
            .load(Ordering::SeqCst),
        2
    );
    connected.finish().await
}

/// # Errors
///
/// Returns a connection, SDK request, cancellation, timeout, envelope or shutdown
/// error.
///
/// # Panics
///
/// Panics if cancellation leaves upstream work, recovery returns the wrong result
/// or verification and execution counts change.
async fn cancellation(http2: bool, stage: PendingStage) -> TestResult<()> {
    let connected = connect(http2).await?;
    connected.upstream.observations().set_pause(stage, true);
    let execution = tool("execute", json!({"operation":"logs.read.v1","input":{}}))?;
    let pending = connected
        .sdk
        .send_cancellable_request(
            ClientRequest::CallToolRequest(CallToolRequest::new(execution.clone())),
            PeerRequestOptions::no_options(),
        )
        .await?;
    connected
        .upstream
        .observations()
        .wait_for_pending(stage, 1)
        .await?;
    timeout(Duration::from_secs(2), pending.cancel(None)).await??;
    connected
        .upstream
        .observations()
        .wait_for_pending(stage, 0)
        .await?;
    let executions = usize::from(matches!(stage, PendingStage::Execution));
    assert_eq!(
        connected
            .upstream
            .observations()
            .verifies()
            .load(Ordering::SeqCst),
        2
    );
    assert_eq!(
        connected
            .upstream
            .observations()
            .executes()
            .load(Ordering::SeqCst),
        executions
    );
    connected.upstream.observations().set_pause(stage, false);
    let reply = connected.sdk.call_tool(execution).await?;
    assert_eq!(
        result(&reply, None)?.pointer("/data/count"),
        Some(&json!(3_i32))
    );
    assert_eq!(
        connected
            .upstream
            .observations()
            .verifies()
            .load(Ordering::SeqCst),
        3
    );
    assert_eq!(
        Some(
            connected
                .upstream
                .observations()
                .executes()
                .load(Ordering::SeqCst)
        ),
        executions.checked_add(1)
    );
    connected.finish().await
}

#[tokio::test]
/// # Errors
///
/// Returns an HTTP/1 SDK contract error or an outer timeout.
///
/// # Panics
///
/// Panics if stock SDK discovery, execution, privacy or recovery assertions fail.
async fn normal_linux_stock_sdk_http1_contracts() -> TestResult<()> {
    timeout(Duration::from_secs(20), contracts(false)).await?
}

#[tokio::test]
/// # Errors
///
/// Returns an HTTP/2 SDK contract error or an outer timeout.
///
/// # Panics
///
/// Panics if stock SDK discovery, execution, privacy or recovery assertions fail.
async fn normal_linux_stock_sdk_http2_contracts() -> TestResult<()> {
    timeout(Duration::from_secs(20), contracts(true)).await?
}

#[tokio::test]
/// # Errors
///
/// Returns an HTTP/1 SDK cancellation error or an outer timeout.
///
/// # Panics
///
/// Panics if execution cancellation or recovery assertions fail.
async fn normal_linux_stock_sdk_http1_cancellation_and_recovery() -> TestResult<()> {
    timeout(
        Duration::from_secs(20),
        cancellation(false, PendingStage::Execution),
    )
    .await?
}

#[tokio::test]
/// # Errors
///
/// Returns an HTTP/2 SDK cancellation error or an outer timeout.
///
/// # Panics
///
/// Panics if execution cancellation or recovery assertions fail.
async fn normal_linux_stock_sdk_http2_cancellation_and_recovery() -> TestResult<()> {
    timeout(
        Duration::from_secs(20),
        cancellation(true, PendingStage::Execution),
    )
    .await?
}

#[tokio::test]
/// # Errors
///
/// Returns an HTTP/1 SDK verification cancellation error or an outer timeout.
///
/// # Panics
///
/// Panics if pending verification cancellation or recovery assertions fail.
async fn normal_linux_stock_sdk_http1_pending_verification_cancellation() -> TestResult<()> {
    timeout(
        Duration::from_secs(20),
        cancellation(false, PendingStage::Verification),
    )
    .await?
}

#[tokio::test]
/// # Errors
///
/// Returns an HTTP/2 SDK verification cancellation error or an outer timeout.
///
/// # Panics
///
/// Panics if pending verification cancellation or recovery assertions fail.
async fn normal_linux_stock_sdk_http2_pending_verification_cancellation() -> TestResult<()> {
    timeout(
        Duration::from_secs(20),
        cancellation(true, PendingStage::Verification),
    )
    .await?
}
