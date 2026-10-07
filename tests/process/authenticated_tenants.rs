//! Overlapping identities through the normal executable and a synthetic project policy.

use core::{fmt::Write as _, sync::atomic::Ordering, time::Duration};
use std::{fs, io};

use rustix::process::Signal;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::time::timeout;

use super::{
    Fixture, Process, TestResult, client, configure, envelope, multiplexed, request_with_token,
    tenant_backend::{Backend, Identity, Observations},
};

/// # Errors
///
/// Returns a configuration, file, JSON, digest-formatting or missing-field error.
fn configure_projects(fixture: &Fixture, endpoint: &str) -> TestResult<()> {
    configure(fixture, endpoint)?;
    drop(fixture.directory.write(
        "clients.json",
        br#"{"version":"1","clients":["synthetic-alpha-client","synthetic-beta-client"]}"#,
        0o600,
    )?);
    let catalog = serde_json::to_vec(&json!({"format_version":1_i32,"operations":[{
        "id":"logs.read.v1","info":{"summary":"Read logs","permission":"logs:read",
            "documentation":"https://docs.example/logs","stability":"stable","cost":"one read","safety":"read_only"},
        "input_schema":{"type":"object","required":["project"],"additionalProperties":false,
            "properties":{"project":{"type":"string","enum":["alpha","beta"]},
                "context":{"type":"object","maxProperties":8_i32,
                    "additionalProperties":{"type":"string","maxLength":256_i32}}}},
        "output_schema":{"type":"object","required":["project","record"],"additionalProperties":false,
            "properties":{"project":{"type":"string","enum":["alpha","beta"]},
                "record":{"type":"string","maxLength":32_i32}}}
    }]}))?;
    let catalog_file = fixture.directory.write("catalog.json", &catalog, 0o644)?;
    let mut digest = String::new();
    for byte in Sha256::digest(&catalog) {
        write!(digest, "{byte:02x}")?;
    }
    let mut config: Value = serde_json::from_slice(&fs::read(&fixture.config)?)?;
    for (field, value) in [
        ("catalog_file", json!(catalog_file)),
        ("catalog_sha256", json!(digest)),
    ] {
        *config
            .get_mut(field)
            .ok_or_else(|| io::Error::other("missing catalog field"))? = value;
    }
    fs::write(&fixture.config, serde_json::to_vec(&config)?)?;
    Ok(())
}

enum Mode {
    Http1,
    Http2,
    SharedHttp2,
}

enum Transport {
    Http1(reqwest::Client),
    Http2(reqwest::Client),
    SharedHttp2(multiplexed::Connection),
}

struct Execution<'a> {
    transport: Transport,
    resource: &'a str,
}

impl Execution<'_> {
    /// # Errors
    ///
    /// Returns a request, HTTP/2 exchange, body-read, decoding or timeout error.
    ///
    /// # Panics
    ///
    /// Panics if the response transport, cache policy, session isolation,
    /// rejection body or private-field redaction changes.
    // Reviewed 2026-10-07; review by 2026-11-07 or on source/toolchain change.
    #[expect(
        clippy::ref_patterns,
        reason = "Shared enum fields must remain borrowed while concurrent identity requests use the same transport."
    )]
    async fn run(
        &self,
        identity: Identity,
        project: &str,
    ) -> TestResult<(reqwest::StatusCode, Value)> {
        let context = match identity {
            Identity::Alpha => json!({"token":Identity::Beta.token(),
                "client_id":"synthetic-beta-client","credential_id":"synthetic-beta-credential"}),
            Identity::Beta | Identity::Rejected => json!({"token":Identity::Alpha.token(),
                "client_id":"synthetic-alpha-client","credential_id":"synthetic-alpha-credential"}),
        };
        let params = json!({"name":"execute","arguments":{"operation":"logs.read.v1",
            "input":{"project":project,"context":context}}});
        match self.transport {
            Transport::Http1(ref http) | Transport::Http2(ref http) => {
                request_with_token(
                    http,
                    self.resource,
                    "tools/call",
                    params,
                    matches!(self.transport, Transport::Http2(_)),
                    identity.token(),
                )
                .await
            }
            Transport::SharedHttp2(ref connection) => {
                connection
                    .execute(self.resource, params, identity.token())
                    .await
            }
        }
    }
}

/// # Errors
///
/// Returns an error if the tool envelope lacks required fields or has invalid JSON.
///
/// # Panics
///
/// Panics if the result differs from the selected project or its tool envelope
/// violates the error, text, structured content or provenance contract.
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
fn result(reply: &Value, project: &str) -> TestResult<()> {
    assert_eq!(
        envelope(reply, None)?.get("data"),
        Some(&json!({"project":project,"record":format!("{project}-result")}))
    );
    Ok(())
}

/// # Errors
///
/// Returns a request, envelope or timeout error, or an error if the alpha request
/// completes before verification is released.
///
/// # Panics
///
/// Panics if beta access, cross-project denial, alpha isolation or its eventual
/// successful response changes.
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::integer_division_remainder_used,
    reason = "Tokio select wraps its branch polling index with remainder; this is not cryptographic arithmetic."
)]
async fn overlapping(execution: &Execution<'_>, observed: &Observations) -> TestResult<()> {
    let alpha = execution.run(Identity::Alpha, "alpha");
    tokio::pin!(alpha);
    timeout(Duration::from_secs(2), async {
        let waiting: TestResult<()> = tokio::select! {
            reply = &mut alpha => {
                drop(reply?);
                Err(io::Error::other("alpha completed before verification was released").into())
            }
            () = observed.alpha_entered().notified() => Ok(())
        };
        waiting
    })
    .await??;
    let (beta_status, beta) = execution.run(Identity::Beta, "beta").await?;
    assert_eq!(beta_status, reqwest::StatusCode::OK);
    result(&beta, "beta")?;
    let (denied_status, denied) = execution.run(Identity::Beta, "alpha").await?;
    assert_eq!(denied_status, reqwest::StatusCode::OK);
    assert_eq!(
        envelope(&denied, Some("permission_denied"))?.get("data"),
        Some(&Value::Null)
    );
    assert_eq!(
        observed
            .executes()
            .first()
            .map(|counter| counter.load(Ordering::SeqCst)),
        Some(0)
    );
    observed.alpha_release().notify_one();
    let (status, reply) = timeout(Duration::from_secs(2), alpha).await??;
    assert_eq!(status, reqwest::StatusCode::OK);
    result(&reply, "alpha")?;
    Ok(())
}

/// # Errors
///
/// Returns a fixture, file, configuration, process, connection, request, timeout,
/// envelope or shutdown error.
///
/// # Panics
///
/// Panics if overlapping identities, project denial, revocation, client rejection,
/// recovery, call counts or executable shutdown changes.
async fn isolation_and_recovery(mode: Mode) -> TestResult<()> {
    let fixture = Fixture::new()?;
    let resource = format!("https://localhost:{}/mcp", fixture.address.port());
    let mut upstream = Backend::start(resource.clone()).await?;
    configure_projects(&fixture, upstream.endpoint())?;
    let roots = fixture.directory.write(
        "upstream-root.pem",
        upstream.certificate().as_bytes(),
        0o600,
    )?;
    let mut process = Process::start_with_roots(&fixture.config, Some(&roots))?;
    fixture.ready(&mut process).await?;
    let transport = match mode {
        Mode::Http1 => Transport::Http1(client(&fixture, false)?),
        Mode::Http2 => Transport::Http2(client(&fixture, true)?),
        Mode::SharedHttp2 => Transport::SharedHttp2(multiplexed::Connection::open(&fixture).await?),
    };
    let mut execution = Execution {
        transport,
        resource: &resource,
    };
    overlapping(&execution, upstream.observations()).await?;
    upstream
        .observations()
        .alpha_active()
        .store(false, Ordering::SeqCst);
    let (revoked_status, _) = execution.run(Identity::Alpha, "alpha").await?;
    assert_eq!(revoked_status, reqwest::StatusCode::UNAUTHORIZED);
    let (healthy_status, beta) = execution.run(Identity::Beta, "beta").await?;
    assert_eq!(healthy_status, reqwest::StatusCode::OK);
    result(&beta, "beta")?;
    let (rejected_status, _) = execution.run(Identity::Rejected, "alpha").await?;
    assert_eq!(rejected_status, reqwest::StatusCode::FORBIDDEN);
    upstream
        .observations()
        .alpha_active()
        .store(true, Ordering::SeqCst);
    let (status, alpha) = execution.run(Identity::Alpha, "alpha").await?;
    assert_eq!(status, reqwest::StatusCode::OK);
    result(&alpha, "alpha")?;
    assert_eq!(
        upstream
            .observations()
            .verifies()
            .each_ref()
            .map(|counter| counter.load(Ordering::SeqCst)),
        [3, 3, 1]
    );
    assert_eq!(
        upstream
            .observations()
            .executes()
            .each_ref()
            .map(|counter| counter.load(Ordering::SeqCst)),
        [2, 3, 0]
    );
    fixture.ready(&mut process).await?;
    if let Transport::SharedHttp2(ref mut connection) = execution.transport {
        connection.close().await?;
    }
    process.signal(Signal::TERM)?;
    assert!(process.wait().await?.success());
    drop(std::net::TcpListener::bind(fixture.address)?);
    upstream.finish().await?;
    Ok(())
}

#[tokio::test]
/// # Errors
///
/// Returns an HTTP/1 tenant isolation error or an outer timeout.
///
/// # Panics
///
/// Panics if identity isolation, access control or recovery assertions fail.
async fn normal_linux_http1_concurrent_identity_isolation_and_recovery() -> TestResult<()> {
    timeout(Duration::from_secs(20), isolation_and_recovery(Mode::Http1)).await?
}

#[tokio::test]
/// # Errors
///
/// Returns an HTTP/2 tenant isolation error or an outer timeout.
///
/// # Panics
///
/// Panics if identity isolation, access control or recovery assertions fail.
async fn normal_linux_http2_concurrent_identity_isolation_and_recovery() -> TestResult<()> {
    timeout(Duration::from_secs(20), isolation_and_recovery(Mode::Http2)).await?
}

#[tokio::test]
/// # Errors
///
/// Returns a shared HTTP/2 tenant isolation error or an outer timeout.
///
/// # Panics
///
/// Panics if identity isolation, access control or recovery assertions fail.
async fn normal_linux_one_http2_connection_isolates_identities_and_recovers() -> TestResult<()> {
    timeout(
        Duration::from_secs(20),
        isolation_and_recovery(Mode::SharedHttp2),
    )
    .await?
}
