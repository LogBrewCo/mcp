//! Overlapping identities through the normal executable and a synthetic project policy.

use std::{fmt::Write as _, fs, io, sync::atomic::Ordering, time::Duration};

use rustix::process::Signal;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::time::timeout;

use super::{
    Fixture, Process, TestResult, client, configure, envelope, request_with_token,
    tenant_backend::{Backend, Identity, Observations},
};

fn configure_projects(fixture: &Fixture, endpoint: &str) -> TestResult<()> {
    configure(fixture, endpoint)?;
    drop(fixture.directory.write(
        "clients.json",
        br#"{"version":"1","clients":["synthetic-alpha-client","synthetic-beta-client"]}"#,
        0o600,
    )?);
    let catalog = serde_json::to_vec(&json!({"format_version":1,"operations":[{
        "id":"logs.read.v1","info":{"summary":"Read logs","permission":"logs:read",
            "documentation":"https://docs.example/logs","stability":"stable","cost":"one read","safety":"read_only"},
        "input_schema":{"type":"object","required":["project"],"additionalProperties":false,
            "properties":{"project":{"type":"string","enum":["alpha","beta"]},
                "context":{"type":"object","maxProperties":8,
                    "additionalProperties":{"type":"string","maxLength":256}}}},
        "output_schema":{"type":"object","required":["project","record"],"additionalProperties":false,
            "properties":{"project":{"type":"string","enum":["alpha","beta"]},
                "record":{"type":"string","maxLength":32}}}
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

struct Execution<'a> {
    http: &'a reqwest::Client,
    resource: &'a str,
    http2: bool,
}

impl Execution<'_> {
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
        request_with_token(
            self.http,
            self.resource,
            "tools/call",
            json!({"name":"execute","arguments":{"operation":"logs.read.v1",
                "input":{"project":project,"context":context}}}),
            self.http2,
            identity.token(),
        )
        .await
    }
}

fn result(reply: &Value, project: &str) -> TestResult<()> {
    assert_eq!(
        envelope(reply, None)?.get("data"),
        Some(&json!({"project":project,"record":format!("{project}-result")}))
    );
    Ok(())
}

async fn overlapping(execution: &Execution<'_>, observed: &Observations) -> TestResult<()> {
    let alpha = execution.run(Identity::Alpha, "alpha");
    tokio::pin!(alpha);
    timeout(Duration::from_secs(2), async {
        let waiting: TestResult<()> = tokio::select! {
            reply = &mut alpha => {
                drop(reply?);
                Err(io::Error::other("alpha completed before verification was released").into())
            }
            () = observed.alpha_entered.notified() => Ok(())
        };
        waiting
    })
    .await??;
    let (status, beta) = execution.run(Identity::Beta, "beta").await?;
    assert_eq!(status, reqwest::StatusCode::OK);
    result(&beta, "beta")?;
    let (status, denied) = execution.run(Identity::Beta, "alpha").await?;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(
        envelope(&denied, Some("permission_denied"))?.get("data"),
        Some(&Value::Null)
    );
    assert_eq!(
        observed
            .executes
            .first()
            .map(|counter| counter.load(Ordering::SeqCst)),
        Some(0)
    );
    observed.alpha_release.notify_one();
    let (status, reply) = timeout(Duration::from_secs(2), alpha).await??;
    assert_eq!(status, reqwest::StatusCode::OK);
    result(&reply, "alpha")?;
    Ok(())
}

async fn isolation_and_recovery(http2: bool) -> TestResult<()> {
    let fixture = Fixture::new()?;
    let resource = format!("https://localhost:{}/mcp", fixture.address.port());
    let mut upstream = Backend::start(resource.clone()).await?;
    configure_projects(&fixture, &upstream.endpoint)?;
    let roots =
        fixture
            .directory
            .write("upstream-root.pem", upstream.certificate.as_bytes(), 0o600)?;
    let mut process = Process::start_with_roots(&fixture.config, Some(&roots))?;
    fixture.ready(&mut process).await?;
    let http = client(&fixture, http2)?;
    let execution = Execution {
        http: &http,
        resource: &resource,
        http2,
    };
    overlapping(&execution, &upstream.observations).await?;
    upstream
        .observations
        .alpha_active
        .store(false, Ordering::SeqCst);
    let (status, _) = execution.run(Identity::Alpha, "alpha").await?;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
    let (status, beta) = execution.run(Identity::Beta, "beta").await?;
    assert_eq!(status, reqwest::StatusCode::OK);
    result(&beta, "beta")?;
    let (status, _) = execution.run(Identity::Rejected, "alpha").await?;
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN);
    upstream
        .observations
        .alpha_active
        .store(true, Ordering::SeqCst);
    let (status, alpha) = execution.run(Identity::Alpha, "alpha").await?;
    assert_eq!(status, reqwest::StatusCode::OK);
    result(&alpha, "alpha")?;
    assert_eq!(
        upstream
            .observations
            .verifies
            .each_ref()
            .map(|counter| counter.load(Ordering::SeqCst)),
        [3, 3, 1]
    );
    assert_eq!(
        upstream
            .observations
            .executes
            .each_ref()
            .map(|counter| counter.load(Ordering::SeqCst)),
        [2, 3, 0]
    );
    fixture.ready(&mut process).await?;
    process.signal(Signal::TERM)?;
    assert!(process.wait().await?.success());
    drop(std::net::TcpListener::bind(fixture.address)?);
    upstream.finish().await?;
    Ok(())
}

#[tokio::test]
async fn normal_linux_http1_concurrent_identity_isolation_and_recovery() -> TestResult<()> {
    timeout(Duration::from_secs(20), isolation_and_recovery(false)).await?
}

#[tokio::test]
async fn normal_linux_http2_concurrent_identity_isolation_and_recovery() -> TestResult<()> {
    timeout(Duration::from_secs(20), isolation_and_recovery(true)).await?
}
