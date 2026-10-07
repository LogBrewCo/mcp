//! Authenticate the normal Linux executable with process-local platform trust.

#[path = "authenticated_backend.rs"]
mod backend;

#[path = "authenticated_cancellation.rs"]
mod cancellation;

#[path = "authenticated_deadline.rs"]
mod deadline;

#[path = "authenticated_encoding.rs"]
mod encoding;

#[path = "authenticated_headers.rs"]
mod headers;

#[path = "authenticated_multiplexed.rs"]
mod multiplexed;

#[path = "authenticated_sdk.rs"]
mod sdk;

#[path = "authenticated_tenant_backend.rs"]
mod tenant_backend;

#[path = "authenticated_tenants.rs"]
mod tenants;

use core::{sync::atomic::Ordering, time::Duration};
use std::{fs, io};

use rustix::process::Signal;
use serde_json::{Value, json};
use tokio::time::timeout;

use super::{Fixture, Process, TestResult};

/// # Errors
///
/// Returns a configuration file, JSON or missing-authority-field error.
fn configure(fixture: &Fixture, endpoint: &str) -> TestResult<()> {
    let mut config: Value = serde_json::from_slice(&fs::read(&fixture.config)?)?;
    for (field, suffix) in [
        ("issuer", ""),
        ("introspection_endpoint", "/introspect"),
        ("execution_endpoint", "/execute"),
    ] {
        *config
            .get_mut(field)
            .ok_or_else(|| io::Error::other("missing authority field"))? =
            json!(format!("{endpoint}{suffix}"));
    }
    drop(fixture.directory.write(
        "clients.json",
        br#"{"version":"1","clients":["synthetic-client"]}"#,
        0o600,
    )?);
    fs::write(&fixture.config, serde_json::to_vec(&config)?)?;
    Ok(())
}

/// # Errors
///
/// Returns a fixture certificate or HTTP client construction error.
fn client(fixture: &Fixture, http2: bool) -> TestResult<reqwest::Client> {
    client_with_timeout(fixture, http2, Duration::from_secs(3))
}

/// # Errors
///
/// Returns a fixture certificate or HTTP client construction error.
fn client_with_timeout(
    fixture: &Fixture,
    http2: bool,
    request_timeout: Duration,
) -> TestResult<reqwest::Client> {
    let builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(0)
        .timeout(request_timeout)
        .add_root_certificate(reqwest::Certificate::from_pem(
            fixture.certificate.as_bytes(),
        )?);
    Ok(if http2 {
        builder.http2_prior_knowledge()
    } else {
        builder.http1_only()
    }
    .build()?)
}

/// # Errors
///
/// Returns a request, parameters, body-read or response decoding error.
///
/// # Panics
///
/// Panics if response transport, cache policy, session isolation, rejection body
/// or private-field redaction changes.
async fn request(
    http: &reqwest::Client,
    resource: &str,
    method: &str,
    params: Value,
    http2: bool,
) -> TestResult<(reqwest::StatusCode, Value)> {
    request_with_token(http, resource, method, params, http2, backend::TOKEN).await
}

/// # Errors
///
/// Returns a request, parameters, body-read or response decoding error.
///
/// # Panics
///
/// Panics if response transport, cache policy, session isolation, rejection body
/// or private-field redaction changes.
async fn request_with_token(
    http: &reqwest::Client,
    resource: &str,
    method: &str,
    params: Value,
    http2: bool,
    token: &str,
) -> TestResult<(reqwest::StatusCode, Value)> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let response = http
        .post(resource)
        .bearer_auth(token)
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", method)
        .header("Mcp-Name", name)
        .json(&message(method, params)?)
        .send()
        .await?;
    assert_eq!(
        response.version(),
        if http2 {
            reqwest::Version::HTTP_2
        } else {
            reqwest::Version::HTTP_11
        }
    );
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.bytes().await?;
    Ok((status, decode_response(status, &headers, &bytes)?))
}

/// # Errors
///
/// Returns an error if request parameters are not a JSON object.
fn message(method: &str, mut params: Value) -> TestResult<Value> {
    drop(
        params
            .as_object_mut()
            .ok_or_else(|| io::Error::other("expected parameters"))?
            .insert(
                "_meta".to_owned(),
                json!({
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientInfo":{"name":"synthetic","version":"1"},
            "io.modelcontextprotocol/clientCapabilities":{}}),
            ),
    );
    Ok(json!({"jsonrpc":"2.0","id":1_i32,"method":method,"params":params}))
}

/// # Errors
///
/// Returns a JSON parsing error for a response that requires a JSON body.
///
/// # Panics
///
/// Panics if cache policy, session isolation, authentication challenge, rejection
/// body or private-field redaction changes.
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
fn decode_response(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    bytes: &[u8],
) -> TestResult<Value> {
    assert_eq!(
        headers
            .get("Cache-Control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert!(!headers.contains_key("Mcp-Session-Id"));
    if status == reqwest::StatusCode::UNAUTHORIZED {
        assert!(
            headers
                .get("WWW-Authenticate")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|challenge| challenge.contains("error=\"invalid_token\""))
        );
    }
    let value = if status == reqwest::StatusCode::UNAUTHORIZED {
        assert_eq!(bytes, b"unauthorized");
        Value::Null
    } else if status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
        assert_eq!(bytes, b"authorization unavailable");
        Value::Null
    } else if status == reqwest::StatusCode::GATEWAY_TIMEOUT {
        assert_eq!(bytes, b"request deadline exceeded");
        Value::Null
    } else if status == reqwest::StatusCode::FORBIDDEN {
        assert_eq!(bytes, b"client access denied");
        Value::Null
    } else {
        serde_json::from_slice::<Value>(bytes)?
    };
    assert!(!value.to_string().contains("SYNTHETIC"));
    Ok(value)
}

/// # Errors
///
/// Returns an error if tool result fields are missing or its text has invalid JSON.
///
/// # Panics
///
/// Panics if error status, structured content, text or provenance disagrees with
/// the tool result contract.
// Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
fn envelope(reply: &Value, error: Option<&str>) -> TestResult<Value> {
    let result = reply
        .get("result")
        .ok_or_else(|| io::Error::other("missing tool result"))?;
    assert_eq!(
        result
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        error.is_some()
    );
    let value = result
        .get("structuredContent")
        .ok_or_else(|| io::Error::other("missing structured result"))?;
    assert_eq!(value.pointer("/error/code").and_then(Value::as_str), error);
    let text = result
        .pointer("/content/0/text")
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::other("missing text result"))?;
    assert_eq!(&serde_json::from_str::<Value>(text)?, value);
    assert!(
        value
            .pointer("/provenance/definition_sha256")
            .and_then(Value::as_str)
            .is_some_and(|digest| digest.len() == 64)
    );
    Ok(value.clone())
}

/// # Errors
///
/// Returns a fixture, configuration, process, client, request, envelope or
/// shutdown error.
///
/// # Panics
///
/// Panics if discovery, tool inventory, search, execution, revocation, invalid
/// input rejection, call counts or executable shutdown changes.
async fn contracts(http2: bool) -> TestResult<()> {
    let fixture = Fixture::new()?;
    let resource = format!("https://localhost:{}/mcp", fixture.address.port());
    let mut upstream = backend::Backend::start(resource.clone()).await?;
    configure(&fixture, upstream.endpoint())?;
    let roots = fixture.directory.write(
        "upstream-root.pem",
        upstream.certificate().as_bytes(),
        0o600,
    )?;
    let mut process = Process::start_with_roots(&fixture.config, Some(&roots))?;
    fixture.ready(&mut process).await?;
    let http = client(&fixture, http2)?;
    let (discovery_status, discovered) =
        request(&http, &resource, "server/discover", json!({}), http2).await?;
    assert_eq!(discovery_status, reqwest::StatusCode::OK);
    assert_eq!(
        discovered.pointer("/result/resultType"),
        Some(&json!("complete"))
    );
    assert_eq!(
        discovered.pointer("/result/capabilities"),
        Some(&json!({"tools":{}}))
    );
    let (inventory_status, inventory) =
        request(&http, &resource, "tools/list", json!({}), http2).await?;
    assert_eq!(inventory_status, reqwest::StatusCode::OK);
    assert_eq!(
        inventory.pointer("/result/tools/0/name"),
        Some(&json!("search"))
    );
    assert_eq!(
        inventory.pointer("/result/tools/1/name"),
        Some(&json!("execute"))
    );
    assert_eq!(
        inventory
            .pointer("/result/tools")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(2)
    );
    let search = json!({"name":"search","arguments":{"query":"logs","limit":1_i32}});
    let (search_status, search_reply) =
        request(&http, &resource, "tools/call", search, http2).await?;
    assert_eq!(search_status, reqwest::StatusCode::OK);
    assert_eq!(
        envelope(&search_reply, None)?.pointer("/data/operations/0/id"),
        Some(&json!("logs.read.v1"))
    );
    revocation(&upstream, &http, &resource, http2).await?;
    let invalid = json!({"name":"execute","arguments":{"operation":"logs.read.v1",
        "input":{"token":"SYNTHETIC_PRIVATE_MARKER"}}});
    let (status, reply) = request(&http, &resource, "tools/call", invalid, http2).await?;
    assert_eq!(status, reqwest::StatusCode::OK);
    drop(envelope(&reply, Some("invalid_input"))?);
    assert_eq!(upstream.observations().verifies().load(Ordering::SeqCst), 7);
    assert_eq!(upstream.observations().executes().load(Ordering::SeqCst), 2);
    process.signal(Signal::TERM)?;
    assert!(process.wait().await?.success());
    drop(std::net::TcpListener::bind(fixture.address)?);
    upstream.finish().await?;
    Ok(())
}

/// # Errors
///
/// Returns a request, body-read, response decoding or envelope error.
///
/// # Panics
///
/// Panics if active, revoked or recovered credentials produce the wrong status,
/// result or verification and execution counts.
async fn revocation(
    upstream: &backend::Backend,
    http: &reqwest::Client,
    resource: &str,
    http2: bool,
) -> TestResult<()> {
    let execution = json!({"name":"execute","arguments":{"operation":"logs.read.v1","input":{}}});
    for attempt in 0_usize..3 {
        let active = attempt != 1;
        upstream
            .observations()
            .active()
            .store(active, Ordering::SeqCst);
        let (status, reply) =
            request(http, resource, "tools/call", execution.clone(), http2).await?;
        if active {
            assert_eq!(status, reqwest::StatusCode::OK);
            assert_eq!(
                envelope(&reply, None)?.pointer("/data/count"),
                Some(&json!(3_i32))
            );
        } else {
            assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
        }
        assert_eq!(
            Some(upstream.observations().verifies().load(Ordering::SeqCst)),
            attempt.checked_add(4)
        );
        assert_eq!(
            upstream.observations().executes().load(Ordering::SeqCst),
            if attempt == 2 { 2 } else { 1 }
        );
    }
    Ok(())
}

#[tokio::test]
/// # Errors
///
/// Returns an HTTP/1 authentication contract error or an outer timeout.
///
/// # Panics
///
/// Panics if authentication, revocation or recovery assertions fail.
async fn normal_linux_http1_authentication_revocation_and_recovery() -> TestResult<()> {
    timeout(Duration::from_secs(20), contracts(false)).await?
}

#[tokio::test]
/// # Errors
///
/// Returns an HTTP/2 authentication contract error or an outer timeout.
///
/// # Panics
///
/// Panics if authentication, revocation or recovery assertions fail.
async fn normal_linux_http2_authentication_revocation_and_recovery() -> TestResult<()> {
    timeout(Duration::from_secs(20), contracts(true)).await?
}
