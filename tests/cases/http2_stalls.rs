//! Bound stalled HTTP/2 input and output while the connection answers PINGs.

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    sync::atomic::Ordering,
    time::Duration,
};

use logbrew_mcp::telemetry::{Outcome, Stage};
use serde_json::{Value, json};
use tokio::time::{Instant, sleep, timeout};

use super::{
    hpack::literal,
    http::{Fixture, TOKEN},
    peer::Peer,
    runtime::Running,
};

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const PRIVATE_BODY: &[u8] = br#"{"SYNTHETIC_PRIVATE_BODY":"#;

fn post() -> TestResult<Vec<u8>> {
    let mut block = vec![0x83, 0x87]; // Static POST and https indices.
    let authorization = format!("Bearer {TOKEN}");
    for (name, value) in [
        (":authority", "resource.example"),
        (":path", "/mcp"),
        ("authorization", authorization.as_str()),
        ("content-type", "application/json"),
        ("accept", "application/json, text/event-stream"),
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "execute"),
    ] {
        literal(&mut block, name.as_bytes(), value.as_bytes(), false)?;
    }
    Ok(block)
}

fn status(block: &[u8], expected: u16) -> TestResult<()> {
    // SETTINGS_HEADER_TABLE_SIZE=0 removes dynamic response indices. The first
    // block can include a zero table-size update before its status field.
    let block = block.strip_prefix(&[0x20]).unwrap_or(block);
    let matches = match expected {
        200 => block.first() == Some(&0x88),
        // Static name index 8, raw 504 or Appendix B codes 5, 0, 4 and EOS padding.
        504 => matches!(
            block.get(..5),
            Some(
                [0x08 | 0x18 | 0x48, 3, b'5', b'0', b'4']
                    | [0x08 | 0x18 | 0x48, 0x83, 0x6c, 0x0d, 0x7f]
            )
        ),
        // Appendix B codes 4, 0, 1 occupy exactly sixteen bits.
        401 => {
            matches!(
                block.get(..5),
                Some([0x08 | 0x18 | 0x48, 3, b'4', b'0', b'1'])
            ) || matches!(block.get(..4), Some([0x08 | 0x18 | 0x48, 0x82, 0x68, 0x01]))
        }
        _ => false,
    };
    if !matches {
        return Err(io::Error::other(format!(
            "unexpected fixture status {expected}: {:02x?}",
            block.get(..12).unwrap_or(block)
        ))
        .into());
    }
    Ok(())
}

#[derive(Default)]
struct Response {
    headers: bool,
    complete: bool,
    body: Vec<u8>,
}

async fn responses(
    peer: &mut Peer,
    streams: &[u32],
    expected: u16,
    drip: bool,
) -> TestResult<(usize, BTreeMap<u32, Response>)> {
    let mut responses: BTreeMap<_, _> = streams
        .iter()
        .map(|stream| (*stream, Response::default()))
        .collect();
    let mut pings = 0_usize;
    for _ in 0_i32..512_i32 {
        let frame = peer
            .next()
            .await?
            .ok_or_else(|| io::Error::other("responsive connection closed"))?;
        if frame.kind == 6 && frame.flags == 0 && frame.stream == 0 {
            assert_eq!(frame.payload.len(), 8);
            peer.send(0, 6, 1, &frame.payload).await?;
            pings = pings.checked_add(1).ok_or("fixture ping count overflow")?;
            if drip && pings == 1 {
                for stream in streams {
                    // Mid-request progress must not refresh the request deadline.
                    peer.send(*stream, 0, 0, b" ").await?;
                }
            }
            continue;
        }
        if frame.kind == 7 {
            return Err(io::Error::other("unexpected connection shutdown").into());
        }
        let Some(response) = responses.get_mut(&frame.stream) else {
            continue; // SETTINGS, window updates or resets from completed streams.
        };
        match frame.kind {
            1 => {
                assert_eq!(frame.flags & 5, 4);
                assert!(!response.headers);
                status(&frame.payload, expected)?;
                response.headers = true;
            }
            0 => {
                assert!(response.headers && !response.complete);
                assert_eq!(frame.flags & 8, 0, "fixture responses have no padding");
                assert!(
                    response
                        .body
                        .len()
                        .checked_add(frame.payload.len())
                        .is_some_and(|size| size <= 4096)
                );
                response.body.extend_from_slice(&frame.payload);
                response.complete = frame.flags & 1 != 0;
            }
            3 => assert!(response.complete, "reset before complete response"),
            8 => {}
            _ => return Err(io::Error::other("unexpected response frame").into()),
        }
        if responses.values().all(|response| response.complete) {
            return Ok((pings, responses));
        }
    }
    Err(io::Error::other("response frame count exceeds test bound").into())
}

async fn capacity(fixture: &Fixture, running: &Running) -> TestResult<()> {
    timeout(Duration::from_secs(2), async {
        while fixture.state.verifies.load(Ordering::SeqCst) != 64 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|error| {
        io::Error::other(format!(
            "admission observation: {error}; verifies={}",
            fixture.state.verifies.load(Ordering::SeqCst),
        ))
    })?;
    let response = running
        .http1_client()
        .post(format!("https://localhost:{}/mcp", running.address.port()))
        .header("Host", "resource.example")
        .body("{}")
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 64);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

async fn recovery(peer: &mut Peer, block: &[u8], stream: u32) -> TestResult<()> {
    let body = json!({"jsonrpc":"2.0","id":"recovered","method":"tools/call","params":{
        "name":"execute","arguments":{"operation":"logs.read.v1","input":{}},"_meta":{
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":{}}}});
    peer.send(stream, 1, 4, block).await?;
    peer.send(stream, 0, 1, body.to_string().as_bytes()).await?;
    let (_, responses) = responses(peer, &[stream], 200, false).await?;
    let response = responses.get(&stream).ok_or("missing recovery response")?;
    let value: Value = serde_json::from_slice(&response.body)?;
    assert_eq!(value.get("id"), Some(&json!("recovered")));
    assert_eq!(
        value.pointer("/result/structuredContent/data/count"),
        Some(&json!(3_i32))
    );
    Ok(())
}

fn observations(fixture: &Fixture) -> TestResult<()> {
    let snapshot = fixture.telemetry.snapshot().ok_or("missing observations")?;
    let requests = snapshot
        .stages
        .iter()
        .find(|stage| stage.stage == Stage::RequestPrepared)
        .ok_or("missing request observations")?;
    assert_eq!(requests.started, 67);
    assert_eq!(requests.finished, 67);
    assert_eq!(requests.pending, Some(0));
    for (outcome, expected) in [(Outcome::Deadline, 64), (Outcome::Throttled, 1)] {
        assert_eq!(
            requests
                .outcomes
                .iter()
                .find(|entry| entry.outcome == outcome)
                .ok_or("missing request outcome")?
                .count,
            expected
        );
    }
    let encoded = serde_json::to_string(&snapshot)?;
    assert!(!encoded.contains("SYNTHETIC_PRIVATE_BODY"));
    assert!(!encoded.contains(TOKEN));
    Ok(())
}

#[tokio::test]
async fn unfinished_http2_bodies_expire_despite_ping_and_body_progress_and_capacity_recovers() {
    let fixture = Fixture::new().await.expect("fixture");
    let mut running = Running::start(fixture.router.clone())
        .await
        .expect("runtime");
    let mut peer = Peer::connect(running.tls(Some(b"h2")).await.expect("TLS"), true)
        .await
        .expect("HTTP/2 SETTINGS");
    peer.send(0, 4, 0, &[0, 1, 0, 0, 0, 0])
        .await
        .expect("zero response table");
    let streams: Vec<_> = (1..128).step_by(2).collect();
    let block = post().expect("complete request headers");
    for stream in &streams {
        peer.send(*stream, 1, 4, &block)
            .await
            .expect("HEADERS without END_STREAM");
        peer.send(*stream, 0, 0, PRIVATE_BODY)
            .await
            .expect("unfinished private body");
    }
    capacity(&fixture, &running)
        .await
        .expect("64 admitted requests and excess capacity rejection");
    let (pings, responses) = timeout(
        Duration::from_secs(12),
        responses(&mut peer, &streams, 504, true),
    )
    .await
    .expect("all unfinished bodies expire within the request bound")
    .expect("complete deadline responses on a live connection");
    assert!(pings > 0, "the peer actually answered a server PING");
    assert_eq!(responses.len(), 64);
    for response in responses.values() {
        assert_eq!(response.body, b"request deadline exceeded");
    }
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    timeout(Duration::from_secs(2), recovery(&mut peer, &block, 129))
        .await
        .expect("same connection recovery deadline")
        .expect("authenticated execution after all timeouts");
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 65);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);
    observations(&fixture).expect("complete privacy-safe observations");
    drop(peer);
    running.stop.cancel();
    running.wait().await.expect("runtime drain");
}

async fn withheld_window(peer: &mut Peer) -> TestResult<usize> {
    let mut headers = BTreeSet::new();
    let mut resets = BTreeSet::new();
    let mut pings = 0_usize;
    for _ in 0_i32..512_i32 {
        let Some(frame) = peer.next().await? else {
            assert_eq!(headers.len(), 64);
            return Ok(pings);
        };
        match frame.kind {
            6 if frame.stream == 0 && frame.flags == 0 => {
                assert_eq!(frame.payload.len(), 8);
                peer.send(0, 6, 1, &frame.payload).await?;
                pings = pings.checked_add(1).ok_or("fixture ping count overflow")?;
                if pings == 3 {
                    assert_eq!(headers.len(), 64);
                    return Ok(pings);
                }
            }
            1 => {
                assert!(frame.stream > 0 && frame.stream < 128 && frame.stream % 2 == 1);
                assert_eq!(frame.flags & 5, 4);
                status(&frame.payload, 401)?;
                assert!(headers.insert(frame.stream));
            }
            3 => {
                assert!(headers.contains(&frame.stream));
                assert_eq!(frame.payload.len(), 4);
                assert!(resets.insert(frame.stream));
                if resets.len() == 64 {
                    return Ok(pings);
                }
            }
            0 => return Err(io::Error::other("DATA sent without stream capacity").into()),
            7 => return Ok(pings),
            4 | 8 => {}
            _ => return Err(io::Error::other("unexpected withheld-window frame").into()),
        }
    }
    Err(io::Error::other("control frame count exceeds test bound").into())
}

async fn prepared_challenges(fixture: &Fixture) -> TestResult<()> {
    timeout(Duration::from_secs(2), async {
        loop {
            if fixture.telemetry.snapshot().is_some_and(|snapshot| {
                snapshot
                    .stages
                    .iter()
                    .any(|stage| stage.stage == Stage::RequestPrepared && stage.finished == 65)
            }) {
                return;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|error| {
        io::Error::other(format!(
            "challenge observation: {error}; finished={:?}",
            fixture.telemetry.snapshot().and_then(|snapshot| snapshot
                .stages
                .into_iter()
                .find(|stage| stage.stage == Stage::RequestPrepared)
                .map(|stage| stage.finished))
        ))
    })?;
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    let snapshot = fixture
        .telemetry
        .snapshot()
        .ok_or("missing retention snapshot")?;
    assert_eq!(snapshot.format_version, 3);
    let retained = snapshot
        .stages
        .iter()
        .find(|stage| stage.stage == Stage::ResponseRetained)
        .ok_or("missing retained-response observations")?;
    assert_eq!(retained.started, 64);
    assert_eq!(retained.finished, 0);
    assert_eq!(retained.pending, Some(64));
    assert_eq!(retained.p99_upper_ns, None);
    Ok(())
}

async fn closed_retention(fixture: &Fixture) -> TestResult<()> {
    timeout(Duration::from_secs(2), async {
        loop {
            if let Some(snapshot) = fixture.telemetry.snapshot()
                && let Some(retained) = snapshot
                    .stages
                    .iter()
                    .find(|stage| stage.stage == Stage::ResponseRetained)
                && retained.finished == 64
            {
                assert_eq!(retained.started, 64);
                assert_eq!(retained.pending, Some(0));
                assert_eq!(retained.timed, 64);
                assert_eq!(retained.dropped_updates, 0);
                let count = |outcome| {
                    retained
                        .outcomes
                        .iter()
                        .find(|entry| entry.outcome == outcome)
                        .map_or(0, |entry| entry.count)
                };
                assert!(count(Outcome::Deadline) > 0);
                assert_eq!(
                    count(Outcome::Deadline).checked_add(count(Outcome::Cancelled)),
                    Some(64)
                );
                assert_eq!(count(Outcome::Completed), 0);
                assert_eq!(count(Outcome::Released), 0);
                let encoded = serde_json::to_string(&snapshot)?;
                assert!(!encoded.contains(TOKEN));
                assert!(!encoded.contains("resource.example"));
                return Ok(());
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await?
}

#[tokio::test]
async fn withheld_http2_response_window_cannot_keep_all_request_slots_despite_ping() {
    let fixture = Fixture::new().await.expect("fixture");
    let mut running = Running::start(fixture.router.clone())
        .await
        .expect("runtime");
    let mut peer = Peer::connect(running.tls(Some(b"h2")).await.expect("TLS"), true)
        .await
        .expect("HTTP/2 SETTINGS");
    // Header table size zero and initial stream window zero. Response HEADERS
    // remain deliverable, while no response DATA can make progress.
    peer.send(0, 4, 0, &[0, 1, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0])
        .await
        .expect("bounded response settings");
    let mut block = vec![0x83, 0x87];
    literal(&mut block, b":authority", b"resource.example", false).expect("authority");
    literal(&mut block, b":path", b"/mcp", false).expect("protected path");
    for stream in (1..128).step_by(2) {
        peer.send(stream, 1, 5, &block)
            .await
            .expect("complete request without credentials");
    }
    prepared_challenges(&fixture)
        .await
        .expect("all challenges prepared without authority calls");
    let blocked = running
        .http1_client()
        .post(format!("https://localhost:{}/mcp", running.address.port()))
        .header("Host", "resource.example")
        .body("{}")
        .send()
        .await
        .expect("excess protected request");
    assert_eq!(blocked.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    drop(blocked);
    let pings = timeout(Duration::from_secs(18), withheld_window(&mut peer))
        .await
        .expect("withheld response observation bound")
        .expect("responsive peer or bounded stream cancellation");
    assert!(pings > 0, "the peer answered a server PING");
    closed_retention(&fixture)
        .await
        .expect("all retained responses finish with deadline or connection cancellation");
    assert_eq!(
        running
            .execute()
            .await
            .expect("response stalls released request admission")
            .pointer("/result/structuredContent/data/count"),
        Some(&json!(3_i32))
    );
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);
    drop(peer);
    running.stop.cancel();
    running.wait().await.expect("runtime drain");
}

#[tokio::test]
async fn completed_http2_delivery_keeps_the_connection_reusable_after_its_deadline() {
    let fixture = Fixture::new().await.expect("fixture");
    let mut running = Running::start(fixture.router.clone())
        .await
        .expect("runtime");
    let mut peer = Peer::connect(running.tls(Some(b"h2")).await.expect("TLS"), true)
        .await
        .expect("HTTP/2 SETTINGS");
    peer.send(0, 4, 0, &[0, 1, 0, 0, 0, 0])
        .await
        .expect("zero response table");
    let block = post().expect("complete request headers");
    timeout(Duration::from_secs(2), recovery(&mut peer, &block, 1))
        .await
        .expect("initial response bound")
        .expect("complete initial response");
    let completed = Instant::now();
    timeout(Duration::from_secs(18), async {
        let mut pings = 0_i32;
        for _ in 0_i32..32_i32 {
            let frame = peer.next().await?.ok_or("completed connection closed")?;
            match frame.kind {
                6 if frame.stream == 0 && frame.flags == 0 => {
                    assert_eq!(frame.payload.len(), 8);
                    peer.send(0, 6, 1, &frame.payload).await?;
                    pings += 1_i32;
                    if pings == 3_i32 {
                        return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
                    }
                }
                3 | 4 | 8 => {}
                _ => return Err(io::Error::other("unexpected reuse control frame").into()),
            }
        }
        Err(io::Error::other("reuse control frame count exceeds bound").into())
    })
    .await
    .expect("observation after the old delivery deadline")
    .expect("three actual server PINGs on a reusable connection");
    assert!(completed.elapsed() >= Duration::from_secs(10));
    timeout(Duration::from_secs(2), recovery(&mut peer, &block, 3))
        .await
        .expect("reused response bound")
        .expect("complete response on the same connection");
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 2);
    drop(peer);
    running.stop.cancel();
    running.wait().await.expect("runtime drain");
}
