//! Exercise HTTP/2 control traffic over verified, ALPN-negotiated process TLS.

use std::{collections::BTreeSet, io, time::Duration};

use rustix::process::Signal;
use tokio::time::timeout;

use super::{Fixture, Process, TestResult, hpack::literal, peer::Peer};

/// Observe whether an unanswered server PING precedes peer closure.
///
/// # Errors
/// Propagates frame-read failures or rejects more than sixteen control frames.
async fn ignored_ping_closes(peer: &mut Peer) -> TestResult<bool> {
    let mut ping = false;
    for _ in 0_i32..16_i32 {
        let Some(frame) = peer.next().await? else {
            return Ok(ping);
        };
        if frame.kind == 6 && frame.flags == 0 && frame.stream == 0 && frame.payload.len() == 8 {
            ping = true;
        }
    }
    Err(io::Error::other("control frame count exceeds test bound").into())
}

/// Acknowledge the first valid server PING within sixteen control frames.
///
/// # Errors
/// Propagates frame-read/send failures and rejects premature closure or a missing PING.
async fn acknowledge_server_ping(peer: &mut Peer) -> TestResult<()> {
    for _ in 0_i32..16_i32 {
        let frame = peer
            .next()
            .await?
            .ok_or_else(|| io::Error::other("responsive peer closed"))?;
        if frame.kind == 6 && frame.flags == 0 && frame.stream == 0 && frame.payload.len() == 8 {
            return peer.send(0, 6, 1, &frame.payload).await;
        }
    }
    Err(io::Error::other("control frame count exceeds test bound").into())
}

/// Verify unanswered PING closure and recovery of all sixty-four connection slots.
///
/// # Panics
/// Fails if fixture/process setup, PING closure, slot recovery, shutdown or
/// listener release violates the expected outcome or deadline.
#[tokio::test]
async fn unresponsive_http2_peers_close_after_preface_and_settings_and_capacity_recovers() {
    let fixture = Fixture::new().expect("fixture");
    let mut process = Process::start(&fixture.config).expect("native executable");
    fixture.ready(&mut process).await.expect("readiness");
    let (incomplete, complete) = {
        let mut incomplete =
            Peer::connect(fixture.tls_protocol(Some(b"h2")).await.expect("TLS"), false)
                .await
                .expect("preface peer");
        let mut complete =
            Peer::connect(fixture.tls_protocol(Some(b"h2")).await.expect("TLS"), true)
                .await
                .expect("idle peer");
        timeout(
            Duration::from_secs(12),
            idle_peers(&mut incomplete, &mut complete),
        )
        .await
        .expect("dead HTTP/2 peers close within the connection bound")
    };
    assert!(incomplete.expect("preface peer closure and ping"));
    assert!(complete.expect("idle peer closure and ping"));
    timeout(Duration::from_secs(3), recovered_slots(&fixture))
        .await
        .expect("all 64 slots recovered before the prefix deadline")
        .expect("recovered TLS slots");
    fixture
        .ready(&mut process)
        .await
        .expect("listener recovered");
    process.signal(Signal::TERM).expect("shutdown signal");
    assert!(process.wait().await.expect("exit").success());
    drop(std::net::TcpListener::bind(fixture.address).expect("listener released"));
}

/// Verify PING acknowledgements keep an idle connection usable across two cycles.
///
/// # Panics
/// Fails if fixture/process setup, negotiation, PING exchange, recovery, shutdown
/// or listener release violates the expected outcome or deadline.
#[tokio::test]
async fn responsive_idle_http2_peer_survives_ping_cycles_and_remains_usable() {
    let fixture = Fixture::new().expect("fixture");
    let mut process = Process::start(&fixture.config).expect("native executable");
    fixture.ready(&mut process).await.expect("readiness");
    let mut peer = Peer::connect(fixture.tls_protocol(Some(b"h2")).await.expect("TLS"), true)
        .await
        .expect("idle peer");
    for _ in 0_i32..2_i32 {
        timeout(Duration::from_secs(7), acknowledge_server_ping(&mut peer))
            .await
            .expect("server ping bound")
            .expect("acknowledged ping");
    }
    timeout(Duration::from_secs(2), peer.probe())
        .await
        .expect("live peer probe bound")
        .expect("matching ping acknowledgement");
    drop(peer);
    fixture
        .ready(&mut process)
        .await
        .expect("listener recovered");
    process.signal(Signal::INT).expect("shutdown signal");
    assert!(process.wait().await.expect("exit").success());
    drop(std::net::TcpListener::bind(fixture.address).expect("listener released"));
}

/// Verify a withheld response window releases native response admission after closure.
///
/// # Panics
/// Fails if fixture/process setup, request/frame exchange, stalled connection
/// closure, capacity recovery, shutdown or listener release violates its contract.
#[tokio::test]
async fn native_process_releases_response_admission_when_http2_window_is_withheld() {
    let fixture = Fixture::new().expect("fixture");
    let mut process = Process::start(&fixture.config).expect("native executable");
    fixture.ready(&mut process).await.expect("readiness");
    let mut peer = Peer::connect(fixture.tls_protocol(Some(b"h2")).await.expect("TLS"), true)
        .await
        .expect("HTTP/2 SETTINGS");
    peer.send(0, 4, 0, &[0, 1, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0])
        .await
        .expect("zero response window");
    let mut block = vec![0x83, 0x87];
    literal(
        &mut block,
        b":authority",
        format!("localhost:{}", fixture.address.port()).as_bytes(),
        false,
    )
    .expect("process authority");
    literal(&mut block, b":path", b"/mcp", false).expect("protected path");
    for stream in (1..128).step_by(2) {
        peer.send(stream, 1, 5, &block)
            .await
            .expect("complete anonymous request");
    }
    let client = fixture.client().expect("certificate-verified client");
    let url = format!("https://localhost:{}/mcp", fixture.address.port());
    let (headers, pings) = timeout(
        Duration::from_secs(12),
        withheld_window(&mut peer, &client, &url),
    )
    .await
    .expect("native response delivery bound")
    .expect("stalled connection closed");
    assert_eq!(headers.len(), 64);
    assert!(
        pings > 0_i32,
        "the native process received actual PING acknowledgements"
    );
    assert_eq!(
        client
            .post(&url)
            .send()
            .await
            .expect("recovered admission")
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    drop(peer);
    process.signal(Signal::TERM).expect("shutdown signal");
    assert!(process.wait().await.expect("exit").success());
    drop(std::net::TcpListener::bind(fixture.address).expect("listener released"));
}

async fn idle_peers(
    incomplete: &mut Peer,
    complete: &mut Peer,
) -> (TestResult<bool>, TestResult<bool>) {
    tokio::join!(
        ignored_ping_closes(incomplete),
        ignored_ping_closes(complete)
    )
}

/// Open every connection slot after the stalled peers have closed.
///
/// # Errors
/// Propagates fixture TLS connection failures.
///
/// # Panics
/// Fails if the completed connection inventory does not contain sixty-four slots.
async fn recovered_slots(fixture: &Fixture) -> TestResult<()> {
    let mut slots = Vec::new();
    for _ in 0_i32..64_i32 {
        slots.push(fixture.tls().await?);
    }
    assert_eq!(slots.len(), 64);
    Ok(())
}

/// Inspect stalled response frames while checking excess admission and PING traffic.
///
/// # Errors
/// Propagates frame/request failures and rejects unexpected frames, PING-count
/// overflow or more than 256 control frames.
///
/// # Panics
/// Fails if response stream IDs, flags, uniqueness, PING length or excess-request
/// status violate the fixture contract.
#[expect(
    clippy::integer_division_remainder_used,
    reason = "The HTTP/2 fixture checks client stream parity; this is not cryptographic arithmetic."
)]
async fn withheld_window(
    peer: &mut Peer,
    client: &reqwest::Client,
    url: &str,
) -> TestResult<(BTreeSet<u32>, i32)> {
    let mut headers = BTreeSet::new();
    let mut pings = 0_i32;
    for _ in 0_i32..256_i32 {
        let Some(frame) = peer.next().await? else {
            return Ok((headers, pings));
        };
        let check_excess = match frame.kind {
            1 => {
                assert!(frame.stream > 0 && frame.stream < 128 && frame.stream % 2 == 1);
                assert_eq!(frame.flags & 5, 4);
                assert!(headers.insert(frame.stream));
                headers.len() == 64
            }
            6 if frame.stream == 0 && frame.flags == 0 => {
                assert_eq!(frame.payload.len(), 8);
                peer.send(0, 6, 1, &frame.payload).await?;
                pings = pings
                    .checked_add(1_i32)
                    .ok_or("fixture ping count overflow")?;
                false
            }
            4 | 8 => false,
            _ => return Err(io::Error::other("unexpected process stall frame").into()),
        };
        if check_excess {
            let excess = client.post(url).send().await?;
            assert_eq!(excess.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
        }
    }
    Err(io::Error::other("process stall frame count exceeds bound").into())
}
