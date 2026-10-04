//! Exercise HTTP/2 control traffic over verified, ALPN-negotiated process TLS.

use std::{collections::BTreeSet, io, time::Duration};

use rustix::process::Signal;
use tokio::time::timeout;

use super::{Fixture, Process, TestResult, hpack::literal, peer::Peer};

impl Peer {
    async fn ignored_ping_closes(&mut self) -> TestResult<bool> {
        let mut ping = false;
        for _ in 0_i32..16_i32 {
            let Some(frame) = self.next().await? else {
                return Ok(ping);
            };
            if frame.kind == 6 && frame.flags == 0 && frame.stream == 0 && frame.payload.len() == 8
            {
                ping = true;
            }
        }
        Err(io::Error::other("control frame count exceeds test bound").into())
    }

    async fn acknowledge_server_ping(&mut self) -> TestResult<()> {
        for _ in 0_i32..16_i32 {
            let frame = self
                .next()
                .await?
                .ok_or_else(|| io::Error::other("responsive peer closed"))?;
            if frame.kind == 6 && frame.flags == 0 && frame.stream == 0 && frame.payload.len() == 8
            {
                return self.send(0, 6, 1, &frame.payload).await;
            }
        }
        Err(io::Error::other("control frame count exceeds test bound").into())
    }
}

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
        timeout(Duration::from_secs(12), async {
            tokio::join!(
                incomplete.ignored_ping_closes(),
                complete.ignored_ping_closes()
            )
        })
        .await
        .expect("dead HTTP/2 peers close within the connection bound")
    };
    assert!(incomplete.expect("preface peer closure and ping"));
    assert!(complete.expect("idle peer closure and ping"));
    timeout(Duration::from_secs(3), async {
        let mut slots = Vec::new();
        for _ in 0_i32..64_i32 {
            slots.push(fixture.tls().await.expect("recovered TLS slot"));
        }
        assert_eq!(slots.len(), 64);
    })
    .await
    .expect("all 64 slots recovered before the prefix deadline");
    fixture
        .ready(&mut process)
        .await
        .expect("listener recovered");
    process.signal(Signal::TERM).expect("shutdown signal");
    assert!(process.wait().await.expect("exit").success());
    drop(std::net::TcpListener::bind(fixture.address).expect("listener released"));
}

#[tokio::test]
async fn responsive_idle_http2_peer_survives_ping_cycles_and_remains_usable() {
    let fixture = Fixture::new().expect("fixture");
    let mut process = Process::start(&fixture.config).expect("native executable");
    fixture.ready(&mut process).await.expect("readiness");
    let mut peer = Peer::connect(fixture.tls_protocol(Some(b"h2")).await.expect("TLS"), true)
        .await
        .expect("idle peer");
    for _ in 0_i32..2_i32 {
        timeout(Duration::from_secs(7), peer.acknowledge_server_ping())
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
    let mut headers = BTreeSet::new();
    let mut pings = 0_i32;
    timeout(Duration::from_secs(12), async {
        for _ in 0_i32..256_i32 {
            let Some(frame) = peer.next().await? else {
                return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
            };
            match frame.kind {
                1 => {
                    assert!(frame.stream > 0 && frame.stream < 128 && frame.stream % 2 == 1);
                    assert_eq!(frame.flags & 5, 4);
                    assert!(headers.insert(frame.stream));
                    if headers.len() == 64 {
                        let excess = client.post(&url).send().await?;
                        assert_eq!(excess.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
                    }
                }
                6 if frame.stream == 0 && frame.flags == 0 => {
                    assert_eq!(frame.payload.len(), 8);
                    peer.send(0, 6, 1, &frame.payload).await?;
                    pings += 1_i32;
                }
                4 | 8 => {}
                _ => return Err(io::Error::other("unexpected process stall frame").into()),
            }
        }
        Err(io::Error::other("process stall frame count exceeds bound").into())
    })
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
