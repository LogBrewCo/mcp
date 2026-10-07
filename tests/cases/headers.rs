//! Exercise parser limits before credential verification over actual TLS.

use core::{fmt::Write as _, sync::atomic::Ordering, time::Duration};
use std::io;

use serde_json::json;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    time::timeout,
};

use super::{
    hpack::literal,
    http::{Fixture, TOKEN},
    peer::Peer,
    runtime::Running,
};

type TestResult<T> = Result<T, Box<dyn core::error::Error + Send + Sync>>;
const LIMIT: usize = 16 << 10;

/// # Errors
///
/// Returns a TLS, write, read or timeout error during the bounded HTTP/1 exchange.
async fn http1(running: &Running, request: &[u8]) -> TestResult<Vec<u8>> {
    let mut stream = running.tls(Some(b"http/1.1")).await?;
    stream.write_all(request).await?;
    let mut response = Vec::new();
    let _: usize = timeout(
        Duration::from_secs(2),
        stream.take(4096).read_to_end(&mut response),
    )
    .await??;
    Ok(response)
}

/// # Panics
///
/// Panics if a rejected request starts introspection or execution.
fn no_backend_work(fixture: &Fixture) {
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
}

/// # Errors
///
/// Returns an execution or runtime shutdown error during valid-request recovery.
///
/// # Panics
///
/// Panics if the recovered result or introspection and execution counts differ
/// from one successful request.
async fn recovery(fixture: &Fixture, running: &mut Running) -> TestResult<()> {
    assert_eq!(
        running
            .execute()
            .await?
            .pointer("/result/structuredContent/data/count"),
        Some(&json!(3_i32))
    );
    assert_eq!(fixture.state.verifies.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);
    running.stop.cancel();
    running.wait().await?;
    Ok(())
}

#[tokio::test]
/// # Panics
///
/// Panics if setup or wire exchanges fail, HTTP/1 header byte or count limits
/// change, rejected requests start upstream work, or recovery and drain fail.
async fn http1_header_bytes_and_count_reject_before_authorization_and_recover() {
    let fixture = Fixture::new().await.expect("fixture");
    let mut running = Running::start(fixture.router.clone())
        .await
        .expect("runtime");
    // Host, Connection and 98 extension fields reach 100 fields below the byte limit.
    let mut control = String::from(
        "GET /.well-known/oauth-protected-resource/mcp HTTP/1.1\r\nHost: resource.example\r\nConnection: close\r\n",
    );
    for _ in 0_i32..97_i32 {
        control.push_str("X-Count: a\r\n");
    }
    write!(control, "X-Control: {}\r\n\r\n", "a".repeat(14_500)).expect("control field");
    assert!(control.len() > 15_000 && control.len() < LIMIT);
    assert!(
        http1(&running, control.as_bytes())
            .await
            .expect("100-field control")
            .starts_with(b"HTTP/1.1 200 ")
    );
    no_backend_work(&fixture);

    let prefix = format!(
        "POST /mcp HTTP/1.1\r\nHost: resource.example\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n"
    );
    let large = format!(
        "{prefix}X-Large: {}\r\nContent-Length: 0\r\n\r\n",
        "a".repeat(LIMIT)
    );
    assert!(
        http1(&running, large.as_bytes())
            .await
            .expect("byte rejection")
            .starts_with(b"HTTP/1.1 431 ")
    );
    no_backend_work(&fixture);

    let incomplete = format!("{prefix}X-Large: {}", "a".repeat(LIMIT));
    assert!(
        http1(&running, incomplete.as_bytes())
            .await
            .expect("incomplete byte rejection")
            .starts_with(b"HTTP/1.1 431 ")
    );
    no_backend_work(&fixture);

    let mut count = prefix;
    for _ in 0_i32..97_i32 {
        count.push_str("X-Count: a\r\n");
    }
    count.push_str("Content-Length: 0\r\n\r\n");
    assert!(
        http1(&running, count.as_bytes())
            .await
            .expect("count rejection")
            .starts_with(b"HTTP/1.1 431 ")
    );
    no_backend_work(&fixture);
    recovery(&fixture, &mut running)
        .await
        .expect("recovery and drain");
}

/// # Errors
///
/// Returns a header encoding error while constructing the synthetic POST block.
fn post() -> TestResult<Vec<u8>> {
    // Static indices 3 (:method POST) and 7 (:scheme https).
    let mut block = vec![0x83, 0x87];
    literal(&mut block, b":authority", b"resource.example", false)?;
    literal(&mut block, b":path", b"/mcp", false)?;
    literal(
        &mut block,
        b"authorization",
        format!("Bearer {TOKEN}").as_bytes(),
        false,
    )?;
    Ok(block)
}

/// # Errors
///
/// Returns a peer write, read or connection-probe error, or an error if the
/// rejection is missing or exceeds the response frame bound.
///
/// # Panics
///
/// Panics if the rejection is not a complete empty response with status 431.
async fn rejected(peer: &mut Peer, block: &[u8]) -> TestResult<()> {
    // Split a large literal block into HEADERS and CONTINUATION frames. Send no DATA.
    let chunks = block.chunks(LIMIT);
    let count = chunks.len();
    for (index, chunk) in chunks.enumerate() {
        let kind = if index == 0 { 1 } else { 9 };
        // END_STREAM belongs to HEADERS; END_HEADERS belongs to the final fragment.
        let mut flags = u8::from(index == 0);
        if index.checked_add(1) == Some(count) {
            flags |= 4;
        }
        peer.send(1, kind, flags, chunk).await?;
    }
    for _ in 0_i32..16_i32 {
        let frame = peer
            .next()
            .await?
            .ok_or_else(|| io::Error::other("missing rejection"))?;
        if frame.kind == 1 && frame.stream == 1 {
            assert_eq!(frame.flags & 5, 5, "complete, empty response");
            // Fresh decoder: literal :status (static name index 8), raw or Huffman 431.
            // Appendix B codes 4=011010, 3=011001, 1=00001, then EOS padding.
            assert!(
                matches!(
                    frame.payload.as_slice(),
                    [0x08 | 0x18 | 0x48, 3, b'4', b'3', b'1']
                        | [0x08 | 0x18 | 0x48, 0x83, 0x69, 0x90, 0xff]
                ),
                "431 status field: {:?}",
                frame.payload
            );
            return peer.probe().await;
        }
    }
    Err(io::Error::other("response frame count exceeds test bound").into())
}

/// # Errors
///
/// Returns a header encoding, peer I/O or JSON error, or an error for an
/// unexpected frame, missing peer response or exceeded frame bound.
///
/// # Panics
///
/// Panics if encoded metadata exceeds its header limit, the response status or
/// resource is incorrect, or body bytes exceed the recovery bound.
async fn metadata(peer: &mut Peer, indexed: bool) -> TestResult<()> {
    let mut block = vec![0x82, 0x87]; // GET, https
    literal(&mut block, b":authority", b"resource.example", false)?;
    literal(
        &mut block,
        b":path",
        b"/.well-known/oauth-protected-resource/mcp",
        false,
    )?;
    if indexed {
        // Reuse the dynamic entry from the rejected block to check decoder state.
        block.push(0xbe);
    } else {
        literal(&mut block, b"x-control", &[b'a'; 15_000], false)?;
    }
    assert!(block.len() < LIMIT);
    peer.send(3, 1, 5, &block).await?;
    let mut body = Vec::new();
    let mut status = false;
    for _ in 0_i32..16_i32 {
        let frame = peer
            .next()
            .await?
            .ok_or_else(|| io::Error::other("metadata peer closed"))?;
        if frame.stream != 3 {
            continue;
        }
        let complete = match frame.kind {
            1 => {
                assert_eq!(frame.payload.first(), Some(&0x88), "static :status 200");
                status = true;
                false
            }
            0 => {
                assert!(
                    body.len()
                        .checked_add(frame.payload.len())
                        .is_some_and(|size| size <= 4096)
                );
                body.extend_from_slice(&frame.payload);
                frame.flags & 1 != 0
            }
            _ => return Err(io::Error::other("unexpected metadata frame").into()),
        };
        if complete {
            assert!(status);
            let value: serde_json::Value = serde_json::from_slice(&body)?;
            assert_eq!(
                value.get("resource"),
                Some(&json!("https://resource.example/mcp"))
            );
            return Ok(());
        }
    }
    Err(io::Error::other("metadata frame count exceeds test bound").into())
}

#[tokio::test]
/// # Panics
///
/// Panics if setup or wire exchanges fail, literal or compressed header limits
/// change, rejection starts upstream work, or decoder recovery and drain fail.
async fn http2_literal_and_compressed_header_limits_reject_before_authorization_and_recover() {
    let fixture = Fixture::new().await.expect("fixture");
    let mut running = Running::start(fixture.router.clone())
        .await
        .expect("runtime");
    let mut literal_block = post().expect("POST block");
    literal(&mut literal_block, b"x-large", &[b'a'; LIMIT], false).expect("large field");
    assert!(literal_block.len() > LIMIT);
    let mut compressed = post().expect("POST block");
    literal(&mut compressed, b"x-repeat", &[b'a'; 1000], true).expect("indexed field");
    // Index 62 is the newest dynamic entry. Each repetition contributes its decoded
    // name and value plus 32 bytes to the header list (RFC 9113 section 6.5.2).
    compressed.extend(core::iter::repeat_n(0xbe, 16));
    assert!(compressed.len() < 1200);
    assert!((1000 + b"x-repeat".len() + 32) * 17 > LIMIT);
    let mut overhead = post().expect("POST block");
    literal(&mut overhead, b"x-repeat", b"", true).expect("indexed field");
    overhead.extend(core::iter::repeat_n(0xbe, 410));
    assert!(overhead.len() < 600);
    assert!(b"x-repeat".len() * 411 < LIMIT);
    assert!((b"x-repeat".len() + 32) * 411 > LIMIT);
    for (block, indexed) in [(literal_block, false), (compressed, true), (overhead, true)] {
        let mut peer = Peer::connect(running.tls(Some(b"h2")).await.expect("TLS"), true)
            .await
            .expect("HTTP/2 SETTINGS");
        timeout(Duration::from_secs(2), rejected(&mut peer, &block))
            .await
            .expect("bounded rejection and connection probe")
            .expect("431 and live connection");
        no_backend_work(&fixture);
        timeout(Duration::from_secs(2), metadata(&mut peer, indexed))
            .await
            .expect("same connection metadata bound")
            .expect("decoder and request recovery");
        no_backend_work(&fixture);
    }
    recovery(&fixture, &mut running)
        .await
        .expect("recovery and drain");
}
