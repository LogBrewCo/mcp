//! Client budgets stay isolated, bounded and refundable.

use core::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use axum::http::{HeaderMap, HeaderValue};

use super::{Admission, Limiter};

const fn limits(burst: u32, per_minute: u32, tracked_clients: u32) -> Admission {
    Admission {
        burst,
        per_minute,
        tracked_clients,
        rejected_token_seconds: 0,
        trusted_proxy: None,
    }
}

/// # Panics
/// Panics if the synthetic address does not parse.
fn ip(text: &str) -> IpAddr {
    text.parse().expect("synthetic address")
}

/// Whether the limiter admits one more request from the client.
fn admits(limiter: &Limiter, client: &str) -> bool {
    limiter.reserve(Some(ip(client))).is_ok()
}

/// # Panics
/// Panics if a client exceeds its burst, a refund is lost, or the wait is not reported.
#[test]
fn burst_is_enforced_and_refunds_restore_the_budget() {
    let limiter = Limiter::new(limits(3, 1, 8)).expect("limits");
    let client = Some(ip("192.0.2.1"));
    let tickets: Vec<_> =
        core::iter::repeat_with(|| limiter.reserve(client).expect("within burst"))
            .take(3)
            .collect();
    let wait = limiter.reserve(client).err().expect("burst exhausted");
    assert!(wait > Duration::ZERO && wait <= Duration::from_secs(60));
    for ticket in tickets {
        limiter.refund(ticket);
    }
    let admitted = core::iter::repeat_with(|| admits(&limiter, "192.0.2.1")).take(4);
    assert_eq!(admitted.collect::<Vec<_>>(), [true, true, true, false]);
    assert!(admits(&limiter, "192.0.2.2"));
}

/// # Panics
/// Panics if tracked clients exceed the bound, overflow clients are not shared,
/// or idle clients are not evicted.
#[tokio::test]
async fn tracked_clients_are_bounded_and_overflow_shares_one_budget() {
    let limiter = Limiter::new(limits(1, 600, 2)).expect("limits");
    assert!(admits(&limiter, "192.0.2.1"));
    assert!(admits(&limiter, "192.0.2.2"));
    assert!(admits(&limiter, "192.0.2.3"));
    assert!(!admits(&limiter, "192.0.2.4"));
    assert!(
        limiter
            .reserve(None)
            .is_err_and(|wait| wait > Duration::ZERO)
    );
    assert_eq!(limiter.tracked_len(), 2);
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(admits(&limiter, "192.0.2.5"));
    assert!(limiter.tracked_len() <= 2);
}

/// # Panics
/// Panics if a forwarded address is trusted from another peer, a duplicate or
/// invalid header is used, or IPv6 clients are not grouped by /64.
#[test]
fn only_the_trusted_proxy_names_the_client() {
    let limiter = Limiter::new(Admission {
        trusted_proxy: Some(ip("127.0.0.1")),
        ..limits(1, 1, 8)
    })
    .expect("limits");
    let proxy: SocketAddr = "127.0.0.1:443".parse().expect("proxy");
    let direct: SocketAddr = "198.51.100.9:443".parse().expect("peer");
    let headers = |values: &[&str]| {
        let mut headers = HeaderMap::new();
        for value in values {
            let _appended: bool =
                headers.append("x-real-ip", HeaderValue::from_str(value).expect("value"));
        }
        headers
    };
    let named = headers(&["203.0.113.7"]);
    assert_eq!(limiter.client(Some(proxy), &named), Some(ip("203.0.113.7")));
    assert_eq!(
        limiter.client(Some(direct), &named),
        Some(ip("198.51.100.9"))
    );
    for invalid in [
        headers(&[]),
        headers(&["203.0.113.7", "203.0.113.8"]),
        headers(&["not-an-address"]),
    ] {
        assert_eq!(limiter.client(Some(proxy), &invalid), Some(ip("127.0.0.1")));
    }
    assert_eq!(
        limiter.client(Some(proxy), &headers(&["2001:db8:1:2:3:4:5:6"])),
        Some(ip("2001:db8:1:2::"))
    );
    assert_eq!(
        limiter.client(Some(proxy), &headers(&["::ffff:203.0.113.7"])),
        Some(ip("203.0.113.7"))
    );
    assert_eq!(limiter.client(None, &named), None);
}

/// # Panics
/// Panics if a limit outside its documented range is accepted.
#[test]
fn limits_outside_their_ranges_fail_configuration() {
    let _: Admission = limits(1, 1, 1).validate().expect("smallest limits");
    for invalid in [
        limits(0, 60, 8),
        limits(65, 60, 8),
        limits(1, 0, 8),
        limits(1, 60_001, 8),
        limits(1, 60, 0),
        limits(1, 60, 100_001),
        Admission {
            rejected_token_seconds: 301,
            ..limits(1, 60, 8)
        },
    ] {
        let _: crate::Failure = invalid.validate().unwrap_err();
    }
}
