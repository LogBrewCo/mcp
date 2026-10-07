//! Retry advice preserves the supplied deadline and the public delay bound.

use core::time::Duration;
use std::time::UNIX_EPOCH;

use super::retry_after_at;

/// # Panics
/// Panics if future dates round below their deadline, or past dates add a delay.
#[test]
fn http_dates_round_up_to_milliseconds_without_retrying_early() {
    for (nanoseconds, expected) in [
        (0, 2000),
        (1_250_000_000, 750),
        (1_250_000_001, 750),
        (1_249_999_999, 751),
        (1_999_000_000, 1),
        (1_999_000_001, 1),
        (1_998_999_999, 2),
        (1_999_999_999, 1),
        (2_000_000_000, 0),
        (2_000_000_001, 0),
        (3_000_000_000, 0),
    ] {
        let now = UNIX_EPOCH
            .checked_add(Duration::from_nanos(nanoseconds))
            .expect("synthetic clock");
        assert_eq!(
            retry_after_at("Thu, 01 Jan 1970 00:00:02 GMT", now),
            Some(expected),
            "clock offset {nanoseconds} ns"
        );
    }
}

/// # Panics
/// Panics if date delays above the public bound round into an accepted value.
#[test]
fn http_date_delay_bound_includes_the_fractional_remainder() {
    let date = "Tue, 19 Jan 2038 03:14:07 GMT";
    assert_eq!(retry_after_at(date, UNIX_EPOCH), Some(2_147_483_647_000));
    let after_epoch = UNIX_EPOCH
        .checked_add(Duration::from_nanos(1))
        .expect("synthetic clock");
    assert_eq!(retry_after_at(date, after_epoch), Some(2_147_483_647_000));
    let before_epoch = UNIX_EPOCH
        .checked_sub(Duration::from_nanos(1))
        .expect("synthetic clock");
    assert_eq!(retry_after_at(date, before_epoch), None);
}

/// # Panics
/// Panics if numeric delays change units or invalid advice becomes a known delay.
#[test]
fn numeric_and_unknown_delays_keep_their_existing_meaning() {
    for (header, expected) in [
        ("0", Some(0)),
        ("00", Some(0)),
        ("1", Some(1000)),
        ("0001", Some(1000)),
        ("2147483647", Some(2_147_483_647_000)),
        ("2147483648", None),
        ("18446744073709551615", None),
        ("", None),
        ("-1", None),
        ("+1", None),
        ("0.5", None),
        ("1, 2", None),
        ("SYNTHETIC_PRIVATE_MARKER", None),
    ] {
        assert_eq!(retry_after_at(header, UNIX_EPOCH), expected);
    }
    assert_eq!(retry_after_at(&"0".repeat(128), UNIX_EPOCH), Some(0));
    assert_eq!(retry_after_at(&"0".repeat(129), UNIX_EPOCH), None);
}
