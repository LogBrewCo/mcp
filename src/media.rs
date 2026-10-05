//! Recognize JSON media types and unencoded content using HTTP field syntax.

use axum::http::{HeaderMap, header};

pub fn json(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    values.next().is_none() && json_value(ows(value.as_bytes())).is_some()
}

pub fn unencoded(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
        .all(unencoded_coding)
}

fn unencoded_coding(coding: &[u8]) -> bool {
    let coding = ows(coding);
    // RFC 9110 section 5.6.1 requires ignoring empty list members.
    coding.is_empty()
        || token(coding).is_some_and(|(name, rest)| {
            name.eq_ignore_ascii_case(b"identity") && ows(rest).is_empty()
        })
}

fn json_value(value: &[u8]) -> Option<()> {
    let (kind, rest) = token(value)?;
    let (subtype, rest) = token(rest.strip_prefix(b"/")?)?;
    if !kind.eq_ignore_ascii_case(b"application") || !subtype.eq_ignore_ascii_case(b"json") {
        return None;
    }
    let mut rest = ows(rest);
    // RFC 9110 sections 5.6.6 and 8.3.1 permit OWS and empty parameters.
    while !rest.is_empty() {
        rest = ows(rest.strip_prefix(b";")?);
        if rest.is_empty() || rest.starts_with(b";") {
            continue;
        }
        let (_, suffix) = token(rest)?;
        rest = suffix.strip_prefix(b"=")?;
        rest = if let Some(quoted) = rest.strip_prefix(b"\"") {
            quoted_value(quoted)?
        } else {
            token(rest)?.1
        };
        rest = ows(rest);
    }
    Some(())
}

fn token(value: &[u8]) -> Option<(&[u8], &[u8])> {
    let length = value
        .iter()
        .take_while(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    **byte,
                    b'!' | b'#'
                        ..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
                )
        })
        .count();
    if length == 0 {
        None
    } else {
        value.split_at_checked(length)
    }
}

const fn ows(mut value: &[u8]) -> &[u8] {
    while let Some((b' ' | b'\t', rest)) = value.split_first() {
        value = rest;
    }
    value
}

fn quoted_value(value: &[u8]) -> Option<&[u8]> {
    let mut escaped = false;
    for (index, byte) in value.iter().copied().enumerate() {
        if escaped && !matches!(byte, b'\t' | b' '..=b'~' | 0x80..=0xff) {
            return None;
        }
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'"' => return value.get(index.checked_add(1)?..),
            b'\\' => escaped = true,
            b'\t' | b' ' | b'!' | b'#'..=b'[' | b']'..=b'~' | 0x80..=0xff => {}
            _ => return None,
        }
    }
    None
}
