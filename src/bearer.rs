//! Bounded OAuth bearer credentials with HTTP field whitespace handling.

use axum::http::{HeaderMap, header};

const TOKEN_BYTES: usize = 8 << 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rejection {
    Missing,
    Malformed,
}

/// Borrow the exact token from one bounded Bearer authorization field.
///
/// # Errors
/// Returns Missing for an absent field or another authentication scheme.
/// Returns Malformed for duplicate fields, invalid syntax or an invalid token.
pub fn parse(headers: &HeaderMap) -> Result<&str, Rejection> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(Rejection::Missing)?;
    if values.next().is_some() {
        return Err(Rejection::Malformed);
    }
    let value = value
        .to_str()
        .map_err(|_| Rejection::Malformed)?
        .trim_matches([' ', '\t']);
    if value.is_empty() {
        return Err(Rejection::Malformed);
    }
    let end = value.find([' ', '\t']).unwrap_or(value.len());
    let (scheme, rest) = value.split_at(end);
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(Rejection::Missing);
    }
    // The scheme delimiter is one or more SP, not general whitespace.
    let token = rest
        .strip_prefix(' ')
        .ok_or(Rejection::Malformed)?
        .trim_start_matches(' ');
    valid(token).then_some(token).ok_or(Rejection::Malformed)
}

pub fn valid(token: &str) -> bool {
    if token.is_empty() || token.len() > TOKEN_BYTES {
        return false;
    }
    let payload = token.trim_end_matches('=');
    !payload.is_empty()
        && payload.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
}

#[cfg(test)]
mod tests {
    use super::valid;

    #[test]
    fn token68_accepts_opaque_alphabet_and_trailing_padding_only() {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/";
        assert!(valid(alphabet));
        assert!(valid(&format!("{alphabet}===")));
        for byte in 0..=u8::MAX {
            let allowed = alphabet.as_bytes().contains(&byte);
            let token = format!("A{}Z", char::from(byte));
            assert_eq!(valid(&token), allowed, "byte {byte}");
        }
        for token in ["", "=", "===", "=A", "A=Z", "A==Z", " A", "A "] {
            assert!(!valid(token));
        }
    }

    #[test]
    fn token_size_includes_padding_without_base64_decoding() {
        assert!(valid(&"A".repeat(8192)));
        assert!(valid(&format!("A{}", "=".repeat(8191))));
        assert!(!valid(&"A".repeat(8193)));
        assert!(!valid(&format!("A{}", "=".repeat(8192))));
        assert!(valid("A"));
        assert!(valid(".~"));
    }
}
