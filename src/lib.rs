//! Authenticated, bounded `LogBrew` MCP service.

mod bearer;
pub mod catalog;
pub mod clients;
mod connections;
mod deadline;
mod delivery;
pub mod error;
pub mod json;
mod media;
mod outbound;
pub mod protocol;
mod responses;
pub mod runtime;
pub mod startup;
pub mod telemetry;
mod transport;
pub mod upstream;

/// Maximum bytes in one complete protocol request.
pub const REQUEST_BYTES: usize = 64 << 10;
/// Maximum bytes in operation input.
pub const INPUT_BYTES: usize = 4 << 10;
/// Maximum bytes in operation output data.
pub const OUTPUT_BYTES: usize = 2 << 20;
/// Separate allowance for fixed result metadata.
pub const ENVELOPE_BYTES: usize = OUTPUT_BYTES + 1024;

/// Fixed, privacy-safe execution failure and recovery guidance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    /// Stable failure classification.
    pub kind: error::Kind,
    /// Supplied retry delay, with unknown distinct from zero.
    pub retry_after_ms: Option<u64>,
}

impl Failure {
    /// Convert an internal cause into a fixed public category.
    ///
    /// Causes can contain paths, credentials or payloads. This boundary drops
    /// the cause and retains only the selected category, with an unknown retry
    /// delay. `Display`, `Debug` and `Error::source` cannot expose the discarded cause.
    pub(crate) fn redact<E>(kind: error::Kind) -> impl FnOnce(E) -> Self {
        move |cause| {
            drop(cause);
            Self::from(kind)
        }
    }
}

impl From<error::Kind> for Failure {
    fn from(kind: error::Kind) -> Self {
        Self {
            kind,
            retry_after_ms: None,
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.kind.code())
    }
}

impl std::error::Error for Failure {}

#[cfg(test)]
mod tests {
    use std::{error::Error as _, io, sync::Arc};

    use super::{Failure, error::Kind};

    /// Reject retained sensitive causes and preserve the fixed failure contract.
    ///
    /// # Panics
    /// Fails if redaction retains a cause, changes its category or retry delay,
    /// or exposes the discarded value through a diagnostic or source chain.
    #[test]
    fn redaction_drops_sensitive_cause_and_preserves_public_failure() {
        let cause = Arc::new(io::Error::other(
            "SYNTHETIC_PRIVATE_PATH SYNTHETIC_BEARER_SECRET SYNTHETIC_UPSTREAM_PAYLOAD",
        ));
        let observed = Arc::downgrade(&cause);
        let failure = Failure::redact::<io::Error>(Kind::Unavailable)(io::Error::other(cause));
        assert!(observed.upgrade().is_none());
        assert_eq!(failure.kind, Kind::Unavailable);
        assert_eq!(failure.retry_after_ms, None);
        assert_eq!(failure.to_string(), "unavailable");
        assert_eq!(
            format!("{failure:?}"),
            "Failure { kind: Unavailable, retry_after_ms: None }"
        );
        assert!(failure.source().is_none());
    }
}
