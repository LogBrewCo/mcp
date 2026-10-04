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

impl From<error::Kind> for Failure {
    fn from(kind: error::Kind) -> Self {
        Self {
            kind,
            retry_after_ms: None,
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.kind.code())
    }
}

impl std::error::Error for Failure {}
