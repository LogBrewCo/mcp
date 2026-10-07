//! Checks the pinned dependency policy tool's process and structured results.

/// # Errors
///
/// Returns an error for invalid arguments, untrusted tooling, process failures, incomplete output, or rejected dependency policy records.
fn main() -> Result<(), Box<dyn core::error::Error>> {
    logbrew_mcp_notices::policy(std::env::args_os().skip(1))
}
