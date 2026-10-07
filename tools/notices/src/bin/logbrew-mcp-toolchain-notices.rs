//! Preserves authenticated Rust standard-library notices without network access.

/// # Errors
///
/// Returns an error for invalid arguments, failed input reads or toolchain notice verification, or failed notice publication.
fn main() -> Result<(), Box<dyn core::error::Error>> {
    logbrew_mcp_notices::toolchain(std::env::args_os().skip(1))
}
