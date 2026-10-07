//! Collects locked dependency source notices without network access.

/// # Errors
///
/// Returns an error for invalid arguments, failed input reads or source verification, or failed notice publication.
fn main() -> Result<(), Box<dyn core::error::Error>> {
    logbrew_mcp_notices::run(std::env::args_os().skip(1))
}
