//! Bundles a bound server binary and notice inventories without network access.

/// # Errors
///
/// Returns an error for invalid arguments, failed input reads or package verification, or failed archive publication.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    logbrew_mcp_notices::package(std::env::args_os().skip(1))
}
