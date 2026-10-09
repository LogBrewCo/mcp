//! Exports checked GNU linker inputs without extraction or binary execution.

/// # Errors
/// Returns an error for invalid inputs, rejected relocation or publication.
fn main() -> Result<(), Box<dyn core::error::Error>> {
    logbrew_mcp_notices::relink(std::env::args_os().skip(1))
}
