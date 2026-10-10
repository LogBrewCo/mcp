//! Bundles selected recipient files with byte bindings and explicit coverage limits.

/// # Errors
/// Returns an error for rejected inputs or failed atomic publication.
fn main() -> Result<(), Box<dyn core::error::Error>> {
    logbrew_mcp_notices::materials(std::env::args_os().skip(1))
}
