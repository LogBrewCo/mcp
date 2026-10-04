//! Collects locked dependency source notices without network access.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    logbrew_mcp_notices::run(std::env::args_os().skip(1))
}
