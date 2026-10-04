//! Preserves authenticated Rust standard-library notices without network access.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    logbrew_mcp_notices::toolchain(std::env::args_os().skip(1))
}
