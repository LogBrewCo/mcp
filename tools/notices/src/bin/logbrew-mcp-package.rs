//! Bundles a bound server binary and notice inventories without network access.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    logbrew_mcp_notices::package(std::env::args_os().skip(1))
}
