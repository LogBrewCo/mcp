//! Checks the pinned dependency policy tool's process and structured results.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    logbrew_mcp_notices::policy(std::env::args_os().skip(1))
}
