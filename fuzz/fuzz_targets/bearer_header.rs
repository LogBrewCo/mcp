//! Fuzzes the Bearer authorization parser with Authorization fields split on
//! NUL bytes. A token it accepts must pass the token check on its own.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let values = data.split(|byte| *byte == 0).collect::<Vec<_>>();
    if let Some(token) = logbrew_mcp::fuzzing::bearer_token(&values) {
        assert!(
            logbrew_mcp::fuzzing::valid_token(&token),
            "accepted an invalid token"
        );
    }
});
