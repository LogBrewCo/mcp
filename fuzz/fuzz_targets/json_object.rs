//! Fuzzes the bounded JSON object parser that reads every request body.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _object = logbrew_mcp::json::object(data, logbrew_mcp::REQUEST_BYTES);
});
