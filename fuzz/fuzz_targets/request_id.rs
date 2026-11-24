//! Fuzzes request ID handling: a numeric JSON-RPC ID that the server replaces
//! must come back unchanged in the reply.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some((original, restored)) = logbrew_mcp::fuzzing::request_id(data) {
        assert_eq!(
            restored.as_deref(),
            Some(original.as_str()),
            "the reply changed the request ID"
        );
    }
});
