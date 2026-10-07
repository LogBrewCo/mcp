//! Preserve the return type of discarded fixture counters.

/// Discard a counter value while requiring the exact `usize` contract.
pub const fn discard_count(_: usize) {}
