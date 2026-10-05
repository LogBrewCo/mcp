use std::path::Path;

use crate::Result;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix;

/// # Errors
/// Rejects unsupported platforms or oversized output and propagates staging,
/// write, and publication errors. A directory-sync error can occur after the
/// destination has been replaced.
pub fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unix::write(path, bytes)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (path, bytes);
        Err(crate::error(
            "atomic notice output is supported on Linux and macOS",
        ))
    }
}
