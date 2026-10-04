use std::path::Path;

use crate::Result;

pub fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use rustix::fs::{self, FileType, Mode, OFlags};
        let file = std::fs::File::from(fs::open(
            path,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let before = fs::fstat(&file)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || u64::try_from(before.st_size)? > limit
        {
            return Err(crate::error("notice input must be a bounded regular file"));
        }
        let bytes = crate::bounded(&file, limit)?;
        if u64::try_from(bytes.len())? != u64::try_from(before.st_size)?
            || fs::fstat(&file)?.st_size != before.st_size
        {
            return Err(crate::error("notice input size changed while reading"));
        }
        Ok(bytes)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (path, limit);
        Err(crate::error("notice input is supported on Linux and macOS"))
    }
}
