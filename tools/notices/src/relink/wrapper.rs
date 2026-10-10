use alloc::{collections::BTreeSet, string::String, vec::Vec};
use std::io::Read as _;

use flate2::bufread::GzDecoder;
use serde::Deserialize;

use crate::{Result, bounded, checksum, error, package::FileBinding, relative_path};

const EXPANDED_BYTES: u64 = 96 << 20;
const ENTRY_COUNT: usize = 64;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Capture {
    pub binding: FileBinding,
    pub member: String,
}

impl Capture {
    /// # Errors
    /// Rejects invalid compressed bindings or unsafe selected member paths.
    pub(super) fn validate(&self) -> Result<()> {
        self.binding.validate(super::ARCHIVE_BYTES)?;
        let _path: &std::path::Path = relative_path(&self.member)?;
        Ok(())
    }

    /// # Errors
    /// Rejects excess expansion, corrupt gzip data, additional streams or
    /// trailing bytes, ambiguous tar members and changed enclosed archive bytes.
    pub(super) fn decode(&self, bytes: &[u8], expected: &FileBinding) -> Result<Vec<u8>> {
        let mut decoder = GzDecoder::new(bytes);
        let expanded = bounded(&mut decoder, EXPANDED_BYTES)?;
        if !decoder.into_inner().is_empty() {
            return Err(error(
                "capture wrapper has trailing or concatenated gzip data",
            ));
        }
        collect(&expanded, &self.member, expected)
    }
}

/// # Errors
/// Rejects links, special files, duplicates, unsafe paths, missing selected
/// input, changed bytes, nonzero tar trailing data and exceeded budgets.
fn collect(bytes: &[u8], member: &str, expected: &FileBinding) -> Result<Vec<u8>> {
    let mut archive = tar::Archive::new(bytes);
    let mut paths = BTreeSet::new();
    let mut payload_bytes = 0_u64;
    let mut path_bytes = 0_usize;
    let mut selected = None;
    for (index, entry) in archive.entries()?.raw(true).enumerate() {
        if index >= ENTRY_COUNT {
            return Err(error("capture wrapper entry count exceeds limit"));
        }
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let path = path
            .to_str()
            .ok_or_else(|| error("non-UTF8 capture wrapper path"))?;
        let _safe: &std::path::Path = relative_path(path)?;
        if !entry.header().entry_type().is_file() || !paths.insert(path.to_owned()) {
            return Err(error(
                "capture wrapper has a duplicate or nonregular member",
            ));
        }
        payload_bytes = payload_bytes
            .checked_add(entry.size())
            .ok_or_else(|| error("capture wrapper payload size overflow"))?;
        path_bytes = path_bytes
            .checked_add(path.len())
            .ok_or_else(|| error("capture wrapper path size overflow"))?;
        if entry.size() > super::ARCHIVE_BYTES
            || payload_bytes > EXPANDED_BYTES
            || path_bytes > 64_usize << 10_u32
        {
            return Err(error("capture wrapper payload or path budget exceeded"));
        }
        if path == member {
            let body = bounded(&mut entry, super::ARCHIVE_BYTES)?;
            selected = Some(body);
        }
    }
    let mut tail = Vec::new();
    let _remaining: usize = archive.into_inner().read_to_end(&mut tail)?;
    if tail.len() < 512 || !bytes.len().is_multiple_of(512) || tail.iter().any(|byte| *byte != 0) {
        return Err(error(
            "capture wrapper has missing, unaligned or nonzero tar end data",
        ));
    }
    let selected =
        selected.ok_or_else(|| error("capture wrapper lacks selected linker archive"))?;
    if u64::try_from(selected.len())? != expected.bytes || checksum(&selected)? != expected.sha256 {
        return Err(error(
            "enclosed linker archive differs from its trusted binding",
        ));
    }
    Ok(selected)
}
