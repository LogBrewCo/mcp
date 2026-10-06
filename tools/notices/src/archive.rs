use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read as _},
    path::Path,
};

use flate2::read::MultiGzDecoder;
use serde_json::Value;

use crate::{Result, bounded, checksum, error, relative_path, string};

pub const ARCHIVE_BYTES: u64 = 64 << 20;
pub const NOTICE_BYTES: u64 = 1 << 20;

pub struct Collected {
    pub vcs: Option<Value>,
    pub notices: BTreeMap<String, String>,
}

pub struct Prefix {
    pub bytes: u64,
    pub sha256: String,
    pub text: Vec<u8>,
}

impl Prefix {
    /// # Errors
    /// Rejects a changed complete source file or a mismatched notice prefix.
    fn verify(&self, entry: impl io::Read, limits: Limits, total_bytes: &mut usize) -> Result<()> {
        let source = bounded(entry, limits.notice_bytes)?;
        if u64::try_from(source.len())? != self.bytes
            || checksum(&source)? != self.sha256
            || self.text.is_empty()
            || !source.starts_with(&self.text)
        {
            return Err(error("source notice prefix binding mismatch"));
        }
        *total_bytes = total_bytes
            .checked_add(source.len())
            .ok_or_else(|| error("source size overflow"))?;
        if *total_bytes > limits.total_notice_bytes {
            return Err(error("source notice budget exceeded"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct Limits {
    pub expanded_bytes: u64,
    pub entries: usize,
    pub path_bytes: usize,
    pub notice_bytes: u64,
    pub total_notice_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            expanded_bytes: 256 << 20,
            entries: 100_000,
            path_bytes: 16 << 20,
            notice_bytes: NOTICE_BYTES,
            total_notice_bytes: 16 << 20,
        }
    }
}

pub fn category(filename: &str) -> Option<&'static str> {
    let lower = filename.to_ascii_lowercase();
    if Path::new(&lower)
        .extension()
        .and_then(|part| part.to_str())
        .is_some_and(|extension| {
            matches!(
                extension,
                "rs" | "toml"
                    | "json"
                    | "c"
                    | "h"
                    | "cc"
                    | "cpp"
                    | "hpp"
                    | "py"
                    | "go"
                    | "java"
                    | "js"
                    | "ts"
                    | "sh"
            )
        })
    {
        return None;
    }
    for (prefix, kind) in [
        ("license", "license"),
        ("licence", "license"),
        ("copying", "license"),
        ("notice", "notice"),
        ("copyright", "attribution"),
        ("authors", "attribution"),
    ] {
        if lower == prefix
            || lower.strip_prefix(prefix).is_some_and(|tail| {
                tail.starts_with('.') || tail.starts_with('-') || tail.starts_with('_')
            })
        {
            return Some(kind);
        }
    }
    None
}

/// # Errors
/// Read errors, invalid or empty UTF-8, notice-count overflow, or a notice
/// byte budget violation prevent insertion.
fn add_notice(
    entry: impl io::Read,
    relative: &str,
    limits: Limits,
    notices: &mut BTreeMap<String, String>,
    notice_bytes: &mut usize,
) -> Result<()> {
    let bytes = bounded(entry, limits.notice_bytes)?;
    let text = std::str::from_utf8(&bytes)?;
    if text.trim().is_empty() {
        return Err(error("empty notice file"));
    }
    *notice_bytes = notice_bytes
        .checked_add(bytes.len())
        .ok_or_else(|| error("notice size overflow"))?;
    if *notice_bytes > limits.total_notice_bytes || notices.len() >= 256 {
        return Err(error("notice budget exceeded"));
    }
    let _previous: Option<String> = notices.insert(relative.to_owned(), text.to_owned());
    Ok(())
}

/// # Errors
/// Rejects invalid archive size or checksum, unsafe or duplicate paths, links,
/// malformed metadata, mismatched package identity, exceeded entry or text
/// budgets, and incomplete or corrupt tar/gzip data. Reader and decoder errors
/// propagate.
pub fn collect(package: &Value, bytes: &[u8], expected: &str, limits: Limits) -> Result<Collected> {
    collect_with_prefixes(package, bytes, expected, limits, &BTreeMap::new())
}

/// # Errors
/// Rejects unsafe source paths and metadata or named-notice selections.
fn validate_prefixes(prefixes: &BTreeMap<String, Prefix>) -> Result<()> {
    for path in prefixes.keys() {
        let filename = relative_path(path)?
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| error("missing source filename"))?;
        if matches!(path.as_str(), "Cargo.toml" | ".cargo_vcs_info.json")
            || category(filename).is_some()
        {
            return Err(error("source prefix must select a source file"));
        }
    }
    Ok(())
}

/// # Errors
/// Rejects an absent package manifest or identity, license or repository drift.
fn verify_manifest(manifest: Option<&toml::Table>, package: &Value) -> Result<()> {
    let declared = manifest
        .and_then(|value| value.get("package"))
        .ok_or_else(|| error("missing archive manifest"))?;
    for key in ["name", "version", "license", "repository"] {
        if declared.get(key).and_then(toml::Value::as_str)
            != package.get(key).and_then(Value::as_str)
        {
            return Err(error("archive manifest disagrees with metadata"));
        }
    }
    Ok(())
}

/// # Errors
/// Applies the archive checks from `collect` and rejects unsafe or missing
/// source paths, metadata/notice-file selections, changed source bindings,
/// mismatched prefixes, and exceeded source-text budgets.
pub fn collect_with_prefixes(
    package: &Value,
    bytes: &[u8],
    expected: &str,
    limits: Limits,
    prefixes: &BTreeMap<String, Prefix>,
) -> Result<Collected> {
    validate_prefixes(prefixes)?;
    if u64::try_from(bytes.len())? > ARCHIVE_BYTES || checksum(bytes)? != expected {
        return Err(error("registry archive checksum or size mismatch"));
    }
    let prefix = format!(
        "{}-{}",
        string(package, "name")?,
        string(package, "version")?
    );
    let expanded_limit = limits
        .expanded_bytes
        .checked_add(1)
        .ok_or_else(|| error("invalid expansion limit"))?;
    let mut archive = tar::Archive::new(MultiGzDecoder::new(bytes).take(expanded_limit));
    let mut notices = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut path_bytes = 0_usize;
    let mut notice_bytes = 0_usize;
    let mut manifest = None;
    let mut vcs = None;
    let mut matched_prefixes = 0_usize;
    for (index, entry) in archive.entries()?.enumerate() {
        if index >= limits.entries {
            return Err(error("archive entry limit reached"));
        }
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let path = path
            .to_str()
            .ok_or_else(|| error("non-UTF8 archive path"))?;
        path_bytes = path_bytes
            .checked_add(path.len())
            .ok_or_else(|| error("archive path size overflow"))?;
        if path.len() > 4096 || path_bytes > limits.path_bytes {
            return Err(error("archive path budget exceeded"));
        }
        let _path: &Path = relative_path(path)?;
        let relative = Path::new(path)
            .strip_prefix(&prefix)?
            .to_str()
            .ok_or_else(|| error("invalid archive prefix"))?;
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            continue;
        }
        let _relative: &Path = relative_path(relative)?;
        if !kind.is_file() {
            return Err(error("archive link or special file rejected"));
        }
        if !seen.insert(relative.to_owned()) {
            return Err(error("duplicate archive path"));
        }
        let filename = Path::new(relative)
            .file_name()
            .and_then(|p| p.to_str())
            .ok_or_else(|| error("missing filename"))?;
        if relative == "Cargo.toml" {
            let manifest_bytes = bounded(&mut entry, 64 << 10)?;
            manifest = Some(std::str::from_utf8(&manifest_bytes)?.parse::<toml::Table>()?);
            continue;
        }
        if relative == ".cargo_vcs_info.json" {
            vcs = Some(serde_json::from_slice::<Value>(&bounded(
                &mut entry,
                16 << 10,
            )?)?);
            continue;
        }
        if let Some(source_prefix) = prefixes.get(relative) {
            source_prefix.verify(&mut entry, limits, &mut notice_bytes)?;
            matched_prefixes = matched_prefixes
                .checked_add(1)
                .ok_or_else(|| error("source count overflow"))?;
        }
        if category(filename).is_some() {
            add_notice(
                &mut entry,
                relative,
                limits,
                &mut notices,
                &mut notice_bytes,
            )?;
        }
    }
    // Read through every gzip footer, including data after the tar end marker.
    let mut expanded = archive.into_inner();
    let _remaining_bytes: u64 = io::copy(&mut expanded, &mut io::sink())?;
    if expanded.limit() == 0 {
        return Err(error("expanded archive exceeds limit"));
    }
    if matched_prefixes != prefixes.len() {
        return Err(error("source notice file missing from archive"));
    }
    verify_manifest(manifest.as_ref(), package)?;
    Ok(Collected { vcs, notices })
}
