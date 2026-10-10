//! Collects named source notices from locked Cargo archives and checked supplements.

extern crate alloc;

mod archive;
mod input;
mod materials;
mod package;
mod policy;
mod publication;
mod relink;
mod supplement;
mod toolchain;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod test_directory;

use alloc::collections::BTreeMap;
use core::fmt::Write as _;
use std::{
    io::{self, Read as _},
    path::{Component, Path, PathBuf},
};

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

type Result<T> = core::result::Result<T, Box<dyn core::error::Error>>;

/// Bundle selected, checksum-bound recipient materials without extracting them.
///
/// # Errors
/// Rejects invalid plans, changed or unsafe inputs, selected private markers,
/// output aliases and publication failures.
pub fn materials<Args>(args: Args) -> Result<()>
where
    Args: Iterator<Item = std::ffi::OsString>,
{
    materials::run(args)
}

/// Export bound GNU linker inputs with checked relative-path mappings.
///
/// # Errors
/// Rejects an invalid plan, changed or unsafe archive inputs, unsupported
/// response arguments, selected private markers, and publication failures.
pub fn relink<Args>(args: Args) -> Result<()>
where
    Args: Iterator<Item = std::ffi::OsString>,
{
    relink::run(args)
}

/// Run the pinned offline dependency policy gate from one executable argument.
///
/// # Errors
/// Rejects process failures, incomplete output, and warning or error records.
pub fn policy<Args>(args: Args) -> Result<()>
where
    Args: Iterator<Item = std::ffi::OsString>,
{
    policy::run(args)
}

fn error(message: &str) -> Box<dyn core::error::Error> {
    io::Error::other(message).into()
}

/// # Errors
/// Returns an error if the requested field is absent or is not a string.
fn string<'value>(value: &'value Value, key: &str) -> Result<&'value str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| error("missing string field"))
}

/// # Errors
/// Propagates hexadecimal digest formatting errors.
fn checksum(bytes: &[u8]) -> Result<String> {
    let mut result = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(result, "{byte:02x}")?;
    }
    Ok(result)
}

/// # Errors
/// Rejects limit overflow, reader failures, byte-count conversion failure,
/// and input beyond the byte limit.
fn bounded<Reader>(reader: Reader, limit: u64) -> Result<Vec<u8>>
where
    Reader: io::Read,
{
    let read_limit = limit
        .checked_add(1)
        .ok_or_else(|| error("invalid byte limit"))?;
    let mut bytes = Vec::new();
    let _read_bytes: usize = reader.take(read_limit).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len())? > limit {
        return Err(error("file exceeds limit"));
    }
    Ok(bytes)
}

/// # Errors
/// Rejects empty, oversized, absolute, nonnormal, or ambiguous paths,
/// including dot components, empty components, backslashes, NULs, and line breaks.
fn relative_path(value: &str) -> Result<&Path> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 4096
        || value.contains(['\\', '\0', '\n', '\r'])
        || value
            .split('/')
            .any(|part| part == "." || part == ".." || part.is_empty())
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(error("invalid relative path"));
    }
    Ok(path)
}

/// # Errors
/// Rejects missing name/version strings and empty, oversized, or unsupported
/// package identity characters.
fn identity(package: &Value) -> Result<String> {
    let name = string(package, "name")?;
    let version = string(package, "version")?;
    if name.is_empty()
        || name.len() > 128
        || version.is_empty()
        || version.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
    {
        return Err(error("invalid package identity"));
    }
    Ok(format!("{name} {version}"))
}

#[derive(Default)]
struct Texts {
    values: BTreeMap<String, String>,
    bytes: usize,
    files: usize,
}

impl Texts {
    /// # Errors
    /// Rejects file-count or text-size overflow, exceeded file/text budgets, and
    /// a digest collision. Counters may have advanced before failure; callers
    /// discard the failed inventory.
    fn insert(&mut self, text: &str) -> Result<String> {
        self.files = self
            .files
            .checked_add(1)
            .ok_or_else(|| error("file count overflow"))?;
        if self.files > 4096 {
            return Err(error("notice file limit reached"));
        }
        let digest = checksum(text.as_bytes())?;
        let existing = self.values.get(&digest);
        if existing.is_some_and(|value| value != text) {
            return Err(error("notice digest collision"));
        }
        if existing.is_some() {
            return Ok(digest);
        }
        self.bytes = self
            .bytes
            .checked_add(text.len())
            .ok_or_else(|| error("text size overflow"))?;
        if self.bytes > 16_usize << 20_u32 {
            return Err(error("total notice text budget exceeded"));
        }
        let _previous: Option<String> = self.values.insert(digest.clone(), text.to_owned());
        Ok(digest)
    }
}

/// # Errors
/// Returns an error for absent package fields, bounded archive or installed
/// file reads, archive verification, changed installed notice bytes, invalid
/// notice categories, and text-inventory admission.
fn registry(
    package: &Value,
    root: &Path,
    cache: &Path,
    expected: &str,
    texts: &mut Texts,
) -> Result<Value> {
    let name = string(package, "name")?;
    let version = string(package, "version")?;
    let bytes = input::read(
        &cache.join(format!("{name}-{version}.crate")),
        archive::ARCHIVE_BYTES,
    )?;
    let collected = archive::collect(package, &bytes, expected, archive::Limits::default())?;
    let mut files = BTreeMap::new();
    for (relative, text) in collected.notices {
        let installed = input::read(&root.join(&relative), archive::NOTICE_BYTES)?;
        if installed != text.as_bytes() {
            return Err(error("installed notice differs from locked archive"));
        }
        let kind = Path::new(&relative)
            .file_name()
            .and_then(|p| p.to_str())
            .and_then(archive::category)
            .ok_or_else(|| error("invalid notice category"))?;
        let digest = texts.insert(&text)?;
        let _previous: Option<Value> = files.insert(
            relative,
            json!({"kind":kind,"sha256":digest,"bytes":text.len()}),
        );
    }
    Ok(
        json!({"name":name,"version":version,"declared_license":package.get("license"),
        "repository":package.get("repository"),"vcs":collected.vcs,"files":files,
        "published_package_sha256":expected,"published_archive_verified":true}),
    )
}

/// # Errors
/// Rejects failed bounded license reads, invalid or empty UTF-8, and text
/// inventory admission failures.
fn project_notice(package: &Value, root: &Path, texts: &mut Texts) -> Result<Value> {
    let bytes = input::read(&root.join("LICENSE"), archive::NOTICE_BYTES)?;
    let text = core::str::from_utf8(&bytes)?;
    if text.trim().is_empty() {
        return Err(error("empty project license"));
    }
    let digest = texts.insert(text)?;
    Ok(
        json!({"name":package.get("name"),"version":package.get("version"),"declared_license":package.get("license"),
        "files":{"LICENSE":{"kind":"license","sha256":digest,"bytes":bytes.len()}},
        "published_archive_verified":false}),
    )
}

/// # Errors
/// Rejects invalid lockfile or metadata, excess or incomplete package coverage,
/// duplicate identities, unsupported sources, source disagreement, absent
/// checksums or package paths, and failed archive or project-notice verification.
fn inventory(
    metadata: &Value,
    lock_bytes: &[u8],
    cache: &Path,
    texts: &mut Texts,
) -> Result<BTreeMap<String, Value>> {
    let lock = core::str::from_utf8(lock_bytes)?.parse::<toml::Table>()?;
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| error("invalid packages"))?;
    if packages.is_empty() || packages.len() > 512 {
        return Err(error("invalid package count"));
    }
    let locked = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| error("invalid lock packages"))?;
    if locked.len() != packages.len() {
        return Err(error("metadata does not cover full lockfile"));
    }
    let mut expected = BTreeMap::new();
    for package in locked {
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| error("missing lock name"))?;
        let version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| error("missing lock version"))?;
        let source = package.get("source").and_then(toml::Value::as_str);
        let digest = package.get("checksum").and_then(toml::Value::as_str);
        if expected
            .insert(format!("{name} {version}"), (source, digest))
            .is_some()
        {
            return Err(error("duplicate lock package"));
        }
    }
    let mut result = BTreeMap::new();
    for package in packages {
        let key = identity(package)?;
        let &(source, digest) = expected
            .get(&key)
            .ok_or_else(|| error("metadata package absent from lockfile"))?;
        if source != package.get("source").and_then(Value::as_str) {
            return Err(error("source disagrees with lockfile"));
        }
        let root = Path::new(string(package, "manifest_path")?)
            .parent()
            .ok_or_else(|| error("invalid package root"))?;
        let record = if source == Some("registry+https://github.com/rust-lang/crates.io-index") {
            registry(
                package,
                root,
                cache,
                digest.ok_or_else(|| error("missing archive checksum"))?,
                texts,
            )?
        } else if string(package, "name")? == "logbrew-mcp" && source.is_none() && digest.is_none()
        {
            project_notice(package, root, texts)?
        } else {
            return Err(error("unsupported source"));
        };
        if result.insert(key, record).is_some() {
            return Err(error("duplicate metadata package"));
        }
    }
    if result.keys().ne(expected.keys()) {
        return Err(error("metadata does not cover full lockfile"));
    }
    Ok(result)
}

/// # Errors
/// Returns an error for failed package or supplement verification, missing
/// verified notices, checksum or JSON serialization failure, and output beyond
/// the byte budget.
fn generate(
    metadata: &Value,
    lock_bytes: &[u8],
    cache: &Path,
    supplemental_bytes: &[u8],
    supplemental_root: &Path,
) -> Result<Vec<u8>> {
    let mut texts = Texts::default();
    let mut packages = inventory(metadata, lock_bytes, cache, &mut texts)?;
    supplement::apply(
        &mut packages,
        &mut texts,
        supplemental_bytes,
        supplemental_root,
        cache,
    )?;
    for package in packages.values() {
        let files = package
            .get("files")
            .and_then(Value::as_object)
            .ok_or_else(|| error("missing notice inventory"))?;
        if files.is_empty()
            && package
                .get("supplemental_notices")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
        {
            return Err(error("package has no verified notice source"));
        }
    }
    let output = json!({"format_version":1_u32,"scope":"all_locked_packages_including_inactive_and_development",
        "inventory_kind":"named_source_license_and_attribution_files_with_verified_source_prefixes","binary_and_toolchain_coverage":"not_evaluated",
        "license_permission_check":"separate_cargo_deny_gate_required","cargo_lock_sha256":checksum(lock_bytes)?,
        "supplement_manifest_sha256":checksum(supplemental_bytes)?,"packages":packages,"texts":texts.values});
    let mut bytes = serde_json::to_vec_pretty(&output)?;
    bytes.push(b'\n');
    if bytes.len() > 64_usize << 20_u32 {
        return Err(error("output budget exceeded"));
    }
    Ok(bytes)
}

/// Generate a locked dependency source inventory from five path arguments.
///
/// # Errors
/// Returns an error for invalid arguments, failed source verification or publication.
pub fn run<Args>(mut args: Args) -> Result<()>
where
    Args: Iterator<Item = std::ffi::OsString>,
{
    let metadata_path = args
        .next()
        .ok_or_else(|| error("missing Cargo metadata JSON argument"))?;
    let lock_path = args
        .next()
        .ok_or_else(|| error("missing Cargo.lock argument"))?;
    let cache_path = args
        .next()
        .ok_or_else(|| error("missing registry cache directory argument"))?;
    let supplemental_path = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| error("missing supplemental source manifest argument"))?;
    let output_path = args
        .next()
        .ok_or_else(|| error("missing output argument"))?;
    if args.next().is_some() {
        return Err(error("extra arguments"));
    }
    let metadata = serde_json::from_slice(&input::read(Path::new(&metadata_path), 16 << 20)?)?;
    let lock_bytes = input::read(Path::new(&lock_path), 1 << 20)?;
    let supplemental_bytes = input::read(&supplemental_path, 512 << 10)?;
    let supplemental_root = supplemental_path
        .parent()
        .ok_or_else(|| error("invalid supplement directory"))?;
    let output = generate(
        &metadata,
        &lock_bytes,
        Path::new(&cache_path),
        &supplemental_bytes,
        supplemental_root,
    )?;
    publication::write(Path::new(&output_path), &output)?;
    Ok(())
}

/// Verify and preserve Rust standard-library notices from five path arguments.
///
/// # Errors
/// Returns an error for invalid source bindings, distribution data or publication.
pub fn toolchain<Args>(mut args: Args) -> Result<()>
where
    Args: Iterator<Item = std::ffi::OsString>,
{
    let sources = args.next().ok_or_else(|| error("missing source binding"))?;
    let manifest = args
        .next()
        .ok_or_else(|| error("missing distribution manifest"))?;
    let archive = args
        .next()
        .ok_or_else(|| error("missing component archive"))?;
    let installed = args
        .next()
        .ok_or_else(|| error("missing installed library notice"))?;
    let output = args.next().ok_or_else(|| error("missing output"))?;
    if args.next().is_some() {
        return Err(error("extra arguments"));
    }
    let sources = toolchain::source(&input::read(Path::new(&sources), 8 << 10)?)?;
    let manifest = input::read(Path::new(&manifest), 2 << 20)?;
    toolchain::distribution(&sources, &manifest)?;
    let archive = input::read(Path::new(&archive), toolchain::ARCHIVE_BYTES)?;
    let installed = input::read(Path::new(&installed), toolchain::NOTICE_BYTES)?;
    let output_bytes = toolchain::collect(&sources, &archive, &installed)?;
    publication::write(Path::new(&output), &output_bytes)
}

/// Bundle a bound server binary and notices from four path arguments.
///
/// # Errors
/// Returns an error for invalid bindings, mismatched input bytes or publication.
pub fn package<Args>(mut args: Args) -> Result<()>
where
    Args: Iterator<Item = std::ffi::OsString>,
{
    let plan_path = args.next().ok_or_else(|| error("missing packaging plan"))?;
    let binary = args.next().ok_or_else(|| error("missing server binary"))?;
    let root = args
        .next()
        .ok_or_else(|| error("missing repository root"))?;
    let output = args.next().ok_or_else(|| error("missing package output"))?;
    if args.next().is_some() {
        return Err(error("extra arguments"));
    }
    let plan = input::read(Path::new(&plan_path), 16 << 10)?;
    let bytes = package::build(&plan, Path::new(&binary), Path::new(&root))?;
    package::guard_output(
        &plan,
        Path::new(&plan_path),
        Path::new(&binary),
        Path::new(&root),
        Path::new(&output),
    )?;
    publication::write(Path::new(&output), &bytes)
}
