use alloc::{collections::BTreeMap, string::String, vec::Vec};
use std::{
    io::Read as _,
    path::{Path, PathBuf},
};

use flate2::{Compression, GzBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Result, bounded, checksum, error, input, package, publication, relative_path};
use package::FileBinding;

mod paths;
mod response;

#[cfg(test)]
mod tests;

const ARCHIVE_BYTES: u64 = 64 << 20;
const FILE_BYTES: u64 = 32 << 20;
const FILE_COUNT: usize = 1024;
const RESPONSE_BYTES: usize = 128 << 10;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Linker {
    version: String,
    source_commit: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathMap {
    from: String,
    to: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    format_version: u8,
    package_version: String,
    build_identity: String,
    source_revision: String,
    rust_release: String,
    target: String,
    input_archive: FileBinding,
    reference_binary: FileBinding,
    linker: Linker,
    archive_root: String,
    path_maps: Vec<PathMap>,
    private_path_markers: Vec<String>,
}

impl Plan {
    /// # Errors
    /// Rejects unknown or duplicate fields, invalid identity, unsupported
    /// target, malformed bindings, mappings or marker limits.
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 16_usize << 10_u32 {
            return Err(error("relink plan exceeds limit"));
        }
        let plan: Self = serde_json::from_slice(bytes)?;
        if plan.format_version != 1
            || plan.package_version != env!("CARGO_PKG_VERSION")
            || plan.rust_release != env!("CARGO_PKG_RUST_VERSION")
            || !package::hex(&plan.source_revision, 40)
            || plan.build_identity != "development" && plan.build_identity != plan.package_version
            || !matches!(
                plan.target.as_str(),
                "aarch64-unknown-linux-gnu" | "x86_64-unknown-linux-gnu"
            )
            || plan.linker.version != "23.1.3"
            || plan.linker.source_commit != "0d261d1ca552c95a8f007e061c787ac7132fbcbc"
            || plan.archive_root.contains('/')
        {
            return Err(error("invalid relink identity"));
        }
        let _root: &std::path::Path = relative_path(&plan.archive_root)?;
        plan.input_archive.validate(ARCHIVE_BYTES)?;
        plan.reference_binary.validate(ARCHIVE_BYTES)?;
        paths::validate(&plan.path_maps, &plan.private_path_markers)?;
        Ok(plan)
    }
}

/// # Errors
/// Rejects unsafe, duplicate or nonregular entries, exceeded budgets, malformed
/// tar input and nonzero data after the tar end marker.
fn collect(bytes: &[u8], root: &str) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut archive = tar::Archive::new(bytes);
    let mut files = BTreeMap::new();
    let mut path_bytes = 0_usize;
    let mut payload_bytes = 0_usize;
    for (index, entry) in archive.entries()?.enumerate() {
        if index >= FILE_COUNT {
            return Err(error("relink input count exceeds limit"));
        }
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            return Err(error("relink archive must contain regular files only"));
        }
        let full_path = entry.path()?.into_owned();
        let full_path = full_path
            .to_str()
            .ok_or_else(|| error("non-UTF8 relink input path"))?;
        let _safe: &std::path::Path = relative_path(full_path)?;
        let path = full_path
            .strip_prefix(root)
            .and_then(|suffix| suffix.strip_prefix('/'))
            .ok_or_else(|| error("relink input outside declared archive root"))?;
        let _relative: &std::path::Path = relative_path(path)?;
        path_bytes = path_bytes
            .checked_add(full_path.len())
            .ok_or_else(|| error("relink path size overflow"))?;
        if path_bytes > 2_usize << 20_u32 || files.contains_key(path) {
            return Err(error("duplicate relink input or path budget exceeded"));
        }
        let body = bounded(&mut entry, FILE_BYTES)?;
        payload_bytes = payload_bytes
            .checked_add(body.len())
            .ok_or_else(|| error("relink input size overflow"))?;
        if u64::try_from(payload_bytes)? > ARCHIVE_BYTES {
            return Err(error("relink input budget exceeded"));
        }
        let _previous: Option<Vec<u8>> = files.insert(path.to_owned(), body);
    }
    let mut tail = Vec::new();
    let _remaining: usize = archive.into_inner().read_to_end(&mut tail)?;
    if tail.iter().any(|byte| *byte != 0) || files.len() < 3 {
        return Err(error(
            "relink archive has nonzero trailing data or missing inputs",
        ));
    }
    Ok(files)
}

/// # Errors
/// Rejects a missing or changed exact linker version record.
fn verify_linker(plan: &Plan, files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    let expected = format!(
        "LLD {} (https://github.com/llvm/llvm-project {})\n",
        plan.linker.version, plan.linker.source_commit
    );
    if files.get("version.txt").map(Vec::as_slice) != Some(expected.as_bytes()) {
        return Err(error("relink linker version differs from plan"));
    }
    Ok(())
}

/// # Errors
/// Rejects invalid response data, unsafe or colliding output paths, unused
/// mappings, selected private markers and archive-write failures.
fn export(plan: &Plan, input: &[u8]) -> Result<Vec<u8>> {
    let files = collect(input, &plan.archive_root)?;
    verify_linker(plan, &files)?;
    let original_response = files
        .get("response.txt")
        .filter(|bytes| bytes.len() <= RESPONSE_BYTES)
        .ok_or_else(|| error("missing or oversized relink response"))?;
    let mut remapper = paths::Remapper::new(&plan.path_maps);
    let response = response::rewrite(
        core::str::from_utf8(original_response)?,
        &files,
        &mut remapper,
        &plan.target,
    )?;
    let mut output_files = BTreeMap::new();
    let mut records = Vec::<Value>::new();
    for (path, bytes) in files {
        let output_path = remapper.map(&path)?;
        let _relative: &std::path::Path = relative_path(&output_path)?;
        if response::conflicts(&output_path, "MANIFEST.json")
            || output_files
                .keys()
                .any(|previous: &String| response::conflicts(previous, &output_path))
        {
            return Err(error("relink output path collision"));
        }
        let body = if path == "response.txt" {
            response.as_bytes().to_vec()
        } else {
            bytes
        };
        paths::check_markers(output_path.as_bytes(), &plan.private_path_markers)?;
        paths::check_markers(&body, &plan.private_path_markers)?;
        records.push(json!({
            "path": output_path,
            "bytes": body.len(),
            "sha256": checksum(&body)?,
        }));
        let _previous: Option<Vec<u8>> = output_files.insert(output_path, body);
    }
    remapper.finish()?;
    let manifest = serde_json::to_vec_pretty(&json!({
        "format_version": 1_u32,
        "scope": "gnu_final_link_inputs",
        "package_version": plan.package_version,
        "build_identity": plan.build_identity,
        "source_revision": plan.source_revision,
        "rust_release": plan.rust_release,
        "target": plan.target,
        "source_archive": plan.input_archive,
        "reference_binary": plan.reference_binary,
        "linker": plan.linker,
        "command": ["ld.lld", "@response.txt"],
        "working_directory": "relink",
        "files": records,
        "selected_private_marker_checks": "passed",
        "unchanged_executable_reproduction": "external_required",
        "complete_corresponding_source": "external_required",
        "source_modification_and_relink": "external_required",
        "complete_permissions_and_release": "external_required",
    }))?;
    paths::check_markers(&manifest, &plan.private_path_markers)?;
    let writer = GzBuilder::new().mtime(0).operating_system(255).write(
        package::Output {
            bytes: Vec::new(),
            limit: usize::try_from(ARCHIVE_BYTES)?,
        },
        Compression::default(),
    );
    let mut builder = tar::Builder::new(writer);
    for (path, bytes) in output_files {
        package::append(&mut builder, "relink", &path, &bytes, 0o644)?;
    }
    package::append(&mut builder, "relink", "MANIFEST.json", &manifest, 0o644)?;
    Ok(builder.into_inner()?.finish()?.bytes)
}

/// # Errors
/// Rejects invalid arguments, aliased output, invalid or changed bound inputs,
/// failed relocation or atomic publication.
pub fn run<Args>(args: Args) -> Result<()>
where
    Args: Iterator<Item = std::ffi::OsString>,
{
    let mut paths = args.map(PathBuf::from);
    let plan_path = paths
        .next()
        .ok_or_else(|| error("missing relink plan path"))?;
    let archive_path = paths
        .next()
        .ok_or_else(|| error("missing relink archive path"))?;
    let output_path = paths
        .next()
        .ok_or_else(|| error("missing relink output path"))?;
    if paths.next().is_some() {
        return Err(error(
            "expected relink plan, LLD tar archive and output archive",
        ));
    }
    if !plan_path.is_absolute() || !archive_path.is_absolute() || !output_path.is_absolute() {
        return Err(error("relink paths must be absolute"));
    }
    guard_output(&output_path, &[&plan_path, &archive_path])?;
    let plan = Plan::parse(&input::read(&plan_path, 16 << 10)?)?;
    let archive = plan.input_archive.read(&archive_path, ARCHIVE_BYTES)?;
    publication::write(&output_path, &export(&plan, &archive)?)
}

/// # Errors
/// Rejects output paths aliasing either input and propagates metadata failures.
pub fn guard_output(output: &Path, inputs: &[&PathBuf]) -> Result<()> {
    let parent = output
        .parent()
        .ok_or_else(|| error("missing relink output parent"))?;
    let name = output
        .file_name()
        .ok_or_else(|| error("missing relink output filename"))?;
    let destination = std::fs::canonicalize(parent)?.join(name);
    for input_path in inputs {
        if destination == std::fs::canonicalize(input_path)? {
            return Err(error("relink output would replace an input"));
        }
        guard_identity(output, input_path)?;
    }
    Ok(())
}

/// # Errors
/// Rejects hard-link aliases and propagates unexpected metadata failures.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn guard_identity(output: &Path, input: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let source = std::fs::metadata(input)?;
    match std::fs::symlink_metadata(output) {
        Ok(existing) if source.dev() == existing.dev() && source.ino() == existing.ino() => {
            Err(error("relink output aliases an input"))
        }
        Ok(_) => Ok(()),
        Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(failure) => Err(failure.into()),
    }
}

/// # Errors
/// Unsupported hosts fail before input reads or publication.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn guard_identity(_output: &Path, _input: &Path) -> Result<()> {
    Err(error("relink export is supported on Linux and macOS"))
}
