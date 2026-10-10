use alloc::{collections::BTreeSet, string::String, vec::Vec};
use std::path::PathBuf;

use flate2::{Compression, GzBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Result, checksum, error, input, package, publication, relative_path, relink};
use package::FileBinding;

#[cfg(test)]
mod tests;

const PLAN_BYTES: u64 = 128 << 10;
const FILE_BYTES: u64 = 32 << 20;
const PAYLOAD_BYTES: u64 = 64 << 20;
const FILE_COUNT: usize = 256;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    SourceArchive,
    Header,
    Recipe,
    License,
    LinkInputs,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    input_path: PathBuf,
    path: String,
    kind: Kind,
    binding: FileBinding,
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
    reference_binary: FileBinding,
    files: Vec<File>,
    private_path_markers: Vec<String>,
}

impl Plan {
    /// # Errors
    /// Rejects malformed strict-schema JSON, unsupported identity, invalid
    /// bindings, unsafe or colliding destinations, and excess size or counts.
    fn parse(bytes: &[u8]) -> Result<Self> {
        if u64::try_from(bytes.len())? > PLAN_BYTES {
            return Err(error("materials plan exceeds limit"));
        }
        let mut plan: Self = serde_json::from_slice(bytes)?;
        if plan.format_version != 1
            || plan.package_version != env!("CARGO_PKG_VERSION")
            || plan.rust_release != env!("CARGO_PKG_RUST_VERSION")
            || !package::hex(&plan.source_revision, 40)
            || plan.build_identity != "development" && plan.build_identity != plan.package_version
            || !matches!(
                plan.target.as_str(),
                "aarch64-unknown-linux-gnu" | "x86_64-unknown-linux-gnu"
            )
            || plan.files.is_empty()
            || plan.files.len() > FILE_COUNT
            || plan.private_path_markers.is_empty()
            || plan.private_path_markers.len() > 16
            || plan.private_path_markers.iter().any(|marker| {
                marker.is_empty()
                    || marker.len() > 256
                    || !marker.is_ascii()
                    || marker.contains(['\0', '\n', '\r'])
            })
        {
            return Err(error("invalid materials identity, count or marker limits"));
        }
        plan.reference_binary.validate(PAYLOAD_BYTES)?;
        validate_files(&plan.files, &plan.private_path_markers)?;
        plan.files
            .sort_by(|first, second| first.path.cmp(&second.path));
        Ok(plan)
    }
}

/// # Errors
/// Rejects unsafe or colliding paths, invalid bindings and excess total sizes.
fn validate_files(files: &[File], markers: &[String]) -> Result<()> {
    let mut paths = BTreeSet::new();
    let mut payload_bytes = 0_u64;
    let mut path_bytes = 0_usize;
    for file in files {
        let path = relative_path(&file.path)?;
        if !file.input_path.is_absolute()
            || file.path.len() > 512
            || !file.path.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'.')
            })
            || path.starts_with("MANIFEST.json")
            || paths.iter().any(|previous: &&std::path::Path| {
                path.starts_with(previous) || previous.starts_with(path)
            })
        {
            return Err(error("invalid or colliding materials path"));
        }
        check_markers(file.path.as_bytes(), markers)?;
        if !paths.insert(path) {
            return Err(error("duplicate materials destination"));
        }
        file.binding.validate(FILE_BYTES)?;
        payload_bytes = payload_bytes
            .checked_add(file.binding.bytes)
            .ok_or_else(|| error("materials payload size overflow"))?;
        path_bytes = path_bytes
            .checked_add(file.path.len())
            .ok_or_else(|| error("materials path size overflow"))?;
        if payload_bytes > PAYLOAD_BYTES || path_bytes > 64_usize << 10_u32 {
            return Err(error("materials payload or path budget exceeded"));
        }
    }
    Ok(())
}

/// # Errors
/// Rejects an exact selected marker in the given raw bytes.
fn check_markers(bytes: &[u8], markers: &[String]) -> Result<()> {
    if markers.iter().any(|marker| {
        bytes
            .windows(marker.len())
            .any(|part| part == marker.as_bytes())
    }) {
        return Err(error("materials contain a selected private marker"));
    }
    Ok(())
}

/// # Errors
/// Rejects changed, linked, special or oversized files and selected private
/// markers. Propagates archive, checksum and serialization failures.
fn build(plan: &Plan, plan_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut builder = tar::Builder::new(GzBuilder::new().mtime(0).operating_system(255).write(
        package::Output {
            bytes: Vec::new(),
            limit: usize::try_from(PAYLOAD_BYTES)?,
        },
        Compression::default(),
    ));
    let mut records = Vec::<Value>::new();
    for file in &plan.files {
        let bytes = file.binding.read(&file.input_path, FILE_BYTES)?;
        check_markers(&bytes, &plan.private_path_markers)?;
        package::append(&mut builder, "materials", &file.path, &bytes, 0o644)?;
        records.push(json!({"path":file.path,"kind":file.kind,"binding":file.binding}));
    }
    let manifest = serde_json::to_vec_pretty(&json!({
        "format_version":1_u32,"scope":"selected_recipient_materials",
        "package_version":plan.package_version,"build_identity":plan.build_identity,
        "source_revision":plan.source_revision,"rust_release":plan.rust_release,
        "target":plan.target,"reference_binary":plan.reference_binary,
        "operator_plan_sha256":checksum(plan_bytes)?,"files":records,
        "integrity_scope":"selected_file_bytes",
        "selected_private_marker_checks":"raw_paths_bodies_and_manifest_only",
        "nested_archive_contents":"not_inspected",
        "build_provenance":"external_required",
        "complete_corresponding_source":"external_required",
        "complete_component_coverage":"external_required",
        "source_modification_and_relink":"external_required",
        "license_permissions_and_release":"external_required",
    }))?;
    check_markers(&manifest, &plan.private_path_markers)?;
    package::append(&mut builder, "materials", "MANIFEST.json", &manifest, 0o644)?;
    Ok(builder.into_inner()?.finish()?.bytes)
}

/// # Errors
/// Rejects invalid arguments, an aliased output, invalid or changed inputs,
/// and failed archive construction or atomic publication.
pub fn run<Args>(args: Args) -> Result<()>
where
    Args: Iterator<Item = std::ffi::OsString>,
{
    let mut paths = args.map(PathBuf::from);
    let plan_path = paths
        .next()
        .ok_or_else(|| error("missing materials plan"))?;
    let output_path = paths
        .next()
        .ok_or_else(|| error("missing materials output"))?;
    if paths.next().is_some() || !plan_path.is_absolute() || !output_path.is_absolute() {
        return Err(error("expected absolute materials plan and output paths"));
    }
    let plan_bytes = input::read(&plan_path, PLAN_BYTES)?;
    let plan = Plan::parse(&plan_bytes)?;
    let inputs: Vec<&PathBuf> = core::iter::once(&plan_path)
        .chain(plan.files.iter().map(|file| &file.input_path))
        .collect();
    relink::guard_output(&output_path, &inputs)?;
    publication::write(&output_path, &build(&plan, &plan_bytes)?)
}
