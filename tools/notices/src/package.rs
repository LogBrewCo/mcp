use std::{io, path::Path};

use flate2::{Compression, GzBuilder, write::GzEncoder};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Result, checksum, error, input};

mod binary;
mod linked;
mod readable;

#[cfg(test)]
mod tests;

const OUTPUT_BYTES: usize = 64 << 20;
const BINARY_BYTES: u64 = 64 << 20;
const LICENSE_BYTES: u64 = 512 << 10;
const DEPENDENCY_BYTES: u64 = 16 << 20;
const TOOLCHAIN_BYTES: u64 = 8 << 20;
const LINKED_NOTICE_BYTES: u64 = 4 << 20;

#[derive(Clone, Copy, Deserialize, Serialize)]
enum Target {
    #[serde(rename = "aarch64-apple-darwin")]
    MacArm,
    #[serde(rename = "x86_64-apple-darwin")]
    MacX86,
    #[serde(rename = "aarch64-unknown-linux-gnu")]
    LinuxArm,
    #[serde(rename = "x86_64-unknown-linux-gnu")]
    LinuxX86,
}

impl Target {
    const fn label(self) -> &'static str {
        match self {
            Self::MacArm => "aarch64-apple-darwin",
            Self::MacX86 => "x86_64-apple-darwin",
            Self::LinuxArm => "aarch64-unknown-linux-gnu",
            Self::LinuxX86 => "x86_64-unknown-linux-gnu",
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileBinding {
    bytes: u64,
    sha256: String,
}

impl FileBinding {
    /// # Errors
    /// Rejects zero or excessive size and a checksum that is not 64 lowercase
    /// hexadecimal characters.
    fn validate(&self, limit: u64) -> Result<()> {
        if self.bytes == 0 || self.bytes > limit || !hex(&self.sha256, 64) {
            return Err(error("invalid package file binding"));
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error for bounded file-read failure or a
    /// byte-count or checksum mismatch.
    fn read(&self, path: &Path, limit: u64) -> Result<Vec<u8>> {
        let bytes = input::read(path, limit)?;
        if u64::try_from(bytes.len())? != self.bytes || checksum(&bytes)? != self.sha256 {
            return Err(error("package input differs from its trusted binding"));
        }
        Ok(bytes)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    format_version: u8,
    package_version: String,
    build_identity: String,
    source_revision: String,
    rust_release: String,
    target: Target,
    cargo_lock_sha256: String,
    binary: FileBinding,
    project_license: FileBinding,
    sdk_license: FileBinding,
    dependency_notices: FileBinding,
    toolchain_notices: FileBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    linked_target_notices: Option<FileBinding>,
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

impl Plan {
    /// # Errors
    /// Rejects oversized or malformed strict-schema JSON, unsupported plan
    /// version, incompatible linked-notice presence, incorrect package or Rust
    /// pins, invalid revision/build identity, and invalid input bindings.
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 16_usize << 10_u32 {
            return Err(error("packaging plan exceeds limit"));
        }
        let plan: Self = serde_json::from_slice(bytes)?;
        if !matches!(plan.format_version, 1..=3)
            || (plan.format_version >= 2) != plan.linked_target_notices.is_some()
            || plan.package_version != env!("CARGO_PKG_VERSION")
            || plan.rust_release != env!("CARGO_PKG_RUST_VERSION")
            || !hex(&plan.cargo_lock_sha256, 64)
            || !matches!(plan.build_identity.as_str(), "development")
                && plan.build_identity != plan.package_version
            || plan.source_revision != "uncommitted" && !hex(&plan.source_revision, 40)
            || plan.source_revision == "uncommitted" && plan.build_identity != "development"
        {
            return Err(error("invalid packaging identity"));
        }
        for (binding, limit) in [
            (&plan.binary, BINARY_BYTES),
            (&plan.project_license, LICENSE_BYTES),
            (&plan.sdk_license, LICENSE_BYTES),
            (&plan.dependency_notices, DEPENDENCY_BYTES),
            (&plan.toolchain_notices, TOOLCHAIN_BYTES),
        ] {
            binding.validate(limit)?;
        }
        if let Some(binding) = plan.linked_target_notices.as_ref() {
            binding.validate(LINKED_NOTICE_BYTES)?;
        }
        Ok(plan)
    }
}

struct Output {
    bytes: Vec<u8>,
    limit: usize,
}

impl io::Write for Output {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(buf.len())
            .is_none_or(|size| size > self.limit)
        {
            return Err(io::Error::other("compressed package exceeds limit"));
        }
        self.bytes
            .try_reserve(buf.len())
            .map_err(io::Error::other)?;
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

type Builder = tar::Builder<GzEncoder<Output>>;

/// # Errors
/// Propagates size conversion, tar-path encoding, and archive-write errors.
fn append(builder: &mut Builder, prefix: &str, path: &str, bytes: &[u8], mode: u32) -> Result<()> {
    let mut header = tar::Header::new_ustar();
    header.set_size(u64::try_from(bytes.len())?);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    builder.append_data(&mut header, format!("{prefix}/{path}"), bytes)?;
    Ok(())
}

/// # Errors
/// Rejects malformed JSON and inventory version, scope, lockfile, Rust
/// release, or target values that disagree with the packaging plan.
fn notices(plan: &Plan, dependency: &[u8], toolchain: &[u8]) -> Result<()> {
    let dependency: Value = serde_json::from_slice(dependency)?;
    let toolchain: Value = serde_json::from_slice(toolchain)?;
    if dependency.get("format_version") != Some(&Value::from(1_u32))
        || dependency.get("cargo_lock_sha256").and_then(Value::as_str)
            != Some(&plan.cargo_lock_sha256)
        || dependency.get("scope").and_then(Value::as_str)
            != Some("all_locked_packages_including_inactive_and_development")
        || toolchain.get("format_version") != Some(&Value::from(1_u32))
        || toolchain.get("scope").and_then(Value::as_str)
            != Some("rust_standard_library_source_notices")
        || toolchain.get("release").and_then(Value::as_str) != Some(&plan.rust_release)
        || toolchain.get("target").and_then(Value::as_str) != Some(plan.target.label())
    {
        return Err(error(
            "notice inventory identity differs from packaging plan",
        ));
    }
    Ok(())
}

/// # Errors
/// Returns an error for bound license-file reads or checksum mismatches and
/// tar-header or archive-write failures.
fn append_source_notices(
    builder: &mut Builder,
    prefix: &str,
    plan: &Plan,
    root: &Path,
    dependency: &[u8],
    toolchain: &[u8],
) -> Result<()> {
    for (path, binding) in [
        ("LICENSE", &plan.project_license),
        ("licenses/rmcp-3.5.1.txt", &plan.sdk_license),
    ] {
        append(
            builder,
            prefix,
            path,
            &binding.read(&root.join(path), LICENSE_BYTES)?,
            0o644,
        )?;
    }
    for (path, bytes) in [
        ("licenses/locked-source-notices.json", dependency),
        ("licenses/locked-rust-toolchain-notices.json", toolchain),
    ] {
        append(builder, prefix, path, bytes, 0o644)?;
    }
    Ok(())
}

/// # Errors
/// Rejects invalid plans, changed or oversized inputs, lockfile or binary
/// disagreement, invalid load metadata or notice inventories, and malformed
/// readable notices. Serialization and bounded tar/gzip write errors propagate.
pub fn build(plan_bytes: &[u8], binary_path: &Path, root: &Path) -> Result<Vec<u8>> {
    let plan = Plan::parse(plan_bytes)?;
    let lock = input::read(&root.join("Cargo.lock"), 1 << 20)?;
    if checksum(&lock)? != plan.cargo_lock_sha256 {
        return Err(error("repository lockfile differs from packaging plan"));
    }
    let binary = plan.binary.read(binary_path, BINARY_BYTES)?;
    let requirements = binary::requirements(plan.target, &binary)?;
    let dependency = plan.dependency_notices.read(
        &root.join("licenses/locked-source-notices.json"),
        DEPENDENCY_BYTES,
    )?;
    let toolchain = plan.toolchain_notices.read(
        &root.join("licenses/locked-rust-toolchain-notices.json"),
        TOOLCHAIN_BYTES,
    )?;
    notices(&plan, &dependency, &toolchain)?;
    let linked = plan
        .linked_target_notices
        .as_ref()
        .map(|binding| {
            let bytes = binding.read(
                &root.join("licenses/linked-target-notices.json"),
                LINKED_NOTICE_BYTES,
            )?;
            let report = linked::validate(plan.target.label(), &plan.binary.sha256, &bytes)?;
            Ok::<_, Box<dyn std::error::Error>>((bytes, report))
        })
        .transpose()?;
    let readable = if plan.format_version == 3 {
        let linked_bytes = &linked
            .as_ref()
            .ok_or_else(|| error("missing linked notice inventory"))?
            .0;
        readable::derive(&dependency, &toolchain, linked_bytes)?
    } else {
        Vec::new()
    };
    let prefix = format!(
        "logbrew-mcp-{}-{}",
        plan.package_version,
        plan.target.label()
    );
    let mut builder = tar::Builder::new(GzBuilder::new().mtime(0).write(
        Output {
            bytes: Vec::new(),
            limit: OUTPUT_BYTES,
        },
        Compression::default(),
    ));
    append(&mut builder, &prefix, "bin/logbrew-mcp", &binary, 0o755)?;
    append_source_notices(&mut builder, &prefix, &plan, root, &dependency, &toolchain)?;
    if let Some(bytes) = linked.as_ref().map(|record| &record.0) {
        append(
            &mut builder,
            &prefix,
            "licenses/linked-target-notices.json",
            bytes,
            0o644,
        )?;
    }
    for file in &readable {
        append(&mut builder, &prefix, file.path, &file.bytes, 0o644)?;
    }
    let mut manifest = json!({"format_version":1_u32,
        "integrity_scope":"bound_input_bytes","release_evidence":"external_required",
        "binary_header_check":"format_and_architecture_only",
        "binary_load_requirements":requirements,
        "runtime_compatibility":"external_required","static_components":"not_evaluated",
        "final_linked_target_notices":"external_required",
        "packaging_plan_sha256":checksum(plan_bytes)?,"plan":plan});
    if let Some((_, report)) = linked {
        let _previous: Option<Value> = manifest
            .as_object_mut()
            .ok_or_else(|| error("invalid package manifest"))?
            .insert("linked_target_notice_inventory".into(), report);
    }
    if !readable.is_empty() {
        let _previous: Option<Value> = manifest
            .as_object_mut()
            .ok_or_else(|| error("invalid package manifest"))?
            .insert("readable_notices".into(), readable::report(&readable)?);
    }
    let manifest = serde_json::to_vec_pretty(&manifest)?;
    append(&mut builder, &prefix, "MANIFEST.json", &manifest, 0o644)?;
    Ok(builder.into_inner()?.finish()?.bytes)
}

/// # Errors
/// Rejects invalid output paths, failed path canonicalization, invalid plans,
/// and outputs that would replace a packaging input.
pub fn guard_output(
    plan_bytes: &[u8],
    plan: &Path,
    binary: &Path,
    root: &Path,
    output: &Path,
) -> Result<()> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let filename = output
        .file_name()
        .ok_or_else(|| error("invalid package output path"))?;
    let canonical_output = std::fs::canonicalize(parent)?.join(filename);
    let mut sources = vec![
        plan.to_path_buf(),
        binary.to_path_buf(),
        root.join("Cargo.lock"),
        root.join("LICENSE"),
        root.join("licenses/rmcp-3.5.1.txt"),
        root.join("licenses/locked-source-notices.json"),
        root.join("licenses/locked-rust-toolchain-notices.json"),
    ];
    if Plan::parse(plan_bytes)?.linked_target_notices.is_some() {
        sources.push(root.join("licenses/linked-target-notices.json"));
    }
    for source in sources {
        if canonical_output == std::fs::canonicalize(source)? {
            return Err(error("package output would replace an input file"));
        }
    }
    Ok(())
}
