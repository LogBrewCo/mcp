use alloc::{collections::BTreeMap, string::String, vec::Vec};
use std::path::PathBuf;

use flate2::read::GzDecoder;
use serde_json::{Value, json};

use super::{Plan, build};
use crate::{Result, checksum, input};

struct Directory(PathBuf);

impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup: std::io::Result<()> = std::fs::remove_dir_all(&self.0);
    }
}

/// # Errors
/// Propagates exclusive fixture-directory creation failures.
fn directory() -> Result<Directory> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let directory = Directory(
        std::env::temp_dir().join(format!("logbrew-materials-{}-{nanos}", std::process::id())),
    );
    std::fs::DirBuilder::new().create(&directory.0)?;
    Ok(directory)
}

/// # Errors
/// Propagates fixture publication or checksum errors.
fn fixture(directory: &Directory) -> Result<Value> {
    let body = b"complete upstream text\n";
    let path = directory.0.join("private-input.txt");
    std::fs::write(&path, body)?;
    Ok(json!({
        "format_version":1_u32,"package_version":"0.1.0","build_identity":"development",
        "source_revision":"a".repeat(40),"rust_release":"1.99.0",
        "target":"aarch64-unknown-linux-gnu",
        "reference_binary":{"bytes":1_u32,"sha256":"b".repeat(64)},
        "files":[{"input_path":path,"path":"licenses/upstream.txt","kind":"license",
            "binding":{"bytes":body.len(),"sha256":checksum(body)?}}],
        "private_path_markers":["private-input","private-material"]
    }))
}

/// # Errors
/// Rejects invalid fixture mutation fields.
fn file(value: &mut Value) -> Result<&mut Value> {
    value
        .get_mut("files")
        .and_then(Value::as_array_mut)
        .and_then(|files| files.first_mut())
        .ok_or_else(|| "missing fixture file".into())
}

/// # Errors
/// Propagates fixture-plan encoding or parsing failures.
fn parse(value: &Value) -> Result<Plan> {
    Plan::parse(&serde_json::to_vec(value)?)
}

#[test]
/// # Errors
/// Fails if exact input bytes, deterministic output, fixed metadata or explicit
/// external requirements are lost, or private input paths enter the manifest.
fn selected_materials_preserve_bytes_and_leave_coverage_external() -> Result<()> {
    let directory = directory()?;
    let value = fixture(&directory)?;
    let bytes = serde_json::to_vec(&value)?;
    let plan = parse(&value)?;
    let output = build(&plan, &bytes)?;
    if output != build(&plan, &bytes)? {
        return Err("materials archive is nondeterministic".into());
    }
    let mut archive = tar::Archive::new(GzDecoder::new(output.as_slice()));
    let mut files = BTreeMap::<String, Vec<u8>>::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let header = entry.header();
        if !header.entry_type().is_file()
            || header.mode()? != 0o644
            || header.uid()? != 0
            || header.gid()? != 0
            || header.mtime()? != 0
        {
            return Err("materials archive metadata differs".into());
        }
        let path = entry
            .path()?
            .to_str()
            .ok_or("non-UTF8 fixture path")?
            .to_owned();
        let _prior: Option<Vec<u8>> = files.insert(path, crate::bounded(&mut entry, 1 << 20)?);
    }
    if files.len() != 2
        || files
            .get("materials/licenses/upstream.txt")
            .map(Vec::as_slice)
            != Some(b"complete upstream text\n")
    {
        return Err("materials archive changed upstream text".into());
    }
    let manifest_bytes = files
        .get("materials/MANIFEST.json")
        .ok_or("missing manifest")?;
    super::check_markers(manifest_bytes, &plan.private_path_markers)?;
    let manifest: Value = serde_json::from_slice(manifest_bytes)?;
    for key in [
        "build_provenance",
        "complete_corresponding_source",
        "complete_component_coverage",
        "source_modification_and_relink",
        "license_permissions_and_release",
    ] {
        if manifest.get(key).and_then(Value::as_str) != Some("external_required") {
            return Err("materials manifest claimed unverified coverage".into());
        }
    }
    if manifest
        .get("nested_archive_contents")
        .and_then(Value::as_str)
        != Some("not_inspected")
    {
        return Err("materials manifest claimed nested archive inspection".into());
    }
    Ok(())
}

#[test]
/// # Errors
/// Fails if unsafe, reserved, duplicate or ancestor/descendant paths pass.
fn destinations_reject_traversal_collisions_and_selected_markers() -> Result<()> {
    let directory = directory()?;
    let original = fixture(&directory)?;
    for path in [
        "",
        "../escape",
        "/absolute",
        "a//b",
        "a/./b",
        "a\\b",
        "a\nb",
        "a:b",
        "MANIFEST.json",
        "MANIFEST.json/child",
        "private-input.txt",
        "a/../b",
    ] {
        let mut value = original.clone();
        *file(&mut value)?.get_mut("path").ok_or("missing path")? = json!(path);
        if parse(&value).is_ok() {
            return Err("unsafe materials destination accepted".into());
        }
    }
    for path in [
        "licenses/upstream.txt",
        "licenses",
        "licenses/upstream.txt/child",
    ] {
        let mut value = original.clone();
        let mut added = file(&mut value)?.clone();
        *added.get_mut("path").ok_or("missing added path")? = json!(path);
        value
            .get_mut("files")
            .and_then(Value::as_array_mut)
            .ok_or("missing files")?
            .push(added);
        if parse(&value).is_ok() {
            return Err("colliding materials destinations accepted".into());
        }
    }
    Ok(())
}

#[test]
/// # Errors
/// Fails if unsupported identity, unknown/duplicate fields or invalid markers pass.
fn strict_plan_rejects_identity_and_schema_drift() -> Result<()> {
    let directory = directory()?;
    let original = fixture(&directory)?;
    for (key, replacement) in [
        ("format_version", json!(2_u32)),
        ("package_version", json!("0.2.0")),
        ("rust_release", json!("1.98.0")),
        ("target", json!("aarch64-apple-darwin")),
        ("source_revision", json!("uncommitted")),
        ("build_identity", json!("release")),
        ("files", json!([])),
        ("private_path_markers", json!([])),
        ("private_path_markers", json!([""])),
        ("private_path_markers", json!(["bad\nmarker"])),
    ] {
        let mut value = original.clone();
        *value.get_mut(key).ok_or("missing plan field")? = replacement;
        if parse(&value).is_ok() {
            return Err("invalid materials identity accepted".into());
        }
    }
    let encoded = serde_json::to_string(&original)?;
    for suffix in ["\"format_version\":1", "\"unknown\":true"] {
        let malformed = encoded.replacen('{', &format!("{{{suffix},"), 1);
        if Plan::parse(malformed.as_bytes()).is_ok() {
            return Err("duplicate or unknown plan field accepted".into());
        }
    }
    let mut value = original;
    let _previous: Option<Value> = file(&mut value)?
        .as_object_mut()
        .ok_or("missing file object")?
        .insert("unknown".to_owned(), json!(true));
    if parse(&value).is_ok() {
        return Err("unknown file field accepted".into());
    }
    Ok(())
}

#[test]
/// # Errors
/// Fails if malformed bindings or per-file, total-payload, count or plan budgets pass.
fn plan_budgets_fail_before_file_reads() -> Result<()> {
    let directory = directory()?;
    let original = fixture(&directory)?;
    for binding in [
        json!({"bytes":0_u32,"sha256":"b".repeat(64)}),
        json!({"bytes":(32_u64 << 20_u32).saturating_add(1),"sha256":"b".repeat(64)}),
        json!({"bytes":1_u32,"sha256":"B".repeat(64)}),
        json!({"bytes":1_u32,"sha256":"b".repeat(63)}),
    ] {
        let mut value = original.clone();
        *file(&mut value)?
            .get_mut("binding")
            .ok_or("missing binding")? = binding;
        if parse(&value).is_ok() {
            return Err("invalid materials binding accepted".into());
        }
    }
    for (count, bytes) in [(3_usize, 32_u64 << 20_u32), (257, 1)] {
        let mut value = original.clone();
        let template = file(&mut value)?.clone();
        let mut files = Vec::new();
        for index in 0..count {
            let mut item = template.clone();
            *item.get_mut("path").ok_or("missing path")? = json!(format!("file-{index}"));
            *item
                .get_mut("binding")
                .and_then(|binding| binding.get_mut("bytes"))
                .ok_or("missing size")? = json!(bytes);
            files.push(item);
        }
        *value.get_mut("files").ok_or("missing files")? = json!(files);
        if parse(&value).is_ok() {
            return Err("materials count or payload limit exceeded".into());
        }
    }
    if Plan::parse(&vec![b' '; (128_usize << 10_u32).saturating_add(1)]).is_ok() {
        return Err("oversized materials plan accepted".into());
    }
    Ok(())
}

#[test]
/// # Errors
/// Fails if changed bytes or a selected marker replaces prior output, or a
/// final-component input symlink passes the bounded reader.
fn rejected_inputs_preserve_previous_output() -> Result<()> {
    let directory = directory()?;
    let mut value = fixture(&directory)?;
    let plan_path = directory.0.join("plan.json");
    let output_path = directory.0.join("output.tar.gz");
    std::fs::write(&plan_path, serde_json::to_vec(&value)?)?;
    let arguments = || {
        [&plan_path, &output_path]
            .into_iter()
            .map(|path| path.as_os_str().to_owned())
    };
    super::run(arguments())?;
    let prior = input::read(&output_path, super::PAYLOAD_BYTES)?;
    std::fs::write(directory.0.join("private-input.txt"), b"changed source")?;
    if super::run(arguments()).is_ok() || input::read(&output_path, super::PAYLOAD_BYTES)? != prior
    {
        return Err("changed material replaced previous output".into());
    }
    let private = b"private-input";
    std::fs::write(directory.0.join("private-input.txt"), private)?;
    *file(&mut value)?
        .get_mut("binding")
        .ok_or("missing binding")? = json!({"bytes":private.len(),"sha256":checksum(private)?});
    std::fs::write(&plan_path, serde_json::to_vec(&value)?)?;
    if super::run(arguments()).is_ok() || input::read(&output_path, super::PAYLOAD_BYTES)? != prior
    {
        return Err("selected private marker replaced previous output".into());
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let link = directory.0.join("input-link");
        std::os::unix::fs::symlink(directory.0.join("private-input.txt"), &link)?;
        *file(&mut value)?
            .get_mut("input_path")
            .ok_or("missing input")? = json!(link);
        std::fs::write(&plan_path, serde_json::to_vec(&value)?)?;
        if super::run(arguments()).is_ok() {
            return Err("input symlink accepted".into());
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
/// # Errors
/// Fails if publication accepts an input alias or leaves staging files.
fn command_rejects_every_input_alias() -> Result<()> {
    let directory = directory()?;
    let value = fixture(&directory)?;
    let plan_path = directory.0.join("plan.json");
    std::fs::write(&plan_path, serde_json::to_vec(&value)?)?;
    let source_path = directory.0.join("private-input.txt");
    let alias_path = directory.0.join("alias");
    std::fs::hard_link(&source_path, &alias_path)?;
    for destination in [&plan_path, &source_path, &alias_path] {
        if super::run(
            [&plan_path, destination]
                .into_iter()
                .map(|path| path.as_os_str().to_owned()),
        )
        .is_ok()
        {
            return Err("materials input alias accepted".into());
        }
    }
    if std::fs::read_dir(&directory.0)?.count() != 3 {
        return Err("rejected materials publication left staging files".into());
    }
    Ok(())
}
