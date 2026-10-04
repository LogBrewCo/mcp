use std::{collections::BTreeMap, fs, io::Read as _, path::Path, process::Command};

use flate2::read::MultiGzDecoder;
use serde_json::{Value, json};

use super::{Fixture, Result, digest, write_json};

const PREFIX: &str = "logbrew-mcp-0.1.0-aarch64-apple-darwin/";

#[path = "package/linked.rs"]
mod linked;

#[path = "package/readable.rs"]
mod readable;

fn files() -> Result<BTreeMap<&'static str, Vec<u8>>> {
    let mut binary = vec![0; 56];
    for (start, bytes) in [
        (0, 0xfeed_facfu32),
        (4, 0x0100_000cu32),
        (12, 2u32),
        (16, 1),
        (20, 24),
        (32, goblin::mach::load_command::LC_BUILD_VERSION),
        (36, 24),
        (40, 1),
        (44, 11 << 16),
        (48, 27 << 16),
    ] {
        binary
            .get_mut(start..start + 4)
            .ok_or("invalid fixture header")?
            .copy_from_slice(&bytes.to_le_bytes());
    }
    let lock = b"synthetic locked source";
    Ok(BTreeMap::from([
        ("server", binary),
        ("Cargo.lock", lock.to_vec()),
        ("LICENSE", b"synthetic project license\n".to_vec()),
        (
            "licenses/rmcp-3.5.0.txt",
            b"synthetic SDK license\n".to_vec(),
        ),
        (
            "licenses/locked-source-notices.json",
            serde_json::to_vec(&json!({
            "format_version":1,"scope":"all_locked_packages_including_inactive_and_development",
            "cargo_lock_sha256":digest(lock)?}))?,
        ),
        (
            "licenses/locked-rust-toolchain-notices.json",
            serde_json::to_vec(&json!({
            "format_version":1,"scope":"rust_standard_library_source_notices",
            "release":"1.99.0","target":"aarch64-apple-darwin"}))?,
        ),
    ]))
}

fn fixture() -> Result<Fixture> {
    let fixture = Fixture::new()?;
    fs::create_dir(fixture.root.join("licenses"))?;
    let source_files = files()?;
    let mut plan = json!({"format_version":1,"package_version":"0.1.0",
        "build_identity":"development","source_revision":"uncommitted","rust_release":"1.99.0",
        "target":"aarch64-apple-darwin","cargo_lock_sha256":digest(source_files.get("Cargo.lock").ok_or("missing lock")?)?});
    for (field, path) in [
        ("binary", "server"),
        ("project_license", "LICENSE"),
        ("sdk_license", "licenses/rmcp-3.5.0.txt"),
        ("dependency_notices", "licenses/locked-source-notices.json"),
        (
            "toolchain_notices",
            "licenses/locked-rust-toolchain-notices.json",
        ),
    ] {
        let bytes = source_files.get(path).ok_or("missing source")?;
        plan.as_object_mut().ok_or("missing plan object")?.insert(
            field.into(),
            json!({"bytes":bytes.len(),"sha256":digest(bytes)?}),
        );
    }
    for (path, bytes) in source_files {
        fs::write(fixture.root.join(path), bytes)?;
    }
    write_json(&fixture.root.join("plan.json"), &plan)?;
    Ok(fixture)
}

fn run(fixture: &Fixture) -> Result<std::process::Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_logbrew-mcp-package"))
        .args([
            fixture.root.join("plan.json"),
            fixture.root.join("server"),
            fixture.root.clone(),
            fixture.root.join("package.tar.gz"),
        ])
        .output()?)
}

#[test]
fn package_is_reproducible_and_preserves_all_bound_bytes_with_fixed_metadata() -> Result<()> {
    let fixture = fixture()?;
    let result = run(&fixture)?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, [0u8; 0]);
    let first = fs::read(fixture.root.join("package.tar.gz"))?;
    assert!(run(&fixture)?.status.success());
    assert_eq!(fs::read(fixture.root.join("package.tar.gz"))?, first);
    let mut archive = tar::Archive::new(MultiGzDecoder::new(first.as_slice()));
    let mut archived = BTreeMap::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().into_owned();
        let relative = path.strip_prefix(PREFIX).ok_or("wrong package prefix")?;
        assert!(entry.header().entry_type().is_file());
        assert_eq!(entry.header().uid()?, 0);
        assert_eq!(entry.header().gid()?, 0);
        assert_eq!(entry.header().mtime()?, 0);
        assert_eq!(
            entry.header().mode()?,
            if relative == "bin/logbrew-mcp" {
                0o755
            } else {
                0o644
            }
        );
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        assert!(archived.insert(relative.to_owned(), bytes).is_none());
    }
    let mut decoded = archive.into_inner();
    std::io::copy(&mut decoded, &mut std::io::sink())?;
    let header = decoded.header().ok_or("missing gzip header")?;
    assert_eq!(header.mtime(), 0);
    assert!(header.filename().is_none());
    assert!(header.comment().is_none());
    assert_eq!(archived.len(), 6);
    for (path, bytes) in files()? {
        if path != "Cargo.lock" {
            let archived_path = if path == "server" {
                "bin/logbrew-mcp"
            } else {
                path
            };
            assert_eq!(archived.get(archived_path), Some(&bytes));
        }
    }
    let manifest: Value =
        serde_json::from_slice(archived.get("MANIFEST.json").ok_or("missing manifest")?)?;
    assert_eq!(
        manifest.get("release_evidence").and_then(Value::as_str),
        Some("external_required")
    );
    assert_eq!(
        manifest.pointer("/binary_load_requirements/deployment/minimum_os"),
        Some(&json!("11.0.0"))
    );
    assert_eq!(
        manifest.pointer("/binary_load_requirements/deployment/sdk"),
        Some(&json!("27.0.0"))
    );
    assert_eq!(
        manifest.get("runtime_compatibility"),
        Some(&json!("external_required"))
    );
    assert_eq!(
        manifest.get("static_components"),
        Some(&json!("not_evaluated"))
    );
    assert_eq!(
        manifest
            .get("packaging_plan_sha256")
            .and_then(Value::as_str),
        Some(digest(&fs::read(fixture.root.join("plan.json"))?)?.as_str())
    );
    Ok(())
}

#[test]
fn changed_package_inputs_preserve_the_previous_complete_archive() -> Result<()> {
    let fixture = fixture()?;
    assert!(run(&fixture)?.status.success());
    let previous = fs::read(fixture.root.join("package.tar.gz"))?;
    for path in files()?.keys() {
        let path = fixture.root.join(path);
        let before = fs::read(&path)?;
        fs::write(&path, b"changed input")?;
        assert!(!run(&fixture)?.status.success());
        assert_eq!(fs::read(fixture.root.join("package.tar.gz"))?, previous);
        fs::write(path, before)?;
    }
    Ok(())
}

#[test]
fn trusted_hash_does_not_allow_inconsistent_load_command_regions() -> Result<()> {
    let fixture = fixture()?;
    assert!(run(&fixture)?.status.success());
    let previous = fs::read(fixture.root.join("package.tar.gz"))?;
    let original = fs::read(fixture.root.join("server"))?;
    for (region, command) in [(8u32, 24u32), (32, 24), (24, 0), (16, 16), (25, 25)] {
        let mut binary = original.clone();
        binary.resize(binary.len().max(32 + usize::try_from(region)?), 0);
        binary
            .get_mut(20..24)
            .ok_or("missing extent")?
            .copy_from_slice(&region.to_le_bytes());
        binary
            .get_mut(36..40)
            .ok_or("missing command size")?
            .copy_from_slice(&command.to_le_bytes());
        fs::write(fixture.root.join("server"), &binary)?;
        let mut plan: Value = serde_json::from_slice(&fs::read(fixture.root.join("plan.json"))?)?;
        *plan.get_mut("binary").ok_or("missing binary binding")? =
            json!({"bytes":binary.len(),"sha256":digest(&binary)?});
        write_json(&fixture.root.join("plan.json"), &plan)?;
        assert!(
            !run(&fixture)?.status.success(),
            "region={region}, command={command}"
        );
        assert_eq!(fs::read(fixture.root.join("package.tar.gz"))?, previous);
    }
    Ok(())
}

#[test]
fn trusted_hash_does_not_allow_missing_deployment_metadata() -> Result<()> {
    let fixture = fixture()?;
    assert!(run(&fixture)?.status.success());
    let previous = fs::read(fixture.root.join("package.tar.gz"))?;
    let mut binary = fs::read(fixture.root.join("server"))?;
    binary.truncate(32);
    for offset in [16, 20] {
        binary
            .get_mut(offset..offset + 4)
            .ok_or("missing command header")?
            .copy_from_slice(&0_u32.to_le_bytes());
    }
    fs::write(fixture.root.join("server"), &binary)?;
    let mut plan: Value = serde_json::from_slice(&fs::read(fixture.root.join("plan.json"))?)?;
    *plan.get_mut("binary").ok_or("missing binary binding")? =
        json!({"bytes":binary.len(),"sha256":digest(&binary)?});
    write_json(&fixture.root.join("plan.json"), &plan)?;
    assert!(!run(&fixture)?.status.success());
    assert_eq!(fs::read(fixture.root.join("package.tar.gz"))?, previous);
    Ok(())
}

#[test]
fn trusted_hash_does_not_allow_packaging_a_workstation_path() -> Result<()> {
    let fixture = fixture()?;
    assert!(run(&fixture)?.status.success());
    let previous = fs::read(fixture.root.join("package.tar.gz"))?;
    let mut binary = fs::read(fixture.root.join("server"))?;
    binary.extend_from_slice(b"/home/synthetic/private-workspace/src/main.rs");
    fs::write(fixture.root.join("server"), &binary)?;
    let mut plan: Value = serde_json::from_slice(&fs::read(fixture.root.join("plan.json"))?)?;
    *plan.get_mut("binary").ok_or("missing binary binding")? =
        json!({"bytes":binary.len(),"sha256":digest(&binary)?});
    write_json(&fixture.root.join("plan.json"), &plan)?;
    let result = run(&fixture)?;
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("workstation path marker"));
    assert_eq!(fs::read(fixture.root.join("package.tar.gz"))?, previous);
    Ok(())
}

#[test]
fn rebound_notice_hashes_do_not_allow_another_lockfile_release_or_target() -> Result<()> {
    let fixture = fixture()?;
    assert!(run(&fixture)?.status.success());
    let previous = fs::read(fixture.root.join("package.tar.gz"))?;
    let original_plan = fs::read(fixture.root.join("plan.json"))?;
    for (path, binding, field, value) in [
        (
            "licenses/locked-source-notices.json",
            "dependency_notices",
            "cargo_lock_sha256",
            "f".repeat(64),
        ),
        (
            "licenses/locked-rust-toolchain-notices.json",
            "toolchain_notices",
            "release",
            "1.98.1".into(),
        ),
        (
            "licenses/locked-rust-toolchain-notices.json",
            "toolchain_notices",
            "target",
            "x86_64-unknown-linux-gnu".into(),
        ),
    ] {
        let path = fixture.root.join(path);
        let before = fs::read(&path)?;
        let mut notice: Value = serde_json::from_slice(&before)?;
        *notice.get_mut(field).ok_or("missing notice field")? = Value::from(value);
        let changed = serde_json::to_vec(&notice)?;
        fs::write(&path, &changed)?;
        let mut plan: Value = serde_json::from_slice(&original_plan)?;
        *plan.get_mut(binding).ok_or("missing binding")? =
            json!({"bytes":changed.len(),"sha256":digest(&changed)?});
        write_json(&fixture.root.join("plan.json"), &plan)?;
        assert!(!run(&fixture)?.status.success());
        assert_eq!(fs::read(fixture.root.join("package.tar.gz"))?, previous);
        fs::write(path, before)?;
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn package_rejects_a_bound_input_symlink_without_changing_existing_output() -> Result<()> {
    let fixture = fixture()?;
    assert!(run(&fixture)?.status.success());
    let previous = fs::read(fixture.root.join("package.tar.gz"))?;
    fs::rename(
        fixture.root.join("server"),
        fixture.root.join("real-server"),
    )?;
    std::os::unix::fs::symlink(Path::new("real-server"), fixture.root.join("server"))?;
    assert!(!run(&fixture)?.status.success());
    assert_eq!(fs::read(fixture.root.join("package.tar.gz"))?, previous);
    Ok(())
}

#[test]
fn package_output_cannot_replace_its_plan_binary_lockfile_or_notices() -> Result<()> {
    let fixture = fixture()?;
    let mut paths = files()?.into_keys().collect::<Vec<_>>();
    paths.extend(["plan.json", "licenses/../LICENSE"]);
    for path in paths {
        let output = fixture.root.join(path);
        let before = fs::read(&output)?;
        let result = Command::new(env!("CARGO_BIN_EXE_logbrew-mcp-package"))
            .args([
                fixture.root.join("plan.json"),
                fixture.root.join("server"),
                fixture.root.clone(),
                output.clone(),
            ])
            .output()?;
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("replace an input file"));
        assert_eq!(fs::read(output)?, before);
    }
    Ok(())
}
