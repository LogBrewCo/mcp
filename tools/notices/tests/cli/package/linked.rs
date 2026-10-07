use alloc::collections::BTreeMap;
use std::{fs, io::Read as _, process::Command};

use flate2::read::MultiGzDecoder;
use serde_json::{Value, json};

use super::{Fixture, PREFIX, Result, digest, fixture, run, write_json};

const NOTICE_PATH: &str = "licenses/linked-target-notices.json";

/// # Errors
///
/// Returns an error if the server fixture cannot be read or its checksum cannot be recorded.
pub(super) fn inventory(fixture: &Fixture) -> Result<Value> {
    let text = "synthetic runtime attribution\n";
    Ok(
        json!({"format_version":1_u32,"scope":"linked_target_source_notices",
        "target":"aarch64-apple-darwin","binary_sha256":digest(&fs::read(fixture.root.join("server"))?)?,
        "components":[{"name":"synthetic-runtime","version":"1.0.0",
            "source_url":"https://example.com/runtime/1.0.0.tar.gz",
            "notices":[{"upstream_path":"COPYING","sha256":digest(text.as_bytes())?,"text":text}]}]}),
    )
}

/// # Errors
///
/// Returns an error if JSON conversion, fixture file access, checksum recording, or plan field access fails.
pub(super) fn bind(fixture: &Fixture, inventory: &Value) -> Result<Vec<u8>> {
    write_json(&fixture.root.join(NOTICE_PATH), inventory)?;
    let bytes = fs::read(fixture.root.join(NOTICE_PATH))?;
    let mut plan: Value = serde_json::from_slice(&fs::read(fixture.root.join("plan.json"))?)?;
    let object = plan.as_object_mut().ok_or("missing plan")?;
    let _previous_format: Option<Value> = object.insert("format_version".into(), json!(2_u32));
    let _previous: Option<Value> = object.insert(
        "linked_target_notices".into(),
        json!({"bytes":bytes.len(),"sha256":digest(&bytes)?}),
    );
    write_json(&fixture.root.join("plan.json"), &plan)?;
    Ok(bytes)
}

#[test]
/// # Errors
///
/// Returns an error if fixture preparation, command execution, archive decoding, file access, or manifest decoding fails.
///
/// # Panics
///
/// Panics if packaging, reproducibility, archive metadata, linked notice bytes, or release requirements differ from the expected values.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn version_two_preserves_linked_notice_bytes_and_external_release_requirements() -> Result<()> {
    let fixture = fixture()?;
    let expected = bind(&fixture, &inventory(&fixture)?)?;
    let output = run(&fixture)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let first = fs::read(fixture.root.join("package.tar.gz"))?;
    assert!(run(&fixture)?.status.success());
    assert_eq!(fs::read(fixture.root.join("package.tar.gz"))?, first);
    let mut archive = tar::Archive::new(MultiGzDecoder::new(first.as_slice()));
    let mut files = BTreeMap::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().into_owned();
        let relative = path.strip_prefix(PREFIX).ok_or("wrong prefix")?.to_owned();
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
        let _read_bytes: usize = entry.read_to_end(&mut bytes)?;
        assert!(files.insert(relative, bytes).is_none());
    }
    let _remaining_bytes: u64 = std::io::copy(&mut archive.into_inner(), &mut std::io::sink())?;
    assert_eq!(files.len(), 7);
    assert_eq!(files.get(NOTICE_PATH), Some(&expected));
    let manifest: Value =
        serde_json::from_slice(files.get("MANIFEST.json").ok_or("missing manifest")?)?;
    for pointer in [
        "/release_evidence",
        "/final_linked_target_notices",
        "/linked_target_notice_inventory/coverage",
        "/linked_target_notice_inventory/compilation_eligibility",
        "/linked_target_notice_inventory/license_permission_check",
    ] {
        assert_eq!(
            manifest.pointer(pointer),
            Some(&json!("external_required")),
            "{pointer}"
        );
    }
    assert_eq!(
        manifest.pointer("/linked_target_notice_inventory/inventory_sha256"),
        Some(&json!(digest(&expected)?))
    );
    Ok(())
}

#[test]
/// # Errors
///
/// Returns an error if fixture preparation, JSON field access, file updates, or command execution fails.
///
/// # Panics
///
/// Panics if an invalid binary, target, or notice is accepted, or if the previous package changes.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn another_binary_or_target_and_corrupted_text_preserve_the_complete_package() -> Result<()> {
    let fixture = fixture()?;
    let original = inventory(&fixture)?;
    let _original_bound: Vec<u8> = bind(&fixture, &original)?;
    assert!(run(&fixture)?.status.success());
    let previous = fs::read(fixture.root.join("package.tar.gz"))?;
    for (pointer, value) in [
        ("/binary_sha256", json!("f".repeat(64))),
        ("/target", json!("x86_64-unknown-linux-gnu")),
        (
            "/components/0/notices/0/text",
            json!("corrupted attribution"),
        ),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).ok_or("missing notice field")? = value;
        let _bound: Vec<u8> = bind(&fixture, &changed)?;
        assert!(!run(&fixture)?.status.success(), "{pointer}");
        assert_eq!(fs::read(fixture.root.join("package.tar.gz"))?, previous);
    }
    Ok(())
}

#[test]
/// # Errors
///
/// Returns an error if fixture preparation, command execution, or inventory file access fails.
///
/// # Panics
///
/// Panics if packaging accepts replacement of its inventory, omits the expected rejection, or changes the inventory.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn package_output_cannot_replace_the_bound_linked_notice_inventory() -> Result<()> {
    let fixture = fixture()?;
    let original = bind(&fixture, &inventory(&fixture)?)?;
    let result = Command::new(env!("CARGO_BIN_EXE_logbrew-mcp-package"))
        .args([
            fixture.root.join("plan.json"),
            fixture.root.join("server"),
            fixture.root.clone(),
            fixture.root.join(NOTICE_PATH),
        ])
        .output()?;
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("replace an input file"));
    assert_eq!(fs::read(fixture.root.join(NOTICE_PATH))?, original);
    Ok(())
}

#[cfg(unix)]
#[test]
/// # Errors
///
/// Returns an error if fixture preparation, command execution, file access, renaming, or symlink creation fails.
///
/// # Panics
///
/// Panics if a linked notice symlink is accepted or the previous package changes.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn linked_notice_input_symlink_preserves_the_previous_package() -> Result<()> {
    let fixture = fixture()?;
    let _bound: Vec<u8> = bind(&fixture, &inventory(&fixture)?)?;
    assert!(run(&fixture)?.status.success());
    let previous = fs::read(fixture.root.join("package.tar.gz"))?;
    fs::rename(
        fixture.root.join(NOTICE_PATH),
        fixture.root.join("real-notice.json"),
    )?;
    std::os::unix::fs::symlink(
        fixture.root.join("real-notice.json"),
        fixture.root.join(NOTICE_PATH),
    )?;
    assert!(!run(&fixture)?.status.success());
    assert_eq!(fs::read(fixture.root.join("package.tar.gz"))?, previous);
    Ok(())
}
