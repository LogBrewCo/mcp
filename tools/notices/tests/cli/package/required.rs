use std::{fs, process::Command};

use serde_json::{Value, json};

use super::{Fixture, Result, archived_package, digest, linked, readable, run, write_json};

const REQUIRED: &str = "licenses/required-linked-notices.json";

/// # Errors
/// Propagates input reads, JSON encoding or fixture-field errors.
fn bind(fixture: &Fixture, required: &Value) -> Result<Vec<u8>> {
    write_json(&fixture.root.join(REQUIRED), required)?;
    let bytes = fs::read(fixture.root.join(REQUIRED))?;
    let mut plan: Value = serde_json::from_slice(&fs::read(fixture.root.join("plan.json"))?)?;
    *plan.get_mut("format_version").ok_or("missing version")? = json!(4_u32);
    let _previous: Option<Value> = plan.as_object_mut().ok_or("missing plan")?.insert(
        "required_linked_notices".into(),
        json!({"bytes":bytes.len(),"sha256":digest(&bytes)?}),
    );
    write_json(&fixture.root.join("plan.json"), &plan)?;
    Ok(bytes)
}

/// # Errors
/// Propagates synthetic inventory preparation or field-access errors.
fn expected(fixture: &Fixture) -> Result<Value> {
    let mut inventory = linked::inventory(fixture)?;
    *inventory.get_mut("scope").ok_or("missing scope")? = json!("required_linked_source_notices");
    Ok(inventory)
}

#[test]
/// # Errors
/// Propagates fixture preparation, packaging or archive reads, and fails if
/// required notices are omitted, altered, or not bound into the final archive.
fn required_notice_omission_preserves_the_package_and_complete_text_recovers() -> Result<()> {
    let fixture = readable::readable_fixture()?;
    let original = expected(&fixture)?;
    let required_bytes = bind(&fixture, &original)?;
    if !run(&fixture)?.status.success() {
        return Err("complete required inventory failed".into());
    }
    let previous = fs::read(fixture.root.join("package.tar.gz"))?;
    let files = archived_package(&previous)?;
    if files.len() != 14 || files.get(REQUIRED) != Some(&required_bytes) {
        return Err("required inventory was not preserved in the archive".into());
    }
    let manifest: Value =
        serde_json::from_slice(files.get("MANIFEST.json").ok_or("missing manifest")?)?;
    if manifest.pointer("/required_linked_notice_inventory/inventory_sha256")
        != Some(&json!(digest(&required_bytes)?))
        || manifest.pointer("/required_linked_notice_inventory/coverage")
            != Some(&json!("external_required"))
        || manifest.get("release_evidence") != Some(&json!("external_required"))
    {
        return Err("required inventory manifest binding or external gate changed".into());
    }
    for (pointer, value) in [
        ("/components/0/name", json!("missing-header-component")),
        (
            "/components/0/notices",
            json!([{ "upstream_path":"COPYING",
            "text":"different complete text\n","sha256":digest(b"different complete text\n")? }]),
        ),
    ] {
        let mut changed = original.clone();
        *changed
            .pointer_mut(pointer)
            .ok_or("missing required field")? = value;
        let _changed_bytes: Vec<u8> = bind(&fixture, &changed)?;
        if run(&fixture)?.status.success()
            || fs::read(fixture.root.join("package.tar.gz"))? != previous
        {
            return Err("omitted or changed required notice replaced the package".into());
        }
    }
    let _restored_bytes: Vec<u8> = bind(&fixture, &original)?;
    if !run(&fixture)?.status.success()
        || fs::read(fixture.root.join("package.tar.gz"))? != previous
    {
        return Err("restored exact required notices did not reproduce the package".into());
    }
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture preparation or process reads, and fails if the required
/// inventory can be replaced by the package output.
fn required_inventory_cannot_be_replaced_by_package_output() -> Result<()> {
    let fixture = readable::readable_fixture()?;
    let original = bind(&fixture, &expected(&fixture)?)?;
    let result = Command::new(env!("CARGO_BIN_EXE_logbrew-mcp-package"))
        .args([
            fixture.root.join("plan.json"),
            fixture.root.join("server"),
            fixture.root.clone(),
            fixture.root.join(REQUIRED),
        ])
        .output()?;
    if result.status.success()
        || !String::from_utf8_lossy(&result.stderr).contains("replace an input file")
        || fs::read(fixture.root.join(REQUIRED))? != original
    {
        return Err("required inventory output guard failed".into());
    }
    Ok(())
}

#[cfg(unix)]
#[test]
/// # Errors
/// Propagates fixture or symlink preparation, and fails if a linked required
/// inventory is read or a failed check changes the previous package.
fn required_inventory_symlink_preserves_previous_package() -> Result<()> {
    let fixture = readable::readable_fixture()?;
    let _original: Vec<u8> = bind(&fixture, &expected(&fixture)?)?;
    if !run(&fixture)?.status.success() {
        return Err("valid required package failed".into());
    }
    let previous = fs::read(fixture.root.join("package.tar.gz"))?;
    fs::rename(
        fixture.root.join(REQUIRED),
        fixture.root.join("real-required.json"),
    )?;
    std::os::unix::fs::symlink(
        fixture.root.join("real-required.json"),
        fixture.root.join(REQUIRED),
    )?;
    if run(&fixture)?.status.success() || fs::read(fixture.root.join("package.tar.gz"))? != previous
    {
        return Err("required input symlink changed the previous package".into());
    }
    Ok(())
}
