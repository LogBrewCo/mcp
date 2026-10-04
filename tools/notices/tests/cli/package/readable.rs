use std::{collections::BTreeMap, fs, io::Read as _};

use flate2::read::MultiGzDecoder;
use serde_json::{Value, json};

use super::{Fixture, PREFIX, Result, digest, fixture, linked, run, write_json};

const DEPENDENCY: &str = "licenses/locked-source-notices.json";
const TOOLCHAIN: &str = "licenses/locked-rust-toolchain-notices.json";
const SHARED: &str = "Copyright synthetic upstream ©\r\nShared license without final newline";
const SUPPLEMENT: &str = "Synthetic supplementary notice\n";
const RUST_FILES: [(&str, &str, &str); 4] = [
    (
        "COPYRIGHT",
        "licenses/rust/COPYRIGHT",
        "Synthetic Rust copyright\n",
    ),
    (
        "LICENSE-APACHE",
        "licenses/rust/LICENSE-APACHE",
        "Synthetic Apache license\r\n",
    ),
    (
        "LICENSE-MIT",
        "licenses/rust/LICENSE-MIT",
        "Synthetic MIT license",
    ),
    (
        "rustc/share/doc/rust/COPYRIGHT-library.html",
        "licenses/rust/COPYRIGHT-library.html",
        "<!DOCTYPE html>\n<html><body>Synthetic Rust attribution ©</body></html>\n",
    ),
];

fn record(text: &str) -> Result<Value> {
    Ok(json!({"bytes":text.len(),"sha256":digest(text.as_bytes())?,"text":text}))
}

fn insert(value: &mut Value, key: &str, entry: Value) -> Result<()> {
    value
        .as_object_mut()
        .ok_or("missing fixture object")?
        .insert(key.into(), entry);
    Ok(())
}

fn bind(fixture: &Fixture, field: &str, path: &str, inventory: &Value) -> Result<()> {
    write_json(&fixture.root.join(path), inventory)?;
    let bytes = fs::read(fixture.root.join(path))?;
    let mut plan: Value = serde_json::from_slice(&fs::read(fixture.root.join("plan.json"))?)?;
    *plan.get_mut(field).ok_or("missing binding")? =
        json!({"bytes":bytes.len(),"sha256":digest(&bytes)?});
    write_json(&fixture.root.join("plan.json"), &plan)
}

fn readable_fixture() -> Result<Fixture> {
    let fixture = fixture()?;
    linked::bind(&fixture, &linked::inventory(&fixture)?)?;
    let mut dependency: Value = serde_json::from_slice(&fs::read(fixture.root.join(DEPENDENCY))?)?;
    let shared = digest(SHARED.as_bytes())?;
    let supplement = digest(SUPPLEMENT.as_bytes())?;
    insert(
        &mut dependency,
        "packages",
        json!({
        "synthetic-a 1.0.0":{"name":"synthetic-a","version":"1.0.0",
            "files":{"LICENSE":record(SHARED)?},"supplemental_notices":[{
                "upstream_path":"NOTICE","bytes":SUPPLEMENT.len(),"sha256":supplement}]},
        "synthetic-b 2.0.0":{"name":"synthetic-b","version":"2.0.0",
            "files":{"COPYING":record(SHARED)?}}}),
    )?;
    insert(
        &mut dependency,
        "texts",
        json!({shared:SHARED,supplement:SUPPLEMENT}),
    )?;
    bind(&fixture, "dependency_notices", DEPENDENCY, &dependency)?;
    let mut toolchain: Value = serde_json::from_slice(&fs::read(fixture.root.join(TOOLCHAIN))?)?;
    let mut files = serde_json::Map::new();
    for (source, _, text) in RUST_FILES {
        files.insert(source.into(), record(text)?);
    }
    insert(&mut toolchain, "files", Value::Object(files))?;
    bind(&fixture, "toolchain_notices", TOOLCHAIN, &toolchain)?;
    let mut plan: Value = serde_json::from_slice(&fs::read(fixture.root.join("plan.json"))?)?;
    *plan.get_mut("format_version").ok_or("missing version")? = json!(3);
    write_json(&fixture.root.join("plan.json"), &plan)?;
    Ok(fixture)
}

#[test]
fn readable_package_preserves_texts_and_binds_each_copy_to_its_inventory() -> Result<()> {
    let fixture = readable_fixture()?;
    let result = run(&fixture)?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
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
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        assert!(files.insert(relative, bytes).is_none());
    }
    std::io::copy(&mut archive.into_inner(), &mut std::io::sink())?;
    assert_eq!(files.len(), 13);
    for (_, path, text) in RUST_FILES {
        assert_eq!(files.get(path).map(Vec::as_slice), Some(text.as_bytes()));
    }
    let dependency = std::str::from_utf8(
        files
            .get("licenses/DEPENDENCIES.txt")
            .ok_or("missing readable dependencies")?,
    )?;
    assert!(dependency.contains("synthetic-a 1.0.0\n  LICENSE\n"));
    assert!(dependency.contains("synthetic-b 2.0.0\n  COPYING\n"));
    assert!(dependency.contains("  NOTICE\n"));
    assert_eq!(dependency.matches(SHARED).count(), 1);
    assert_eq!(dependency.matches(SUPPLEMENT).count(), 1);
    let linked_text = std::str::from_utf8(
        files
            .get("licenses/LINKED-TARGET.txt")
            .ok_or("missing readable linked notices")?,
    )?;
    assert!(linked_text.contains("synthetic-runtime 1.0.0"));
    assert!(linked_text.contains("https://example.com/runtime/1.0.0.tar.gz"));
    assert!(linked_text.contains("synthetic runtime attribution\n"));
    let manifest: Value =
        serde_json::from_slice(files.get("MANIFEST.json").ok_or("missing manifest")?)?;
    let entries = manifest
        .pointer("/readable_notices/files")
        .and_then(Value::as_object)
        .ok_or("missing readable bindings")?;
    assert_eq!(entries.len(), 6);
    for (path, binding) in entries {
        let bytes = files.get(path).ok_or("missing readable file")?;
        assert_eq!(binding.get("bytes"), Some(&json!(bytes.len())));
        assert_eq!(binding.get("sha256"), Some(&json!(digest(bytes)?)));
        let source = binding
            .get("source_inventory")
            .and_then(Value::as_str)
            .ok_or("missing source inventory")?;
        assert_eq!(
            binding.get("source_inventory_sha256"),
            Some(&json!(digest(
                files.get(source).ok_or("missing inventory")?
            )?))
        );
    }
    assert_eq!(
        manifest.pointer("/readable_notices/license_permission_check"),
        Some(&json!("external_required"))
    );
    assert_eq!(
        manifest.get("release_evidence"),
        Some(&json!("external_required"))
    );
    Ok(())
}

#[test]
fn malformed_readable_sources_cannot_replace_an_existing_package() -> Result<()> {
    let fixture = readable_fixture()?;
    assert!(run(&fixture)?.status.success());
    let previous = fs::read(fixture.root.join("package.tar.gz"))?;
    let original: Value = serde_json::from_slice(&fs::read(fixture.root.join(DEPENDENCY))?)?;
    for (pointer, value) in [
        ("/packages/synthetic-a 1.0.0/name", json!("different-name")),
        ("/packages/synthetic-a 1.0.0/files/LICENSE/bytes", json!(1)),
        (
            "/packages/synthetic-a 1.0.0/files/LICENSE/sha256",
            json!("0".repeat(64)),
        ),
        (
            "/packages/synthetic-a 1.0.0/supplemental_notices/0/bytes",
            json!(1),
        ),
        (
            "/packages/synthetic-a 1.0.0/supplemental_notices/0/upstream_path",
            json!("../NOTICE"),
        ),
        ("/texts", json!({})),
    ] {
        let mut changed = original.clone();
        *changed
            .pointer_mut(pointer)
            .ok_or("missing fixture field")? = value;
        bind(&fixture, "dependency_notices", DEPENDENCY, &changed)?;
        assert!(!run(&fixture)?.status.success(), "{pointer}");
        assert_eq!(fs::read(fixture.root.join("package.tar.gz"))?, previous);
    }
    bind(&fixture, "dependency_notices", DEPENDENCY, &original)?;
    let original: Value = serde_json::from_slice(&fs::read(fixture.root.join(TOOLCHAIN))?)?;
    for (pointer, value) in [
        ("/files/COPYRIGHT/text", json!("changed upstream text")),
        ("/files", json!({})),
        ("/files/LICENSE-MIT/bytes", json!(0)),
    ] {
        let mut changed = original.clone();
        *changed
            .pointer_mut(pointer)
            .ok_or("missing fixture field")? = value;
        bind(&fixture, "toolchain_notices", TOOLCHAIN, &changed)?;
        assert!(!run(&fixture)?.status.success(), "{pointer}");
        assert_eq!(fs::read(fixture.root.join("package.tar.gz"))?, previous);
    }
    Ok(())
}
