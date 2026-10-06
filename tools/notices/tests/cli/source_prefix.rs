use std::{fs, io};

use flate2::{Compression, write::GzEncoder};
use serde_json::{Value, json};

use super::{Fixture, Result, digest, write_json};

#[path = "source_prefix/encoded.rs"]
mod encoded;

#[path = "source_prefix/count.rs"]
mod count;

#[path = "source_prefix/budget.rs"]
mod budget;

const NOTICE: &[u8] = b"// Copyright synthetic author\r\n// Permission synthetic notice\r\n";
const SOURCE: &[u8] =
    b"// Copyright synthetic author\r\n// Permission synthetic notice\r\nfn original() {}\n";

struct Scenario {
    fixture: Fixture,
    manifest: Value,
    output: Vec<u8>,
}

/// # Errors
/// Propagates tar construction, byte conversion, or gzip encoding errors.
fn archive(source: &[u8]) -> Result<Vec<u8>> {
    let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
    for (path, bytes) in [
        ("Cargo.toml", b"[package]\nname='example'\nversion='1.0.0'\nlicense='MIT'\nrepository='https://github.com/example/project'\n".as_slice()),
        (".cargo_vcs_info.json", b"{\"git\":{\"sha1\":\"0000000000000000000000000000000000000000\"},\"path_in_vcs\":\"crates/example\"}".as_slice()),
        ("src/one.rs", source),
        ("src/two.rs", SOURCE),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(u64::try_from(bytes.len())?);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        builder.append_data(&mut header, format!("example-1.0.0/{path}"), bytes)?;
    }
    Ok(builder.into_inner()?.finish()?)
}

/// # Errors
/// Propagates fixture creation, file writes, command failure, and output reads.
fn scenario() -> Result<Scenario> {
    let fixture = Fixture::new()?;
    let root = &fixture.root;
    fs::create_dir_all(root.join("cache"))?;
    fs::create_dir_all(root.join("dependency"))?;
    let bytes = archive(SOURCE)?;
    let archive_digest = digest(&bytes)?;
    fs::write(root.join("cache/example-1.0.0.crate"), &bytes)?;
    fs::write(root.join("header.txt"), NOTICE)?;
    fs::write(root.join("license.txt"), b"complete omitted license\n")?;
    fs::write(
        root.join("Cargo.lock"),
        format!(
            "version=4\n[[package]]\nname='example'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{archive_digest}'\n"
        ),
    )?;
    write_json(
        &root.join("metadata.json"),
        &json!({"packages":[{
            "name":"example","version":"1.0.0","license":"MIT",
            "source":"registry+https://github.com/rust-lang/crates.io-index",
            "repository":"https://github.com/example/project",
            "manifest_path":root.join("dependency/Cargo.toml")
        }]}),
    )?;
    let mut notices = Vec::new();
    for path in ["src/one.rs", "src/two.rs"] {
        let upstream = format!("crates/example/{path}");
        notices.push(json!({
            "package":"example","version":"1.0.0","published_package_sha256":archive_digest,
            "source_commit":"0".repeat(40),"upstream_path":upstream,
            "source_url":format!("https://raw.githubusercontent.com/example/project/{}/{upstream}", "0".repeat(40)),
            "file":"header.txt","sha256":digest(NOTICE)?,
            "source_prefix":{"archive_path":path,"bytes":SOURCE.len(),"sha256":digest(SOURCE)?}
        }));
    }
    notices.push(json!({
        "package":"example","version":"1.0.0","published_package_sha256":archive_digest,
        "source_commit":"0".repeat(40),"upstream_path":"LICENSE",
        "source_url":format!("https://raw.githubusercontent.com/example/project/{}/LICENSE", "0".repeat(40)),
        "file":"license.txt","sha256":digest(b"complete omitted license\n")?
    }));
    let manifest = json!({"format_version":1_u32,"notices":notices});
    write_json(&root.join("sources.json"), &manifest)?;
    let result = fixture.run()?;
    if !result.status.success() {
        return Err(io::Error::other(String::from_utf8_lossy(&result.stderr)).into());
    }
    let output = fs::read(root.join("output.json"))?;
    Ok(Scenario {
        fixture,
        manifest,
        output,
    })
}

/// # Errors
/// Propagates fixture preparation, manifest field access, generation or output reads.
fn archive_scenario() -> Result<Scenario> {
    let mut scenario = scenario()?;
    for record in scenario
        .manifest
        .get_mut("notices")
        .and_then(Value::as_array_mut)
        .ok_or("missing notices")?
        .iter_mut()
        .take(2)
    {
        let _previous: Option<Value> = record
            .get_mut("source_prefix")
            .and_then(Value::as_object_mut)
            .ok_or("missing prefix")?
            .insert("source_url_kind".into(), json!("published_archive"));
        *record.get_mut("source_url").ok_or("missing URL")? =
            json!("https://static.crates.io/crates/example/example-1.0.0.crate");
    }
    let root = &scenario.fixture.root;
    write_json(&root.join("sources.json"), &scenario.manifest)?;
    let result = scenario.fixture.run()?;
    if !result.status.success() {
        return Err(io::Error::other(String::from_utf8_lossy(&result.stderr)).into());
    }
    scenario.output = fs::read(root.join("output.json"))?;
    Ok(scenario)
}

#[test]
/// # Errors
/// Propagates fixture setup, command execution, output decoding or field access.
///
/// # Panics
/// Panics if archive provenance loses the parent revision, complete-file binding or shared text.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-06, revisit 2026-11-06"
)]
fn preserves_verified_archive_prefix_provenance() -> Result<()> {
    let scenario = archive_scenario()?;
    let inventory: Value = serde_json::from_slice(&scenario.output)?;
    let records = inventory
        .pointer("/packages/example 1.0.0/supplemental_notices")
        .and_then(Value::as_array)
        .ok_or("missing records")?;
    for record in records.iter().take(2) {
        assert_eq!(
            record.get("source_url"),
            Some(&json!(
                "https://static.crates.io/crates/example/example-1.0.0.crate"
            ))
        );
        assert_eq!(record.get("source_commit"), Some(&json!("0".repeat(40))));
        assert_eq!(
            record.pointer("/source_prefix/source_url_kind"),
            Some(&json!("published_archive"))
        );
        assert_eq!(
            record.pointer("/source_prefix/sha256"),
            Some(&json!(digest(SOURCE)?))
        );
    }
    assert_eq!(
        inventory.pointer(&format!("/texts/{}", digest(NOTICE)?)),
        Some(&json!(std::str::from_utf8(NOTICE)?))
    );
    assert_eq!(records.len(), 3);
    assert!(scenario.fixture.run()?.status.success());
    assert_eq!(
        fs::read(scenario.fixture.root.join("output.json"))?,
        scenario.output
    );
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture setup, decoding, file access, or command execution errors.
///
/// # Panics
/// Panics if distinct source paths, verbatim text, deduplication or provenance is lost.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-06, revisit 2026-11-06"
)]
fn preserves_source_references_and_shared_prefix_text() -> Result<()> {
    let scenario = scenario()?;
    let inventory: Value = serde_json::from_slice(&scenario.output)?;
    let records = inventory
        .pointer("/packages/example 1.0.0/supplemental_notices")
        .and_then(Value::as_array)
        .ok_or("missing records")?;
    assert_eq!(records.len(), 3);
    for (index, path) in ["src/one.rs", "src/two.rs"].into_iter().enumerate() {
        let record = records.get(index).ok_or("missing source reference")?;
        assert_eq!(
            record.get("upstream_path"),
            Some(&json!(format!("crates/example/{path}")))
        );
        assert_eq!(
            record.get("source_kind"),
            Some(&json!("checked_published_archive_source_prefix"))
        );
        assert_eq!(
            record.pointer("/source_prefix/prefix_bytes"),
            Some(&json!(NOTICE.len()))
        );
        assert_eq!(
            record.pointer("/source_prefix/sha256"),
            Some(&json!(digest(SOURCE)?))
        );
    }
    assert_eq!(
        records.get(2).and_then(|record| record.get("source_kind")),
        Some(&json!(
            "checked_upstream_file_omitted_from_published_archive"
        ))
    );
    let texts = inventory
        .get("texts")
        .and_then(Value::as_object)
        .ok_or("missing texts")?;
    assert_eq!(texts.len(), 2);
    assert_eq!(
        texts.get(&digest(NOTICE)?),
        Some(&json!(std::str::from_utf8(NOTICE)?))
    );
    assert!(scenario.fixture.run()?.status.success());
    assert_eq!(
        fs::read(scenario.fixture.root.join("output.json"))?,
        scenario.output
    );
    Ok(())
}

/// # Errors
/// Propagates fixture setup, file access, field lookup, hashing or command execution errors.
///
/// # Panics
/// Panics if invalid bindings pass or failed generation changes the previous output.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-06, revisit 2026-11-06"
)]
fn reject_changed_bindings(scenario: Scenario) -> Result<()> {
    let root = &scenario.fixture.root;
    for (pointer, replacement) in [
        ("/notices/0/source_prefix/sha256", json!("1".repeat(64))),
        ("/notices/0/source_prefix/bytes", json!(1_u32)),
        (
            "/notices/0/source_prefix/archive_path",
            json!("../src/one.rs"),
        ),
        ("/notices/0/source_prefix/archive_path", json!("src/two.rs")),
        (
            "/notices/0/source_prefix",
            json!({"archive_path":"src/one.rs","bytes":SOURCE.len(),"sha256":digest(SOURCE)?,"extra":true}),
        ),
        ("/notices/0/upstream_path", json!("src/one.rs")),
        ("/notices/0/source_commit", json!("1".repeat(40))),
        (
            "/notices/0/source_url",
            json!("https://example.invalid/src/one.rs"),
        ),
        ("/notices/0/published_package_sha256", json!("1".repeat(64))),
        ("/notices/0/sha256", json!("1".repeat(64))),
        ("/notices/0/file", json!("../header.txt")),
    ] {
        let mut changed = scenario.manifest.clone();
        *changed
            .pointer_mut(pointer)
            .ok_or("missing source fixture field")? = replacement;
        write_json(&root.join("sources.json"), &changed)?;
        assert!(!scenario.fixture.run()?.status.success(), "{pointer}");
        assert_eq!(fs::read(root.join("output.json"))?, scenario.output);
    }
    write_json(&root.join("sources.json"), &scenario.manifest)?;
    fs::write(root.join("header.txt"), b"changed prefix")?;
    assert!(!scenario.fixture.run()?.status.success());
    assert_eq!(fs::read(root.join("output.json"))?, scenario.output);
    fs::write(root.join("header.txt"), NOTICE)?;
    let changed = archive(
        b"// Copyright synthetic author\r\n// Permission synthetic notice\r\nfn modified() {}\n",
    )?;
    let changed_digest = digest(&changed)?;
    fs::write(root.join("cache/example-1.0.0.crate"), changed)?;
    fs::write(
        root.join("Cargo.lock"),
        format!(
            "version=4\n[[package]]\nname='example'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{changed_digest}'\n"
        ),
    )?;
    let mut changed_manifest = scenario.manifest;
    for record in changed_manifest
        .get_mut("notices")
        .and_then(Value::as_array_mut)
        .ok_or("missing notices")?
    {
        *record
            .get_mut("published_package_sha256")
            .ok_or("missing archive binding")? = json!(changed_digest);
    }
    write_json(&root.join("sources.json"), &changed_manifest)?;
    assert!(
        !scenario.fixture.run()?.status.success(),
        "changed source after the prefix"
    );
    assert_eq!(fs::read(root.join("output.json"))?, scenario.output);
    Ok(())
}

#[test]
/// # Errors
/// Propagates the repository-prefix binding regression and fixture setup.
fn rejects_changed_bindings_and_preserves_previous_inventory() -> Result<()> {
    reject_changed_bindings(scenario()?)
}

#[test]
/// # Errors
/// Propagates the archive-prefix binding regression and fixture setup.
fn rejects_changed_archive_bindings_and_preserves_previous_inventory() -> Result<()> {
    reject_changed_bindings(archive_scenario()?)
}

#[test]
/// # Errors
/// Propagates fixture setup, manifest field access, writes or command execution.
///
/// # Panics
/// Panics if an unknown URL kind or incorrect archive URL is accepted.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-06, revisit 2026-11-06"
)]
fn rejects_unknown_archive_url_kinds_and_urls() -> Result<()> {
    let scenario = archive_scenario()?;
    let root = &scenario.fixture.root;
    for (pointer, replacement) in [
        ("/notices/0/source_prefix/source_url_kind", json!("other")),
        ("/notices/0/source_prefix/source_url_kind", json!(true)),
        ("/notices/0/source_prefix/source_url_kind", json!(null)),
        (
            "/notices/0/source_url",
            json!("https://static.crates.io/crates/other/other-1.0.0.crate"),
        ),
        (
            "/notices/0/source_url",
            json!("https://static.crates.io/crates/example/example-1.0.1.crate"),
        ),
        (
            "/notices/0/source_url",
            json!("https://static.crates.io/crates/example/example-1.0.0.crate?extra=true"),
        ),
    ] {
        let mut changed = scenario.manifest.clone();
        *changed
            .pointer_mut(pointer)
            .ok_or("missing fixture field")? = replacement;
        write_json(&root.join("sources.json"), &changed)?;
        assert!(!scenario.fixture.run()?.status.success(), "{pointer}");
        assert_eq!(fs::read(root.join("output.json"))?, scenario.output);
    }
    Ok(())
}
