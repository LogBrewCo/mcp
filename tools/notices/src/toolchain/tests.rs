use std::{collections::BTreeMap, io::Write as _};

use flate2::{Compression, write::GzEncoder};
use serde_json::{Value, json};

use super::{
    Binding, LIBRARY_NOTICE, NOTICE_PATHS, collect, collect_bounded, distribution, source,
};
use crate::{Result, checksum, error};

const TEXT: &[u8] = b"synthetic copyright and license\r\n";

fn archive(entries: &[(&str, &[u8], tar::EntryType)]) -> Result<Vec<u8>> {
    archive_for_target(entries, "synthetic-target")
}

fn archive_for_target(entries: &[(&str, &[u8], tar::EntryType)], target: &str) -> Result<Vec<u8>> {
    let prefix = format!("rustc-{}-{target}", env!("CARGO_PKG_RUST_VERSION"));
    let mut builder = tar::Builder::new(Vec::new());
    for (relative, bytes, kind) in entries {
        let name = format!("{prefix}/{relative}");
        let mut header = tar::Header::new_gnu();
        header.set_size(u64::try_from(bytes.len())?);
        header.set_mode(0o644);
        header.set_entry_type(*kind);
        header
            .as_mut_bytes()
            .get_mut(..name.len())
            .ok_or_else(|| error("fixture path too long"))?
            .copy_from_slice(name.as_bytes());
        header.set_cksum();
        builder.append(&header, *bytes)?;
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(&builder.into_inner()?)?;
    Ok(encoder.finish()?)
}

fn fixture() -> Result<(Value, Vec<u8>, Vec<u8>)> {
    fixture_for_target("synthetic-target")
}

fn fixture_for_target(target: &str) -> Result<(Value, Vec<u8>, Vec<u8>)> {
    let entries: Vec<_> = NOTICE_PATHS
        .iter()
        .map(|path| (*path, TEXT, tar::EntryType::Regular))
        .collect();
    let bytes = archive_for_target(&entries, target)?;
    let commit = "a".repeat(40);
    let url = format!(
        "https://static.rust-lang.org/dist/2026-10-01/rustc-{}-{target}.tar.gz",
        env!("CARGO_PKG_RUST_VERSION")
    );
    let manifest = format!("manifest-version='2'\ndate='2026-10-01'\n[pkg.rustc]\nversion='{} (synthetic)'\ngit_commit_hash='{commit}'\n[pkg.rustc.target.{target}]\navailable=true\nurl='{url}'\nhash='{}'\n", env!("CARGO_PKG_RUST_VERSION"), checksum(&bytes)?).into_bytes();
    let files: BTreeMap<_, _> = NOTICE_PATHS
        .iter()
        .map(|path| Ok((*path, json!({"sha256":checksum(TEXT)?,"bytes":TEXT.len()}))))
        .collect::<Result<_>>()?;
    let binding = json!({"format_version":1_u32,"scope":"rust_standard_library_source_notices","release":env!("CARGO_PKG_RUST_VERSION"),
        "target":target,"source_commit":commit,"release_date":"2026-10-01","distribution_manifest_sha256":checksum(&manifest)?,
        "component_archive_sha256":checksum(&bytes)?,"component_archive_url":url,"files":files});
    Ok((binding, manifest, bytes))
}

fn binding(value: &Value) -> Result<Binding> {
    source(&serde_json::to_vec(value)?)
}

#[test]
fn verifies_x86_targets_through_distribution_and_notice_collection() -> Result<()> {
    for target in ["x86_64-apple-darwin", "x86_64-unknown-linux-gnu"] {
        let (value, manifest, bytes) = fixture_for_target(target)?;
        let source = binding(&value)?;
        distribution(&source, &manifest)?;
        let output: Value = serde_json::from_slice(&collect(&source, &bytes, TEXT)?)?;
        assert_eq!(output.get("target").and_then(Value::as_str), Some(target));
        for path in NOTICE_PATHS {
            assert_eq!(
                output
                    .get("files")
                    .and_then(|files| files.get(path))
                    .and_then(|notice| notice.get("text"))
                    .and_then(Value::as_str)
                    .map(str::as_bytes),
                Some(TEXT)
            );
        }
    }
    Ok(())
}

#[test]
fn verifies_distribution_and_preserves_all_notice_bytes() -> Result<()> {
    let (value, manifest, bytes) = fixture()?;
    let source = binding(&value)?;
    distribution(&source, &manifest)?;
    let output: Value = serde_json::from_slice(&collect(&source, &bytes, TEXT)?)?;
    assert_eq!(
        output.get("binary_linkage_coverage"),
        Some(&json!("not_evaluated"))
    );
    let files = output
        .get("files")
        .and_then(Value::as_object)
        .ok_or_else(|| error("missing output files"))?;
    assert_eq!(files.len(), 4);
    for notice in files.values() {
        assert_eq!(
            notice
                .get("text")
                .and_then(Value::as_str)
                .map(str::as_bytes),
            Some(TEXT)
        );
    }
    Ok(())
}

#[test]
fn rejects_invalid_duplicate_unknown_and_incomplete_source_bindings() -> Result<()> {
    let (value, _, _) = fixture()?;
    for (pointer, replacement) in [
        ("/format_version", json!(2_u32)),
        ("/scope", json!("binary_compliance")),
        ("/release", json!("0.1.0")),
        ("/target", json!("../target")),
        ("/source_commit", json!("a".repeat(39))),
        ("/release_date", json!("2026-1-01")),
        ("/distribution_manifest_sha256", json!("A".repeat(64))),
        ("/component_archive_sha256", json!("x".repeat(64))),
        (
            "/component_archive_url",
            json!("https://example.invalid/archive.tar.gz"),
        ),
        ("/files", json!({})),
    ] {
        let mut changed = value.clone();
        *changed
            .pointer_mut(pointer)
            .ok_or_else(|| error("missing fixture field"))? = replacement;
        assert!(binding(&changed).is_err(), "{pointer}");
    }
    let mut changed = value.clone();
    let _previous: Option<Value> = changed
        .as_object_mut()
        .ok_or_else(|| error("missing object"))?
        .insert("unknown".to_owned(), json!(true));
    assert!(binding(&changed).is_err());
    let text = serde_json::to_string(&value)?;
    let duplicate = text.replacen('{', "{\"format_version\":1,", 1);
    assert!(source(duplicate.as_bytes()).is_err());
    let notice = value
        .pointer("/files/COPYRIGHT")
        .ok_or_else(|| error("missing fixture notice"))?;
    let duplicate_path = text.replacen(
        "\"files\":{",
        &format!("\"files\":{{\"COPYRIGHT\":{notice},"),
        1,
    );
    assert!(source(duplicate_path.as_bytes()).is_err());
    Ok(())
}

#[test]
fn rejects_changed_distribution_fields_even_with_updated_manifest_checksum() -> Result<()> {
    let (value, manifest, _) = fixture()?;
    assert!(distribution(&binding(&value)?, b"changed manifest").is_err());
    for (needle, replacement) in [
        ("2026-10-01", "2026-10-02"),
        ("available=true", "available=false"),
        ("synthetic-target]", "other-target]"),
        ("version='1.99.0", "version='0.1.0"),
        ("aaaaaaaa", "bbbbbbbb"),
        ("https://static.rust-lang.org", "https://example.invalid"),
    ] {
        let changed = std::str::from_utf8(&manifest)?
            .replacen(needle, replacement, 1)
            .into_bytes();
        let mut binding_value = value.clone();
        *binding_value
            .get_mut("distribution_manifest_sha256")
            .ok_or_else(|| error("missing checksum"))? = json!(checksum(&changed)?);
        assert!(
            distribution(&binding(&binding_value)?, &changed).is_err(),
            "{needle}"
        );
    }
    Ok(())
}

#[test]
fn rejects_changed_archive_notice_installed_copy_and_gzip_footer() -> Result<()> {
    let (value, _, bytes) = fixture()?;
    let source = binding(&value)?;
    let _error: Box<dyn std::error::Error> =
        collect(&source, b"changed archive", TEXT).expect_err("input must be rejected");
    let _error: Box<dyn std::error::Error> =
        collect(&source, &bytes, b"changed installed copy").expect_err("input must be rejected");
    let mut changed = bytes.clone();
    let index = changed
        .len()
        .checked_sub(8)
        .ok_or_else(|| error("missing footer"))?;
    *changed
        .get_mut(index)
        .ok_or_else(|| error("missing checksum"))? ^= 1;
    let mut updated = value;
    *updated
        .get_mut("component_archive_sha256")
        .ok_or_else(|| error("missing checksum"))? = json!(checksum(&changed)?);
    let _error: Box<dyn std::error::Error> =
        collect(&binding(&updated)?, &changed, TEXT).expect_err("input must be rejected");
    let mut truncated = bytes;
    let _removed: Option<u8> = truncated.pop();
    *updated
        .get_mut("component_archive_sha256")
        .ok_or_else(|| error("missing checksum"))? = json!(checksum(&truncated)?);
    let _error: Box<dyn std::error::Error> =
        collect(&binding(&updated)?, &truncated, TEXT).expect_err("input must be rejected");
    let mut entries: Vec<_> = NOTICE_PATHS
        .iter()
        .map(|path| (*path, TEXT, tar::EntryType::Regular))
        .collect();
    let _removed: Option<(&str, &[u8], tar::EntryType)> = entries.pop();
    entries.push((LIBRARY_NOTICE, b"wrong text", tar::EntryType::Regular));
    let changed = archive(&entries)?;
    *updated
        .get_mut("component_archive_sha256")
        .ok_or_else(|| error("missing checksum"))? = json!(checksum(&changed)?);
    let _error: Box<dyn std::error::Error> =
        collect(&binding(&updated)?, &changed, TEXT).expect_err("input must be rejected");
    Ok(())
}

#[test]
fn rejects_missing_notices_links_special_files_duplicate_and_unsafe_paths() -> Result<()> {
    let (value, _, _) = fixture()?;
    for extra in [
        None,
        Some(("COPYRIGHT", TEXT, tar::EntryType::Regular)),
        Some(("link", b"".as_slice(), tar::EntryType::Symlink)),
        Some(("pipe", b"".as_slice(), tar::EntryType::Fifo)),
        Some(("../outside", TEXT, tar::EntryType::Regular)),
    ] {
        let mut entries: Vec<_> = NOTICE_PATHS
            .iter()
            .map(|path| (*path, TEXT, tar::EntryType::Regular))
            .collect();
        if let Some(extra) = extra {
            entries.push(extra);
        } else {
            let _removed: Option<(&str, &[u8], tar::EntryType)> = entries.pop();
        }
        let bytes = archive(&entries)?;
        let mut updated = value.clone();
        *updated
            .get_mut("component_archive_sha256")
            .ok_or_else(|| error("missing checksum"))? = json!(checksum(&bytes)?);
        assert!(
            collect(&binding(&updated)?, &bytes, TEXT).is_err(),
            "{extra:?}"
        );
    }
    Ok(())
}

#[test]
fn enforces_expansion_limit_and_reads_gzip_members_after_tar_end() -> Result<()> {
    let (mut value, _, mut bytes) = fixture()?;
    let source = binding(&value)?;
    let _error: Box<dyn std::error::Error> =
        collect_bounded(&source, &bytes, TEXT, 1024).expect_err("input must be rejected");
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(&vec![0; 8192])?;
    bytes.extend_from_slice(&encoder.finish()?);
    *value
        .get_mut("component_archive_sha256")
        .ok_or_else(|| error("missing checksum"))? = json!(checksum(&bytes)?);
    let _error: Box<dyn std::error::Error> =
        collect_bounded(&binding(&value)?, &bytes, TEXT, 8192).expect_err("input must be rejected");
    let _output: Vec<u8> = collect(&binding(&value)?, &bytes, TEXT)?;
    let index = bytes
        .len()
        .checked_sub(8)
        .ok_or_else(|| error("missing second footer"))?;
    *bytes
        .get_mut(index)
        .ok_or_else(|| error("missing checksum"))? ^= 1;
    *value
        .get_mut("component_archive_sha256")
        .ok_or_else(|| error("missing checksum"))? = json!(checksum(&bytes)?);
    let _error: Box<dyn std::error::Error> =
        collect(&binding(&value)?, &bytes, TEXT).expect_err("input must be rejected");
    Ok(())
}
