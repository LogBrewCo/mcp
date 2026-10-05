use std::{collections::BTreeSet, io::Write as _, path::Path};

use serde_json::{Map, Value, json};

use super::Output;
use crate::{Result, checksum, error, identity, relative_path, string};

const TEXT_BYTES: usize = 32 << 20;
const RUST_PATHS: [(&str, &str); 4] = [
    ("COPYRIGHT", "licenses/rust/COPYRIGHT"),
    ("LICENSE-APACHE", "licenses/rust/LICENSE-APACHE"),
    ("LICENSE-MIT", "licenses/rust/LICENSE-MIT"),
    (
        "rustc/share/doc/rust/COPYRIGHT-library.html",
        "licenses/rust/COPYRIGHT-library.html",
    ),
];

pub(super) struct File {
    pub path: &'static str,
    pub bytes: Vec<u8>,
    inventory: &'static str,
    inventory_sha256: String,
}

/// # Errors
/// Returns an error if the named field is absent or is not a JSON object.
fn object<'a>(value: &'a Value, key: &str) -> Result<&'a Map<String, Value>> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| error("missing readable notice inventory map"))
}

const fn writer() -> Output {
    Output {
        bytes: Vec::new(),
        limit: TEXT_BYTES,
    }
}

/// # Errors
/// Rejects absent, empty, or oversized text and a mismatched byte count or
/// checksum.
fn text<'a>(record: &Value, text: &'a str, limit: usize) -> Result<&'a str> {
    if text.trim().is_empty()
        || text.len() > limit
        || record.get("bytes").and_then(Value::as_u64) != Some(u64::try_from(text.len())?)
        || checksum(text.as_bytes())? != string(record, "sha256")?
    {
        return Err(error("readable notice text binding mismatch"));
    }
    Ok(text)
}

/// # Errors
/// Rejects unsafe paths, missing text references, invalid text bindings, and
/// output writes that exceed the rendering budget.
fn reference(
    output: &mut Output,
    texts: &Map<String, Value>,
    seen: &mut BTreeSet<String>,
    path: &str,
    record: &Value,
) -> Result<()> {
    let _path: &Path = relative_path(path)?;
    let digest = string(record, "sha256")?;
    let content = texts
        .get(digest)
        .and_then(Value::as_str)
        .ok_or_else(|| error("missing referenced notice text"))?;
    let _content: &str = text(record, content, 1_usize << 20_u32)?;
    let _new: bool = seen.insert(digest.to_owned());
    writeln!(output, "  {path}\n    SHA-256: {digest}")?;
    Ok(())
}

/// # Errors
/// Rejects malformed JSON, missing or excessive package or text records,
/// invalid notice maps or bindings, excess references, unreferenced text,
/// and bounded-output write failures.
fn dependencies(bytes: &[u8]) -> Result<Vec<u8>> {
    let inventory: Value = serde_json::from_slice(bytes)?;
    let packages = object(&inventory, "packages")?;
    let texts = object(&inventory, "texts")?;
    if packages.is_empty() || packages.len() > 512 || texts.is_empty() || texts.len() > 4096 {
        return Err(error("readable dependency notice count exceeds limit"));
    }
    let mut output = writer();
    output.write_all(b"LogBrew MCP locked dependency source notices\n\nIncludes inactive and development packages.\nThe package index identifies each source file by SHA-256.\nEach unique upstream text appears once in the notice texts section.\n\nPackage index\n=============\n")?;
    let mut seen = BTreeSet::new();
    let mut count = 0_usize;
    for (key, package) in packages {
        if identity(package)? != *key {
            return Err(error("readable dependency identity mismatch"));
        }
        writeln!(output, "\n{key}")?;
        let files = object(package, "files")?;
        let supplements = package
            .get("supplemental_notices")
            .map(|value| {
                value
                    .as_array()
                    .ok_or_else(|| error("invalid supplemental notice list"))
            })
            .transpose()?;
        let package_count = files
            .len()
            .checked_add(supplements.map_or(0, Vec::len))
            .ok_or_else(|| error("readable notice count overflow"))?;
        count = count
            .checked_add(package_count)
            .ok_or_else(|| error("readable notice count overflow"))?;
        if package_count == 0 || count > 4096 {
            return Err(error("readable dependency notice count exceeds limit"));
        }
        for (path, record) in files {
            reference(&mut output, texts, &mut seen, path, record)?;
        }
        for record in supplements.into_iter().flatten() {
            let path = string(record, "upstream_path")?;
            reference(&mut output, texts, &mut seen, path, record)?;
            output.write_all(
                b"    Supplemental upstream source; see JSON inventory for provenance.\n",
            )?;
        }
    }
    if seen.iter().ne(texts.keys()) {
        return Err(error("unreferenced readable dependency notice text"));
    }
    output.write_all(b"\nNotice texts\n============\n")?;
    for (digest, content) in texts {
        writeln!(
            output,
            "\nSHA-256: {digest}\n----- BEGIN UPSTREAM TEXT -----"
        )?;
        output.write_all(
            content
                .as_str()
                .ok_or_else(|| error("invalid dependency notice text"))?
                .as_bytes(),
        )?;
        output.write_all(b"\n----- END UPSTREAM TEXT -----\n")?;
    }
    Ok(output.bytes)
}

/// # Errors
/// Returns an error for invalid dependency or toolchain inventories, missing
/// or invalid bindings for the four Rust notices, linked-inventory decoding,
/// checksum formatting, or bounded-output writes.
pub(super) fn derive(dependency: &[u8], toolchain: &[u8], linked: &[u8]) -> Result<Vec<File>> {
    let mut files = vec![File {
        path: "licenses/DEPENDENCIES.txt",
        bytes: dependencies(dependency)?,
        inventory: "licenses/locked-source-notices.json",
        inventory_sha256: checksum(dependency)?,
    }];
    let inventory: Value = serde_json::from_slice(toolchain)?;
    let notices = object(&inventory, "files")?;
    if notices.len() != RUST_PATHS.len() {
        return Err(error("readable Rust notice coverage mismatch"));
    }
    for (source, path) in RUST_PATHS {
        let record = notices
            .get(source)
            .ok_or_else(|| error("missing readable Rust notice"))?;
        files.push(File {
            path,
            bytes: text(record, string(record, "text")?, 2 << 20)?
                .as_bytes()
                .to_vec(),
            inventory: "licenses/locked-rust-toolchain-notices.json",
            inventory_sha256: checksum(toolchain)?,
        });
    }
    files.push(File {
        path: "licenses/LINKED-TARGET.txt",
        bytes: super::linked::readable(linked)?,
        inventory: "licenses/linked-target-notices.json",
        inventory_sha256: checksum(linked)?,
    });
    Ok(files)
}

/// # Errors
/// Propagates checksum formatting errors while constructing file bindings.
pub(super) fn report(files: &[File]) -> Result<Value> {
    let mut entries = Map::new();
    for file in files {
        let _previous: Option<Value> = entries.insert(
            file.path.into(),
            json!({"bytes":file.bytes.len(),"sha256":checksum(&file.bytes)?,
                "source_inventory":file.inventory,"source_inventory_sha256":file.inventory_sha256}),
        );
    }
    Ok(
        json!({"format_version":1_u32,"scope":"readable_copies_of_bound_inventory_texts",
        "upstream_text":"preserved_verbatim","license_permission_check":"external_required",
        "files":entries}),
    )
}
