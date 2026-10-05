use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{Result, Texts, archive::NOTICE_BYTES, checksum, error, relative_path, string};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format_version: u8,
    notices: Vec<Notice>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Notice {
    package: String,
    version: String,
    published_package_sha256: String,
    source_commit: String,
    upstream_path: String,
    source_url: String,
    file: String,
    sha256: String,
}

/// # Errors
/// Rejects absent repository or VCS fields, unsupported GitHub repository
/// paths, revision mismatch, and unsafe upstream paths.
fn source_url(package: &Value, source_commit: &str, upstream_path: &str) -> Result<String> {
    let repository = string(package, "repository")?.trim_end_matches('/');
    let repository = repository.strip_suffix(".git").unwrap_or(repository);
    let repository = repository
        .strip_prefix("https://github.com/")
        .ok_or_else(|| error("unsupported supplemental repository"))?;
    let parts: Vec<_> = repository.split('/').collect();
    if parts.len() != 2
        || parts.iter().any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return Err(error("invalid supplemental repository"));
    }
    let vcs = package
        .get("vcs")
        .and_then(|v| v.get("git"))
        .and_then(|v| v.get("sha1"))
        .and_then(Value::as_str)
        .ok_or_else(|| error("supplement has no archived source revision"))?;
    if source_commit.len() != 40
        || !source_commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || source_commit != vcs
    {
        return Err(error("supplemental revision mismatch"));
    }
    let _path: &Path = relative_path(upstream_path)?;
    Ok(format!(
        "https://raw.githubusercontent.com/{repository}/{source_commit}/{upstream_path}"
    ))
}

/// # Errors
/// Rejects malformed or excessive supplements, missing or unverified packages,
/// archive or revision disagreement, URL mismatch, duplicates, unsafe file
/// paths, failed bounded reads, invalid UTF-8 or empty text, checksum mismatch,
/// and malformed package records. Earlier supplements may already be applied
/// when a later one fails; callers discard the failed inventory.
pub fn apply(
    packages: &mut BTreeMap<String, Value>,
    texts: &mut Texts,
    bytes: &[u8],
    root: &Path,
) -> Result<()> {
    let manifest: Manifest = serde_json::from_slice(bytes)?;
    if manifest.format_version != 1 || manifest.notices.len() > 64 {
        return Err(error("invalid supplement manifest"));
    }
    let mut seen = BTreeSet::new();
    for notice in manifest.notices {
        let key = format!("{} {}", notice.package, notice.version);
        let package = packages
            .get_mut(&key)
            .ok_or_else(|| error("unused supplemental package"))?;
        if package.get("published_archive_verified") != Some(&Value::Bool(true))
            || package
                .get("published_package_sha256")
                .and_then(Value::as_str)
                != Some(notice.published_package_sha256.as_str())
        {
            return Err(error("supplemental archive mismatch"));
        }
        if source_url(package, &notice.source_commit, &notice.upstream_path)? != notice.source_url {
            return Err(error("supplemental source URL mismatch"));
        }
        if !seen.insert((key, notice.upstream_path.clone())) {
            return Err(error("duplicate supplement"));
        }
        let file = relative_path(&notice.file)?;
        if file.components().count() != 1 {
            return Err(error("supplement must be a sibling file"));
        }
        let bytes = crate::input::read(&root.join(file), NOTICE_BYTES)?;
        if checksum(&bytes)? != notice.sha256 {
            return Err(error("supplemental text checksum mismatch"));
        }
        let text = std::str::from_utf8(&bytes)?;
        if text.trim().is_empty() {
            return Err(error("empty supplemental text"));
        }
        let digest = texts.insert(text)?;
        let record = json!({"file":notice.file,"sha256":digest,"bytes":bytes.len(),"source_url":notice.source_url,
            "source_commit":notice.source_commit,"upstream_path":notice.upstream_path,
            "source_kind":"checked_upstream_file_omitted_from_published_archive"});
        let package = package
            .as_object_mut()
            .ok_or_else(|| error("invalid package record"))?;
        let notices = package
            .entry("supplemental_notices")
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or_else(|| error("invalid supplemental notices"))?;
        notices.push(record);
    }
    Ok(())
}
