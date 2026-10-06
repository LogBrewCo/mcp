use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::{Result, Texts, archive, checksum, error, relative_path, string};

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
    source_prefix: Option<SourcePrefix>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourcePrefix {
    archive_path: String,
    bytes: u64,
    sha256: String,
    source_url_kind: Option<PrefixUrlKind>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum PrefixUrlKind {
    PublishedArchive,
}

/// # Errors
/// Rejects missing archive proof or a supplement bound to another archive.
fn verified_package(package: &Value, notice: &Notice) -> Result<()> {
    if package.get("published_archive_verified") != Some(&Value::Bool(true))
        || package
            .get("published_package_sha256")
            .and_then(Value::as_str)
            != Some(notice.published_package_sha256.as_str())
    {
        return Err(error("supplemental archive mismatch"));
    }
    Ok(())
}

/// # Errors
/// Rejects unsafe sibling paths, failed bounded reads, changed checksums,
/// empty text, or invalid UTF-8.
fn notice_text(notice: &Notice, root: &Path) -> Result<Vec<u8>> {
    let file = relative_path(&notice.file)?;
    if file.components().count() != 1 {
        return Err(error("supplement must be a sibling file"));
    }
    let bytes = crate::input::read(&root.join(file), archive::NOTICE_BYTES)?;
    if checksum(&bytes)? != notice.sha256 {
        return Err(error("supplemental text checksum mismatch"));
    }
    if std::str::from_utf8(&bytes)?.trim().is_empty() {
        return Err(error("empty supplemental text"));
    }
    Ok(bytes)
}

/// # Errors
/// Rejects missing package/VCS data, unsafe or mismatched source paths,
/// duplicate selections, changed notices, and failed archive verification.
fn verify_prefixes(
    packages: &BTreeMap<String, Value>,
    manifest: &Manifest,
    root: &Path,
    cache: &Path,
) -> Result<()> {
    let mut grouped: BTreeMap<String, BTreeMap<String, archive::Prefix>> = BTreeMap::new();
    for notice in &manifest.notices {
        let Some(prefix) = &notice.source_prefix else {
            continue;
        };
        let key = format!("{} {}", notice.package, notice.version);
        let package = packages
            .get(&key)
            .ok_or_else(|| error("unused supplemental package"))?;
        verified_package(package, notice)?;
        let path = relative_path(&prefix.archive_path)?;
        let vcs_path = package
            .pointer("/vcs/path_in_vcs")
            .and_then(Value::as_str)
            .ok_or_else(|| error("missing archived repository path"))?;
        let upstream_path = if vcs_path.is_empty() {
            prefix.archive_path.clone()
        } else {
            let _path: &Path = relative_path(vcs_path)?;
            format!("{vcs_path}/{}", path.display())
        };
        if upstream_path != notice.upstream_path {
            return Err(error("source notice archive path mismatch"));
        }
        let selected = grouped.entry(key).or_default();
        if selected
            .insert(
                prefix.archive_path.clone(),
                archive::Prefix {
                    bytes: prefix.bytes,
                    sha256: prefix.sha256.clone(),
                    text: notice_text(notice, root)?,
                },
            )
            .is_some()
        {
            return Err(error("duplicate source prefix"));
        }
    }
    for (key, prefixes) in grouped {
        let package = packages
            .get(&key)
            .ok_or_else(|| error("unused supplemental package"))?;
        let metadata = json!({"name":package.get("name"),"version":package.get("version"),
            "license":package.get("declared_license"),"repository":package.get("repository")});
        let bytes = crate::input::read(
            &cache.join(format!(
                "{}-{}.crate",
                string(package, "name")?,
                string(package, "version")?
            )),
            archive::ARCHIVE_BYTES,
        )?;
        let collected = archive::collect_with_prefixes(
            &metadata,
            &bytes,
            string(package, "published_package_sha256")?,
            archive::Limits::default(),
            &prefixes,
        )?;
        if collected.vcs.as_ref() != package.get("vcs") {
            return Err(error("source notice archived revision mismatch"));
        }
    }
    Ok(())
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
/// Rejects unsafe registry URL path components.
fn published_archive_url(package: &Value) -> Result<String> {
    let name = string(package, "name")?;
    let version = string(package, "version")?;
    if name.is_empty()
        || version.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'+'))
    {
        return Err(error("invalid published archive URL identity"));
    }
    Ok(format!(
        "https://static.crates.io/crates/{name}/{name}-{version}.crate"
    ))
}

/// # Errors
/// Rejects invalid package repository, revision, path or registry URL bindings.
fn notice_url(package: &Value, notice: &Notice) -> Result<String> {
    let repository = source_url(package, &notice.source_commit, &notice.upstream_path)?;
    if notice
        .source_prefix
        .as_ref()
        .is_some_and(|prefix| prefix.source_url_kind.is_some())
    {
        return published_archive_url(package);
    }
    Ok(repository)
}

fn prefix_record(prefix: &SourcePrefix, length: usize) -> Value {
    let mut fields: Map<String, Value> = [
        ("archive_path".to_owned(), json!(prefix.archive_path)),
        ("bytes".to_owned(), json!(prefix.bytes)),
        ("sha256".to_owned(), json!(prefix.sha256)),
        ("prefix_bytes".to_owned(), json!(length)),
    ]
    .into_iter()
    .collect();
    if prefix.source_url_kind.is_some() {
        let _previous: Option<Value> =
            fields.insert("source_url_kind".to_owned(), json!("published_archive"));
    }
    Value::Object(fields)
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
    cache: &Path,
) -> Result<()> {
    let manifest: Manifest = serde_json::from_slice(bytes)?;
    if manifest.format_version != 1 || manifest.notices.len() > 64 {
        return Err(error("invalid supplement manifest"));
    }
    verify_prefixes(packages, &manifest, root, cache)?;
    let mut seen = BTreeSet::new();
    for notice in manifest.notices {
        let key = format!("{} {}", notice.package, notice.version);
        let package = packages
            .get_mut(&key)
            .ok_or_else(|| error("unused supplemental package"))?;
        verified_package(package, &notice)?;
        if notice_url(package, &notice)? != notice.source_url {
            return Err(error("supplemental source URL mismatch"));
        }
        if !seen.insert((key, notice.upstream_path.clone())) {
            return Err(error("duplicate supplement"));
        }
        let text_bytes = notice_text(&notice, root)?;
        let text = std::str::from_utf8(&text_bytes)?;
        let digest = texts.insert(text)?;
        let mut record = json!({"file":notice.file,"sha256":digest,"bytes":text_bytes.len(),"source_url":notice.source_url,
            "source_commit":notice.source_commit,"upstream_path":notice.upstream_path,
            "source_kind":"checked_upstream_file_omitted_from_published_archive"});
        if let Some(prefix) = notice.source_prefix {
            let fields = record
                .as_object_mut()
                .ok_or_else(|| error("invalid notice record"))?;
            let _previous_kind: Option<Value> = fields.insert(
                "source_kind".to_owned(),
                Value::String("checked_published_archive_source_prefix".to_owned()),
            );
            let _previous_prefix: Option<Value> = fields.insert(
                "source_prefix".to_owned(),
                prefix_record(&prefix, text_bytes.len()),
            );
        }
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
