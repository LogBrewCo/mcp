use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read as _},
};

use flate2::read::MultiGzDecoder;
use serde::Deserialize;
use serde_json::json;

use crate::{Result, bounded, checksum, error, relative_path};

pub const ARCHIVE_BYTES: u64 = 128 << 20;
pub const NOTICE_BYTES: u64 = 2 << 20;
const EXPANDED_BYTES: u64 = 512 << 20;
const LIBRARY_NOTICE: &str = "rustc/share/doc/rust/COPYRIGHT-library.html";
const NOTICE_PATHS: [&str; 4] = ["COPYRIGHT", "LICENSE-APACHE", "LICENSE-MIT", LIBRARY_NOTICE];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    format_version: u8,
    scope: String,
    release: String,
    target: String,
    source_commit: String,
    release_date: String,
    distribution_manifest_sha256: String,
    component_archive_sha256: String,
    component_archive_url: String,
    #[serde(deserialize_with = "files")]
    files: BTreeMap<String, Notice>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Notice {
    sha256: String,
    bytes: u64,
}

fn files<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, Notice>, D::Error> {
    struct Unique;
    impl<'de> serde::de::Visitor<'de> for Unique {
        type Value = BTreeMap<String, Notice>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("four unique standard-library notice paths")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut files = BTreeMap::new();
            while let Some((path, notice)) = map.next_entry::<String, Notice>()? {
                if files.len() >= 4 || files.insert(path, notice).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate or excess Rust notice path",
                    ));
                }
            }
            Ok(files)
        }
    }
    deserializer.deserialize_map(Unique)
}

fn hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn source(bytes: &[u8]) -> Result<Binding> {
    let source: Binding = serde_json::from_slice(bytes)?;
    let date = source.release_date.as_bytes();
    if source.format_version != 1
        || source.scope != "rust_standard_library_source_notices"
        || source.release != env!("CARGO_PKG_RUST_VERSION")
        || source.target.is_empty()
        || source.target.len() > 128
        || !source
            .target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || date.len() != 10
        || date.get(4) != Some(&b'-')
        || date.get(7) != Some(&b'-')
        || date
            .iter()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 4 | 7) && !byte.is_ascii_digit())
        || !hex(&source.source_commit, 40)
        || !hex(&source.distribution_manifest_sha256, 64)
        || !hex(&source.component_archive_sha256, 64)
        || source.files.keys().map(String::as_str).ne(NOTICE_PATHS)
        || source.files.values().any(|notice| {
            !hex(&notice.sha256, 64) || notice.bytes == 0 || notice.bytes > NOTICE_BYTES
        })
        || source.component_archive_url
            != format!(
                "https://static.rust-lang.org/dist/{}/rustc-{}-{}.tar.gz",
                source.release_date, source.release, source.target
            )
    {
        return Err(error("invalid Rust source binding"));
    }
    Ok(source)
}

pub fn distribution(source: &Binding, bytes: &[u8]) -> Result<()> {
    if checksum(bytes)? != source.distribution_manifest_sha256 {
        return Err(error("Rust distribution manifest checksum mismatch"));
    }
    let manifest = std::str::from_utf8(bytes)?.parse::<toml::Table>()?;
    let rustc = manifest
        .get("pkg")
        .and_then(|value| value.get("rustc"))
        .ok_or_else(|| error("missing Rust compiler component"))?;
    let target = rustc
        .get("target")
        .and_then(|value| value.get(&source.target))
        .ok_or_else(|| error("missing Rust compiler target"))?;
    if manifest
        .get("manifest-version")
        .and_then(toml::Value::as_str)
        != Some("2")
        || manifest.get("date").and_then(toml::Value::as_str) != Some(&source.release_date)
        || rustc.get("git_commit_hash").and_then(toml::Value::as_str) != Some(&source.source_commit)
        || rustc
            .get("version")
            .and_then(toml::Value::as_str)
            .is_none_or(|value| !value.starts_with(&format!("{} (", source.release)))
        || target.get("available").and_then(toml::Value::as_bool) != Some(true)
        || target.get("url").and_then(toml::Value::as_str) != Some(&source.component_archive_url)
        || target.get("hash").and_then(toml::Value::as_str)
            != Some(&source.component_archive_sha256)
    {
        return Err(error("Rust distribution disagrees with source binding"));
    }
    Ok(())
}

pub fn collect(source: &Binding, bytes: &[u8], installed: &[u8]) -> Result<Vec<u8>> {
    collect_bounded(source, bytes, installed, EXPANDED_BYTES)
}

fn collect_bounded(
    source: &Binding,
    bytes: &[u8],
    installed: &[u8],
    expanded_bytes: u64,
) -> Result<Vec<u8>> {
    if u64::try_from(bytes.len())? > ARCHIVE_BYTES
        || checksum(bytes)? != source.component_archive_sha256
    {
        return Err(error("Rust component archive checksum or size mismatch"));
    }
    let prefix = format!("rustc-{}-{}", source.release, source.target);
    let expanded_limit = expanded_bytes
        .checked_add(1)
        .ok_or_else(|| error("invalid Rust component expansion limit"))?;
    let mut archive = tar::Archive::new(MultiGzDecoder::new(bytes).take(expanded_limit));
    let mut seen = BTreeSet::new();
    let mut notices = BTreeMap::new();
    let mut path_bytes = 0usize;
    let mut notice_bytes = 0usize;
    for (index, entry) in archive.entries()?.enumerate() {
        if index >= 4096 {
            return Err(error("Rust component entry budget exceeded"));
        }
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let path = path
            .to_str()
            .ok_or_else(|| error("invalid Rust component path encoding"))?;
        path_bytes = path_bytes
            .checked_add(path.len())
            .ok_or_else(|| error("Rust component path overflow"))?;
        if path.len() > 4096 || path_bytes > 1 << 20 {
            return Err(error("Rust component path budget exceeded"));
        }
        let kind = entry.header().entry_type();
        let path = if kind.is_dir() {
            path.trim_end_matches('/')
        } else {
            path
        };
        relative_path(path)?;
        let relative = std::path::Path::new(path)
            .strip_prefix(&prefix)?
            .to_str()
            .ok_or_else(|| error("invalid Rust component prefix"))?;
        if !seen.insert(relative.to_owned()) {
            return Err(error("duplicate Rust component path"));
        }
        if kind.is_dir() {
            continue;
        }
        relative_path(relative)?;
        if !kind.is_file() {
            return Err(error("Rust component link or special file rejected"));
        }
        if let Some(expected) = source.files.get(relative) {
            let content = bounded(&mut entry, NOTICE_BYTES)?;
            if u64::try_from(content.len())? != expected.bytes
                || checksum(&content)? != expected.sha256
            {
                return Err(error("Rust notice checksum or size mismatch"));
            }
            notice_bytes = notice_bytes
                .checked_add(content.len())
                .ok_or_else(|| error("Rust notice size overflow"))?;
            if notice_bytes > 4 << 20 {
                return Err(error("Rust notice text budget exceeded"));
            }
            let text = std::str::from_utf8(&content)?;
            if text.trim().is_empty() {
                return Err(error("empty Rust notice"));
            }
            if relative == LIBRARY_NOTICE && content != installed {
                return Err(error(
                    "installed Rust library notice differs from distribution",
                ));
            }
            notices.insert(
                relative.to_owned(),
                json!({"sha256":expected.sha256,"bytes":expected.bytes,"text":text}),
            );
        }
    }
    let mut expanded = archive.into_inner();
    io::copy(&mut expanded, &mut io::sink())?;
    if expanded.limit() == 0 {
        return Err(error("Rust component expansion budget exceeded"));
    }
    if notices.keys().ne(source.files.keys()) {
        return Err(error("Rust component notice coverage mismatch"));
    }
    let output = json!({"format_version":1,"scope":source.scope,"release":source.release,"target":source.target,
        "source_commit":source.source_commit,"release_date":source.release_date,
        "distribution_manifest_sha256":source.distribution_manifest_sha256,"component_archive_sha256":source.component_archive_sha256,
        "component_archive_url":source.component_archive_url,"source_binding":"trusted_distribution_manifest_and_component_checksums",
        "installed_library_notice_verified":true,"binary_linkage_coverage":"not_evaluated",
        "license_permission_check":"separate_target_specific_gate_required","files":notices});
    let mut bytes = serde_json::to_vec_pretty(&output)?;
    bytes.push(b'\n');
    if bytes.len() > 8 << 20 {
        return Err(error("Rust notice output budget exceeded"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
