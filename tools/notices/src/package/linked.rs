use std::{collections::BTreeSet, io::Write as _, path::Path};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{Result, checksum, error, identity, relative_path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    format_version: u8,
    scope: String,
    target: String,
    binary_sha256: String,
    components: Vec<Component>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Component {
    name: String,
    version: String,
    source_url: String,
    notices: Vec<Notice>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Notice {
    upstream_path: String,
    sha256: String,
    text: String,
}

/// # Errors
/// Rejects an oversized or non-HTTPS URL, invalid host, nongraphic bytes,
/// credentials, query, fragment, or backslash.
fn source_url(value: &str) -> Result<()> {
    let authority = value
        .strip_prefix("https://")
        .ok_or_else(|| error("linked notice source must use HTTPS"))?
        .split('/')
        .next()
        .ok_or_else(|| error("missing linked notice source host"))?;
    if value.len() > 2048
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
        || value.contains(['@', '?', '#', '\\'])
        || authority.is_empty()
        || !authority
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err(error("invalid linked notice source URL"));
    }
    Ok(())
}

/// # Errors
/// Rejects invalid identity or source metadata, excess or duplicate notices,
/// unsafe paths, empty or oversized text, and mismatched text checksums.
fn component(component: &Component) -> Result<String> {
    let key = identity(&json!({"name":component.name,"version":component.version}))?;
    source_url(&component.source_url)?;
    if component.notices.is_empty() || component.notices.len() > 16 {
        return Err(error("invalid linked component notice count"));
    }
    let mut seen = BTreeSet::new();
    for notice in &component.notices {
        let _path: &Path = relative_path(&notice.upstream_path)?;
        if !seen.insert(&notice.upstream_path)
            || notice.text.trim().is_empty()
            || notice.text.len() > 512_usize << 10_u32
            || checksum(notice.text.as_bytes())? != notice.sha256
        {
            return Err(error("invalid linked component notice text"));
        }
    }
    Ok(key)
}

/// # Errors
/// Rejects oversized or malformed strict-schema JSON, mismatched version,
/// scope, target, or binary identity, excessive counts, duplicate components,
/// and invalid component notices.
pub fn validate(target: &str, binary_sha256: &str, bytes: &[u8]) -> Result<Value> {
    if bytes.len() > 4_usize << 20_u32 {
        return Err(error("linked notice inventory exceeds limit"));
    }
    let inventory: Inventory = serde_json::from_slice(bytes)?;
    if inventory.format_version != 1
        || inventory.scope != "linked_target_source_notices"
        || inventory.target != target
        || inventory.binary_sha256 != binary_sha256
        || inventory.components.is_empty()
        || inventory.components.len() > 64
    {
        return Err(error("linked notice inventory identity mismatch"));
    }
    let mut seen = BTreeSet::new();
    let mut count = 0_usize;
    for source in &inventory.components {
        if !seen.insert(component(source)?) {
            return Err(error("duplicate linked component"));
        }
        count = count
            .checked_add(source.notices.len())
            .ok_or_else(|| error("linked notice count overflow"))?;
        if count > 256 {
            return Err(error("linked notice count exceeds limit"));
        }
    }
    Ok(json!({"scope":inventory.scope,"target":inventory.target,
        "binary_sha256":inventory.binary_sha256,"inventory_sha256":checksum(bytes)?,
        "components":inventory.components.len(),"notices":count,
        "verification":"bound_input_bytes_and_inventory_structure",
        "coverage":"external_required","compilation_eligibility":"external_required",
        "license_permission_check":"external_required"}))
}

/// # Errors
/// Returns an error for JSON decoding or bounded-output writes. Callers must
/// validate inventory identity and notice bindings before rendering.
pub(super) fn readable(bytes: &[u8]) -> Result<Vec<u8>> {
    let inventory: Inventory = serde_json::from_slice(bytes)?;
    let mut output = super::Output {
        bytes: Vec::new(),
        limit: 8 << 20,
    };
    output.write_all(b"LogBrew MCP linked target source notices\n\n")?;
    writeln!(
        output,
        "Target: {}\nBinary SHA-256: {}",
        inventory.target, inventory.binary_sha256
    )?;
    for source in inventory.components {
        writeln!(
            output,
            "\n{} {}\nSource: {}",
            source.name, source.version, source.source_url
        )?;
        for notice in source.notices {
            writeln!(
                output,
                "\n{}\nSHA-256: {}\n----- BEGIN UPSTREAM TEXT -----",
                notice.upstream_path, notice.sha256
            )?;
            output.write_all(notice.text.as_bytes())?;
            output.write_all(b"\n----- END UPSTREAM TEXT -----\n")?;
        }
    }
    Ok(output.bytes)
}

#[cfg(test)]
mod tests;
