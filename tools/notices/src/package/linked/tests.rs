use serde_json::{Value, json};

use super::validate;
use crate::{Result, checksum};

const TARGET: &str = "aarch64-unknown-linux-gnu";

fn inventory() -> Result<Value> {
    let text = "synthetic component attribution\n";
    Ok(
        json!({"format_version":1_u32,"scope":"linked_target_source_notices",
        "target":TARGET,"binary_sha256":"b".repeat(64),
        "components":[{"name":"synthetic-runtime","version":"1.0.0",
            "source_url":"https://example.com/runtime/1.0.0.tar.gz",
            "notices":[{"upstream_path":"COPYING","sha256":checksum(text.as_bytes())?,"text":text}]}]}),
    )
}

fn check(value: &Value) -> Result<Value> {
    validate(TARGET, &"b".repeat(64), &serde_json::to_vec(value)?)
}

#[test]
fn bound_inventory_preserves_external_coverage_and_permission_requirements() -> Result<()> {
    let report = check(&inventory()?)?;
    for key in [
        "coverage",
        "compilation_eligibility",
        "license_permission_check",
    ] {
        assert_eq!(report.get(key), Some(&json!("external_required")), "{key}");
    }
    assert_eq!(report.get("components"), Some(&json!(1_u32)));
    assert_eq!(report.get("notices"), Some(&json!(1_u32)));
    Ok(())
}

#[test]
fn another_binary_target_or_scope_cannot_use_a_rebound_inventory_hash() -> Result<()> {
    for (key, value) in [
        ("format_version", json!(2_u32)),
        ("scope", json!("complete_permission")),
        ("target", json!("x86_64-unknown-linux-gnu")),
        ("binary_sha256", json!("c".repeat(64))),
        ("private_metadata", json!("synthetic private field")),
        ("components", json!([])),
    ] {
        let mut value_inventory = inventory()?;
        let _previous: Option<Value> = value_inventory
            .as_object_mut()
            .ok_or("missing inventory")?
            .insert(key.into(), value);
        assert!(check(&value_inventory).is_err(), "{key}");
    }
    let encoded = serde_json::to_string(&inventory()?)?;
    let duplicate = encoded.replace(
        "\"format_version\":1",
        "\"format_version\":1,\"format_version\":1",
    );
    let _error: Box<dyn std::error::Error> =
        validate(TARGET, &"b".repeat(64), duplicate.as_bytes())
            .expect_err("input must be rejected");
    Ok(())
}

#[test]
fn modified_text_paths_and_unrecognized_notice_fields_are_rejected() -> Result<()> {
    for (key, value) in [
        ("text", json!("modified attribution")),
        ("text", json!("  \n")),
        ("sha256", json!("A".repeat(64))),
        ("upstream_path", json!("../private/COPYING")),
        ("unknown", json!(true)),
    ] {
        let mut value_inventory = inventory()?;
        let _previous: Option<Value> = value_inventory
            .pointer_mut("/components/0/notices/0")
            .and_then(Value::as_object_mut)
            .ok_or("missing notice")?
            .insert(key.into(), value);
        assert!(check(&value_inventory).is_err(), "{key}");
    }
    Ok(())
}

#[test]
fn duplicate_component_or_notice_identity_is_rejected() -> Result<()> {
    for pointer in ["/components", "/components/0/notices"] {
        let mut value_inventory = inventory()?;
        let values = value_inventory
            .pointer_mut(pointer)
            .and_then(Value::as_array_mut)
            .ok_or("missing inventory array")?;
        let first = values.first().ok_or("missing first value")?.clone();
        values.push(first);
        assert!(check(&value_inventory).is_err(), "{pointer}");
    }
    Ok(())
}

#[test]
fn source_metadata_rejects_credentials_and_non_https_sources() -> Result<()> {
    for url in [
        "http://example.com/source.tar.gz",
        "https://user:credential@example.com/source.tar.gz",
        "https://example.com/source.tar.gz?credential=synthetic",
        "https://example.com/source.tar.gz#synthetic",
        "https:///source.tar.gz",
    ] {
        let mut value_inventory = inventory()?;
        *value_inventory
            .pointer_mut("/components/0/source_url")
            .ok_or("missing source URL")? = json!(url);
        assert!(check(&value_inventory).is_err(), "{url}");
    }
    Ok(())
}

#[test]
fn notice_text_and_encoded_inventory_limits_reject_before_packaging() -> Result<()> {
    let mut value_inventory = inventory()?;
    let text = "a".repeat((512 << 10) + 1);
    let notice = value_inventory
        .pointer_mut("/components/0/notices/0")
        .ok_or("missing notice")?;
    *notice = json!({"upstream_path":"COPYING","sha256":checksum(text.as_bytes())?,"text":text});
    let _error: Box<dyn std::error::Error> =
        check(&value_inventory).expect_err("input must be rejected");
    let _error: Box<dyn std::error::Error> =
        validate(TARGET, &"b".repeat(64), &vec![b' '; (4 << 20) + 1])
            .expect_err("oversized inventory must be rejected");
    Ok(())
}

#[test]
fn component_and_notice_count_limits_preserve_the_exact_boundary() -> Result<()> {
    let mut value_inventory = inventory()?;
    let original = value_inventory
        .pointer("/components/0")
        .ok_or("missing component")?
        .clone();
    let mut sources = Vec::new();
    for index in 0_usize..64_usize {
        let mut source = original.clone();
        *source.get_mut("name").ok_or("missing name")? = json!(format!("runtime-{index}"));
        let first = source
            .pointer("/notices/0")
            .ok_or("missing notice")?
            .clone();
        let mut notices = Vec::new();
        for notice_index in 0_usize..4_usize {
            let mut notice = first.clone();
            *notice.get_mut("upstream_path").ok_or("missing path")? =
                json!(format!("COPYING-{notice_index}"));
            notices.push(notice);
        }
        *source.get_mut("notices").ok_or("missing notices")? = json!(notices);
        sources.push(source);
    }
    *value_inventory
        .get_mut("components")
        .ok_or("missing components")? = json!(sources);
    let report = check(&value_inventory)?;
    assert_eq!(report.get("components"), Some(&json!(64_u32)));
    assert_eq!(report.get("notices"), Some(&json!(256_u32)));
    let values = value_inventory
        .pointer_mut("/components/0/notices")
        .and_then(Value::as_array_mut)
        .ok_or("missing notices")?;
    let mut additional = values.first().ok_or("missing notice")?.clone();
    *additional.get_mut("upstream_path").ok_or("missing path")? = json!("ADDITIONAL");
    values.push(additional);
    let _error: Box<dyn std::error::Error> =
        check(&value_inventory).expect_err("input must be rejected");
    Ok(())
}
