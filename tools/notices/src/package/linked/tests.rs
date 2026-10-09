use serde_json::{Value, json};

use super::{required, validate};
use crate::{Result, checksum};

const TARGET: &str = "aarch64-unknown-linux-gnu";

/// # Errors
/// Propagates checksum formatting failure while building the synthetic inventory.
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

/// # Errors
/// Propagates inventory encoding or validation failure.
fn check(value: &Value) -> Result<Value> {
    validate(TARGET, &"b".repeat(64), &serde_json::to_vec(value)?)
}

#[test]
/// # Errors
/// Propagates fixture construction or inventory validation failure.
///
/// # Panics
/// Panics if coverage, permission requirements, or count fields differ from expectations.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
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
/// # Errors
/// Propagates fixture construction, encoding, or missing fixture-field errors.
///
/// # Panics
/// Panics if invalid identity, scope, schema, or duplicate fields are accepted.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
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
    let _error: Box<dyn core::error::Error> =
        validate(TARGET, &"b".repeat(64), duplicate.as_bytes())
            .expect_err("input must be rejected");
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture construction or missing notice-field errors.
///
/// # Panics
/// Panics if modified notice text, unsafe paths, or unknown fields are accepted.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
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
/// # Errors
/// Propagates fixture construction or missing inventory-array errors.
///
/// # Panics
/// Panics if duplicate component or notice identities are accepted.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
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
/// # Errors
/// Propagates fixture construction or missing source-URL errors.
///
/// # Panics
/// Panics if a prohibited source URL is accepted.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
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
/// # Errors
/// Propagates fixture construction, checksum, or missing notice-field errors.
fn notice_text_and_encoded_inventory_limits_reject_before_packaging() -> Result<()> {
    let mut value_inventory = inventory()?;
    let text = "a".repeat((512 << 10) + 1);
    let notice = value_inventory
        .pointer_mut("/components/0/notices/0")
        .ok_or("missing notice")?;
    *notice = json!({"upstream_path":"COPYING","sha256":checksum(text.as_bytes())?,"text":text});
    let _text_error: Box<dyn core::error::Error> =
        check(&value_inventory).expect_err("input must be rejected");
    let _error: Box<dyn core::error::Error> =
        validate(TARGET, &"b".repeat(64), &vec![b' '; (4 << 20) + 1])
            .expect_err("oversized inventory must be rejected");
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture construction, missing fixture fields, or boundary validation errors.
///
/// # Panics
/// Panics if accepted boundary counts differ from 64 components and 256 notices.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
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
    let _error: Box<dyn core::error::Error> =
        check(&value_inventory).expect_err("input must be rejected");
    Ok(())
}

/// # Errors
/// Propagates inventory encoding and required-component validation errors.
fn check_required(expected: &Value, linked: &Value) -> Result<Value> {
    required(
        TARGET,
        &"b".repeat(64),
        &serde_json::to_vec(expected)?,
        &serde_json::to_vec(linked)?,
    )
}

#[test]
/// # Errors
/// Propagates fixture access, checksum or validation errors, and fails if a
/// missing component or rebound but changed required notice is accepted.
fn required_components_reject_omissions_and_changed_metadata_or_notice_bytes() -> Result<()> {
    let linked = inventory()?;
    let mut expected = linked.clone();
    *expected.get_mut("scope").ok_or("missing scope")? = json!("required_linked_source_notices");
    let _valid: Value = check_required(&expected, &linked)?;
    for (pointer, value) in [
        ("/components/0/name", json!("omitted-component")),
        ("/components/0/version", json!("2.0.0")),
        (
            "/components/0/source_url",
            json!("https://example.com/another-source"),
        ),
        ("/components/0/notices/0/upstream_path", json!("NOTICE")),
        ("/target", json!("x86_64-unknown-linux-gnu")),
        ("/binary_sha256", json!("c".repeat(64))),
        ("/scope", json!("linked_target_source_notices")),
        ("/components", json!([])),
    ] {
        let mut changed = expected.clone();
        *changed
            .pointer_mut(pointer)
            .ok_or("missing fixture field")? = value;
        if check_required(&changed, &linked).is_ok() {
            return Err(format!("invalid required notice accepted: {pointer}").into());
        }
    }
    let mut changed_linked = linked;
    let changed_text = "changed attribution\n";
    *changed_linked
        .pointer_mut("/components/0/notices/0")
        .ok_or("missing notice")? = json!({"upstream_path":"COPYING",
        "sha256":checksum(changed_text.as_bytes())?,"text":changed_text});
    let _internally_valid: Value = check(&changed_linked)?;
    if check_required(&expected, &changed_linked).is_ok() {
        return Err("rebound changed text was accepted".into());
    }
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture access, encoding or validation errors, and fails if the
/// exact required subset or external release requirements are not preserved.
fn required_notice_subset_allows_additional_notices_and_keeps_external_gates() -> Result<()> {
    let mut linked = inventory()?;
    let mut expected = linked.clone();
    *expected.get_mut("scope").ok_or("missing scope")? = json!("required_linked_source_notices");
    let extra_text = "another source notice\n";
    let notices = linked
        .pointer_mut("/components/0/notices")
        .and_then(Value::as_array_mut)
        .ok_or("missing notices")?;
    notices.insert(
        0,
        json!({"upstream_path":"NOTICE",
        "sha256":checksum(extra_text.as_bytes())?,"text":extra_text}),
    );
    let report = check_required(&expected, &linked)?;
    for key in [
        "coverage",
        "compilation_eligibility",
        "license_permission_check",
    ] {
        if report.get(key) != Some(&json!("external_required")) {
            return Err(format!("external gate changed: {key}").into());
        }
    }
    if report.get("components") != Some(&json!(1_u32))
        || report.get("notices") != Some(&json!(1_u32))
    {
        return Err("required subset counts changed".into());
    }
    Ok(())
}
