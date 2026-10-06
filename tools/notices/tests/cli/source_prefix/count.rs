use std::fs;

use serde_json::{Value, json};

use super::{Result, archive_scenario, write_json};

#[test]
/// # Errors
/// Propagates fixture setup, source writes, generation, decoding or field access.
///
/// # Panics
/// Panics if a complete bounded inventory loses references or an excessive
/// supplement replaces the last successful inventory.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-06, revisit 2026-11-06"
)]
fn larger_supplements_preserve_all_references_and_reject_overflow() -> Result<()> {
    let mut scenario = archive_scenario()?;
    let root = &scenario.fixture.root;
    let notices = scenario
        .manifest
        .get_mut("notices")
        .and_then(Value::as_array_mut)
        .ok_or("missing notices")?;
    let template = notices.get(2).ok_or("missing whole notice")?.clone();
    for index in 3_usize..128_usize {
        let mut notice = template.clone();
        let path = format!("NOTICE-{index}");
        *notice.get_mut("upstream_path").ok_or("missing path")? = json!(path);
        *notice.get_mut("source_url").ok_or("missing URL")? = json!(format!(
            "https://raw.githubusercontent.com/example/project/{}/{path}",
            "0".repeat(40)
        ));
        notices.push(notice);
    }
    write_json(&root.join("sources.json"), &scenario.manifest)?;
    assert!(fs::metadata(root.join("sources.json"))?.len() < 64_u64 << 10_u32);
    let generated = scenario.fixture.run()?;
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let previous = fs::read(root.join("output.json"))?;
    let inventory: Value = serde_json::from_slice(&previous)?;
    let records = inventory
        .pointer("/packages/example 1.0.0/supplemental_notices")
        .and_then(Value::as_array)
        .ok_or("missing generated records")?;
    assert_eq!(records.len(), 128);
    assert_eq!(
        inventory
            .get("texts")
            .and_then(Value::as_object)
            .map(serde_json::Map::len),
        Some(2)
    );
    assert!(scenario.fixture.run()?.status.success());
    assert_eq!(fs::read(root.join("output.json"))?, previous);

    let mut overflow = template;
    *overflow.get_mut("upstream_path").ok_or("missing path")? = json!("NOTICE-overflow");
    *overflow.get_mut("source_url").ok_or("missing URL")? = json!(format!(
        "https://raw.githubusercontent.com/example/project/{}/NOTICE-overflow",
        "0".repeat(40)
    ));
    scenario
        .manifest
        .get_mut("notices")
        .and_then(Value::as_array_mut)
        .ok_or("missing notices")?
        .push(overflow);
    write_json(&root.join("sources.json"), &scenario.manifest)?;
    assert!(fs::metadata(root.join("sources.json"))?.len() < 64_u64 << 10_u32);
    let rejected = scenario.fixture.run()?;
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("invalid supplement manifest"));
    assert_eq!(fs::read(root.join("output.json"))?, previous);
    Ok(())
}
