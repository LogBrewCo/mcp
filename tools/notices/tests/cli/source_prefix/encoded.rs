use std::{fs, io};

use serde_json::{Value, json};

use super::{Result, Scenario, archive, archive_scenario, digest, write_json};

const HEADER: &[u8] = b"// Copyright synthetic author \t\r\n// Permission synthetic notice\r\n";
const LICENSE: &[u8] = b"complete omitted license \t\r\n";

/// # Errors
/// Propagates record lookup, encoding, hashing, or file writes.
fn bind_asset(scenario: &mut Scenario, index: usize, bytes: &[u8]) -> Result<()> {
    let record = scenario
        .manifest
        .pointer_mut(&format!("/notices/{index}"))
        .and_then(Value::as_object_mut)
        .ok_or("missing notice")?;
    let file = format!("encoded-{index}.json");
    fs::write(scenario.fixture.root.join(&file), bytes)?;
    let _previous_file: Option<Value> = record.insert("file".into(), json!(file));
    let _previous_encoding: Option<Value> = record.insert(
        "file_encoding".into(),
        json!({"format":"json_string","bytes":bytes.len(),"sha256":digest(bytes)?}),
    );
    Ok(())
}

/// # Errors
/// Propagates fixture preparation, archive encoding, hashing, command execution or reads.
fn scenario() -> Result<Scenario> {
    let mut scenario = archive_scenario()?;
    let root = scenario.fixture.root.clone();
    let mut source = HEADER.to_vec();
    source.extend_from_slice(b"fn original() {}\n");
    let bytes = archive(&source)?;
    let checksum = digest(&bytes)?;
    fs::write(root.join("cache/example-1.0.0.crate"), bytes)?;
    fs::write(
        root.join("Cargo.lock"),
        format!(
            "version=4\n[[package]]\nname='example'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{checksum}'\n"
        ),
    )?;
    for record in scenario
        .manifest
        .get_mut("notices")
        .and_then(Value::as_array_mut)
        .ok_or("missing notices")?
    {
        *record
            .get_mut("published_package_sha256")
            .ok_or("missing archive checksum")? = json!(checksum);
    }
    for (index, text) in [(0_usize, HEADER), (2_usize, LICENSE)] {
        bind_asset(
            &mut scenario,
            index,
            &serde_json::to_vec(core::str::from_utf8(text)?)?,
        )?;
        *scenario
            .manifest
            .pointer_mut(&format!("/notices/{index}/sha256"))
            .ok_or("missing text checksum")? = json!(digest(text)?);
    }
    *scenario
        .manifest
        .pointer_mut("/notices/0/source_prefix")
        .ok_or("missing source binding")? = json!({
        "archive_path":"src/one.rs","bytes":source.len(),"sha256":digest(&source)?,
        "source_url_kind":"published_archive"
    });
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
/// Propagates fixture preparation, output decoding, field lookup, hashing or command errors.
///
/// # Panics
/// Panics if decoded whitespace, text checksums, asset provenance or deterministic output is lost.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-06, revisit 2026-11-06"
)]
fn preserves_decoded_whitespace_and_encoded_asset_provenance() -> Result<()> {
    let scenario = scenario()?;
    let inventory: Value = serde_json::from_slice(&scenario.output)?;
    for (index, text) in [(0_usize, HEADER), (2_usize, LICENSE)] {
        assert_eq!(
            inventory.pointer(&format!("/texts/{}", digest(text)?)),
            Some(&json!(core::str::from_utf8(text)?))
        );
        let record = inventory
            .pointer(&format!(
                "/packages/example 1.0.0/supplemental_notices/{index}"
            ))
            .ok_or("missing inventory notice")?;
        assert_eq!(record.get("bytes"), Some(&json!(text.len())));
        assert_eq!(record.get("sha256"), Some(&json!(digest(text)?)));
        assert_eq!(
            record.get("file_encoding"),
            scenario
                .manifest
                .pointer(&format!("/notices/{index}/file_encoding"))
        );
    }
    assert_eq!(
        inventory
            .pointer("/packages/example 1.0.0/supplemental_notices/0/source_prefix/prefix_bytes"),
        Some(&json!(HEADER.len()))
    );
    assert!(scenario.fixture.run()?.status.success());
    assert_eq!(
        fs::read(scenario.fixture.root.join("output.json"))?,
        scenario.output
    );
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture preparation, field lookup, file writes or command errors.
///
/// # Panics
/// Panics if an invalid encoding binding passes or changes the previous output.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-06, revisit 2026-11-06"
)]
fn rejects_changed_encoding_bindings_and_preserves_previous_output() -> Result<()> {
    let scenario = scenario()?;
    let root = &scenario.fixture.root;
    for (pointer, value) in [
        ("/notices/0/file_encoding/format", json!("other")),
        ("/notices/0/file_encoding/format", json!(true)),
        ("/notices/0/file_encoding/format", json!(null)),
        ("/notices/0/file_encoding/bytes", json!(1_u64)),
        ("/notices/0/file_encoding/sha256", json!("1".repeat(64))),
        ("/notices/0/file_encoding", json!({"format":"json_string"})),
        ("/notices/0/file_encoding", json!(null)),
        ("/notices/0/sha256", json!("1".repeat(64))),
    ] {
        let mut changed = scenario.manifest.clone();
        *changed
            .pointer_mut(pointer)
            .ok_or("missing encoding field")? = value;
        write_json(&root.join("sources.json"), &changed)?;
        assert!(!scenario.fixture.run()?.status.success(), "{pointer}");
        assert_eq!(fs::read(root.join("output.json"))?, scenario.output);
    }
    let mut changed = scenario.manifest.clone();
    let encoding = changed
        .pointer_mut("/notices/0/file_encoding")
        .and_then(Value::as_object_mut)
        .ok_or("missing encoding")?;
    let _previous: Option<Value> = encoding.insert("unknown".into(), json!(true));
    write_json(&root.join("sources.json"), &changed)?;
    assert!(!scenario.fixture.run()?.status.success());
    assert_eq!(fs::read(root.join("output.json"))?, scenario.output);
    write_json(&root.join("sources.json"), &scenario.manifest)?;
    fs::write(root.join("encoded-0.json"), b"\"changed encoded asset\"")?;
    assert!(!scenario.fixture.run()?.status.success());
    assert_eq!(fs::read(root.join("output.json"))?, scenario.output);
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture preparation, hashing, field lookup, file writes or command errors.
///
/// # Panics
/// Panics if malformed, oversized, empty or non-prefix decoded text changes the previous output.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-06, revisit 2026-11-06"
)]
fn rejects_invalid_encoded_text_even_with_matching_asset_bindings() -> Result<()> {
    let mut scenario = scenario()?;
    let original = scenario.manifest.clone();
    for bytes in [
        b"null".as_slice(),
        b"{}".as_slice(),
        b"[]".as_slice(),
        b"42".as_slice(),
        b"\"truncated".as_slice(),
        b"\"first\" \"second\"".as_slice(),
        b"\"\\ud800\"".as_slice(),
        b"\"\xff\"".as_slice(),
        b"\" \\t\\r\\n\"".as_slice(),
        b"\"changed decoded text\"".as_slice(),
    ] {
        scenario.manifest = original.clone();
        bind_asset(&mut scenario, 0, bytes)?;
        write_json(
            &scenario.fixture.root.join("sources.json"),
            &scenario.manifest,
        )?;
        assert!(!scenario.fixture.run()?.status.success(), "{bytes:?}");
        assert_eq!(
            fs::read(scenario.fixture.root.join("output.json"))?,
            scenario.output
        );
    }
    let mut normalized = core::str::from_utf8(HEADER)?.replace(" \t\r\n", "\r\n");
    normalized.push('\n');
    bind_asset(&mut scenario, 0, &serde_json::to_vec(&normalized)?)?;
    *scenario
        .manifest
        .pointer_mut("/notices/0/sha256")
        .ok_or("missing decoded checksum")? = json!(digest(normalized.as_bytes())?);
    write_json(
        &scenario.fixture.root.join("sources.json"),
        &scenario.manifest,
    )?;
    assert!(!scenario.fixture.run()?.status.success());
    assert_eq!(
        fs::read(scenario.fixture.root.join("output.json"))?,
        scenario.output
    );
    let oversized = vec![b' '; (1 << 20) + 1];
    bind_asset(&mut scenario, 0, &oversized)?;
    write_json(
        &scenario.fixture.root.join("sources.json"),
        &scenario.manifest,
    )?;
    assert!(!scenario.fixture.run()?.status.success());
    assert_eq!(
        fs::read(scenario.fixture.root.join("output.json"))?,
        scenario.output
    );
    Ok(())
}
