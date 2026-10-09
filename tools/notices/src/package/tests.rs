use std::io::Write as _;

use serde_json::{Value, json};

use super::{FileBinding, Output, Plan, Target, binary};
use crate::Result;

fn plan() -> Value {
    let binding = json!({"bytes":1_u32,"sha256":"0".repeat(64)});
    json!({"format_version":1_u32,"package_version":"0.1.0","build_identity":"development",
        "source_revision":"uncommitted","rust_release":"1.99.0",
        "target":"aarch64-apple-darwin","cargo_lock_sha256":"0".repeat(64),
        "binary":binding,"project_license":binding,"sdk_license":binding,
        "dependency_notices":binding,"toolchain_notices":binding})
}

#[test]
/// # Errors
/// Propagates valid-plan encoding/parsing, UTF-8 conversion, or missing fixture fields.
///
/// # Panics
/// Panics if invalid plan fields, duplicate fields, or invalid file bindings are accepted.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn packaging_plan_rejects_unknown_duplicate_or_invalid_identity_fields() -> Result<()> {
    let encoded = serde_json::to_vec(&plan())?;
    let _plan: Plan = Plan::parse(&encoded)?;
    let duplicate = String::from_utf8(encoded)?.replace(
        "\"format_version\":1",
        "\"format_version\":1,\"format_version\":1",
    );
    assert!(Plan::parse(duplicate.as_bytes()).is_err());
    for (key, value) in [
        ("private_metadata", Value::from("synthetic nonpublic value")),
        ("format_version", Value::from(2_u32)),
        ("package_version", Value::from("9.9.9")),
        ("build_identity", Value::from("0.1.0")),
        ("source_revision", Value::from("../revision")),
        ("rust_release", Value::from("1.98.1")),
        ("target", Value::from("../target")),
        ("cargo_lock_sha256", Value::from("A".repeat(64))),
    ] {
        let mut value_plan = plan();
        let _previous: Option<Value> = value_plan
            .as_object_mut()
            .ok_or("missing plan object")?
            .insert(key.into(), value);
        assert!(
            Plan::parse(&serde_json::to_vec(&value_plan)?).is_err(),
            "{key}"
        );
    }
    assert!(Plan::parse(&vec![b' '; (16 << 10) + 1]).is_err());
    assert!(
        serde_json::from_str::<FileBinding>(r#"{"bytes":1,"sha256":"a","path":"../private"}"#)
            .is_err()
    );
    for binding in [
        FileBinding {
            bytes: 0,
            sha256: "0".repeat(64),
        },
        FileBinding {
            bytes: 9,
            sha256: "0".repeat(64),
        },
        FileBinding {
            bytes: 1,
            sha256: "wrong".into(),
        },
    ] {
        assert!(binding.validate(8).is_err());
    }
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture-field access, JSON encoding, or valid later-version parsing errors.
///
/// # Panics
/// Panics if version-specific linked-notice requirements are not enforced.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn later_versions_require_a_linked_notice_binding_and_version_one_rejects_it() -> Result<()> {
    let mut value_plan = plan();
    let object = value_plan.as_object_mut().ok_or("missing plan")?;
    let _previous: Option<Value> = object.insert(
        "linked_target_notices".into(),
        json!({"bytes":1_u32,"sha256":"a".repeat(64)}),
    );
    assert!(Plan::parse(&serde_json::to_vec(&value_plan)?).is_err());
    for version in [2_u32, 3_u32] {
        *value_plan
            .get_mut("format_version")
            .ok_or("missing version")? = json!(version);
        let _plan: Plan = Plan::parse(&serde_json::to_vec(&value_plan)?)?;
        let mut missing = value_plan.clone();
        let _removed: Option<Value> = missing
            .as_object_mut()
            .ok_or("missing plan")?
            .remove("linked_target_notices");
        assert!(Plan::parse(&serde_json::to_vec(&missing)?).is_err());
    }
    *value_plan
        .get_mut("linked_target_notices")
        .ok_or("missing binding")? =
        json!({"bytes":(4_u64 << 20_u32) + 1_u64,"sha256":"a".repeat(64)});
    assert!(Plan::parse(&serde_json::to_vec(&value_plan)?).is_err());
    Ok(())
}

/// # Errors
/// Rejects fixture offset overflow or a field outside the fixture buffer.
fn field(bytes: &mut [u8], start: usize, value: &[u8]) -> Result<()> {
    let end = start.checked_add(value.len()).ok_or("fixture overflow")?;
    bytes
        .get_mut(start..end)
        .ok_or("missing fixture field")?
        .copy_from_slice(value);
    Ok(())
}

/// # Errors
/// Propagates failure to write the synthetic executable header fields.
fn header(target: Target) -> Result<Vec<u8>> {
    let mut bytes = vec![0; 64];
    let fields: Vec<(usize, Vec<u8>)> = match target {
        Target::MacArm | Target::MacX86 => vec![
            (0, 0xfeed_facf_u32.to_le_bytes().to_vec()),
            (
                4,
                if matches!(target, Target::MacArm) {
                    0x0100_000c_u32
                } else {
                    0x0100_0007_u32
                }
                .to_le_bytes()
                .to_vec(),
            ),
            (12, 2_u32.to_le_bytes().to_vec()),
        ],
        Target::LinuxArm | Target::LinuxX86 => vec![
            (0, b"\x7fELF\x02\x01\x01".to_vec()),
            (16, 3_u16.to_le_bytes().to_vec()),
            (
                18,
                if matches!(target, Target::LinuxArm) {
                    183_u16
                } else {
                    62_u16
                }
                .to_le_bytes()
                .to_vec(),
            ),
            (20, 1_u32.to_le_bytes().to_vec()),
            (52, 64_u16.to_le_bytes().to_vec()),
        ],
    };
    for (start, value) in fields {
        field(&mut bytes, start, &value)?;
    }
    Ok(bytes)
}

#[test]
/// # Errors
/// Propagates header construction, valid binary checks, or fixture-prefix access errors.
///
/// # Panics
/// Panics if wrong architectures, truncated headers, or workstation paths are accepted.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn target_header_checks_reject_wrong_architecture_format_and_host_paths() -> Result<()> {
    for target in [
        Target::MacArm,
        Target::MacX86,
        Target::LinuxArm,
        Target::LinuxX86,
    ] {
        let bytes = header(target)?;
        binary::check(target, &bytes)?;
        assert!(binary::check(target, bytes.get(..24).ok_or("missing prefix")?).is_err());
        let different = match target {
            Target::MacArm | Target::LinuxX86 => Target::MacX86,
            Target::MacX86 | Target::LinuxArm => Target::LinuxX86,
        };
        assert!(binary::check(different, &bytes).is_err());
        for marker in [
            b"/Users/synthetic/source.rs".as_slice(),
            b"/home/synthetic/source.rs",
            b"/private/var/folders/synthetic/source.rs",
        ] {
            let mut private = bytes.clone();
            private.extend_from_slice(marker);
            assert!(binary::check(target, &private).is_err());
        }
    }
    Ok(())
}

#[test]
/// # Errors
/// Propagates writes that should fit within the synthetic output limit.
///
/// # Panics
/// Panics if over-limit writes succeed or change the expected output bytes.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn compressed_output_limit_fails_without_exceeding_the_buffer_budget() -> Result<()> {
    let mut output = Output {
        bytes: Vec::new(),
        limit: 8,
    };
    output.write_all(b"1234")?;
    assert!(output.write_all(b"56789").is_err());
    assert_eq!(output.bytes, b"1234");
    output.write_all(b"5678")?;
    assert_eq!(output.bytes, b"12345678");
    assert!(output.write_all(b"9").is_err());
    Ok(())
}

#[test]
/// # Errors
/// Propagates header construction or missing command-count field errors.
fn load_requirements_reject_missing_segments_and_oversized_command_headers() -> Result<()> {
    for target in [
        Target::LinuxArm,
        Target::LinuxX86,
        Target::MacArm,
        Target::MacX86,
    ] {
        let mut bytes = header(target)?;
        let _missing_error: Box<dyn core::error::Error> =
            binary::requirements(target, &bytes).expect_err("input must be rejected");
        if matches!(target, Target::MacArm | Target::MacX86) {
            bytes
                .get_mut(16..20)
                .ok_or("missing command count")?
                .copy_from_slice(&u32::MAX.to_le_bytes());
            let _error: Box<dyn core::error::Error> =
                binary::requirements(target, &bytes).expect_err("input must be rejected");
        }
    }
    Ok(())
}

#[test]
/// # Errors
/// Propagates header construction, field writes, valid metadata parsing, or missing command errors.
///
/// # Panics
/// Panics if the accepted minimum macOS version differs from the fixture.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn deployment_records_reject_other_platforms_and_conflicting_metadata() -> Result<()> {
    let target = Target::MacArm;
    let mut bytes = header(target)?;
    bytes.truncate(32);
    field(&mut bytes, 16, &1_u32.to_le_bytes())?;
    field(&mut bytes, 20, &24_u32.to_le_bytes())?;
    for value in [0x32_u32, 24, 1, 11 << 16_u32, 27 << 16_u32, 0] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    let report = binary::requirements(target, &bytes)?;
    assert_eq!(
        report
            .get("deployment")
            .and_then(|value| value.get("minimum_os"))
            .and_then(Value::as_str),
        Some("11.0.0")
    );
    field(&mut bytes, 40, &2_u32.to_le_bytes())?;
    let _platform_error: Box<dyn core::error::Error> =
        binary::requirements(target, &bytes).expect_err("input must be rejected");
    field(&mut bytes, 40, &1_u32.to_le_bytes())?;
    let duplicate = bytes.get(32..56).ok_or("missing command")?.to_vec();
    bytes.extend_from_slice(&duplicate);
    field(&mut bytes, 16, &2_u32.to_le_bytes())?;
    field(&mut bytes, 20, &48_u32.to_le_bytes())?;
    let _error: Box<dyn core::error::Error> =
        binary::requirements(target, &bytes).expect_err("input must be rejected");
    Ok(())
}

#[test]
/// # Errors
/// Propagates header construction, field writes, or valid metadata parsing errors.
///
/// # Panics
/// Panics if the zero-count fixture reports symbol-version requirements.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn declared_gnu_version_count_requires_corresponding_records() -> Result<()> {
    let target = Target::LinuxArm;
    let mut bytes = header(target)?;
    bytes.resize(208, 0);
    field(&mut bytes, 24, &0x40_0078_u64.to_le_bytes())?;
    field(&mut bytes, 32, &64_u64.to_le_bytes())?;
    field(&mut bytes, 54, &56_u16.to_le_bytes())?;
    field(&mut bytes, 56, &2_u16.to_le_bytes())?;
    for (offset, values) in [
        (64, [0_u64, 0x40_0000, 0x40_0000, 208, 208, 4096]),
        (120, [176_u64, 0x40_00b0, 0x40_00b0, 32, 32, 8]),
    ] {
        field(
            &mut bytes,
            offset,
            &if offset == 64 { 1_u32 } else { 2_u32 }.to_le_bytes(),
        )?;
        field(&mut bytes, offset + 4, &5_u32.to_le_bytes())?;
        for (index, value) in values.into_iter().enumerate() {
            let start = offset + 8 + index * 8;
            field(&mut bytes, start, &value.to_le_bytes())?;
        }
    }
    field(&mut bytes, 176, &0x6fff_ffff_u64.to_le_bytes())?;
    let report = binary::requirements(target, &bytes)?;
    assert_eq!(report.get("symbol_version_requirements"), Some(&json!([])));
    field(&mut bytes, 184, &1_u64.to_le_bytes())?;
    let _error: Box<dyn core::error::Error> =
        binary::requirements(target, &bytes).expect_err("input must be rejected");
    Ok(())
}

/// # Errors
/// Propagates header construction, field writes, or command-length conversion failure.
fn command_fixture(region: &[u8], count: u32) -> Result<Vec<u8>> {
    let mut binary = header(Target::MacArm)?;
    binary.truncate(32);
    field(&mut binary, 16, &count.to_le_bytes())?;
    field(&mut binary, 20, &u32::try_from(region.len())?.to_le_bytes())?;
    binary.extend_from_slice(region);
    Ok(binary)
}

fn command_words(values: &[u32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

#[test]
/// # Errors
/// Propagates fixture construction, valid metadata parsing, or path-field access errors.
///
/// # Panics
/// Panics if the library identity or search path differs from the fixture.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn command_strings_are_local_and_a_library_named_self_is_preserved() -> Result<()> {
    let mut region = command_words(&[0x32, 24, 1, 11 << 16_u32, 27 << 16_u32, 0]);
    region.extend(command_words(&[0xc, 32, 24, 0, 0, 0]));
    region.extend_from_slice(b"self\0\0\0\0");
    let mut rpath = command_words(&[0x8000_001c, 32, 12]);
    rpath.extend_from_slice(b"@loader_path\0\0\0\0\0\0\0\0");
    region.extend_from_slice(&rpath);
    let report = binary::requirements(Target::MacArm, &command_fixture(&region, 3)?)?;
    assert_eq!(report.get("libraries"), Some(&json!(["self"])));
    assert_eq!(report.get("rpaths"), Some(&json!(["@loader_path"])));

    let mut escaped = command_words(&[0x32, 24, 1, 11 << 16_u32, 27 << 16_u32, 0]);
    escaped.extend(command_words(&[0x8000_001c, 16, 16, 0]));
    let mut binary = command_fixture(&escaped, 2)?;
    binary.extend_from_slice(b"outside\0");
    let _error: Box<dyn core::error::Error> =
        binary::requirements(Target::MacArm, &binary).expect_err("input must be rejected");
    escaped.truncate(24);
    rpath.get_mut(12..).ok_or("missing path")?.fill(b'x');
    escaped.extend_from_slice(&rpath);
    let mut unterminated_binary = command_fixture(&escaped, 2)?;
    unterminated_binary.push(0);
    let _unterminated_error: Box<dyn core::error::Error> =
        binary::requirements(Target::MacArm, &unterminated_binary)
            .expect_err("input must be rejected");
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture field writes, size conversion, or valid metadata parsing errors.
fn build_tool_and_segment_section_counts_fit_their_own_commands() -> Result<()> {
    let mut build = command_words(&[0x32, 24, 1, 11 << 16_u32, 27 << 16_u32, 0]);
    let _build_requirements: Value =
        binary::requirements(Target::MacArm, &command_fixture(&build, 1)?)?;
    for count in [1_u32, u32::MAX] {
        field(&mut build, 20, &count.to_le_bytes())?;
        let _error: Box<dyn core::error::Error> =
            binary::requirements(Target::MacArm, &command_fixture(&build, 1)?)
                .expect_err("input must be rejected");
    }
    field(&mut build, 20, &0_u32.to_le_bytes())?;
    for (kind, size, section_offset) in [(0x19_u32, 72_usize, 64_usize), (1, 56, 48)] {
        let mut segment = vec![0; size];
        field(&mut segment, 0, &kind.to_le_bytes())?;
        field(&mut segment, 4, &u32::try_from(size)?.to_le_bytes())?;
        let mut region = build.clone();
        region.extend_from_slice(&segment);
        let _requirements: Value =
            binary::requirements(Target::MacArm, &command_fixture(&region, 2)?)?;
        for count in [1_u32, u32::MAX] {
            field(&mut segment, section_offset, &count.to_le_bytes())?;
            region.truncate(build.len());
            region.extend_from_slice(&segment);
            let _error: Box<dyn core::error::Error> =
                binary::requirements(Target::MacArm, &command_fixture(&region, 2)?)
                    .expect_err("input must be rejected");
        }
    }
    Ok(())
}
