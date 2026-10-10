use super::{Plan, export, fixture, plan, plan_value};
use crate::{Result, checksum};
use alloc::{string::String, vec::Vec};
use serde_json::{Value, json};

/// # Errors
/// Propagates compressed capture fixture construction failures.
fn wrap(entries: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    let writer = flate2::GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(writer);
    for &(path, body) in entries {
        let mut header = tar::Header::new_ustar();
        header.set_size(u64::try_from(body.len())?);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, body)?;
    }
    Ok(builder.into_inner()?.finish()?)
}

/// # Errors
/// Propagates compressed capture plan construction failures.
fn wrapped_plan_value(input: &[u8], compressed: &[u8]) -> Result<Value> {
    let mut value = plan_value(input)?;
    *value.get_mut("format_version").ok_or("missing version")? = json!(2_u32);
    let _old: Option<Value> = value.as_object_mut().ok_or("missing plan object")?.insert(
        "capture_wrapper".into(),
        json!({
            "binding":{"bytes":compressed.len(),"sha256":checksum(compressed)?},
            "member":"capture.tar"
        }),
    );
    Ok(value)
}

#[test]
/// # Errors
/// Fails if compressed capture reading changes the existing exported bytes.
fn compressed_capture_keeps_the_plain_capture_export_byte_identical() -> Result<()> {
    let input = fixture()?;
    let compressed = wrap(&[
        ("capture.tar", &input),
        ("other.txt", b"unselected companion"),
    ])?;
    let value = wrapped_plan_value(&input, &compressed)?;
    let wrapped = Plan::parse(&serde_json::to_vec(&value)?)?;
    let capture = wrapped
        .capture_wrapper
        .as_ref()
        .ok_or("missing capture wrapper")?;
    let unpacked = capture.decode(&compressed, &wrapped.input_archive)?;
    if unpacked != input || export(&wrapped, &unpacked)? != export(&plan(&input)?, &input)? {
        return Err("compressed capture changed plain archive or exported bytes".into());
    }
    Ok(())
}

#[test]
/// # Errors
/// Fails if corrupt gzip footers, truncation or additional data/streams pass.
fn compressed_capture_rejects_corruption_and_extra_streams() -> Result<()> {
    let input = fixture()?;
    let compressed = wrap(&[("capture.tar", &input)])?;
    let value = wrapped_plan_value(&input, &compressed)?;
    let wrapped = Plan::parse(&serde_json::to_vec(&value)?)?;
    let capture = wrapped
        .capture_wrapper
        .as_ref()
        .ok_or("missing capture wrapper")?;
    let mut corrupt = compressed.clone();
    let footer_index = corrupt
        .len()
        .checked_sub(8)
        .ok_or("missing fixture footer")?;
    *corrupt
        .get_mut(footer_index)
        .ok_or("missing fixture checksum")? ^= 1;
    let mut concatenated = compressed.clone();
    concatenated.extend_from_slice(&compressed);
    let mut trailing = compressed.clone();
    trailing.push(1);
    let truncated = compressed
        .get(..compressed.len().saturating_sub(1))
        .ok_or("invalid fixture")?;
    for bad in [
        corrupt.as_slice(),
        concatenated.as_slice(),
        trailing.as_slice(),
        truncated,
    ] {
        if capture.decode(bad, &wrapped.input_archive).is_ok() {
            return Err("corrupt or extended compressed capture accepted".into());
        }
    }
    Ok(())
}

#[test]
/// # Errors
/// Fails if duplicate/missing selected members or changed enclosed bytes pass.
fn compressed_capture_requires_one_exact_selected_archive() -> Result<()> {
    let input = fixture()?;
    let compressed = wrap(&[("capture.tar", &input)])?;
    let wrapped = Plan::parse(&serde_json::to_vec(&wrapped_plan_value(
        &input,
        &compressed,
    )?)?)?;
    let capture = wrapped
        .capture_wrapper
        .as_ref()
        .ok_or("missing capture wrapper")?;
    for entries in [
        vec![
            ("capture.tar", input.as_slice()),
            ("capture.tar", input.as_slice()),
        ],
        vec![("other.tar", input.as_slice())],
        vec![("capture.tar", b"changed archive".as_slice())],
    ] {
        if capture
            .decode(&wrap(&entries)?, &wrapped.input_archive)
            .is_ok()
        {
            return Err("ambiguous or changed selected capture accepted".into());
        }
    }
    Ok(())
}

#[test]
/// # Errors
/// Fails if wrapper fields are incompatible with the plan version or unsafe.
fn compressed_capture_plan_rejects_wrong_version_path_or_binding() -> Result<()> {
    let input = fixture()?;
    let compressed = wrap(&[("capture.tar", &input)])?;
    for (key, value) in [
        ("format_version", json!(1_u32)),
        ("capture_wrapper", json!(null)),
        (
            "capture_wrapper",
            json!({"binding":{"bytes":0_u32,"sha256":"b".repeat(64)},"member":"capture.tar"}),
        ),
        (
            "capture_wrapper",
            json!({"binding":{"bytes":1_u32,"sha256":"b".repeat(64)},"member":"../capture.tar"}),
        ),
        (
            "capture_wrapper",
            json!({"binding":{"bytes":1_u32,"sha256":"b".repeat(64)},"member":"capture.tar","extra":true}),
        ),
    ] {
        let mut plan_value = wrapped_plan_value(&input, &compressed)?;
        let _old: Option<Value> = plan_value
            .as_object_mut()
            .ok_or("missing plan object")?
            .insert(key.into(), value);
        if Plan::parse(&serde_json::to_vec(&plan_value)?).is_ok() {
            return Err("invalid compressed capture plan accepted".into());
        }
    }
    Ok(())
}

#[test]
/// # Errors
/// Fails if the exact wrapper entry-count boundary is rejected or excess passes.
fn wrapper_entry_count_has_an_exact_boundary() -> Result<()> {
    let input = fixture()?;
    let names: Vec<String> = (0_usize..63_usize)
        .map(|index| format!("companion-{index}"))
        .collect();
    let mut entries: Vec<(&str, &[u8])> = core::iter::once(("capture.tar", input.as_slice()))
        .chain(names.iter().map(|name| (name.as_str(), b"".as_slice())))
        .collect();
    let compressed = wrap(&entries)?;
    let wrapped = Plan::parse(&serde_json::to_vec(&wrapped_plan_value(
        &input,
        &compressed,
    )?)?)?;
    let capture = wrapped.capture_wrapper.as_ref().ok_or("missing wrapper")?;
    if capture.decode(&compressed, &wrapped.input_archive)? != input {
        return Err("wrapper rejected exact entry-count boundary".into());
    }
    entries.push(("one-too-many", b""));
    let failure = capture
        .decode(&wrap(&entries)?, &wrapped.input_archive)
        .err()
        .ok_or("excess wrapper entries accepted")?;
    if !failure.to_string().contains("entry count exceeds limit") {
        return Err("entry-count failure did not exercise the budget".into());
    }
    Ok(())
}

#[test]
/// # Errors
/// Fails if valid gzip can conceal missing, unaligned or nonzero tar end data.
fn wrapper_requires_complete_zero_tar_end_records() -> Result<()> {
    let input = fixture()?;
    let compressed = wrap(&[("capture.tar", &input)])?;
    let wrapped = Plan::parse(&serde_json::to_vec(&wrapped_plan_value(
        &input,
        &compressed,
    )?)?)?;
    let capture = wrapped.capture_wrapper.as_ref().ok_or("missing wrapper")?;
    let raw = crate::bounded(flate2::read::GzDecoder::new(compressed.as_slice()), 1 << 20)?;
    let end = input
        .len()
        .div_ceil(512)
        .checked_mul(512)
        .and_then(|size| size.checked_add(512))
        .ok_or("fixture size overflow")?;
    let missing = raw.get(..end).ok_or("missing fixture body")?.to_vec();
    let mut unaligned = raw.clone();
    unaligned.push(0);
    let mut nonzero = raw;
    nonzero.push(1);
    for body in [missing, unaligned, nonzero] {
        let mut encoder =
            flate2::GzBuilder::new().write(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &body)?;
        let failure = capture
            .decode(&encoder.finish()?, &wrapped.input_archive)
            .err()
            .ok_or("malformed tar end accepted")?;
        if !failure.to_string().contains("tar end data") {
            return Err("tar end fixture did not exercise framing validation".into());
        }
    }
    Ok(())
}

#[test]
/// # Errors
/// Fails if nonregular raw entries or excessive declared member sizes pass.
fn wrapper_rejects_special_members_and_size_overruns_before_reading() -> Result<()> {
    let input = fixture()?;
    let compressed = wrap(&[("capture.tar", &input)])?;
    let wrapped = Plan::parse(&serde_json::to_vec(&wrapped_plan_value(
        &input,
        &compressed,
    )?)?)?;
    let capture = wrapped.capture_wrapper.as_ref().ok_or("missing wrapper")?;
    for (kind, size, expected) in [
        (tar::EntryType::Symlink, 0_u64, "nonregular member"),
        (
            tar::EntryType::Regular,
            (64_u64 << 20_u32).saturating_add(1),
            "payload or path budget",
        ),
    ] {
        let mut header = tar::Header::new_ustar();
        header.set_path("capture.tar")?;
        header.set_entry_type(kind);
        header.set_size(size);
        header.set_mode(0o644);
        header.set_cksum();
        let mut raw = header.as_bytes().to_vec();
        raw.extend_from_slice(&[0_u8; 1024]);
        let mut encoder =
            flate2::GzBuilder::new().write(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &raw)?;
        let failure = capture
            .decode(&encoder.finish()?, &wrapped.input_archive)
            .err()
            .ok_or("invalid raw wrapper member accepted")?;
        if !failure.to_string().contains(expected) {
            return Err("raw wrapper test did not exercise its expected rejection".into());
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
/// # Errors
/// Fails if changed compressed input replaces a successful prior export.
fn wrapper_command_preserves_previous_output_after_changed_input() -> Result<()> {
    let directory = crate::test_directory::directory("wrapper")?;
    let input = fixture()?;
    let compressed = wrap(&[("capture.tar", &input)])?;
    let plan_path = directory.path().join("plan.json");
    let capture_path = directory.path().join("capture.tar.gz");
    let output_path = directory.path().join("output.tar.gz");
    std::fs::write(
        &plan_path,
        serde_json::to_vec(&wrapped_plan_value(&input, &compressed)?)?,
    )?;
    std::fs::write(&capture_path, compressed)?;
    let arguments = || {
        [&plan_path, &capture_path, &output_path]
            .into_iter()
            .map(|path| path.as_os_str().to_owned())
    };
    crate::relink::run(arguments())?;
    let prior = crate::input::read(&output_path, super::super::ARCHIVE_BYTES)?;
    std::fs::write(&capture_path, b"changed compressed capture")?;
    if crate::relink::run(arguments()).is_ok()
        || crate::input::read(&output_path, super::super::ARCHIVE_BYTES)? != prior
        || std::fs::read_dir(directory.path())?.count() != 3
    {
        return Err("changed wrapper replaced output or left staging".into());
    }
    Ok(())
}
