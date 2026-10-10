use alloc::{string::String, vec::Vec};

use flate2::read::GzDecoder;
use serde_json::{Value, json};

use super::{Plan, collect, export, paths, response};
use crate::{Result, checksum};

mod wrapper;

const RESPONSE: &str = "--chroot . -m aarch64linux -dynamic-linker /lib/ld-linux-aarch64.so.1 -o program private-build/input.o -L private-build/search -z relro --why-extract=extractions.tsv";
const VERSION: &str =
    "LLD 23.1.3 (https://github.com/llvm/llvm-project 0d261d1ca552c95a8f007e061c787ac7132fbcbc)\n";

/// # Errors
/// Propagates fixture archive construction errors.
fn archive(entries: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    for &(path, body) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(u64::try_from(body.len())?);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, format!("capture/{path}"), body)?;
    }
    Ok(builder.into_inner()?)
}

/// # Errors
/// Propagates fixture archive construction errors.
fn fixture() -> Result<Vec<u8>> {
    archive(&[
        ("response.txt", RESPONSE.as_bytes()),
        ("version.txt", VERSION.as_bytes()),
        ("private-build/input.o", b"unchanged object bytes"),
    ])
}

/// # Errors
/// Propagates checksum generation errors.
fn plan_value(bytes: &[u8]) -> Result<Value> {
    Ok(json!({
        "format_version": 1_u32, "package_version": "0.1.0", "build_identity": "development",
        "source_revision": "a".repeat(40), "rust_release": "1.99.0", "target": "aarch64-unknown-linux-gnu",
        "input_archive": {"bytes":bytes.len(),"sha256":checksum(bytes)?},
        "reference_binary": {"bytes":1_u32,"sha256":"b".repeat(64)},
        "linker":{"version":"23.1.3","source_commit":"0d261d1ca552c95a8f007e061c787ac7132fbcbc"},
        "archive_root":"capture", "path_maps":[{"from":"private-build","to":"application"}],
        "private_path_markers":["private-build"]
    }))
}

/// # Errors
/// Propagates fixture plan encoding and validation errors.
fn plan(bytes: &[u8]) -> Result<Plan> {
    Plan::parse(&serde_json::to_vec(&plan_value(bytes)?)?)
}

#[test]
/// # Errors
/// Fails if GNU token concatenation, escapes or malformed syntax are mishandled.
fn gnu_response_preserves_quoted_and_escaped_arguments() -> Result<()> {
    let actual = response::tokenize(
        "'two words' a\"b c\"d empty\"\" '' escaped\\ space \"a\\\"b\" 'c\\\'d'\r\n",
    )?;
    if actual
        != [
            "two words",
            "ab cd",
            "empty",
            "",
            "escaped space",
            "a\"b",
            "c'd",
        ]
    {
        return Err("GNU response argument semantics changed".into());
    }
    for text in ["unterminated'", "trailing\\", "embedded\0nul", "\\\0"] {
        if response::tokenize(text).is_ok() {
            return Err("malformed GNU response accepted".into());
        }
    }
    Ok(())
}

#[test]
/// # Errors
/// Fails if export is nondeterministic, changes object bytes, leaks selected
/// markers, changes the runtime interpreter or claims external proof.
fn relocated_archive_preserves_inputs_and_records_external_requirements() -> Result<()> {
    let input = fixture()?;
    let plan = plan(&input)?;
    let output = export(&plan, &input)?;
    if output != export(&plan, &input)? {
        return Err("relink export is nondeterministic".into());
    }
    let files = collect(
        &crate::bounded(GzDecoder::new(output.as_slice()), super::ARCHIVE_BYTES)?,
        "relink",
    )?;
    if files.len() != 4
        || files.get("application/input.o").map(Vec::as_slice) != Some(b"unchanged object bytes")
        || files
            .values()
            .any(|body| paths::check_markers(body, &plan.private_path_markers).is_err())
    {
        return Err("relink export changed input bytes or retained selected markers".into());
    }
    let arguments = response::tokenize(core::str::from_utf8(
        files.get("response.txt").ok_or("missing response")?,
    )?)?;
    let expected = response::tokenize(&RESPONSE.replace("private-build", "application"))?;
    if arguments != expected {
        return Err("relink arguments or runtime interpreter changed".into());
    }
    let manifest: Value =
        serde_json::from_slice(files.get("MANIFEST.json").ok_or("missing manifest")?)?;
    for key in [
        "unchanged_executable_reproduction",
        "complete_corresponding_source",
        "source_modification_and_relink",
        "complete_permissions_and_release",
    ] {
        if manifest.get(key).and_then(Value::as_str) != Some("external_required") {
            return Err("export claimed unexecuted recipient or release proof".into());
        }
    }
    Ok(())
}

#[test]
/// # Errors
/// Fails if unsafe, duplicate, unsupported or incomplete arguments are accepted.
fn response_rejects_hidden_inputs_outputs_and_unsupported_options() -> Result<()> {
    let input = fixture()?;
    let plan = plan(&input)?;
    let files = collect(&input, "capture")?;
    for text in [
        RESPONSE.replace("private-build/input.o", "@nested.txt"),
        RESPONSE.replace("private-build/input.o", "missing.o"),
        RESPONSE.replace("-o program", "-o ../program"),
        RESPONSE.replace("-o program", "-o application/input.o"),
        RESPONSE.replace("-o program", "-o response.txt"),
        RESPONSE.replace("-o program", "-o MANIFEST.json/child"),
        RESPONSE.replace("--chroot .", "--chroot /"),
        RESPONSE.replace("--chroot .", ""),
        RESPONSE.replace("aarch64linux", "elf_x86_64"),
        RESPONSE.replace("/lib/ld-linux-aarch64.so.1", "/private/loader"),
        format!("{RESPONSE} --plugin plugin.so"),
        format!("{RESPONSE} -o duplicate"),
        format!("{RESPONSE} --Map extractions.tsv"),
        format!("{RESPONSE} --dependency-file extractions.tsv/child"),
    ] {
        if response::rewrite(
            &text,
            &files,
            &mut paths::Remapper::new(&plan.path_maps),
            &plan.target,
        )
        .is_ok()
        {
            return Err("unsafe or unsupported response was accepted".into());
        }
    }
    Ok(())
}

#[test]
/// # Errors
/// Fails if invalid identity, bindings, map prefixes or markers are accepted.
fn plan_rejects_unknown_identity_overlapping_maps_and_invalid_markers() -> Result<()> {
    let input = fixture()?;
    for (key, replacement) in [
        ("extra", json!(true)),
        ("source_revision", json!("uncommitted")),
        ("target", json!("aarch64-apple-darwin")),
        ("archive_root", json!("capture/child")),
        ("private_path_markers", json!([])),
        ("private_path_markers", json!([""])),
        (
            "input_archive",
            json!({"bytes":0_u32,"sha256":"b".repeat(64)}),
        ),
        (
            "path_maps",
            json!([{"from":"private-build","to":"application"},{"from":"private-build/child","to":"child"}]),
        ),
        (
            "path_maps",
            json!([{"from":"private-build","to":"../application"}]),
        ),
    ] {
        let mut value = plan_value(&input)?;
        let _old: Option<Value> = value
            .as_object_mut()
            .ok_or("missing plan object")?
            .insert(key.into(), replacement);
        if Plan::parse(&serde_json::to_vec(&value)?).is_ok() {
            return Err("invalid relink plan was accepted".into());
        }
    }
    let duplicated = String::from_utf8(serde_json::to_vec(&plan_value(&input)?)?)?.replace(
        "\"format_version\":1",
        "\"format_version\":1,\"format_version\":1",
    );
    if Plan::parse(duplicated.as_bytes()).is_ok() {
        return Err("duplicate plan field was accepted".into());
    }
    Ok(())
}

#[test]
/// # Errors
/// Fails if marker-bearing bodies, unused maps or destination collisions pass.
fn export_rejects_residual_markers_unused_maps_and_path_collisions() -> Result<()> {
    let input = fixture()?;
    for entries in [
        vec![
            ("response.txt", RESPONSE.as_bytes()),
            ("version.txt", VERSION.as_bytes()),
            ("private-build/input.o", b"private-build".as_slice()),
        ],
        vec![
            ("response.txt", RESPONSE.as_bytes()),
            ("version.txt", VERSION.as_bytes()),
            ("private-build/input.o", b"object".as_slice()),
            ("application/input.o", b"other".as_slice()),
        ],
        vec![
            ("response.txt", RESPONSE.as_bytes()),
            ("version.txt", VERSION.as_bytes()),
            ("private-build/input.o", b"object".as_slice()),
            ("application", b"file".as_slice()),
        ],
    ] {
        let bytes = archive(&entries)?;
        if export(&plan(&bytes)?, &bytes).is_ok() {
            return Err("unsafe exported material accepted".into());
        }
    }
    let mut unused = plan_value(&input)?;
    *unused.get_mut("path_maps").ok_or("missing mappings")? =
        json!([{"from":"absent","to":"recipient"}]);
    *unused
        .get_mut("private_path_markers")
        .ok_or("missing markers")? = json!(["unrelated"]);
    if export(&Plan::parse(&serde_json::to_vec(&unused)?)?, &input).is_ok() {
        return Err("unused mapping accepted".into());
    }
    Ok(())
}

#[test]
/// # Errors
/// Fails if duplicates, wrong roots, unsafe paths, links or trailing data pass.
fn tar_rejects_ambiguous_and_nonregular_material() -> Result<()> {
    let duplicate = archive(&[("a", b"1"), ("a", b"2"), ("b", b"3")])?;
    if collect(&duplicate, "capture").is_ok() || collect(&fixture()?, "other").is_ok() {
        return Err("ambiguous tar accepted".into());
    }
    let mut tail = fixture()?;
    tail.extend_from_slice(b"hidden trailing data");
    if collect(&tail, "capture").is_ok() {
        return Err("nonzero trailing tar data accepted".into());
    }
    for (path, kind) in [
        ("../escape", tar::EntryType::Regular),
        ("capture/link", tar::EntryType::Symlink),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_entry_type(kind);
        let field = header
            .as_mut_bytes()
            .get_mut(..100)
            .ok_or("missing tar name")?;
        field.fill(0);
        field
            .get_mut(..path.len())
            .ok_or("tar name too long")?
            .copy_from_slice(path.as_bytes());
        header.set_cksum();
        let mut builder = tar::Builder::new(Vec::new());
        builder.append(
            &header,
            core::iter::empty::<u8>().collect::<Vec<_>>().as_slice(),
        )?;
        if collect(&builder.into_inner()?, "capture").is_ok() {
            return Err("unsafe tar entry accepted".into());
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
/// # Errors
/// Fails if changed input replaces prior output, an input alias passes or
/// failed publication leaves staging files behind.
fn command_preserves_previous_output_and_rejects_input_aliases() -> Result<()> {
    let directory = crate::test_directory::directory("relink")?;
    let plan_path = directory.path().join("plan.json");
    let archive_path = directory.path().join("capture.tar");
    let output_path = directory.path().join("output.tar.gz");
    let input = fixture()?;
    std::fs::write(&plan_path, serde_json::to_vec(&plan_value(&input)?)?)?;
    std::fs::write(&archive_path, &input)?;
    super::run(
        [&plan_path, &archive_path, &output_path]
            .into_iter()
            .map(|path| path.as_os_str().to_owned()),
    )?;
    let prior = crate::input::read(&output_path, super::ARCHIVE_BYTES)?;
    std::fs::write(&archive_path, b"changed capture")?;
    if super::run(
        [&plan_path, &archive_path, &output_path]
            .into_iter()
            .map(|path| path.as_os_str().to_owned()),
    )
    .is_ok()
        || crate::input::read(&output_path, super::ARCHIVE_BYTES)? != prior
    {
        return Err("changed input replaced previous output".into());
    }
    std::fs::hard_link(&plan_path, directory.path().join("alias"))?;
    for output in [&plan_path, &directory.path().join("alias")] {
        if super::guard_output(output, &[&plan_path, &archive_path]).is_ok() {
            return Err("input alias accepted".into());
        }
    }
    if std::fs::read_dir(directory.path())?.count() != 4 {
        return Err("failed export left staging files".into());
    }
    Ok(())
}
