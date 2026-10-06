use std::{fs, io};

use flate2::{Compression, read::MultiGzDecoder, write::GzEncoder};
use serde_json::{Value, json};

use super::{NOTICE, Result, SOURCE, Scenario, archive_scenario, digest, write_json};

/// # Errors
/// Propagates source sizing, archive reading, encoding or entry writes.
fn expanded_archive(previous: &[u8], extra_byte: bool) -> Result<Vec<u8>> {
    let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
    let mut previous_archive = tar::Archive::new(MultiGzDecoder::new(previous));
    for entry in previous_archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let mut header = entry.header().clone();
        builder.append_data(&mut header, path, &mut entry)?;
    }
    for index in 0_usize..16_usize {
        let bytes = source_bytes(index, extra_byte)?;
        let mut header = tar::Header::new_gnu();
        header.set_size(u64::try_from(bytes.len())?);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        builder.append_data(
            &mut header,
            format!("example-1.0.0/src/budget-{index}.rs"),
            bytes.as_slice(),
        )?;
    }
    Ok(builder.into_inner()?.finish()?)
}

/// # Errors
/// Propagates fixture-size overflow.
fn source_bytes(index: usize, extra_byte: bool) -> Result<Vec<u8>> {
    let original_bytes = SOURCE.len().checked_mul(2).ok_or("fixture size overflow")?;
    let length = (1_usize << 20_u32)
        .checked_sub(if index == 15 { original_bytes } else { 0 })
        .and_then(|length| length.checked_add(usize::from(index == 15 && extra_byte)))
        .ok_or("fixture size overflow")?;
    let mut source = NOTICE.to_vec();
    source.resize(length, b' ');
    Ok(source)
}

/// # Errors
/// Propagates checksum, fixture writes or missing manifest fields.
fn bind_archive(scenario: &mut Scenario, archive: &[u8], extra_byte: bool) -> Result<()> {
    let root = &scenario.fixture.root;
    let archive_digest = digest(archive)?;
    fs::write(root.join("cache/example-1.0.0.crate"), archive)?;
    fs::write(
        root.join("Cargo.lock"),
        format!(
            "version=4\n[[package]]\nname='example'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{archive_digest}'\n"
        ),
    )?;
    let notices = scenario
        .manifest
        .get_mut("notices")
        .and_then(Value::as_array_mut)
        .ok_or("missing notices")?;
    notices.truncate(3);
    let template = notices.first().ok_or("missing source reference")?.clone();
    for index in 0_usize..16_usize {
        let mut notice = template.clone();
        let path = format!("src/budget-{index}.rs");
        let source = source_bytes(index, extra_byte)?;
        *notice.get_mut("upstream_path").ok_or("missing path")? =
            json!(format!("crates/example/{path}"));
        *notice.get_mut("source_prefix").ok_or("missing prefix")? = json!({
            "archive_path":path,"bytes":source.len(),
            "sha256":digest(&source)?,
            "source_url_kind":"published_archive"
        });
        notices.push(notice);
    }
    for notice in notices {
        *notice
            .get_mut("published_package_sha256")
            .ok_or("missing archive binding")? = json!(archive_digest);
    }
    write_json(&root.join("sources.json"), &scenario.manifest)?;
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture setup, archive generation, output reads or command failure.
///
/// # Panics
/// Panics if aggregate overflow succeeds or changes the last valid inventory.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-06, revisit 2026-11-06"
)]
fn accepts_complete_source_budget_and_preserves_output_on_overflow() -> Result<()> {
    let mut scenario = archive_scenario()?;
    let original = fs::read(scenario.fixture.root.join("cache/example-1.0.0.crate"))?;
    let exact = expanded_archive(&original, false)?;
    bind_archive(&mut scenario, &exact, false)?;
    let accepted = scenario.fixture.run()?;
    if !accepted.status.success() {
        return Err(io::Error::other(String::from_utf8_lossy(&accepted.stderr)).into());
    }
    let previous = fs::read(scenario.fixture.root.join("output.json"))?;
    assert!(scenario.fixture.run()?.status.success());
    assert_eq!(
        fs::read(scenario.fixture.root.join("output.json"))?,
        previous
    );
    let overflow = expanded_archive(&original, true)?;
    bind_archive(&mut scenario, &overflow, true)?;
    let rejected = scenario.fixture.run()?;
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("source notice budget exceeded"));
    assert_eq!(
        fs::read(scenario.fixture.root.join("output.json"))?,
        previous
    );
    Ok(())
}
