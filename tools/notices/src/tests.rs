use std::{collections::BTreeMap, io::Write as _, path::Path};

use flate2::{Compression, write::GzEncoder};
use serde_json::{Value, json};

use crate::{
    Result, Texts,
    archive::{self, Limits},
    checksum, error, identity, inventory, relative_path, supplement,
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
/// # Errors
/// Propagates clock, fixture setup, file reads/writes, symlink creation, or byte-count conversion errors.
///
/// # Panics
/// Panics if valid reads differ or the source bytes change after rejected inputs.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn regular_notice_input_rejects_links_directories_and_size_overruns() -> Result<()> {
    struct Directory(std::path::PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _cleanup: std::io::Result<()> = std::fs::remove_dir_all(&self.0);
        }
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "logbrew-notice-input-{}-{nanos}",
        std::process::id()
    ));
    std::fs::DirBuilder::new().create(&path)?;
    let directory = Directory(path);
    let file = directory.0.join("source");
    let bytes = b"complete source";
    std::fs::write(&file, bytes)?;
    assert_eq!(
        crate::input::read(&file, u64::try_from(bytes.len())?)?,
        bytes
    );
    let _budget_error: Box<dyn std::error::Error> =
        crate::input::read(&file, 1).expect_err("input must be rejected");
    let _directory_error: Box<dyn std::error::Error> =
        crate::input::read(&directory.0, 1024).expect_err("input must be rejected");
    let link = directory.0.join("link");
    std::os::unix::fs::symlink(&file, &link)?;
    let _error: Box<dyn std::error::Error> =
        crate::input::read(&link, 1024).expect_err("input must be rejected");
    assert_eq!(std::fs::read(&file)?, bytes);
    Ok(())
}

const MANIFEST: &[u8] = b"[package]\nname='example'\nversion='1.0.0'\nlicense='MIT'\nrepository='https://github.com/example/project'\n";

fn package() -> Value {
    json!({"name":"example","version":"1.0.0","license":"MIT","repository":"https://github.com/example/project"})
}

/// # Errors
/// Propagates gzip writes or encoder finalization errors.
fn gzip(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}

/// # Errors
/// Propagates size conversion, fixture-path bounds, tar writes, or gzip encoding errors.
fn fixture(entries: &[(&str, &[u8], tar::EntryType)]) -> Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, bytes, kind) in std::iter::once((
        "example-1.0.0/Cargo.toml",
        MANIFEST,
        tar::EntryType::Regular,
    ))
    .chain(entries.iter().copied())
    {
        let mut header = tar::Header::new_gnu();
        header.set_size(u64::try_from(bytes.len())?);
        header.set_entry_type(kind);
        header.set_mode(0o644);
        header.set_mtime(0);
        // Raw header bytes permit invalid paths for rejection tests.
        header
            .as_mut_bytes()
            .get_mut(..path.len())
            .ok_or_else(|| error("fixture path too long"))?
            .copy_from_slice(path.as_bytes());
        header.set_cksum();
        builder.append(&header, bytes)?;
    }
    gzip(&builder.into_inner()?)
}

#[test]
/// # Errors
/// Propagates fixture encoding, archive verification, checksums, or fixture-prefix errors.
///
/// # Panics
/// Panics if the collected notice count or verbatim text differs from the fixture.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn preserves_nested_notices_and_attribution_verbatim() -> Result<()> {
    let entries = [
        (
            "example-1.0.0/LICENSE",
            b"license text\r\n".as_slice(),
            tar::EntryType::Regular,
        ),
        (
            "example-1.0.0/third-party/COPYING",
            b"nested license\n".as_slice(),
            tar::EntryType::Regular,
        ),
        (
            "example-1.0.0/NOTICE.txt",
            b"notice\n".as_slice(),
            tar::EntryType::Regular,
        ),
        (
            "example-1.0.0/COPYRIGHT",
            b"copyright\n".as_slice(),
            tar::EntryType::Regular,
        ),
        (
            "example-1.0.0/AUTHORS",
            b"author and license\n".as_slice(),
            tar::EntryType::Regular,
        ),
        (
            "example-1.0.0/license_parser.rs",
            b"source code\n".as_slice(),
            tar::EntryType::Regular,
        ),
    ];
    let bytes = fixture(&entries)?;
    let collected = archive::collect(&package(), &bytes, &checksum(&bytes)?, Limits::default())?;
    assert_eq!(collected.notices.len(), 5);
    for (path, text, _) in entries.iter().take(5) {
        let relative = path
            .strip_prefix("example-1.0.0/")
            .ok_or_else(|| error("fixture prefix"))?;
        assert_eq!(
            collected.notices.get(relative).map(String::as_bytes),
            Some(*text)
        );
    }
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture encoding, checksum formatting, or missing gzip-footer errors.
///
/// # Panics
/// Panics if checksum, footer, or truncation corruption is accepted.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn rejects_checksum_gzip_footer_and_truncation_corruption() -> Result<()> {
    let bytes = fixture(&[])?;
    assert!(archive::collect(&package(), &bytes, &"0".repeat(64), Limits::default()).is_err());
    let mut footer_corrupt = bytes.clone();
    let index = footer_corrupt
        .len()
        .checked_sub(8)
        .ok_or_else(|| error("missing gzip footer"))?;
    let byte = footer_corrupt
        .get_mut(index)
        .ok_or_else(|| error("missing gzip checksum"))?;
    *byte ^= 1;
    assert!(
        archive::collect(
            &package(),
            &footer_corrupt,
            &checksum(&footer_corrupt)?,
            Limits::default()
        )
        .is_err()
    );
    let mut truncated = bytes;
    let _removed: Option<u8> = truncated.pop();
    assert!(
        archive::collect(
            &package(),
            &truncated,
            &checksum(&truncated)?,
            Limits::default()
        )
        .is_err()
    );
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture encoding, checksum formatting, valid collection, or footer-field errors.
///
/// # Panics
/// Panics if post-tar expansion limits or corrupt trailing gzip members are accepted.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn validates_members_and_expansion_after_tar_end_marker() -> Result<()> {
    let mut bytes = fixture(&[])?;
    let trailing = gzip(&vec![0; 8192])?;
    bytes.extend_from_slice(&trailing);
    let _collected: archive::Collected =
        archive::collect(&package(), &bytes, &checksum(&bytes)?, Limits::default())?;
    let limits = Limits {
        expanded_bytes: 4096,
        ..Limits::default()
    };
    assert!(archive::collect(&package(), &bytes, &checksum(&bytes)?, limits).is_err());
    let index = bytes
        .len()
        .checked_sub(8)
        .ok_or_else(|| error("missing second footer"))?;
    *bytes
        .get_mut(index)
        .ok_or_else(|| error("missing second checksum"))? ^= 1;
    assert!(archive::collect(&package(), &bytes, &checksum(&bytes)?, Limits::default()).is_err());
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture encoding or checksum formatting errors.
///
/// # Panics
/// Panics if unsafe paths, links, special files, or duplicate archive paths are accepted.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn rejects_unsafe_paths_links_special_files_and_duplicate_paths() -> Result<()> {
    for (path, kind) in [
        ("example-1.0.0/../LICENSE", tar::EntryType::Regular),
        ("/example-1.0.0/LICENSE", tar::EntryType::Regular),
        ("other-1.0.0/LICENSE", tar::EntryType::Regular),
        ("example-1.0.0/./LICENSE", tar::EntryType::Regular),
        ("example-1.0.0/LICENSE", tar::EntryType::Symlink),
        ("example-1.0.0/LICENSE", tar::EntryType::Link),
        ("example-1.0.0/LICENSE", tar::EntryType::Fifo),
    ] {
        let bytes = fixture(&[(path, b"", kind)])?;
        assert!(
            archive::collect(&package(), &bytes, &checksum(&bytes)?, Limits::default()).is_err(),
            "{path} {kind:?}"
        );
    }
    let bytes = fixture(&[
        ("example-1.0.0/LICENSE", b"one", tar::EntryType::Regular),
        ("example-1.0.0/LICENSE", b"two", tar::EntryType::Regular),
    ])?;
    assert!(archive::collect(&package(), &bytes, &checksum(&bytes)?, Limits::default()).is_err());
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture encoding, missing metadata fields, or checksum formatting errors.
///
/// # Panics
/// Panics if metadata disagreement or entry/path/notice budgets are not enforced.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn rejects_mismatched_manifest_and_notice_or_entry_budget_overruns() -> Result<()> {
    let bytes = fixture(&[("example-1.0.0/LICENSE", b"notice", tar::EntryType::Regular)])?;
    for key in ["name", "version", "license", "repository"] {
        let mut metadata = package();
        *metadata
            .get_mut(key)
            .ok_or_else(|| error("missing fixture field"))? = Value::String("different".to_owned());
        assert!(
            archive::collect(&metadata, &bytes, &checksum(&bytes)?, Limits::default()).is_err()
        );
    }
    for limits in [
        Limits {
            entries: 1,
            ..Limits::default()
        },
        Limits {
            path_bytes: 1,
            ..Limits::default()
        },
        Limits {
            notice_bytes: 5,
            ..Limits::default()
        },
        Limits {
            total_notice_bytes: 5,
            ..Limits::default()
        },
    ] {
        assert!(archive::collect(&package(), &bytes, &checksum(&bytes)?, limits).is_err());
    }
    for notice in [b"\n ".as_slice(), b"\xff".as_slice()] {
        let invalid_notice =
            fixture(&[("example-1.0.0/LICENSE", notice, tar::EntryType::Regular)])?;
        assert!(
            archive::collect(
                &package(),
                &invalid_notice,
                &checksum(&invalid_notice)?,
                Limits::default()
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
/// # Errors
/// Propagates synthetic supplement JSON encoding failure.
///
/// # Panics
/// Panics if duplicate, unknown, invalid-version, or unused supplement records are accepted.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn rejects_duplicate_unknown_and_unused_supplement_records() -> Result<()> {
    for bytes in [
        b"{\"format_version\":1,\"format_version\":1,\"notices\":[]}".as_slice(),
        b"{\"format_version\":1,\"notices\":[],\"extra\":true}".as_slice(),
        b"{\"format_version\":2,\"notices\":[]}".as_slice(),
    ] {
        assert!(
            supplement::apply(
                &mut BTreeMap::new(),
                &mut Texts::default(),
                bytes,
                Path::new("."),
                Path::new(".")
            )
            .is_err()
        );
    }
    let bytes = serde_json::to_vec(
        &json!({"format_version":1_u32,"notices":[{"package":"example","version":"1.0.0",
        "published_package_sha256":"0".repeat(64),"source_commit":"0".repeat(40),"source_url":"https://example.invalid/LICENSE",
        "upstream_path":"LICENSE","file":"example.txt","sha256":"0".repeat(64)}]}),
    )?;
    assert!(
        supplement::apply(
            &mut BTreeMap::new(),
            &mut Texts::default(),
            &bytes,
            Path::new("."),
            Path::new(".")
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn rejects_lockfile_identity_source_and_coverage_mismatches_before_reads() {
    let metadata = json!({"packages":[{"name":"example","version":"1.0.0","source":"registry+https://github.com/rust-lang/crates.io-index"}]});
    for lock in [
        "[[package]]\nname='example'\nversion='1.0.0'\nsource='registry+https://example.invalid'\n",
        "[[package]]\nname='other'\nversion='1.0.0'\n",
        "[[package]]\nname='example'\nversion='1.0.0'\n[[package]]\nname='example'\nversion='1.0.0'\n",
        "package=[]\n",
    ] {
        let _error: Box<dyn std::error::Error> = inventory(
            &metadata,
            lock.as_bytes(),
            Path::new("."),
            &mut Texts::default(),
        )
        .expect_err("invalid lockfile must be rejected");
    }
    for name in ["../example", "", "example/example", "example\\example"] {
        let _error: Box<dyn std::error::Error> =
            identity(&json!({"name":name,"version":"1.0.0"})).expect_err("input must be rejected");
    }
    for path in [
        "../LICENSE",
        "LICENSE/../secret",
        "/LICENSE",
        "./LICENSE",
        "LICENSE\\secret",
    ] {
        let _error: Box<dyn std::error::Error> =
            relative_path(path).expect_err("input must be rejected");
    }
}

#[test]
/// # Errors
/// Propagates archive encoding, checksums, or valid source collection errors.
///
/// # Panics
/// Panics if a changed source, missing selection, or exceeded budget is accepted.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-06, revisit 2026-11-06"
)]
fn source_prefix_checks_the_complete_file() -> Result<()> {
    let source = b"// synthetic notice\nfn original() {}\n";
    let bytes = fixture(&[("example-1.0.0/src/lib.rs", source, tar::EntryType::Regular)])?;
    let selected = BTreeMap::from([(
        "src/lib.rs".to_owned(),
        archive::Prefix {
            bytes: u64::try_from(source.len())?,
            sha256: checksum(source)?,
            text: b"// synthetic notice\n".to_vec(),
        },
    )]);
    let _collected: archive::Collected = archive::collect_with_prefixes(
        &package(),
        &bytes,
        &checksum(&bytes)?,
        Limits::default(),
        &selected,
    )?;
    let changed = fixture(&[(
        "example-1.0.0/src/lib.rs",
        b"// synthetic notice\nfn modified() {}\n",
        tar::EntryType::Regular,
    )])?;
    assert!(
        archive::collect_with_prefixes(
            &package(),
            &changed,
            &checksum(&changed)?,
            Limits::default(),
            &selected,
        )
        .is_err()
    );
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture encoding, checksum or byte conversion errors.
///
/// # Panics
/// Panics if missing, unsafe or inconsistent source selections are accepted.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-06, revisit 2026-11-06"
)]
fn source_prefix_rejects_invalid_selections() -> Result<()> {
    let source = b"// synthetic notice\nfn original() {}\n";
    let bytes = fixture(&[("example-1.0.0/src/lib.rs", source, tar::EntryType::Regular)])?;
    for (path, text, size, hash) in [
        (
            "src/missing.rs",
            b"// synthetic notice\n".as_slice(),
            source.len(),
            checksum(source)?,
        ),
        (
            "src/lib.rs",
            b"changed".as_slice(),
            source.len(),
            checksum(source)?,
        ),
        (
            "src/lib.rs",
            b"".as_slice(),
            source.len(),
            checksum(source)?,
        ),
        (
            "src/lib.rs",
            b"// synthetic notice\n".as_slice(),
            1,
            checksum(source)?,
        ),
        (
            "src/lib.rs",
            b"// synthetic notice\n".as_slice(),
            source.len(),
            "0".repeat(64),
        ),
        ("../src/lib.rs", b"notice".as_slice(), 1, checksum(source)?),
        ("Cargo.toml", b"notice".as_slice(), 1, checksum(source)?),
        (
            ".cargo_vcs_info.json",
            b"notice".as_slice(),
            1,
            checksum(source)?,
        ),
        ("LICENSE", b"notice".as_slice(), 1, checksum(source)?),
    ] {
        let invalid = BTreeMap::from([(
            path.to_owned(),
            archive::Prefix {
                bytes: u64::try_from(size)?,
                sha256: hash,
                text: text.to_vec(),
            },
        )]);
        assert!(
            archive::collect_with_prefixes(
                &package(),
                &bytes,
                &checksum(&bytes)?,
                Limits::default(),
                &invalid,
            )
            .is_err(),
            "{path}"
        );
    }
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture encoding, checksum or byte conversion errors.
///
/// # Panics
/// Panics if a source-text or archive budget overrun is accepted.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-06, revisit 2026-11-06"
)]
fn source_prefix_enforces_archive_and_source_budgets() -> Result<()> {
    let source = b"// synthetic notice\nfn original() {}\n";
    let bytes = fixture(&[("example-1.0.0/src/lib.rs", source, tar::EntryType::Regular)])?;
    let selected = BTreeMap::from([(
        "src/lib.rs".to_owned(),
        archive::Prefix {
            bytes: u64::try_from(source.len())?,
            sha256: checksum(source)?,
            text: b"// synthetic notice\n".to_vec(),
        },
    )]);
    for limits in [
        Limits {
            notice_bytes: 1,
            ..Limits::default()
        },
        Limits {
            total_notice_bytes: 1,
            ..Limits::default()
        },
        Limits {
            entries: 1,
            ..Limits::default()
        },
        Limits {
            expanded_bytes: 1,
            ..Limits::default()
        },
        Limits {
            path_bytes: 1,
            ..Limits::default()
        },
    ] {
        assert!(
            archive::collect_with_prefixes(
                &package(),
                &bytes,
                &checksum(&bytes)?,
                limits,
                &selected,
            )
            .is_err()
        );
    }
    assert!(
        archive::collect_with_prefixes(
            &package(),
            &bytes,
            &"0".repeat(64),
            Limits::default(),
            &selected,
        )
        .is_err()
    );
    Ok(())
}
