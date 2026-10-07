use core::{
    error::Error as _,
    sync::atomic::{AtomicU64, Ordering},
};
use std::{
    fs,
    io::{self, Write as _},
    os::unix::{fs::PermissionsExt as _, net::UnixListener},
    path::PathBuf,
};

use rustix::io::Errno;

use super::{DirectorySyncFailure, Staged, next_sequence, replace, write};
use crate::{Result, error};

/// # Panics
/// Fails if sequence exhaustion changes the counter or returns another error.
#[test]
fn sequence_exhaustion_preserves_counter_and_fixed_failure() {
    let sequence = AtomicU64::new(u64::MAX);
    let failure = next_sequence(&sequence).unwrap_err();
    assert_eq!(sequence.load(Ordering::Relaxed), u64::MAX);
    assert_eq!(failure.to_string(), "notice staging sequence exhausted");
    assert!(failure.source().is_none());
}

/// # Panics
/// Fails if a sync error loses replacement state or its original OS error.
#[test]
fn directory_sync_error_preserves_replacement_state_and_os_cause() {
    let failure = DirectorySyncFailure { cause: Errno::IO };
    assert_eq!(
        failure.to_string(),
        format!(
            "notice output replaced; directory durability is unconfirmed: {}",
            Errno::IO
        )
    );
    let cause = failure.source().expect("original directory sync error");
    assert_eq!(cause.downcast_ref::<Errno>(), Some(&Errno::IO));
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    /// # Errors
    /// Propagates staging-file or isolated test-directory creation errors.
    fn new() -> Result<Self> {
        let staged = Staged::create(&std::env::temp_dir())?;
        let root = std::env::temp_dir()
            .join(&staged.name)
            .with_extension("directory");
        fs::DirBuilder::new().create(&root)?;
        Ok(Self { root })
    }

    /// # Errors
    /// Propagates directory enumeration or entry-read errors.
    fn entries(&self) -> Result<Vec<PathBuf>> {
        Ok(fs::read_dir(&self.root)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<io::Result<_>>()?)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _cleanup: io::Result<()> = fs::remove_dir_all(&self.root);
    }
}

#[test]
/// # Errors
/// Propagates fixture setup, filesystem writes, or output/directory read errors.
///
/// # Panics
/// Panics if partial writes succeed, change prior output, or leave staging files.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn failed_partial_write_preserves_previous_output_and_removes_staging_file() -> Result<()> {
    let fixture = Fixture::new()?;
    let path = fixture.root.join("output.json");
    fs::write(&path, b"previous complete inventory")?;
    let result = replace(&path, |file| {
        file.write_all(b"incomplete replacement")?;
        Err(io::Error::other("controlled write failure"))
    });
    assert!(result.is_err());
    assert_eq!(fs::read(&path)?, b"previous complete inventory");
    assert_eq!(fixture.entries()?, [path]);
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture setup or directory enumeration errors.
///
/// # Panics
/// Panics if the controlled initial write succeeds or leaves any files.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn failed_initial_write_leaves_no_output_or_staging_file() -> Result<()> {
    let fixture = Fixture::new()?;
    assert!(
        replace(&fixture.root.join("output.json"), |file| {
            file.write_all(b"incomplete first inventory")?;
            Err(io::Error::other("controlled write failure"))
        })
        .is_err()
    );
    assert_eq!(fixture.entries()?, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture setup, FIFO creation/status, socket binding, or directory errors.
///
/// # Panics
/// Panics if a nonregular destination is accepted or the fixture entries change.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn rejects_fifo_socket_and_directory_without_opening_them() -> Result<()> {
    let fixture = Fixture::new()?;
    let fifo = fixture.root.join("pipe");
    if !std::process::Command::new("/usr/bin/mkfifo")
        .arg(&fifo)
        .status()?
        .success()
    {
        return Err(error("could not create fixture FIFO"));
    }
    let socket = fixture.root.join("socket");
    let _listener = UnixListener::bind(&socket)?;
    let directory = fixture.root.join("directory");
    fs::DirBuilder::new().create(&directory)?;
    for path in [&fifo, &socket, &directory] {
        assert!(write(path, b"replacement").is_err());
    }
    assert_eq!(fixture.entries()?.len(), 3);
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture setup, directory creation, symlink creation, or directory reads.
///
/// # Panics
/// Panics if publication through a symlinked directory succeeds or changes its target.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn rejects_symlinked_output_directory() -> Result<()> {
    let fixture = Fixture::new()?;
    let target = fixture.root.join("target");
    let link = fixture.root.join("link");
    fs::DirBuilder::new().create(&target)?;
    std::os::unix::fs::symlink(&target, &link)?;
    assert!(write(&link.join("output.json"), b"replacement").is_err());
    assert!(fs::read_dir(target)?.next().is_none());
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture setup, staging, filesystem mutation, or output/directory reads.
///
/// # Panics
/// Panics if a changed parent is accepted, outputs change, or staging cleanup is incorrect.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn rejects_changed_parent_and_cleans_only_its_original_directory() -> Result<()> {
    let fixture = Fixture::new()?;
    let parent = fixture.root.join("parent");
    let archived = fixture.root.join("original");
    fs::DirBuilder::new().create(&parent)?;
    fs::write(parent.join("output.json"), b"previous complete inventory")?;
    let mut staged = Staged::create(&parent)?;
    staged.file.write_all(b"replacement")?;
    fs::rename(&parent, &archived)?;
    fs::DirBuilder::new().create(&parent)?;
    fs::write(parent.join("output.json"), b"new directory output")?;
    assert!(staged.publish(&parent, "output.json".as_ref()).is_err());
    assert_eq!(
        fs::read(archived.join("output.json"))?,
        b"previous complete inventory"
    );
    assert_eq!(
        fs::read(parent.join("output.json"))?,
        b"new directory output"
    );
    assert_eq!(fs::read_dir(archived)?.count(), 1);
    assert_eq!(fs::read_dir(parent)?.count(), 1);
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture setup, staging, file replacement, or output/directory reads.
///
/// # Panics
/// Panics if foreign staging ownership is accepted or the foreign file is changed.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn changed_staging_name_is_rejected_and_foreign_replacement_is_preserved() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut staged = Staged::create(&fixture.root)?;
    staged.file.write_all(b"replacement")?;
    let name = fixture.root.join(&staged.name);
    fs::remove_file(&name)?;
    fs::write(&name, b"foreign file")?;
    assert!(
        staged
            .publish(&fixture.root, "output.json".as_ref())
            .is_err()
    );
    assert_eq!(fs::read(&name)?, b"foreign file");
    assert_eq!(fixture.entries()?, [name]);
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture setup, staging, symlink creation, or metadata/output reads.
///
/// # Panics
/// Panics if a symlink destination is accepted or protected bytes are changed.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn target_changed_to_symlink_during_staging_is_preserved() -> Result<()> {
    let fixture = Fixture::new()?;
    let protected = fixture.root.join("protected");
    fs::write(&protected, b"protected bytes")?;
    let mut staged = Staged::create(&fixture.root)?;
    staged.file.write_all(b"replacement")?;
    let output = fixture.root.join("output.json");
    std::os::unix::fs::symlink(&protected, &output)?;
    assert!(
        staged
            .publish(&fixture.root, "output.json".as_ref())
            .is_err()
    );
    assert!(fs::symlink_metadata(output)?.is_symlink());
    assert_eq!(fs::read(protected)?, b"protected bytes");
    assert_eq!(fixture.entries()?.len(), 2);
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture setup, filesystem operations, publication, or output reads.
///
/// # Panics
/// Panics if replacement changes the expected permissions or output bytes.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn preserves_existing_read_write_permissions() -> Result<()> {
    let fixture = Fixture::new()?;
    let output = fixture.root.join("output.json");
    fs::write(&output, b"previous")?;
    fs::set_permissions(&output, fs::Permissions::from_mode(0o600))?;
    write(&output, b"replacement")?;
    assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o7777, 0o600);
    assert_eq!(fs::read(output)?, b"replacement");
    Ok(())
}
