//! Exclusively owned, clock-independent directories for filesystem fixtures.

use alloc::format;
use core::sync::atomic::{AtomicU64, Ordering};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

const ATTEMPTS: u64 = 64;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A fixture directory acquired through exclusive creation.
pub struct Directory(PathBuf);

impl Directory {
    /// Return the path owned by this fixture.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup: io::Result<()> = fs::remove_dir_all(&self.0);
    }
}

/// # Errors
/// Rejects exhausted names and filesystem errors without owning existing paths.
pub fn directory(label: &str) -> io::Result<Directory> {
    allocate(&std::env::temp_dir(), label, &SEQUENCE)
}

fn candidate(root: &Path, label: &str, sequence: u64) -> PathBuf {
    root.join(format!("logbrew-{label}-{}-{sequence}", std::process::id()))
}

/// # Errors
/// Propagates exclusive directory creation failures before cleanup ownership.
fn create(path: PathBuf) -> io::Result<Directory> {
    fs::DirBuilder::new().create(&path)?;
    Ok(Directory(path))
}

/// # Errors
/// Rejects counter exhaustion, excessive collisions and other filesystem errors.
fn allocate(root: &Path, label: &str, sequence: &AtomicU64) -> io::Result<Directory> {
    for _ in 0..ATTEMPTS {
        let id = sequence
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_current| io::Error::other("test directory sequence exhausted"))?;
        match create(candidate(root, label, id)) {
            Ok(directory) => return Ok(directory),
            Err(failure) if failure.kind() == io::ErrorKind::AlreadyExists => {}
            Err(failure) => return Err(failure),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "test directory collision limit reached",
    ))
}

#[test]
/// # Errors
/// Propagates fixture setup and read failures.
///
/// # Panics
/// Fails if a collision or cleanup changes an existing path.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain diagnostic filesystem assertions; reviewed 2026-10-10, revisit 2026-11-10"
)]
fn collisions_preserve_existing_paths_and_cleanup_only_the_owned_directory() -> io::Result<()> {
    let root = directory("directory-ownership")?;
    let existing = candidate(&root.0, "reserved", 0);
    fs::DirBuilder::new().create(&existing)?;
    fs::write(existing.join("marker"), b"keep directory")?;
    let existing_file = candidate(&root.0, "reserved", 1);
    fs::write(&existing_file, b"keep file")?;
    let owned = allocate(&root.0, "reserved", &AtomicU64::new(0))?;
    let owned_path = owned.0.clone();
    fs::write(owned_path.join("marker"), b"owned")?;
    drop(owned);
    assert_eq!(fs::read(existing.join("marker"))?, b"keep directory");
    assert_eq!(fs::read(&existing_file)?, b"keep file");
    assert!(!owned_path.try_exists()?);
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture setup and read failures.
///
/// # Panics
/// Fails if collision retries exceed their bound or change reserved files.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain diagnostic filesystem assertions; reviewed 2026-10-10, revisit 2026-11-10"
)]
fn collision_limit_preserves_every_reserved_path() -> io::Result<()> {
    let root = directory("directory-collisions")?;
    for id in 0..ATTEMPTS {
        fs::write(candidate(&root.0, "reserved", id), b"reserved")?;
    }
    let sequence = AtomicU64::new(0);
    let failure = allocate(&root.0, "reserved", &sequence)
        .err()
        .ok_or_else(|| io::Error::other("collision budget accepted"))?;
    assert_eq!(failure.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(sequence.load(Ordering::Relaxed), ATTEMPTS);
    assert_eq!(
        fs::read_dir(&root.0)?.count(),
        usize::try_from(ATTEMPTS).map_err(io::Error::other)?
    );
    for id in 0..ATTEMPTS {
        assert_eq!(fs::read(candidate(&root.0, "reserved", id))?, b"reserved");
    }
    Ok(())
}

#[test]
/// # Errors
/// Propagates fixture setup failures.
///
/// # Panics
/// Fails if an exhausted counter wraps or creates a directory.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain diagnostic filesystem assertions; reviewed 2026-10-10, revisit 2026-11-10"
)]
fn sequence_exhaustion_does_not_wrap_or_create_paths() -> io::Result<()> {
    let root = directory("directory-exhaustion")?;
    let sequence = AtomicU64::new(u64::MAX);
    let failure = allocate(&root.0, "reserved", &sequence)
        .err()
        .ok_or_else(|| io::Error::other("exhausted sequence accepted"))?;
    assert_eq!(failure.to_string(), "test directory sequence exhausted");
    assert_eq!(sequence.load(Ordering::Relaxed), u64::MAX);
    assert_eq!(fs::read_dir(&root.0)?.count(), 0);
    Ok(())
}

#[test]
/// # Errors
/// Propagates allocation, worker and filesystem failures.
///
/// # Panics
/// Fails if simultaneous allocations reuse a name or leave owned directories.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain diagnostic filesystem assertions; reviewed 2026-10-10, revisit 2026-11-10"
)]
fn concurrent_allocations_are_unique_and_drop_cleanly() -> io::Result<()> {
    let root = directory("directory-concurrent")?;
    let sequence = AtomicU64::new(0);
    let groups = std::thread::scope(|scope| {
        let workers: alloc::vec::Vec<_> =
            core::iter::repeat_with(|| scope.spawn(|| allocate_batch(&root.0, &sequence)))
                .take(8)
                .collect();
        workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .map_err(|_payload| io::Error::other("directory worker panicked"))?
            })
            .collect::<io::Result<alloc::vec::Vec<_>>>()
    })?;
    let directories: alloc::vec::Vec<_> = groups.into_iter().flatten().collect();
    let paths: alloc::collections::BTreeSet<_> = directories.iter().map(|item| &item.0).collect();
    assert_eq!(directories.len(), 64);
    assert_eq!(paths.len(), 64);
    drop(directories);
    assert_eq!(fs::read_dir(&root.0)?.count(), 0);
    Ok(())
}

/// # Errors
/// Propagates allocation failures while dropping any partially collected fixtures.
fn allocate_batch(root: &Path, sequence: &AtomicU64) -> io::Result<alloc::vec::Vec<Directory>> {
    core::iter::repeat_with(|| allocate(root, "worker", sequence))
        .take(8)
        .collect()
}
