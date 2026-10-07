use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Write as _},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use rustix::{
    fd::{AsFd, OwnedFd},
    fs::{self, AtFlags, FileType, Mode, OFlags},
    io::Errno,
};

use crate::{Result, error};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct DirectorySyncFailure {
    cause: Errno,
}

impl std::fmt::Display for DirectorySyncFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "notice output replaced; directory durability is unconfirmed: {}",
            self.cause
        )
    }
}

impl std::error::Error for DirectorySyncFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

struct Staged {
    directory: OwnedFd,
    file: File,
    name: OsString,
    published: bool,
}

/// # Errors
/// Rejects an existing destination that is not a regular file and propagates
/// metadata lookup errors other than an absent destination.
fn permissions<Directory>(directory: Directory, name: &OsStr) -> Result<Mode>
where
    Directory: AsFd,
{
    match fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => {
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
                return Err(error("notice output must be a regular file"));
            }
            Ok(Mode::from_raw_mode(stat.st_mode)
                & (Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH))
        }
        Err(Errno::NOENT) => Ok(Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH),
        Err(error) => Err(error.into()),
    }
}

/// # Errors
/// Rejects exhaustion without changing the staging sequence.
#[expect(
    clippy::map_err_ignore,
    reason = "Atomic update failure contains only the previous counter value. Keep a fixed exhaustion error and prove no wraparound or mutation. Reviewed 2026-10-05; review by 2026-11-05 or on sequence changes."
)]
fn next_sequence(sequence: &AtomicU64) -> Result<u64> {
    sequence
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| error("notice staging sequence exhausted"))
}

/// # Errors
/// Rejects staging-sequence exhaustion and propagates exclusive-file open
/// failures other than a name collision.
fn create_file<Directory>(directory: Directory) -> Result<Option<(File, OsString)>>
where
    Directory: AsFd,
{
    let sequence = next_sequence(&SEQUENCE)?;
    let name = OsString::from(format!(
        ".logbrew-notices-{}-{sequence}.tmp",
        std::process::id()
    ));
    match fs::openat(
        directory,
        &name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(file) => Ok(Some((File::from(file), name))),
        Err(Errno::EXIST) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// # Errors
/// Returns an error for staging creation failure or eight consecutive name
/// collisions.
fn stage_file(directory: &OwnedFd) -> Result<(File, OsString)> {
    for _ in 0_u8..8_u8 {
        if let Some(file) = create_file(directory)? {
            return Ok(file);
        }
    }
    Err(error("notice staging collision limit reached"))
}

impl Staged {
    /// # Errors
    /// Propagates directory-open or staging-file creation failures.
    fn create(parent: &Path) -> Result<Self> {
        let directory = fs::open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
        let (file, name) = stage_file(&directory)?;
        Ok(Self {
            directory,
            file,
            name,
            published: false,
        })
    }

    fn owns_name(&self) -> bool {
        match (
            fs::fstat(&self.file),
            fs::statat(&self.directory, &self.name, AtFlags::SYMLINK_NOFOLLOW),
        ) {
            (Ok(opened), Ok(named)) => {
                opened.st_dev == named.st_dev
                    && opened.st_ino == named.st_ino
                    && FileType::from_raw_mode(named.st_mode) == FileType::RegularFile
            }
            _ => false,
        }
    }

    /// # Errors
    /// Rejects changed staging ownership or directory identity, nonregular
    /// destinations, and metadata, permission, file-sync, or rename failures.
    /// Directory-sync failure is reported after replacement: the new output
    /// exists, but directory durability is unconfirmed.
    fn publish(mut self, parent: &Path, destination: &OsStr) -> Result<()> {
        let directory_now = fs::open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let held = fs::fstat(&self.directory)?;
        let current = fs::fstat(directory_now)?;
        if held.st_dev != current.st_dev || held.st_ino != current.st_ino || !self.owns_name() {
            return Err(error("notice staging directory or file changed"));
        }
        let mode = permissions(&self.directory, destination)?;
        fs::fchmod(&self.file, mode)?;
        self.file.sync_all()?;
        fs::renameat(&self.directory, &self.name, &self.directory, destination)?;
        self.published = true;
        fs::fsync(&self.directory).map_err(|cause| DirectorySyncFailure { cause })?;
        Ok(())
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.published && self.owns_name() {
            let _cleanup: rustix::io::Result<()> =
                fs::unlinkat(&self.directory, &self.name, AtFlags::empty());
        }
    }
}

/// # Errors
/// Rejects an invalid destination name or destination type and propagates
/// staging, writer, and publication failures. A directory-sync failure may
/// occur after replacement; unpublished staging cleanup is best effort.
fn replace<Write>(path: &Path, write: Write) -> Result<()>
where
    Write: FnOnce(&mut File) -> io::Result<()>,
{
    let destination = path
        .file_name()
        .ok_or_else(|| error("invalid notice output filename"))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staged = Staged::create(parent)?;
    let _initial_permissions: Mode = permissions(&staged.directory, destination)?;
    write(&mut staged.file)?;
    staged.publish(parent, destination)
}

/// # Errors
/// Rejects output over 64 MiB and propagates staging, write, and publication
/// failures. A directory-sync error can occur after the output is replaced.
pub fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.len() > 64_usize << 20_u32 {
        return Err(error("notice output exceeds limit"));
    }
    replace(path, |file| file.write_all(bytes))
}

#[cfg(test)]
mod tests;
