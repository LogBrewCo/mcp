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

struct Staged {
    directory: OwnedFd,
    file: File,
    name: OsString,
    published: bool,
}

fn permissions(directory: impl AsFd, name: &OsStr) -> Result<Mode> {
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

impl Staged {
    fn create(parent: &Path) -> Result<Self> {
        let directory = fs::open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
        for _ in 0..8 {
            let sequence = SEQUENCE
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
                .map_err(|_| error("notice staging sequence exhausted"))?;
            let name = OsString::from(format!(
                ".logbrew-notices-{}-{sequence}.tmp",
                std::process::id()
            ));
            match fs::openat(
                &directory,
                &name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(file) => {
                    return Ok(Self {
                        directory,
                        file: File::from(file),
                        name,
                        published: false,
                    });
                }
                Err(Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(error("notice staging collision limit reached"))
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
        fs::fsync(&self.directory)
            .map_err(|_| error("notice output replaced; directory durability is unconfirmed"))?;
        Ok(())
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.published && self.owns_name() {
            let _ = fs::unlinkat(&self.directory, &self.name, AtFlags::empty());
        }
    }
}

fn replace(path: &Path, write: impl FnOnce(&mut File) -> io::Result<()>) -> Result<()> {
    let destination = path
        .file_name()
        .ok_or_else(|| error("invalid notice output filename"))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staged = Staged::create(parent)?;
    permissions(&staged.directory, destination)?;
    write(&mut staged.file)?;
    staged.publish(parent, destination)
}

pub fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.len() > 64 << 20 {
        return Err(error("notice output exceeds limit"));
    }
    replace(path, |file| file.write_all(bytes))
}

#[cfg(test)]
mod tests;
