//! File access rejects symlinks, special files, broad permissions, and excess bytes.

use std::{
    fs,
    os::unix::fs::{DirBuilderExt as _, PermissionsExt as _, symlink},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use logbrew_mcp::startup::read_file;

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Directory(PathBuf);

impl Directory {
    /// # Errors
    ///
    /// Returns the filesystem error if the private disposable directory cannot
    /// be created.
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "logbrew-mcp-files-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

#[test]
/// # Panics
///
/// Panics if fixture setup fails, file bytes change, or file identity, permission,
/// path or exact byte limits do not reject the corresponding invalid input.
fn file_identity_permissions_and_exact_byte_limits_are_enforced() {
    let directory = Directory::new().expect("disposable directory");
    let file = directory.0.join("secret");
    fs::write(&file, b"SYNTHETIC_SECRET\n").expect("synthetic secret");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("private mode");
    let bytes = read_file(&file, 17, 0o600).expect("bounded private file");
    assert_eq!(bytes.as_slice(), b"SYNTHETIC_SECRET\n");
    let _: logbrew_mcp::Failure = read_file(&file, 16, 0o600).unwrap_err();
    let _: logbrew_mcp::Failure = read_file(&directory.0, 1024, 0o700).unwrap_err();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("broad mode");
    let _: logbrew_mcp::Failure = read_file(&file, 17, 0o600).unwrap_err();
    drop(read_file(&file, 17, 0o644).unwrap());
    let link = directory.0.join("link");
    symlink(&file, &link).expect("synthetic symlink");
    let _: logbrew_mcp::Failure = read_file(&link, 17, 0o644).unwrap_err();
    let _: logbrew_mcp::Failure =
        read_file(std::path::Path::new("relative"), 1024, 0o644).unwrap_err();
}
