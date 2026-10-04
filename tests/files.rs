//! File access rejects symlinks, special files, broad permissions, and excess bytes.

use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use logbrew_mcp::startup::read_file;

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Directory(PathBuf);

impl Directory {
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "logbrew-mcp-files-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn file_identity_permissions_and_exact_byte_limits_are_enforced() {
    let directory = Directory::new().expect("disposable directory");
    let file = directory.0.join("secret");
    fs::write(&file, b"SYNTHETIC_SECRET\n").expect("synthetic secret");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("private mode");
    let bytes = read_file(&file, 17, 0o600).expect("bounded private file");
    assert_eq!(bytes.as_slice(), b"SYNTHETIC_SECRET\n");
    assert!(read_file(&file, 16, 0o600).is_err());
    assert!(read_file(&directory.0, 1024, 0o700).is_err());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("broad mode");
    assert!(read_file(&file, 17, 0o600).is_err());
    assert!(read_file(&file, 17, 0o644).is_ok());
    let link = directory.0.join("link");
    symlink(&file, &link).expect("synthetic symlink");
    assert!(read_file(&link, 17, 0o644).is_err());
    assert!(read_file(std::path::Path::new("relative"), 1024, 0o644).is_err());
}
