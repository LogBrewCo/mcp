//! Select a Linux runtime loader without changing the packaged executable.

use std::{ffi::OsString, io, path::Path, process::Command};

/// Construct a direct launch or an explicitly selected Linux loader invocation.
///
/// # Errors
/// Rejects incomplete loader options, unsupported hosts and relative paths.
/// The library path must identify one directory, without a search-path separator.
pub fn command(
    executable: OsString,
    loader: Option<OsString>,
    library_path: Option<OsString>,
) -> io::Result<Command> {
    match (loader, library_path) {
        (None, None) => Ok(Command::new(executable)),
        (Some(loader), Some(library_path))
            if cfg!(target_os = "linux")
                && Path::new(&executable).is_absolute()
                && Path::new(&loader).is_absolute()
                && library_path
                    .to_str()
                    .is_some_and(|path| Path::new(path).is_absolute() && !path.contains(':')) =>
        {
            let mut command = Command::new(loader);
            let _: &mut Command = command
                .arg("--inhibit-cache")
                .arg("--library-path")
                .arg(library_path)
                .arg(executable);
            Ok(command)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid test runtime-loader selection",
        )),
    }
}

/// # Panics
/// Panics if an invalid loader selection is accepted or has the wrong error kind.
#[test]
fn rejects_incomplete_relative_and_search_list_loader_options() {
    for (executable, loader, library_path) in [
        ("/bin/server", Some("/lib/loader"), None),
        ("/bin/server", None, Some("/lib/runtime")),
        ("server", Some("/lib/loader"), Some("/lib/runtime")),
        ("/bin/server", Some("loader"), Some("/lib/runtime")),
        ("/bin/server", Some("/lib/loader"), Some("runtime")),
        ("/bin/server", Some("/lib/loader"), Some("")),
        ("/bin/server", Some("/lib/loader"), Some("/lib/runtime:")),
        ("/bin/server", Some("/lib/loader"), Some("/lib/a:/lib/b")),
    ] {
        let result = command(
            executable.into(),
            loader.map(OsString::from),
            library_path.map(OsString::from),
        );
        match result {
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::InvalidInput),
            Ok(_) => panic!("invalid runtime-loader selection was accepted"),
        }
    }
}

#[cfg(target_os = "linux")]
/// # Panics
/// Panics if the private fixture cannot be created, the selected loader changes,
/// or a missing loader starts a child or returns the wrong error kind.
#[test]
fn missing_loader_does_not_fall_back_to_the_executable() {
    let directory = super::Directory::new().expect("private test directory");
    let loader = directory.0.join("missing-loader");
    let mut command = command(
        "/bin/true".into(),
        Some(loader.clone().into_os_string()),
        Some(directory.0.clone().into_os_string()),
    )
    .expect("valid absolute loader selection");
    assert_eq!(command.get_program(), loader.as_os_str());
    match command.spawn() {
        Err(error) => assert_eq!(error.kind(), io::ErrorKind::NotFound),
        Ok(mut child) => {
            child.kill().expect("stop unexpected process");
            let _: std::process::ExitStatus = child.wait().expect("reap unexpected process");
            panic!("missing loader unexpectedly started a process");
        }
    }
}

#[cfg(not(target_os = "linux"))]
/// # Panics
/// Panics if a Linux loader is accepted or has the wrong error kind.
#[test]
fn loader_options_are_rejected_on_other_hosts() {
    match command(
        "/bin/server".into(),
        Some("/lib/loader".into()),
        Some("/lib/runtime".into()),
    ) {
        Err(error) => assert_eq!(error.kind(), io::ErrorKind::InvalidInput),
        Ok(_) => panic!("Linux loader was accepted on another host"),
    }
}
