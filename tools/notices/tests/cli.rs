//! Verifies notice commands and preservation of existing output after failed input.

extern crate alloc;

use core::{
    fmt::Write as _,
    sync::atomic::{AtomicU64, Ordering},
};
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use flate2::{Compression, write::GzEncoder};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

#[path = "cli/package.rs"]
mod package;

#[path = "cli/source_prefix.rs"]
mod source_prefix;

type Result<T> = core::result::Result<T, Box<dyn core::error::Error>>;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    /// # Errors
    ///
    /// Returns an error if the system time precedes the Unix epoch or the fixture directory cannot be created.
    fn new() -> Result<Self> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!(
            "logbrew-notices-{}-{nanos}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        // Require a new directory so a fixture cannot adopt an existing tree.
        fs::DirBuilder::new().create(&root)?;
        Ok(Self { root })
    }

    /// # Errors
    ///
    /// Returns an error if the notice command cannot be launched or its output cannot be collected.
    fn run(&self) -> Result<std::process::Output> {
        Ok(Command::new(env!("CARGO_BIN_EXE_logbrew-mcp-notices"))
            .args([
                self.root.join("metadata.json"),
                self.root.join("Cargo.lock"),
                self.root.join("cache"),
                self.root.join("sources.json"),
                self.root.join("output.json"),
            ])
            .output()?)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _cleanup: io::Result<()> = fs::remove_dir_all(&self.root);
    }
}

/// # Errors
///
/// Returns an error if the checksum cannot be formatted.
fn digest(bytes: &[u8]) -> Result<String> {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(output, "{byte:02x}")?;
    }
    Ok(output)
}

/// # Errors
///
/// Returns an error if the notice size cannot be converted or tar or gzip encoding fails.
fn archive() -> Result<Vec<u8>> {
    let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
    for (path, bytes) in [
        ("example-1.0.0/Cargo.toml", b"[package]\nname='example'\nversion='1.0.0'\nlicense='MIT'\nrepository='https://github.com/example/project/'\n".as_slice()),
        ("example-1.0.0/.cargo_vcs_info.json", b"{\"git\":{\"sha1\":\"0000000000000000000000000000000000000000\"}}".as_slice()),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(u64::try_from(bytes.len())?);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        builder.append_data(&mut header, path, bytes)?;
    }
    Ok(builder.into_inner()?.finish()?)
}

/// # Errors
///
/// Returns an error if JSON encoding or file writing fails.
fn write_json(path: &Path, value: &Value) -> Result<()> {
    fs::write(path, serde_json::to_vec(value)?)?;
    Ok(())
}

/// # Errors
///
/// Returns an error if fixture preparation, directory creation, JSON encoding, or file writing fails.
fn project_fixture() -> Result<Fixture> {
    let fixture = Fixture::new()?;
    let root = &fixture.root;
    fs::create_dir_all(root.join("project"))?;
    fs::create_dir_all(root.join("cache"))?;
    fs::write(root.join("project/LICENSE"), b"synthetic project license\n")?;
    fs::write(
        root.join("Cargo.lock"),
        "version=4\n[[package]]\nname='logbrew-mcp'\nversion='0.1.0'\n",
    )?;
    write_json(
        &root.join("metadata.json"),
        &json!({"packages":[{"name":"logbrew-mcp","version":"0.1.0","source":null,
        "license":"Apache-2.0","manifest_path":root.join("project/Cargo.toml")}]}),
    )?;
    write_json(
        &root.join("sources.json"),
        &json!({"format_version":1_u32,"notices":[]}),
    )?;
    Ok(fixture)
}

#[cfg(unix)]
#[test]
/// # Errors
///
/// Returns an error if fixture preparation, file access, symlink creation, or command execution fails.
///
/// # Panics
///
/// Panics if an output symlink is accepted, its target changes, or the symlink is replaced.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn rejects_output_symlinks_without_changing_their_target() -> Result<()> {
    let fixture = project_fixture()?;
    let protected = fixture.root.join("protected.txt");
    fs::write(&protected, b"preserved source bytes")?;
    std::os::unix::fs::symlink(&protected, fixture.root.join("output.json"))?;
    assert!(!fixture.run()?.status.success());
    assert_eq!(fs::read(&protected)?, b"preserved source bytes");
    assert!(fs::symlink_metadata(fixture.root.join("output.json"))?.is_symlink());
    Ok(())
}

#[test]
/// # Errors
///
/// Returns an error if fixture preparation, file access, hard link creation, command execution, or JSON decoding fails.
///
/// # Panics
///
/// Panics if replacement fails, protected bytes or an open reader change, or the output version is unexpected.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn replacement_preserves_an_existing_hard_link_and_open_reader() -> Result<()> {
    use std::io::Read as _;

    let fixture = project_fixture()?;
    let protected = fixture.root.join("protected.txt");
    let output = fixture.root.join("output.json");
    fs::write(&protected, b"previous complete inventory")?;
    fs::hard_link(&protected, &output)?;
    let reader = fs::File::open(&output)?;
    let result = fixture.run()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(&protected)?, b"previous complete inventory");
    let mut old = Vec::new();
    let _read_bytes: usize = reader.take(4096).read_to_end(&mut old)?;
    assert_eq!(old, b"previous complete inventory");
    let inventory: Value = serde_json::from_slice(&fs::read(&output)?)?;
    assert_eq!(inventory.get("format_version"), Some(&Value::from(1_u32)));
    Ok(())
}

#[test]
/// # Errors
///
/// Returns an error if fixture preparation, archive creation, checksum recording, file access, JSON conversion or field access, UTF-8 decoding, or command execution fails.
///
/// # Panics
///
/// Panics if notice generation, verbatim text, path exclusion, reproducibility, invalid source rejection, or preservation of previous output differs from the expected behavior.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn reproducible_generation_rejects_changed_sources_and_preserves_previous_output() -> Result<()> {
    let fixture = Fixture::new()?;
    let root = &fixture.root;
    fs::create_dir_all(root.join("cache"))?;
    fs::create_dir_all(root.join("project"))?;
    fs::create_dir_all(root.join("dependency"))?;
    let bytes = archive()?;
    let package_digest = digest(&bytes)?;
    let notice = b"Copyright synthetic author\r\nPermission synthetic notice\r\n";
    fs::write(root.join("cache/example-1.0.0.crate"), &bytes)?;
    fs::write(root.join("project/LICENSE"), b"project license\n")?;
    fs::write(root.join("example.txt"), notice)?;
    let mut metadata = json!({"packages":[
        {"name":"logbrew-mcp","version":"0.1.0","source":null,"license":"Apache-2.0","manifest_path":root.join("project/Cargo.toml")},
        {"name":"example","version":"1.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","license":"MIT",
            "repository":"https://github.com/example/project/","manifest_path":root.join("dependency/Cargo.toml")}
    ]});
    write_json(&root.join("metadata.json"), &metadata)?;
    fs::write(
        root.join("Cargo.lock"),
        format!(
            "version=4\n[[package]]\nname='example'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{package_digest}'\n[[package]]\nname='logbrew-mcp'\nversion='0.1.0'\n"
        ),
    )?;
    let supplements = json!({"format_version":1_u32,"notices":[{"package":"example","version":"1.0.0","published_package_sha256":package_digest,
        "source_commit":"0".repeat(40),"upstream_path":"LICENSE","source_url":format!("https://raw.githubusercontent.com/example/project/{}/LICENSE", "0".repeat(40)),
        "file":"example.txt","sha256":digest(notice)?}]});
    write_json(&root.join("sources.json"), &supplements)?;
    let output = fixture.run()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, Vec::<u8>::new());
    let first = fs::read(root.join("output.json"))?;
    let inventory: Value = serde_json::from_slice(&first)?;
    assert_eq!(
        inventory
            .pointer(&format!("/texts/{}", digest(notice)?))
            .and_then(Value::as_str),
        Some(core::str::from_utf8(notice)?)
    );
    assert!(!core::str::from_utf8(&first)?.contains(&root.to_string_lossy().into_owned()));
    metadata
        .get_mut("packages")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| io::Error::other("fixture packages missing"))?
        .reverse();
    write_json(&root.join("metadata.json"), &metadata)?;
    assert!(fixture.run()?.status.success());
    assert_eq!(fs::read(root.join("output.json"))?, first);

    for (pointer, replacement) in [
        ("/notices/0/source_commit", Value::String("1".repeat(40))),
        (
            "/notices/0/published_package_sha256",
            Value::String("1".repeat(64)),
        ),
        ("/notices/0/sha256", Value::String("1".repeat(64))),
        (
            "/notices/0/source_url",
            Value::String("https://example.invalid/LICENSE".to_owned()),
        ),
        (
            "/notices/0/file",
            Value::String("../example.txt".to_owned()),
        ),
        ("/notices", Value::Array(Vec::new())),
    ] {
        let mut changed = supplements.clone();
        *changed
            .pointer_mut(pointer)
            .ok_or_else(|| io::Error::other("fixture supplement missing"))? = replacement;
        write_json(&root.join("sources.json"), &changed)?;
        assert!(!fixture.run()?.status.success(), "{pointer}");
        assert_eq!(fs::read(root.join("output.json"))?, first);
    }
    let mut duplicated = supplements.clone();
    let notices = duplicated
        .get_mut("notices")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| io::Error::other("fixture notices missing"))?;
    let extra = notices
        .first()
        .ok_or_else(|| io::Error::other("fixture notice missing"))?
        .clone();
    notices.push(extra);
    write_json(&root.join("sources.json"), &duplicated)?;
    assert!(!fixture.run()?.status.success());
    assert_eq!(fs::read(root.join("output.json"))?, first);

    write_json(&root.join("sources.json"), &supplements)?;
    fs::write(root.join("example.txt"), b"changed notice")?;
    assert!(!fixture.run()?.status.success());
    assert_eq!(fs::read(root.join("output.json"))?, first);
    fs::write(root.join("example.txt"), notice)?;
    fs::write(root.join("cache/example-1.0.0.crate"), b"changed archive")?;
    assert!(!fixture.run()?.status.success());
    assert_eq!(fs::read(root.join("output.json"))?, first);
    Ok(())
}

#[test]
/// # Errors
///
/// Returns an error if fixture preparation, time conversion, archive creation, checksum recording, file access, JSON conversion, UTF-8 decoding, or command execution fails.
///
/// # Panics
///
/// Panics if toolchain notice generation, text coverage, path exclusion, reproducibility, invalid source rejection, or preservation of previous output differs from the expected behavior.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn toolchain_command_preserves_notices_and_previous_output_after_failed_verification() -> Result<()>
{
    let fixture = Fixture::new()?;
    let root = &fixture.root;
    let version = env!("CARGO_PKG_RUST_VERSION");
    let prefix = format!("rustc-{version}-synthetic-target");
    let notice = b"synthetic Rust license and copyright\r\n";
    let paths = [
        "COPYRIGHT",
        "LICENSE-APACHE",
        "LICENSE-MIT",
        "rustc/share/doc/rust/COPYRIGHT-library.html",
    ];
    let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
    let mut files = serde_json::Map::new();
    for path in paths {
        let mut header = tar::Header::new_gnu();
        header.set_size(u64::try_from(notice.len())?);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        builder.append_data(&mut header, format!("{prefix}/{path}"), notice.as_slice())?;
        let _previous: Option<Value> = files.insert(
            path.to_owned(),
            json!({"sha256":digest(notice)?,"bytes":notice.len()}),
        );
    }
    let archive = builder.into_inner()?.finish()?;
    let url = format!("https://static.rust-lang.org/dist/2026-10-01/{prefix}.tar.gz");
    let commit = "a".repeat(40);
    let manifest = format!(
        "manifest-version='2'\ndate='2026-10-01'\n[pkg.rustc]\nversion='{version} (synthetic)'\ngit_commit_hash='{commit}'\n[pkg.rustc.target.synthetic-target]\navailable=true\nurl='{url}'\nhash='{}'\n",
        digest(&archive)?
    );
    let source = json!({"format_version":1_u32,"scope":"rust_standard_library_source_notices","release":version,"target":"synthetic-target",
        "source_commit":commit,"release_date":"2026-10-01","distribution_manifest_sha256":digest(manifest.as_bytes())?,
        "component_archive_sha256":digest(&archive)?,"component_archive_url":url,"files":files});
    write_json(&root.join("sources.json"), &source)?;
    fs::write(root.join("distribution.toml"), manifest)?;
    fs::write(root.join("rustc.tar.gz"), archive)?;
    fs::write(root.join("installed.html"), notice)?;
    let run = || -> Result<std::process::Output> {
        Ok(
            Command::new(env!("CARGO_BIN_EXE_logbrew-mcp-toolchain-notices"))
                .args([
                    root.join("sources.json"),
                    root.join("distribution.toml"),
                    root.join("rustc.tar.gz"),
                    root.join("installed.html"),
                    root.join("output.json"),
                ])
                .output()?,
        )
    };
    let result = run()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, Vec::<u8>::new());
    let first = fs::read(root.join("output.json"))?;
    let value: Value = serde_json::from_slice(&first)?;
    for path in paths {
        assert_eq!(
            value
                .get("files")
                .and_then(|notices| notices.get(path))
                .and_then(|record| record.get("text"))
                .and_then(Value::as_str)
                .map(str::as_bytes),
            Some(notice.as_slice())
        );
    }
    assert_eq!(
        value.get("binary_linkage_coverage"),
        Some(&json!("not_evaluated"))
    );
    assert!(!core::str::from_utf8(&first)?.contains(&root.to_string_lossy().into_owned()));
    assert!(run()?.status.success());
    assert_eq!(fs::read(root.join("output.json"))?, first);
    fs::write(
        root.join("installed.html"),
        b"changed installed library notice",
    )?;
    assert!(!run()?.status.success());
    assert_eq!(fs::read(root.join("output.json"))?, first);
    fs::write(root.join("installed.html"), notice)?;
    fs::write(root.join("distribution.toml"), b"changed distribution")?;
    assert!(!run()?.status.success());
    assert_eq!(fs::read(root.join("output.json"))?, first);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct Process(std::process::Child);

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for Process {
    fn drop(&mut self) {
        let _kill: io::Result<()> = self.0.kill();
        let _status: io::Result<std::process::ExitStatus> = self.0.wait();
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct CommandObservation {
    status: Option<std::process::ExitStatus>,
    elapsed: core::time::Duration,
    stderr: String,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl CommandObservation {
    fn input_rejected(&self) -> bool {
        self.status
            .as_ref()
            .is_some_and(|status| status.code() == Some(1_i32))
            && self
                .stderr
                .contains("notice input must be a bounded regular file")
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
/// # Errors
///
/// Returns an error if the deadline cannot be constructed or the child status cannot be read.
fn exit_before_deadline(
    child: &mut std::process::Child,
    started: std::time::Instant,
) -> Result<Option<std::process::ExitStatus>> {
    let end = started
        .checked_add(core::time::Duration::from_secs(1))
        .ok_or("fixture deadline overflow")?;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if std::time::Instant::now() >= end {
            return Ok(None);
        }
        std::thread::sleep(core::time::Duration::from_millis(10));
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
/// # Errors
///
/// Returns an error if launch, pipe configuration, bounded capture or child polling fails.
fn observe_command(program: &str, args: &[&Path]) -> Result<CommandObservation> {
    use std::io::Read as _;

    let started = std::time::Instant::now();
    let mut child = Process(
        Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()?,
    );
    let wait_started = std::time::Instant::now();
    let stderr = child.0.stderr.take().ok_or("fixture stderr is missing")?;
    let flags = rustix::fs::fcntl_getfl(&stderr)?;
    rustix::fs::fcntl_setfl(&stderr, flags | rustix::fs::OFlags::NONBLOCK)?;
    let status = exit_before_deadline(&mut child.0, wait_started)?;
    let elapsed = started.elapsed();
    // Retire the owned leader before reading; nonblocking capture also rejects a held-open pipe.
    drop(child);
    let mut captured = Vec::new();
    let _bytes = stderr.take(4097).read_to_end(&mut captured)?;
    if captured.len() > 4096 {
        return Err(io::Error::other("fixture stderr exceeded 4 KiB").into());
    }
    Ok(CommandObservation {
        status,
        elapsed,
        stderr: String::from_utf8(captured)?,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
/// # Errors
///
/// Returns an error if fixture preparation, pipe creation, command execution, child polling, or file access fails.
///
/// # Panics
///
/// Panics if a command waits for a pipe writer or changes previous output.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn notice_and_package_commands_reject_input_pipes_without_waiting_for_a_writer() -> Result<()> {
    let fixture = Fixture::new()?;
    let input = fixture.root.join("input");
    if !Command::new("/usr/bin/mkfifo")
        .arg(&input)
        .status()?
        .success()
    {
        return Err(io::Error::other("could not create fixture FIFO").into());
    }
    let output = fixture.root.join("output.json");
    fs::write(&output, b"previous complete inventory")?;
    for (program, args) in [
        (
            env!("CARGO_BIN_EXE_logbrew-mcp-notices"),
            vec![&input, &input, &input, &input, &output],
        ),
        (
            env!("CARGO_BIN_EXE_logbrew-mcp-toolchain-notices"),
            vec![&input, &input, &input, &input, &output],
        ),
        (
            env!("CARGO_BIN_EXE_logbrew-mcp-package"),
            vec![&input, &input, &input, &output],
        ),
        (
            env!("CARGO_BIN_EXE_logbrew-mcp-relink"),
            vec![&input, &input, &output],
        ),
        (
            env!("CARGO_BIN_EXE_logbrew-mcp-materials"),
            vec![&input, &output],
        ),
    ] {
        let args: Vec<&Path> = args.into_iter().map(PathBuf::as_path).collect();
        let observation = observe_command(program, &args)?;
        assert!(
            observation.input_rejected(),
            "{program}: expected regular-input rejection; status={}, elapsed_us={}, stderr={}",
            observation.status.map_or_else(
                || "deadline expired".to_owned(),
                |status| status.to_string()
            ),
            observation.elapsed.as_micros(),
            observation.stderr,
        );
        assert_eq!(fs::read(&output)?, b"previous complete inventory");
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
/// # Errors
///
/// Returns an error if command launch, bounded capture or polling fails.
///
/// # Panics
///
/// Panics if an unrelated argument failure counts as regular-input rejection.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-10, revisit 2026-11-10"
)]
fn argument_errors_do_not_count_as_pipe_rejections() -> Result<()> {
    let observation = observe_command(env!("CARGO_BIN_EXE_logbrew-mcp-notices"), &[])?;
    assert!(
        observation
            .status
            .as_ref()
            .is_some_and(|status| status.code() == Some(1_i32))
    );
    assert!(!observation.input_rejected());
    assert!(
        observation
            .stderr
            .contains("missing Cargo metadata JSON argument")
    );
    Ok(())
}
