use std::{ffi::OsString, path::PathBuf};

use serde::Deserialize;

use crate::{Result, error};

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod process;
#[cfg(test)]
mod tests;

const VERSION: &[u8] = b"cargo-deny 0.20.2\n";
const CHECK_ARGS: &[&str] = &[
    "--format",
    "json",
    "--log-level",
    "debug",
    "--color",
    "never",
    "--locked",
    "--offline",
    "check",
    "--deny",
    "warnings",
    "--show-stats",
    "licenses",
    "bans",
    "sources",
];
const RECORD_BYTES: usize = 1 << 20;
const RECORDS: usize = 16_384;

#[derive(Deserialize)]
#[serde(tag = "type", content = "fields")]
enum Record {
    #[serde(rename = "log")]
    Log(Log),
    #[serde(rename = "diagnostic")]
    Diagnostic(Diagnostic),
    #[serde(rename = "summary")]
    Summary(Summary),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Log {
    level: String,
    message: String,
    timestamp: String,
}

#[derive(Deserialize)]
struct Diagnostic {
    severity: String,
    code: String,
    message: String,
}

#[derive(Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Stats {
    errors: u32,
    warnings: u32,
    notes: u32,
    helps: u32,
}

#[derive(Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Summary {
    bans: Stats,
    licenses: Stats,
    sources: Stats,
}

/// # Errors
/// Rejects unsupported record levels or shapes, empty required log fields,
/// diagnostic-count overflow, and summaries that disagree with observed counts.
fn observe(record: Record, observed: &mut Summary) -> Result<bool> {
    match record {
        Record::Log(log) => {
            if !matches!(log.level.as_str(), "INFO" | "DEBUG" | "TRACE")
                || log.message.is_empty()
                || log.timestamp.is_empty()
            {
                return Err(error(
                    "cargo-deny logged a warning, error or invalid record",
                ));
            }
        }
        Record::Diagnostic(diagnostic) => {
            if diagnostic.message.is_empty() {
                return Err(error("cargo-deny emitted an invalid diagnostic"));
            }
            // These pinned tool codes report explicit policy acceptance.
            // Other diagnostics fail regardless of their severity.
            let counter = match (diagnostic.code.as_str(), diagnostic.severity.as_str()) {
                ("accepted", "help") => &mut observed.licenses.helps,
                ("skipped", "note") => &mut observed.bans.notes,
                _ => return Err(error("cargo-deny emitted an unaccepted diagnostic")),
            };
            *counter = counter
                .checked_add(1)
                .ok_or_else(|| error("cargo-deny diagnostic count exceeded its limit"))?;
        }
        Record::Summary(stats) => {
            if stats != *observed {
                return Err(error(
                    "cargo-deny summary disagrees with its accepted diagnostic records",
                ));
            }
            return Ok(true);
        }
    }
    Ok(false)
}

/// # Errors
/// Rejects process failure, unexpected stdout, incomplete or oversized
/// stderr records, invalid records, and missing, duplicate, or inconsistent
/// final summaries.
fn validate(success: bool, stdout: &[u8], stderr: &[u8]) -> Result<()> {
    if !success || !stdout.is_empty() || !stderr.ends_with(b"\n") {
        return Err(error("cargo-deny failed or produced incomplete output"));
    }
    let mut summary = false;
    let mut observed = Summary::default();
    let records = stderr
        .strip_suffix(b"\n")
        .ok_or_else(|| error("missing record terminator"))?;
    for (index, line) in records.split(|byte| *byte == b'\n').enumerate() {
        if summary || index >= RECORDS || line.is_empty() || line.len() > RECORD_BYTES {
            return Err(error("invalid cargo-deny record sequence"));
        }
        summary = observe(serde_json::from_slice::<Record>(line)?, &mut observed)?;
    }
    if !summary {
        return Err(error("cargo-deny did not complete all required checks"));
    }
    Ok(())
}

/// # Errors
/// Rejects an argument count or executable path violation, unsupported
/// platform, incorrect pinned version, process capture failure, and dependency
/// output that fails the strict policy-record validation.
pub fn run<Args>(mut args: Args) -> Result<()>
where
    Args: Iterator<Item = OsString>,
{
    let executable = PathBuf::from(
        args.next()
            .ok_or_else(|| error("missing cargo-deny executable"))?,
    );
    if args.next().is_some()
        || !executable.is_absolute()
        || !std::fs::symlink_metadata(&executable)?.is_file()
    {
        return Err(error("expected one absolute regular cargo-deny executable"));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use core::time::Duration;
        use std::process::Command;

        let version = process::capture(
            Command::new(&executable).arg("--version"),
            Duration::from_secs(5),
            4096,
        )?;
        if !version.success || version.stdout != VERSION || !version.stderr.is_empty() {
            return Err(error("cargo-deny version must be 0.20.2"));
        }
        let checked = process::capture(
            Command::new(&executable).args(CHECK_ARGS),
            Duration::from_secs(120),
            8 << 20,
        )?;
        validate(checked.success, &checked.stdout, &checked.stderr)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = executable;
        Err(error("policy command is supported on Linux and macOS"))
    }
}
