//! `LogBrew`'s standalone HTTPS MCP process.

use std::{io::Write as _, path::PathBuf, process::ExitCode};

use logbrew_mcp::{Failure, error::Kind, runtime, startup::Service};

/// Run the standalone server or configuration check and return its exit status.
///
/// # Panics
/// Panics if the Tokio runtime cannot be created.
#[tokio::main(worker_threads = 2)]
async fn main() -> ExitCode {
    if run().await.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Report the package identity, check configuration or serve validated startup material.
///
/// # Errors
/// Rejects missing or extra arguments, version-output failure, invalid startup
/// material and serving or shutdown failures without exposing diagnostic values.
async fn run() -> Result<(), Failure> {
    let (path, check_only) = {
        let mut arguments = std::env::args_os().skip(1);
        let first = arguments.next().ok_or(Kind::Configuration)?;
        let version_only = first == "--version";
        if version_only && arguments.next().is_some() {
            return Err(Kind::Configuration.into());
        }
        if version_only {
            return std::io::stdout()
                .lock()
                .write_all(
                    concat!("logbrew-mcp ", env!("CARGO_PKG_VERSION"), " development\n").as_bytes(),
                )
                .map_err(|_| Kind::Unavailable.into());
        }
        let check_only = first == "--check-config";
        let path = if check_only {
            arguments.next().ok_or(Kind::Configuration)?
        } else {
            first
        };
        if arguments.next().is_some() {
            return Err(Kind::Configuration.into());
        }
        (PathBuf::from(path), check_only)
    };
    let service = Service::load(&path)?;
    if check_only {
        Ok(())
    } else {
        runtime::serve(service, shutdown()).await
    }
}

/// Wait for SIGINT or SIGTERM with fair signal polling.
///
/// # Errors
/// Returns Unavailable if either signal listener cannot be installed.
#[expect(
    clippy::integer_division_remainder_used,
    reason = "Tokio select uses remainder for fair branch polling; this is not cryptographic arithmetic."
)]
async fn shutdown() -> Result<(), Failure> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut interrupt =
        signal(SignalKind::interrupt()).map_err(|_| Failure::from(Kind::Unavailable))?;
    let mut terminate =
        signal(SignalKind::terminate()).map_err(|_| Failure::from(Kind::Unavailable))?;
    tokio::select! {
        _ = interrupt.recv() => Ok(()),
        _ = terminate.recv() => Ok(()),
    }
}
