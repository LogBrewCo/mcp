//! `LogBrew`'s standalone HTTPS MCP process.

use std::{path::PathBuf, process::ExitCode};

use logbrew_mcp::{Failure, error::Kind, runtime, startup::Service};

#[tokio::main(worker_threads = 2)]
async fn main() -> ExitCode {
    if run().await.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

async fn run() -> Result<(), Failure> {
    let (path, check_only) = {
        let mut arguments = std::env::args_os().skip(1);
        let first = arguments.next().ok_or(Kind::Configuration)?;
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
