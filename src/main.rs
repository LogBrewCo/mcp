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
    let path = {
        let mut arguments = std::env::args_os().skip(1);
        let path = arguments
            .next()
            .map(PathBuf::from)
            .ok_or(Kind::Configuration)?;
        if arguments.next().is_some() {
            return Err(Kind::Configuration.into());
        }
        path
    };
    let service = Service::load(&path)?;
    runtime::serve(service, shutdown()).await
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
