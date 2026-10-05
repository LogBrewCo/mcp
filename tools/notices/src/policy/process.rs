use std::{
    io::{self, Read},
    os::unix::process::CommandExt as _,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use rustix::{
    fd::AsFd,
    fs::{OFlags, fcntl_setfl},
    process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid},
};

use crate::{Result, error};

pub(super) struct Captured {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

// Keep the leader unreaped until group cleanup so its PID cannot be reused.
struct Process {
    child: Child,
    group: Pid,
    reaped: bool,
}

impl Process {
    /// # Errors
    /// Propagates failure to wait for the leader process. Process-group cleanup
    /// is best effort; this result does not certify descendant retirement.
    fn finish(&mut self) -> Result<ExitStatus> {
        // As in Drop, termination is best effort; an exited-only group can reject signals.
        let _termination: rustix::io::Result<()> = kill_process_group(self.group, Signal::KILL);
        let status: ExitStatus = self.child.wait()?;
        self.reaped = true;
        Ok(status)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if !self.reaped {
            // Attempt reaping even when best-effort group termination fails.
            let _termination: rustix::io::Result<()> = kill_process_group(self.group, Signal::KILL);
            let _status: io::Result<ExitStatus> = self.child.wait();
        }
    }
}

struct Pipe<R> {
    reader: R,
    bytes: Vec<u8>,
    closed: bool,
}

impl<R: Read + AsFd> Pipe<R> {
    /// # Errors
    /// Propagates errors when setting the pipe's nonblocking flags.
    fn new(reader: R) -> Result<Self> {
        fcntl_setfl(&reader, OFlags::NONBLOCK)
            .map_err(|err| io::Error::other(format!("nonblocking pipe setup: {err}")))?;
        Ok(Self {
            reader,
            bytes: Vec::new(),
            closed: false,
        })
    }

    /// # Errors
    /// Rejects an invalid buffer count, byte-count overflow, and output that
    /// exceeds the pipe limit.
    fn append(&mut self, buffer: &[u8], count: usize, limit: usize) -> Result<()> {
        if self
            .bytes
            .len()
            .checked_add(count)
            .is_none_or(|size| size > limit)
        {
            return Err(error("cargo-deny output exceeded its byte limit"));
        }
        self.bytes.extend_from_slice(
            buffer
                .get(..count)
                .ok_or_else(|| error("invalid pipe read"))?,
        );
        Ok(())
    }

    /// # Errors
    /// Propagates read errors other than interruption or would-block, and
    /// rejects output that exceeds the pipe budget.
    fn read_once(&mut self, buffer: &mut [u8], limit: usize) -> Result<bool> {
        match self.reader.read(buffer) {
            Ok(0) => {
                self.closed = true;
                Ok(false)
            }
            Ok(count) => {
                self.append(buffer, count, limit)?;
                Ok(true)
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => Ok(true),
            Err(err) => Err(err.into()),
        }
    }

    /// # Errors
    /// Returns an error for pipe reads or output-budget violations during the
    /// bounded drain.
    fn drain(&mut self, limit: usize) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        let mut buffer = [0_u8; 8192];
        drain_reads(self, &mut buffer, limit)
    }
}

/// # Errors
/// Propagates pipe-read and output-budget failures across the bounded batch.
fn drain_reads<R: Read + AsFd>(pipe: &mut Pipe<R>, buffer: &mut [u8], limit: usize) -> Result<()> {
    // Bound work per pipe so a busy writer cannot starve the deadline.
    for _ in 0_u8..8_u8 {
        if !pipe.read_once(buffer, limit)? {
            break;
        }
    }
    Ok(())
}

/// # Errors
/// Returns an error for process or pipe setup, PID conversion, deadline
/// expiry, output-budget violations, read failures, or leader-wait failures.
/// Cleanup attempts to kill the process group and reap the leader; it does not
/// prove every descendant has retired or establish a kernel-enforced deadline.
pub(super) fn capture(command: &mut Command, timeout: Duration, limit: usize) -> Result<Captured> {
    let start = Instant::now();
    let child = command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| io::Error::other(format!("policy child spawn: {err}")))?;
    let group =
        Pid::from_raw(i32::try_from(child.id())?).ok_or_else(|| error("invalid child PID"))?;
    let mut process = Process {
        child,
        group,
        reaped: false,
    };
    let mut stdout = Pipe::new(
        process
            .child
            .stdout
            .take()
            .ok_or_else(|| error("missing stdout pipe"))?,
    )?;
    let mut stderr = Pipe::new(
        process
            .child
            .stderr
            .take()
            .ok_or_else(|| error("missing stderr pipe"))?,
    )?;
    loop {
        if start.elapsed() >= timeout {
            return Err(error("cargo-deny exceeded its deadline"));
        }
        stdout.drain(limit)?;
        stderr.drain(limit)?;
        if stdout.closed
            && stderr.closed
            && waitid(
                WaitId::Pid(group),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            )
            .map_err(|err| io::Error::other(format!("policy child observation: {err}")))?
            .is_some_and(|status| status.exited() || status.killed() || status.dumped())
        {
            let status = process.finish()?;
            return Ok(Captured {
                success: status.success(),
                stdout: stdout.bytes,
                stderr: stderr.bytes,
            });
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
