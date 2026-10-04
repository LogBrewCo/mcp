use std::{
    io::{self, Read},
    os::unix::process::CommandExt as _,
    process::{Child, Command, Stdio},
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

impl Drop for Process {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = kill_process_group(self.group, Signal::KILL);
            let _ = self.child.wait();
        }
    }
}

struct Pipe<R> {
    reader: R,
    bytes: Vec<u8>,
    closed: bool,
}

impl<R: Read + AsFd> Pipe<R> {
    fn new(reader: R) -> Result<Self> {
        fcntl_setfl(&reader, OFlags::NONBLOCK)
            .map_err(|err| io::Error::other(format!("nonblocking pipe setup: {err}")))?;
        Ok(Self {
            reader,
            bytes: Vec::new(),
            closed: false,
        })
    }

    fn drain(&mut self, limit: usize) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        let mut buffer = [0_u8; 8192];
        // Bound work per pipe so a busy writer cannot starve the deadline.
        for _ in 0..8 {
            match self.reader.read(&mut buffer) {
                Ok(0) => {
                    self.closed = true;
                    break;
                }
                Ok(count) => {
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
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }
}

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
            let status = process.child.wait()?;
            process.reaped = true;
            return Ok(Captured {
                success: status.success(),
                stdout: stdout.bytes,
                stderr: stderr.bytes,
            });
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
