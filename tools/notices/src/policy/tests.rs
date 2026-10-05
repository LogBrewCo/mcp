use serde_json::json;

use super::validate;
use crate::Result;

fn counted_summary(bans_notes: u32, license_helps: u32) -> String {
    let empty = json!({"errors":0_u32,"warnings":0_u32,"notes":0_u32,"helps":0_u32});
    format!(
        "{}\n",
        json!({"type":"summary","fields":{
            "bans":{"errors":0_u32,"warnings":0_u32,"notes":bans_notes,"helps":0_u32},
            "licenses":{"errors":0_u32,"warnings":0_u32,"notes":0_u32,"helps":license_helps},
            "sources":empty
        }})
    )
}

fn diagnostic(severity: &str, code: &str) -> String {
    format!(
        "{}\n",
        json!({"type":"diagnostic","fields":{"severity":severity,"code":code,"message":"synthetic policy result"}})
    )
}

#[test]
/// # Panics
/// Panics if unknown informational diagnostics or unmatched summary counts are accepted.
fn unknown_low_severity_diagnostics_and_unreconciled_counts_fail() {
    let clean = counted_summary(0, 0);
    for (severity, code) in [
        ("note", "future-warning"),
        ("help", "future-warning"),
        ("note", "skipped-by-root"),
        ("help", "skipped"),
        ("note", "accepted"),
    ] {
        assert!(
            validate(
                true,
                b"",
                format!("{}{clean}", diagnostic(severity, code)).as_bytes()
            )
            .is_err()
        );
    }
    for unmatched in [counted_summary(1, 0), counted_summary(0, 1)] {
        assert!(validate(true, b"", unmatched.as_bytes()).is_err());
    }
}

fn summary() -> String {
    counted_summary(0, 0)
}

#[test]
/// # Panics
/// Panics if documented informational records with exact counts fail or mismatched counts pass.
fn documented_informational_records_require_matching_check_totals() {
    let accepted = diagnostic("help", "accepted");
    let skipped = diagnostic("note", "skipped");
    let counted = counted_summary(1, 1);
    validate(
        true,
        b"",
        format!("{accepted}{skipped}{counted}").as_bytes(),
    )
    .expect("valid policy output");
    for output in [
        format!("{accepted}{skipped}{}", summary()),
        format!("{accepted}{counted}"),
        format!("{skipped}{counted}"),
        format!("{accepted}{accepted}{skipped}{counted}"),
        format!("{accepted}{skipped}{skipped}{counted}"),
        format!(
            "{}{counted}",
            accepted.replace("synthetic policy result", "")
        ),
    ] {
        assert!(validate(true, b"", output.as_bytes()).is_err());
    }
}

fn log(level: &str) -> String {
    format!(
        "{}\n",
        json!({"type":"log","fields":{"level":level,"message":"synthetic policy log","timestamp":"2026-10-04T00:00:00Z"}})
    )
}

#[test]
/// # Panics
/// Panics if clean output fails, forbidden log levels pass, or valid informational logs fail.
fn zero_exit_with_a_data_loading_error_cannot_pass_a_clean_summary() {
    let clean = summary();
    validate(true, b"", clean.as_bytes()).expect("valid policy output");
    for level in ["ERROR", "WARN", "unknown"] {
        assert!(validate(true, b"", format!("{}{clean}", log(level)).as_bytes()).is_err());
    }
    validate(true, b"", format!("{}{clean}", log("INFO")).as_bytes()).expect("valid policy output");
}

#[test]
/// # Errors
/// Propagates JSON decoding or missing synthetic summary-field errors.
///
/// # Panics
/// Panics if failed processes, warnings, incomplete records, or missing checks are accepted.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
)]
fn process_failure_warnings_and_incomplete_check_sets_are_rejected() -> Result<()> {
    let clean = summary();
    assert!(validate(false, b"", clean.as_bytes()).is_err());
    assert!(validate(true, b"unexpected stdout", clean.as_bytes()).is_err());
    assert!(validate(true, b"", b"").is_err());
    assert!(validate(true, b"", clean.trim_end().as_bytes()).is_err());
    for check in ["bans", "licenses", "sources"] {
        let mut changed: serde_json::Value = serde_json::from_str(&clean)?;
        let _removed: Option<serde_json::Value> = changed
            .get_mut("fields")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or("missing synthetic fields")?
            .remove(check);
        assert!(validate(true, b"", format!("{changed}\n").as_bytes()).is_err());
        for counter in ["warnings", "errors"] {
            let with_counter_error =
                clean.replacen(&format!("\"{counter}\":0"), &format!("\"{counter}\":1"), 1);
            assert!(validate(true, b"", with_counter_error.as_bytes()).is_err());
        }
    }
    Ok(())
}

#[test]
/// # Panics
/// Panics if malformed, unknown, duplicate, or out-of-order policy records are accepted.
fn malformed_unknown_duplicate_and_out_of_order_records_fail_closed() {
    let clean = summary();
    for output in [
        format!("{clean}{clean}"),
        format!("{clean}{}", log("INFO")),
        format!("\n{clean}"),
        format!("not json\n{clean}"),
        format!("{{\"type\":\"future\",\"fields\":{{}}}}\n{clean}"),
        clean.replace("\"errors\":0", "\"errors\":1,\"errors\":0"),
        clean.replace("\"sources\"", "\"advisories\""),
        clean.replace("\"helps\":0", "\"helps\":-1"),
        format!(
            "{}{clean}",
            log("INFO").replace(
                "\"level\":\"INFO\"",
                "\"level\":\"ERROR\",\"level\":\"INFO\""
            )
        ),
    ] {
        assert!(validate(true, b"", output.as_bytes()).is_err());
    }
    for severity in ["error", "warning", "bug", "unknown", "note", "help"] {
        let record =
            json!({"type":"diagnostic","fields":{"severity":severity,"message":"synthetic"}});
        assert!(validate(true, b"", format!("{record}\n{clean}").as_bytes()).is_err());
    }
}

#[test]
/// # Panics
/// Panics if record limits reject the valid boundary or accept oversized output.
fn record_bytes_and_record_count_have_explicit_limits() {
    let clean = summary();
    let long = "x".repeat(super::RECORD_BYTES);
    let record = json!({"type":"log","fields":{"level":"INFO","message":long,"timestamp":"now"}});
    assert!(validate(true, b"", format!("{record}\n{clean}").as_bytes()).is_err());
    let info = log("INFO");
    validate(
        true,
        b"",
        format!("{}{clean}", info.repeat(super::RECORDS - 1)).as_bytes(),
    )
    .expect("valid policy output");
    assert!(
        validate(
            true,
            b"",
            format!("{}{clean}", info.repeat(super::RECORDS)).as_bytes()
        )
        .is_err()
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
/// # Errors
/// Propagates readiness-read errors or exhaustion of the bounded readiness attempts.
fn await_readiness(mut ready: impl FnMut() -> Result<bool>) -> Result<()> {
    // Read past the native test harness prefix with bounded output.
    for _ in 0_u8..16_u8 {
        if ready()? {
            return Ok(());
        }
    }
    Err("missing descendant readiness".into())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod subprocess {
    use std::{
        io::{self, BufReader, Read as _, Write as _},
        net::{SocketAddr, TcpListener, TcpStream},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    use crate::Result;

    /// # Errors
    /// Propagates failure to locate the current test executable.
    fn fixture_command(mode: &str) -> Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        let _command: &mut Command = command
            .args([
                "--exact",
                "policy::tests::subprocess::native_child_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("LOGBREW_POLICY_TEST_MODE", mode);
        Ok(command)
    }

    /// # Errors
    /// Propagates address parsing, socket setup, or readiness-output errors.
    /// The final socket-read result is deliberately ignored so closure retires the fixture.
    fn connected_descendant() -> Result<()> {
        let address: SocketAddr = std::env::var("LOGBREW_POLICY_TEST_ADDRESS")?.parse()?;
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        std::io::stdout().write_all(b"descendant ready\n")?;
        std::io::stdout().flush()?;
        let mut byte = [0_u8; 1];
        // Parent socket closure also retires this fixture if the regression fails.
        let _read: io::Result<usize> = stream.read(&mut byte);
        Ok(())
    }

    /// # Errors
    /// Propagates fixture-command creation, child spawning, missing stdout, or readiness-read errors.
    fn spawn_connected_descendant() -> Result<()> {
        let mut descendant = fixture_command("connected-descendant")?
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdout = descendant.stdout.take().ok_or("missing fixture stdout")?;
        let mut reader = BufReader::new(stdout.take(4096));
        super::await_readiness(|| ready_line(&mut reader))?;
        drop(descendant);
        Ok(())
    }

    /// # Errors
    /// Propagates line-read failure or EOF before descendant readiness.
    fn ready_line(reader: &mut impl io::BufRead) -> Result<bool> {
        let mut line = Vec::new();
        if reader.read_until(b'\n', &mut line)? == 0 {
            return Err("descendant exited before readiness".into());
        }
        Ok(line.ends_with(b"descendant ready\n"))
    }

    /// # Errors
    /// Returns when writing the output flood fails.
    fn flood() -> Result<()> {
        let buffer = [b'x'; 8192];
        loop {
            std::io::stdout().write_all(&buffer)?;
        }
    }

    #[test]
    #[ignore = "native subprocess fixture invoked by the process-bound tests"]
    /// # Errors
    /// Propagates mode lookup, command spawning, signaling, or output failures;
    /// returns controlled errors for failure modes and unknown modes.
    fn native_child_fixture() -> Result<()> {
        match std::env::var("LOGBREW_POLICY_TEST_MODE")?.as_str() {
            "failure" => return Err("synthetic child failure".into()),
            "flood" => flood()?,
            "stall" => std::thread::sleep(Duration::from_secs(60)),
            "stopped" => {
                rustix::process::kill_process(
                    rustix::process::getpid(),
                    rustix::process::Signal::STOP,
                )?;
                std::thread::sleep(Duration::from_secs(60));
            }
            "inherited-pipe" => {
                let descendant = fixture_command("stall")?.stdin(Stdio::null()).spawn()?;
                drop(descendant);
            }
            "connected-descendant" => connected_descendant()?,
            "closed-pipe-descendant" => spawn_connected_descendant()?,
            "closed-pipe-descendant-failure" => {
                spawn_connected_descendant()?;
                return Err("synthetic child failure".into());
            }
            "success" => {
                std::io::stdout().write_all(b"synthetic stdout\n")?;
                std::io::stderr().write_all(b"synthetic stderr\n")?;
            }
            _ => return Err("invalid synthetic mode".into()),
        }
        Ok(())
    }

    #[test]
    /// # Errors
    /// Propagates socket setup, command capture, connection acceptance, or timeout setup errors.
    ///
    /// # Panics
    /// Panics if leader status differs or the descendant connection remains open.
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
    )]
    fn completed_commands_retire_descendants_with_closed_capture_pipes() -> Result<()> {
        for (mode, expected_success) in [
            ("closed-pipe-descendant", true),
            ("closed-pipe-descendant-failure", false),
        ] {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
            listener.set_nonblocking(true)?;
            let mut command = fixture_command(mode)?;
            let _command: &mut Command = command.env(
                "LOGBREW_POLICY_TEST_ADDRESS",
                listener.local_addr()?.to_string(),
            );
            let captured =
                super::super::process::capture(&mut command, Duration::from_secs(2), 4096)?;
            assert_eq!(captured.success, expected_success, "{mode}");
            // The leader waits for descendant readiness before it exits.
            let (mut stream, _address): (TcpStream, SocketAddr) = listener.accept()?;
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(Duration::from_millis(500)))?;
            let mut byte = [0_u8; 1];
            assert_closed(mode, stream.read(&mut byte));
        }
        Ok(())
    }

    /// # Panics
    /// Panics unless the descendant connection is closed or reset.
    fn assert_closed(mode: &str, result: io::Result<usize>) {
        match result {
            Ok(0) => {}
            Err(err) if err.kind() == io::ErrorKind::ConnectionReset => {}
            unexpected => panic!("{mode}: descendant connection remains open: {unexpected:?}"),
        }
    }

    #[test]
    /// # Errors
    /// Propagates fixture creation, valid-command capture, or captured-output UTF-8 errors.
    ///
    /// # Panics
    /// Panics if status, output, limits, or observed deadline behavior differs from expectations.
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Retain test assertions with diagnostic failures; reviewed 2026-10-05, revisit 2026-11-05"
    )]
    fn native_children_prove_status_pipe_limits_and_deadlines() -> Result<()> {
        let success = super::super::process::capture(
            &mut fixture_command("success")?,
            Duration::from_secs(2),
            4096,
        )?;
        assert!(success.success);
        assert!(String::from_utf8(success.stdout)?.contains("synthetic stdout"));
        assert_eq!(success.stderr, b"synthetic stderr\n");
        let failure = super::super::process::capture(
            &mut fixture_command("failure")?,
            Duration::from_secs(2),
            4096,
        )?;
        assert!(!failure.success);
        for mode in ["flood", "stall", "stopped", "inherited-pipe"] {
            let start = Instant::now();
            assert!(
                super::super::process::capture(
                    &mut fixture_command(mode)?,
                    Duration::from_millis(150),
                    4096
                )
                .is_err(),
                "{mode}"
            );
            assert!(start.elapsed() < Duration::from_secs(2), "{mode}");
        }
        Ok(())
    }
}
