use serde_json::json;

use super::validate;
use crate::Result;

fn counted_summary(bans_notes: u32, license_helps: u32) -> String {
    let empty = json!({"errors":0,"warnings":0,"notes":0,"helps":0});
    format!(
        "{}\n",
        json!({"type":"summary","fields":{
            "bans":{"errors":0,"warnings":0,"notes":bans_notes,"helps":0},
            "licenses":{"errors":0,"warnings":0,"notes":0,"helps":license_helps},
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
fn documented_informational_records_require_matching_check_totals() {
    let accepted = diagnostic("help", "accepted");
    let skipped = diagnostic("note", "skipped");
    let counted = counted_summary(1, 1);
    assert!(
        validate(
            true,
            b"",
            format!("{accepted}{skipped}{counted}").as_bytes()
        )
        .is_ok()
    );
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
fn zero_exit_with_a_data_loading_error_cannot_pass_a_clean_summary() {
    let clean = summary();
    assert!(validate(true, b"", clean.as_bytes()).is_ok());
    for level in ["ERROR", "WARN", "unknown"] {
        assert!(validate(true, b"", format!("{}{clean}", log(level)).as_bytes()).is_err());
    }
    assert!(validate(true, b"", format!("{}{clean}", log("INFO")).as_bytes()).is_ok());
}

#[test]
fn process_failure_warnings_and_incomplete_check_sets_are_rejected() -> Result<()> {
    let clean = summary();
    assert!(validate(false, b"", clean.as_bytes()).is_err());
    assert!(validate(true, b"unexpected stdout", clean.as_bytes()).is_err());
    assert!(validate(true, b"", b"").is_err());
    assert!(validate(true, b"", clean.trim_end().as_bytes()).is_err());
    for check in ["bans", "licenses", "sources"] {
        let mut changed: serde_json::Value = serde_json::from_str(&clean)?;
        changed
            .get_mut("fields")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or("missing synthetic fields")?
            .remove(check);
        assert!(validate(true, b"", format!("{changed}\n").as_bytes()).is_err());
        for counter in ["warnings", "errors"] {
            let changed =
                clean.replacen(&format!("\"{counter}\":0"), &format!("\"{counter}\":1"), 1);
            assert!(validate(true, b"", changed.as_bytes()).is_err());
        }
    }
    Ok(())
}

#[test]
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
fn record_bytes_and_record_count_have_explicit_limits() {
    let clean = summary();
    let long = "x".repeat(super::RECORD_BYTES);
    let record = json!({"type":"log","fields":{"level":"INFO","message":long,"timestamp":"now"}});
    assert!(validate(true, b"", format!("{record}\n{clean}").as_bytes()).is_err());
    let info = log("INFO");
    assert!(
        validate(
            true,
            b"",
            format!("{}{clean}", info.repeat(super::RECORDS - 1)).as_bytes()
        )
        .is_ok()
    );
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
mod subprocess {
    use std::{
        io::Write as _,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    use crate::Result;

    fn fixture_command(mode: &str) -> Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "policy::tests::subprocess::native_child_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("LOGBREW_POLICY_TEST_MODE", mode);
        Ok(command)
    }

    #[test]
    #[ignore = "native subprocess fixture invoked by the process-bound tests"]
    fn native_child_fixture() -> Result<()> {
        match std::env::var("LOGBREW_POLICY_TEST_MODE")?.as_str() {
            "failure" => return Err("synthetic child failure".into()),
            "flood" => {
                let buffer = [b'x'; 8192];
                loop {
                    std::io::stdout().write_all(&buffer)?;
                }
            }
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
            "success" => {
                std::io::stdout().write_all(b"synthetic stdout\n")?;
                std::io::stderr().write_all(b"synthetic stderr\n")?;
            }
            _ => return Err("invalid synthetic mode".into()),
        }
        Ok(())
    }

    #[test]
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
