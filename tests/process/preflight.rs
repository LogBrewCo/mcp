//! Offline configuration checks before replacing a running process.

use std::{ffi::OsStr, io::ErrorKind};

use super::*;

/// Spawn the configuration check with one supplied path.
///
/// # Errors
/// Returns an error if the test executable cannot be started.
fn check(config: &Path) -> std::io::Result<Process> {
    Process::command()
        .arg("--check-config")
        .arg(config)
        .spawn()
        .map(Process)
}

/// Check configuration without disturbing a running service or contacting upstreams.
///
/// # Panics
/// Panics if fixture setup fails, the check changes listener or upstream state,
/// or either process fails to exit with the expected status.
#[tokio::test]
async fn configuration_check_leaves_the_running_service_and_upstreams_untouched() {
    let fixture = Fixture::new().expect("fixture");
    let introspection = TcpListener::bind("127.0.0.1:0").expect("introspection sentinel");
    let execution = TcpListener::bind("127.0.0.1:0").expect("execution sentinel");
    let mut config: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.config).expect("configuration"))
            .expect("configuration JSON");
    for (name, listener) in [
        ("introspection_endpoint", &introspection),
        ("execution_endpoint", &execution),
    ] {
        *config.get_mut(name).expect("endpoint") = json!(format!(
            "https://{}/check-must-not-connect",
            listener.local_addr().expect("sentinel address")
        ));
        listener
            .set_nonblocking(true)
            .expect("nonblocking sentinel");
    }
    fs::write(
        &fixture.config,
        serde_json::to_vec(&config).expect("encode"),
    )
    .expect("configure sentinels");
    let mut running = Process::start(&fixture.config).expect("running server");
    fixture.ready(&mut running).await.expect("service ready");
    let mut preflight = check(&fixture.config).expect("offline check");
    assert_eq!(
        preflight.wait().await.expect("check exits").code(),
        Some(0_i32)
    );
    fixture
        .ready(&mut running)
        .await
        .expect("original service remains ready");
    for listener in [introspection, execution] {
        assert!(
            listener
                .accept()
                .is_err_and(|error| error.kind() == ErrorKind::WouldBlock),
            "configuration checks must not contact either upstream"
        );
    }
    running.signal(Signal::TERM).expect("stop running service");
    assert!(running.wait().await.expect("clean shutdown").success());
}

/// Reject invalid startup material before opening the service listener.
///
/// # Panics
/// Panics if fixture setup fails, an invalid check succeeds or fails to exit,
/// or the configured address remains bound after the check.
#[tokio::test]
async fn configuration_check_rejects_invalid_material_without_disclosing_it() {
    for invalid in ["configuration", "catalog", "key", "policy", "secret"] {
        let fixture = Fixture::new().expect("fixture");
        invalid_material(&fixture, invalid).expect("invalid material");
        let mut process = check(&fixture.config).expect("native executable");
        assert_eq!(
            process.wait().await.expect("bounded private exit").code(),
            Some(1_i32),
            "invalid {invalid} must fail the configuration check"
        );
        drop(TcpListener::bind(fixture.address).expect("invalid check did not bind"));
    }
}

/// Replace one fixture input with an invalid configuration, file or permission.
///
/// # Errors
/// Returns an error if certificate generation, a file write or permission change fails.
fn invalid_material(fixture: &Fixture, invalid: &str) -> TestResult<()> {
    match invalid {
        "configuration" => fs::write(&fixture.config, br#"{"secret":"SYNTHETIC_PRIVATE_VALUE"}"#)?,
        "catalog" => fs::write(fixture.directory.0.join("catalog.json"), b"{}")?,
        "key" => {
            let other = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
            fs::write(
                fixture.directory.0.join("key.pem"),
                other.signing_key.serialize_pem(),
            )?;
        }
        "policy" => fs::write(
            fixture.directory.0.join("clients.json"),
            br#"{"version":"1","clients":["private-client","private-client"]}"#,
        )?,
        _ => fs::set_permissions(
            fixture.directory.0.join("secret"),
            fs::Permissions::from_mode(0o644),
        )?,
    }
    Ok(())
}

/// Reject missing paths, unknown options and extra configuration-check arguments.
///
/// # Panics
/// Panics if fixture setup or process execution fails, rejected arguments return
/// the wrong status, or a rejected invocation leaves the address bound.
#[tokio::test]
async fn configuration_check_requires_one_path_and_rejects_extra_arguments() {
    let fixture = Fixture::new().expect("fixture");
    let flag = OsStr::new("--check-config");
    let path = fixture.config.as_os_str();
    for arguments in [
        vec![],
        vec![flag],
        vec![flag, path, path],
        vec![path, flag],
        vec![OsStr::new("--unknown-option"), path],
    ] {
        let mut process = Process::command()
            .args(arguments)
            .spawn()
            .map(Process)
            .expect("native executable");
        assert_eq!(
            process.wait().await.expect("argument failure").code(),
            Some(1_i32)
        );
        drop(TcpListener::bind(fixture.address).expect("invalid arguments did not bind"));
    }
}
