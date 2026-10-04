//! Offline configuration checks before replacing a running process.

use std::{ffi::OsStr, io::ErrorKind};

use super::*;

fn check(config: &Path) -> std::io::Result<Process> {
    Process::command()
        .arg("--check-config")
        .arg(config)
        .spawn()
        .map(Process)
}

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
    assert_eq!(preflight.wait().await.expect("check exits").code(), Some(0));
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

#[tokio::test]
async fn configuration_check_rejects_invalid_material_without_disclosing_it() {
    for invalid in ["configuration", "catalog", "key", "policy", "secret"] {
        let fixture = Fixture::new().expect("fixture");
        match invalid {
            "configuration" => {
                fs::write(&fixture.config, br#"{"secret":"SYNTHETIC_PRIVATE_VALUE"}"#)
                    .expect("invalid configuration");
            }
            "catalog" => fs::write(fixture.directory.0.join("catalog.json"), b"{}")
                .expect("changed catalog digest"),
            "key" => {
                let other = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
                    .expect("different key");
                fs::write(
                    fixture.directory.0.join("key.pem"),
                    other.signing_key.serialize_pem(),
                )
                .expect("mismatched key");
            }
            "policy" => fs::write(
                fixture.directory.0.join("clients.json"),
                br#"{"version":"1","clients":["private-client","private-client"]}"#,
            )
            .expect("invalid policy"),
            _ => fs::set_permissions(
                fixture.directory.0.join("secret"),
                fs::Permissions::from_mode(0o644),
            )
            .expect("unsafe secret permissions"),
        }
        let mut process = check(&fixture.config).expect("native executable");
        assert_eq!(
            process.wait().await.expect("bounded private exit").code(),
            Some(1),
            "invalid {invalid} must fail the configuration check"
        );
        drop(TcpListener::bind(fixture.address).expect("invalid check did not bind"));
    }
}

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
            Some(1)
        );
        drop(TcpListener::bind(fixture.address).expect("invalid arguments did not bind"));
    }
}
