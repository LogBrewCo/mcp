//! Exercise the native executable with disposable TLS material and offline upstreams.

#[cfg(target_os = "linux")]
#[path = "process/authenticated.rs"]
mod authenticated;
#[path = "support/hpack.rs"]
mod hpack;
#[path = "process/http2.rs"]
mod http2;
#[path = "support/peer.rs"]
mod peer;
#[path = "process/preflight.rs"]
mod preflight;

use std::{
    fmt::Write as _,
    fs,
    io::Read as _,
    net::{SocketAddr, TcpListener},
    os::unix::fs::{DirBuilderExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use rustix::process::{Pid, Signal, kill_process};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    time::{Instant, sleep, timeout},
};

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type TlsStream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Directory(PathBuf);

impl Directory {
    /// Create a private temporary directory for this executable fixture.
    ///
    /// # Errors
    /// Returns an error if the fixture directory cannot be created.
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "logbrew-mcp-process-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }

    /// Write a fixture file and apply its supplied permission mode.
    ///
    /// # Errors
    /// Returns an error if the file write or permission change fails.
    fn write(&self, name: &str, bytes: &[u8], mode: u32) -> std::io::Result<PathBuf> {
        let path = self.0.join(name);
        fs::write(&path, bytes)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
        Ok(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    directory: Directory,
    config: PathBuf,
    address: SocketAddr,
    certificate: String,
}

impl Fixture {
    /// Prepare synthetic configuration, credentials, TLS material and a read catalog.
    ///
    /// # Errors
    /// Returns an error if directory or address selection, certificate generation,
    /// file writes, catalog/configuration encoding or digest formatting fails.
    fn new() -> TestResult<Self> {
        let directory = Directory::new()?;
        let address = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
        let pem = certificate.cert.pem();
        let certificate_file = directory.write("certificate.pem", pem.as_bytes(), 0o644)?;
        let key = directory.write(
            "key.pem",
            certificate.signing_key.serialize_pem().as_bytes(),
            0o600,
        )?;
        let secret = directory.write("secret", b"SYNTHETIC_MACHINE_SECRET", 0o600)?;
        let clients = directory.write("clients.json", br#"{"version":"1","clients":[]}"#, 0o600)?;
        let catalog = serde_json::to_vec(&json!({"format_version":1_i32,"operations":[{
            "id":"logs.read.v1","info":{"summary":"Read logs","permission":"logs:read",
                "documentation":"https://docs.example/logs","stability":"stable","cost":"one read","safety":"read_only"},
            "input_schema":{"type":"object","additionalProperties":false},
            "output_schema":{"type":"object"}
        }]}))?;
        let catalog_file = directory.write("catalog.json", &catalog, 0o644)?;
        let mut digest = String::new();
        for byte in Sha256::digest(&catalog) {
            write!(digest, "{byte:02x}")?;
        }
        let config = serde_json::to_vec(&json!({
            "version":"2","listen":address.to_string(),"client_allowlist_file":clients,
            "resource":format!("https://localhost:{}/mcp", address.port()),
            "issuer":"https://issuer.example", "required_scope":"mcp:read",
            "introspection_endpoint":"https://127.0.0.1:1/introspect",
            "introspection_client_id":"synthetic-introspection", "introspection_secret_file":secret,
            "execution_endpoint":"https://127.0.0.1:1/execute", "execution_client_id":"synthetic-execution",
            "execution_secret_file":secret,"catalog_file":catalog_file,"catalog_sha256":digest,
            "certificate_file":certificate_file,"private_key_file":key
        }))?;
        let config = directory.write("config.json", &config, 0o600)?;
        Ok(Self {
            directory,
            config,
            address,
            certificate: pem,
        })
    }

    /// Build a bounded HTTP/1 client with fixture certificate trust.
    ///
    /// # Errors
    /// Returns an error if certificate parsing or client construction fails.
    fn client(&self) -> TestResult<reqwest::Client> {
        Ok(reqwest::Client::builder()
            .no_proxy()
            .http1_only()
            .pool_max_idle_per_host(0)
            .timeout(Duration::from_millis(500))
            .add_root_certificate(reqwest::Certificate::from_pem(self.certificate.as_bytes())?)
            .build()?)
    }

    /// Wait for the executable's protected-resource metadata.
    ///
    /// # Errors
    /// Returns an error if client setup, process inspection, response parsing
    /// or the bounded readiness check fails.
    ///
    /// # Panics
    /// Panics if the metadata response has an unexpected status or resource.
    async fn ready(&self, process: &mut Process) -> TestResult<()> {
        readiness(self, process).await
    }

    /// Connect to the executable with fixture certificate trust and no ALPN request.
    ///
    /// # Errors
    /// Returns an error if trust setup, TCP connection or TLS negotiation fails.
    async fn tls(&self) -> TestResult<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
        self.tls_protocol(None).await
    }

    /// Connect to the executable with fixture trust and the selected ALPN protocol.
    ///
    /// # Errors
    /// Returns an error if trust setup, TCP connection or TLS negotiation fails.
    async fn tls_protocol(
        &self,
        protocol: Option<&[u8]>,
    ) -> TestResult<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
        peer::tls(self.address, self.certificate.as_bytes(), protocol).await
    }
}

struct Process(Child);

impl Process {
    /// Use the selected package executable, or Cargo's binary when no path is supplied.
    /// A supplied path never falls back to the source binary after a startup failure.
    fn command() -> Command {
        let executable: std::ffi::OsString = std::env::var_os("LOGBREW_MCP_PACKAGE_EXECUTABLE")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_logbrew-mcp").into());
        let mut command = Command::new(executable);
        let _: &mut Command = command
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    /// Spawn the executable with its configuration and cleared environment.
    ///
    /// # Errors
    /// Returns an error if the test executable cannot be started.
    fn start(config: &Path) -> std::io::Result<Self> {
        Self::start_with_roots(config, None)
    }

    /// Spawn the executable with an optional fixture certificate trust file.
    ///
    /// # Errors
    /// Returns an error if the test executable cannot be started.
    fn start_with_roots(config: &Path, roots: Option<&Path>) -> std::io::Result<Self> {
        let mut command = Self::command();
        let _: &mut Command = command.arg(config);
        if let Some(roots) = roots {
            let _: &mut Command = command.env("SSL_CERT_FILE", roots);
        }
        command.spawn().map(Self)
    }

    /// Send the supplied signal to the fixture process.
    ///
    /// # Errors
    /// Returns an error if the process identifier cannot be represented or
    /// validated, or the operating system rejects the signal.
    fn signal(&self, signal: Signal) -> TestResult<()> {
        let pid = Pid::from_raw(i32::try_from(self.0.id())?)
            .ok_or_else(|| std::io::Error::other("invalid child PID"))?;
        kill_process(pid, signal)?;
        Ok(())
    }

    /// Wait for process exit and check its bounded diagnostic output.
    ///
    /// # Errors
    /// Returns an error if process inspection, its exit deadline or output reading fails.
    ///
    /// # Panics
    /// Panics if the executable writes any stdout or stderr diagnostics.
    async fn wait(&mut self) -> TestResult<ExitStatus> {
        let status = process_exit(&mut self.0).await?;
        let mut output = Vec::new();
        if let Some(stdout) = self.0.stdout.take() {
            let _: usize = stdout.take(4096).read_to_end(&mut output)?;
        }
        if let Some(stderr) = self.0.stderr.take() {
            let _: usize = stderr.take(4096).read_to_end(&mut output)?;
        }
        assert!(
            output.is_empty(),
            "process must not emit configuration or credential diagnostics"
        );
        Ok(status)
    }
}

/// Poll metadata until the executable is ready within five seconds.
///
/// # Errors
/// Returns an error if client setup, process inspection, deadline construction
/// or response parsing fails, the process exits early, or readiness expires.
///
/// # Panics
/// Panics if a received metadata response has an unexpected status or resource.
async fn readiness(fixture: &Fixture, process: &mut Process) -> TestResult<()> {
    let client = fixture.client()?;
    let url = format!(
        "https://localhost:{}/.well-known/oauth-protected-resource/mcp",
        fixture.address.port()
    );
    let end = Instant::now()
        .checked_add(Duration::from_secs(5))
        .ok_or("fixture readiness deadline overflow")?;
    loop {
        if process.0.try_wait()?.is_some() {
            return Err(std::io::Error::other("process exited before readiness").into());
        }
        if let Ok(response) = client.get(&url).send().await {
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            let metadata: serde_json::Value = response.json().await?;
            assert_eq!(
                metadata.get("resource"),
                Some(&json!(format!(
                    "https://localhost:{}/mcp",
                    fixture.address.port()
                )))
            );
            return Ok(());
        }
        if Instant::now() >= end {
            return Err(std::io::Error::other("readiness deadline exceeded").into());
        }
        sleep(Duration::from_millis(10)).await;
    }
}

/// Poll for the fixture process's exit within eight seconds.
///
/// # Errors
/// Returns an error if the deadline cannot be represented, process inspection
/// fails, or the process remains running beyond the deadline.
async fn process_exit(child: &mut Child) -> TestResult<ExitStatus> {
    let end = Instant::now()
        .checked_add(Duration::from_secs(8))
        .ok_or("fixture process deadline overflow")?;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= end {
            return Err(std::io::Error::other("exit deadline exceeded").into());
        }
        sleep(Duration::from_millis(10)).await;
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _kill = self.0.kill();
        let _reap = self.0.wait();
    }
}

/// Stop the native HTTPS process with each supported shutdown signal.
///
/// # Panics
/// Panics if fixture setup, readiness or signaling fails, the process does not
/// exit successfully within its bound, or its listener remains occupied.
#[tokio::test]
async fn interrupt_and_terminate_stop_the_native_https_process_and_release_its_port() {
    for signal in [Signal::INT, Signal::TERM] {
        let fixture = Fixture::new().expect("disposable fixture");
        let mut process = Process::start(&fixture.config).expect("native executable");
        fixture
            .ready(&mut process)
            .await
            .expect("offline startup readiness");
        process.signal(signal).expect("shutdown signal");
        assert!(process.wait().await.expect("bounded exit").success());
        drop(TcpListener::bind(fixture.address).expect("listener released"));
    }
}

/// Complete bounded shutdown while a peer withholds its TLS handshake.
///
/// # Panics
/// Panics if setup or signaling fails, shutdown misses its bound or success
/// status, or the service listener is not released.
#[tokio::test]
async fn stalled_tls_handshake_does_not_prevent_bounded_shutdown() {
    let fixture = Fixture::new().expect("fixture");
    let mut process = Process::start(&fixture.config).expect("native executable");
    fixture.ready(&mut process).await.expect("readiness");
    let _stalled = tokio::net::TcpStream::connect(fixture.address)
        .await
        .expect("stalled peer");
    sleep(Duration::from_millis(30)).await;
    process.signal(Signal::TERM).expect("shutdown signal");
    assert!(process.wait().await.expect("bounded TLS drain").success());
    drop(TcpListener::bind(fixture.address).expect("listener released"));
}

/// Close a verified TLS peer that withholds complete HTTP headers.
///
/// # Panics
/// Panics if setup or I/O fails, the peer remains open beyond its deadline,
/// or the process does not exit successfully after the shutdown signal.
#[tokio::test]
async fn incomplete_http_headers_expire_on_a_verified_tls_connection() {
    let fixture = Fixture::new().expect("fixture");
    let mut process = Process::start(&fixture.config).expect("native executable");
    fixture.ready(&mut process).await.expect("readiness");
    let mut tls = fixture.tls().await.expect("verified TLS");
    tls.write_all(b"GET /.well-known/oauth-protected-resource/mcp HTTP/1.1\r\nHost:")
        .await
        .expect("partial headers");
    let mut bytes = [0; 1];
    let result = timeout(Duration::from_secs(7), tls.read(&mut bytes))
        .await
        .expect("header deadline");
    assert!(matches!(result, Ok(0) | Err(_)));
    process.signal(Signal::INT).expect("shutdown signal");
    assert!(process.wait().await.expect("exit").success());
}

/// Expire occupied protocol-prefix slots and recover listener capacity.
///
/// # Panics
/// Panics if setup fails, excess peers are admitted, occupied slots fail to
/// close within the bound, or listener recovery or clean shutdown fails.
#[tokio::test]
async fn idle_and_partial_protocol_prefixes_expire_and_the_listener_recovers() {
    let fixture = Fixture::new().expect("fixture");
    let mut process = Process::start(&fixture.config).expect("native executable");
    fixture.ready(&mut process).await.expect("readiness");
    sleep(Duration::from_millis(50)).await;
    let peers = timeout(Duration::from_secs(3), occupied_prefixes(&fixture))
        .await
        .expect("all slots occupied before the prefix deadline")
        .expect("verified TLS prefixes");
    let mut excess = tokio::net::TcpStream::connect(fixture.address)
        .await
        .expect("excess peer");
    let mut bytes = [0; 1];
    let result = timeout(Duration::from_millis(250), excess.read(&mut bytes))
        .await
        .expect("capacity rejection before prefix expiry");
    assert!(matches!(result, Ok(0) | Err(_)));
    timeout(Duration::from_secs(7), closed_prefixes(peers))
        .await
        .expect("all protocol detection slots expire");
    fixture
        .ready(&mut process)
        .await
        .expect("listener recovered");
    process.signal(Signal::TERM).expect("shutdown signal");
    assert!(process.wait().await.expect("exit").success());
    drop(TcpListener::bind(fixture.address).expect("listener released"));
}

/// Occupy 64 verified TLS connections with idle or partial protocol prefixes.
///
/// # Errors
/// Returns an error if a fixture TLS connection or protocol-prefix write fails.
async fn occupied_prefixes(fixture: &Fixture) -> TestResult<Vec<TlsStream>> {
    let mut peers = Vec::new();
    for prefix in [b"".as_slice(), b"P", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r"]
        .into_iter()
        .cycle()
        .take(64)
    {
        let mut tls = fixture.tls().await?;
        tls.write_all(prefix).await?;
        peers.push(tls);
    }
    Ok(peers)
}

/// Check that every occupied protocol-prefix peer has closed.
///
/// # Panics
/// Panics if a peer supplies bytes instead of closing or returning a read error.
async fn closed_prefixes(peers: Vec<TlsStream>) {
    for mut peer in peers {
        let mut bytes = [0; 1];
        assert!(matches!(peer.read(&mut bytes).await, Ok(0) | Err(_)));
    }
}

/// Reject invalid configuration and mismatched TLS material before listening.
///
/// # Panics
/// Panics if fixture setup or process execution fails, invalid startup returns
/// an unexpected status, or the configured service address remains occupied.
#[tokio::test]
async fn invalid_configuration_and_mismatched_tls_keys_exit_without_listening() {
    let fixture = Fixture::new().expect("fixture");
    let invalid = fixture
        .directory
        .write("invalid.json", b"{\"secret\":\"SYNTHETIC_SECRET\"}", 0o600)
        .expect("invalid file");
    let mut process = Process::start(&invalid).expect("native executable");
    assert_eq!(
        process.wait().await.expect("configuration exit").code(),
        Some(1_i32)
    );
    let other =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("different key");
    drop(
        fixture
            .directory
            .write(
                "key.pem",
                other.signing_key.serialize_pem().as_bytes(),
                0o600,
            )
            .expect("mismatched key"),
    );
    let mut process = Process::start(&fixture.config).expect("native executable");
    assert_eq!(process.wait().await.expect("TLS exit").code(), Some(1_i32));
    drop(TcpListener::bind(fixture.address).expect("no listener on invalid startup"));
}

/// Reject invalid client-policy files and recover with a valid deny-all policy.
///
/// # Panics
/// Panics if fixture setup or policy replacement fails, invalid policies start
/// listening or return the wrong status, or valid recovery and shutdown fail.
#[tokio::test]
async fn invalid_client_policy_exits_before_binding_and_valid_policy_recovers() {
    let fixture = Fixture::new().expect("fixture");
    let oversized = vec![b' '; (16 << 10) + 1];
    for (bytes, mode) in [
        (
            br#"{"version":"1","clients":["private-client","private-client"]}"#.as_slice(),
            0o600,
        ),
        (br#"{"version":"1","clients":[]}"#.as_slice(), 0o644),
        (b"{}".as_slice(), 0o600),
        (oversized.as_slice(), 0o600),
    ] {
        drop(
            fixture
                .directory
                .write("clients.json", bytes, mode)
                .expect("invalid policy"),
        );
        let mut process = Process::start(&fixture.config).expect("native executable");
        assert_eq!(
            process.wait().await.expect("bounded private exit").code(),
            Some(1_i32)
        );
        drop(TcpListener::bind(fixture.address).expect("invalid policy did not bind"));
    }
    fs::remove_file(fixture.directory.0.join("clients.json")).expect("remove disposable policy");
    let mut process = Process::start(&fixture.config).expect("native executable");
    assert_eq!(
        process.wait().await.expect("missing policy exit").code(),
        Some(1_i32)
    );
    let target = fixture
        .directory
        .write(
            "policy-target.json",
            br#"{"version":"1","clients":[]}"#,
            0o600,
        )
        .expect("symlink target");
    std::os::unix::fs::symlink(target, fixture.directory.0.join("clients.json"))
        .expect("disposable policy symlink");
    let mut process = Process::start(&fixture.config).expect("native executable");
    assert_eq!(
        process.wait().await.expect("symlink rejection").code(),
        Some(1_i32)
    );
    drop(TcpListener::bind(fixture.address).expect("no listener on symlink policy"));
    fs::remove_file(fixture.directory.0.join("clients.json")).expect("remove disposable symlink");
    drop(
        fixture
            .directory
            .write("clients.json", br#"{"version":"1","clients":[]}"#, 0o600)
            .expect("valid deny-all policy"),
    );
    let mut process = Process::start(&fixture.config).expect("native executable");
    fixture.ready(&mut process).await.expect("offline recovery");
    process.signal(Signal::TERM).expect("shutdown");
    assert!(process.wait().await.expect("clean exit").success());
    drop(TcpListener::bind(fixture.address).expect("listener released"));
}

/// Close excess connections before TLS and recover after admitted peers leave.
///
/// # Panics
/// Panics if setup fails, excess peers are admitted, existing peers are closed
/// early, or listener recovery and clean shutdown fail.
#[tokio::test]
async fn connections_above_capacity_are_closed_before_tls_and_capacity_recovers() {
    let fixture = Fixture::new().expect("fixture");
    let mut process = Process::start(&fixture.config).expect("native executable");
    fixture.ready(&mut process).await.expect("readiness");
    sleep(Duration::from_millis(50)).await;
    let mut peers = Vec::new();
    for _ in 0_i32..64_i32 {
        peers.push(
            tokio::net::TcpStream::connect(fixture.address)
                .await
                .expect("idle peer"),
        );
    }
    sleep(Duration::from_millis(50)).await;
    let mut excess = tokio::net::TcpStream::connect(fixture.address)
        .await
        .expect("excess peer");
    let mut bytes = [0; 1];
    let result = timeout(Duration::from_secs(1), excess.read(&mut bytes))
        .await
        .expect("immediate capacity rejection");
    assert!(matches!(result, Ok(0) | Err(_)));
    for peer in &peers {
        assert!(
            peer.try_read(&mut bytes)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }
    drop(peers);
    fixture
        .ready(&mut process)
        .await
        .expect("capacity recovered");
    process.signal(Signal::TERM).expect("shutdown signal");
    assert!(process.wait().await.expect("exit").success());
}

/// Preserve an existing listener when valid startup cannot bind its address.
///
/// # Panics
/// Panics if setup or process execution fails, the bind failure returns the
/// wrong status, or the existing listener's address changes.
#[tokio::test]
async fn valid_configuration_does_not_replace_an_existing_listener() {
    let fixture = Fixture::new().expect("fixture");
    let existing = TcpListener::bind(fixture.address).expect("existing listener");
    let mut process = Process::start(&fixture.config).expect("native executable");
    assert_eq!(
        process.wait().await.expect("bind failure exit").code(),
        Some(1_i32)
    );
    assert_eq!(
        existing.local_addr().expect("original listener preserved"),
        fixture.address
    );
}
