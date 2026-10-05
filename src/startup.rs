//! Bounded startup files and explicit listener configuration.

use std::{
    fs::{self, File},
    io::Read as _,
    net::SocketAddr,
    os::unix::fs::MetadataExt as _,
    path::Path,
};

use rustls::pki_types::pem::PemObject as _;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{
    Failure,
    catalog::Catalog,
    clients::ClientAllowlist,
    error::Kind,
    json as strict_json, protocol,
    upstream::{MachineCredential, Upstream, UpstreamOptions},
};

/// Versioned operator configuration contains secret-file references only.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Configuration format version.
    pub version: String,
    /// Numeric listener IP and port.
    pub listen: String,
    /// Canonical protected resource URL.
    pub resource: String,
    /// Expected authorization issuer.
    pub issuer: String,
    /// Required delegated scope.
    pub required_scope: String,
    /// Private client allowlist file. Required by configuration version 2.
    /// Version 1 without this file authorizes no client.
    #[serde(default)]
    pub client_allowlist_file: Option<String>,
    /// Fixed introspection service URL.
    pub introspection_endpoint: String,
    /// Introspection machine client identifier.
    pub introspection_client_id: String,
    /// Introspection secret file reference.
    pub introspection_secret_file: String,
    /// Fixed execution service URL.
    pub execution_endpoint: String,
    /// Execution machine client identifier.
    pub execution_client_id: String,
    /// Execution secret file reference.
    pub execution_secret_file: String,
    /// Trusted operation catalog path.
    pub catalog_file: String,
    /// Expected artifact SHA-256.
    pub catalog_sha256: String,
    /// TLS certificate chain path.
    pub certificate_file: String,
    /// TLS private key path.
    pub private_key_file: String,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("startup configuration [redacted]")
    }
}

impl Config {
    /// Decode exact fields without reading referenced files or making requests.
    ///
    /// # Errors
    /// Rejects unknown, duplicate, missing, empty, or non-string fields.
    /// Version 1 remains supported; version 2 requires a client allowlist file.
    /// Loading version 1 without this file authorizes no client.
    pub fn decode(bytes: &[u8]) -> Result<Self, Failure> {
        let document =
            strict_json::object(bytes, 16 << 10).map_err(Failure::redact(Kind::Configuration))?;
        if document.as_object().is_none_or(|fields| {
            fields
                .values()
                .any(|value| value.as_str().is_none_or(str::is_empty))
        }) {
            return Err(Kind::Configuration.into());
        }
        let config: Self =
            serde_json::from_value(document).map_err(Failure::redact(Kind::Configuration))?;
        if !matches!(config.version.as_str(), "1" | "2")
            || (config.version == "2" && config.client_allowlist_file.is_none())
        {
            return Err(Kind::Configuration.into());
        }
        Ok(config)
    }

    /// Validate a numeric IP address, port, and trusted artifact digest.
    ///
    /// # Errors
    /// Rejects hostnames, scoped IPv6 addresses, zero ports, and malformed digests.
    pub fn address_digest(&self) -> Result<(SocketAddr, [u8; 32]), Failure> {
        let address: SocketAddr = self
            .listen
            .parse()
            .map_err(Failure::redact(Kind::Configuration))?;
        if address.port() == 0 || self.listen.contains('%') || self.catalog_sha256.len() != 64 {
            return Err(Kind::Configuration.into());
        }
        let mut digest = [0; 32];
        for (target, pair) in digest
            .iter_mut()
            .zip(self.catalog_sha256.as_bytes().as_chunks::<2>().0)
        {
            let text = std::str::from_utf8(pair).map_err(Failure::redact(Kind::Configuration))?;
            *target = u8::from_str_radix(text, 16).map_err(Failure::redact(Kind::Configuration))?;
        }
        Ok((address, digest))
    }
}

/// Read an absolute regular file without following its final symlink or waiting on a FIFO.
/// Parent directories must remain under the service operator's control.
///
/// # Errors
/// Rejects file identity, permission, type, size, open, or read failures.
pub fn read_file(path: &Path, limit: u64, allowed: u32) -> Result<Zeroizing<Vec<u8>>, Failure> {
    if !path.is_absolute() || limit == 0 || limit == u64::MAX {
        return Err(Kind::Configuration.into());
    }
    let original = fs::symlink_metadata(path).map_err(Failure::redact(Kind::Configuration))?;
    check_file(&original, limit, allowed)?;
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(Failure::redact(Kind::Configuration))?;
    let file = File::from(fd);
    let opened = file
        .metadata()
        .map_err(Failure::redact(Kind::Configuration))?;
    check_file(&opened, limit, allowed)?;
    if original.dev() != opened.dev() || original.ino() != opened.ino() {
        return Err(Kind::Configuration.into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    let _: usize = file
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(Failure::redact(Kind::Configuration))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(Kind::Configuration.into());
    }
    Ok(bytes)
}

/// Check regular-file identity, size and permitted mode bits.
///
/// # Errors
/// Rejects nonregular files, excessive size and disallowed permissions.
fn check_file(metadata: &fs::Metadata, limit: u64, allowed: u32) -> Result<(), Failure> {
    if !metadata.is_file() || metadata.len() > limit || metadata.mode() & 0o7777 & !allowed != 0 {
        return Err(Kind::Configuration.into());
    }
    Ok(())
}

/// Load authority, catalog, and TLS material before a listener is opened.
pub struct Service {
    /// Validated listener address.
    pub address: SocketAddr,
    /// Authenticated stateless request router.
    pub router: axum::Router,
    /// Validated certificate and matching private key.
    pub tls: axum_server::tls_rustls::RustlsConfig,
}

impl Service {
    /// Assemble the service with no upstream requests.
    ///
    /// # Errors
    /// Reports configuration failures without filenames, contents, or credentials.
    pub fn load(path: &Path) -> Result<Self, Failure> {
        let config_bytes = read_file(path, 16 << 10, 0o600)?;
        let config = Config::decode(&config_bytes)?;
        let (address, digest) = config.address_digest()?;
        let catalog_bytes = read_file(Path::new(&config.catalog_file), 8 << 20, 0o644)?;
        let catalog = Catalog::load(&catalog_bytes, &digest)?;
        let introspection_credential = credential(
            &config.introspection_client_id,
            &config.introspection_secret_file,
        )?;
        let execution_credential =
            credential(&config.execution_client_id, &config.execution_secret_file)?;
        let mut upstream = Upstream::new(UpstreamOptions {
            introspection_endpoint: config.introspection_endpoint,
            execution_endpoint: config.execution_endpoint,
            issuer: config.issuer.clone(),
            resource: config.resource.clone(),
            required_scope: config.required_scope,
            introspection_credential,
            execution_credential,
        })?;
        if let Some(allowlist_path) = config.client_allowlist_file {
            let allowlist_bytes = read_file(Path::new(&allowlist_path), 16 << 10, 0o600)?;
            upstream = upstream.with_client_allowlist(ClientAllowlist::decode(&allowlist_bytes)?);
        }
        let router = protocol::router(catalog, upstream, config.resource, config.issuer)?;
        let certificate = read_file(Path::new(&config.certificate_file), 256 << 10, 0o644)?;
        let key = read_file(Path::new(&config.private_key_file), 64 << 10, 0o600)?;
        let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(&certificate)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Failure::redact(Kind::Configuration))?;
        let private_key = rustls::pki_types::PrivateKeyDer::from_pem_slice(&key)
            .map_err(Failure::redact(Kind::Configuration))?;
        let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut configuration = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(Failure::redact(Kind::Configuration))?
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .map_err(Failure::redact(Kind::Configuration))?;
        configuration.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let tls =
            axum_server::tls_rustls::RustlsConfig::from_config(std::sync::Arc::new(configuration));
        Ok(Self {
            address,
            router,
            tls,
        })
    }
}

/// Load bounded private credential bytes without trimming them.
///
/// # Errors
/// Rejects unsafe or unreadable files, invalid UTF-8 and invalid credentials.
fn credential(id: &str, path: &str) -> Result<MachineCredential, Failure> {
    let bytes = read_file(Path::new(path), 8 << 10, 0o600)?;
    let secret = std::str::from_utf8(&bytes).map_err(Failure::redact(Kind::Configuration))?;
    MachineCredential::new(id.to_owned(), Zeroizing::new(secret.to_owned()))
}
