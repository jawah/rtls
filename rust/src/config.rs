use pyo3::prelude::*;
use rustls::client::{EchConfig, EchGreaseConfig, EchMode};
use rustls::crypto::aws_lc_rs as provider;
use rustls::crypto::SupportedKxGroup;
use rustls::pki_types::{CertificateDer, EchConfigListBytes, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig, SupportedCipherSuite};
use std::io::{BufReader, Write};
use std::sync::Arc;

/// Custom KeyLog implementation that writes to a specific file path,
/// matching stdlib ssl's `SSLContext.keylog_filename` behavior.
/// Unlike rustls's built-in `KeyLogFile` which reads from `$SSLKEYLOGFILE`,
/// this writes to whatever path the user set via `ctx.keylog_filename`.
#[derive(Debug)]
struct KeyLogToFile {
    path: std::path::PathBuf,
}

impl KeyLogToFile {
    fn new(path: String) -> Self {
        Self {
            path: std::path::PathBuf::from(path),
        }
    }
}

impl rustls::KeyLog for KeyLogToFile {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let mut file = match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(f) => f,
            Err(_) => return,
        };
        let cr_hex: String = client_random.iter().map(|b| format!("{:02x}", b)).collect();
        let secret_hex: String = secret.iter().map(|b| format!("{:02x}", b)).collect();
        let _ = writeln!(file, "{} {} {}", label, cr_hex, secret_hex);
    }
}

/// Preferred cipher suite order.
///
/// AES-128 before AES-256, and within each key size ECDSA before RSA.
/// This differs from rustls's default (AES-256 first).
static PREFERRED_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    // TLS 1.3 suites: 128 before 256
    provider::cipher_suite::TLS13_AES_128_GCM_SHA256,
    provider::cipher_suite::TLS13_AES_256_GCM_SHA384,
    provider::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    // TLS 1.2 suites: grouped by cipher, ECDSA before RSA
    provider::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    provider::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    provider::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    provider::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// Preferred key exchange group order.
///
/// X25519MLKEM768 first (post-quantum hybrid), then X25519, then the
/// NIST curves.  Placing MLKEM first also means rustls will include a
/// key share for it in the initial ClientHello.
static PREFERRED_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    provider::kx_group::X25519MLKEM768,
    provider::kx_group::X25519,
    provider::kx_group::SECP256R1,
    provider::kx_group::SECP384R1,
];

use crate::connection::{RustlsClientConnection, RustlsServerConnection};
use crate::error::raise_ssl_error;
use crate::verify::{
    NoHostnameVerifier, NoHostnameVerifierWithIntermediates, NoVerifier,
    ServerVerifierWithIntermediates,
};

/// Verify mode constants (must match Python ssl module)
const CERT_NONE: i32 = 0;
#[allow(dead_code)]
const CERT_OPTIONAL: i32 = 1;
#[allow(dead_code)]
const CERT_REQUIRED: i32 = 2;

/// TLS version constants
const TLS_V1_2: u16 = 0x0303;
const TLS_V1_3: u16 = 0x0304;

/// Check if a DER-encoded certificate is self-signed (subject == issuer).
/// Self-signed certs are root CAs; non-self-signed certs are intermediates.
/// If parsing fails, conservatively treats the cert as self-signed so it
/// still gets added to the root store (safe fallback — worst case it becomes
/// a trust anchor when it shouldn't, which is the old behavior anyway).
fn is_self_signed(cert_der: &CertificateDer<'_>) -> bool {
    use x509_parser::prelude::FromDer;
    match x509_parser::certificate::X509Certificate::from_der(cert_der.as_ref()) {
        Ok((_, cert)) => cert.subject() == cert.issuer(),
        Err(_) => true, // conservative fallback
    }
}

/// Python-facing config builder. Accumulates settings, then builds
/// an immutable rustls ClientConfig/ServerConfig when a connection is created.
#[pyclass]
pub struct RustlsConfigBuilder {
    root_store: RootCertStore,
    /// ALL certs loaded via load_verify_locations() are stored here for
    /// chain building. Only self-signed certs (root CAs) are ALSO added
    /// to `root_store` as trust anchors. This ensures intermediates help
    /// with chain building but cannot act as trust anchors on their own.
    extra_intermediates: Vec<CertificateDer<'static>>,
    client_cert_chain: Option<Vec<CertificateDer<'static>>>,
    client_key: Option<PrivateKeyDer<'static>>,
    alpn_protocols: Vec<Vec<u8>>,
    min_version: Option<u16>,
    max_version: Option<u16>,
    cipher_suites: Option<Vec<String>>,
    verify_mode: i32,
    check_hostname: bool,
    sni_enabled: bool,
    keylog_filename: Option<String>,

    /// Stored server cert chain + key (for server-side TLS)
    server_cert_chain: Option<Vec<CertificateDer<'static>>>,
    server_key: Option<PrivateKeyDer<'static>>,

    /// Track number of root certs loaded for cert_store_stats()
    root_cert_count: usize,
    /// Store raw DER of loaded root certs for get_ca_certs()
    root_certs_der: Vec<Vec<u8>>,
    /// ECH config list bytes (from DNS HTTPS records)
    ech_config_list: Option<Vec<u8>>,
}

#[pymethods]
impl RustlsConfigBuilder {
    #[new]
    fn new() -> Self {
        Self {
            root_store: RootCertStore::empty(),
            extra_intermediates: Vec::new(),
            client_cert_chain: None,
            client_key: None,
            alpn_protocols: Vec::new(),
            min_version: None,
            max_version: None,
            cipher_suites: None,
            verify_mode: CERT_NONE,
            check_hostname: false,
            sni_enabled: true,
            keylog_filename: None,
            server_cert_chain: None,
            server_key: None,
            root_cert_count: 0,
            root_certs_der: Vec::new(),
            ech_config_list: None,
        }
    }

    /// Add CA certs from PEM data. Returns number of certs added.
    ///
    /// Self-signed certs (subject == issuer) are added to `root_store` as
    /// trust anchors.  Non-self-signed certs (intermediates) are added ONLY
    /// to `extra_intermediates` for chain building — they must NOT become
    /// trust anchors, or webpki would accept a chain that terminates at
    /// an intermediate without reaching an actual root CA.
    ///
    /// ALL certs are also stored in `extra_intermediates` so they are
    /// available for chain building (matching OpenSSL's behavior where
    /// `load_verify_locations()` certs assist chain construction).
    ///
    /// GIL is released during PEM parsing and certificate validation.
    fn add_root_certs_from_pem(&mut self, py: Python<'_>, pem_data: &[u8]) -> PyResult<usize> {
        let root_store = &mut self.root_store;
        let root_certs_der = &mut self.root_certs_der;
        let extra_intermediates = &mut self.extra_intermediates;
        let result = py.detach(|| {
            let mut reader = BufReader::new(pem_data);
            let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
                .filter_map(|r| r.ok())
                .collect();
            let mut root_certs = Vec::new();
            for cert in &certs {
                root_certs_der.push(cert.to_vec());
                extra_intermediates.push(cert.clone());
                // Only add self-signed certs (subject == issuer) to root_store.
                // it's weak triaging for now. we'll implement the same algorithm
                // as qh3 self signed check soon.
                if is_self_signed(cert) {
                    root_certs.push(cert.clone());
                }
            }
            let (added, _) = root_store.add_parsable_certificates(root_certs);
            added
        });
        self.root_cert_count += result;
        Ok(result)
    }

    /// Add a single CA cert from DER data.
    ///
    /// Self-signed certs are added to `root_store` as trust anchors.
    /// Non-self-signed certs (intermediates) are ONLY stored in
    /// `extra_intermediates` for chain building.
    fn add_root_cert_from_der(&mut self, py: Python<'_>, der_data: &[u8]) -> PyResult<()> {
        let root_store = &mut self.root_store;
        let der_copy = der_data.to_vec();
        let extra_intermediates = &mut self.extra_intermediates;
        let result: Result<(), String> = py.detach(|| {
            let cert = CertificateDer::from(der_copy.clone());
            extra_intermediates.push(cert.clone());
            if is_self_signed(&cert) {
                root_store
                    .add(cert)
                    .map_err(|e| format!("Invalid cert: {}", e))?;
            }
            Ok(())
        });
        result.map_err(pyo3::exceptions::PyValueError::new_err)?;
        self.root_certs_der.push(der_data.to_vec());
        self.root_cert_count += 1;
        Ok(())
    }

    /// Set client certificate chain + key for mTLS. Accepts PEM data.
    /// Optionally accepts a password for encrypted PKCS#8 keys.
    /// GIL is released during PEM parsing and private key parsing.
    #[pyo3(signature = (cert_pem, key_pem, password=None))]
    fn set_client_cert_chain_pem(
        &mut self,
        py: Python<'_>,
        cert_pem: &[u8],
        key_pem: &[u8],
        password: Option<&[u8]>,
    ) -> PyResult<()> {
        let result = py.detach(
            || -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
                let mut cert_reader = BufReader::new(cert_pem);
                let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
                    .filter_map(|r| r.ok())
                    .collect();
                if certs.is_empty() {
                    return Err("No certificates found in PEM data".to_string());
                }
                let key = load_private_key(key_pem, password).map_err(|e| e.to_string())?;
                Ok((certs, key))
            },
        );
        match result {
            Ok((certs, key)) => {
                self.client_cert_chain = Some(certs);
                self.client_key = Some(key);
                Ok(())
            }
            Err(msg) => Err(raise_ssl_error(py, &format!("[SSL] PEM lib ({})", msg))),
        }
    }

    /// Set server certificate chain + key. Accepts PEM data.
    /// Optionally accepts a password for encrypted PKCS#8 keys.
    /// GIL is released during PEM parsing and private key parsing.
    #[pyo3(signature = (cert_pem, key_pem, password=None))]
    fn set_server_cert_chain_pem(
        &mut self,
        py: Python<'_>,
        cert_pem: &[u8],
        key_pem: &[u8],
        password: Option<&[u8]>,
    ) -> PyResult<()> {
        let result = py.detach(
            || -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
                let mut cert_reader = BufReader::new(cert_pem);
                let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
                    .filter_map(|r| r.ok())
                    .collect();
                if certs.is_empty() {
                    return Err("No certificates found in PEM data".to_string());
                }
                let key = load_private_key(key_pem, password).map_err(|e| e.to_string())?;
                Ok((certs, key))
            },
        );
        match result {
            Ok((certs, key)) => {
                self.server_cert_chain = Some(certs);
                self.server_key = Some(key);
                Ok(())
            }
            Err(msg) => Err(raise_ssl_error(py, &format!("[SSL] PEM lib ({})", msg))),
        }
    }

    /// Set ALPN protocol list.
    fn set_alpn(&mut self, protocols: Vec<Vec<u8>>) {
        self.alpn_protocols = protocols;
    }

    fn set_min_version(&mut self, version: u16) {
        self.min_version = Some(version);
    }

    fn set_max_version(&mut self, version: u16) {
        self.max_version = Some(version);
    }

    /// Set cipher suites by IANA name (after Python-side mapping from OpenSSL names).
    fn set_cipher_suites(&mut self, suites: Vec<String>) {
        self.cipher_suites = Some(suites);
    }

    fn set_verify_mode(&mut self, mode: i32) {
        self.verify_mode = mode;
    }

    fn set_check_hostname(&mut self, check: bool) {
        self.check_hostname = check;
    }

    fn set_sni_enabled(&mut self, enabled: bool) {
        self.sni_enabled = enabled;
    }

    fn set_keylog_filename(&mut self, path: String) {
        self.keylog_filename = Some(path);
    }

    /// Set ECH (Encrypted Client Hello) config list bytes.
    /// The raw bytes come from DNS HTTPS records (the ECHConfigList structure).
    fn set_ech_configs(&mut self, data: &[u8]) {
        self.ech_config_list = Some(data.to_vec());
    }

    /// Check if ECH is configured.
    fn has_ech(&self) -> bool {
        self.ech_config_list.is_some()
    }

    /// Deep-clone this builder into a new independent instance.
    /// Used by Python-side TLSContext.set_ech_configs() to produce a
    /// per-connection clone without mutating the shared (cached) context.
    /// GIL is released during the deep copy of root store, keys, and certs.
    fn clone_builder(&self, py: Python<'_>) -> RustlsConfigBuilder {
        // Borrow all fields we need before entering allow_threads
        let root_store = &self.root_store;
        let extra_intermediates = &self.extra_intermediates;
        let client_cert_chain = &self.client_cert_chain;
        let client_key = &self.client_key;
        let alpn_protocols = &self.alpn_protocols;
        let cipher_suites = &self.cipher_suites;
        let keylog_filename = &self.keylog_filename;
        let server_cert_chain = &self.server_cert_chain;
        let server_key = &self.server_key;
        let root_certs_der = &self.root_certs_der;
        let ech_config_list = &self.ech_config_list;

        py.detach(|| RustlsConfigBuilder {
            root_store: root_store.clone(),
            extra_intermediates: extra_intermediates.clone(),
            client_cert_chain: client_cert_chain.clone(),
            client_key: client_key.as_ref().map(|k| k.clone_key()),
            alpn_protocols: alpn_protocols.clone(),
            min_version: self.min_version,
            max_version: self.max_version,
            cipher_suites: cipher_suites.clone(),
            verify_mode: self.verify_mode,
            check_hostname: self.check_hostname,
            sni_enabled: self.sni_enabled,
            keylog_filename: keylog_filename.clone(),
            server_cert_chain: server_cert_chain.clone(),
            server_key: server_key.as_ref().map(|k| k.clone_key()),
            root_cert_count: self.root_cert_count,
            root_certs_der: root_certs_der.clone(),
            ech_config_list: ech_config_list.clone(),
        })
    }

    /// Get number of root certs loaded.
    fn root_cert_count(&self) -> usize {
        self.root_cert_count
    }

    /// Get loaded root certs as list of DER bytes.
    fn get_root_certs_der(&self) -> Vec<Vec<u8>> {
        self.root_certs_der.clone()
    }

    /// Build a client connection for the given server name.
    /// GIL is released during the heavy config building and connection creation.
    fn build_client_connection(
        &self,
        py: Python<'_>,
        server_name: &str,
    ) -> PyResult<RustlsClientConnection> {
        let sname_str = server_name.to_string();
        let builder = self;
        let result = py.detach(|| -> Result<RustlsClientConnection, String> {
            let config = builder.build_client_config_inner()?;
            let sname = ServerName::try_from(sname_str)
                .map_err(|e| format!("Invalid server name: {}", e))?;
            let conn = rustls::ClientConnection::new(Arc::new(config), sname)
                .map_err(|e| format!("Failed to create connection: {}", e))?;
            Ok(RustlsClientConnection::new(conn))
        });
        result.map_err(|msg| raise_ssl_error(py, &msg))
    }

    /// Build a server connection.
    /// GIL is released during the heavy config building and connection creation.
    fn build_server_connection(&self, py: Python<'_>) -> PyResult<RustlsServerConnection> {
        let builder = self;
        let result = py.detach(|| -> Result<RustlsServerConnection, String> {
            let config = builder.build_server_config_inner()?;
            let conn = rustls::ServerConnection::new(Arc::new(config))
                .map_err(|e| format!("Failed to create server connection: {}", e))?;
            Ok(RustlsServerConnection::new(conn))
        });
        result.map_err(|msg| raise_ssl_error(py, &msg))
    }
}

impl RustlsConfigBuilder {
    fn get_protocol_versions(&self) -> Vec<&'static rustls::SupportedProtocolVersion> {
        let mut versions = Vec::new();
        let min = self.min_version.unwrap_or(TLS_V1_2);
        let max = self.max_version.unwrap_or(TLS_V1_3);

        if min <= TLS_V1_2 && max >= TLS_V1_2 {
            versions.push(&rustls::version::TLS12);
        }
        if min <= TLS_V1_3 && max >= TLS_V1_3 {
            versions.push(&rustls::version::TLS13);
        }
        if versions.is_empty() {
            // Fallback: at least allow TLS 1.2
            versions.push(&rustls::version::TLS12);
        }
        versions
    }

    fn get_cipher_suites(&self) -> Vec<SupportedCipherSuite> {
        if let Some(ref names) = self.cipher_suites {
            let all = provider::ALL_CIPHER_SUITES;
            let mut selected = Vec::new();
            for name in names {
                for suite in all {
                    let suite_name = format!("{:?}", suite.suite());
                    if suite_name == *name {
                        selected.push(*suite);
                    }
                }
            }
            if !selected.is_empty() {
                // Match stdlib behavior: set_ciphers() only controls TLS 1.2
                // suites.  TLS 1.3 suites are always included (unless TLS 1.3
                // is explicitly disabled via max_version / OP_NO_TLSv1_3).
                let tls13_defaults: &[SupportedCipherSuite] = &[
                    provider::cipher_suite::TLS13_AES_128_GCM_SHA256,
                    provider::cipher_suite::TLS13_AES_256_GCM_SHA384,
                    provider::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                ];
                let mut with_tls13 = Vec::new();
                for &s in tls13_defaults {
                    if !selected
                        .iter()
                        .any(|existing| existing.suite() == s.suite())
                    {
                        with_tls13.push(s);
                    }
                }
                with_tls13.extend(selected);
                return with_tls13;
            }
        }
        // Default: Chrome-like cipher suite order (AES-128 before AES-256)
        PREFERRED_CIPHER_SUITES.to_vec()
    }

    /// Resolve ECH mode for the client connection.
    ///
    /// - If explicit ECH config bytes are set → `EchMode::Enable`
    /// - If TLS 1.2 is disabled (i.e. only TLS 1.3) AND no explicit ECH config
    ///   --> `EchMode::Grease` (anti-ossification, RFC 8701)
    /// - Otherwise (TLS 1.2 is in the version range) → `None` (use protocol_versions path)
    ///
    /// ECH (both GREASE and Enable) is inherently TLS 1.3 only.  Rather than
    /// silently breaking TLS 1.2 servers, we only activate GREASE when TLS 1.2
    /// has been explicitly disabled by the caller.
    fn resolve_ech_mode(&self) -> Result<Option<EchMode>, String> {
        let hpke_suites = provider::hpke::ALL_SUPPORTED_SUITES;

        if let Some(ref ech_bytes) = self.ech_config_list {
            // Explicit ECH config always uses Enable (implies TLS 1.3).
            let ech_config_list = EchConfigListBytes::from(ech_bytes.clone());
            let ech_config = EchConfig::new(ech_config_list, hpke_suites)
                .map_err(|e| format!("Failed to parse ECH config: {}", e))?;
            Ok(Some(EchMode::Enable(ech_config)))
        } else {
            // GREASE only when TLS 1.2 is NOT in the version range
            // (i.e. the caller explicitly restricted to TLS 1.3 only).
            let versions = self.get_protocol_versions();
            let has_tls12 = versions.contains(&&rustls::version::TLS12);
            let has_tls13 = versions.contains(&&rustls::version::TLS13);
            if has_tls12 || !has_tls13 {
                return Ok(None);
            }
            let suite = hpke_suites
                .first()
                .ok_or_else(|| "No HPKE suites available for ECH GREASE".to_string())?;
            let (pub_key, _priv_key) = suite
                .generate_key_pair()
                .map_err(|e| format!("Failed to generate GREASE key pair: {}", e))?;
            let grease_config = EchGreaseConfig::new(*suite, pub_key);
            Ok(Some(EchMode::Grease(grease_config)))
        }
    }

    /// Pure-Rust client config builder — no Python GIL needed.
    /// Returns Result<ClientConfig, String> so errors can be converted to
    /// Python exceptions after re-acquiring the GIL.
    fn build_client_config_inner(&self) -> Result<ClientConfig, String> {
        let versions = self.get_protocol_versions();
        let cipher_suites = self.get_cipher_suites();

        let make_provider = || -> Arc<rustls::crypto::CryptoProvider> {
            Arc::new(rustls::crypto::CryptoProvider {
                cipher_suites: cipher_suites.clone(),
                kx_groups: PREFERRED_KX_GROUPS.to_vec(),
                ..provider::default_provider()
            })
        };

        let has_extra_intermediates = !self.extra_intermediates.is_empty();

        // Resolve ECH mode: Enable (explicit), Grease (TLS 1.3 default), or None (TLS 1.2 only).
        let ech_mode = self.resolve_ech_mode()?;

        // Helper macro: given a provider, apply ECH or protocol versions, returning
        // the builder at the WantsVerifier stage. This avoids duplicating the
        // ECH-vs-versions branching across every verify_mode path.
        macro_rules! apply_versions_or_ech {
            ($provider:expr) => {
                if let Some(mode) = ech_mode.clone() {
                    ClientConfig::builder_with_provider($provider)
                        .with_ech(mode)
                        .map_err(|e| format!("ECH setup error: {}", e))
                } else {
                    ClientConfig::builder_with_provider($provider)
                        .with_protocol_versions(&versions)
                        .map_err(|e| format!("Protocol version error: {}", e))
                }
            };
        }

        // Step 1: choose verifier → produces WantsClientCert
        let wants_client_auth = if self.verify_mode == CERT_NONE {
            apply_versions_or_ech!(make_provider())?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
        } else if !self.check_hostname {
            let root_store = Arc::new(self.root_store.clone());
            let crypto_provider = make_provider();

            if has_extra_intermediates {
                let verifier = NoHostnameVerifierWithIntermediates::new(
                    root_store,
                    self.extra_intermediates.clone(),
                    &crypto_provider,
                );
                apply_versions_or_ech!(crypto_provider)?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(verifier))
            } else {
                let webpki_verifier = rustls::client::WebPkiServerVerifier::builder(root_store)
                    .with_crls(vec![])
                    .build()
                    .map_err(|e| format!("Failed to build verifier: {}", e))?;
                apply_versions_or_ech!(crypto_provider)?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoHostnameVerifier::new(
                        webpki_verifier,
                    )))
            }
        } else {
            let root_store = Arc::new(self.root_store.clone());
            let crypto_provider = make_provider();

            if has_extra_intermediates {
                let verifier = ServerVerifierWithIntermediates::new(
                    root_store,
                    self.extra_intermediates.clone(),
                    &crypto_provider,
                );
                apply_versions_or_ech!(crypto_provider)?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(verifier))
            } else {
                apply_versions_or_ech!(crypto_provider)?
                    .with_root_certificates((*root_store).clone())
            }
        };

        // Step 2: apply client auth → produces ClientConfig
        let mut config =
            if let (Some(certs), Some(key)) = (&self.client_cert_chain, &self.client_key) {
                wants_client_auth
                    .with_client_auth_cert(certs.clone(), key.clone_key())
                    .map_err(|e| format!("Failed to set client cert: {}", e))?
            } else {
                wants_client_auth.with_no_client_auth()
            };

        // Step 3: post-config settings
        if !self.alpn_protocols.is_empty() {
            config.alpn_protocols = self.alpn_protocols.clone();
        }

        if let Some(ref path) = self.keylog_filename {
            config.key_log = Arc::new(KeyLogToFile::new(path.clone()));
        }

        config.enable_sni = self.sni_enabled;

        Ok(config)
    }

    /// Pure-Rust server config builder — no Python GIL needed.
    fn build_server_config_inner(&self) -> Result<ServerConfig, String> {
        let versions = self.get_protocol_versions();
        let cipher_suites = self.get_cipher_suites();

        let provider = rustls::crypto::CryptoProvider {
            cipher_suites,
            ..provider::default_provider()
        };

        let certs = self
            .server_cert_chain
            .as_ref()
            .ok_or_else(|| "No server certificate chain configured".to_string())?;
        let key = self
            .server_key
            .as_ref()
            .ok_or_else(|| "No server private key configured".to_string())?;

        let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&versions)
            .map_err(|e| format!("Protocol version error: {}", e))?
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key.clone_key())
            .map_err(|e| format!("Failed to set server cert: {}", e))?;

        if !self.alpn_protocols.is_empty() {
            config.alpn_protocols = self.alpn_protocols.clone();
        }

        if let Some(ref path) = self.keylog_filename {
            config.key_log = Arc::new(KeyLogToFile::new(path.clone()));
        }

        Ok(config)
    }
}

/// Load a private key from PEM data. Tries PKCS#8, then RSA PKCS#1, then SEC1 (EC).
///
/// Handles three encrypted key formats:
/// 1. PKCS#8 encrypted (`BEGIN ENCRYPTED PRIVATE KEY`) — decrypted via the `pkcs8` crate.
/// 2. Traditional OpenSSL encrypted (`Proc-Type: 4,ENCRYPTED` + `DEK-Info`) — decrypted
///    using EVP_BytesToKey-style key derivation with AES-128/256-CBC, DES-EDE3-CBC, or DES-CBC.
/// 3. Plaintext PEM keys — parsed directly via `rustls_pemfile`.
///
/// Pure Rust — no GIL needed (called from within allow_threads blocks).
fn load_private_key(
    pem_data: &[u8],
    password: Option<&[u8]>,
) -> Result<PrivateKeyDer<'static>, String> {
    // Case 1: PKCS#8 encrypted key (BEGIN ENCRYPTED PRIVATE KEY).
    if pem_data
        .windows(b"ENCRYPTED PRIVATE KEY".len())
        .any(|w| w == b"ENCRYPTED PRIVATE KEY")
    {
        let password = password
            .ok_or_else(|| "Private key is encrypted but no password was provided".to_string())?;

        let pem_str = std::str::from_utf8(pem_data)
            .map_err(|e| format!("PEM data is not valid UTF-8: {}", e))?;

        let begin_marker = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
        let end_marker = "-----END ENCRYPTED PRIVATE KEY-----";

        let start = pem_str
            .find(begin_marker)
            .ok_or_else(|| "Could not find ENCRYPTED PRIVATE KEY block".to_string())?;
        let end = pem_str[start..]
            .find(end_marker)
            .ok_or_else(|| "Could not find end of ENCRYPTED PRIVATE KEY block".to_string())?;
        let key_pem = &pem_str[start..start + end + end_marker.len()];

        let (_, der_bytes) = pem_rfc7468::decode_vec(key_pem.as_bytes())
            .map_err(|e| format!("Failed to decode encrypted key PEM: {}", e))?;

        let enc_pk_info = pkcs8::EncryptedPrivateKeyInfo::try_from(der_bytes.as_slice())
            .map_err(|e| format!("Failed to parse encrypted PKCS#8 DER: {}", e))?;

        let secret_doc = enc_pk_info
            .decrypt(password)
            .map_err(|e| format!("Failed to decrypt private key: {}", e))?;

        let decrypted_der = secret_doc.as_bytes().to_vec();

        return Ok(PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(decrypted_der),
        ));
    }

    // Case 2: Traditional OpenSSL encrypted PEM (Proc-Type: 4,ENCRYPTED + DEK-Info header).
    // rustls_pemfile cannot parse these because the Proc-Type/DEK-Info headers
    // contain characters that break strict RFC 7468 base64 parsing.
    if pem_data
        .windows(b"Proc-Type: 4,ENCRYPTED".len())
        .any(|w| w == b"Proc-Type: 4,ENCRYPTED")
    {
        let password = password
            .ok_or_else(|| "Private key is encrypted but no password was provided".to_string())?;

        let decrypted_der = decrypt_traditional_pem(pem_data, password)?;

        // Determine the key type from the PEM header.
        let pem_str = std::str::from_utf8(pem_data)
            .map_err(|e| format!("PEM data is not valid UTF-8: {}", e))?;

        if pem_str.contains("BEGIN RSA PRIVATE KEY") {
            return Ok(PrivateKeyDer::Pkcs1(
                rustls::pki_types::PrivatePkcs1KeyDer::from(decrypted_der),
            ));
        } else if pem_str.contains("BEGIN EC PRIVATE KEY") {
            return Ok(PrivateKeyDer::Sec1(
                rustls::pki_types::PrivateSec1KeyDer::from(decrypted_der),
            ));
        } else if pem_str.contains("BEGIN PRIVATE KEY") {
            return Ok(PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(decrypted_der),
            ));
        }

        return Err("Unrecognized traditional encrypted PEM key type".to_string());
    }

    // Case 3: Plaintext PEM key — parsed by rustls_pemfile.
    let mut reader = BufReader::new(pem_data);

    loop {
        match rustls_pemfile::read_one(&mut reader) {
            Ok(Some(rustls_pemfile::Item::Pkcs8Key(key))) => {
                return Ok(PrivateKeyDer::Pkcs8(key));
            }
            Ok(Some(rustls_pemfile::Item::Pkcs1Key(key))) => {
                return Ok(PrivateKeyDer::Pkcs1(key));
            }
            Ok(Some(rustls_pemfile::Item::Sec1Key(key))) => {
                return Ok(PrivateKeyDer::Sec1(key));
            }
            Ok(Some(_)) => {
                // Skip non-key items (certs, etc.)
                continue;
            }
            Ok(None) => break,
            Err(e) => {
                return Err(format!("Failed to parse PEM key: {}", e));
            }
        }
    }

    Err("No private key found in PEM data".to_string())
}

/// Decrypt a traditional OpenSSL encrypted PEM key.
///
/// Format:
/// ```text
/// -----BEGIN <TYPE> PRIVATE KEY-----
/// Proc-Type: 4,ENCRYPTED
/// DEK-Info: <CIPHER>,<IV-HEX>
///
/// <base64 encrypted body>
/// -----END <TYPE> PRIVATE KEY-----
/// ```
///
/// Key derivation uses OpenSSL's `EVP_BytesToKey` (MD5-based):
///   key = MD5(password || IV[:8]) [|| MD5(prev || password || IV[:8])] ...
///
/// Supported ciphers: AES-128-CBC, AES-256-CBC, DES-EDE3-CBC, DES-CBC.
fn decrypt_traditional_pem(pem_data: &[u8], password: &[u8]) -> Result<Vec<u8>, String> {
    use base64ct::{Base64, Encoding};
    use cipher::BlockDecryptMut;
    use cipher::KeyIvInit;

    let pem_str =
        std::str::from_utf8(pem_data).map_err(|e| format!("PEM is not valid UTF-8: {}", e))?;

    // Parse DEK-Info header to get cipher name and IV hex.
    let dek_line = pem_str
        .lines()
        .find(|l| l.starts_with("DEK-Info:"))
        .ok_or_else(|| "No DEK-Info header in encrypted PEM".to_string())?;

    let dek_value = dek_line
        .strip_prefix("DEK-Info:")
        .ok_or_else(|| "Malformed DEK-Info".to_string())?
        .trim();

    let (cipher_name, iv_hex) = dek_value
        .split_once(',')
        .ok_or_else(|| "Malformed DEK-Info: expected CIPHER,IV".to_string())?;

    let iv = hex_decode(iv_hex.trim())?;

    // Extract the base64 body: everything between the blank line after headers
    // and the END marker.
    let body_b64 = extract_pem_body(pem_str)?;
    let encrypted = Base64::decode_vec(&body_b64)
        .map_err(|e| format!("Failed to base64-decode encrypted key body: {}", e))?;

    // Derive key using EVP_BytesToKey (MD5-based, single iteration, no salt param —
    // the IV[:8] serves as the salt).
    let salt = &iv[..8];

    match cipher_name.trim() {
        "AES-128-CBC" => {
            let key = evp_bytes_to_key::<16>(password, salt);
            let mut buf = encrypted;
            let pt = cbc::Decryptor::<aes::Aes128>::new_from_slices(&key, &iv)
                .map_err(|e| format!("AES-128-CBC init error: {}", e))?
                .decrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut buf)
                .map_err(|e| format!("AES-128-CBC decrypt error: {}", e))?;
            Ok(pt.to_vec())
        }
        "AES-256-CBC" => {
            let key = evp_bytes_to_key::<32>(password, salt);
            let mut buf = encrypted;
            let pt = cbc::Decryptor::<aes::Aes256>::new_from_slices(&key, &iv)
                .map_err(|e| format!("AES-256-CBC init error: {}", e))?
                .decrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut buf)
                .map_err(|e| format!("AES-256-CBC decrypt error: {}", e))?;
            Ok(pt.to_vec())
        }
        "DES-EDE3-CBC" => {
            let key = evp_bytes_to_key::<24>(password, salt);
            let mut buf = encrypted;
            let pt = cbc::Decryptor::<des::TdesEde3>::new_from_slices(&key, &iv)
                .map_err(|e| format!("DES-EDE3-CBC init error: {}", e))?
                .decrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut buf)
                .map_err(|e| format!("DES-EDE3-CBC decrypt error: {}", e))?;
            Ok(pt.to_vec())
        }
        "DES-CBC" => {
            let key = evp_bytes_to_key::<8>(password, salt);
            let mut buf = encrypted;
            let pt = cbc::Decryptor::<des::Des>::new_from_slices(&key, &iv)
                .map_err(|e| format!("DES-CBC init error: {}", e))?
                .decrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut buf)
                .map_err(|e| format!("DES-CBC decrypt error: {}", e))?;
            Ok(pt.to_vec())
        }
        other => Err(format!(
            "Unsupported traditional PEM cipher: {}. \
             Supported: AES-128-CBC, AES-256-CBC, DES-EDE3-CBC, DES-CBC",
            other
        )),
    }
}

/// OpenSSL `EVP_BytesToKey` key derivation (MD5, 1 iteration, no count).
///
/// Produces `KEY_LEN` bytes by repeatedly hashing:
///   D_0 = ""
///   D_i = MD5(D_{i-1} || password || salt)
///   key = D_1 || D_2 || ... truncated to KEY_LEN
fn evp_bytes_to_key<const KEY_LEN: usize>(password: &[u8], salt: &[u8]) -> [u8; KEY_LEN] {
    use md5::{Digest, Md5};

    let mut key = [0u8; KEY_LEN];
    let mut prev_hash: Vec<u8> = Vec::new();
    let mut offset = 0;

    while offset < KEY_LEN {
        let mut hasher = Md5::new();
        if !prev_hash.is_empty() {
            hasher.update(&prev_hash);
        }
        hasher.update(password);
        hasher.update(salt);
        prev_hash = hasher.finalize().to_vec();

        let copy_len = std::cmp::min(prev_hash.len(), KEY_LEN - offset);
        key[offset..offset + copy_len].copy_from_slice(&prev_hash[..copy_len]);
        offset += copy_len;
    }

    key
}

/// Decode a hex string into bytes.
fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("Odd-length hex string in DEK-Info IV".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex in DEK-Info IV: {}", e))
        })
        .collect()
}

/// Extract the base64 body from a traditional encrypted PEM.
///
/// Skips the BEGIN line, Proc-Type, DEK-Info, and blank line,
/// then collects everything up to the END line.
fn extract_pem_body(pem_str: &str) -> Result<String, String> {
    let mut in_body = false;
    let mut body = String::new();
    let mut found_headers = false;

    for line in pem_str.lines() {
        if line.starts_with("-----BEGIN ") && line.ends_with("-----") {
            found_headers = false;
            continue;
        }
        if line.starts_with("-----END ") && line.ends_with("-----") {
            break;
        }
        if line.starts_with("Proc-Type:") || line.starts_with("DEK-Info:") {
            found_headers = true;
            continue;
        }
        // Blank line after headers marks start of base64 body.
        if found_headers && !in_body && line.trim().is_empty() {
            in_body = true;
            continue;
        }
        if in_body {
            body.push_str(line.trim());
        }
    }

    if body.is_empty() {
        return Err("No base64 body found in encrypted PEM".to_string());
    }
    Ok(body)
}
