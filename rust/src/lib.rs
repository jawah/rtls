use pyo3::prelude::*;
use pyo3::types::PyAny;

mod cert;
mod config;
mod connection;
mod error;
mod verify;

use cert::parse_certificate_dict;
use config::RustlsConfigBuilder;
use connection::{RustlsClientConnection, RustlsServerConnection};

/// rtls._rustls — Native Rust TLS state machine backed by rustls.
/// No network I/O — purely encrypt/decrypt byte buffers.
#[pymodule]
fn _rustls(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RustlsConfigBuilder>()?;
    m.add_class::<RustlsClientConnection>()?;
    m.add_class::<RustlsServerConnection>()?;
    m.add_function(wrap_pyfunction!(parse_certificate_dict, m)?)?;
    m.add_function(wrap_pyfunction!(rustls_version, m)?)?;
    m.add_function(wrap_pyfunction!(aws_lc_rs_version, m)?)?;
    m.add_function(wrap_pyfunction!(rand_bytes, m)?)?;
    Ok(())
}

/// Return the rustls version string (e.g. "0.23.37").
#[pyfunction]
fn rustls_version() -> String {
    // Set by build.rs from the actual rustls entry in Cargo.lock
    env!("RUSTLS_VERSION").to_string()
}

/// Return the aws-lc-rs version string (e.g. "1.16.2").
#[pyfunction]
fn aws_lc_rs_version() -> String {
    // Set by build.rs from the actual aws-lc-rs entry in Cargo.lock
    env!("AWS_LC_RS_VERSION").to_string()
}

/// Generate cryptographically secure random bytes.
/// GIL is released during the CSPRNG fill.
#[pyfunction]
fn rand_bytes(py: Python<'_>, n: usize) -> PyResult<Py<PyAny>> {
    use pyo3::types::PyBytes;
    let mut buf = vec![0u8; n];
    py.detach(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .secure_random
            .fill(&mut buf)
            .map_err(|_| ())
    })
    .map_err(|_| pyo3::exceptions::PyOSError::new_err("Failed to generate random bytes"))?;
    Ok(PyBytes::new(py, &buf).into())
}
