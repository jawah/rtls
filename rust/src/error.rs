use pyo3::prelude::*;
use pyo3::types::PyType;

/// Map rustls and I/O errors to Python ssl exception hierarchy.
/// We raise these via the Python-side exception classes so we get
/// proper `ssl.SSLError`, `ssl.SSLWantReadError`, etc.
///
/// Helper: extract a Python type from a module attribute, falling back
/// to `PyOSError` if the attribute is missing or is not actually a type.
fn get_exc_type<'py>(
    py: Python<'py>,
    module: &str,
    attr: &str,
    fallback_prefix: &str,
    msg: &str,
) -> PyErr {
    match py.import(module) {
        Ok(m) => match m.getattr(attr) {
            Ok(cls) => match cls.cast::<PyType>() {
                Ok(ty) => PyErr::from_type(ty.clone(), msg.to_string()),
                Err(_) => pyo3::exceptions::PyOSError::new_err(format!(
                    "{}{} (exception class corrupted)",
                    fallback_prefix, msg
                )),
            },
            Err(e) => e,
        },
        Err(_) => pyo3::exceptions::PyOSError::new_err(format!("{}{}", fallback_prefix, msg)),
    }
}

/// Raise SSLEOFError on the Python side.
pub fn raise_eof(py: Python<'_>, msg: &str) -> PyErr {
    get_exc_type(py, "rtls._exceptions", "SSLEOFError", "SSL: EOF - ", msg)
}

/// Raise SSLCertVerificationError on the Python side.
pub fn raise_cert_verification(py: Python<'_>, msg: &str) -> PyErr {
    get_exc_type(
        py,
        "rtls._exceptions",
        "SSLCertVerificationError",
        "SSL: CERTIFICATE_VERIFY_FAILED - ",
        msg,
    )
}

/// Raise a general SSLError on the Python side.
pub fn raise_ssl_error(py: Python<'_>, msg: &str) -> PyErr {
    get_exc_type(py, "rtls._exceptions", "SSLError", "SSL: ", msg)
}
