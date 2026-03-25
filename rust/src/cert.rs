use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList, PyString, PyTuple};
use x509_parser::extensions::*;
use x509_parser::prelude::*;

/// Intermediate Rust representation of a parsed certificate.
/// Built without the GIL, then converted to Python objects with the GIL.
struct ParsedCert {
    version: u32,
    serial: String,
    issuer: Vec<Vec<(String, String)>>,
    subject: Vec<Vec<(String, String)>>,
    not_before: String,
    not_after: String,
    san: Option<Vec<(String, String)>>,
    ocsp: Vec<String>,
    ca_issuers: Vec<String>,
    crl_distribution_points: Vec<String>,
}

/// Parse a DER-encoded X.509 certificate into a Python dict matching
/// the format returned by CPython's ssl.SSLSocket.getpeercert().
///
/// Returns a dict with keys: subject, issuer, version, serialNumber,
/// notBefore, notAfter, subjectAltName, OCSP, caIssuers, crlDistributionPoints
#[pyfunction]
pub fn parse_certificate_dict(py: Python<'_>, der_bytes: &[u8]) -> PyResult<Py<PyAny>> {
    // Phase 1: Parse DER → Rust struct (GIL released)
    let parsed = py
        .detach(|| parse_cert_to_rust(der_bytes))
        .map_err(pyo3::exceptions::PyValueError::new_err)?;

    // Phase 2: Convert Rust struct → Python dict (GIL held)
    parsed_cert_to_py(py, &parsed)
}

/// Phase 1: Pure Rust DER parsing — no Python objects, no GIL needed.
fn parse_cert_to_rust(der_bytes: &[u8]) -> Result<ParsedCert, String> {
    let (_, cert) = X509Certificate::from_der(der_bytes)
        .map_err(|e| format!("Failed to parse certificate: {}", e))?;

    let version = cert.version().0 + 1;
    let serial = cert.raw_serial_as_string();
    let issuer = x500_name_to_rust(cert.issuer());
    let subject = x500_name_to_rust(cert.subject());
    let not_before = format_asn1_time(&cert.validity().not_before);
    let not_after = format_asn1_time(&cert.validity().not_after);

    let mut san = None;
    let mut ocsp = Vec::new();
    let mut ca_issuers = Vec::new();
    let mut crl_distribution_points = Vec::new();

    for ext in cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san_ext) => {
                let mut entries = Vec::new();
                for name in &san_ext.general_names {
                    match name {
                        GeneralName::DNSName(dns) => {
                            entries.push(("DNS".to_string(), dns.to_string()));
                        }
                        GeneralName::IPAddress(ip) => {
                            entries.push(("IP Address".to_string(), format_ip_address(ip)));
                        }
                        GeneralName::RFC822Name(email) => {
                            entries.push(("email".to_string(), email.to_string()));
                        }
                        GeneralName::URI(uri) => {
                            entries.push(("URI".to_string(), uri.to_string()));
                        }
                        _ => {}
                    }
                }
                san = Some(entries);
            }
            ParsedExtension::AuthorityInfoAccess(aia) => {
                for access_desc in &aia.accessdescs {
                    let uri = match &access_desc.access_location {
                        GeneralName::URI(u) => Some(u.to_string()),
                        _ => None,
                    };
                    if let Some(uri) = uri {
                        let oid_str = access_desc.access_method.to_id_string();
                        if oid_str == "1.3.6.1.5.5.7.48.1" {
                            ocsp.push(uri);
                        } else if oid_str == "1.3.6.1.5.5.7.48.2" {
                            ca_issuers.push(uri);
                        }
                    }
                }
            }
            ParsedExtension::CRLDistributionPoints(crl_dps) => {
                for dp in &crl_dps.points {
                    if let Some(DistributionPointName::FullName(names)) = &dp.distribution_point {
                        for name in names {
                            if let GeneralName::URI(uri) = name {
                                crl_distribution_points.push(uri.to_string());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Ok(ParsedCert {
        version,
        serial,
        issuer,
        subject,
        not_before,
        not_after,
        san,
        ocsp,
        ca_issuers,
        crl_distribution_points,
    })
}

/// Phase 2: Convert the parsed Rust struct into Python objects (requires GIL).
fn parsed_cert_to_py(py: Python<'_>, cert: &ParsedCert) -> PyResult<Py<PyAny>> {
    let dict = PyDict::new(py);

    dict.set_item("version", cert.version)?;
    dict.set_item("serialNumber", &cert.serial)?;

    let issuer = rust_rdns_to_py(py, &cert.issuer)?;
    dict.set_item("issuer", issuer)?;

    let subject = rust_rdns_to_py(py, &cert.subject)?;
    dict.set_item("subject", subject)?;

    dict.set_item("notBefore", &cert.not_before)?;
    dict.set_item("notAfter", &cert.not_after)?;

    if let Some(ref san_entries) = cert.san {
        let san_list = PyList::empty(py);
        for (kind, value) in san_entries {
            let tuple = PyTuple::new(
                py,
                [
                    PyString::new(py, kind).as_any(),
                    PyString::new(py, value).as_any(),
                ],
            )?;
            san_list.append(tuple)?;
        }
        let san_items: Vec<_> = san_list.iter().collect();
        let san_tuple = PyTuple::new(py, san_items.as_slice())?;
        dict.set_item("subjectAltName", san_tuple)?;
    }

    if !cert.ocsp.is_empty() {
        let py_list = PyTuple::new(
            py,
            cert.ocsp
                .iter()
                .map(|s| PyString::new(py, s))
                .collect::<Vec<_>>()
                .as_slice(),
        )?;
        dict.set_item("OCSP", py_list)?;
    }

    if !cert.ca_issuers.is_empty() {
        let py_list = PyTuple::new(
            py,
            cert.ca_issuers
                .iter()
                .map(|s| PyString::new(py, s))
                .collect::<Vec<_>>()
                .as_slice(),
        )?;
        dict.set_item("caIssuers", py_list)?;
    }

    if !cert.crl_distribution_points.is_empty() {
        let py_list = PyTuple::new(
            py,
            cert.crl_distribution_points
                .iter()
                .map(|s| PyString::new(py, s))
                .collect::<Vec<_>>()
                .as_slice(),
        )?;
        dict.set_item("crlDistributionPoints", py_list)?;
    }

    Ok(dict.into())
}

/// Convert X.500 Name to a Rust intermediate representation.
fn x500_name_to_rust(name: &X509Name) -> Vec<Vec<(String, String)>> {
    name.iter()
        .map(|rdn| {
            rdn.iter()
                .map(|attr| {
                    let oid_name = oid_to_name(attr.attr_type()).to_string();
                    let value = attr.as_str().unwrap_or("<binary>").to_string();
                    (oid_name, value)
                })
                .collect()
        })
        .collect()
}

/// Convert Rust RDN representation to Python nested tuples.
fn rust_rdns_to_py<'py>(
    py: Python<'py>,
    rdns: &[Vec<(String, String)>],
) -> PyResult<Bound<'py, PyTuple>> {
    let py_rdns: PyResult<Vec<Bound<'py, PyTuple>>> = rdns
        .iter()
        .map(|rdn| {
            let attrs: PyResult<Vec<Bound<'py, PyTuple>>> = rdn
                .iter()
                .map(|(oid_name, value)| {
                    PyTuple::new(
                        py,
                        [
                            PyString::new(py, oid_name).as_any(),
                            PyString::new(py, value).as_any(),
                        ],
                    )
                })
                .collect();
            PyTuple::new(py, attrs?.as_slice())
        })
        .collect();
    PyTuple::new(py, py_rdns?.as_slice())
}

/// Map common OID to human-readable name (matching CPython ssl output).
fn oid_to_name(oid: &x509_parser::der_parser::oid::Oid) -> &'static str {
    let oid_str = oid.to_id_string();
    match oid_str.as_str() {
        "2.5.4.3" => "commonName",
        "2.5.4.6" => "countryName",
        "2.5.4.7" => "localityName",
        "2.5.4.8" => "stateOrProvinceName",
        "2.5.4.10" => "organizationName",
        "2.5.4.11" => "organizationalUnitName",
        "2.5.4.5" => "serialNumber",
        "2.5.4.12" => "title",
        "2.5.4.42" => "givenName",
        "2.5.4.4" => "surname",
        "2.5.4.46" => "dnQualifier",
        "2.5.4.65" => "pseudonym",
        "1.2.840.113549.1.9.1" => "emailAddress",
        "0.9.2342.19200300.100.1.25" => "domainComponent",
        "2.5.4.9" => "streetAddress",
        "2.5.4.17" => "postalCode",
        "0.9.2342.19200300.100.1.1" => "userId",
        "2.5.4.45" => "uniqueIdentifier",
        "1.3.6.1.4.1.311.60.2.1.3" => "jurisdictionCountryName",
        "1.3.6.1.4.1.311.60.2.1.2" => "jurisdictionStateOrProvinceName",
        "1.3.6.1.4.1.311.60.2.1.1" => "jurisdictionLocalityName",
        "2.5.4.15" => "businessCategory",
        _ => "unknown",
    }
}

/// Format an IP address from raw bytes (4 bytes = IPv4, 16 bytes = IPv6).
fn format_ip_address(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
        16 => {
            let mut parts = Vec::new();
            for i in 0..8 {
                parts.push(format!(
                    "{:x}",
                    u16::from_be_bytes([bytes[i * 2], bytes[i * 2 + 1]])
                ));
            }
            parts.join(":")
        }
        _ => format!("<{} bytes>", bytes.len()),
    }
}

/// Format ASN1 time to the OpenSSL-style string: "Jan  1 00:00:00 2024 GMT"
fn format_asn1_time(time: &ASN1Time) -> String {
    let dt = time.to_datetime();
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let month_idx = dt.month() as usize;
    let month = if (1..=12).contains(&month_idx) {
        months[month_idx - 1]
    } else {
        "???"
    };
    format!(
        "{} {:2} {:02}:{:02}:{:02} {:04} GMT",
        month,
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        dt.year()
    )
}
