use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};
use rustls::client::EchStatus;
use rustls::{ClientConnection, ServerConnection};
use std::io::{Cursor, Read, Write};

use crate::error;

/// Categorized TLS error — carries enough info to map to the right Python
/// exception type *after* re-acquiring the GIL.
enum TlsError {
    CertVerification(String),
    General(String),
}

impl From<rustls::Error> for TlsError {
    fn from(err: rustls::Error) -> Self {
        match &err {
            rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented => {
                TlsError::CertVerification(format!("{}", err))
            }
            _ => TlsError::General(format!("{}", err)),
        }
    }
}

impl TlsError {
    /// Convert to a Python exception (requires the GIL).
    fn into_pyerr(self, py: Python<'_>) -> PyErr {
        match self {
            TlsError::CertVerification(msg) => error::raise_cert_verification(py, &msg),
            TlsError::General(msg) => error::raise_ssl_error(py, &msg),
        }
    }
}

/// Client-side TLS connection state machine.
/// No network I/O — operates purely on byte buffers.
#[pyclass]
pub struct RustlsClientConnection {
    conn: ClientConnection,
    /// Buffer for data that has been fed via read_tls but not yet processed
    peer_certs_cache: Option<Vec<Vec<u8>>>,
}

impl RustlsClientConnection {
    pub fn new(conn: ClientConnection) -> Self {
        Self {
            conn,
            peer_certs_cache: None,
        }
    }
}

#[pymethods]
impl RustlsClientConnection {
    /// Feed ciphertext bytes (from the network) into the TLS state machine.
    /// Returns number of bytes consumed.
    fn read_tls(&mut self, py: Python<'_>, data: &[u8]) -> PyResult<usize> {
        let conn = &mut self.conn;
        let mut cursor = Cursor::new(data);
        let result = py.detach(|| conn.read_tls(&mut cursor));
        result.map_err(|e| error::raise_ssl_error(py, &format!("read_tls failed: {}", e)))
    }

    /// Process any TLS records that have been buffered by read_tls().
    /// This drives the handshake and decrypts application data.
    /// GIL is released during the heavy crypto work.
    fn process_new_packets(&mut self, py: Python<'_>) -> PyResult<()> {
        let conn = &mut self.conn;
        let result = py.detach(|| conn.process_new_packets().map_err(TlsError::from));
        result.map_err(|e: TlsError| e.into_pyerr(py))?;

        // Cache peer certs after handshake completes
        if !self.conn.is_handshaking() && self.peer_certs_cache.is_none() {
            self.peer_certs_cache = self
                .conn
                .peer_certificates()
                .map(|certs| certs.iter().map(|c| c.to_vec()).collect());
        }
        Ok(())
    }

    /// Read decrypted plaintext from the TLS state machine.
    /// Returns bytes. Returns empty bytes if no data available.
    fn read_plaintext(&mut self, py: Python<'_>, max_len: usize) -> PyResult<Py<PyAny>> {
        let conn = &mut self.conn;
        let mut buf = vec![0u8; max_len];
        let result: Result<usize, std::io::Error> = py.detach(|| conn.reader().read(&mut buf));
        match result {
            Ok(n) => {
                buf.truncate(n);
                Ok(PyBytes::new(py, &buf).into())
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                Ok(PyBytes::new(py, &[]).into())
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(error::raise_eof(
                py,
                "EOF occurred in violation of protocol",
            )),
            Err(e) => Err(error::raise_ssl_error(py, &format!("read error: {}", e))),
        }
    }

    /// Write plaintext data to be encrypted by the TLS state machine.
    /// Returns number of bytes accepted.
    fn write_plaintext(&mut self, py: Python<'_>, data: &[u8]) -> PyResult<usize> {
        let conn = &mut self.conn;
        let result = py.detach(|| conn.writer().write(data));
        result.map_err(|e| error::raise_ssl_error(py, &format!("write error: {}", e)))
    }

    /// Extract ciphertext bytes from the TLS state machine (to be sent on the network).
    /// Returns bytes. GIL is released during encryption.
    fn write_tls(&mut self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let conn = &mut self.conn;
        let result = py.detach(|| {
            let mut buf = Vec::new();
            conn.write_tls(&mut buf).map(|_| buf)
        });
        match result {
            Ok(buf) => Ok(PyBytes::new(py, &buf).into()),
            Err(e) => Err(error::raise_ssl_error(
                py,
                &format!("write_tls failed: {}", e),
            )),
        }
    }

    /// Send TLS close_notify alert.
    fn send_close_notify(&mut self) {
        self.conn.send_close_notify();
    }

    /// Returns True if the handshake is still in progress.
    fn is_handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    /// Returns True if the state machine wants to read more ciphertext from the network.
    fn wants_read(&self) -> bool {
        self.conn.wants_read()
    }

    /// Returns True if the state machine has ciphertext to send to the network.
    fn wants_write(&self) -> bool {
        self.conn.wants_write()
    }

    /// Get peer certificates as list of DER-encoded bytes.
    /// Returns None if no certificates available (e.g., before handshake).
    fn peer_certificates(&self, py: Python<'_>) -> PyResult<Option<Vec<Py<PyAny>>>> {
        // Try cache first, then live
        if let Some(ref cached) = self.peer_certs_cache {
            return Ok(Some(
                cached.iter().map(|c| PyBytes::new(py, c).into()).collect(),
            ));
        }

        match self.conn.peer_certificates() {
            Some(certs) => Ok(Some(
                certs
                    .iter()
                    .map(|c| PyBytes::new(py, c.as_ref()).into())
                    .collect(),
            )),
            None => Ok(None),
        }
    }

    /// Get the negotiated ALPN protocol, or None.
    fn alpn_protocol(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        match self.conn.alpn_protocol() {
            Some(proto) => Ok(Some(PyBytes::new(py, proto).into())),
            None => Ok(None),
        }
    }

    /// Get the negotiated protocol version as a u16 (0x0303=TLS1.2, 0x0304=TLS1.3).
    fn protocol_version(&self) -> Option<u16> {
        self.conn.protocol_version().map(|v| match v {
            rustls::ProtocolVersion::TLSv1_2 => TLS_V1_2,
            rustls::ProtocolVersion::TLSv1_3 => TLS_V1_3,
            _ => 0,
        })
    }

    /// Get the negotiated cipher suite name (IANA name).
    fn negotiated_cipher_suite(&self) -> Option<String> {
        self.conn
            .negotiated_cipher_suite()
            .map(|cs| format!("{:?}", cs.suite()))
    }

    /// Get the negotiated cipher suite key exchange bits.
    fn negotiated_cipher_suite_bits(&self) -> Option<u32> {
        self.conn.negotiated_cipher_suite().map(|cs| {
            // Map cipher suites to their effective key bits
            let name = format!("{:?}", cs.suite());
            if name.contains("AES_128") {
                128
            } else if name.contains("AES_256") || name.contains("CHACHA20") {
                256
            } else {
                0
            }
        })
    }

    /// Get the ECH (Encrypted Client Hello) status as a string.
    /// Returns one of: "not_offered", "grease", "offered", "accepted", "rejected"
    fn ech_status(&self) -> &'static str {
        match self.conn.ech_status() {
            EchStatus::NotOffered => "not_offered",
            EchStatus::Grease => "grease",
            EchStatus::Offered => "offered",
            EchStatus::Accepted => "accepted",
            EchStatus::Rejected => "rejected",
        }
    }

    /// Fused read path: feed ciphertext, process TLS records, and return
    /// decrypted plaintext — all in **one** Python→Rust call.
    ///
    /// This avoids 3 separate PyO3 boundary crossings per recv() and
    /// handles the "buffer full" case internally by looping
    /// read_tls → process → drain until all input is consumed.
    ///
    /// Returns `(plaintext_bytes, unconsumed_ciphertext_bytes)`.
    /// `unconsumed` will be non-empty only if we filled `max_plaintext`
    /// before exhausting the input — the caller should stash it back.
    fn decrypt_incoming(
        &mut self,
        py: Python<'_>,
        ciphertext: &[u8],
        max_plaintext: usize,
    ) -> PyResult<(Py<PyAny>, Py<PyAny>)> {
        let conn = &mut self.conn;

        let result = py.detach(|| -> Result<(Vec<u8>, usize), TlsError> {
            let mut plaintext = Vec::with_capacity(max_plaintext);
            let mut offset: usize = 0;
            let total = ciphertext.len();

            while offset < total || !conn.wants_read() {
                // Feed as much ciphertext as rustls will accept
                if offset < total {
                    let mut cursor = Cursor::new(&ciphertext[offset..]);
                    match conn.read_tls(&mut cursor) {
                        Ok(n) => offset += n,
                        Err(e) => {
                            let msg = e.to_string();
                            if msg.contains("buffer full") {
                                // Buffer full — process what we have so far
                            } else {
                                return Err(TlsError::General(format!("read_tls failed: {}", e)));
                            }
                        }
                    }
                }

                // Process buffered TLS records (the expensive crypto work)
                conn.process_new_packets().map_err(TlsError::from)?;

                // Drain available plaintext
                let remaining = max_plaintext - plaintext.len();
                if remaining > 0 {
                    let before = plaintext.len();
                    plaintext.resize(before + remaining, 0);
                    match conn.reader().read(&mut plaintext[before..]) {
                        Ok(n) => plaintext.truncate(before + n),
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            plaintext.truncate(before);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                            plaintext.truncate(before);
                            // Signal EOF — but return what we have first
                            break;
                        }
                        Err(e) => {
                            return Err(TlsError::General(format!("read error: {}", e)));
                        }
                    }
                }

                // If we've filled the plaintext buffer, stop
                if plaintext.len() >= max_plaintext {
                    break;
                }

                // If all ciphertext consumed and nothing left to process, done
                if offset >= total {
                    break;
                }
            }

            Ok((plaintext, offset))
        });

        match result {
            Ok((plaintext, consumed)) => {
                // Cache peer certs if handshake just completed
                if !self.conn.is_handshaking() && self.peer_certs_cache.is_none() {
                    self.peer_certs_cache = self
                        .conn
                        .peer_certificates()
                        .map(|certs| certs.iter().map(|c| c.to_vec()).collect());
                }
                let py_plain = PyBytes::new(py, &plaintext).into();
                let py_uncons = PyBytes::new(py, &ciphertext[consumed..]).into();
                Ok((py_plain, py_uncons))
            }
            Err(e) => Err(e.into_pyerr(py)),
        }
    }
}

const TLS_V1_2: u16 = 0x0303;
const TLS_V1_3: u16 = 0x0304;

/// Server-side TLS connection state machine.
#[pyclass]
pub struct RustlsServerConnection {
    conn: ServerConnection,
    peer_certs_cache: Option<Vec<Vec<u8>>>,
}

impl RustlsServerConnection {
    pub fn new(conn: ServerConnection) -> Self {
        Self {
            conn,
            peer_certs_cache: None,
        }
    }
}

#[pymethods]
impl RustlsServerConnection {
    fn read_tls(&mut self, py: Python<'_>, data: &[u8]) -> PyResult<usize> {
        let conn = &mut self.conn;
        let mut cursor = Cursor::new(data);
        let result = py.detach(|| conn.read_tls(&mut cursor));
        result.map_err(|e| error::raise_ssl_error(py, &format!("read_tls failed: {}", e)))
    }

    fn process_new_packets(&mut self, py: Python<'_>) -> PyResult<()> {
        let conn = &mut self.conn;
        let result = py.detach(|| conn.process_new_packets().map_err(TlsError::from));
        result.map_err(|e: TlsError| e.into_pyerr(py))?;

        if !self.conn.is_handshaking() && self.peer_certs_cache.is_none() {
            self.peer_certs_cache = self
                .conn
                .peer_certificates()
                .map(|certs| certs.iter().map(|c| c.to_vec()).collect());
        }
        Ok(())
    }

    fn read_plaintext(&mut self, py: Python<'_>, max_len: usize) -> PyResult<Py<PyAny>> {
        let conn = &mut self.conn;
        let mut buf = vec![0u8; max_len];
        let result: Result<usize, std::io::Error> = py.detach(|| conn.reader().read(&mut buf));
        match result {
            Ok(n) => {
                buf.truncate(n);
                Ok(PyBytes::new(py, &buf).into())
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                Ok(PyBytes::new(py, &[]).into())
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(error::raise_eof(
                py,
                "EOF occurred in violation of protocol",
            )),
            Err(e) => Err(error::raise_ssl_error(py, &format!("read error: {}", e))),
        }
    }

    fn write_plaintext(&mut self, py: Python<'_>, data: &[u8]) -> PyResult<usize> {
        let conn = &mut self.conn;
        let result = py.detach(|| conn.writer().write(data));
        result.map_err(|e| error::raise_ssl_error(py, &format!("write error: {}", e)))
    }

    fn write_tls(&mut self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let conn = &mut self.conn;
        let result = py.detach(|| {
            let mut buf = Vec::new();
            conn.write_tls(&mut buf).map(|_| buf)
        });
        match result {
            Ok(buf) => Ok(PyBytes::new(py, &buf).into()),
            Err(e) => Err(error::raise_ssl_error(
                py,
                &format!("write_tls failed: {}", e),
            )),
        }
    }

    fn send_close_notify(&mut self) {
        self.conn.send_close_notify();
    }

    fn is_handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    fn wants_read(&self) -> bool {
        self.conn.wants_read()
    }

    fn wants_write(&self) -> bool {
        self.conn.wants_write()
    }

    fn peer_certificates(&self, py: Python<'_>) -> PyResult<Option<Vec<Py<PyAny>>>> {
        if let Some(ref cached) = self.peer_certs_cache {
            return Ok(Some(
                cached.iter().map(|c| PyBytes::new(py, c).into()).collect(),
            ));
        }

        match self.conn.peer_certificates() {
            Some(certs) => Ok(Some(
                certs
                    .iter()
                    .map(|c| PyBytes::new(py, c.as_ref()).into())
                    .collect(),
            )),
            None => Ok(None),
        }
    }

    fn alpn_protocol(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        match self.conn.alpn_protocol() {
            Some(proto) => Ok(Some(PyBytes::new(py, proto).into())),
            None => Ok(None),
        }
    }

    fn protocol_version(&self) -> Option<u16> {
        self.conn.protocol_version().map(|v| match v {
            rustls::ProtocolVersion::TLSv1_2 => TLS_V1_2,
            rustls::ProtocolVersion::TLSv1_3 => TLS_V1_3,
            _ => 0,
        })
    }

    fn negotiated_cipher_suite(&self) -> Option<String> {
        self.conn
            .negotiated_cipher_suite()
            .map(|cs| format!("{:?}", cs.suite()))
    }

    fn negotiated_cipher_suite_bits(&self) -> Option<u32> {
        self.conn.negotiated_cipher_suite().map(|cs| {
            let name = format!("{:?}", cs.suite());
            if name.contains("AES_128") {
                128
            } else if name.contains("AES_256") || name.contains("CHACHA20") {
                256
            } else {
                0
            }
        })
    }

    /// Fused read path for server connections — mirrors
    /// `RustlsClientConnection::decrypt_incoming`.
    fn decrypt_incoming(
        &mut self,
        py: Python<'_>,
        ciphertext: &[u8],
        max_plaintext: usize,
    ) -> PyResult<(Py<PyAny>, Py<PyAny>)> {
        let conn = &mut self.conn;

        let result = py.detach(|| -> Result<(Vec<u8>, usize), TlsError> {
            let mut plaintext = Vec::with_capacity(max_plaintext);
            let mut offset: usize = 0;
            let total = ciphertext.len();

            while offset < total || !conn.wants_read() {
                if offset < total {
                    let mut cursor = Cursor::new(&ciphertext[offset..]);
                    match conn.read_tls(&mut cursor) {
                        Ok(n) => offset += n,
                        Err(e) => {
                            let msg = e.to_string();
                            if msg.contains("buffer full") {
                                // Process what we have so far
                            } else {
                                return Err(TlsError::General(format!("read_tls failed: {}", e)));
                            }
                        }
                    }
                }

                conn.process_new_packets().map_err(TlsError::from)?;

                let remaining = max_plaintext - plaintext.len();
                if remaining > 0 {
                    let before = plaintext.len();
                    plaintext.resize(before + remaining, 0);
                    match conn.reader().read(&mut plaintext[before..]) {
                        Ok(n) => plaintext.truncate(before + n),
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            plaintext.truncate(before);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                            plaintext.truncate(before);
                            break;
                        }
                        Err(e) => {
                            return Err(TlsError::General(format!("read error: {}", e)));
                        }
                    }
                }

                if plaintext.len() >= max_plaintext {
                    break;
                }

                if offset >= total {
                    break;
                }
            }

            Ok((plaintext, offset))
        });

        match result {
            Ok((plaintext, consumed)) => {
                if !self.conn.is_handshaking() && self.peer_certs_cache.is_none() {
                    self.peer_certs_cache = self
                        .conn
                        .peer_certificates()
                        .map(|certs| certs.iter().map(|c| c.to_vec()).collect());
                }
                let py_plain = PyBytes::new(py, &plaintext).into();
                let py_uncons = PyBytes::new(py, &ciphertext[consumed..]).into();
                Ok((py_plain, py_uncons))
            }
            Err(e) => Err(e.into_pyerr(py)),
        }
    }
}
