use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{verify_server_cert_signed_by_trust_anchor, verify_server_name};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use std::fmt::Debug;
use std::sync::Arc;

/// A certificate verifier that accepts ALL certificates unconditionally.
/// Used when verify_mode == CERT_NONE.
/// This is accessed via rustls's `dangerous()` API.
#[derive(Debug)]
pub struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

/// A certificate verifier that verifies the cert chain but does NOT
/// check the hostname. Used when check_hostname=False but verify_mode=CERT_REQUIRED.
#[derive(Debug)]
pub struct NoHostnameVerifier {
    inner: Arc<dyn ServerCertVerifier>,
}

impl NoHostnameVerifier {
    pub fn new(inner: Arc<dyn ServerCertVerifier>) -> Self {
        Self { inner }
    }
}

impl ServerCertVerifier for NoHostnameVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Delegate to the inner verifier — this checks the chain but
        // if hostname check fails we still accept it
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(v) => Ok(v),
            Err(Error::InvalidCertificate(rustls::CertificateError::NotValidForName)) => {
                // Accept cert even though hostname doesn't match
                Ok(ServerCertVerified::assertion())
            }
            Err(Error::InvalidCertificate(rustls::CertificateError::NotValidForNameContext {
                ..
            })) => {
                // Same as above, but with context info (rustls 0.23.37+)
                Ok(ServerCertVerified::assertion())
            }
            Err(e) => Err(e),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// A certificate verifier that injects user-loaded intermediate certificates
/// into the chain-building process. This bridges the compatibility gap between
/// OpenSSL and rustls: in OpenSSL, intermediates loaded via load_verify_locations()
/// are used during chain building even if the server doesn't send them. In rustls,
/// only server-sent intermediates are normally used for chain building.
///
/// This verifier concatenates user-loaded intermediates with the server-sent ones
/// before passing them to webpki for path building. webpki treats the intermediates
/// parameter as a flat bag of DER certs to search through for potential issuers.
pub struct ServerVerifierWithIntermediates {
    roots: Arc<RootCertStore>,
    extra_intermediates: Vec<CertificateDer<'static>>,
    supported: WebPkiSupportedAlgorithms,
}

impl ServerVerifierWithIntermediates {
    pub fn new(
        roots: Arc<RootCertStore>,
        extra_intermediates: Vec<CertificateDer<'static>>,
        provider: &Arc<rustls::crypto::CryptoProvider>,
    ) -> Self {
        Self {
            roots,
            extra_intermediates,
            supported: provider.signature_verification_algorithms,
        }
    }
}

impl Debug for ServerVerifierWithIntermediates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerVerifierWithIntermediates")
            .field("roots", &self.roots.len())
            .field("extra_intermediates", &self.extra_intermediates.len())
            .finish()
    }
}

impl ServerCertVerifier for ServerVerifierWithIntermediates {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;

        // Combine server-sent intermediates with user-loaded extra intermediates.
        // webpki treats this as a flat bag of DER certs for chain building —
        // no ordering requirement, no distinction between sources.
        let mut all_intermediates: Vec<CertificateDer<'_>> = intermediates.to_vec();
        for extra in &self.extra_intermediates {
            all_intermediates.push(CertificateDer::from(extra.as_ref()));
        }

        verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            &all_intermediates,
            now,
            self.supported.all,
        )?;

        verify_server_name(&cert, server_name)?;

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

/// Same as `ServerVerifierWithIntermediates` but skips hostname checking.
/// Used when check_hostname=False but verify_mode=CERT_REQUIRED.
pub struct NoHostnameVerifierWithIntermediates {
    roots: Arc<RootCertStore>,
    extra_intermediates: Vec<CertificateDer<'static>>,
    supported: WebPkiSupportedAlgorithms,
}

impl NoHostnameVerifierWithIntermediates {
    pub fn new(
        roots: Arc<RootCertStore>,
        extra_intermediates: Vec<CertificateDer<'static>>,
        provider: &Arc<rustls::crypto::CryptoProvider>,
    ) -> Self {
        Self {
            roots,
            extra_intermediates,
            supported: provider.signature_verification_algorithms,
        }
    }
}

impl Debug for NoHostnameVerifierWithIntermediates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoHostnameVerifierWithIntermediates")
            .field("roots", &self.roots.len())
            .field("extra_intermediates", &self.extra_intermediates.len())
            .finish()
    }
}

impl ServerCertVerifier for NoHostnameVerifierWithIntermediates {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;

        let mut all_intermediates: Vec<CertificateDer<'_>> = intermediates.to_vec();
        for extra in &self.extra_intermediates {
            all_intermediates.push(CertificateDer::from(extra.as_ref()));
        }

        verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            &all_intermediates,
            now,
            self.supported.all,
        )?;

        // Intentionally skip verify_server_name — hostname checking is disabled
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}
