Release History
===============

2026.4.24
---------

- Updated aws-lc-rs v1.16.2 to v1.16.3
- Updated rustls v0.23.37 to v0.23.39
- Updated pyo3 v0.28.2 to v0.28.3
- Fixed performance issue with DER_cert_to_PEM_cert and PEM_cert_to_DER_cert functions
- Fixed honoring `VERIFY_X509_TRUSTED_FIRST` and `VERIFY_X509_PARTIAL_CHAIN`.

2026.3.29
---------

- Added `sslobj` public shortcut to `_sslobj` property for backward compatibility to TLSSocket.
- Updated aws-lc-sys v0.39.0 to v0.39.1.

2026.3.28
---------

- Disabled eager ech grease when TLS 1.2 is still enabled.

2026.3.27
---------

- Fixed keylogfile path ignored.
- Fixed loading mtls encrypted keys.
- Fixed fd leakage upon SSLError.
- Fixed ssl ctx options handling.
- Fixed untriaged CA bundle anchors and intermediates.
- Removed hostname_checks_common_name as Rustls don't support it.

2026.3.26
---------

- Initial release
