Release History
===============

2026.7.25
---------

- Added support for WASI as the first TLS backend that match stdlib `ssl` behavior.
  Tested with componentize-py 0.25+ under wasmtime 47. A mere `pip install rtls` is
  sufficient. As the backend AWS-LC cannot target WASIp1 we made our WASI target
  Ring instead for Rustls.
  As wasi-tls is rather unusable at the moment for a mature http client such as urllib3-future
  we decided to deliver this TLS engine to WASI as a way to escape current known limitations.
  Beware that if your WASM runtime have an unsafe rng implementation, you should not use it
  in production.
- Updated aws-lc-rs v1.17.1 to v1.17.3

2026.5.30
---------

- Fixed general performance issue. Expect 30% faster throughput in general.

2026.5.14
---------

- Fixed fallback `load_default_certs` ignoring `SSL_CERT_FILE` and `SSL_CERT_DIR` environment variables.
  CPython default on OpenSSL, which in turn respect `SSL_CERT_FILE` and `SSL_CERT_DIR` via the load_default_certs.
  rtls will now align itself on OpenSSL behavior. (https://github.com/jawah/urllib3.future/issues/368)
- Updated aws-lc-rs v1.16.3 to v1.17.0

2026.5.7
--------

- Fixed RuntimeError "Already borrowed" (https://github.com/jawah/niquests/issues/393)
- Updated rustls v0.23.39 to v0.23.40

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
