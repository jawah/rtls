from __future__ import annotations

import collections
import enum
import os

PROTOCOL_TLS = 2
PROTOCOL_TLS_CLIENT = 16
PROTOCOL_TLS_SERVER = 17
PROTOCOL_SSLv23 = PROTOCOL_TLS  # Deprecated alias

# Deprecated per-version protocols — we define the constants for compatibility
# but rtls only supports TLS 1.2+
PROTOCOL_TLSv1 = 3
PROTOCOL_TLSv1_1 = 4
PROTOCOL_TLSv1_2 = 5


class TLSVersion(enum.IntEnum):
    MINIMUM_SUPPORTED = -2
    SSLv3 = 0x0300  # Not actually supported by rustls
    TLSv1 = 0x0301  # Not actually supported by rustls
    TLSv1_1 = 0x0302  # Not actually supported by rustls
    TLSv1_2 = 0x0303
    TLSv1_3 = 0x0304
    MAXIMUM_SUPPORTED = -1


class VerifyMode(enum.IntEnum):
    CERT_NONE = 0
    CERT_OPTIONAL = 1
    CERT_REQUIRED = 2


CERT_NONE = VerifyMode.CERT_NONE
CERT_OPTIONAL = VerifyMode.CERT_OPTIONAL
CERT_REQUIRED = VerifyMode.CERT_REQUIRED


class VerifyFlags(enum.IntFlag):
    VERIFY_DEFAULT = 0x0
    VERIFY_CRL_CHECK_LEAF = 0x4
    VERIFY_CRL_CHECK_CHAIN = 0xC
    VERIFY_X509_STRICT = 0x20
    VERIFY_X509_TRUSTED_FIRST = 0x8000
    VERIFY_X509_PARTIAL_CHAIN = 0x80000
    VERIFY_ALLOW_PROXY_CERTS = 0x40


VERIFY_DEFAULT = VerifyFlags.VERIFY_DEFAULT
VERIFY_CRL_CHECK_LEAF = VerifyFlags.VERIFY_CRL_CHECK_LEAF
VERIFY_CRL_CHECK_CHAIN = VerifyFlags.VERIFY_CRL_CHECK_CHAIN
VERIFY_X509_STRICT = VerifyFlags.VERIFY_X509_STRICT
VERIFY_X509_TRUSTED_FIRST = VerifyFlags.VERIFY_X509_TRUSTED_FIRST
VERIFY_X509_PARTIAL_CHAIN = VerifyFlags.VERIFY_X509_PARTIAL_CHAIN
VERIFY_ALLOW_PROXY_CERTS = VerifyFlags.VERIFY_ALLOW_PROXY_CERTS


class Options(enum.IntFlag):
    OP_ALL = 0x80000BFF
    OP_NO_SSLv2 = 0x01000000
    OP_NO_SSLv3 = 0x02000000
    OP_NO_TLSv1 = 0x04000000
    OP_NO_TLSv1_1 = 0x10000000
    OP_NO_TLSv1_2 = 0x08000000
    OP_NO_TLSv1_3 = 0x20000000
    OP_NO_RENEGOTIATION = 0x40000000
    OP_CIPHER_SERVER_PREFERENCE = 0x00400000
    OP_SINGLE_DH_USE = 0x00100000
    OP_SINGLE_ECDH_USE = 0x00080000
    OP_ENABLE_MIDDLEBOX_COMPAT = 0x00100000
    OP_NO_COMPRESSION = 0x00020000
    OP_NO_TICKET = 0x00004000
    OP_IGNORE_UNEXPECTED_EOF = 0x00000080
    OP_ENABLE_KTLS = 0x00000008
    OP_LEGACY_SERVER_CONNECT = 0x00000004


OP_ALL = Options.OP_ALL
OP_NO_SSLv2 = Options.OP_NO_SSLv2
OP_NO_SSLv3 = Options.OP_NO_SSLv3
OP_NO_TLSv1 = Options.OP_NO_TLSv1
OP_NO_TLSv1_1 = Options.OP_NO_TLSv1_1
OP_NO_TLSv1_2 = Options.OP_NO_TLSv1_2
OP_NO_TLSv1_3 = Options.OP_NO_TLSv1_3
OP_NO_RENEGOTIATION = Options.OP_NO_RENEGOTIATION
OP_CIPHER_SERVER_PREFERENCE = Options.OP_CIPHER_SERVER_PREFERENCE
OP_SINGLE_DH_USE = Options.OP_SINGLE_DH_USE
OP_SINGLE_ECDH_USE = Options.OP_SINGLE_ECDH_USE
OP_ENABLE_MIDDLEBOX_COMPAT = Options.OP_ENABLE_MIDDLEBOX_COMPAT
OP_NO_COMPRESSION = Options.OP_NO_COMPRESSION
OP_NO_TICKET = Options.OP_NO_TICKET
OP_IGNORE_UNEXPECTED_EOF = Options.OP_IGNORE_UNEXPECTED_EOF
OP_ENABLE_KTLS = Options.OP_ENABLE_KTLS
OP_LEGACY_SERVER_CONNECT = Options.OP_LEGACY_SERVER_CONNECT

SSL_ERROR_SSL = 1
SSL_ERROR_WANT_READ = 2
SSL_ERROR_WANT_WRITE = 3
SSL_ERROR_WANT_X509_LOOKUP = 4
SSL_ERROR_SYSCALL = 5
SSL_ERROR_ZERO_RETURN = 6
SSL_ERROR_WANT_CONNECT = 7
SSL_ERROR_EOF = 8
SSL_ERROR_INVALID_ERROR_CODE = 10

# rustls capabilities
HAS_ALPN = True
HAS_ECDH = True
HAS_SNI = True
HAS_TLSv1_2 = True
HAS_TLSv1_3 = True
HAS_NEVER_CHECK_COMMON_NAME = True

# rustls does NOT support these
HAS_NPN = False
HAS_SSLv2 = False
HAS_SSLv3 = False
HAS_TLSv1 = False
HAS_TLSv1_1 = False
HAS_PSK = False
HAS_PHA = False  # Limited support, but safer to report False


class _ASN1ObjectBase:
    """Minimal ASN1Object-like for Purpose enum."""

    def __init__(self, nid: int, shortname: str, longname: str, oid: str):
        self.nid = nid
        self.shortname = shortname
        self.longname = longname
        self.oid = oid

    def __repr__(self) -> str:
        return f"<Purpose.{self.shortname}: {self.oid}>"


class _Purpose:
    """Purpose constants for create_default_context()."""

    SERVER_AUTH = _ASN1ObjectBase(129, "SERVER_AUTH", "serverAuth", "1.3.6.1.5.5.7.3.1")
    CLIENT_AUTH = _ASN1ObjectBase(130, "CLIENT_AUTH", "clientAuth", "1.3.6.1.5.5.7.3.2")


Purpose = _Purpose


class AlertDescription(enum.IntEnum):
    ALERT_DESCRIPTION_CLOSE_NOTIFY = 0
    ALERT_DESCRIPTION_UNEXPECTED_MESSAGE = 10
    ALERT_DESCRIPTION_BAD_RECORD_MAC = 20
    ALERT_DESCRIPTION_RECORD_OVERFLOW = 22
    ALERT_DESCRIPTION_DECOMPRESSION_FAILURE = 30
    ALERT_DESCRIPTION_HANDSHAKE_FAILURE = 40
    ALERT_DESCRIPTION_BAD_CERTIFICATE = 42
    ALERT_DESCRIPTION_UNSUPPORTED_CERTIFICATE = 43
    ALERT_DESCRIPTION_CERTIFICATE_REVOKED = 44
    ALERT_DESCRIPTION_CERTIFICATE_EXPIRED = 45
    ALERT_DESCRIPTION_CERTIFICATE_UNKNOWN = 46
    ALERT_DESCRIPTION_ILLEGAL_PARAMETER = 47
    ALERT_DESCRIPTION_UNKNOWN_CA = 48
    ALERT_DESCRIPTION_ACCESS_DENIED = 49
    ALERT_DESCRIPTION_DECODE_ERROR = 50
    ALERT_DESCRIPTION_DECRYPT_ERROR = 51
    ALERT_DESCRIPTION_PROTOCOL_VERSION = 70
    ALERT_DESCRIPTION_INSUFFICIENT_SECURITY = 71
    ALERT_DESCRIPTION_INTERNAL_ERROR = 80
    ALERT_DESCRIPTION_USER_CANCELLED = 90
    ALERT_DESCRIPTION_NO_RENEGOTIATION = 100
    ALERT_DESCRIPTION_UNSUPPORTED_EXTENSION = 110


# Export alert descriptions as module-level constants
ALERT_DESCRIPTION_CLOSE_NOTIFY = AlertDescription.ALERT_DESCRIPTION_CLOSE_NOTIFY
ALERT_DESCRIPTION_UNEXPECTED_MESSAGE = (
    AlertDescription.ALERT_DESCRIPTION_UNEXPECTED_MESSAGE
)
ALERT_DESCRIPTION_BAD_RECORD_MAC = AlertDescription.ALERT_DESCRIPTION_BAD_RECORD_MAC
ALERT_DESCRIPTION_RECORD_OVERFLOW = AlertDescription.ALERT_DESCRIPTION_RECORD_OVERFLOW
ALERT_DESCRIPTION_DECOMPRESSION_FAILURE = (
    AlertDescription.ALERT_DESCRIPTION_DECOMPRESSION_FAILURE
)
ALERT_DESCRIPTION_HANDSHAKE_FAILURE = (
    AlertDescription.ALERT_DESCRIPTION_HANDSHAKE_FAILURE
)
ALERT_DESCRIPTION_BAD_CERTIFICATE = AlertDescription.ALERT_DESCRIPTION_BAD_CERTIFICATE
ALERT_DESCRIPTION_UNSUPPORTED_CERTIFICATE = (
    AlertDescription.ALERT_DESCRIPTION_UNSUPPORTED_CERTIFICATE
)
ALERT_DESCRIPTION_CERTIFICATE_REVOKED = (
    AlertDescription.ALERT_DESCRIPTION_CERTIFICATE_REVOKED
)
ALERT_DESCRIPTION_CERTIFICATE_EXPIRED = (
    AlertDescription.ALERT_DESCRIPTION_CERTIFICATE_EXPIRED
)
ALERT_DESCRIPTION_CERTIFICATE_UNKNOWN = (
    AlertDescription.ALERT_DESCRIPTION_CERTIFICATE_UNKNOWN
)
ALERT_DESCRIPTION_ILLEGAL_PARAMETER = (
    AlertDescription.ALERT_DESCRIPTION_ILLEGAL_PARAMETER
)
ALERT_DESCRIPTION_UNKNOWN_CA = AlertDescription.ALERT_DESCRIPTION_UNKNOWN_CA
ALERT_DESCRIPTION_ACCESS_DENIED = AlertDescription.ALERT_DESCRIPTION_ACCESS_DENIED
ALERT_DESCRIPTION_DECODE_ERROR = AlertDescription.ALERT_DESCRIPTION_DECODE_ERROR
ALERT_DESCRIPTION_DECRYPT_ERROR = AlertDescription.ALERT_DESCRIPTION_DECRYPT_ERROR
ALERT_DESCRIPTION_PROTOCOL_VERSION = AlertDescription.ALERT_DESCRIPTION_PROTOCOL_VERSION
ALERT_DESCRIPTION_INSUFFICIENT_SECURITY = (
    AlertDescription.ALERT_DESCRIPTION_INSUFFICIENT_SECURITY
)
ALERT_DESCRIPTION_INTERNAL_ERROR = AlertDescription.ALERT_DESCRIPTION_INTERNAL_ERROR
ALERT_DESCRIPTION_USER_CANCELLED = AlertDescription.ALERT_DESCRIPTION_USER_CANCELLED
ALERT_DESCRIPTION_NO_RENEGOTIATION = AlertDescription.ALERT_DESCRIPTION_NO_RENEGOTIATION
ALERT_DESCRIPTION_UNSUPPORTED_EXTENSION = (
    AlertDescription.ALERT_DESCRIPTION_UNSUPPORTED_EXTENSION
)

CHANNEL_BINDING_TYPES = ["tls-unique"]

try:
    from rtls._rustls import aws_lc_rs_version as _aws_lc_rs_version
    from rtls._rustls import rustls_version as _rustls_version

    _RUSTLS_VERSION = _rustls_version()
    _AWS_LC_RS_VERSION = _aws_lc_rs_version()
except ImportError:
    _RUSTLS_VERSION = "0.0.0"
    _AWS_LC_RS_VERSION = "0.0.0"

# Parse the rustls semver components for VERSION_NUMBER and VERSION_INFO.
_rustls_parts = [int(x) for x in _RUSTLS_VERSION.split(".")]
_rustls_major = _rustls_parts[0] if len(_rustls_parts) > 0 else 0
_rustls_minor = _rustls_parts[1] if len(_rustls_parts) > 1 else 0
_rustls_patch = _rustls_parts[2] if len(_rustls_parts) > 2 else 0

# OPENSSL_VERSION: report as "Rustls X.Y.Z aws-lc-rs A.B.C".
OPENSSL_VERSION = f"Rustls {_RUSTLS_VERSION} — aws-lc-rs {_AWS_LC_RS_VERSION}"

# OPENSSL_VERSION_NUMBER: encode rustls semver in OpenSSL's 0xMNNFFPPS layout.
# M=major, NN=minor, FF=fix, PP=patch(0), S=status(0xf=release).
# e.g. rustls 0.23.37 → 0x01737000 + 0xf = 0x0173700f
OPENSSL_VERSION_NUMBER = (
    (_rustls_major + 1) << 28
    | _rustls_minor << 20
    | _rustls_patch << 12
    | 0xF  # release status
)

# OPENSSL_VERSION_INFO: 5-tuple matching CPython's ssl.OPENSSL_VERSION_INFO,
# derived from the rustls version.
OPENSSL_VERSION_INFO = (_rustls_major, _rustls_minor, _rustls_patch, 0, 0)

DefaultVerifyPaths = collections.namedtuple(
    "DefaultVerifyPaths",
    [
        "cafile",
        "capath",
        "openssl_cafile_env",
        "openssl_cafile",
        "openssl_capath_env",
        "openssl_capath",
    ],
)


def _get_default_verify_paths() -> DefaultVerifyPaths:
    """Return default verify paths (from environment or platform defaults)."""
    cafile = os.environ.get("SSL_CERT_FILE")
    capath = os.environ.get("SSL_CERT_DIR")
    return DefaultVerifyPaths(
        cafile=cafile,
        capath=capath,
        openssl_cafile_env="SSL_CERT_FILE",
        openssl_cafile=cafile or "",
        openssl_capath_env="SSL_CERT_DIR",
        openssl_capath=capath or "",
    )
