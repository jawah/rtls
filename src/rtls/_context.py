from __future__ import annotations

import os
import socket
import ssl as _stdlib_ssl
from typing import Any, Callable

from ._bio import MemoryBIO
from ._ciphers import get_default_ciphers, parse_cipher_string
from ._constants import (
    CERT_NONE,
    CERT_REQUIRED,
    OP_ALL,
    PROTOCOL_TLS,
    PROTOCOL_TLS_CLIENT,
    PROTOCOL_TLS_SERVER,
    OP_NO_SSLv2,
    OP_NO_SSLv3,
    Options,
    TLSVersion,
    VerifyMode,
)
from ._exceptions import SSLError


class TLSContext(_stdlib_ssl.SSLContext):
    """TLS context backed by rustls, subclassing ssl.SSLContext for asyncio.

    Usage::

        ctx = TLSContext(PROTOCOL_TLS_CLIENT)
        ctx.load_default_certs()
        ssock = ctx.wrap_socket(sock, server_hostname="example.com")
    """

    # We need __new__ because ssl.SSLContext.__new__ takes a protocol argument
    # and does C-level initialization we want to coexist with.
    def __new__(
        cls, protocol: int = PROTOCOL_TLS, *args: Any, **kwargs: Any
    ) -> TLSContext:
        # Map our protocol constants to stdlib ones for the base class.
        # ssl.SSLContext.__new__ requires a valid stdlib protocol.
        stdlib_protocol = _stdlib_ssl.PROTOCOL_TLS_CLIENT
        return super().__new__(cls, stdlib_protocol)

    def __init__(self, protocol: int = PROTOCOL_TLS, *args: Any, **kwargs: Any) -> None:
        # Don't call super().__init__() — ssl.SSLContext.__init__ re-init is
        # not needed (it's done in __new__). We just set up our own state.

        self._protocol = protocol

        # Create the Rust config builder
        from ._rustls import RustlsConfigBuilder

        self._builder = RustlsConfigBuilder()

        # Internal state tracking
        self._verify_mode = CERT_NONE
        self._check_hostname = False
        self._options = OP_ALL | OP_NO_SSLv2 | OP_NO_SSLv3
        self._minimum_version: TLSVersion | None = TLSVersion.TLSv1_2
        self._maximum_version: TLSVersion | None = TLSVersion.TLSv1_3
        self._alpn_protocols: list[bytes] = []
        self._ciphers_string: str | None = None
        self._sni_callback: Callable | None = None
        self._post_handshake_auth = False
        self._keylog_filename: str | None = None
        self._verify_flags: int = 0

        # Cert/key data (kept for stats & reloads)
        self._cert_chain_loaded = False
        self._ca_certs_loaded = False
        self._num_ca_certs = 0

        # Apply protocol-specific defaults
        if protocol == PROTOCOL_TLS_CLIENT:
            self._verify_mode = CERT_REQUIRED
            self._check_hostname = True
            self._builder.set_verify_mode(CERT_REQUIRED)
            self._builder.set_check_hostname(True)
        elif protocol == PROTOCOL_TLS_SERVER:
            self._verify_mode = CERT_NONE
            self._check_hostname = False

    def _get_builder(self) -> Any:
        """Return the RustlsConfigBuilder (used by TLSObject/TLSSocket)."""
        return self._builder

    def wrap_socket(  # type: ignore[override]
        self,
        sock: socket.socket,
        server_side: bool = False,
        do_handshake_on_connect: bool = True,
        suppress_ragged_eofs: bool = True,
        server_hostname: str | None = None,
    ) -> Any:
        """Wrap a socket with TLS, returning an TLSSocket."""
        from ._socket import TLSSocket

        if not server_side and self._check_hostname and not server_hostname:
            raise ValueError("check_hostname requires server_hostname")

        return TLSSocket(
            sock=sock,
            context=self,
            server_side=server_side,
            server_hostname=server_hostname,
            do_handshake_on_connect=do_handshake_on_connect,
            suppress_ragged_eofs=suppress_ragged_eofs,
        )

    def wrap_bio(  # type: ignore[override]
        self,
        incoming: MemoryBIO,
        outgoing: MemoryBIO,
        server_side: bool = False,
        server_hostname: str | None = None,
    ) -> Any:
        """Wrap a pair of MemoryBIOs with TLS, returning an TLSObject.

        This is the method asyncio's SSLProtocol calls to create a sans-I/O
        TLS state machine.
        """
        from ._object import TLSObject

        return TLSObject(
            context=self,
            incoming=incoming,
            outgoing=outgoing,
            server_side=server_side,
            server_hostname=server_hostname,
        )

    def load_cert_chain(  # type: ignore[override]
        self,
        certfile: str | bytes | None = None,
        keyfile: str | bytes | None = None,
        password: str | bytes | Callable | None = None,
    ) -> None:
        """Load a certificate chain for client/server authentication.

        Accepts either:
          - File paths (str): reads PEM from disk
          - PEM data (bytes): uses directly — this makes urllib3-future's
            contrib/imcc module unnecessary!

        For encrypted PKCS#8 keys (``ENCRYPTED PRIVATE KEY``), provide
        a password (str, bytes, or a callable returning str/bytes).
        """
        cert_pem = self._load_pem_data(certfile)
        key_pem = self._load_pem_data(keyfile) if keyfile else cert_pem

        # Validate that the cert PEM contains at least one parseable certificate.
        # OpenSSL does this validation in SSL_CTX_use_certificate_chain_file;
        # rustls-pemfile silently skips invalid PEM items, so we catch it here.
        self._validate_cert_pem(cert_pem)

        # Resolve password to bytes or None
        pw_bytes: bytes | None = None
        if password is not None:
            if callable(password):
                password = password()
            if isinstance(password, str):
                pw_bytes = password.encode("utf-8")
            elif isinstance(password, (bytes, bytearray)):
                pw_bytes = bytes(password)
            else:
                raise TypeError(
                    "password must be str, bytes, or callable,"
                    f" got {type(password).__name__}"
                )

        if self._protocol == PROTOCOL_TLS_SERVER:
            self._builder.set_server_cert_chain_pem(cert_pem, key_pem, pw_bytes)
        else:
            self._builder.set_client_cert_chain_pem(cert_pem, key_pem, pw_bytes)

        self._cert_chain_loaded = True

    def load_verify_locations(  # type: ignore[override]
        self,
        cafile: str | None = None,
        capath: str | None = None,
        cadata: str | bytes | None = None,
    ) -> None:
        """Load CA certificates for verification."""
        loaded = 0

        if cafile:
            with open(cafile, "rb") as f:
                pem_data = f.read()
            loaded += self._builder.add_root_certs_from_pem(pem_data)

        if capath:
            for entry in os.scandir(capath):
                if entry.is_file() and (
                    entry.name.endswith(".pem")
                    or entry.name.endswith(".crt")
                    or entry.name.endswith(".0")
                ):
                    with open(entry.path, "rb") as f:
                        pem_data = f.read()
                    loaded += self._builder.add_root_certs_from_pem(pem_data)

        if cadata:
            if isinstance(cadata, str):
                cadata = cadata.encode("ascii")
            # Could be PEM or DER
            if b"-----BEGIN" in cadata:
                loaded += self._builder.add_root_certs_from_pem(cadata)
            else:
                self._builder.add_root_cert_from_der(cadata)
                loaded += 1

        self._ca_certs_loaded = True
        self._num_ca_certs += loaded

    def load_default_certs(self, purpose: Any = None) -> None:
        """Load the default set of CA certificates via wassima.

        Uses wassima.root_der_certificates() to extract the OS trust store
        and feeds each DER cert into the Rust builder.
        """
        import wassima

        der_certs = wassima.root_der_certificates()
        for der_cert in der_certs:
            self._builder.add_root_cert_from_der(der_cert)
        self._num_ca_certs += len(der_certs)
        self._ca_certs_loaded = True

    # Alias matching CPython ssl.SSLContext.load_default_certs
    set_default_verify_paths = load_default_certs

    def set_ciphers(self, ciphers: str) -> None:
        """Set cipher suites using an OpenSSL cipher string.

        Unknown/unsupported ciphers are silently dropped. DHE ciphers
        are not supported by rustls and will be ignored.
        """
        self._ciphers_string = ciphers
        iana_names = parse_cipher_string(ciphers)
        self._builder.set_cipher_suites(iana_names)

    def get_ciphers(self) -> list[dict[str, object]]:  # type: ignore[override]
        """Return the list of enabled ciphers."""
        return get_default_ciphers()

    def set_alpn_protocols(self, protocols: list[str]) -> None:  # type: ignore[override]
        """Set ALPN protocols for negotiation."""
        self._alpn_protocols = [p.encode("ascii") for p in protocols]
        self._builder.set_alpn(self._alpn_protocols)

    def get_alpn_protocols(self) -> list[str]:
        """Return the configured ALPN protocols."""
        return [p.decode("ascii") for p in self._alpn_protocols]

    @property
    def protocol(self) -> int:  # type: ignore[override]
        return self._protocol

    @property  # type: ignore[override]
    def verify_mode(self) -> VerifyMode:
        return VerifyMode(self._verify_mode)

    @verify_mode.setter
    def verify_mode(self, value: int) -> None:
        self._verify_mode = int(value)  # type: ignore[assignment]
        self._builder.set_verify_mode(self._verify_mode)

        # CPython behavior: setting verify_mode to CERT_NONE also disables
        # check_hostname
        if self._verify_mode == CERT_NONE:
            self._check_hostname = False
            self._builder.set_check_hostname(False)

    @property
    def check_hostname(self) -> bool:
        return self._check_hostname

    @check_hostname.setter
    def check_hostname(self, value: bool) -> None:
        if value and self._verify_mode == CERT_NONE:
            raise ValueError(
                "Cannot set check_hostname to True with verify_mode=CERT_NONE"
            )
        self._check_hostname = value
        self._builder.set_check_hostname(value)

    @property  # type: ignore[override]
    def options(self) -> Options:
        return Options(self._options)

    @options.setter
    def options(self, value: int) -> None:
        self._options = int(value)  # type: ignore[assignment]
        # Update min/max version based on OP_NO_* flags
        self._apply_version_options()

    @property  # type: ignore[override]
    def minimum_version(self) -> TLSVersion | None:
        return self._minimum_version

    @minimum_version.setter
    def minimum_version(self, value: TLSVersion | int | None) -> None:
        if value is None or value == TLSVersion.MINIMUM_SUPPORTED:
            self._minimum_version = TLSVersion.TLSv1_2
            self._builder.set_min_version(0x0303)  # TLS 1.2 is our min
        else:
            value = TLSVersion(value)
            if value < TLSVersion.TLSv1_2:
                # rustls doesn't support < TLS 1.2, silently clamp
                value = TLSVersion.TLSv1_2
            self._minimum_version = value
            self._builder.set_min_version(int(value))

    @property  # type: ignore[override]
    def maximum_version(self) -> TLSVersion | None:
        return self._maximum_version

    @maximum_version.setter
    def maximum_version(self, value: TLSVersion | int | None) -> None:
        if value is None or value == TLSVersion.MAXIMUM_SUPPORTED:
            self._maximum_version = TLSVersion.TLSv1_3
            self._builder.set_max_version(0x0304)  # TLS 1.3
        else:
            value = TLSVersion(value)
            self._maximum_version = value
            self._builder.set_max_version(int(value))

    @property
    def post_handshake_auth(self) -> bool:
        return self._post_handshake_auth

    @post_handshake_auth.setter
    def post_handshake_auth(self, value: bool) -> None:
        # rustls doesn't support PHA, but we store the value
        self._post_handshake_auth = value

    @property
    def keylog_filename(self) -> str | None:
        return self._keylog_filename

    @keylog_filename.setter
    def keylog_filename(self, value: str | None) -> None:
        self._keylog_filename = value
        if value:
            self._builder.set_keylog_filename(value)

    @property
    def hostname_checks_common_name(self) -> bool:
        raise AttributeError(
            "rtls does not support hostname_checks_common_name"
            " (rustls only checks SAN, never CN)"
        )

    @hostname_checks_common_name.setter
    def hostname_checks_common_name(self, value: bool) -> None:
        raise AttributeError(
            "rtls does not support hostname_checks_common_name"
            " (rustls only checks SAN, never CN)"
        )

    @property  # type: ignore[override]
    def verify_flags(self) -> int:
        return self._verify_flags

    @verify_flags.setter
    def verify_flags(self, value: int) -> None:
        self._verify_flags = int(value)
        self._builder.set_verify_flags(self._verify_flags)

    @property
    def security_level(self) -> int:  # type: ignore[override]
        """Return a high security level (rustls defaults are strong)."""
        return 2

    @property
    def sni_callback(self) -> Callable | None:
        return self._sni_callback

    @sni_callback.setter
    def sni_callback(self, callback: Callable | None) -> None:
        self._sni_callback = callback

    def cert_store_stats(self) -> dict[str, int]:
        """Return cert store statistics."""
        return {
            "x509": self._num_ca_certs,
            "x509_ca": self._num_ca_certs,
            "crl": 0,
        }

    def get_ca_certs(self, binary_form: bool = False) -> list[dict] | list[bytes]:  # type: ignore[override]
        """Return loaded CA certs."""
        if binary_form:
            return self._builder.get_root_certs_der()

        result: list[dict] = []
        try:
            from ._rustls import parse_certificate_dict

            for der in self._builder.get_root_certs_der():
                try:
                    result.append(parse_certificate_dict(der))
                except Exception:
                    pass
        except ImportError:
            pass
        return result

    def session_stats(self) -> dict[str, int]:
        """Return session cache statistics (always empty for rustls)."""
        return {
            "number": 0,
            "connect": 0,
            "connect_good": 0,
            "connect_renegotiate": 0,
            "accept": 0,
            "accept_good": 0,
            "accept_renegotiate": 0,
            "hits": 0,
            "misses": 0,
            "timeouts": 0,
            "cache_full": 0,
        }

    def set_npn_protocols(self, protocols: list[str]) -> None:  # type: ignore[override]
        """No-op — NPN is not supported by rustls."""
        pass

    def set_ech_configs(self, ech_config_list: bytes) -> TLSContext:
        """Create a **new** TLSContext clone with ECH enabled."""
        if not isinstance(ech_config_list, (bytes, bytearray, memoryview)):
            raise TypeError(
                f"expected bytes-like object, got {type(ech_config_list).__name__}"
            )

        # 1. Create a blank TLSContext (same protocol as self).
        clone = TLSContext.__new__(TLSContext, self._protocol)
        clone.__init__(self._protocol)  # type: ignore[misc]

        # 2. Replace the blank builder with a deep copy of ours.
        clone._builder = self._builder.clone_builder()

        # 3. Copy all Python-side state.
        clone._verify_mode = self._verify_mode
        clone._check_hostname = self._check_hostname
        clone._options = self._options
        clone._minimum_version = self._minimum_version
        clone._maximum_version = self._maximum_version
        clone._alpn_protocols = list(self._alpn_protocols)
        clone._ciphers_string = self._ciphers_string
        clone._sni_callback = self._sni_callback
        clone._post_handshake_auth = self._post_handshake_auth
        clone._keylog_filename = self._keylog_filename
        clone._cert_chain_loaded = self._cert_chain_loaded
        clone._ca_certs_loaded = self._ca_certs_loaded
        clone._num_ca_certs = self._num_ca_certs
        clone._verify_flags = self._verify_flags
        clone._protocol = self._protocol

        # 4. Inject ECH into the *clone* only.
        clone._builder.set_ech_configs(bytes(ech_config_list))

        # 5. ECH is inherently TLS 1.3 only — forcibly disable TLS 1.2.
        from ._constants import TLSVersion

        clone._minimum_version = TLSVersion.TLSv1_3
        clone._builder.set_min_version(int(TLSVersion.TLSv1_3))

        return clone

    @property
    def ech_enabled(self) -> bool:
        """Return True if ECH configs have been set."""
        return self._builder.has_ech()

    def _apply_version_options(self) -> None:
        """Translate OP_NO_* option flags into min/max version settings."""
        from ._constants import OP_NO_TLSv1_2, OP_NO_TLSv1_3

        # Start from the explicitly set versions (or defaults)
        min_v = int(self._minimum_version) if self._minimum_version else 0x0303
        max_v = int(self._maximum_version) if self._maximum_version else 0x0304

        # OP_NO_* can only further constrain, never loosen
        if self._options & OP_NO_TLSv1_2:
            min_v = max(min_v, 0x0304)

        if self._options & OP_NO_TLSv1_3:
            max_v = min(max_v, 0x0303)

        self._builder.set_min_version(min_v)
        self._builder.set_max_version(max_v)

    @staticmethod
    def _load_pem_data(source: str | bytes | None) -> bytes:
        """Load PEM data from a file path (str) or return raw bytes directly.

        If a ``str`` looks like inline PEM content (contains ``-----BEGIN``),
        it is encoded to bytes and returned directly instead of being treated
        as a file path.  ``bytes`` are always returned as-is (raw PEM data).
        """
        if source is None:
            raise SSLError("No certificate data provided")
        if isinstance(source, bytes):
            return source
        if isinstance(source, str):
            if "-----BEGIN" in source:
                return source.encode("ascii")
            with open(source, "rb") as f:
                return f.read()
        raise TypeError(f"Expected str or bytes, got {type(source).__name__}")

    @staticmethod
    def _validate_cert_pem(pem_data: bytes) -> None:
        """Validate that PEM data contains at least one parseable certificate.

        OpenSSL validates cert data eagerly in ``SSL_CTX_use_certificate_chain_file``.
        rustls-pemfile silently skips invalid items, so we need to check ourselves.
        """
        import base64
        import re

        # Extract all CERTIFICATE blocks
        pattern = rb"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----"
        blocks = re.findall(pattern, pem_data, re.DOTALL)
        if not blocks:
            raise SSLError(1, "[SSL] No certificate found in cert data")

        # Validate that at least one block contains valid base64 that decodes
        # to something resembling DER (at minimum, valid base64).
        for block in blocks:
            b64_data = b"".join(block.split())
            try:
                der = base64.b64decode(b64_data, validate=True)
                if len(der) < 10:
                    continue  # Too short to be a real cert
                return  # Found at least one valid cert
            except Exception:
                continue

        raise SSLError(1, "[SSL] No valid certificate found in cert data")

    def __repr__(self) -> str:
        return (
            f"<TLSContext"
            f" protocol={self._protocol}"
            f" verify_mode={self._verify_mode}"
            f" check_hostname={self._check_hostname}>"
        )
