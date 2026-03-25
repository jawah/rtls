from __future__ import annotations

from typing import Any


class TLSCertificate:
    """Wrapper around a DER-encoded X.509 certificate.

    Mimics CPython's ``_ssl.Certificate`` class (added in 3.10):
      - ``get_info()`` → dict matching ``getpeercert()`` format
      - ``public_bytes()`` → raw DER bytes
    """

    __slots__ = ("_der_bytes", "_parsed_cache")

    def __init__(self, der_bytes: bytes) -> None:
        if not isinstance(der_bytes, (bytes, bytearray, memoryview)):
            raise TypeError(
                f"expected bytes-like object, got {type(der_bytes).__name__}"
            )
        self._der_bytes: bytes = bytes(der_bytes)
        self._parsed_cache: dict[str, Any] | None = None

    def get_info(self) -> dict[str, Any]:
        """Return a dict describing the certificate, matching getpeercert() format.

        Uses the Rust-side x509-parser via ``rtls._rustls.parse_certificate_dict``.
        """
        if self._parsed_cache is not None:
            return self._parsed_cache

        try:
            from ._rustls import parse_certificate_dict

            self._parsed_cache = parse_certificate_dict(self._der_bytes)
        except ImportError:
            # Fallback: return minimal dict if Rust module not available
            self._parsed_cache = {}

        return self._parsed_cache

    def public_bytes(self) -> bytes:
        """Return the DER-encoded certificate bytes."""
        return self._der_bytes

    def __eq__(self, other: object) -> bool:
        if isinstance(other, TLSCertificate):
            return self._der_bytes == other._der_bytes
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._der_bytes)

    def __repr__(self) -> str:
        info = self.get_info()
        subject = info.get("subject", ())
        # Try to extract CN for a readable repr
        cn = ""
        for rdn in subject:
            for attr_name, attr_value in rdn:
                if attr_name == "commonName":
                    cn = attr_value
                    break
        if cn:
            return f"<TLSCertificate subject='{cn}'>"
        return f"<TLSCertificate [{len(self._der_bytes)} bytes]>"
