from __future__ import annotations

import encodings.idna  # noqa: F401
import socket
import sys

from wit_world import exports

import rtls


def _connect_tls(host: str, context: rtls.SSLContext | None = None) -> rtls.SSLSocket:
    raw = socket.create_connection((host, 443))
    context = context or rtls.create_default_context()
    return context.wrap_socket(raw, server_hostname=host)


def _verified_https() -> None:
    context = rtls.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    with _connect_tls("example.com", context) as tls:
        tls.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        response = tls.recv(4096)
        assert response.startswith(b"HTTP/1.1 200 OK"), response[:100]
        assert tls.version() == "TLSv1.3"
        assert tls.selected_alpn_protocol() == "http/1.1"
        assert tls.getpeercert() is not None
        print("[ok] verified HTTPS, TLS 1.3, and ALPN")


def _tls_1_2() -> None:
    context = rtls.create_default_context()
    context.minimum_version = rtls.TLSVersion.TLSv1_2
    context.maximum_version = rtls.TLSVersion.TLSv1_2
    with _connect_tls("tls-v1-2.badssl.com", context) as tls:
        assert tls.version() == "TLSv1.2"
        print("[ok] TLS 1.2 negotiation")


def _expect_verification_failure(host: str) -> None:
    try:
        _connect_tls(host)
    except rtls.SSLCertVerificationError:
        print(f"[ok] rejected invalid certificate: {host}")
        return
    raise AssertionError(f"TLS verification unexpectedly accepted {host}")


def smoke() -> None:
    assert sys.platform == "wasi"
    assert rtls._rustls.__name__ == "rtls._wasi._rustls"
    assert rtls._rustls.crypto_provider() == "ring"
    assert not hasattr(rtls.SSLContext(rtls.PROTOCOL_TLS_CLIENT), "set_ech_configs")

    first = rtls.RAND_bytes(32)
    second = rtls.RAND_bytes(32)
    assert len(first) == 32 and len(second) == 32
    assert first != second and first != bytes(32) and second != bytes(32)
    print(f"[ok] secure random through {rtls.OPENSSL_VERSION}")

    _verified_https()
    _tls_1_2()
    _expect_verification_failure("expired.badssl.com")
    _expect_verification_failure("self-signed.badssl.com")
    _expect_verification_failure("wrong.host.badssl.com")
    print("WASI TLS survival suite passed")


class Run(exports.Run):
    async def run(self) -> None:
        smoke()
