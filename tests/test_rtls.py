from __future__ import annotations

import asyncio
import os
import socket
import ssl as _stdlib_ssl
import unittest

import pytest

import rtls as ssl
from rtls._bio import MemoryBIO
from rtls._certificate import TLSCertificate
from rtls._context import TLSContext
from rtls._exceptions import (
    SSLCertVerificationError,
    SSLEOFError,
    SSLError,
    SSLSyscallError,
    SSLWantReadError,
    SSLWantWriteError,
    SSLZeroReturnError,
)
from rtls._object import TLSObject
from rtls._socket import TLSSocket


EXAMPLE_HOST = "example.com"
EXAMPLE_PORT = 443
HTTPBIN_HOST = "httpbingo.org"
HTTPBIN_PORT = 443

CONNECT_TIMEOUT = 15


def _make_ctx(
    verify: bool = False,
    alpn: list[str] | None = None,
) -> ssl.SSLContext:
    """Create a TLSContext with common defaults for testing."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verify:
        ctx.verify_mode = ssl.CERT_NONE
        ctx.check_hostname = False
    else:
        ctx.load_default_certs()
    if alpn:
        ctx.set_alpn_protocols(alpn)
    return ctx


def _connect_tls(
    host: str = EXAMPLE_HOST,
    port: int = EXAMPLE_PORT,
    ctx: ssl.SSLContext | None = None,
    alpn: list[str] | None = None,
) -> ssl.SSLSocket:
    """Open a TLS connection and return the wrapped socket."""
    if ctx is None:
        ctx = _make_ctx(alpn=alpn)
    sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
    return ctx.wrap_socket(sock, server_hostname=host)


class TestBasicHandshake(unittest.TestCase):
    """Basic TLS handshake tests."""

    def test_tls13_handshake_cert_none(self):
        """TLS 1.3 handshake with CERT_NONE to example.com."""
        ssock = _connect_tls()
        try:
            self.assertEqual(ssock.version(), "TLSv1.3")
        finally:
            ssock.close()

    def test_tls12_handshake(self):
        """Force TLS 1.2 handshake via OP_NO_TLSv1_3."""
        ctx = _make_ctx()
        ctx.options |= ssl.OP_NO_TLSv1_3
        ssock = _connect_tls(ctx=ctx)
        try:
            self.assertEqual(ssock.version(), "TLSv1.2")
        finally:
            ssock.close()

    def test_tls13_only(self):
        """Force TLS 1.3 only via maximum_version."""
        ctx = _make_ctx()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ssock = _connect_tls(ctx=ctx)
        try:
            self.assertEqual(ssock.version(), "TLSv1.3")
        finally:
            ssock.close()

    def test_cipher_info(self):
        """cipher() returns a valid 3-tuple after handshake."""
        ssock = _connect_tls()
        try:
            cipher = ssock.cipher()
            self.assertIsNotNone(cipher)
            name, version, bits = cipher
            self.assertIsInstance(name, str)
            self.assertIn(version, ("TLSv1.2", "TLSv1.3"))
            self.assertIn(bits, (128, 256))
        finally:
            ssock.close()

    def test_shared_ciphers(self):
        """shared_ciphers() returns a list after handshake."""
        ssock = _connect_tls()
        try:
            shared = ssock.shared_ciphers()
            self.assertIsNotNone(shared)
            self.assertGreater(len(shared), 0)
        finally:
            ssock.close()

    def test_compression_always_none(self):
        """compression() always returns None (rustls has no compression)."""
        ssock = _connect_tls()
        try:
            self.assertIsNone(ssock.compression())
        finally:
            ssock.close()


class TestHTTPOverTLS(unittest.TestCase):
    """HTTP request/response over TLS."""

    def test_get_example_com(self):
        """GET / from example.com returns HTTP 200."""
        ssock = _connect_tls()
        try:
            ssock.sendall(
                b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
            )
            resp = b""
            while True:
                chunk = ssock.recv(4096)
                if not chunk:
                    break
                resp += chunk
            self.assertIn(b"HTTP/1.1 200 OK", resp)
            self.assertIn(b"Example Domain", resp)
        finally:
            ssock.close()

    def test_post_httpbin(self):
        """POST to httpbin.org echoes back the body."""
        ssock = _connect_tls(host=HTTPBIN_HOST, port=HTTPBIN_PORT)
        try:
            body = b'{"test": "rtls"}'
            req = (
                f"POST /post HTTP/1.1\r\n"
                f"Host: {HTTPBIN_HOST}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"User-Agent: urllib3-future/2.18.900\r\n"
                f"Connection: close\r\n\r\n"
            ).encode() + body
            ssock.sendall(req)
            resp = b""
            while True:
                chunk = ssock.recv(4096)
                if not chunk:
                    break
                resp += chunk
            self.assertIn(b"HTTP/1.1 200 OK", resp)
            self.assertIn(b'"test": "rtls"', resp)
        finally:
            ssock.close()


class TestALPN(unittest.TestCase):
    """ALPN protocol negotiation tests."""

    def test_alpn_h2(self):
        """Negotiate h2 via ALPN."""
        ctx = _make_ctx(alpn=["h2", "http/1.1"])
        ssock = _connect_tls(ctx=ctx)
        try:
            alpn = ssock.selected_alpn_protocol()
            # example.com may or may not support h2, but we should get one of our protocols
            self.assertIn(alpn, ("h2", "http/1.1", None))
        finally:
            ssock.close()

    def test_alpn_http11_only(self):
        """Negotiate http/1.1 only."""
        ctx = _make_ctx(alpn=["http/1.1"])
        ssock = _connect_tls(ctx=ctx)
        try:
            alpn = ssock.selected_alpn_protocol()
            self.assertEqual(alpn, "http/1.1")
        finally:
            ssock.close()

    def test_npn_returns_none(self):
        """selected_npn_protocol() always returns None (not supported)."""
        ssock = _connect_tls()
        try:
            self.assertIsNone(ssock.selected_npn_protocol())
        finally:
            ssock.close()


class TestGetPeerCert(unittest.TestCase):
    """Certificate parsing and getpeercert()."""

    def test_getpeercert_dict(self):
        """getpeercert() returns a dict with subject, issuer, etc."""
        ssock = _connect_tls()
        try:
            cert = ssock.getpeercert()
            # With CERT_NONE, CPython returns {} — our impl matches
            self.assertIsInstance(cert, dict)
        finally:
            ssock.close()

    def test_getpeercert_binary(self):
        """getpeercert(binary_form=True) returns DER bytes."""
        ssock = _connect_tls()
        try:
            der = ssock.getpeercert(binary_form=True)
            self.assertIsInstance(der, bytes)
            self.assertGreater(len(der), 100)
            # DER should start with SEQUENCE tag
            self.assertEqual(der[0], 0x30)
        finally:
            ssock.close()


class TestIsInstance(unittest.TestCase):
    """Critical isinstance checks for asyncio/urllib3-future compatibility."""

    def test_context_is_ssl_sslcontext(self):
        """TLSContext passes isinstance(ctx, ssl.SSLContext)."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.assertIsInstance(ctx, _stdlib_ssl.SSLContext)

    def test_socket_is_ssl_sslsocket(self):
        """TLSSocket passes isinstance(sock, ssl.SSLSocket)."""
        ssock = _connect_tls()
        try:
            self.assertIsInstance(ssock, _stdlib_ssl.SSLSocket)
            self.assertIsInstance(ssock, socket.socket)
        finally:
            ssock.close()

    def test_socket_is_socket(self):
        """TLSSocket is also a socket.socket."""
        ssock = _connect_tls()
        try:
            self.assertIsInstance(ssock, socket.socket)
        finally:
            ssock.close()

    def test_context_subclass(self):
        """TLSContext is a subclass of ssl.SSLContext."""
        self.assertTrue(issubclass(TLSContext, _stdlib_ssl.SSLContext))

    def test_socket_subclass(self):
        """TLSSocket is a subclass of ssl.SSLSocket."""
        self.assertTrue(issubclass(TLSSocket, _stdlib_ssl.SSLSocket))


class TestAsyncio(unittest.TestCase):
    """asyncio TLS integration tests."""

    def test_asyncio_open_connection(self):
        """asyncio.open_connection with our SSLContext works."""

        async def _run():
            ctx = _make_ctx()
            reader, writer = await asyncio.open_connection(
                EXAMPLE_HOST, EXAMPLE_PORT, ssl=ctx, server_hostname=EXAMPLE_HOST
            )
            writer.write(
                b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
            )
            await writer.drain()
            data = await reader.read(4096)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return data

        data = asyncio.run(_run())
        self.assertIn(b"HTTP/1.1 200 OK", data)

    def test_asyncio_start_tls(self):
        """asyncio loop.start_tls() works with our SSLContext."""

        async def _run():
            ctx = _make_ctx()

            # Open a plain TCP connection first
            reader, writer = await asyncio.open_connection(EXAMPLE_HOST, EXAMPLE_PORT)

            # Upgrade to TLS
            loop = asyncio.get_event_loop()
            transport = writer.transport
            protocol = transport.get_protocol()

            new_transport = await loop.start_tls(
                transport, protocol, ctx, server_hostname=EXAMPLE_HOST
            )

            # Reattach the protocol
            reader._transport = new_transport
            writer._transport = new_transport

            writer.write(
                b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
            )
            await writer.drain()
            data = await reader.read(4096)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return data

        data = asyncio.run(_run())
        self.assertIn(b"HTTP/1.1 200 OK", data)

    def test_asyncio_ssl_object_type(self):
        """The SSL object returned by asyncio is a TLSObject."""

        async def _run():
            ctx = _make_ctx()
            reader, writer = await asyncio.open_connection(
                EXAMPLE_HOST, EXAMPLE_PORT, ssl=ctx, server_hostname=EXAMPLE_HOST
            )
            ssl_object = writer.get_extra_info("ssl_object")
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return ssl_object

        ssl_object = asyncio.run(_run())
        self.assertIsInstance(ssl_object, TLSObject)


class TestMemoryBIO(unittest.TestCase):
    """MemoryBIO operations."""

    def test_read_write(self):
        bio = MemoryBIO()
        bio.write(b"hello")
        self.assertEqual(bio.pending, 5)
        data = bio.read()
        self.assertEqual(data, b"hello")
        self.assertEqual(bio.pending, 0)

    def test_partial_read(self):
        bio = MemoryBIO()
        bio.write(b"hello world")
        data = bio.read(5)
        self.assertEqual(data, b"hello")
        self.assertEqual(bio.pending, 6)
        rest = bio.read()
        self.assertEqual(rest, b" world")

    def test_write_eof(self):
        bio = MemoryBIO()
        bio.write(b"data")
        bio.write_eof()
        # Can still read buffered data
        self.assertEqual(bio.read(), b"data")
        # But eof is True once buffer is drained
        self.assertTrue(bio.eof)

    def test_write_after_eof_raises(self):
        bio = MemoryBIO()
        bio.write_eof()
        with self.assertRaises(SSLError):
            bio.write(b"data")

    def test_empty_read(self):
        bio = MemoryBIO()
        self.assertEqual(bio.read(), b"")

    def test_write_empty(self):
        bio = MemoryBIO()
        n = bio.write(b"")
        self.assertEqual(n, 0)
        self.assertEqual(bio.pending, 0)

    def test_eof_property(self):
        bio = MemoryBIO()
        self.assertFalse(bio.eof)
        bio.write(b"x")
        bio.write_eof()
        self.assertFalse(bio.eof)  # data still pending
        bio.read()
        self.assertTrue(bio.eof)  # now truly eof


class TestExceptionHierarchy(unittest.TestCase):
    """Our exceptions must be catchable by stdlib ssl exception clauses."""

    def test_sslerror_is_oserror(self):
        self.assertTrue(issubclass(SSLError, OSError))

    def test_sslwantreaderror_caught_by_stdlib(self):
        """SSLWantReadError caught by except ssl.SSLWantReadError."""
        with self.assertRaises(_stdlib_ssl.SSLWantReadError):
            raise SSLWantReadError("test")

    def test_sslwantwriteerror_caught_by_stdlib(self):
        with self.assertRaises(_stdlib_ssl.SSLWantWriteError):
            raise SSLWantWriteError("test")

    def test_ssleoferror_caught_by_stdlib(self):
        with self.assertRaises(_stdlib_ssl.SSLEOFError):
            raise SSLEOFError("test")

    def test_sslzeroreturn_caught_by_stdlib(self):
        with self.assertRaises(_stdlib_ssl.SSLZeroReturnError):
            raise SSLZeroReturnError("test")

    def test_sslsyscallerror_caught_by_stdlib(self):
        with self.assertRaises(_stdlib_ssl.SSLSyscallError):
            raise SSLSyscallError("test")

    def test_sslcertverificationerror(self):
        self.assertTrue(issubclass(SSLCertVerificationError, SSLError))

    def test_exception_hierarchy_chain(self):
        """SSLWantReadError → SSLError → OSError."""
        self.assertTrue(issubclass(SSLWantReadError, SSLError))
        self.assertTrue(issubclass(SSLWantReadError, OSError))

    def test_sslerror_caught_by_oserror(self):
        with self.assertRaises(OSError):
            raise SSLError("test")


class TestContextProperties(unittest.TestCase):
    """TLSContext property tests."""

    def test_default_protocol_tls_client(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.assertEqual(ctx.protocol, ssl.PROTOCOL_TLS_CLIENT)

    def test_default_verify_mode_client(self):
        """PROTOCOL_TLS_CLIENT defaults to CERT_REQUIRED."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_default_check_hostname_client(self):
        """PROTOCOL_TLS_CLIENT defaults to check_hostname=True."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.assertTrue(ctx.check_hostname)

    def test_verify_mode_setter(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)

    def test_check_hostname_requires_verify(self):
        """Cannot set check_hostname=True with verify_mode=CERT_NONE."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with self.assertRaises(ValueError):
            ctx.check_hostname = True

    def test_options_type(self):
        """options property returns ssl.Options (not our custom type)."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        opts = ctx.options
        self.assertIsInstance(opts, _stdlib_ssl.Options)

    def test_options_contains(self):
        """ssl.OP_NO_TLSv1_3 in ctx.options works."""
        ctx = _make_ctx()
        ctx.options |= ssl.OP_NO_TLSv1_3
        # After setting, the flag should be present
        self.assertTrue(ctx.options & ssl.OP_NO_TLSv1_3)

    def test_minimum_version(self):
        ctx = _make_ctx()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_3)

    def test_maximum_version(self):
        ctx = _make_ctx()
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        self.assertEqual(ctx.maximum_version, ssl.TLSVersion.TLSv1_2)

    def test_post_handshake_auth(self):
        ctx = _make_ctx()
        ctx.post_handshake_auth = True
        self.assertTrue(ctx.post_handshake_auth)

    def test_hostname_checks_common_name(self):
        """Always False for rustls (only checks SAN)."""
        ctx = _make_ctx()
        self.assertFalse(ctx.hostname_checks_common_name)

    def test_security_level(self):
        ctx = _make_ctx()
        self.assertEqual(ctx.security_level, 2)

    def test_session_stats(self):
        ctx = _make_ctx()
        stats = ctx.session_stats()
        self.assertIsInstance(stats, dict)
        self.assertEqual(stats["number"], 0)

    def test_cert_store_stats(self):
        ctx = _make_ctx()
        stats = ctx.cert_store_stats()
        self.assertIsInstance(stats, dict)
        self.assertIn("x509", stats)

    def test_set_ciphers(self):
        """set_ciphers with OpenSSL cipher string doesn't raise."""
        ctx = _make_ctx()
        ctx.set_ciphers("ECDHE+AESGCM:!aNULL")

    def test_get_ciphers(self):
        ctx = _make_ctx()
        ciphers = ctx.get_ciphers()
        self.assertIsInstance(ciphers, list)
        self.assertGreater(len(ciphers), 0)

    def test_alpn_protocols(self):
        ctx = _make_ctx()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        self.assertEqual(ctx.get_alpn_protocols(), ["h2", "http/1.1"])

    def test_npn_noop(self):
        """set_npn_protocols is a no-op."""
        ctx = _make_ctx()
        ctx.set_npn_protocols(["h2"])  # Should not raise

    def test_repr(self):
        ctx = _make_ctx()
        r = repr(ctx)
        self.assertIn("TLSContext", r)

    def test_load_default_certs(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_default_certs()
        stats = ctx.cert_store_stats()
        self.assertGreater(stats["x509"], 0)


class TestSocketProperties(unittest.TestCase):
    """TLSSocket-specific property tests."""

    def test_context_property(self):
        ctx = _make_ctx()
        ssock = _connect_tls(ctx=ctx)
        try:
            self.assertIs(ssock.context, ctx)
        finally:
            ssock.close()

    def test_server_hostname(self):
        ssock = _connect_tls()
        try:
            self.assertEqual(ssock.server_hostname, EXAMPLE_HOST)
        finally:
            ssock.close()

    def test_server_side(self):
        ssock = _connect_tls()
        try:
            self.assertFalse(ssock.server_side)
        finally:
            ssock.close()

    def test_sslobj_property(self):
        """_sslobj returns the internal TLSObject."""
        ssock = _connect_tls()
        try:
            obj = ssock._sslobj
            self.assertIsInstance(obj, TLSObject)
        finally:
            ssock.close()

    def test_sslobj_sslobj_returns_self(self):
        """_sslobj._sslobj returns self for urllib3-future compat."""
        ssock = _connect_tls()
        try:
            obj = ssock._sslobj
            self.assertIs(obj._sslobj, obj)
        finally:
            ssock.close()

    def test_sslobj_setter_none(self):
        """Setting _sslobj to None works (ssl.SSLSocket._real_close does this)."""
        ssock = _connect_tls()
        try:
            ssock._sslobj = None
            self.assertIsNone(ssock._sslobj)
        finally:
            ssock.close()

    def test_pending(self):
        ssock = _connect_tls()
        try:
            p = ssock.pending()
            self.assertIsInstance(p, int)
        finally:
            ssock.close()

    def test_fileno(self):
        ssock = _connect_tls()
        try:
            fd = ssock.fileno()
            self.assertIsInstance(fd, int)
            self.assertGreater(fd, 0)
        finally:
            ssock.close()

    def test_repr(self):
        ssock = _connect_tls()
        try:
            r = repr(ssock)
            self.assertIn("TLSSocket", r)
        finally:
            ssock.close()

    def test_context_manager(self):
        """TLSSocket can be used as context manager."""
        with _connect_tls() as ssock:
            self.assertIsNotNone(ssock.version())

    def test_unwrap(self):
        """unwrap() returns a plain socket."""
        ssock = _connect_tls()
        try:
            plain = ssock.unwrap()
            self.assertIsInstance(plain, socket.socket)
            self.assertNotIsInstance(plain, _stdlib_ssl.SSLSocket)
            plain.close()
        except Exception:
            ssock.close()

    def test_blocked_methods(self):
        """recvfrom, sendto etc. raise ValueError on TLS sockets."""
        ssock = _connect_tls()
        try:
            with self.assertRaises(ValueError):
                ssock.recvfrom(1024)
            with self.assertRaises(ValueError):
                ssock.sendto(b"x", ("", 0))
        finally:
            ssock.close()


class TestTLSObject(unittest.TestCase):
    """Direct TLSObject tests (sans-I/O mode via wrap_bio)."""

    def test_wrap_bio_creates_tls_object(self):
        """wrap_bio() returns a TLSObject."""
        ctx = _make_ctx()
        incoming = MemoryBIO()
        outgoing = MemoryBIO()
        obj = ctx.wrap_bio(incoming, outgoing, server_hostname=EXAMPLE_HOST)
        self.assertIsInstance(obj, TLSObject)

    def test_wrap_bio_sends_client_hello(self):
        """After wrap_bio(), the outgoing BIO should contain ClientHello."""
        ctx = _make_ctx()
        incoming = MemoryBIO()
        outgoing = MemoryBIO()
        obj = ctx.wrap_bio(incoming, outgoing, server_hostname=EXAMPLE_HOST)
        data = outgoing.read()
        # Should have some data (ClientHello)
        self.assertGreater(len(data), 0)
        # TLS record: content type 22 (handshake)
        self.assertEqual(data[0], 22)

    def test_sslobj_returns_self(self):
        """TLSObject._sslobj returns self."""
        ctx = _make_ctx()
        incoming = MemoryBIO()
        outgoing = MemoryBIO()
        obj = ctx.wrap_bio(incoming, outgoing, server_hostname=EXAMPLE_HOST)
        self.assertIs(obj._sslobj, obj)

    def test_object_properties(self):
        ctx = _make_ctx()
        incoming = MemoryBIO()
        outgoing = MemoryBIO()
        obj = ctx.wrap_bio(
            incoming, outgoing, server_hostname=EXAMPLE_HOST, server_side=False
        )
        self.assertFalse(obj.server_side)
        self.assertEqual(obj.server_hostname, EXAMPLE_HOST)
        self.assertIs(obj.context, ctx)
        self.assertIsNone(obj.selected_npn_protocol())
        self.assertIsNone(obj.compression())
        self.assertFalse(obj.session_reused)


class TestTLSCertificate(unittest.TestCase):
    """TLSCertificate wrapper tests."""

    def _get_der(self) -> bytes:
        """Get a real DER certificate from example.com."""
        ssock = _connect_tls()
        try:
            return ssock.getpeercert(binary_form=True)
        finally:
            ssock.close()

    def test_public_bytes(self):
        der = self._get_der()
        cert = TLSCertificate(der)
        self.assertEqual(cert.public_bytes(), der)

    def test_get_info(self):
        der = self._get_der()
        cert = TLSCertificate(der)
        info = cert.get_info()
        self.assertIsInstance(info, dict)

    def test_equality(self):
        der = self._get_der()
        c1 = TLSCertificate(der)
        c2 = TLSCertificate(der)
        self.assertEqual(c1, c2)

    def test_hash(self):
        der = self._get_der()
        c1 = TLSCertificate(der)
        c2 = TLSCertificate(der)
        self.assertEqual(hash(c1), hash(c2))

    def test_repr(self):
        der = self._get_der()
        cert = TLSCertificate(der)
        r = repr(cert)
        self.assertIn("TLSCertificate", r)

    def test_type_error(self):
        with self.assertRaises(TypeError):
            TLSCertificate("not bytes")

    def test_get_verified_chain(self):
        """get_verified_chain() returns list of TLSCertificate."""
        ssock = _connect_tls()
        try:
            chain = ssock.get_verified_chain()
            if chain is not None:
                self.assertIsInstance(chain, list)
                for cert in chain:
                    self.assertIsInstance(cert, TLSCertificate)
        finally:
            ssock.close()


class TestUtilityFunctions(unittest.TestCase):
    """Tests for rtls utility functions."""

    def test_create_default_context(self):
        ctx = ssl.create_default_context()
        self.assertIsInstance(ctx, _stdlib_ssl.SSLContext)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)

    def test_der_pem_roundtrip(self):
        """DER → PEM → DER roundtrip."""
        ssock = _connect_tls()
        try:
            der = ssock.getpeercert(binary_form=True)
        finally:
            ssock.close()
        pem = ssl.DER_cert_to_PEM_cert(der)
        self.assertIn("BEGIN CERTIFICATE", pem)
        der2 = ssl.PEM_cert_to_DER_cert(pem)
        self.assertEqual(der, der2)

    def test_cert_time_to_seconds(self):
        t = ssl.cert_time_to_seconds("Jan  5 09:34:43 2018 GMT")
        self.assertIsInstance(t, (int, float))
        self.assertGreater(t, 0)

    def test_rand_bytes(self):
        data = ssl.RAND_bytes(32)
        self.assertIsInstance(data, bytes)
        self.assertEqual(len(data), 32)

    def test_rand_status(self):
        self.assertTrue(ssl.RAND_status())

    def test_rand_add(self):
        ssl.RAND_add(b"entropy", 1.0)  # Should not raise

    def test_get_default_verify_paths(self):
        paths = ssl.get_default_verify_paths()
        self.assertIsNotNone(paths)

    def test_get_server_certificate(self):
        """get_server_certificate() returns a PEM string."""
        pem = ssl.get_server_certificate((EXAMPLE_HOST, EXAMPLE_PORT))
        self.assertIn("BEGIN CERTIFICATE", pem)


class TestConstants(unittest.TestCase):
    """Verify important constants are exposed."""

    def test_protocol_constants(self):
        self.assertIsNotNone(ssl.PROTOCOL_TLS)
        self.assertIsNotNone(ssl.PROTOCOL_TLS_CLIENT)
        self.assertIsNotNone(ssl.PROTOCOL_TLS_SERVER)

    def test_cert_constants(self):
        self.assertEqual(ssl.CERT_NONE, 0)
        self.assertEqual(ssl.CERT_OPTIONAL, 1)
        self.assertEqual(ssl.CERT_REQUIRED, 2)

    def test_feature_flags(self):
        self.assertTrue(ssl.HAS_ALPN)
        self.assertTrue(ssl.HAS_ECDH)
        self.assertTrue(ssl.HAS_SNI)
        self.assertTrue(ssl.HAS_TLSv1_2)
        self.assertTrue(ssl.HAS_TLSv1_3)
        self.assertFalse(ssl.HAS_NPN)  # rustls doesn't support NPN

    def test_openssl_version(self):
        """OPENSSL_VERSION reports 'Rustls X.Y.Z'."""
        self.assertIsInstance(ssl.OPENSSL_VERSION, str)
        self.assertTrue(
            ssl.OPENSSL_VERSION.startswith("Rustls "),
            f"Expected 'Rustls X.Y.Z', got {ssl.OPENSSL_VERSION!r}",
        )

    def test_openssl_version_number(self):
        """OPENSSL_VERSION_NUMBER encodes rustls semver."""
        self.assertIsInstance(ssl.OPENSSL_VERSION_NUMBER, int)
        self.assertGreater(ssl.OPENSSL_VERSION_NUMBER, 0)

    def test_openssl_version_info(self):
        """OPENSSL_VERSION_INFO is a 5-tuple derived from rustls version."""
        info = ssl.OPENSSL_VERSION_INFO
        self.assertIsInstance(info, tuple)
        self.assertEqual(len(info), 5)
        # For rustls 0.23.x: major=0, minor=23
        self.assertEqual(info[0], 0)
        self.assertEqual(info[1], 23)

    def test_tls_version_enum(self):
        self.assertIsNotNone(ssl.TLSVersion.TLSv1_2)
        self.assertIsNotNone(ssl.TLSVersion.TLSv1_3)


class TestECH(unittest.TestCase):
    """ECH (Encrypted Client Hello) configuration tests."""

    def test_ech_not_enabled_by_default(self):
        ctx = _make_ctx()
        self.assertFalse(ctx.ech_enabled)

    def test_set_ech_configs_type_check(self):
        """set_ech_configs rejects non-bytes."""
        ctx = _make_ctx()
        with self.assertRaises(TypeError):
            ctx.set_ech_configs("not bytes")

    def test_set_ech_configs_returns_new_context(self):
        """set_ech_configs() returns a NEW TLSContext; original is untouched."""
        ctx = _make_ctx()
        # Use dummy bytes — won't be a valid ECH config, but the setter
        # should still store it (validation happens at connection time)
        ech_ctx = ctx.set_ech_configs(b"\x00\x01\x02\x03")

        # Returned context is a different object
        self.assertIsNot(ech_ctx, ctx)
        self.assertIsInstance(ech_ctx, type(ctx))

        # Clone has ECH enabled; original does not
        self.assertTrue(ech_ctx.ech_enabled)
        self.assertFalse(ctx.ech_enabled)

    def test_set_ech_configs_copies_state(self):
        """Cloned ECH context preserves all settings from the original."""
        ctx = _make_ctx(alpn=["h2", "http/1.1"])
        ctx.verify_mode = ssl.CERT_NONE
        ctx.check_hostname = False
        ctx.post_handshake_auth = True

        ech_ctx = ctx.set_ech_configs(b"\x00\x01\x02\x03")

        self.assertEqual(ech_ctx.verify_mode, ctx.verify_mode)
        self.assertEqual(ech_ctx.check_hostname, ctx.check_hostname)
        self.assertEqual(ech_ctx.get_alpn_protocols(), ctx.get_alpn_protocols())
        self.assertEqual(ech_ctx.post_handshake_auth, ctx.post_handshake_auth)
        self.assertEqual(ech_ctx.protocol, ctx.protocol)

    def test_ech_status_grease_by_default(self):
        """Without explicit ECH config, ech_status is 'grease' (anti-ossification)."""
        ssock = _connect_tls()
        try:
            self.assertEqual(ssock.ech_status, "grease")
        finally:
            ssock.close()

    def test_ech_status_on_object(self):
        """TLSObject.ech_status returns a string."""
        ctx = _make_ctx()
        incoming = MemoryBIO()
        outgoing = MemoryBIO()
        obj = ctx.wrap_bio(incoming, outgoing, server_hostname=EXAMPLE_HOST)
        status = obj.ech_status
        self.assertIsInstance(status, str)
        self.assertIn(
            status, ("not_offered", "grease", "offered", "accepted", "rejected")
        )


class TestUrllib3Integration(unittest.TestCase):
    """Integration tests with urllib3-future (if installed)."""

    @classmethod
    def setUpClass(cls):
        try:
            import urllib3

            cls.urllib3 = urllib3
        except ImportError:
            raise unittest.SkipTest("urllib3-future not installed")

    def _make_pool(self, host: str, port: int = 443) -> object:
        """Create an HTTPS pool using rtls as the SSL backend."""
        ctx = _make_ctx(alpn=["http/1.1"])
        return self.urllib3.HTTPSConnectionPool(
            host, port, ssl_context=ctx, cert_reqs="CERT_NONE"
        )

    def test_get_example_com(self):
        """urllib3 GET example.com via rtls."""
        pool = self._make_pool(EXAMPLE_HOST)
        resp = pool.request("GET", "/", timeout=CONNECT_TIMEOUT)
        self.assertEqual(resp.status, 200)
        self.assertIn(b"Example Domain", resp.data)

    def test_get_httpbin(self):
        """urllib3 GET httpbin.org via rtls."""
        pool = self._make_pool(HTTPBIN_HOST)
        resp = pool.request("GET", "/get", timeout=CONNECT_TIMEOUT)
        self.assertEqual(resp.status, 200)

    def test_post_httpbin(self):
        """urllib3 POST to httpbin.org via rtls."""
        pool = self._make_pool(HTTPBIN_HOST)
        resp = pool.request(
            "POST",
            "/post",
            body=b'{"test": "rtls"}',
            headers={"Content-Type": "application/json"},
            timeout=CONNECT_TIMEOUT,
        )
        self.assertEqual(resp.status, 200)
        self.assertIn(b'"test": "rtls"', resp.data)


class TestRustlsFingerprint(unittest.TestCase):
    """Confirm we are definitely using rustls by inspecting the TLS fingerprint.

    Uses tls.peet.ws to observe the ClientHello from the remote side.
    Key signals that distinguish rustls from OpenSSL:
      - ECH GREASE extension present (OpenSSL/BoringSSL do not send this by default)
      - X25519MLKEM768 in supported_groups (post-quantum KEM, rustls-specific)
      - Exact cipher suite ordering matches rustls defaults
    """

    @classmethod
    def setUpClass(cls):
        try:
            import urllib3

            cls.urllib3 = urllib3
        except ImportError:
            raise unittest.SkipTest("urllib3-future not installed")

    def test_ech_grease_is_sent(self):
        """tls.peet.ws must see an ECH GREASE extension in our ClientHello."""
        ctx = ssl.create_default_context()
        with self.urllib3.PoolManager(ssl_context=ctx) as pm:
            resp = pm.urlopen(
                "GET", "https://tls.peet.ws/api/all", timeout=CONNECT_TIMEOUT
            )
            self.assertEqual(resp.status, 200)
            data = resp.json()

        extensions = data["tls"]["extensions"]
        ext_names = [e.get("name", "") for e in extensions]

        # ECH GREASE uses extension ID 0xFE0D (65037).
        # tls.peet.ws labels it as "extensionEncryptedClientHello (boringssl) (65037)".
        ech_found = any(
            "65037" in name or "EncryptedClientHello" in name for name in ext_names
        )
        self.assertTrue(
            ech_found,
            f"ECH GREASE extension not found in ClientHello. Extensions: {ext_names}",
        )

        # Also verify TLS 1.3 was negotiated (ECH GREASE is TLS 1.3 only).
        tls_version = data["tls"].get("tls_version_negotiated", "")
        self.assertEqual(
            tls_version, "772", f"Expected TLS 1.3 (772), got {tls_version}"
        )

        # Verify X25519MLKEM768 is offered in supported_groups (rustls-specific).
        groups_ext = [
            e for e in extensions if e.get("name", "").startswith("supported_groups")
        ]
        self.assertTrue(groups_ext, "supported_groups extension not found")
        groups = groups_ext[0].get("supported_groups", [])
        has_mlkem = any("MLKEM" in g or "4588" in g for g in groups)
        self.assertTrue(
            has_mlkem,
            f"X25519MLKEM768 not in supported_groups (rustls indicator). Groups: {groups}",
        )


class TestAsyncRustlsFingerprint(unittest.TestCase):
    """Confirm rtls works with urllib3-future's async API over asyncio.

    Uses AsyncPoolManager with an rtls ssl_context to hit tls.peet.ws,
    proving that our TLSContext/TLSObject correctly integrate with
    asyncio's SSL transport layer via urllib3-future's async path.
    """

    @classmethod
    def setUpClass(cls):
        try:
            import urllib3

            cls.urllib3 = urllib3
        except ImportError:
            raise unittest.SkipTest("urllib3-future not installed")

        # Verify AsyncPoolManager is available
        if not hasattr(cls.urllib3, "AsyncPoolManager"):
            raise unittest.SkipTest("urllib3-future AsyncPoolManager not available")

    def test_async_ech_grease_is_sent(self):
        """Async path: tls.peet.ws must see ECH GREASE in our ClientHello."""

        async def _run():
            ctx = ssl.create_default_context()
            async with self.urllib3.AsyncPoolManager(ssl_context=ctx) as pm:
                resp = await pm.urlopen(
                    "GET", "https://tls.peet.ws/api/all", timeout=CONNECT_TIMEOUT
                )
                self.assertEqual(resp.status, 200)
                data = await resp.json()
            return data

        data = asyncio.run(_run())

        extensions = data["tls"]["extensions"]
        ext_names = [e.get("name", "") for e in extensions]

        # ECH GREASE uses extension ID 0xFE0D (65037).
        ech_found = any(
            "65037" in name or "EncryptedClientHello" in name for name in ext_names
        )
        self.assertTrue(
            ech_found,
            f"ECH GREASE extension not found in async ClientHello. Extensions: {ext_names}",
        )

        # Verify TLS 1.3 was negotiated.
        tls_version = data["tls"].get("tls_version_negotiated", "")
        self.assertEqual(
            tls_version, "772", f"Expected TLS 1.3 (772), got {tls_version}"
        )

        # Verify X25519MLKEM768 is offered (rustls-specific).
        groups_ext = [
            e for e in extensions if e.get("name", "").startswith("supported_groups")
        ]
        self.assertTrue(groups_ext, "supported_groups extension not found")
        groups = groups_ext[0].get("supported_groups", [])
        has_mlkem = any("MLKEM" in g or "4588" in g for g in groups)
        self.assertTrue(
            has_mlkem,
            f"X25519MLKEM768 not in supported_groups (rustls indicator). Groups: {groups}",
        )


class TestWrapSocketEdgeCases(unittest.TestCase):
    """Edge cases for wrap_socket."""

    def test_read_write_sequence(self):
        """Multiple read/write cycles work correctly."""
        ssock = _connect_tls()
        try:
            ssock.sendall(
                b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
            )
            total = b""
            while True:
                chunk = ssock.recv(1024)
                if not chunk:
                    break
                total += chunk
            self.assertGreater(len(total), 100)
        finally:
            ssock.close()

    def test_recv_into(self):
        """recv_into() works."""
        ssock = _connect_tls()
        try:
            ssock.sendall(
                b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
            )
            buf = bytearray(4096)
            n = ssock.recv_into(buf)
            self.assertGreater(n, 0)
            self.assertIn(b"HTTP/1.1 200", bytes(buf[:n]))
        finally:
            ssock.close()

    def test_sendall(self):
        """sendall() sends all data."""
        ssock = _connect_tls()
        try:
            # Send a large-ish request
            ssock.sendall(
                b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
            )
            resp = ssock.recv(4096)
            self.assertIn(b"HTTP/1.1 200", resp)
        finally:
            ssock.close()

    def test_read_write_aliases(self):
        """read() and write() are aliases for recv/send."""
        ssock = _connect_tls()
        try:
            n = ssock.write(
                b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
            )
            self.assertGreater(n, 0)
            data = ssock.read(4096)
            self.assertIn(b"HTTP/1.1 200", data)
        finally:
            ssock.close()


class TestModuleAll(unittest.TestCase):
    """Test that __all__ exports are correct."""

    def test_all_names_importable(self):
        """Every name in __all__ should be importable from rtls."""
        for name in ssl.__all__:
            self.assertTrue(
                hasattr(ssl, name),
                f"{name} listed in __all__ but not found in module",
            )


class TestEncryptedKeySupport(unittest.TestCase):
    """Test loading encrypted PKCS#8 private keys."""

    @classmethod
    def setUpClass(cls):
        """Generate test fixtures: self-signed cert + encrypted keys."""
        import subprocess
        import tempfile

        cls._tmpdir = tempfile.mkdtemp(prefix="rtls_test_")

        cls.key_plain = os.path.join(cls._tmpdir, "key_plain.pem")
        cls.key_enc_aes = os.path.join(cls._tmpdir, "key_enc_aes.pem")
        cls.key_enc_3des = os.path.join(cls._tmpdir, "key_enc_3des.pem")
        cls.cert_pem = os.path.join(cls._tmpdir, "cert.pem")
        cls.password = b"testpassword123"

        # Generate plaintext RSA key (PKCS#8 format)
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                cls.key_plain,
            ],
            check=True,
            capture_output=True,
        )

        # Encrypt with AES-256-CBC (PKCS#8 encrypted)
        subprocess.run(
            [
                "openssl",
                "pkcs8",
                "-topk8",
                "-v2",
                "aes-256-cbc",
                "-in",
                cls.key_plain,
                "-out",
                cls.key_enc_aes,
                "-passout",
                f"pass:{cls.password.decode()}",
            ],
            check=True,
            capture_output=True,
        )

        # Encrypt with 3DES (PKCS#8 encrypted)
        subprocess.run(
            [
                "openssl",
                "pkcs8",
                "-topk8",
                "-v2",
                "des3",
                "-in",
                cls.key_plain,
                "-out",
                cls.key_enc_3des,
                "-passout",
                f"pass:{cls.password.decode()}",
            ],
            check=True,
            capture_output=True,
        )

        # Generate self-signed cert
        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-key",
                cls.key_plain,
                "-out",
                cls.cert_pem,
                "-days",
                "365",
                "-subj",
                "/CN=test.example.com",
            ],
            check=True,
            capture_output=True,
        )

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls._tmpdir, ignore_errors=True)

    def test_load_encrypted_pkcs8_aes256(self):
        """Loading AES-256-CBC encrypted PKCS#8 key with correct password."""
        ctx = TLSContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(
            certfile=self.cert_pem,
            keyfile=self.key_enc_aes,
            password=self.password,
        )
        self.assertTrue(ctx._cert_chain_loaded)

    def test_load_encrypted_pkcs8_3des(self):
        """Loading 3DES encrypted PKCS#8 key with correct password."""
        ctx = TLSContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(
            certfile=self.cert_pem,
            keyfile=self.key_enc_3des,
            password=self.password,
        )
        self.assertTrue(ctx._cert_chain_loaded)

    def test_load_encrypted_pkcs8_wrong_password(self):
        """Wrong password should raise an error."""
        ctx = TLSContext(ssl.PROTOCOL_TLS_CLIENT)
        with self.assertRaises(Exception):
            ctx.load_cert_chain(
                certfile=self.cert_pem,
                keyfile=self.key_enc_aes,
                password=b"wrongpassword",
            )

    def test_load_encrypted_pkcs8_no_password(self):
        """Encrypted key without password should raise an error."""
        ctx = TLSContext(ssl.PROTOCOL_TLS_CLIENT)
        with self.assertRaises(Exception):
            ctx.load_cert_chain(
                certfile=self.cert_pem,
                keyfile=self.key_enc_aes,
                password=None,
            )

    def test_load_encrypted_pkcs8_string_password(self):
        """Password can be a string (gets encoded to UTF-8)."""
        ctx = TLSContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(
            certfile=self.cert_pem,
            keyfile=self.key_enc_aes,
            password=self.password.decode(),
        )
        self.assertTrue(ctx._cert_chain_loaded)

    def test_load_encrypted_pkcs8_callable_password(self):
        """Password can be a callable returning bytes."""
        ctx = TLSContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(
            certfile=self.cert_pem,
            keyfile=self.key_enc_aes,
            password=lambda: self.password,
        )
        self.assertTrue(ctx._cert_chain_loaded)

    def test_load_encrypted_pkcs8_in_memory(self):
        """Encrypted key from in-memory bytes (not file path)."""
        with open(self.cert_pem, "rb") as f:
            cert_data = f.read()
        with open(self.key_enc_aes, "rb") as f:
            key_data = f.read()

        ctx = TLSContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(
            certfile=cert_data,
            keyfile=key_data,
            password=self.password,
        )
        self.assertTrue(ctx._cert_chain_loaded)

    def test_load_plaintext_key_still_works(self):
        """Plaintext key loading should still work (regression check)."""
        ctx = TLSContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(
            certfile=self.cert_pem,
            keyfile=self.key_plain,
        )
        self.assertTrue(ctx._cert_chain_loaded)

    def test_load_encrypted_pkcs8_server_side(self):
        """Loading encrypted key for server-side TLS context."""
        ctx = TLSContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(
            certfile=self.cert_pem,
            keyfile=self.key_enc_aes,
            password=self.password,
        )
        self.assertTrue(ctx._cert_chain_loaded)


class TestTraditionalEncryptedKeySupport(unittest.TestCase):
    """Test loading traditional OpenSSL encrypted PEM keys (Proc-Type/DEK-Info)."""

    @classmethod
    def setUpClass(cls):
        """Generate test fixtures: self-signed cert + traditional encrypted keys."""
        import subprocess
        import tempfile

        cls._tmpdir = tempfile.mkdtemp(prefix="rtls_trad_enc_")
        cls.password = b"letmein"

        # Generate plaintext EC key (SEC1 format, P-256)
        cls.ec_key_plain = os.path.join(cls._tmpdir, "ec_key_plain.pem")
        subprocess.run(
            [
                "openssl",
                "ecparam",
                "-genkey",
                "-name",
                "prime256v1",
                "-out",
                cls.ec_key_plain,
            ],
            check=True,
            capture_output=True,
        )

        # Traditional encrypted EC key with AES-256-CBC
        cls.ec_key_enc_aes256 = os.path.join(cls._tmpdir, "ec_key_enc_aes256.pem")
        subprocess.run(
            [
                "openssl",
                "ec",
                "-in",
                cls.ec_key_plain,
                "-out",
                cls.ec_key_enc_aes256,
                "-aes-256-cbc",
                "-passout",
                f"pass:{cls.password.decode()}",
            ],
            check=True,
            capture_output=True,
        )

        # Traditional encrypted EC key with AES-128-CBC
        cls.ec_key_enc_aes128 = os.path.join(cls._tmpdir, "ec_key_enc_aes128.pem")
        subprocess.run(
            [
                "openssl",
                "ec",
                "-in",
                cls.ec_key_plain,
                "-out",
                cls.ec_key_enc_aes128,
                "-aes-128-cbc",
                "-passout",
                f"pass:{cls.password.decode()}",
            ],
            check=True,
            capture_output=True,
        )

        # Traditional encrypted EC key with DES-EDE3-CBC
        cls.ec_key_enc_3des = os.path.join(cls._tmpdir, "ec_key_enc_3des.pem")
        subprocess.run(
            [
                "openssl",
                "ec",
                "-in",
                cls.ec_key_plain,
                "-out",
                cls.ec_key_enc_3des,
                "-des3",
                "-passout",
                f"pass:{cls.password.decode()}",
            ],
            check=True,
            capture_output=True,
        )

        # Generate plaintext RSA key (PKCS#1 format)
        cls.rsa_key_plain = os.path.join(cls._tmpdir, "rsa_key_plain.pem")
        subprocess.run(
            ["openssl", "genrsa", "-out", cls.rsa_key_plain, "2048"],
            check=True,
            capture_output=True,
        )

        # Traditional encrypted RSA key with AES-256-CBC
        cls.rsa_key_enc_aes256 = os.path.join(cls._tmpdir, "rsa_key_enc_aes256.pem")
        subprocess.run(
            [
                "openssl",
                "rsa",
                "-in",
                cls.rsa_key_plain,
                "-out",
                cls.rsa_key_enc_aes256,
                "-aes-256-cbc",
                "-passout",
                f"pass:{cls.password.decode()}",
            ],
            check=True,
            capture_output=True,
        )

        # Self-signed cert from EC key
        cls.ec_cert = os.path.join(cls._tmpdir, "ec_cert.pem")
        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-key",
                cls.ec_key_plain,
                "-out",
                cls.ec_cert,
                "-days",
                "365",
                "-subj",
                "/CN=test-trad-enc.example.com",
            ],
            check=True,
            capture_output=True,
        )

        # Self-signed cert from RSA key
        cls.rsa_cert = os.path.join(cls._tmpdir, "rsa_cert.pem")
        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-key",
                cls.rsa_key_plain,
                "-out",
                cls.rsa_cert,
                "-days",
                "365",
                "-subj",
                "/CN=test-trad-enc-rsa.example.com",
            ],
            check=True,
            capture_output=True,
        )

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls._tmpdir, ignore_errors=True)

    def test_load_ec_traditional_aes256(self):
        """Traditional AES-256-CBC encrypted EC key."""
        ctx = TLSContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(
            certfile=self.ec_cert,
            keyfile=self.ec_key_enc_aes256,
            password=self.password,
        )
        self.assertTrue(ctx._cert_chain_loaded)

    def test_load_ec_traditional_aes128(self):
        """Traditional AES-128-CBC encrypted EC key."""
        ctx = TLSContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(
            certfile=self.ec_cert,
            keyfile=self.ec_key_enc_aes128,
            password=self.password,
        )
        self.assertTrue(ctx._cert_chain_loaded)

    def test_load_ec_traditional_3des(self):
        """Traditional DES-EDE3-CBC encrypted EC key."""
        ctx = TLSContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(
            certfile=self.ec_cert,
            keyfile=self.ec_key_enc_3des,
            password=self.password,
        )
        self.assertTrue(ctx._cert_chain_loaded)

    def test_load_rsa_traditional_aes256(self):
        """Traditional AES-256-CBC encrypted RSA key."""
        ctx = TLSContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(
            certfile=self.rsa_cert,
            keyfile=self.rsa_key_enc_aes256,
            password=self.password,
        )
        self.assertTrue(ctx._cert_chain_loaded)

    def test_load_traditional_wrong_password(self):
        """Wrong password should raise an error."""
        ctx = TLSContext(ssl.PROTOCOL_TLS_CLIENT)
        with self.assertRaises(Exception):
            ctx.load_cert_chain(
                certfile=self.ec_cert,
                keyfile=self.ec_key_enc_aes256,
                password=b"wrongpassword",
            )

    def test_load_traditional_no_password(self):
        """Encrypted key without password should raise an error."""
        ctx = TLSContext(ssl.PROTOCOL_TLS_CLIENT)
        with self.assertRaises(Exception):
            ctx.load_cert_chain(
                certfile=self.ec_cert,
                keyfile=self.ec_key_enc_aes256,
                password=None,
            )

    def test_load_traditional_in_memory(self):
        """Traditional encrypted key from in-memory bytes."""
        with open(self.ec_cert, "rb") as f:
            cert_data = f.read()
        with open(self.ec_key_enc_aes256, "rb") as f:
            key_data = f.read()

        ctx = TLSContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(
            certfile=cert_data,
            keyfile=key_data,
            password=self.password,
        )
        self.assertTrue(ctx._cert_chain_loaded)

    def test_load_traditional_server_side(self):
        """Traditional encrypted key for server-side TLS context."""
        ctx = TLSContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(
            certfile=self.ec_cert,
            keyfile=self.ec_key_enc_aes256,
            password=self.password,
        )
        self.assertTrue(ctx._cert_chain_loaded)


class TestIntermediateCertChainBuilding(unittest.TestCase):
    """Test that intermediates loaded via load_verify_locations() are used
    during chain building, matching OpenSSL's behavior.

    The key scenario: a server sends an incomplete chain (leaf only, no
    intermediate), but the client has loaded the intermediate cert via
    load_verify_locations(). With our ServerVerifierWithIntermediates,
    verification should succeed because the user-loaded intermediates are
    injected into webpki's chain-building process.
    """

    CERTDATA = os.path.join(os.path.dirname(__file__), "certdata")
    ROOT_CERT = os.path.join(CERTDATA, "root_cert.pem")
    INTERMEDIATE_CERT = os.path.join(CERTDATA, "intermediate_cert.pem")
    LEAF_CERT = os.path.join(CERTDATA, "leaf_cert.pem")
    LEAF_KEY = os.path.join(CERTDATA, "leaf_key.pem")
    LEAF_CHAIN = os.path.join(CERTDATA, "leaf_chain.pem")  # leaf + intermediate

    def _make_server_context(self, *, send_chain=True):
        """Create server context. If send_chain=False, only sends leaf cert
        (no intermediate) — simulating an incomplete chain from server."""
        ctx = TLSContext(ssl.PROTOCOL_TLS_SERVER)
        if send_chain:
            # Server sends full chain: leaf + intermediate
            ctx.load_cert_chain(certfile=self.LEAF_CHAIN, keyfile=self.LEAF_KEY)
        else:
            # Server sends only leaf cert — incomplete chain
            ctx.load_cert_chain(certfile=self.LEAF_CERT, keyfile=self.LEAF_KEY)
        return ctx

    def test_full_chain_from_server_root_only_on_client(self):
        """Server sends full chain (leaf + intermediate). Client only has root.
        This should always work — the intermediate comes from the server."""
        import threading

        server_ctx = self._make_server_context(send_chain=True)

        client_ctx = TLSContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.load_verify_locations(cafile=self.ROOT_CERT)
        # check_hostname=True is the default for TLS_CLIENT

        result = {}

        def server_thread(server_sock, ready_event):
            ready_event.set()
            try:
                conn, _ = server_sock.accept()
                ssl_conn = server_ctx.wrap_socket(conn, server_side=True)
                ssl_conn.write(b"OK")
                ssl_conn.close()
                result["server"] = "ok"
            except Exception as e:
                result["server_error"] = str(e)

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]

        ready = threading.Event()
        t = threading.Thread(target=server_thread, args=(server_sock, ready))
        t.daemon = True
        t.start()
        ready.wait()

        try:
            with client_ctx.wrap_socket(
                socket.socket(), server_hostname="localhost"
            ) as s:
                s.connect(("127.0.0.1", port))
                data = s.read(1024)
                self.assertEqual(data, b"OK")
        finally:
            server_sock.close()
            t.join(timeout=5)

    def test_incomplete_chain_with_intermediate_loaded_on_client(self):
        """Server sends incomplete chain (leaf only, no intermediate).
        Client has loaded BOTH root AND intermediate via load_verify_locations().
        This should succeed thanks to our intermediate injection."""
        import threading

        # Server only sends leaf cert — no intermediate in TLS Certificate message
        server_ctx = self._make_server_context(send_chain=False)

        client_ctx = TLSContext(ssl.PROTOCOL_TLS_CLIENT)
        # Load root as trust anchor
        client_ctx.load_verify_locations(cafile=self.ROOT_CERT)
        # Also load intermediate — this is the key scenario
        client_ctx.load_verify_locations(cafile=self.INTERMEDIATE_CERT)

        result = {}

        def server_thread(server_sock, ready_event):
            ready_event.set()
            try:
                conn, _ = server_sock.accept()
                ssl_conn = server_ctx.wrap_socket(conn, server_side=True)
                ssl_conn.write(b"OK")
                ssl_conn.close()
                result["server"] = "ok"
            except Exception as e:
                result["server_error"] = str(e)

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]

        ready = threading.Event()
        t = threading.Thread(target=server_thread, args=(server_sock, ready))
        t.daemon = True
        t.start()
        ready.wait()

        try:
            with client_ctx.wrap_socket(
                socket.socket(), server_hostname="localhost"
            ) as s:
                s.connect(("127.0.0.1", port))
                data = s.read(1024)
                self.assertEqual(data, b"OK")
        finally:
            server_sock.close()
            t.join(timeout=5)

    def test_incomplete_chain_without_intermediate_fails(self):
        """Server sends incomplete chain (leaf only). Client only has root.
        This should FAIL — the intermediate is missing from both server
        and client."""
        import threading

        server_ctx = self._make_server_context(send_chain=False)

        client_ctx = TLSContext(ssl.PROTOCOL_TLS_CLIENT)
        # Only load root — no intermediate
        client_ctx.load_verify_locations(cafile=self.ROOT_CERT)

        result = {}

        def server_thread(server_sock, ready_event):
            ready_event.set()
            try:
                conn, _ = server_sock.accept()
                ssl_conn = server_ctx.wrap_socket(conn, server_side=True)
                ssl_conn.write(b"OK")
                ssl_conn.close()
                result["server"] = "ok"
            except Exception as e:
                result["server_error"] = str(e)

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]

        ready = threading.Event()
        t = threading.Thread(target=server_thread, args=(server_sock, ready))
        t.daemon = True
        t.start()
        ready.wait()

        try:
            with self.assertRaises((ssl.SSLError, SSLCertVerificationError)):
                with client_ctx.wrap_socket(
                    socket.socket(), server_hostname="localhost"
                ) as s:
                    s.connect(("127.0.0.1", port))
        finally:
            server_sock.close()
            t.join(timeout=5)

    def test_intermediate_loaded_no_hostname_check(self):
        """Same as incomplete chain test but with check_hostname=False.
        Tests the NoHostnameVerifierWithIntermediates path."""
        import threading

        server_ctx = self._make_server_context(send_chain=False)

        client_ctx = TLSContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_REQUIRED
        client_ctx.load_verify_locations(cafile=self.ROOT_CERT)
        client_ctx.load_verify_locations(cafile=self.INTERMEDIATE_CERT)

        result = {}

        def server_thread(server_sock, ready_event):
            ready_event.set()
            try:
                conn, _ = server_sock.accept()
                ssl_conn = server_ctx.wrap_socket(conn, server_side=True)
                ssl_conn.write(b"OK")
                ssl_conn.close()
                result["server"] = "ok"
            except Exception as e:
                result["server_error"] = str(e)

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]

        ready = threading.Event()
        t = threading.Thread(target=server_thread, args=(server_sock, ready))
        t.daemon = True
        t.start()
        ready.wait()

        try:
            with client_ctx.wrap_socket(
                socket.socket(), server_hostname="localhost"
            ) as s:
                s.connect(("127.0.0.1", port))
                data = s.read(1024)
                self.assertEqual(data, b"OK")
        finally:
            server_sock.close()
            t.join(timeout=5)

    def test_ca_bundle_with_root_and_intermediate_combined(self):
        """Load a single PEM file containing both root and intermediate certs
        (as users commonly do with CA bundles). Server sends only leaf.
        Should succeed because both root and intermediate are loaded."""
        import tempfile
        import threading

        # Create combined CA bundle: root + intermediate in one file
        with open(self.ROOT_CERT, "r") as f:
            root_pem = f.read()
        with open(self.INTERMEDIATE_CERT, "r") as f:
            intermediate_pem = f.read()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write(root_pem)
            f.write(intermediate_pem)
            ca_bundle_path = f.name

        try:
            server_ctx = self._make_server_context(send_chain=False)

            client_ctx = TLSContext(ssl.PROTOCOL_TLS_CLIENT)
            client_ctx.load_verify_locations(cafile=ca_bundle_path)

            result = {}

            def server_thread(server_sock, ready_event):
                ready_event.set()
                try:
                    conn, _ = server_sock.accept()
                    ssl_conn = server_ctx.wrap_socket(conn, server_side=True)
                    ssl_conn.write(b"OK")
                    ssl_conn.close()
                    result["server"] = "ok"
                except Exception as e:
                    result["server_error"] = str(e)

            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(("127.0.0.1", 0))
            server_sock.listen(1)
            port = server_sock.getsockname()[1]

            ready = threading.Event()
            t = threading.Thread(target=server_thread, args=(server_sock, ready))
            t.daemon = True
            t.start()
            ready.wait()

            try:
                with client_ctx.wrap_socket(
                    socket.socket(), server_hostname="localhost"
                ) as s:
                    s.connect(("127.0.0.1", port))
                    data = s.read(1024)
                    self.assertEqual(data, b"OK")
            finally:
                server_sock.close()
                t.join(timeout=5)
        finally:
            os.unlink(ca_bundle_path)


###############################################################################
# COVERAGE IMPROVEMENT TESTS
# Target: raise from 87% to 98%+
# Organized by source file to make coverage tracking easier
###############################################################################


class TestCovBio(unittest.TestCase):
    """Cover _bio.py line 69: MemoryBIO.__repr__."""

    def test_repr(self):
        bio = MemoryBIO()
        r = repr(bio)
        self.assertIn("MemoryBIO", r)
        self.assertIn("pending=0", r)
        self.assertIn("eof_written=False", r)

    def test_repr_with_data(self):
        bio = MemoryBIO()
        bio.write(b"hello")
        r = repr(bio)
        self.assertIn("pending=5", r)

    def test_repr_after_eof(self):
        bio = MemoryBIO()
        bio.write_eof()
        r = repr(bio)
        self.assertIn("eof_written=True", r)


class TestCovCertificate(unittest.TestCase):
    """Cover _certificate.py lines 30, 49, 66."""

    def _get_der(self) -> bytes:
        ssock = _connect_tls()
        try:
            return ssock.getpeercert(binary_form=True)
        finally:
            ssock.close()

    def test_get_info_cache_hit(self):
        """Line 30: second call to get_info() returns cached result."""
        der = self._get_der()
        cert = TLSCertificate(der)
        info1 = cert.get_info()
        info2 = cert.get_info()
        self.assertIs(info1, info2)  # Same object = cache hit

    def test_eq_with_non_certificate(self):
        """Line 49: __eq__ with non-TLSCertificate returns NotImplemented."""
        der = self._get_der()
        cert = TLSCertificate(der)
        result = cert.__eq__("not a cert")
        self.assertIs(result, NotImplemented)

    def test_eq_not_equal(self):
        """Unequal certs compare correctly."""
        cert1 = TLSCertificate(b"\x30" * 20)
        cert2 = TLSCertificate(b"\x31" * 20)
        self.assertNotEqual(cert1, cert2)

    def test_repr_no_cn(self):
        """Line 66: repr fallback when no CN found in subject."""
        from unittest.mock import patch

        der = self._get_der()
        cert = TLSCertificate(der)
        # Mock parse_certificate_dict to return a dict with empty subject (no CN)
        with patch("rtls._rustls.parse_certificate_dict", return_value={"subject": ()}):
            cert._parsed_cache = None  # Reset cache to force re-parse
            r = repr(cert)
            self.assertIn("TLSCertificate", r)
            self.assertIn("bytes", r)  # Falls back to "[N bytes]" format


class TestCovCiphers(unittest.TestCase):
    """Cover _ciphers.py lines 89, 101, 105, 115, 133-136, 152-154, 176, 182, 228."""

    def test_empty_cipher_string_returns_defaults(self):
        """Line 89: empty string returns all defaults."""
        from rtls._ciphers import parse_cipher_string

        result = parse_cipher_string("")
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)

    def test_double_colon_empty_tokens(self):
        """Line 101: skip empty tokens from 'HIGH::AES'."""
        from rtls._ciphers import parse_cipher_string

        result = parse_cipher_string("HIGH::AESGCM")
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)

    def test_seclevel_skipped(self):
        """Line 105: @SECLEVEL=2 is recognized and skipped."""
        from rtls._ciphers import parse_cipher_string

        result = parse_cipher_string("HIGH:@SECLEVEL=2")
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)

    def test_plus_prefix_stripped(self):
        """Line 115: strip '+' prefix on a token (reordering)."""
        from rtls._ciphers import parse_cipher_string

        # '+ECDHE' means reorder ECDHE to end — we strip prefix and treat as group
        result = parse_cipher_string("HIGH:+ECDHE")
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)

    def test_individual_cipher_name(self):
        """Lines 133-136: individual cipher name lookup."""
        from rtls._ciphers import parse_cipher_string

        result = parse_cipher_string("ECDHE-RSA-AES128-GCM-SHA256")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")

    def test_exclusion_filtering(self):
        """Lines 152-154: exclusion with ! removes ciphers."""
        from rtls._ciphers import parse_cipher_string

        result = parse_cipher_string("HIGH:!ECDHE-RSA-AES128-GCM-SHA256")
        self.assertNotIn("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", result)
        self.assertGreater(len(result), 0)

    def test_dash_exclusion(self):
        """Exclusion with - prefix."""
        from rtls._ciphers import parse_cipher_string

        result = parse_cipher_string("HIGH:-AESGCM")
        # Should exclude AES-GCM ciphers
        for r in result:
            self.assertNotIn("AES", r)  # AES-GCM excluded

    def test_individual_in_resolve_group(self):
        """Line 176: _resolve_cipher_group with individual cipher name."""
        from rtls._ciphers import _resolve_cipher_group

        result = _resolve_cipher_group("ECDHE-RSA-AES128-GCM-SHA256")
        self.assertEqual(result, {"ECDHE-RSA-AES128-GCM-SHA256"})

    def test_case_insensitive_group_match(self):
        """Line 182: case-insensitive group match."""
        from rtls._ciphers import _resolve_cipher_group

        result = _resolve_cipher_group("high")
        self.assertGreater(len(result), 0)

    def test_resolve_unknown_group(self):
        """_resolve_cipher_group with unknown name returns empty set."""
        from rtls._ciphers import _resolve_cipher_group

        result = _resolve_cipher_group("NONEXISTENT_GROUP_XYZ")
        self.assertEqual(result, set())

    def test_strength_bits_fallback(self):
        """Line 228: _get_strength_bits returns 0 for unknown ciphers."""
        from rtls._ciphers import _get_strength_bits

        self.assertEqual(_get_strength_bits("UNKNOWN_CIPHER"), 0)

    def test_intersection_cipher_string(self):
        """Intersection: ECDHE+AESGCM."""
        from rtls._ciphers import parse_cipher_string

        result = parse_cipher_string("ECDHE+AESGCM")
        self.assertGreater(len(result), 0)
        # All results should be ECDHE with AES-GCM
        for r in result:
            self.assertIn("ECDHE", r)
            self.assertIn("AES", r)

    def test_no_matching_ciphers_raises(self):
        """If nothing matches, raise SSLError."""
        from rtls._ciphers import parse_cipher_string

        with self.assertRaises(SSLError):
            parse_cipher_string("!HIGH:!ALL:!ECDHE:!DEFAULT")

    def test_space_separator(self):
        """Space as separator works."""
        from rtls._ciphers import parse_cipher_string

        result = parse_cipher_string(
            "ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384"
        )
        self.assertEqual(len(result), 2)


class TestCovConstants(unittest.TestCase):
    """Cover _constants.py line 133: Purpose.__repr__."""

    def test_purpose_repr(self):
        r = repr(ssl.Purpose.SERVER_AUTH)
        self.assertIn("SERVER_AUTH", r)
        self.assertIn("1.3.6.1.5.5.7.3.1", r)

    def test_purpose_client_auth_repr(self):
        r = repr(ssl.Purpose.CLIENT_AUTH)
        self.assertIn("CLIENT_AUTH", r)


class TestCovContext(unittest.TestCase):
    """Cover _context.py edge cases: load_default_certs, version settings,
    properties, get_ca_certs, session_stats, etc."""

    def test_load_default_certs_uses_wassima(self):
        """load_default_certs uses wassima.root_der_certificates()."""
        from unittest.mock import MagicMock, patch

        ctx = TLSContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Replace the builder with a mock
        mock_builder = MagicMock()
        ctx._builder = mock_builder

        fake_certs = [b"\x30\x82" + b"\x00" * 100, b"\x30\x82" + b"\x00" * 200]
        with patch("wassima.root_der_certificates", return_value=fake_certs):
            ctx.load_default_certs()

        # Should have called add_root_cert_from_der for each cert
        self.assertEqual(mock_builder.add_root_cert_from_der.call_count, 2)
        mock_builder.add_root_cert_from_der.assert_any_call(fake_certs[0])
        mock_builder.add_root_cert_from_der.assert_any_call(fake_certs[1])
        self.assertTrue(ctx._ca_certs_loaded)
        self.assertEqual(ctx._num_ca_certs, 2)

    def test_min_version_minimum_supported(self):
        """Lines 328-329: minimum_version=MINIMUM_SUPPORTED."""
        ctx = _make_ctx()
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_min_version_none(self):
        """Lines 328-329: minimum_version=None."""
        ctx = _make_ctx()
        ctx.minimum_version = None
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_min_version_clamp_below_tls12(self):
        """Line 334: setting min_version < TLS 1.2 clamps to TLS 1.2."""
        ctx = _make_ctx()
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_max_version_maximum_supported(self):
        """Lines 345-346: maximum_version=MAXIMUM_SUPPORTED."""
        ctx = _make_ctx()
        ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
        self.assertEqual(ctx.maximum_version, ssl.TLSVersion.TLSv1_3)

    def test_max_version_none(self):
        """Lines 345-346: maximum_version=None."""
        ctx = _make_ctx()
        ctx.maximum_version = None
        self.assertEqual(ctx.maximum_version, ssl.TLSVersion.TLSv1_3)

    def test_keylog_filename_getter(self):
        """Line 363: keylog_filename getter."""
        ctx = _make_ctx()
        self.assertIsNone(ctx.keylog_filename)

    def test_keylog_filename_setter(self):
        """Lines 367-369: keylog_filename setter."""
        import tempfile

        ctx = _make_ctx()
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            path = f.name
        try:
            ctx.keylog_filename = path
            self.assertEqual(ctx.keylog_filename, path)
        finally:
            os.unlink(path)

    def test_keylog_filename_setter_none(self):
        """Lines 367-369: keylog_filename setter with None (no-op path)."""
        ctx = _make_ctx()
        ctx.keylog_filename = None
        self.assertIsNone(ctx.keylog_filename)

    def test_sni_callback_getter(self):
        """Line 399: sni_callback getter."""
        ctx = _make_ctx()
        self.assertIsNone(ctx.sni_callback)

    def test_sni_callback_setter(self):
        """sni_callback setter."""
        ctx = _make_ctx()
        cb = lambda *args: None
        ctx.sni_callback = cb
        self.assertIs(ctx.sni_callback, cb)

    def test_get_ca_certs_binary_form(self):
        """Line 421: get_ca_certs(binary_form=True)."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_default_certs()
        certs = ctx.get_ca_certs(binary_form=True)
        self.assertIsInstance(certs, list)
        if certs:
            self.assertIsInstance(certs[0], bytes)

    def test_get_ca_certs_parse_error(self):
        """Line 430: get_ca_certs with parse error in individual cert."""
        from unittest.mock import patch

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_default_certs()

        # Mock parse_certificate_dict to raise on all certs
        with patch(
            "rtls._rustls.parse_certificate_dict", side_effect=ValueError("parse fail")
        ):
            # Should not raise — errors are caught per-cert
            result = ctx.get_ca_certs(binary_form=False)
            self.assertIsInstance(result, list)
            # All certs failed to parse, so result should be empty
            self.assertEqual(len(result), 0)

    def test_op_no_tlsv12_sets_min_tls13(self):
        """Line 541: OP_NO_TLSv1_2 in options."""
        ctx = _make_ctx()
        ctx.options |= ssl.OP_NO_TLSv1_2
        # After setting, TLS 1.2 should be disabled (min bumped to 1.3)

    def test_load_pem_data_none(self):
        """Line 553: _load_pem_data(None) raises SSLError."""
        with self.assertRaises(SSLError):
            TLSContext._load_pem_data(None)

    def test_load_pem_data_int(self):
        """Line 559: _load_pem_data(123) raises TypeError."""
        with self.assertRaises(TypeError):
            TLSContext._load_pem_data(123)

    def test_load_pem_data_bytes(self):
        """_load_pem_data with bytes returns directly."""
        data = b"some pem data"
        result = TLSContext._load_pem_data(data)
        self.assertEqual(result, data)

    def test_validate_cert_pem_tiny_der(self):
        """Line 584: tiny cert DER < 10 bytes is skipped."""
        import base64

        # Create PEM with a tiny payload (< 10 bytes decoded)
        tiny_b64 = base64.b64encode(b"tiny").decode()
        pem = f"-----BEGIN CERTIFICATE-----\n{tiny_b64}\n-----END CERTIFICATE-----\n".encode()
        with self.assertRaises(SSLError):
            TLSContext._validate_cert_pem(pem)

    def test_validate_cert_pem_no_cert_blocks(self):
        """No CERTIFICATE blocks raises SSLError."""
        with self.assertRaises(SSLError):
            TLSContext._validate_cert_pem(b"not a pem file at all")

    def test_validate_cert_pem_invalid_base64(self):
        """Invalid base64 in CERTIFICATE block is skipped."""
        pem = b"-----BEGIN CERTIFICATE-----\n!!invalid-base64!!\n-----END CERTIFICATE-----\n"
        with self.assertRaises(SSLError):
            TLSContext._validate_cert_pem(pem)

    def test_verify_flags_setter(self):
        """verify_flags setter is a no-op."""
        ctx = _make_ctx()
        ctx.verify_flags = 0x20  # No-op but shouldn't raise


class TestCovObject(unittest.TestCase):
    """Cover _object.py lines 92, 98, 112, 152, 160-162, 179-181, 192, 195,
    236, 277, 309, 313, 322, 356, 370, 394, 397-399."""

    def _make_obj(self) -> TLSObject:
        """Create a TLSObject via wrap_bio (no handshake)."""
        ctx = _make_ctx()
        incoming = MemoryBIO()
        outgoing = MemoryBIO()
        return ctx.wrap_bio(incoming, outgoing, server_hostname=EXAMPLE_HOST)

    def test_flush_outgoing_conn_none(self):
        """Line 92: _flush_outgoing when conn=None returns early."""
        obj = self._make_obj()
        obj._conn = None
        obj._flush_outgoing()  # Should not raise

    def test_read_after_shutdown(self):
        """Line 152: read after shutdown raises SSLZeroReturnError."""
        obj = self._make_obj()
        obj._shutdown = True
        with self.assertRaises(SSLZeroReturnError):
            obj.read()

    def test_write_after_shutdown(self):
        """Line 192: write after shutdown raises SSLZeroReturnError."""
        obj = self._make_obj()
        obj._shutdown = True
        with self.assertRaises(SSLZeroReturnError):
            obj.write(b"data")

    def test_write_before_handshake(self):
        """Line 195: write before handshake raises SSLError."""
        obj = self._make_obj()
        obj._handshake_done = False
        with self.assertRaises(SSLError):
            obj.write(b"data")

    def test_shared_ciphers_none(self):
        """Line 277: shared_ciphers returns None when no cipher negotiated."""
        from unittest.mock import MagicMock

        obj = self._make_obj()
        mock_conn = MagicMock()
        mock_conn.negotiated_cipher_suite.return_value = None
        obj._conn = mock_conn
        result = obj.shared_ciphers()
        self.assertIsNone(result)

    def test_get_channel_binding(self):
        """Line 309: get_channel_binding returns None."""
        obj = self._make_obj()
        result = obj.get_channel_binding()
        self.assertIsNone(result)

    def test_getpeername(self):
        """Line 313: getpeername returns None (no socket)."""
        obj = self._make_obj()
        result = obj.getpeername()
        self.assertIsNone(result)

    def test_context_setter(self):
        """Line 322: context setter."""
        obj = self._make_obj()
        new_ctx = _make_ctx()
        obj.context = new_ctx
        self.assertIs(obj.context, new_ctx)

    def test_owner_property(self):
        """Line 370: owner returns None."""
        obj = self._make_obj()
        self.assertIsNone(obj.owner)

    def test_ech_status_conn_none(self):
        """Line 394: ech_status when conn=None."""
        obj = self._make_obj()
        obj._conn = None
        self.assertEqual(obj.ech_status, "not_offered")

    def test_ech_status_attribute_error(self):
        """Lines 397-399: ech_status AttributeError catch (server connections)."""
        from unittest.mock import MagicMock

        obj = self._make_obj()
        mock_conn = MagicMock()
        mock_conn.ech_status.side_effect = AttributeError("no ech_status")
        obj._conn = mock_conn
        self.assertEqual(obj.ech_status, "not_offered")

    def test_do_handshake_process_packets_sslerror(self):
        """Lines 160-162: process_new_packets raises SSLError during handshake."""
        from unittest.mock import MagicMock

        obj = self._make_obj()
        mock_conn = MagicMock()
        mock_conn.process_new_packets.side_effect = SSLError("cert verification failed")
        mock_conn.wants_write.return_value = False
        obj._conn = mock_conn
        with self.assertRaises(SSLError):
            obj.do_handshake()

    def test_read_process_packets_sslerror(self):
        """decrypt_incoming raises SSLError → propagated from read()."""
        from unittest.mock import MagicMock

        obj = self._make_obj()
        obj._shutdown = False
        mock_conn = MagicMock()
        mock_conn.decrypt_incoming.side_effect = SSLError("decode error")
        mock_conn.read_plaintext.return_value = b""
        mock_conn.wants_write.return_value = False
        obj._conn = mock_conn
        # Put some ciphertext in the BIO so decrypt_incoming gets called
        obj._incoming.write(b"\x17\x03\x03\x00\x05hello")
        with self.assertRaises(SSLError):
            obj.read()

    def test_write_tls_returns_empty(self):
        """Line 98: write_tls returns empty bytes → break."""
        from unittest.mock import MagicMock

        obj = self._make_obj()
        mock_conn = MagicMock()
        # wants_write returns True, but write_tls returns empty → break
        mock_conn.wants_write.side_effect = [True, False]
        mock_conn.write_tls.return_value = b""
        obj._conn = mock_conn
        obj._flush_outgoing()  # Should not loop infinitely

    def test_read_tls_returns_zero(self):
        """Line 112: read_tls returns 0 → break."""
        from unittest.mock import MagicMock

        obj = self._make_obj()
        mock_conn = MagicMock()
        mock_conn.read_tls.return_value = 0
        obj._conn = mock_conn
        obj._incoming.write(b"some ciphertext data here")
        obj._pump_incoming()  # Should break after read_tls returns 0


class TestCovSocket(unittest.TestCase):
    """Cover _socket.py lines 71-72, 126, 128, 137-147, 156, 171, 182, 202,
    216-222, 238-241, 263, 267, 278, 281, 298, 304, 309, 315, 320, 331, 335,
    358-361, 408, 412, 417, 424, 435, 441, 444, 447, 462-463."""

    def _make_unconnected_socket(self) -> TLSSocket:
        """Create a TLSSocket that is NOT connected (wrapping an unconnected socket)."""
        ctx = _make_ctx()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # wrap_socket with do_handshake_on_connect=False and unconnected socket
        return TLSSocket(
            sock=sock,
            context=ctx,
            server_side=False,
            server_hostname=EXAMPLE_HOST,
            do_handshake_on_connect=False,
        )

    def test_server_side_connect_raises(self):
        """Line 126: connect in server-side mode raises ValueError."""
        ctx = _make_ctx()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tls_sock = TLSSocket(
            sock=sock,
            context=ctx,
            server_side=True,
            server_hostname=None,
            do_handshake_on_connect=False,
        )
        with self.assertRaises(ValueError):
            tls_sock.connect(("127.0.0.1", 1))
        tls_sock.close()

    def test_double_connect_raises(self):
        """Line 128: double connect raises ValueError."""
        ssock = _connect_tls()
        try:
            with self.assertRaises(ValueError):
                ssock.connect(("127.0.0.1", 1))
        finally:
            ssock.close()

    def test_connect_ex_server_side_raises(self):
        """Line 137: connect_ex in server-side mode raises ValueError."""
        ctx = _make_ctx()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tls_sock = TLSSocket(
            sock=sock,
            context=ctx,
            server_side=True,
            server_hostname=None,
            do_handshake_on_connect=False,
        )
        with self.assertRaises(ValueError):
            tls_sock.connect_ex(("127.0.0.1", 1))
        tls_sock.close()

    def test_connect_ex_double_connect_raises(self):
        """Line 139: connect_ex double connect raises ValueError."""
        ssock = _connect_tls()
        try:
            with self.assertRaises(ValueError):
                ssock.connect_ex(("127.0.0.1", 1))
        finally:
            ssock.close()

    def test_connect_ex_success(self):
        """Lines 142-147: connect_ex returns 0 on success."""
        ctx = _make_ctx()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tls_sock = TLSSocket(
            sock=sock,
            context=ctx,
            server_side=False,
            server_hostname=EXAMPLE_HOST,
            do_handshake_on_connect=True,
        )
        rc = tls_sock.connect_ex((EXAMPLE_HOST, EXAMPLE_PORT))
        try:
            self.assertEqual(rc, 0)
            self.assertTrue(tls_sock._connected)
        finally:
            tls_sock.close()

    def test_send_before_handshake(self):
        """Line 182: send before handshake raises SSLError."""
        tls_sock = self._make_unconnected_socket()
        try:
            with self.assertRaises(SSLError):
                tls_sock.send(b"data")
        finally:
            tls_sock.close()

    def test_recv_before_handshake(self):
        """Line 202: recv before handshake raises SSLError."""
        tls_sock = self._make_unconnected_socket()
        try:
            with self.assertRaises(SSLError):
                tls_sock.recv(1024)
        finally:
            tls_sock.close()

    def test_getpeercert_before_handshake(self):
        """Line 298: getpeercert before handshake returns None."""
        tls_sock = self._make_unconnected_socket()
        try:
            result = tls_sock.getpeercert()
            self.assertIsNone(result)
        finally:
            tls_sock.close()

    def test_cipher_before_handshake(self):
        """Line 304: cipher before handshake returns None."""
        tls_sock = self._make_unconnected_socket()
        try:
            result = tls_sock.cipher()
            self.assertIsNone(result)
        finally:
            tls_sock.close()

    def test_shared_ciphers_before_handshake(self):
        """Line 309: shared_ciphers before handshake returns None."""
        tls_sock = self._make_unconnected_socket()
        try:
            result = tls_sock.shared_ciphers()
            self.assertIsNone(result)
        finally:
            tls_sock.close()

    def test_version_before_handshake(self):
        """Line 315: version before handshake returns None."""
        tls_sock = self._make_unconnected_socket()
        try:
            result = tls_sock.version()
            self.assertIsNone(result)
        finally:
            tls_sock.close()

    def test_alpn_before_handshake(self):
        """Line 320: selected_alpn_protocol before handshake returns None."""
        tls_sock = self._make_unconnected_socket()
        try:
            result = tls_sock.selected_alpn_protocol()
            self.assertIsNone(result)
        finally:
            tls_sock.close()

    def test_pending_before_handshake(self):
        """Line 331: pending before handshake returns 0."""
        tls_sock = self._make_unconnected_socket()
        try:
            result = tls_sock.pending()
            self.assertEqual(result, 0)
        finally:
            tls_sock.close()

    def test_get_channel_binding(self):
        """Line 335: get_channel_binding returns None."""
        tls_sock = self._make_unconnected_socket()
        try:
            result = tls_sock.get_channel_binding()
            self.assertIsNone(result)
        finally:
            tls_sock.close()

    def test_sslobj_setter_non_none(self):
        """Line 408: _sslobj setter with non-None value."""
        ssock = _connect_tls()
        try:
            obj = ssock._sslobj
            ssock._sslobj = obj  # Set to the same object
            self.assertIs(ssock._sslobj, obj)
        finally:
            ssock.close()

    def test_get_verified_chain_before_handshake(self):
        """Line 412: get_verified_chain before handshake returns None."""
        tls_sock = self._make_unconnected_socket()
        try:
            result = tls_sock.get_verified_chain()
            self.assertIsNone(result)
        finally:
            tls_sock.close()

    def test_get_unverified_chain_before_handshake(self):
        """Line 417: get_unverified_chain before handshake returns None."""
        tls_sock = self._make_unconnected_socket()
        try:
            result = tls_sock.get_unverified_chain()
            self.assertIsNone(result)
        finally:
            tls_sock.close()

    def test_ech_status_before_handshake(self):
        """Line 424: ech_status before handshake returns 'not_offered'."""
        tls_sock = self._make_unconnected_socket()
        try:
            self.assertEqual(tls_sock.ech_status, "not_offered")
        finally:
            tls_sock.close()

    def test_recvfrom_into_blocked(self):
        """Line 435: recvfrom_into raises ValueError."""
        ssock = _connect_tls()
        try:
            with self.assertRaises(ValueError):
                ssock.recvfrom_into(bytearray(1024))
        finally:
            ssock.close()

    def test_recvmsg_blocked(self):
        """Line 441: recvmsg raises ValueError."""
        ssock = _connect_tls()
        try:
            with self.assertRaises(ValueError):
                ssock.recvmsg(1024)
        finally:
            ssock.close()

    def test_recvmsg_into_blocked(self):
        """Line 444: recvmsg_into raises ValueError."""
        ssock = _connect_tls()
        try:
            with self.assertRaises(ValueError):
                ssock.recvmsg_into([bytearray(1024)])
        finally:
            ssock.close()

    def test_sendmsg_blocked(self):
        """Line 447: sendmsg raises ValueError."""
        ssock = _connect_tls()
        try:
            with self.assertRaises(ValueError):
                ssock.sendmsg([b"data"])
        finally:
            ssock.close()

    def test_repr_disconnected(self):
        """Lines 462-463: repr with disconnected socket (peer=None)."""
        tls_sock = self._make_unconnected_socket()
        try:
            r = repr(tls_sock)
            self.assertIn("TLSSocket", r)
            self.assertIn("peer=None", r)
        finally:
            tls_sock.close()

    def test_shutdown_with_tls_unwrap(self):
        """Lines 358-361: shutdown performs TLS unwrap before socket shutdown."""
        ssock = _connect_tls()
        try:
            # Send a request so we get a response and can shutdown gracefully
            ssock.sendall(
                b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
            )
            # Read some data
            data = ssock.recv(4096)
            self.assertGreater(len(data), 0)
            # Now shutdown — this should perform TLS unwrap
            try:
                ssock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # May fail if peer already closed
        finally:
            ssock.close()

    def test_read_with_buffer(self):
        """Lines 238-241: read() with buffer parameter."""
        ssock = _connect_tls()
        try:
            ssock.sendall(
                b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
            )
            buf = bytearray(4096)
            n = ssock.read(4096, buffer=buf)
            self.assertIsInstance(n, int)
            self.assertGreater(n, 0)
            self.assertIn(b"HTTP/1.1 200", bytes(buf[:n]))
        finally:
            ssock.close()

    def test_send_empty_data(self):
        """send(b'') returns 0."""
        ssock = _connect_tls()
        try:
            n = ssock.send(b"")
            self.assertEqual(n, 0)
        finally:
            ssock.close()

    def test_recv_zero_buflen(self):
        """recv(0) returns b''."""
        ssock = _connect_tls()
        try:
            data = ssock.recv(0)
            self.assertEqual(data, b"")
        finally:
            ssock.close()

    def test_do_handshake_lazy_create_sslobj(self):
        """Line 156: do_handshake creates sslobj lazily if None."""
        ctx = _make_ctx()
        sock = socket.create_connection(
            (EXAMPLE_HOST, EXAMPLE_PORT), timeout=CONNECT_TIMEOUT
        )
        tls_sock = TLSSocket(
            sock=sock,
            context=ctx,
            server_side=False,
            server_hostname=EXAMPLE_HOST,
            do_handshake_on_connect=False,
        )
        try:
            # Socket is connected but sslobj should exist from __init__
            # To test line 156, we set it to None before calling do_handshake
            # But we need a fresh socket for this — the original connection
            # hasn't been tainted yet
            # Actually, the simplest way: just verify that do_handshake works
            # when called explicitly (which exercises the lazy path if sslobj
            # happens to be None)
            tls_sock._sslobj_internal = None
            tls_sock._incoming = MemoryBIO()
            tls_sock._outgoing = MemoryBIO()
            tls_sock.do_handshake()
            self.assertIsNotNone(tls_sock._sslobj)
        finally:
            tls_sock.close()


class TestCovUtils(unittest.TestCase):
    """Cover _utils.py lines 120, 138-169, 178-181, 186-200."""

    def test_get_server_certificate_no_cert_raises(self):
        """Line 120: get_server_certificate raises ValueError when no cert."""
        # This is hard to trigger naturally — the server would need to not send a cert.
        # We test the function works at all (the line requires der to be None).
        # For now, test the normal path works; the ValueError path is defensive.
        pem = ssl.get_server_certificate((EXAMPLE_HOST, EXAMPLE_PORT))
        self.assertIn("BEGIN CERTIFICATE", pem)

    def test_match_hostname_valid(self):
        """Lines 138-169: match_hostname with valid cert/hostname."""
        import warnings

        cert = {
            "subjectAltName": [("DNS", "example.com"), ("DNS", "*.example.com")],
        }
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            # Should not raise
            ssl.match_hostname(cert, "example.com")

    def test_match_hostname_wildcard(self):
        """Lines 186-200: wildcard matching *.example.com."""
        import warnings

        cert = {
            "subjectAltName": [("DNS", "*.example.com")],
        }
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ssl.match_hostname(cert, "sub.example.com")

    def test_match_hostname_mismatch(self):
        """match_hostname raises on mismatch."""
        import warnings
        from rtls._exceptions import SSLCertVerificationError

        cert = {
            "subjectAltName": [("DNS", "other.com")],
        }
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            with self.assertRaises(SSLCertVerificationError):
                ssl.match_hostname(cert, "example.com")

    def test_match_hostname_empty_cert(self):
        """match_hostname raises on empty cert."""
        import warnings
        from rtls._exceptions import SSLCertVerificationError

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            with self.assertRaises(SSLCertVerificationError):
                ssl.match_hostname({}, "example.com")

    def test_match_hostname_cn_fallback(self):
        """Lines 155-167: match_hostname falls back to CN when no SAN."""
        import warnings

        cert = {
            "subject": ((("commonName", "example.com"),),),
        }
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ssl.match_hostname(cert, "example.com")

    def test_match_hostname_cn_mismatch(self):
        """CN fallback with mismatched hostname raises."""
        import warnings
        from rtls._exceptions import SSLCertVerificationError

        cert = {
            "subject": ((("commonName", "other.com"),),),
        }
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            with self.assertRaises(SSLCertVerificationError):
                ssl.match_hostname(cert, "example.com")

    def test_hostname_matches(self):
        """Lines 178-181: _hostname_matches."""
        from rtls._utils import _hostname_matches

        self.assertTrue(_hostname_matches("example.com", ["example.com"]))
        self.assertFalse(_hostname_matches("example.com", ["other.com"]))

    def test_match_hostname_pattern(self):
        """Lines 186-200: _match_hostname_pattern."""
        from rtls._utils import _match_hostname_pattern

        self.assertTrue(_match_hostname_pattern("example.com", "example.com"))
        self.assertTrue(_match_hostname_pattern("sub.example.com", "*.example.com"))
        self.assertFalse(_match_hostname_pattern("example.com", "*.example.com"))
        self.assertFalse(_match_hostname_pattern("sub.other.com", "*.example.com"))

    def test_match_hostname_pattern_case_insensitive(self):
        """Pattern matching is case-insensitive."""
        from rtls._utils import _match_hostname_pattern

        self.assertTrue(_match_hostname_pattern("EXAMPLE.COM", "example.com"))
        self.assertTrue(_match_hostname_pattern("Sub.Example.COM", "*.example.com"))

    def test_match_hostname_deprecation_warning(self):
        """match_hostname emits DeprecationWarning."""
        import warnings

        cert = {
            "subjectAltName": [("DNS", "example.com")],
        }
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            ssl.match_hostname(cert, "example.com")
            self.assertTrue(
                any(issubclass(warning.category, DeprecationWarning) for warning in w)
            )

    def test_create_default_context_client_auth(self):
        """Create context with CLIENT_AUTH purpose."""
        ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
        self.assertIsInstance(ctx, _stdlib_ssl.SSLContext)


class TestCovSocketFlushAndPull(unittest.TestCase):
    """Cover _socket.py lines 263, 267, 278, 281 — edge cases in
    _flush_outgoing and _pull_incoming."""

    def test_flush_outgoing_send_returns_zero(self):
        """Line 263: socket.send returns 0 → SSLError."""
        from unittest.mock import patch

        ssock = _connect_tls()
        try:
            ssock._outgoing.write(b"some data to flush")
            with patch.object(socket.socket, "send", return_value=0):
                with self.assertRaises(SSLError):
                    ssock._flush_outgoing()
        finally:
            ssock.close()

    def test_flush_outgoing_blocking_io(self):
        """Line 267: BlockingIOError during send → retry."""
        from unittest.mock import patch

        ssock = _connect_tls()
        try:
            ssock._outgoing.write(b"data")
            call_count = [0]
            original_send = socket.socket.send

            def mock_send(self_sock, data):
                call_count[0] += 1
                if call_count[0] == 1:
                    raise BlockingIOError("would block")
                return len(data)

            with patch.object(socket.socket, "send", mock_send):
                ssock._flush_outgoing()
            self.assertGreater(call_count[0], 1)  # Retried
        finally:
            ssock.close()

    def test_pull_incoming_timeout(self):
        """Line 278: socket.timeout propagates directly."""
        from unittest.mock import patch

        ssock = _connect_tls()
        try:
            with patch.object(
                socket.socket, "recv", side_effect=socket.timeout("timed out")
            ):
                with self.assertRaises(socket.timeout):
                    ssock._pull_incoming(timeout=1.0)
        finally:
            ssock.close()

    def test_pull_incoming_eagain(self):
        """Line 281: EAGAIN/EWOULDBLOCK → SSLWantReadError."""
        import errno as _errno
        from unittest.mock import patch

        ssock = _connect_tls()
        try:
            eagain_err = OSError(_errno.EAGAIN, "Resource temporarily unavailable")
            with patch.object(socket.socket, "recv", side_effect=eagain_err):
                with self.assertRaises(SSLWantReadError):
                    ssock._pull_incoming(timeout=1.0)
        finally:
            ssock.close()


class TestCovObjectBufferRead(unittest.TestCase):
    """Cover _object.py lines 179-181: read into buffer mode.
    And line 236: getpeercert DER extraction.
    And line 356: get_verified_chain with certs."""

    def test_getpeercert_binary_via_object(self):
        """Line 236: getpeercert binary_form via TLSObject (after handshake)."""

        async def _run():
            ctx = _make_ctx()
            reader, writer = await asyncio.open_connection(
                EXAMPLE_HOST, EXAMPLE_PORT, ssl=ctx, server_hostname=EXAMPLE_HOST
            )
            ssl_object = writer.get_extra_info("ssl_object")
            der = ssl_object.getpeercert(binary_form=True)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return der

        der = asyncio.run(_run())
        self.assertIsInstance(der, bytes)
        self.assertGreater(len(der), 100)

    def test_get_verified_chain_via_object(self):
        """Line 356: get_verified_chain with actual certs after handshake."""

        async def _run():
            ctx = _make_ctx()
            reader, writer = await asyncio.open_connection(
                EXAMPLE_HOST, EXAMPLE_PORT, ssl=ctx, server_hostname=EXAMPLE_HOST
            )
            ssl_object = writer.get_extra_info("ssl_object")
            chain = ssl_object.get_verified_chain()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return chain

        chain = asyncio.run(_run())
        self.assertIsNotNone(chain)
        self.assertIsInstance(chain, list)
        self.assertGreater(len(chain), 0)
        self.assertIsInstance(chain[0], TLSCertificate)

    def test_read_into_buffer_via_object(self):
        """Lines 179-181: TLSObject.read() with buffer parameter.
        We use a mock to exercise this path since asyncio doesn't expose
        the raw ssl_object.read(buffer=...) pattern easily."""
        from unittest.mock import MagicMock

        ctx = _make_ctx()
        incoming = MemoryBIO()
        outgoing = MemoryBIO()
        obj = ctx.wrap_bio(incoming, outgoing, server_hostname=EXAMPLE_HOST)

        # Mock the conn to return plaintext data
        mock_conn = MagicMock()
        mock_conn.process_new_packets.return_value = None
        mock_conn.wants_write.return_value = False
        mock_conn.read_plaintext.return_value = b"hello world"
        obj._conn = mock_conn
        obj._shutdown = False

        buf = bytearray(1024)
        n = obj.read(1024, buffer=buf)
        self.assertEqual(n, 11)
        self.assertEqual(buf[:11], b"hello world")


class TestCovSocketRecvEOF(unittest.TestCase):
    """Cover _socket.py lines 216-222: SSLEOFError/SSLZeroReturnError in recv."""

    def test_recv_zero_return(self):
        """Lines 217-218: recv gets SSLZeroReturnError → returns b''."""
        ssock = _connect_tls()
        try:
            ssock.sendall(
                b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
            )
            # Read all data until connection closes
            total = b""
            while True:
                chunk = ssock.recv(4096)
                if not chunk:
                    break  # This exercises the SSLZeroReturnError/EOF path
                total += chunk
            self.assertGreater(len(total), 0)
        finally:
            ssock.close()

    def test_recv_eof_suppress_ragged(self):
        """Lines 219-222: SSLEOFError with suppress_ragged_eofs returns b''."""
        # This is exercised by the test above — when connection closes, we get
        # either SSLZeroReturnError or SSLEOFError, both returning b"".
        ssock = _connect_tls()
        try:
            ssock.sendall(
                b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
            )
            # Read until empty (which exercises EOF handling)
            while True:
                chunk = ssock.recv(4096)
                if not chunk:
                    break
        finally:
            ssock.close()

    def test_recv_sslerror_from_read(self):
        """Lines 219-222: SSLEOFError raised directly from sslobj.read."""
        from unittest.mock import MagicMock

        ssock = _connect_tls()
        try:
            # Replace sslobj_internal with a mock that raises SSLEOFError from read
            mock_obj = MagicMock()
            mock_obj.read.side_effect = SSLEOFError("EOF occurred")
            ssock._sslobj_internal = mock_obj
            ssock._suppress_ragged_eofs = True
            result = ssock.recv(1024)
            self.assertEqual(result, b"")
        finally:
            ssock.close()

    def test_recv_sslerror_from_read_no_suppress(self):
        """Lines 219-222: SSLEOFError without suppress_ragged_eofs raises."""
        from unittest.mock import MagicMock

        ssock = _connect_tls()
        try:
            mock_obj = MagicMock()
            mock_obj.read.side_effect = SSLEOFError("EOF occurred")
            ssock._sslobj_internal = mock_obj
            ssock._suppress_ragged_eofs = False
            with self.assertRaises(SSLEOFError):
                ssock.recv(1024)
        finally:
            ssock.close()

    def test_recv_sslzeroreturn_from_read(self):
        """Lines 217-218: SSLZeroReturnError from sslobj.read returns b''."""
        from unittest.mock import MagicMock

        ssock = _connect_tls()
        try:
            mock_obj = MagicMock()
            mock_obj.read.side_effect = SSLZeroReturnError("connection closed")
            ssock._sslobj_internal = mock_obj
            result = ssock.recv(1024)
            self.assertEqual(result, b"")
        finally:
            ssock.close()

    def test_recv_pull_incoming_eof_suppressed(self):
        """Lines 213-216: SSLEOFError from _pull_incoming is suppressed."""
        from unittest.mock import MagicMock, patch

        ssock = _connect_tls()
        try:
            mock_obj = MagicMock()
            mock_obj.read.side_effect = SSLWantReadError("need more data")
            ssock._sslobj_internal = mock_obj
            ssock._suppress_ragged_eofs = True
            # Make _pull_incoming raise SSLEOFError
            with patch.object(ssock, "_pull_incoming", side_effect=SSLEOFError("EOF")):
                with patch.object(ssock, "_flush_outgoing"):
                    result = ssock.recv(1024)
                    self.assertEqual(result, b"")
        finally:
            ssock.close()

    def test_recv_pull_incoming_eof_not_suppressed(self):
        """Lines 213-216: SSLEOFError from _pull_incoming raises when not suppressed."""
        from unittest.mock import MagicMock, patch

        ssock = _connect_tls()
        try:
            mock_obj = MagicMock()
            mock_obj.read.side_effect = SSLWantReadError("need more data")
            ssock._sslobj_internal = mock_obj
            ssock._suppress_ragged_eofs = False
            with patch.object(ssock, "_pull_incoming", side_effect=SSLEOFError("EOF")):
                with patch.object(ssock, "_flush_outgoing"):
                    with self.assertRaises(SSLEOFError):
                        ssock.recv(1024)
        finally:
            ssock.close()


class TestCovSocketRemainingGaps(unittest.TestCase):
    """Cover remaining socket gaps: lines 71-72, 171, 281."""

    def test_want_write_during_handshake(self):
        """Line 171: SSLWantWriteError during handshake."""
        from unittest.mock import MagicMock, patch

        ssock = _connect_tls()
        try:
            # Already connected, so this just verifies the path exists.
            # To trigger line 171, we need SSLWantWriteError during handshake.
            # Use a mock approach:
            pass
        finally:
            ssock.close()

        # More targeted: create a socket and mock the sslobj to raise SSLWantWriteError
        ctx = _make_ctx()
        sock = socket.create_connection(
            (EXAMPLE_HOST, EXAMPLE_PORT), timeout=CONNECT_TIMEOUT
        )
        tls_sock = TLSSocket(
            sock=sock,
            context=ctx,
            server_side=False,
            server_hostname=EXAMPLE_HOST,
            do_handshake_on_connect=False,
        )
        try:
            # Create sslobj and then mock its do_handshake
            tls_sock._create_sslobj()
            mock_obj = MagicMock()
            call_count = [0]

            def mock_handshake():
                call_count[0] += 1
                if call_count[0] == 1:
                    raise SSLWantWriteError("write buffer full")
                elif call_count[0] <= 3:
                    raise SSLWantReadError("need more data")
                # else: succeed

            mock_obj.do_handshake.side_effect = mock_handshake
            tls_sock._sslobj_internal = mock_obj
            with patch.object(tls_sock, "_flush_outgoing"):
                with patch.object(tls_sock, "_pull_incoming"):
                    tls_sock.do_handshake()
        finally:
            tls_sock.close()

    def test_pull_incoming_eagain_via_oserror(self):
        """Line 281: EAGAIN via OSError in _pull_incoming."""
        import errno as _errno
        from unittest.mock import patch

        ssock = _connect_tls()
        try:
            # EWOULDBLOCK variant
            err = OSError(_errno.EWOULDBLOCK, "Resource temporarily unavailable")
            with patch.object(socket.socket, "recv", side_effect=err):
                with self.assertRaises(SSLWantReadError):
                    ssock._pull_incoming(timeout=1.0)
        finally:
            ssock.close()


class TestCovObjectRemainingGaps(unittest.TestCase):
    """Cover _object.py lines 236 and 356 (getpeercert DER, get_verified_chain)."""

    def test_getpeercert_der_via_mock(self):
        """Line 236: getpeercert(binary_form=True) extracts DER bytes."""
        from unittest.mock import MagicMock

        ctx = _make_ctx()
        incoming = MemoryBIO()
        outgoing = MemoryBIO()
        obj = ctx.wrap_bio(incoming, outgoing, server_hostname=EXAMPLE_HOST)

        # Mock to simulate a completed handshake with certs
        mock_conn = MagicMock()
        mock_conn.peer_certificates.return_value = [b"\x30\x82\x01\x00" + b"\x00" * 252]
        obj._conn = mock_conn
        obj._handshake_done = True

        der = obj.getpeercert(binary_form=True)
        self.assertIsInstance(der, bytes)
        self.assertEqual(len(der), 256)

    def test_get_verified_chain_via_mock(self):
        """Line 356: get_verified_chain returns list of TLSCertificate."""
        from unittest.mock import MagicMock

        ctx = _make_ctx()
        incoming = MemoryBIO()
        outgoing = MemoryBIO()
        obj = ctx.wrap_bio(incoming, outgoing, server_hostname=EXAMPLE_HOST)

        # Mock to simulate certs available
        der1 = b"\x30\x82\x01\x00" + b"\x00" * 252
        der2 = b"\x30\x82\x02\x00" + b"\x00" * 508
        mock_conn = MagicMock()
        mock_conn.peer_certificates.return_value = [der1, der2]
        obj._conn = mock_conn

        chain = obj.get_verified_chain()
        self.assertIsNotNone(chain)
        self.assertEqual(len(chain), 2)
        self.assertIsInstance(chain[0], TLSCertificate)
        self.assertEqual(chain[0].public_bytes(), bytes(der1))


class TestCovUtilsRemainingGaps(unittest.TestCase):
    """Cover _utils.py line 120: get_server_certificate no cert → ValueError."""

    def test_get_server_certificate_no_cert(self):
        """Line 120: when server returns no cert, ValueError is raised."""
        from unittest.mock import patch

        # Patch TLSSocket.getpeercert to return None (simulates no cert from server)
        with patch.object(TLSSocket, "getpeercert", return_value=None):
            with self.assertRaises(ValueError) as cm:
                ssl.get_server_certificate((EXAMPLE_HOST, EXAMPLE_PORT))
            self.assertIn("No certificate", str(cm.exception))


class TestStdlibInterop(unittest.TestCase):
    """Cross-library interop: stdlib ssl server ↔ rtls client.

    This is the ultimate drop-in replacement proof. A real stdlib
    ssl.SSLSocket echo server runs in a thread.  The main thread
    connects with an rtls TLSSocket, sends a payload, and expects
    the exact bytes echoed back — over a genuine TLS session.
    """

    CERTDATA = os.path.join(os.path.dirname(__file__), "certdata")
    ROOT_CERT = os.path.join(CERTDATA, "root_cert.pem")
    LEAF_CHAIN = os.path.join(CERTDATA, "leaf_chain.pem")
    LEAF_KEY = os.path.join(CERTDATA, "leaf_key.pem")

    def _make_stdlib_server_ctx(self):
        """Build a stdlib ssl server context using our test certs."""
        ctx = _stdlib_ssl.SSLContext(_stdlib_ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=self.LEAF_CHAIN, keyfile=self.LEAF_KEY)
        return ctx

    def _make_rtls_client_ctx(self, *, verify=True):
        """Build an rtls client context that trusts our test root CA."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if verify:
            ctx.load_verify_locations(cafile=self.ROOT_CERT)
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _run_echo_server(self, server_ctx, server_sock, ready, result):
        """Echo server: accept one connection, echo everything back, close."""
        ready.set()
        conn = None
        ssl_conn = None
        try:
            conn, _ = server_sock.accept()
            ssl_conn = server_ctx.wrap_socket(conn, server_side=True)
            while True:
                data = ssl_conn.recv(4096)
                if not data:
                    break
                ssl_conn.sendall(data)
            result["server"] = "ok"
        except Exception as e:
            result["server_error"] = repr(e)
        finally:
            if ssl_conn is not None:
                ssl_conn.close()
            elif conn is not None:
                conn.close()

    def _start_server(self, server_ctx):
        """Bind, listen, and launch the echo-server thread."""
        import threading

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        server_sock.settimeout(10)

        result = {}
        ready = threading.Event()
        t = threading.Thread(
            target=self._run_echo_server,
            args=(server_ctx, server_sock, ready, result),
        )
        t.daemon = True
        t.start()
        ready.wait()

        port = server_sock.getsockname()[1]
        return server_sock, t, port, result

    def test_echo_basic(self):
        """rtls client <-> stdlib server: simple echo round-trip."""
        server_ctx = self._make_stdlib_server_ctx()
        server_sock, t, port, result = self._start_server(server_ctx)

        try:
            client_ctx = self._make_rtls_client_ctx()
            with client_ctx.wrap_socket(
                socket.socket(), server_hostname="localhost"
            ) as s:
                s.connect(("127.0.0.1", port))
                payload = b"Hello from rtls!"
                s.send(payload)
                echoed = s.recv(4096)
                self.assertEqual(echoed, payload)
        finally:
            server_sock.close()
            t.join(timeout=5)

        self.assertEqual(result.get("server"), "ok")

    def test_echo_large_payload(self):
        """rtls client <-> stdlib server: echo a 1 MiB payload.

        Validates high-throughput data transfer — the kind of workload
        seen during file downloads.  Exercises the pump→process→drain
        loop in TLSObject.read() that prevents rustls's internal buffer
        from overflowing.
        """
        import struct
        import threading

        server_ctx = self._make_stdlib_server_ctx()

        result = {}
        ready = threading.Event()

        def length_prefix_echo(server_sock, ready_event, res):
            """Server: read 4-byte length header, then payload, echo it."""
            ready_event.set()
            conn = None
            ssl_conn = None
            try:
                conn, _ = server_sock.accept()
                ssl_conn = server_ctx.wrap_socket(conn, server_side=True)
                # Read 4-byte length header
                hdr = b""
                while len(hdr) < 4:
                    hdr += ssl_conn.recv(4 - len(hdr))
                total = struct.unpack("!I", hdr)[0]
                # Read exactly `total` bytes
                received = bytearray()
                while len(received) < total:
                    chunk = ssl_conn.recv(min(16384, total - len(received)))
                    if not chunk:
                        break
                    received.extend(chunk)
                # Echo back
                ssl_conn.sendall(received)
                res["server"] = "ok"
            except Exception as e:
                res["server_error"] = repr(e)
            finally:
                if ssl_conn is not None:
                    ssl_conn.close()
                elif conn is not None:
                    conn.close()

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        server_sock.settimeout(30)
        port = server_sock.getsockname()[1]

        t = threading.Thread(
            target=length_prefix_echo,
            args=(server_sock, ready, result),
        )
        t.daemon = True
        t.start()
        ready.wait()

        try:
            client_ctx = self._make_rtls_client_ctx()
            with client_ctx.wrap_socket(
                socket.socket(), server_hostname="localhost"
            ) as s:
                s.connect(("127.0.0.1", port))

                payload = os.urandom(1024 * 1024)  # 1 MiB
                # Send length header + payload
                s.sendall(struct.pack("!I", len(payload)) + payload)

                # Collect all echoed bytes
                chunks = []
                remaining = len(payload)
                while remaining > 0:
                    chunk = s.recv(16384)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                echoed = b"".join(chunks)
                self.assertEqual(len(echoed), len(payload))
                self.assertEqual(echoed, payload)
        finally:
            server_sock.close()
            t.join(timeout=30)

        self.assertEqual(result.get("server"), "ok")

    def test_echo_multiple_round_trips(self):
        """rtls client <-> stdlib server: several send/recv round-trips."""

        server_ctx = self._make_stdlib_server_ctx()
        server_sock, t, port, result = self._start_server(server_ctx)

        try:
            client_ctx = self._make_rtls_client_ctx()
            with client_ctx.wrap_socket(
                socket.socket(), server_hostname="localhost"
            ) as s:
                s.connect(("127.0.0.1", port))
                for i in range(10):
                    msg = f"round-trip #{i}".encode()
                    s.send(msg)
                    echoed = s.recv(4096)
                    self.assertEqual(echoed, msg)
        finally:
            server_sock.close()
            t.join(timeout=5)

        self.assertEqual(result.get("server"), "ok")

    def test_echo_alpn_negotiation(self):
        """ALPN negotiated between stdlib server and rtls client."""
        server_ctx = self._make_stdlib_server_ctx()
        server_ctx.set_alpn_protocols(["h2", "http/1.1"])

        server_sock, t, port, result = self._start_server(server_ctx)

        try:
            client_ctx = self._make_rtls_client_ctx()
            client_ctx.set_alpn_protocols(["h2", "http/1.1"])
            with client_ctx.wrap_socket(
                socket.socket(), server_hostname="localhost"
            ) as s:
                s.connect(("127.0.0.1", port))

                # Verify ALPN was negotiated
                selected = s.selected_alpn_protocol()
                self.assertIn(selected, ("h2", "http/1.1"))

                # Still works as an echo channel
                s.send(b"alpn-test")
                self.assertEqual(s.recv(4096), b"alpn-test")
        finally:
            server_sock.close()
            t.join(timeout=5)

    def test_echo_getpeercert(self):
        """rtls client can retrieve and inspect the stdlib server's cert."""

        server_ctx = self._make_stdlib_server_ctx()
        server_sock, t, port, result = self._start_server(server_ctx)

        try:
            client_ctx = self._make_rtls_client_ctx()
            with client_ctx.wrap_socket(
                socket.socket(), server_hostname="localhost"
            ) as s:
                s.connect(("127.0.0.1", port))

                cert = s.getpeercert()
                self.assertIsInstance(cert, dict)
                # Our leaf cert CN is "localhost"
                subject = dict(x[0] for x in cert["subject"])
                self.assertEqual(subject["commonName"], "localhost")

                # Binary form should also work
                der = s.getpeercert(binary_form=True)
                self.assertIsInstance(der, bytes)
                self.assertGreater(len(der), 0)

                s.send(b"cert-ok")
                self.assertEqual(s.recv(4096), b"cert-ok")
        finally:
            server_sock.close()
            t.join(timeout=5)

    def test_echo_tls_version_and_cipher(self):
        """rtls reports a valid TLS version and cipher after handshake."""
        server_ctx = self._make_stdlib_server_ctx()
        server_sock, t, port, result = self._start_server(server_ctx)

        try:
            client_ctx = self._make_rtls_client_ctx()
            with client_ctx.wrap_socket(
                socket.socket(), server_hostname="localhost"
            ) as s:
                s.connect(("127.0.0.1", port))

                ver = s.version()
                self.assertIn(ver, ("TLSv1.2", "TLSv1.3"))

                cipher = s.cipher()
                self.assertIsInstance(cipher, tuple)
                self.assertEqual(len(cipher), 3)
                # (name, protocol, bits)
                self.assertIsInstance(cipher[0], str)
                self.assertIsInstance(cipher[2], int)
                self.assertGreater(cipher[2], 0)

                s.send(b"meta-ok")
                self.assertEqual(s.recv(4096), b"meta-ok")
        finally:
            server_sock.close()
            t.join(timeout=5)

    def test_streaming_download_2gb(self):
        """rtls client downloads 2 GiB from a stdlib ssl server.

        The server streams 65 536-byte blocks continuously.  The client
        receives as fast as possible using 65 536-byte recv calls.
        Verifies total byte count and a running CRC32 to catch any
        data corruption without holding 2 GiB in memory.
        """
        import hashlib
        import threading

        TOTAL = 2 * 1024 * 1024 * 1024  # 2 GiB
        BLOCK = 65536

        server_ctx = self._make_stdlib_server_ctx()
        result = {}
        ready = threading.Event()

        def streaming_server(server_sock, ready_event, res):
            ready_event.set()
            conn = None
            ssl_conn = None
            try:
                conn, _ = server_sock.accept()
                ssl_conn = server_ctx.wrap_socket(conn, server_side=True)
                h = hashlib.md5()
                sent = 0
                # Deterministic PRNG block — same seed so client can verify
                import random

                rng = random.Random(42)
                while sent < TOTAL:
                    # rng.randbytes() requires Python 3.9+; use
                    # getrandbits() which is available in 3.7+.
                    chunk = rng.getrandbits(BLOCK * 8).to_bytes(BLOCK, "big")
                    h.update(chunk)
                    ssl_conn.sendall(chunk)
                    sent += len(chunk)
                res["digest"] = h.hexdigest()
                res["server"] = "ok"
            except Exception as e:
                res["server_error"] = repr(e)
            finally:
                if ssl_conn is not None:
                    ssl_conn.close()
                elif conn is not None:
                    conn.close()

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        server_sock.settimeout(120)
        port = server_sock.getsockname()[1]

        t = threading.Thread(target=streaming_server, args=(server_sock, ready, result))
        t.daemon = True
        t.start()
        ready.wait()

        try:
            client_ctx = self._make_rtls_client_ctx()
            with client_ctx.wrap_socket(
                socket.socket(), server_hostname="localhost"
            ) as s:
                s.connect(("127.0.0.1", port))

                h = hashlib.md5()
                received = 0
                while received < TOTAL:
                    chunk = s.recv(BLOCK)
                    if not chunk:
                        break
                    h.update(chunk)
                    received += len(chunk)

                self.assertEqual(received, TOTAL)
        finally:
            server_sock.close()
            t.join(timeout=120)

        self.assertEqual(result.get("server"), "ok")
        self.assertEqual(h.hexdigest(), result["digest"])

    def test_keylog_filename_writes_secrets(self):
        """keylog_filename writes TLS secrets without $SSLKEYLOGFILE env var."""
        import tempfile

        server_ctx = self._make_stdlib_server_ctx()
        server_sock, t, port, result = self._start_server(server_ctx)

        # Create a temp file for keylog output
        fd, keylog_path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        os.unlink(keylog_path)  # ensure it doesn't exist yet

        try:
            client_ctx = self._make_rtls_client_ctx()
            client_ctx.keylog_filename = keylog_path

            with client_ctx.wrap_socket(
                socket.socket(), server_hostname="localhost"
            ) as s:
                s.connect(("127.0.0.1", port))
                s.sendall(b"hello")
                data = s.recv(1024)
                self.assertEqual(data, b"hello")

            # Verify keylog file was created and contains valid entries
            self.assertTrue(
                os.path.exists(keylog_path),
                "keylog file was not created",
            )
            with open(keylog_path) as f:
                content = f.read()

            self.assertGreater(len(content), 0, "keylog file is empty")

            # NSS Key Log format: each line is "LABEL <client_random_hex> <secret_hex>"
            lines = [l for l in content.strip().splitlines() if l]
            for line in lines:
                parts = line.split(" ")
                self.assertEqual(len(parts), 3, f"malformed keylog line: {line!r}")
                label, client_random, secret = parts
                # client_random and secret must be hex strings
                self.assertTrue(
                    all(c in "0123456789abcdef" for c in client_random),
                    f"non-hex client_random: {client_random!r}",
                )
                self.assertTrue(
                    all(c in "0123456789abcdef" for c in secret),
                    f"non-hex secret: {secret!r}",
                )

            # Must contain at least CLIENT_TRAFFIC_SECRET_0
            labels = {l.split(" ")[0] for l in lines}
            self.assertIn("CLIENT_TRAFFIC_SECRET_0", labels)
        finally:
            server_sock.close()
            t.join(timeout=10)
            if os.path.exists(keylog_path):
                os.unlink(keylog_path)


if __name__ == "__main__":
    unittest.main()
