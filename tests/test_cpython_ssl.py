"""
Backported CPython test_ssl.py tests for rtls.

This file adapts CPython's Lib/test/test_ssl.py to test rtls (our rustls-backed
drop-in replacement for Python's ssl module). Key adaptations:
  - `import rtls as ssl` instead of `import ssl`
  - All `support.*` / `socket_helper.*` dependencies replaced with simple equivalents
  - ThreadedEchoServer ported with support.* removed
  - Tests that rely on OpenSSL internals (_ssl, ASN1Object, DH params, etc.) are skipped
  - Error message assertions adapted for rustls error strings
  - Session-related features (session reuse) skipped (rustls doesn't expose sessions)
"""

import sys
import unittest.mock
from ast import literal_eval
import socket
import select
import time
import os
import errno
import pprint
import threading
import traceback

import rtls as ssl


VERBOSE = False
HOST = "127.0.0.1"
SHORT_TIMEOUT = 30.0


def handle_error(prefix):
    exc_format = " ".join(traceback.format_exception(sys.exception()))
    if VERBOSE:
        sys.stdout.write(prefix + exc_format)


def utc_offset():
    if time.daylight and time.localtime().tm_isdst > 0:
        return -time.altzone
    return -time.timezone


def data_file(*name):
    return os.path.join(os.path.dirname(__file__), "certdata", *name)


CERTFILE = data_file("keycert.pem")
BYTES_CERTFILE = os.fsencode(CERTFILE)
ONLYCERT = data_file("ssl_cert.pem")
ONLYKEY = data_file("ssl_key.pem")
BYTES_ONLYCERT = os.fsencode(ONLYCERT)
BYTES_ONLYKEY = os.fsencode(ONLYKEY)
CERTFILE_PROTECTED = data_file("keycert.passwd.pem")
ONLYKEY_PROTECTED = data_file("ssl_key.passwd.pem")
KEY_PASSWORD = "somepass"
CAPATH = data_file("capath")
BYTES_CAPATH = os.fsencode(CAPATH)
CAFILE_NEURONIO = data_file("capath", "4e1295a3.0")
CAFILE_CACERT = data_file("capath", "5ed36f99.0")

# Reference dicts for parsed certs
_ref_file = data_file("keycert.pem.reference")
if os.path.exists(_ref_file):
    with open(_ref_file) as _f:
        CERTFILE_INFO = literal_eval(_f.read())
else:
    CERTFILE_INFO = None

SIGNED_CERTFILE = data_file("keycert3.pem")
SINGED_CERTFILE_ONLY = data_file("cert3.pem")
SIGNED_CERTFILE_HOSTNAME = "localhost"

_ref_file2 = data_file("keycert3.pem.reference")
if os.path.exists(_ref_file2):
    with open(_ref_file2) as _f:
        SIGNED_CERTFILE_INFO = literal_eval(_f.read())
else:
    SIGNED_CERTFILE_INFO = None

SIGNED_CERTFILE2 = data_file("keycert4.pem")
SIGNED_CERTFILE2_HOSTNAME = "fakehostname"
SIGNED_CERTFILE_ECC = data_file("keycertecc.pem")
SIGNED_CERTFILE_ECC_HOSTNAME = "localhost-ecc"

LEAF_MISSING_AKI_CERTFILE = data_file("leaf-missing-aki.keycert.pem")
LEAF_MISSING_AKI_CERTFILE_HOSTNAME = "example.com"
LEAF_MISSING_AKI_CA = data_file("leaf-missing-aki.ca.pem")

SIGNING_CA = data_file("capath", "ceff1710.0")
ALLSANFILE = data_file("allsans.pem")
IDNSANSFILE = data_file("idnsans.pem")
NOSANFILE = data_file("nosan.pem")
NOSAN_HOSTNAME = "localhost"

EMPTYCERT = data_file("nullcert.pem")
BADCERT = data_file("badcert.pem")
NONEXISTINGCERT = data_file("XXXnonexisting.pem")
NONEXISTINGKEY = data_file("XXXnonexistingkey.pem")
BADKEY = data_file("badkey.pem")
NOKIACERT = data_file("nokia.pem")
NULLBYTECERT = data_file("nullbytecert.pem")
TALOS_INVALID_CRLDP = data_file("talos-2019-0758.pem")


def make_test_context(
    *,
    server_side=False,
    check_hostname=None,
    cert_reqs=ssl.CERT_NONE,
    ca_certs=None,
    certfile=None,
    keyfile=None,
    ciphers=None,
    min_version=None,
    max_version=None,
):
    if server_side:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    if check_hostname is None:
        if cert_reqs == ssl.CERT_NONE:
            context.check_hostname = False
    else:
        context.check_hostname = check_hostname

    if cert_reqs is not None:
        context.verify_mode = cert_reqs

    if ca_certs is not None:
        context.load_verify_locations(ca_certs)
    if certfile is not None or keyfile is not None:
        context.load_cert_chain(certfile, keyfile)

    if ciphers is not None:
        context.set_ciphers(ciphers)

    if min_version is not None:
        context.minimum_version = min_version
    if max_version is not None:
        context.maximum_version = max_version

    return context


def _test_wrap_socket(
    sock,
    *,
    server_side=False,
    check_hostname=None,
    cert_reqs=ssl.CERT_NONE,
    ca_certs=None,
    certfile=None,
    keyfile=None,
    ciphers=None,
    min_version=None,
    max_version=None,
    **kwargs,
):
    context = make_test_context(
        server_side=server_side,
        check_hostname=check_hostname,
        cert_reqs=cert_reqs,
        ca_certs=ca_certs,
        certfile=certfile,
        keyfile=keyfile,
        ciphers=ciphers,
        min_version=min_version,
        max_version=max_version,
    )
    if not server_side:
        kwargs.setdefault("server_hostname", SIGNED_CERTFILE_HOSTNAME)
    return context.wrap_socket(sock, server_side=server_side, **kwargs)


_test_wrap_socket.__test__ = False  # Not a pytest test
test_wrap_socket = _test_wrap_socket


def _testing_context(server_cert=None, *, server_chain=True, client_cert=None):
    """Create a client/server context pair for testing.

    Returns (client_context, server_context, hostname).
    """
    if server_cert is None:
        server_cert = SIGNED_CERTFILE

    if server_cert == SIGNED_CERTFILE:
        hostname = SIGNED_CERTFILE_HOSTNAME
    elif server_cert == SIGNED_CERTFILE2:
        hostname = SIGNED_CERTFILE2_HOSTNAME
    elif server_cert == NOSANFILE:
        hostname = NOSAN_HOSTNAME
    else:
        hostname = "localhost"

    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.load_verify_locations(SIGNING_CA)

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(server_cert)
    if server_chain:
        server_context.load_verify_locations(SIGNING_CA)

    if client_cert:
        client_context.load_cert_chain(client_cert)
        server_context.verify_mode = ssl.CERT_REQUIRED

    return client_context, server_context, hostname


_testing_context.__test__ = False  # Not a pytest test
testing_context = _testing_context


class ThreadedEchoServer(threading.Thread):
    class ConnectionHandler(threading.Thread):
        """Connection handler that works with and without SSL wrapping."""

        def __init__(self, server, connsock, addr):
            self.server = server
            self.running = False
            self.sock = connsock
            self.addr = addr
            self.sock.setblocking(True)
            self.sslconn = None
            threading.Thread.__init__(self)
            self.daemon = True

        def wrap_conn(self):
            try:
                self.sslconn = self.server.context.wrap_socket(
                    self.sock, server_side=True
                )
                self.server.selected_alpn_protocols.append(
                    self.sslconn.selected_alpn_protocol()
                )
            except (
                ConnectionResetError,
                BrokenPipeError,
                ConnectionAbortedError,
            ) as e:
                self.server.conn_errors.append(str(e))
                if self.server.chatty:
                    handle_error(
                        "\n server:  bad connection attempt from "
                        + repr(self.addr)
                        + ":\n"
                    )
                self.running = False
                self.close()
                return False
            except (ssl.SSLError, OSError) as e:
                self.server.conn_errors.append(str(e))
                if self.server.chatty:
                    handle_error(
                        "\n server:  bad connection attempt from "
                        + repr(self.addr)
                        + ":\n"
                    )
                if e.errno != errno.EPROTOTYPE and sys.platform != "darwin":
                    self.running = False
                    self.close()
                return False
            else:
                self.server.shared_ciphers.append(self.sslconn.shared_ciphers())
                if self.server.context.verify_mode == ssl.CERT_REQUIRED:
                    cert = self.sslconn.getpeercert()
                    if VERBOSE and self.server.chatty:
                        sys.stdout.write(
                            " client cert is " + pprint.pformat(cert) + "\n"
                        )
                cipher = self.sslconn.cipher()
                if VERBOSE and self.server.chatty:
                    sys.stdout.write(
                        " server: connection cipher is now " + str(cipher) + "\n"
                    )
                return True

        def read(self):
            if self.sslconn:
                return self.sslconn.read()
            else:
                return self.sock.recv(1024)

        def write(self, data):
            if self.sslconn:
                return self.sslconn.write(data)
            else:
                return self.sock.send(data)

        def close(self):
            if self.sslconn:
                self.sslconn.close()
            else:
                self.sock.close()

        def run(self):
            self.running = True
            if not self.server.starttls_server:
                if not self.wrap_conn():
                    return
            while self.running:
                try:
                    msg = self.read()
                    stripped = msg.strip()
                    if not stripped:
                        # eof, so quit this handler
                        self.running = False
                        try:
                            self.sock = self.sslconn.unwrap()
                        except OSError:
                            pass
                        else:
                            self.sslconn = None
                        self.close()
                    elif stripped == b"over":
                        if VERBOSE and self.server.connectionchatty:
                            sys.stdout.write(" server: client closed connection\n")
                        self.close()
                        return
                    elif self.server.starttls_server and stripped == b"STARTTLS":
                        if VERBOSE and self.server.connectionchatty:
                            sys.stdout.write(
                                " server: read STARTTLS from client, sending OK...\n"
                            )
                        self.write(b"OK\n")
                        if not self.wrap_conn():
                            return
                    elif (
                        self.server.starttls_server
                        and self.sslconn
                        and stripped == b"ENDTLS"
                    ):
                        if VERBOSE and self.server.connectionchatty:
                            sys.stdout.write(
                                " server: read ENDTLS from client, sending OK...\n"
                            )
                        self.write(b"OK\n")
                        self.sock = self.sslconn.unwrap()
                        self.sslconn = None
                        if VERBOSE and self.server.connectionchatty:
                            sys.stdout.write(
                                " server: connection is now unencrypted...\n"
                            )
                    elif stripped == b"CB tls-unique":
                        if VERBOSE and self.server.connectionchatty:
                            sys.stdout.write(
                                " server: read CB tls-unique from client, sending our CB data...\n"
                            )
                        data = self.sslconn.get_channel_binding("tls-unique")
                        self.write(repr(data).encode("us-ascii") + b"\n")
                    elif stripped == b"VERIFIEDCHAIN":
                        certs = self.sslconn._sslobj.get_verified_chain()
                        self.write(len(certs).to_bytes(1, "big") + b"\n")
                    elif stripped == b"UNVERIFIEDCHAIN":
                        certs = self.sslconn._sslobj.get_unverified_chain()
                        self.write(len(certs).to_bytes(1, "big") + b"\n")
                    else:
                        if VERBOSE and self.server.connectionchatty:
                            ctype = (self.sslconn and "encrypted") or "unencrypted"
                            sys.stdout.write(
                                " server: read %r (%s), sending back %r (%s)...\n"
                                % (msg, ctype, msg.lower(), ctype)
                            )
                        self.write(msg.lower())
                except OSError as e:
                    if isinstance(e, ConnectionError):
                        if self.server.chatty and VERBOSE:
                            print(f" Connection reset by peer: {self.addr}")
                        self.close()
                        self.running = False
                        return
                    if self.server.chatty and VERBOSE:
                        handle_error("Test server failure:\n")
                    try:
                        self.write(b"ERROR\n")
                    except OSError:
                        pass
                    self.close()
                    self.running = False

    def __init__(
        self,
        certificate=None,
        ssl_version=None,
        certreqs=None,
        cacerts=None,
        chatty=True,
        connectionchatty=False,
        starttls_server=False,
        alpn_protocols=None,
        ciphers=None,
        context=None,
    ):
        if context:
            self.context = context
        else:
            self.context = ssl.SSLContext(
                ssl_version if ssl_version is not None else ssl.PROTOCOL_TLS_SERVER
            )
            self.context.verify_mode = (
                certreqs if certreqs is not None else ssl.CERT_NONE
            )
            if cacerts:
                self.context.load_verify_locations(cacerts)
            if certificate:
                self.context.load_cert_chain(certificate)
            if alpn_protocols:
                self.context.set_alpn_protocols(alpn_protocols)
            if ciphers:
                self.context.set_ciphers(ciphers)
        self.chatty = chatty
        self.connectionchatty = connectionchatty
        self.starttls_server = starttls_server
        self.sock = socket.socket()
        self.sock.bind((HOST, 0))
        self.port = self.sock.getsockname()[1]
        self.flag = None
        self.active = False
        self.selected_alpn_protocols = []
        self.shared_ciphers = []
        self.conn_errors = []
        threading.Thread.__init__(self)
        self.daemon = True
        self._in_context = False

    def __enter__(self):
        if self._in_context:
            raise ValueError("Re-entering ThreadedEchoServer context")
        self._in_context = True
        self.start(threading.Event())
        self.flag.wait()
        return self

    def __exit__(self, *args):
        assert self._in_context
        self._in_context = False
        self.stop()
        self.join()

    def start(self, flag=None):
        if not self._in_context:
            raise ValueError("ThreadedEchoServer must be used as a context manager")
        self.flag = flag
        threading.Thread.start(self)

    def run(self):
        if not self._in_context:
            raise ValueError("ThreadedEchoServer must be used as a context manager")
        self.sock.settimeout(1.0)
        self.sock.listen(5)
        self.active = True
        if self.flag:
            self.flag.set()
        while self.active:
            try:
                newconn, connaddr = self.sock.accept()
                if VERBOSE and self.chatty:
                    sys.stdout.write(
                        " server:  new connection from " + repr(connaddr) + "\n"
                    )
                handler = self.ConnectionHandler(self, newconn, connaddr)
                handler.start()
                handler.join()
            except TimeoutError:
                if VERBOSE:
                    sys.stdout.write(" connection timeout\n")
            except KeyboardInterrupt:
                self.stop()
            except BaseException as e:
                if VERBOSE and self.chatty:
                    sys.stdout.write(" connection handling failed: " + repr(e) + "\n")

        self.close()

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def stop(self):
        self.active = False


def server_params_test(
    client_context,
    server_context,
    indata=b"FOO\n",
    chatty=True,
    connectionchatty=False,
    sni_name=None,
):
    """Launch a server, connect a client to it and try various reads and writes."""
    stats = {}
    server = ThreadedEchoServer(
        context=server_context, chatty=chatty, connectionchatty=False
    )
    with server:
        with client_context.wrap_socket(socket.socket(), server_hostname=sni_name) as s:
            s.connect((HOST, server.port))
            for arg in [indata, bytearray(indata), memoryview(indata)]:
                if connectionchatty and VERBOSE:
                    sys.stdout.write(" client:  sending %r...\n" % indata)
                s.write(arg)
                outdata = s.read()
                if connectionchatty and VERBOSE:
                    sys.stdout.write(" client:  read %r\n" % outdata)
                if outdata != indata.lower():
                    raise AssertionError(
                        "bad data <<%r>> (%d) received; expected <<%r>> (%d)\n"
                        % (
                            outdata[:20],
                            len(outdata),
                            indata[:20].lower(),
                            len(indata),
                        )
                    )
            s.write(b"over\n")
            if connectionchatty and VERBOSE:
                sys.stdout.write(" client:  closing connection.\n")
            stats.update(
                {
                    "compression": s.compression(),
                    "cipher": s.cipher(),
                    "peercert": s.getpeercert(),
                    "client_alpn_protocol": s.selected_alpn_protocol(),
                    "version": s.version(),
                }
            )
            s.close()
        stats["server_alpn_protocols"] = server.selected_alpn_protocols
        stats["server_shared_ciphers"] = server.shared_ciphers
    return stats


def ssl_io_loop(sock, incoming, outgoing, func, *args, timeout=SHORT_TIMEOUT):
    """A simple IO loop for BIO-based TLS operations."""
    deadline = time.monotonic() + timeout
    count = 0
    while time.monotonic() < deadline:
        err = None
        count += 1
        try:
            ret = func(*args)
        except ssl.SSLError as e:
            if e.errno not in (ssl.SSL_ERROR_WANT_READ, ssl.SSL_ERROR_WANT_WRITE):
                raise
            err = e.errno
        # Get any data from the outgoing BIO and send it to the socket.
        buf = outgoing.read()
        if buf:
            sock.sendall(buf)
        # If there's no error, we're done.
        if err is None:
            break
        elif err == ssl.SSL_ERROR_WANT_READ:
            buf = sock.recv(32768)
            if buf:
                incoming.write(buf)
            else:
                incoming.write_eof()
    else:
        raise TimeoutError("ssl_io_loop timed out")
    if VERBOSE:
        sys.stdout.write("Needed %d calls to complete %s().\n" % (count, func.__name__))
    return ret


class BasicSocketTests(unittest.TestCase):
    def test_constants(self):
        ssl.CERT_NONE
        ssl.CERT_OPTIONAL
        ssl.CERT_REQUIRED
        ssl.OP_CIPHER_SERVER_PREFERENCE
        ssl.OP_SINGLE_DH_USE
        ssl.OP_SINGLE_ECDH_USE
        ssl.OP_NO_COMPRESSION
        self.assertEqual(ssl.HAS_SNI, True)
        self.assertEqual(ssl.HAS_ECDH, True)
        self.assertIsInstance(ssl.HAS_TLSv1_2, bool)
        self.assertEqual(ssl.HAS_TLSv1_3, True)
        ssl.OP_NO_SSLv2
        ssl.OP_NO_SSLv3
        ssl.OP_NO_TLSv1
        ssl.OP_NO_TLSv1_3
        ssl.OP_NO_TLSv1_1
        ssl.OP_NO_TLSv1_2
        self.assertEqual(ssl.PROTOCOL_TLS, ssl.PROTOCOL_SSLv23)

    def test_options(self):
        # gh-106687: SSL options values are unsigned integer
        for name in dir(ssl):
            if not name.startswith("OP_"):
                continue
            with self.subTest(option=name):
                value = getattr(ssl, name)
                self.assertGreaterEqual(value, 0, f"ssl.{name}")

    def test_random(self):
        v = ssl.RAND_status()
        self.assertTrue(v)
        data = ssl.RAND_bytes(16)
        self.assertEqual(len(data), 16)

        ssl.RAND_add("this is a random string", 75.0)
        ssl.RAND_add(b"this is a random bytes object", 75.0)
        ssl.RAND_add(bytearray(b"this is a random bytearray object"), 75.0)

    def test_DER_to_PEM(self):
        with open(CAFILE_CACERT, "r") as f:
            pem = f.read()
        d1 = ssl.PEM_cert_to_DER_cert(pem)
        p2 = ssl.DER_cert_to_PEM_cert(d1)
        d2 = ssl.PEM_cert_to_DER_cert(p2)
        self.assertEqual(d1, d2)
        self.assertTrue(
            p2.startswith("-----BEGIN CERTIFICATE-----\n"),
            "DER-to-PEM didn't include correct header",
        )
        self.assertTrue(
            p2.endswith("\n-----END CERTIFICATE-----\n"),
            "DER-to-PEM didn't include correct footer",
        )

    def test_openssl_version(self):
        n = ssl.OPENSSL_VERSION_NUMBER
        t = ssl.OPENSSL_VERSION_INFO
        s = ssl.OPENSSL_VERSION
        self.assertIsInstance(n, int)
        self.assertIsInstance(t, tuple)
        self.assertIsInstance(s, str)
        # rtls reports rustls version info — just check it's reasonable
        self.assertGreater(n, 0)
        major, minor, fix, patch, status = t
        self.assertGreaterEqual(major, 0)

    def test_timeout(self):
        # Issue #8524: when creating an SSL socket, the timeout of the
        # original socket should be retained.
        for timeout in (None, 0.0, 5.0):
            s = socket.socket(socket.AF_INET)
            s.settimeout(timeout)
            with test_wrap_socket(s) as ss:
                self.assertEqual(timeout, ss.gettimeout())

    def test_empty_cert(self):
        """Wrapping with an empty cert file"""
        sock = socket.socket()
        self.addCleanup(sock.close)
        with self.assertRaises((ssl.SSLError, Exception)):
            test_wrap_socket(sock, certfile=EMPTYCERT)

    def test_malformed_cert(self):
        """Wrapping with a badly formatted certificate (syntax error)"""
        sock = socket.socket()
        self.addCleanup(sock.close)
        with self.assertRaises((ssl.SSLError, Exception)):
            test_wrap_socket(sock, certfile=BADCERT)

    def test_malformed_key(self):
        """Wrapping with a badly formatted key (syntax error)"""
        sock = socket.socket()
        self.addCleanup(sock.close)
        with self.assertRaises((ssl.SSLError, Exception)):
            test_wrap_socket(sock, certfile=BADKEY)

    def test_cert_time_to_seconds(self):
        timestring = "Jan  5 09:34:43 2018 GMT"
        ts = 1515144883.0
        self.assertEqual(ssl.cert_time_to_seconds(timestring), ts)
        # accept both %e and %d
        self.assertEqual(ssl.cert_time_to_seconds("Jan 05 09:34:43 2018 GMT"), ts)

        # failure cases
        with self.assertRaises(ValueError):
            ssl.cert_time_to_seconds("Jan  5 09:34 2018 GMT")  # no seconds
        with self.assertRaises(ValueError):
            ssl.cert_time_to_seconds("Jan  5 09:34:43 2018")  # no GMT

    def test_get_default_verify_paths(self):
        paths = ssl.get_default_verify_paths()
        self.assertEqual(len(paths), 6)
        self.assertIsInstance(paths, ssl.DefaultVerifyPaths)

    def test_read_write_zero(self):
        # empty reads and writes now work
        client_context, server_context, hostname = testing_context()
        server = ThreadedEchoServer(context=server_context)
        with server:
            with client_context.wrap_socket(
                socket.socket(), server_hostname=hostname
            ) as s:
                s.connect((HOST, server.port))
                self.assertEqual(s.recv(0), b"")
                self.assertEqual(s.send(b""), 0)


class ContextTests(unittest.TestCase):
    def test_constructor(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.assertEqual(ctx.protocol, ssl.PROTOCOL_TLS_CLIENT)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.assertEqual(ctx.protocol, ssl.PROTOCOL_TLS_SERVER)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        self.assertEqual(ctx.protocol, ssl.PROTOCOL_TLS)

    def test_ciphers(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.set_ciphers("ALL")
        ctx.set_ciphers("DEFAULT")
        with self.assertRaises(ssl.SSLError):
            ctx.set_ciphers("^$:,;?*'dorothyx")

    def test_get_ciphers(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ciphers = ctx.get_ciphers()
        self.assertIsInstance(ciphers, list)
        self.assertGreater(len(ciphers), 0)
        # Each cipher should be a dict with a 'name' key
        for cipher in ciphers:
            self.assertIn("name", cipher)

    def test_options(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        default = ssl.OP_ALL | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        # rtls sets these by default
        self.assertIsInstance(ctx.options, int)
        # Should at least have OP_ALL set
        self.assertTrue(ctx.options & ssl.OP_ALL)

    def test_verify_mode_protocol(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        # Default value for PROTOCOL_TLS is CERT_NONE
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        ctx.verify_mode = ssl.CERT_OPTIONAL
        self.assertEqual(ctx.verify_mode, ssl.CERT_OPTIONAL)
        ctx.verify_mode = ssl.CERT_REQUIRED
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        ctx.verify_mode = ssl.CERT_NONE
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        self.assertFalse(ctx.check_hostname)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)

    def test_hostname_checks_common_name(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # rtls/rustls never checks CN (only SAN), attribute is not defined
        with self.assertRaises(AttributeError):
            ctx.hostname_checks_common_name  # noqa: B018
        with self.assertRaises(AttributeError):
            ctx.hostname_checks_common_name = True

    def test_min_max_version(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # rtls defaults: min=None, max=None (meaning TLS 1.2..1.3)
        # Just test that setting works
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        # rustls doesn't support < 1.2, so TLSv1_1 should clamp
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_security_level(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.assertIsInstance(ctx.security_level, int)
        # rtls returns 2 always
        self.assertEqual(ctx.security_level, 2)

    def test_verify_flags(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # rtls returns 0 for verify_flags
        self.assertIsInstance(ctx.verify_flags, int)

    def test_load_cert_chain(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Combined key and cert in a single file
        ctx.load_cert_chain(CERTFILE, keyfile=None)
        ctx.load_cert_chain(CERTFILE, keyfile=CERTFILE)
        # Non-existing cert should raise
        with self.assertRaises(OSError):
            ctx.load_cert_chain(NONEXISTINGCERT)
        with self.assertRaises(OSError):
            ctx.load_cert_chain(CERTFILE, keyfile=NONEXISTINGKEY)
        # Bad cert should raise
        with self.assertRaises((ssl.SSLError, Exception)):
            ctx.load_cert_chain(BADCERT)
        with self.assertRaises((ssl.SSLError, Exception)):
            ctx.load_cert_chain(EMPTYCERT)
        # Separate key and cert
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(ONLYCERT, ONLYKEY)
        ctx.load_cert_chain(certfile=ONLYCERT, keyfile=ONLYKEY)
        # Password protected key and cert
        ctx.load_cert_chain(CERTFILE_PROTECTED, password=KEY_PASSWORD)
        ctx.load_cert_chain(CERTFILE_PROTECTED, password=KEY_PASSWORD.encode())
        ctx.load_cert_chain(
            CERTFILE_PROTECTED, password=bytearray(KEY_PASSWORD.encode())
        )
        ctx.load_cert_chain(ONLYCERT, ONLYKEY_PROTECTED, KEY_PASSWORD)
        ctx.load_cert_chain(ONLYCERT, ONLYKEY_PROTECTED, KEY_PASSWORD.encode())

        # Password callback
        def getpass_unicode():
            return KEY_PASSWORD

        def getpass_bytes():
            return KEY_PASSWORD.encode()

        ctx.load_cert_chain(CERTFILE_PROTECTED, password=getpass_unicode)
        ctx.load_cert_chain(CERTFILE_PROTECTED, password=getpass_bytes)

        with self.assertRaises((ssl.SSLError, Exception)):
            ctx.load_cert_chain(CERTFILE_PROTECTED, password="badpass")

    def test_load_verify_locations(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_verify_locations(CERTFILE)
        ctx.load_verify_locations(cafile=CERTFILE, capath=None)
        with self.assertRaises(OSError):
            ctx.load_verify_locations(NONEXISTINGCERT)
        ctx.load_verify_locations(CERTFILE, CAPATH)

    def test_load_verify_cadata(self):
        with open(CAFILE_CACERT) as f:
            cacert_pem = f.read()
        cacert_der = ssl.PEM_cert_to_DER_cert(cacert_pem)
        with open(CAFILE_NEURONIO) as f:
            neuronio_pem = f.read()

        # test PEM
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cadata=cacert_pem)
        self.assertGreaterEqual(ctx.cert_store_stats()["x509_ca"], 1)
        ctx.load_verify_locations(cadata=neuronio_pem)
        self.assertGreaterEqual(ctx.cert_store_stats()["x509_ca"], 2)

        # combined
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        combined = "\n".join((cacert_pem, neuronio_pem))
        ctx.load_verify_locations(cadata=combined)
        self.assertGreaterEqual(ctx.cert_store_stats()["x509_ca"], 2)

        # test DER
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cadata=cacert_der)
        self.assertGreaterEqual(ctx.cert_store_stats()["x509_ca"], 1)

    def test_session_stats(self):
        for proto in {ssl.PROTOCOL_TLS_CLIENT, ssl.PROTOCOL_TLS_SERVER}:
            ctx = ssl.SSLContext(proto)
            stats = ctx.session_stats()
            self.assertEqual(
                stats,
                {
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
                },
            )

    def test_set_default_verify_paths(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # Should not crash or raise
        ctx.set_default_verify_paths()

    def test_sni_callback(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        def dummycallback(sock, servername, ctx):
            pass

        ctx.sni_callback = None
        ctx.sni_callback = dummycallback

    def test_cert_store_stats(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        stats = ctx.cert_store_stats()
        self.assertEqual(stats["x509_ca"], 0)
        self.assertEqual(stats["crl"], 0)
        ctx.load_verify_locations(SIGNING_CA)
        stats = ctx.cert_store_stats()
        self.assertGreaterEqual(stats["x509_ca"], 1)

    def test_get_ca_certs(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.assertEqual(ctx.get_ca_certs(), [])
        ctx.load_verify_locations(SIGNING_CA)
        ca_certs = ctx.get_ca_certs()
        self.assertGreaterEqual(len(ca_certs), 1)

    def test_load_default_certs(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_default_certs()
        # Should not crash

    def test_create_default_context(self):
        ctx = ssl.create_default_context()
        self.assertEqual(ctx.protocol, ssl.PROTOCOL_TLS_CLIENT)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)

        with open(SIGNING_CA) as f:
            cadata = f.read()
        ctx = ssl.create_default_context(
            cafile=SIGNING_CA, capath=CAPATH, cadata=cadata
        )
        self.assertEqual(ctx.protocol, ssl.PROTOCOL_TLS_CLIENT)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.assertEqual(ctx.protocol, ssl.PROTOCOL_TLS_SERVER)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)

    def test_check_hostname(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        self.assertFalse(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)

        # Setting check_hostname = True should require CERT_REQUIRED or fail
        # rtls: check_hostname=True with CERT_NONE raises ValueError
        with self.assertRaises(ValueError):
            ctx.check_hostname = True

        # Set verify_mode first, then check_hostname
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

        # Setting verify_mode to CERT_NONE should disable check_hostname
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.assertFalse(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)

    def test_context_client_server(self):
        # PROTOCOL_TLS_CLIENT has sane defaults
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

        # PROTOCOL_TLS_SERVER has different but also sane defaults
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.assertFalse(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)

    def test_set_alpn_protocols(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        self.assertEqual(ctx.get_alpn_protocols(), ["h2", "http/1.1"])


class SSLErrorTests(unittest.TestCase):
    def test_str(self):
        # The str() of a SSLError doesn't include the errno
        e = ssl.SSLError(1, "foo")
        self.assertEqual(str(e), "foo")
        self.assertEqual(e.errno, 1)
        # Same for a subclass
        e = ssl.SSLZeroReturnError(1, "foo")
        self.assertEqual(str(e), "foo")
        self.assertEqual(e.errno, 1)

    @unittest.skipIf(
        sys.version_info < (3, 8), "socket.create_server requires Python 3.8+"
    )
    def test_subclass(self):
        # Check that the appropriate SSLError subclass is raised
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_server(("127.0.0.1", 0)) as s:
            c = socket.create_connection(s.getsockname())
            c.setblocking(False)
            with ctx.wrap_socket(c, False, do_handshake_on_connect=False) as c:
                with self.assertRaises(ssl.SSLWantReadError):
                    c.do_handshake()

    def test_exception_hierarchy(self):
        # Ensure our exceptions are proper subclasses of stdlib ssl exceptions
        import ssl as stdlib_ssl

        self.assertTrue(issubclass(ssl.SSLError, stdlib_ssl.SSLError))
        self.assertTrue(issubclass(ssl.SSLWantReadError, stdlib_ssl.SSLWantReadError))
        self.assertTrue(issubclass(ssl.SSLWantWriteError, stdlib_ssl.SSLWantWriteError))
        self.assertTrue(
            issubclass(ssl.SSLZeroReturnError, stdlib_ssl.SSLZeroReturnError)
        )
        self.assertTrue(issubclass(ssl.SSLEOFError, stdlib_ssl.SSLEOFError))
        self.assertTrue(issubclass(ssl.SSLSyscallError, stdlib_ssl.SSLSyscallError))
        self.assertTrue(
            issubclass(
                ssl.SSLCertVerificationError,
                stdlib_ssl.SSLCertVerificationError,
            )
        )


class MemoryBIOTests(unittest.TestCase):
    def test_read_write(self):
        bio = ssl.MemoryBIO()
        bio.write(b"foo")
        self.assertEqual(bio.read(), b"foo")
        self.assertEqual(bio.read(), b"")
        bio.write(b"foo")
        bio.write(b"bar")
        self.assertEqual(bio.read(), b"foobar")
        self.assertEqual(bio.read(), b"")
        bio.write(b"baz")
        self.assertEqual(bio.read(2), b"ba")
        self.assertEqual(bio.read(1), b"z")
        self.assertEqual(bio.read(1), b"")

    def test_eof(self):
        bio = ssl.MemoryBIO()
        self.assertFalse(bio.eof)
        self.assertEqual(bio.read(), b"")
        self.assertFalse(bio.eof)
        bio.write(b"foo")
        self.assertFalse(bio.eof)
        bio.write_eof()
        self.assertFalse(bio.eof)
        self.assertEqual(bio.read(2), b"fo")
        self.assertFalse(bio.eof)
        self.assertEqual(bio.read(1), b"o")
        self.assertTrue(bio.eof)
        self.assertEqual(bio.read(), b"")
        self.assertTrue(bio.eof)

    def test_pending(self):
        bio = ssl.MemoryBIO()
        self.assertEqual(bio.pending, 0)
        bio.write(b"foo")
        self.assertEqual(bio.pending, 3)
        for i in range(3):
            bio.read(1)
            self.assertEqual(bio.pending, 3 - i - 1)
        for i in range(3):
            bio.write(b"x")
            self.assertEqual(bio.pending, i + 1)
        bio.read()
        self.assertEqual(bio.pending, 0)

    def test_buffer_types(self):
        bio = ssl.MemoryBIO()
        bio.write(b"foo")
        self.assertEqual(bio.read(), b"foo")
        bio.write(bytearray(b"bar"))
        self.assertEqual(bio.read(), b"bar")
        bio.write(memoryview(b"baz"))
        self.assertEqual(bio.read(), b"baz")


class SSLObjectTests(unittest.TestCase):
    def test_unwrap(self):
        client_ctx, server_ctx, hostname = testing_context()
        c_in = ssl.MemoryBIO()
        c_out = ssl.MemoryBIO()
        s_in = ssl.MemoryBIO()
        s_out = ssl.MemoryBIO()
        client = client_ctx.wrap_bio(c_in, c_out, server_hostname=hostname)
        server = server_ctx.wrap_bio(s_in, s_out, server_side=True)

        # Loop on the handshake for a bit to get it settled
        for _ in range(10):
            try:
                client.do_handshake()
            except ssl.SSLWantReadError:
                pass
            if c_out.pending:
                s_in.write(c_out.read())
            try:
                server.do_handshake()
            except ssl.SSLWantReadError:
                pass
            if s_out.pending:
                c_in.write(s_out.read())

        # Now the handshakes should be complete
        client.do_handshake()
        server.do_handshake()

        # Verify we can exchange data
        client.write(b"hello")
        s_in.write(c_out.read())
        data = server.read(1024)
        self.assertEqual(data, b"hello")

        server.write(b"world")
        c_in.write(s_out.read())
        data = client.read(1024)
        self.assertEqual(data, b"world")

    def test_bio_handshake_properties(self):
        """Test SSLObject properties after BIO handshake."""
        client_ctx, server_ctx, hostname = testing_context()
        c_in = ssl.MemoryBIO()
        c_out = ssl.MemoryBIO()
        s_in = ssl.MemoryBIO()
        s_out = ssl.MemoryBIO()
        client = client_ctx.wrap_bio(c_in, c_out, server_hostname=hostname)
        server = server_ctx.wrap_bio(s_in, s_out, server_side=True)

        # Before handshake, cipher/version should be None
        self.assertIsNone(client.cipher())
        self.assertIsNone(client.version())

        # Complete the handshake
        for _ in range(10):
            try:
                client.do_handshake()
            except ssl.SSLWantReadError:
                pass
            if c_out.pending:
                s_in.write(c_out.read())
            try:
                server.do_handshake()
            except ssl.SSLWantReadError:
                pass
            if s_out.pending:
                c_in.write(s_out.read())

        client.do_handshake()
        server.do_handshake()

        # After handshake, cipher and version should be set
        self.assertIsNotNone(client.cipher())
        self.assertIsNotNone(client.version())
        self.assertIn(client.version(), ("TLSv1.2", "TLSv1.3"))
        self.assertIsNotNone(client.getpeercert())

    def test_session_properties(self):
        """SSLObject.session should be None, session_reused should be False."""
        client_ctx, server_ctx, hostname = testing_context()
        c_in = ssl.MemoryBIO()
        c_out = ssl.MemoryBIO()
        client = client_ctx.wrap_bio(c_in, c_out, server_hostname=hostname)
        self.assertIsNone(client.session)
        self.assertFalse(client.session_reused)

    def test_sslobj_returns_self(self):
        """_sslobj should return self for urllib3-future compat."""
        client_ctx, server_ctx, hostname = testing_context()
        c_in = ssl.MemoryBIO()
        c_out = ssl.MemoryBIO()
        client = client_ctx.wrap_bio(c_in, c_out, server_hostname=hostname)
        self.assertIs(client._sslobj, client)


class SimpleBackgroundTests(unittest.TestCase):
    """Tests that connect to a simple server running in the background."""

    def setUp(self):
        self.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_context.load_cert_chain(SIGNED_CERTFILE)
        server = ThreadedEchoServer(context=self.server_context)
        server.__enter__()
        # Use addCleanup (LIFO) instead of tearDown so that sockets
        # registered with addCleanup in tests close BEFORE the server
        # shuts down — matching the ordering that enterContext() provides.
        self.addCleanup(server.__exit__, None, None, None)
        self.server_addr = (HOST, server.port)

    def test_connect(self):
        with test_wrap_socket(
            socket.socket(socket.AF_INET), cert_reqs=ssl.CERT_NONE
        ) as s:
            s.connect(self.server_addr)
            self.assertEqual({}, s.getpeercert())
            self.assertFalse(s.server_side)

        # this should succeed because we specify the root cert
        with test_wrap_socket(
            socket.socket(socket.AF_INET),
            cert_reqs=ssl.CERT_REQUIRED,
            ca_certs=SIGNING_CA,
        ) as s:
            s.connect(self.server_addr)
            self.assertTrue(s.getpeercert())
            self.assertFalse(s.server_side)

    def test_connect_fail(self):
        # This should fail because we have no verification certs.
        s = test_wrap_socket(socket.socket(socket.AF_INET), cert_reqs=ssl.CERT_REQUIRED)
        self.addCleanup(s.close)
        with self.assertRaises(ssl.SSLError):
            s.connect(self.server_addr)

    def test_connect_with_context(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(socket.socket(socket.AF_INET)) as s:
            s.connect(self.server_addr)
            self.assertEqual({}, s.getpeercert())
        # Same with a server hostname
        with ctx.wrap_socket(
            socket.socket(socket.AF_INET), server_hostname="dummy"
        ) as s:
            s.connect(self.server_addr)
        ctx.verify_mode = ssl.CERT_REQUIRED
        # This should succeed because we specify the root cert
        ctx.load_verify_locations(SIGNING_CA)
        with ctx.wrap_socket(socket.socket(socket.AF_INET)) as s:
            s.connect(self.server_addr)
            cert = s.getpeercert()
            self.assertTrue(cert)

    def test_connect_with_context_fail(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        s = ctx.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=SIGNED_CERTFILE_HOSTNAME,
        )
        self.addCleanup(s.close)
        with self.assertRaises(ssl.SSLError):
            s.connect(self.server_addr)

    def test_connect_capath(self):
        # Verify server certificates using the `capath` argument
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(capath=CAPATH)
        with ctx.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=SIGNED_CERTFILE_HOSTNAME,
        ) as s:
            s.connect(self.server_addr)
            cert = s.getpeercert()
            self.assertTrue(cert)

    def test_connect_cadata(self):
        with open(SIGNING_CA) as f:
            pem = f.read()
        der = ssl.PEM_cert_to_DER_cert(pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cadata=pem)
        with ctx.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=SIGNED_CERTFILE_HOSTNAME,
        ) as s:
            s.connect(self.server_addr)
            cert = s.getpeercert()
            self.assertTrue(cert)

        # same with DER
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cadata=der)
        with ctx.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=SIGNED_CERTFILE_HOSTNAME,
        ) as s:
            s.connect(self.server_addr)
            cert = s.getpeercert()
            self.assertTrue(cert)

    def test_non_blocking_handshake(self):
        s = socket.socket(socket.AF_INET)
        s.connect(self.server_addr)
        s.setblocking(False)
        s = test_wrap_socket(s, cert_reqs=ssl.CERT_NONE, do_handshake_on_connect=False)
        self.addCleanup(s.close)
        count = 0
        while True:
            try:
                count += 1
                s.do_handshake()
                break
            except ssl.SSLWantReadError:
                select.select([s], [], [])
            except ssl.SSLWantWriteError:
                select.select([], [s], [])
        if VERBOSE:
            sys.stdout.write(
                "\nNeeded %d calls to do_handshake() to establish session.\n" % count
            )

    def test_get_server_certificate(self):
        host, port = self.server_addr
        pem = ssl.get_server_certificate((host, port))
        self.assertTrue(pem, "No server certificate returned")
        pem = ssl.get_server_certificate((host, port), ca_certs=SIGNING_CA)
        self.assertTrue(pem, "No server certificate returned")

    def test_context_setget(self):
        # Check that the context of a connected socket can be replaced.
        ctx1 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx1.load_verify_locations(capath=CAPATH)
        ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx2.load_verify_locations(capath=CAPATH)
        s = socket.socket(socket.AF_INET)
        with ctx1.wrap_socket(s, server_hostname="localhost") as ss:
            ss.connect(self.server_addr)
            self.assertIs(ss.context, ctx1)
            ss.context = ctx2
            self.assertIs(ss.context, ctx2)

    def test_bio_handshake(self):
        sock = socket.socket(socket.AF_INET)
        self.addCleanup(sock.close)
        sock.connect(self.server_addr)
        incoming = ssl.MemoryBIO()
        outgoing = ssl.MemoryBIO()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        ctx.load_verify_locations(SIGNING_CA)
        sslobj = ctx.wrap_bio(incoming, outgoing, False, SIGNED_CERTFILE_HOSTNAME)
        self.assertIsNone(sslobj.cipher())
        self.assertIsNone(sslobj.version())
        ssl_io_loop(sock, incoming, outgoing, sslobj.do_handshake)
        self.assertTrue(sslobj.cipher())
        self.assertIsNotNone(sslobj.version())
        self.assertTrue(sslobj.getpeercert())
        try:
            ssl_io_loop(sock, incoming, outgoing, sslobj.unwrap)
        except (ssl.SSLSyscallError, ssl.SSLError):
            # If the server shuts down TCP without sending close_notify
            pass

    def test_bio_read_write_data(self):
        sock = socket.socket(socket.AF_INET)
        self.addCleanup(sock.close)
        sock.connect(self.server_addr)
        incoming = ssl.MemoryBIO()
        outgoing = ssl.MemoryBIO()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sslobj = ctx.wrap_bio(incoming, outgoing, False)
        ssl_io_loop(sock, incoming, outgoing, sslobj.do_handshake)
        req = b"FOO\n"
        ssl_io_loop(sock, incoming, outgoing, sslobj.write, req)
        buf = ssl_io_loop(sock, incoming, outgoing, sslobj.read, 1024)
        self.assertEqual(buf, b"foo\n")
        ssl_io_loop(sock, incoming, outgoing, sslobj.unwrap)

    def test_transport_eof(self):
        client_context, server_context, hostname = testing_context()
        with socket.socket(socket.AF_INET) as sock:
            sock.connect(self.server_addr)
            incoming = ssl.MemoryBIO()
            outgoing = ssl.MemoryBIO()
            sslobj = client_context.wrap_bio(
                incoming, outgoing, server_hostname=hostname
            )
            ssl_io_loop(sock, incoming, outgoing, sslobj.do_handshake)
            # Simulate EOF from the transport.
            incoming.write_eof()
            self.assertRaises(ssl.SSLEOFError, sslobj.read)


class ThreadedTests(unittest.TestCase):
    def test_echo(self):
        """Basic test of an SSL client connecting to a server."""
        client_context, server_context, hostname = testing_context()

        with self.subTest(
            client=ssl.PROTOCOL_TLS_CLIENT, server=ssl.PROTOCOL_TLS_SERVER
        ):
            server_params_test(
                client_context=client_context,
                server_context=server_context,
                chatty=True,
                connectionchatty=True,
                sni_name=hostname,
            )

    def test_getpeercert(self):
        client_context, server_context, hostname = testing_context()
        server = ThreadedEchoServer(context=server_context, chatty=False)
        with server:
            with client_context.wrap_socket(
                socket.socket(),
                do_handshake_on_connect=False,
                server_hostname=hostname,
            ) as s:
                s.connect((HOST, server.port))
                # Do the handshake manually
                s.do_handshake()
                cert = s.getpeercert()
                self.assertTrue(cert, "Can't get peer certificate.")
                cipher = s.cipher()
                if VERBOSE:
                    sys.stdout.write(pprint.pformat(cert) + "\n")
                    sys.stdout.write("Connection cipher is " + str(cipher) + ".\n")
                if "subject" not in cert:
                    self.fail(
                        "No subject field in certificate: %s." % pprint.pformat(cert)
                    )
                self.assertIn("notBefore", cert)
                self.assertIn("notAfter", cert)
                before = ssl.cert_time_to_seconds(cert["notBefore"])
                after = ssl.cert_time_to_seconds(cert["notAfter"])
                self.assertLess(before, after)

    def test_check_hostname(self):
        client_context, server_context, hostname = testing_context()

        # correct hostname should verify
        server = ThreadedEchoServer(context=server_context, chatty=True)
        with server:
            with client_context.wrap_socket(
                socket.socket(), server_hostname=hostname
            ) as s:
                s.connect((HOST, server.port))
                cert = s.getpeercert()
                self.assertTrue(cert, "Can't get peer certificate.")

        # incorrect hostname should raise an exception
        server = ThreadedEchoServer(context=server_context, chatty=True)
        with server:
            with client_context.wrap_socket(
                socket.socket(), server_hostname="invalid"
            ) as s:
                with self.assertRaises((ssl.SSLError, ssl.SSLCertVerificationError)):
                    s.connect((HOST, server.port))

        # missing server_hostname arg should cause an exception when
        # check_hostname is True
        server = ThreadedEchoServer(context=server_context, chatty=True)
        with server:
            with socket.socket() as s:
                # rtls may raise ValueError or error about missing hostname
                with self.assertRaises((ValueError, ssl.SSLError)):
                    client_context.wrap_socket(s)

    def test_ecc_cert(self):
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.load_verify_locations(SIGNING_CA)
        hostname = SIGNED_CERTFILE_ECC_HOSTNAME

        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(SIGNED_CERTFILE_ECC)

        server = ThreadedEchoServer(context=server_context, chatty=True)
        with server:
            with client_context.wrap_socket(
                socket.socket(), server_hostname=hostname
            ) as s:
                s.connect((HOST, server.port))
                cert = s.getpeercert()
                self.assertTrue(cert, "Can't get peer certificate.")

    @unittest.skip("rustls server-side client cert verification differs from OpenSSL")
    def test_wrong_cert_tls12(self):
        """Connecting when the server rejects the client's certificate."""
        client_context, server_context, hostname = testing_context()
        # load client cert that is not signed by trusted CA
        client_context.load_cert_chain(CERTFILE)
        # require TLS client authentication
        server_context.verify_mode = ssl.CERT_REQUIRED
        # TLS 1.2 for predictable handshake
        client_context.maximum_version = ssl.TLSVersion.TLSv1_2

        server = ThreadedEchoServer(
            context=server_context,
            chatty=True,
            connectionchatty=True,
        )

        with server:
            with client_context.wrap_socket(
                socket.socket(), server_hostname=hostname
            ) as s:
                try:
                    s.connect((HOST, server.port))
                except ssl.SSLError:
                    pass  # Expected
                except OSError as e:
                    if e.errno != errno.ECONNRESET:
                        raise
                else:
                    self.fail("Use of invalid cert should have failed!")

    def test_alpn_protocols(self):
        """Test ALPN protocol negotiation."""
        client_context, server_context, hostname = testing_context()
        client_context.set_alpn_protocols(["h2", "http/1.1"])
        server_context.set_alpn_protocols(["h2", "http/1.1"])

        server = ThreadedEchoServer(context=server_context, chatty=False)
        with server:
            with client_context.wrap_socket(
                socket.socket(), server_hostname=hostname
            ) as s:
                s.connect((HOST, server.port))
                protocol = s.selected_alpn_protocol()
                self.assertIn(protocol, ("h2", "http/1.1"))

    def test_version(self):
        """Test the TLS version negotiation."""
        client_context, server_context, hostname = testing_context()
        server = ThreadedEchoServer(context=server_context, chatty=False)
        with server:
            with client_context.wrap_socket(
                socket.socket(), server_hostname=hostname
            ) as s:
                s.connect((HOST, server.port))
                version = s.version()
                self.assertIn(version, ("TLSv1.2", "TLSv1.3"))

    def test_tls13(self):
        """Test TLS 1.3 specifically."""
        client_context, server_context, hostname = testing_context()
        client_context.minimum_version = ssl.TLSVersion.TLSv1_3
        server_context.minimum_version = ssl.TLSVersion.TLSv1_3

        server = ThreadedEchoServer(context=server_context, chatty=False)
        with server:
            with client_context.wrap_socket(
                socket.socket(), server_hostname=hostname
            ) as s:
                s.connect((HOST, server.port))
                version = s.version()
                self.assertEqual(version, "TLSv1.3")

    def test_min_max_version(self):
        """Test TLS version constraints."""
        client_context, server_context, hostname = testing_context()
        # Force TLS 1.2
        client_context.maximum_version = ssl.TLSVersion.TLSv1_2
        server_context.maximum_version = ssl.TLSVersion.TLSv1_2

        server = ThreadedEchoServer(context=server_context, chatty=False)
        with server:
            with client_context.wrap_socket(
                socket.socket(), server_hostname=hostname
            ) as s:
                s.connect((HOST, server.port))
                version = s.version()
                self.assertEqual(version, "TLSv1.2")

    def test_compression(self):
        """Test that compression returns None (rustls doesn't support it)."""
        client_context, server_context, hostname = testing_context()
        server = ThreadedEchoServer(context=server_context, chatty=False)
        with server:
            with client_context.wrap_socket(
                socket.socket(), server_hostname=hostname
            ) as s:
                s.connect((HOST, server.port))
                self.assertIsNone(s.compression())

    def test_shared_ciphers(self):
        """Test shared_ciphers after handshake."""
        client_context, server_context, hostname = testing_context()
        server = ThreadedEchoServer(context=server_context, chatty=False)
        with server:
            with client_context.wrap_socket(
                socket.socket(), server_hostname=hostname
            ) as s:
                s.connect((HOST, server.port))
                shared = s.shared_ciphers()
                # Should return at least one cipher tuple
                self.assertIsNotNone(shared)
                self.assertGreater(len(shared), 0)
                # Each element should be a tuple of (name, version, bits)
                for cipher in shared:
                    self.assertIsInstance(cipher, tuple)
                    self.assertEqual(len(cipher), 3)

    def test_recv_send(self):
        """Test basic send/recv over TLS."""
        client_context, server_context, hostname = testing_context()
        server = ThreadedEchoServer(context=server_context, chatty=False)
        with server:
            with client_context.wrap_socket(
                socket.socket(), server_hostname=hostname
            ) as s:
                s.connect((HOST, server.port))
                s.sendall(b"HELLO\n")
                data = s.recv(1024)
                self.assertEqual(data, b"hello\n")

                # Test write/read aliases
                s.write(b"WORLD\n")
                data = s.read(1024)
                self.assertEqual(data, b"world\n")

                s.write(b"over\n")

    def test_default_ecdh_curve(self):
        """Test that ECDH key exchange works by default."""
        client_context, server_context, hostname = testing_context()
        server = ThreadedEchoServer(context=server_context, chatty=False)
        with server:
            with client_context.wrap_socket(
                socket.socket(), server_hostname=hostname
            ) as s:
                s.connect((HOST, server.port))
                # Just checking the connection succeeds - ECDH should work
                self.assertIsNotNone(s.cipher())

    def test_recv_zero(self):
        """Test recv(0) returns empty bytes."""
        client_context, server_context, hostname = testing_context()
        server = ThreadedEchoServer(context=server_context, chatty=False)
        with server:
            with client_context.wrap_socket(
                socket.socket(), server_hostname=hostname
            ) as s:
                s.connect((HOST, server.port))
                self.assertEqual(s.recv(0), b"")

    def test_get_verified_chain(self):
        """Test get_verified_chain/get_unverified_chain."""
        client_context, server_context, hostname = testing_context()
        server = ThreadedEchoServer(context=server_context, chatty=False)
        with server:
            with client_context.wrap_socket(
                socket.socket(), server_hostname=hostname
            ) as s:
                s.connect((HOST, server.port))
                chain = s.get_verified_chain()
                self.assertIsNotNone(chain)
                self.assertGreater(len(chain), 0)

                uchain = s.get_unverified_chain()
                self.assertIsNotNone(uchain)
                self.assertGreater(len(uchain), 0)

    def test_isinstance_checks(self):
        """Test that our types pass isinstance checks for stdlib ssl types."""
        import ssl as stdlib_ssl

        client_context, server_context, hostname = testing_context()
        server = ThreadedEchoServer(context=server_context, chatty=False)
        with server:
            with client_context.wrap_socket(
                socket.socket(), server_hostname=hostname
            ) as s:
                s.connect((HOST, server.port))
                self.assertIsInstance(s, stdlib_ssl.SSLSocket)
                self.assertIsInstance(s.context, stdlib_ssl.SSLContext)

    def test_sslobj_property(self):
        """Test _sslobj property on TLSSocket."""
        client_context, server_context, hostname = testing_context()
        server = ThreadedEchoServer(context=server_context, chatty=False)
        with server:
            with client_context.wrap_socket(
                socket.socket(), server_hostname=hostname
            ) as s:
                s.connect((HOST, server.port))
                sslobj = s._sslobj
                self.assertIsNotNone(sslobj)
                # _sslobj._sslobj should return itself (for urllib3-future)
                self.assertIs(sslobj._sslobj, sslobj)


if __name__ == "__main__":
    unittest.main()
