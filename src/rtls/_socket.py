from __future__ import annotations

import errno
import socket
import ssl as _stdlib_ssl
from typing import TYPE_CHECKING, Any

from ._bio import MemoryBIO
from ._certificate import TLSCertificate
from ._constants import SSL_ERROR_WANT_READ
from ._exceptions import (
    SSLEOFError,
    SSLError,
    SSLWantReadError,
    SSLWantWriteError,
    SSLZeroReturnError,
)
from ._object import TLSObject

if TYPE_CHECKING:
    from ._context import TLSContext


_DEFAULT_BUFFER_SIZE = 16384


class TLSSocket(_stdlib_ssl.SSLSocket):
    """TLS-wrapped socket, equivalent of ``ssl.SSLSocket``.

    Inherits from ``ssl.SSLSocket`` so it passes isinstance checks
    (both ``isinstance(s, socket.socket)`` and ``isinstance(s, ssl.SSLSocket)``).
    Intercepts send/recv to route through the rustls TLS state machine.
    """

    def __new__(cls, *args: Any, **kwargs: Any) -> TLSSocket:
        # Use socket.socket.__new__ to allocate, skipping ssl.SSLSocket
        # which doesn't have its own __new__ anyway.
        return socket.socket.__new__(cls)

    def __init__(
        self,
        sock: socket.socket,
        context: TLSContext,
        server_side: bool = False,
        server_hostname: str | None = None,
        do_handshake_on_connect: bool = True,
        suppress_ragged_eofs: bool = True,
    ) -> None:
        # NOTE: We intentionally do NOT call ssl.SSLSocket.__init__() because
        # it raises TypeError (SSLSocket has no public constructor). All real
        # initialization goes through socket.socket.__init__() instead.
        self._rtls_context = context
        self._server_side = server_side
        self._server_hostname = server_hostname
        self._do_handshake_on_connect = do_handshake_on_connect
        self._suppress_ragged_eofs = suppress_ragged_eofs
        self._connected = False
        self._closed = False

        # Take over the underlying socket's fd.
        # Save socket properties before detaching
        _family = sock.family
        _type = sock.type
        _proto = sock.proto
        _timeout = sock.gettimeout()

        # First, close the fd that socket.__new__ may have created.
        try:
            # If __new__ allocated a real fd, close it
            if self.fileno() >= 0:
                socket.socket.close(self)  # Defensive: should not happen, ever.
        except Exception:  # Defensive: just in case(...)
            pass

        fd = sock.detach()
        # Re-init with the real fd
        socket.socket.__init__(
            self,
            family=_family,
            type=_type,
            proto=_proto,
            fileno=fd,
        )

        # Restore the timeout/blocking mode from the original socket
        if _timeout is None:
            self.setblocking(True)
        else:
            self.settimeout(_timeout)

        # Create the MemoryBIO pair and TLSObject
        self._incoming = MemoryBIO()
        self._outgoing = MemoryBIO()

        self._sslobj_internal: TLSObject | None = None

        # If the socket was already connected, do handshake now
        try:
            self.getpeername()
            self._connected = True
        except OSError:
            self._connected = False

        if self._connected:
            self._create_sslobj()
            if self._do_handshake_on_connect:
                try:
                    self.do_handshake()
                except BaseException:
                    self.close()
                    raise

    def _create_sslobj(self) -> None:
        """Create the internal TLSObject."""
        self._sslobj_internal = TLSObject(
            context=self._rtls_context,
            incoming=self._incoming,
            outgoing=self._outgoing,
            server_side=self._server_side,
            server_hostname=self._server_hostname,
        )

    def connect(self, addr: Any) -> None:
        """Connect and perform TLS handshake."""
        if self._server_side:
            raise ValueError("can't connect in server-side mode")
        if self._connected:
            raise ValueError("attempt to connect already-connected SSLSocket!")
        socket.socket.connect(self, addr)
        self._connected = True
        self._create_sslobj()
        if self._do_handshake_on_connect:
            self.do_handshake()

    def connect_ex(self, addr: Any) -> int:
        """Connect and perform TLS handshake, returning error code."""
        if self._server_side:
            raise ValueError("can't connect in server-side mode")
        if self._connected:
            raise ValueError("attempt to connect already-connected SSLSocket!")
        rc = socket.socket.connect_ex(self, addr)
        if rc == 0:
            self._connected = True
            self._create_sslobj()
            if self._do_handshake_on_connect:
                self.do_handshake()
        return rc

    def do_handshake(self) -> None:  # type: ignore[override]
        """Perform the TLS handshake, blocking until complete."""
        if self._sslobj_internal is None:
            self._create_sslobj()

        self._flush_outgoing()

        timeout = self.gettimeout()
        self._do_handshake_loop(timeout)

    def _do_handshake_loop(self, timeout: float | None) -> None:
        """Inner handshake loop - drives TLSObject.do_handshake()."""
        while True:
            try:
                self._sslobj_internal.do_handshake()
                break
            except SSLWantReadError:
                # Flush any outgoing data (handshake messages)
                self._flush_outgoing()
                # Read more ciphertext from the network
                self._pull_incoming(timeout)
            except SSLWantWriteError:
                self._flush_outgoing()

    def send(self, data: bytes, flags: int = 0) -> int:  # type: ignore[override]
        """Encrypt and send data."""
        if not data:
            return 0
        if self._sslobj_internal is None:
            raise SSLError("SSL handshake not done")

        n = self._sslobj_internal.write(data)
        self._flush_outgoing()
        return n

    def sendall(self, data: bytes, flags: int = 0) -> None:  # type: ignore[override]
        """Send all data, blocking until complete."""
        view = memoryview(data)
        total = len(view)
        sent = 0
        while sent < total:
            n = self.send(bytes(view[sent:]))
            sent += n

    def recv(self, buflen: int = _DEFAULT_BUFFER_SIZE, flags: int = 0) -> bytes:
        """Receive decrypted data."""
        if buflen == 0:
            return b""
        if self._sslobj_internal is None:
            raise SSLError("SSL handshake not done")

        timeout = self.gettimeout()

        while True:
            try:
                return self._sslobj_internal.read(buflen)  # type: ignore[return-value]
            except SSLWantReadError:
                self._flush_outgoing()
                try:
                    self._pull_incoming(timeout)
                except SSLEOFError:
                    if self._suppress_ragged_eofs:
                        return b""
                    raise
            except SSLZeroReturnError:
                return b""
            except SSLEOFError:
                if self._suppress_ragged_eofs:
                    return b""
                raise

    def recv_into(self, buffer: bytearray, nbytes: int = 0, flags: int = 0) -> int:  # type: ignore[override]
        """Receive decrypted data into a buffer."""
        if nbytes == 0:
            nbytes = len(buffer)
        data = self.recv(nbytes, flags)
        n = len(data)
        buffer[:n] = data
        return n

    def read(  # type: ignore[override]
        self, n: int = _DEFAULT_BUFFER_SIZE, buffer: bytearray | None = None
    ) -> bytes | int:
        """Read decrypted data. Alias matching ssl.SSLSocket.read()."""
        if buffer is not None:
            data = self.recv(n)
            nbytes = len(data)
            buffer[:nbytes] = data
            return nbytes
        return self.recv(n)

    def write(self, data: bytes) -> int:  # type: ignore[override]
        """Write data to be encrypted. Alias matching ssl.SSLSocket.write()."""
        return self.send(data)

    def _flush_outgoing(self) -> None:
        """Send any pending ciphertext from the outgoing BIO to the network."""
        data = self._outgoing.read()
        if data:
            # Use explicit unbound method call to bypass our TLS interception
            # and avoid potential MRO issues with super() after fd swap.
            total = 0
            while total < len(data):
                try:
                    n = socket.socket.send(self, data[total:])
                    if n == 0:
                        raise SSLError("connection closed during TLS write")
                    total += n
                except BlockingIOError:
                    # For non-blocking sockets, retry
                    continue

    def _pull_incoming(self, timeout: float | None = None) -> None:
        """Read ciphertext from the network into the incoming BIO."""
        try:
            data = socket.socket.recv(self, _DEFAULT_BUFFER_SIZE)
        except (BlockingIOError, InterruptedError):
            raise SSLWantReadError(
                SSL_ERROR_WANT_READ, "The read operation did not complete"
            )
        except (socket.timeout, TimeoutError):
            raise  # Let timeout propagate — don't convert to SSLWantReadError
        except OSError as e:
            if e.errno == errno.EAGAIN or e.errno == errno.EWOULDBLOCK:
                raise SSLWantReadError(
                    SSL_ERROR_WANT_READ, "The read operation did not complete"
                )
            raise

        if not data:
            raise SSLEOFError("EOF on underlying transport")

        self._incoming.write(data)

    def getpeercert(self, binary_form: bool = False) -> dict | bytes | None:  # type: ignore[override]
        """Return the peer's certificate."""
        if self._sslobj_internal is None:
            return None
        return self._sslobj_internal.getpeercert(binary_form)

    def cipher(self) -> tuple[str, str, int] | None:
        """Return cipher info tuple."""
        if self._sslobj_internal is None:
            return None
        return self._sslobj_internal.cipher()

    def shared_ciphers(self) -> list[tuple[str, str, int]] | None:
        if self._sslobj_internal is None:
            return None
        return self._sslobj_internal.shared_ciphers()

    def version(self) -> str | None:
        """Return the negotiated TLS version string."""
        if self._sslobj_internal is None:
            return None
        return self._sslobj_internal.version()

    def selected_alpn_protocol(self) -> str | None:
        if self._sslobj_internal is None:
            return None
        return self._sslobj_internal.selected_alpn_protocol()

    def selected_npn_protocol(self) -> None:
        return None

    def compression(self) -> None:
        return None

    def pending(self) -> int:
        if self._sslobj_internal is None:
            return 0
        return self._sslobj_internal.pending()

    def get_channel_binding(self, cb_type: str = "tls-unique") -> bytes | None:
        return None

    def unwrap(self) -> socket.socket:
        """Shut down the TLS layer and return the underlying socket.

        Returns a plain ``socket.socket`` (with the same fd) that can
        be used for unencrypted communication.
        """
        if self._sslobj_internal is not None:
            self._sslobj_internal.unwrap()
            self._flush_outgoing()
            self._sslobj_internal = None

        # Create a new plain socket from our fd (detach so we don't close it)
        fd = self.detach()
        return socket.socket(fileno=fd)

    def shutdown(self, how: int) -> None:
        """Shut down one or both halves of the connection."""
        if self._sslobj_internal is not None:
            self._sslobj_internal.unwrap()
            self._flush_outgoing()
        socket.socket.shutdown(self, how)

    def close(self) -> None:
        """Close the TLS connection and underlying socket.

        When ``makefile()`` references are still open (``_io_refs > 0``),
        this only marks the socket as closed — the TLS state and fd stay
        alive so buffered I/O streams (and direct send/recv) keep working.
        The actual cleanup is deferred to ``_real_close()`` which runs once
        all makefile references have been drained.
        """
        self._closed = True
        if self._io_refs <= 0:  # type: ignore[attr-defined]
            self._real_close()

    def _real_close(self) -> None:
        """Tear down TLS state and close the underlying fd.

        Called by the inherited ``socket.socket`` machinery once
        ``_io_refs`` drops to zero (all makefile wrappers are closed).
        """
        if self._sslobj_internal is not None:
            try:
                self._sslobj_internal.unwrap()
                self._flush_outgoing()
            except Exception:
                pass
            self._sslobj_internal = None
        socket.socket._real_close(self)  # type: ignore[attr-defined]

    @property  # type: ignore[override]
    def context(self) -> TLSContext:
        return self._rtls_context

    @context.setter
    def context(self, ctx: TLSContext) -> None:
        self._rtls_context = ctx

    @property
    def server_side(self) -> bool:  # type: ignore[override]
        return self._server_side

    @property
    def server_hostname(self) -> str | None:  # type: ignore[override]
        return self._server_hostname

    # urllib3-future compatibility
    @property
    def _sslobj(self) -> TLSObject | None:
        """Return the underlying TLSObject for urllib3-future compatibility."""
        return self._sslobj_internal

    @_sslobj.setter
    def _sslobj(self, value: Any) -> None:
        """Allow setting _sslobj (ssl.SSLSocket._real_close sets it to None)."""
        self._sslobj_internal = value

    @property
    def sslobj(self) -> TLSObject | None:
        return self._sslobj_internal

    def get_verified_chain(self) -> list[TLSCertificate] | None:
        if self._sslobj_internal is None:
            return None
        return self._sslobj_internal.get_verified_chain()

    def get_unverified_chain(self) -> list[TLSCertificate] | None:
        if self._sslobj_internal is None:
            return None
        return self._sslobj_internal.get_unverified_chain()

    @property
    def ech_status(self) -> str:
        """Return the ECH status string. See TLSObject.ech_status."""
        if self._sslobj_internal is None:
            return "not_offered"
        return self._sslobj_internal.ech_status

    def recvfrom(self, *args: Any, **kwargs: Any) -> Any:
        raise ValueError("recvfrom not allowed on TLS sockets")

    def recvfrom_into(self, *args: Any, **kwargs: Any) -> Any:
        raise ValueError("recvfrom_into not allowed on TLS sockets")

    def sendto(self, *args: Any, **kwargs: Any) -> Any:
        raise ValueError("sendto not allowed on TLS sockets")

    def recvmsg(self, *args: Any, **kwargs: Any) -> Any:
        raise ValueError("recvmsg not allowed on TLS sockets")

    def recvmsg_into(self, *args: Any, **kwargs: Any) -> Any:
        raise ValueError("recvmsg_into not allowed on TLS sockets")

    def sendmsg(self, *args: Any, **kwargs: Any) -> Any:
        raise ValueError("sendmsg not allowed on TLS sockets")

    def __enter__(self) -> TLSSocket:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        try:
            peer = self.getpeername()
        except Exception:
            peer = None
        return (
            f"<TLSSocket"
            f" server_side={self._server_side}"
            f" server_hostname={self._server_hostname!r}"
            f" peer={peer}>"
        )
