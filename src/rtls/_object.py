from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ._bio import MemoryBIO
from ._certificate import TLSCertificate
from ._constants import (
    CERT_NONE,
    SSL_ERROR_WANT_READ,
)
from ._exceptions import (
    SSLEOFError,
    SSLError,
    SSLWantReadError,
    SSLZeroReturnError,
)

if TYPE_CHECKING:
    from ._context import TLSContext


# Map protocol version u16 → TLSVersion string for cipher() tuple
_VERSION_MAP = {
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
}

# Map IANA suite debug names to OpenSSL-style names for cipher() tuple
_SUITE_TO_OPENSSL = {
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "ECDHE-RSA-AES128-GCM-SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": "ECDHE-RSA-AES256-GCM-SHA384",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": "ECDHE-RSA-CHACHA20-POLY1305",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": "ECDHE-ECDSA-AES128-GCM-SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": "ECDHE-ECDSA-AES256-GCM-SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": "ECDHE-ECDSA-CHACHA20-POLY1305",
    "TLS13_AES_128_GCM_SHA256": "TLS_AES_128_GCM_SHA256",
    "TLS13_AES_256_GCM_SHA384": "TLS_AES_256_GCM_SHA384",
    "TLS13_CHACHA20_POLY1305_SHA256": "TLS_CHACHA20_POLY1305_SHA256",
}


class TLSObject:
    """Sans-I/O TLS object — equivalent of ``ssl.SSLObject``.

    Created by ``TLSContext.wrap_bio(incoming, outgoing, ...)``.
    Asyncio's ``SSLProtocol`` drives this by:
      1. Writing ciphertext into ``incoming`` BIO
      2. Calling ``do_handshake()`` / ``read()`` / ``write()``
      3. Reading ciphertext from ``outgoing`` BIO to send on the wire
    """

    def __init__(
        self,
        context: TLSContext,
        incoming: MemoryBIO,
        outgoing: MemoryBIO,
        server_side: bool = False,
        server_hostname: str | None = None,
    ) -> None:
        self._context = context
        self._incoming = incoming
        self._outgoing = outgoing
        self._server_side = server_side
        self._server_hostname = server_hostname
        self._conn: Any = None  # RustlsClientConnection or RustlsServerConnection
        self._handshake_done = False
        self._shutdown = False

        # Build the Rust connection via the context's config builder
        self._init_connection()

    def _init_connection(self) -> None:
        """Create the Rust TLS connection state machine."""
        builder = self._context._get_builder()

        if self._server_side:
            self._conn = builder.build_server_connection()
        else:
            hostname = self._server_hostname or "localhost"
            self._conn = builder.build_client_connection(hostname)

        # After building client connection, the state machine immediately
        # has a ClientHello to send — flush it to the outgoing BIO
        self._flush_outgoing()

    def _flush_outgoing(self) -> None:
        """Move any ciphertext from the Rust state machine to the outgoing BIO."""
        if self._conn is None:
            return
        while self._conn.wants_write():
            data = self._conn.write_tls()
            if data:
                self._outgoing.write(data)
            else:
                break

    def _pump_incoming(self) -> None:
        """Move ciphertext from the incoming BIO into the Rust state machine.

        If rustls's internal buffer is full (``read_tls`` raises "message
        buffer full"), we stop feeding and put the unconsumed ciphertext
        back into the BIO so it will be picked up on the next call after
        the caller drains plaintext via ``process_new_packets`` +
        ``read_plaintext``.
        """
        data = self._incoming.read()
        if data:
            # read_tls may not consume all data at once (it reads one TLS
            # record at a time), so we must loop until everything is fed.
            view = memoryview(data)
            total = len(view)
            offset = 0
            while offset < total:
                try:
                    consumed = self._conn.read_tls(bytes(view[offset:]))
                except SSLError as e:  # Defensive:
                    # Rustls buffer full — stop feeding, stash the rest
                    if "buffer full" in str(e):
                        self._incoming.write(bytes(view[offset:]))
                        return
                    raise
                if consumed == 0:
                    break
                offset += consumed

    def do_handshake(self) -> None:
        """Perform the TLS handshake.

        Raises SSLWantReadError if more data is needed from the network.
        asyncio catches this and waits for more data.
        """
        if self._handshake_done:
            return

        # Feed any available incoming ciphertext to rustls
        self._pump_incoming()

        # Process the TLS records
        try:
            self._conn.process_new_packets()
        except SSLError:
            # Flush any alert that rustls wants to send
            self._flush_outgoing()
            raise

        # Flush outgoing ciphertext (handshake messages)
        self._flush_outgoing()

        if self._conn.is_handshaking():
            raise SSLWantReadError(
                SSL_ERROR_WANT_READ, "The handshake operation did not complete"
            )

        self._handshake_done = True

    def read(self, n: int = -1, buffer: bytearray | None = None) -> bytes | int:
        """Read decrypted data from the TLS connection.

        Returns bytes, or if *buffer* is given, reads into it and returns count.
        Raises SSLWantReadError if no data is available yet.

        Uses the fused ``decrypt_incoming`` Rust method that performs
        read_tls → process_new_packets → read_plaintext in a single
        Python→Rust call, handling buffer-full looping internally.
        """
        if self._shutdown:
            raise SSLZeroReturnError("TLS/SSL connection has been closed")

        max_len = n if n > 0 else 16384

        # Read all available ciphertext from the BIO
        ciphertext = self._incoming.read()

        if ciphertext:
            # Fast path: one Rust call does everything
            plaintext, unconsumed = self._conn.decrypt_incoming(ciphertext, max_len)

            # Stash any unconsumed ciphertext back in the BIO
            if unconsumed:
                self._incoming.write(unconsumed)

            # Flush any outgoing data (post-handshake messages, key updates)
            self._flush_outgoing()

            if plaintext:
                if buffer is not None:
                    nbytes = min(len(plaintext), len(buffer))
                    buffer[:nbytes] = plaintext[:nbytes]
                    return nbytes
                return plaintext

        # No ciphertext available (or it produced no plaintext).
        # Try draining any plaintext already buffered in rustls from
        # a previous decrypt_incoming call that hit max_len.
        data = self._conn.read_plaintext(max_len)
        if data:
            if buffer is not None:
                nbytes = min(len(data), len(buffer))
                buffer[:nbytes] = data[:nbytes]
                return nbytes
            return data

        # Truly no data available
        if self._incoming.eof:
            raise SSLEOFError("EOF occurred in violation of protocol")
        raise SSLWantReadError(
            SSL_ERROR_WANT_READ, "The read operation did not complete"
        )

    def write(self, data: bytes | bytearray | memoryview) -> int:
        """Write plaintext data to be encrypted and sent.

        Returns number of bytes written. The encrypted ciphertext is
        placed in the outgoing BIO for the transport to send.
        """
        if self._shutdown:
            raise SSLZeroReturnError("TLS/SSL connection has been closed")

        if not self._handshake_done:
            raise SSLError("handshake not done yet")

        # Ensure data is bytes for the Rust side
        if isinstance(data, (bytearray, memoryview)):
            data = bytes(data)

        n = self._conn.write_plaintext(data)

        # Flush the resulting ciphertext to the outgoing BIO
        self._flush_outgoing()

        return n

    def unwrap(self) -> None:
        """Perform orderly TLS shutdown (send close_notify).

        Returns None. The close_notify alert is placed in the outgoing BIO.
        """
        if self._conn is not None and not self._shutdown:
            self._conn.send_close_notify()
            self._flush_outgoing()
            self._shutdown = True

    def getpeercert(self, binary_form: bool = False) -> dict | bytes | None:
        """Return the peer's certificate.

        If ``binary_form`` is True, return the DER-encoded bytes.
        Otherwise, return a dict matching CPython's getpeercert() format.
        Returns None if no certificate was presented.

        CPython behavior: when verify_mode is CERT_NONE and binary_form
        is False, returns {} (empty dict) after handshake — the cert is
        not validated so its contents are not exposed.
        """
        # CPython: CERT_NONE + dict form → always {} after handshake
        if not binary_form and self._handshake_done:
            if self._context.verify_mode == CERT_NONE:
                return {}

        certs = self._conn.peer_certificates()
        if not certs:
            return None

        der_bytes = bytes(certs[0])

        if binary_form:
            return der_bytes

        try:
            from ._rustls import parse_certificate_dict

            return parse_certificate_dict(der_bytes)
        except ImportError:
            return {}

    def cipher(self) -> tuple[str, str, int] | None:
        """Return a 3-tuple (cipher_name, tls_version, secret_bits) or None."""
        suite_name = self._conn.negotiated_cipher_suite()
        if suite_name is None:
            return None

        version_num = self._conn.protocol_version()
        version_str = (
            _VERSION_MAP.get(version_num, "unknown") if version_num else "unknown"
        )

        # Map IANA name to OpenSSL name
        openssl_name = _SUITE_TO_OPENSSL.get(suite_name, suite_name)

        bits = self._conn.negotiated_cipher_suite_bits() or 0

        return (openssl_name, version_str, bits)

    def shared_ciphers(self) -> list[tuple[str, str, int]] | None:
        """Return the list of ciphers shared with the peer.

        We return the single negotiated cipher (rustls doesn't expose
        the full intersection list).
        """
        c = self.cipher()
        if c is not None:
            return [c]
        return None

    def version(self) -> str | None:
        """Return the negotiated TLS version string, e.g. 'TLSv1.3'."""
        v = self._conn.protocol_version()
        if v is None:
            return None
        return _VERSION_MAP.get(v, None)

    def selected_alpn_protocol(self) -> str | None:
        """Return the selected ALPN protocol as a string, or None."""
        proto = self._conn.alpn_protocol()
        if proto is None:
            return None
        return proto.decode("ascii", errors="replace")

    def selected_npn_protocol(self) -> None:
        """NPN is not supported by rustls. Always returns None."""
        return None

    def compression(self) -> None:
        """rustls does not support TLS compression. Always returns None."""
        return None

    def pending(self) -> int:
        """Return the number of already decrypted bytes available for read."""
        # Try to read 0 bytes to check; rustls doesn't expose this directly.
        # Return incoming BIO pending as approximation.
        return self._incoming.pending

    def get_channel_binding(self, cb_type: str = "tls-unique") -> bytes | None:
        """Return channel binding data. Not yet implemented."""
        return None

    def getpeername(self) -> tuple | None:
        """SSLObject doesn't have a socket, so no peername."""
        return None

    @property
    def context(self) -> TLSContext:
        """The TLSContext that created this object."""
        return self._context

    @context.setter
    def context(self, ctx: TLSContext) -> None:
        self._context = ctx

    @property
    def server_side(self) -> bool:
        return self._server_side

    @property
    def server_hostname(self) -> str | None:
        return self._server_hostname

    @property
    def _sslobj(self) -> TLSObject:
        """Return self so that ``sslobj._sslobj.get_verified_chain()`` works.

        urllib3-future's async backend does:
            ssl_object = writer.get_extra_info("ssl_object")  → TLSObject
            chain = ssl_object._sslobj.get_verified_chain()

        Since we ARE the ssl object AND the _sslobj, returning self makes
        the chain traversal work.
        """
        return self

    def get_verified_chain(self) -> list[TLSCertificate] | None:
        """Return the verified peer certificate chain as TLSCertificate list.

        Returns None if no certificates are available.
        """
        certs = self._conn.peer_certificates()
        if not certs:
            return None  # Defensive:
        return [TLSCertificate(bytes(der)) for der in certs]

    def get_unverified_chain(self) -> list[TLSCertificate] | None:
        """Return the unverified peer certificate chain.

        Same as get_verified_chain() for our purposes — rustls either
        verified it or we used CERT_NONE.
        """
        return self.get_verified_chain()

    @property
    def owner(self) -> Any:
        """SSLObject owner (transport). Not tracked by rtls."""
        return None

    @property
    def session(self) -> None:
        """TLS session for resumption. Not yet implemented."""
        return None

    @property
    def session_reused(self) -> bool:
        """Whether the TLS session was reused. Always False for now."""
        return False

    @property
    def ech_status(self) -> str:
        """Return the ECH (Encrypted Client Hello) status string.

        Possible values:
          - "not_offered": ECH was not configured
          - "grease": GREASE ECH was sent (anti-ossification)
          - "offered": ECH was offered but handshake not complete
          - "accepted": ECH was accepted by the server
          - "rejected": ECH was rejected by the server
        """
        if self._conn is None:
            return "not_offered"
        try:
            return self._conn.ech_status()
        except AttributeError:
            # Server connections don't have ech_status
            return "not_offered"
