from __future__ import annotations

import threading


class MemoryBIO:
    """In-memory BIO that buffers bytes, compatible with ssl.MemoryBIO.

    Used by TLSObject (via wrap_bio) to replace network I/O with
    memory-based byte shuffling, exactly like asyncio's SSLProtocol does
    with ssl.MemoryBIO.
    """

    __slots__ = ("_buf", "_eof", "_lock")

    def __init__(self) -> None:
        self._buf = bytearray()
        self._eof = False
        self._lock = threading.Lock()

    def read(self, n: int = -1) -> bytes:
        """Read up to *n* bytes from the BIO.

        If *n* is -1 or omitted, read all available data.
        Returns b"" if no data is available (non-blocking).
        """
        with self._lock:
            if n < 0 or n >= len(self._buf):
                data = bytes(self._buf)
                self._buf.clear()
                return data
            data = bytes(self._buf[:n])
            del self._buf[:n]
            return data

    def write(self, data: bytes) -> int:
        """Write *data* into the BIO. Returns number of bytes written.

        Raises ``ssl.SSLError`` if write_eof() has been called.
        """
        if self._eof:
            from ._exceptions import SSLError

            raise SSLError("cannot write to a BIO after write_eof()")
        if not data:
            return 0
        with self._lock:
            self._buf.extend(data)
            return len(data)

    def write_eof(self) -> None:
        """Signal that no more data will be written.

        After this, further write() calls will raise SSLError.
        """
        self._eof = True

    @property
    def pending(self) -> int:
        """Number of bytes currently in the buffer waiting to be read."""
        return len(self._buf)

    @property
    def eof(self) -> bool:
        """True if write_eof() was called AND all buffered data has been read."""
        return self._eof and len(self._buf) == 0

    def __repr__(self) -> str:
        return f"<MemoryBIO pending={self.pending} eof_written={self._eof}>"
