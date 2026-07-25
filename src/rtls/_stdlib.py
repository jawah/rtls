from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import ssl
else:
    try:
        import ssl
    except ModuleNotFoundError as error:
        if error.name != "_ssl":
            raise

        class _SSLContext:
            def __new__(cls, *args: object, **kwargs: object) -> _SSLContext:
                return object.__new__(cls)

        class _SSLSocket:
            pass

        class _SSLError(OSError):
            pass

        class _SSLZeroReturnError(OSError):
            pass

        class _SSLWantReadError(OSError):
            pass

        class _SSLWantWriteError(OSError):
            pass

        class _SSLSyscallError(OSError):
            pass

        class _SSLEOFError(OSError):
            pass

        class _SSLCertVerificationError(OSError):
            pass

        ssl = SimpleNamespace(
            PROTOCOL_TLS_CLIENT=16,
            SSLContext=_SSLContext,
            SSLSocket=_SSLSocket,
            SSLError=_SSLError,
            SSLZeroReturnError=_SSLZeroReturnError,
            SSLWantReadError=_SSLWantReadError,
            SSLWantWriteError=_SSLWantWriteError,
            SSLSyscallError=_SSLSyscallError,
            SSLEOFError=_SSLEOFError,
            SSLCertVerificationError=_SSLCertVerificationError,
        )
