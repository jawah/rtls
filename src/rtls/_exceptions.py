from __future__ import annotations

import ssl as _ssl
from typing import Any


class SSLError(_ssl.SSLError):
    """Base SSL error, analogous to ssl.SSLError."""

    library: str | None
    reason: str | None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.library = kwargs.get("library") or "rtls"
        self.reason = kwargs.get("reason") or (str(args[0]) if args else "unknown")


class SSLZeroReturnError(SSLError, _ssl.SSLZeroReturnError):
    """SSL connection has been closed cleanly."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class SSLWantReadError(SSLError, _ssl.SSLWantReadError):
    """Non-blocking SSL socket needs to read more data."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class SSLWantWriteError(SSLError, _ssl.SSLWantWriteError):
    """Non-blocking SSL socket needs to write data."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class SSLSyscallError(SSLError, _ssl.SSLSyscallError):
    """System call error during SSL operation."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class SSLEOFError(SSLError, _ssl.SSLEOFError):
    """SSL connection terminated abruptly (EOF without close_notify)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class SSLCertVerificationError(SSLError, _ssl.SSLCertVerificationError):
    """Certificate verification failed."""

    verify_code: int
    verify_message: str

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.verify_code = kwargs.pop("verify_code", 0)
        self.verify_message = kwargs.pop("verify_message", "")
        super().__init__(*args, **kwargs)


# Alias used by CPython
CertificateError = SSLCertVerificationError
