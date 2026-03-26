Rustls-backed TLS for CPython
-----------------------------

Ever dreamed of getting rid of OpenSSL within CPython without creating a custom build of CPython for this?
Tired of waiting half a decade for a solid and up-to-date TLS experience, shipping Post-quantum, and ECH support by default?

Then `rtls` is made for you.

It's a drop-in replacement for the `ssl` stdlib!
Support CPython 3.7 onward. Including freethreaded.

### Getting Started

Install from source (requires a Rust toolchain and maturin):

```
pip install rtls
```

Then swap `ssl` for `rtls` anywhere in your code:

```python
import rtls as ssl

ctx = ssl.create_default_context()
```

Or use it alongside the stdlib:

```python
from rtls import SSLContext, PROTOCOL_TLS_CLIENT

ctx = SSLContext(PROTOCOL_TLS_CLIENT)
ctx.load_default_certs()

import socket
sock = socket.create_connection(("example.com", 443))
ssock = ctx.wrap_socket(sock, server_hostname="example.com")
ssock.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
print(ssock.recv(4096).decode())
```

It works with asyncio out of the box:

```python
import asyncio
import rtls as ssl

async def main():
    ctx = ssl.create_default_context()
    reader, writer = await asyncio.open_connection("example.com", 443, ssl=ctx)
    writer.write(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    await writer.drain()
    print((await reader.read(4096)).decode())
    writer.close()

asyncio.run(main())
```

### Feature Parity with stdlib

rtls re-exports **93 public names** matching the `ssl` module API. The table below summarizes
coverage across the main areas.

**What's different from `ssl`:**

- TLS 1.2 is the minimum version. SSLv2, SSLv3, TLS 1.0 and TLS 1.1 are not available.
- Hostname verification uses SAN only, never the Common Name.
- `compression()` always returns `None` (TLS compression is disabled, as it should be).
- `security_level` is always 2. rustls defaults are strong by design.
- `load_cert_chain` natively accepts **in-memory PEM bytes** as `certfile`/`keyfile`, not just file paths.

### Disclaimer

This project is in an early stage. The public API is stable, we do not plan to diverge from stdlib.
It's not pure Python, so you'll have either a pre-built wheel compatible with your platform or build
from the sources by yourself.

A notice is present to acknowledge CPython rights on the ssl Python codebase. The project itself is licensed
under MIT as we always do. Rustls is also permissively licensed.

Right now we deliberately focus on the client side. PRs are accepted to help us finalize/improve the server side.

- We are not inclined to enable FIPS mode via aws-lc-rs for the moment, however, it's on our roadmap.
- Do not open issue about "JA fingerprint", "Browser impersonator" or alike, we'll most likely close them on the spot. We are not interested in pursing this.
- PyPy is not going to be supported, unfortunately.

It's not faster than the stdlib. Expect roughly 5 to 10% slower. For example, a quick benchmark reveal that ssl stdlib can reach 456 MB/s raw throughput on my modest laptop while our
implementation reached 410 MB/s. Why? We heavily pay for crossing the boundary between Rust and CPython. We could implement the Buffer protocol (avoid needless memcpy each time), but that
would cost us our high CPython (i.e. 3.7+) compatibility. That trade off is quickly hided by the fact that you will run a memory safe TLS implementation. No longer in C shall we do TLS!

Contributions, bug reports, and feedback are welcome.

### Versioning

This project is based on calver (YYYY-0M-0D), it does not need semver as it aims to be a drop-in replacement for stdlib `ssl`.
You do not need to constraint the upper bound version.

### Prior art

I saw https://github.com/djc/pyrtls a couple of months ago, and it inspired me to write this alternative.
Why? As you are aware, we are maintaining a fork of urllib3 and requests, and having to handwrite a support for a non ssl
compatible lib is going to be a nightmare. We just can't ask the maintainer to rewrite everything for our
own needs.

### Documentation

See https://docs.python.org/3/library/ssl.html as it's fairly detailed and spotless.
We would host our own version later having unsupported feature removed. Amongst import naming, etc(...).
