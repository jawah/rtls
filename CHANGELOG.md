Release History
===============

2026.3.27
---------

- Fixed keylogfile path ignored.
- Fixed loading mtls encrypted keys.
- Fixed fd leakage upon SSLError.
- Fixed ssl ctx options handling.
- Fixed untriaged CA bundle anchors and intermediates.
- Removed hostname_checks_common_name as Rustls don't support it.
- Removed unsupported PROTOCOL constants.

2026.3.26
---------

- Initial release
