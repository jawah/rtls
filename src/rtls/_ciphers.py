from __future__ import annotations

# TLS 1.2 suites
_OPENSSL_TO_IANA: dict[str, str] = {
    # ECDHE-RSA
    "ECDHE-RSA-AES128-GCM-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    # ECDHE-ECDSA
    "ECDHE-ECDSA-AES128-GCM-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}

# TLS 1.3 suites (these are always enabled, OpenSSL names differ)
_TLS13_SUITES: dict[str, str] = {
    "TLS_AES_128_GCM_SHA256": "TLS13_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384": "TLS13_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256": "TLS13_CHACHA20_POLY1305_SHA256",
}

# Reverse map for get_ciphers()
_IANA_TO_OPENSSL: dict[str, str] = {v: k for k, v in _OPENSSL_TO_IANA.items()}
_IANA_TO_OPENSSL.update({v: k for k, v in _TLS13_SUITES.items()})

# Group aliases used in OpenSSL cipher strings
_GROUP_ALIASES: dict[str, set[str]] = {
    "HIGH": set(_OPENSSL_TO_IANA.keys()),
    "ALL": set(_OPENSSL_TO_IANA.keys()),
    "DEFAULT": set(_OPENSSL_TO_IANA.keys()),
    "ECDH": {k for k in _OPENSSL_TO_IANA if "ECDHE" in k},
    "ECDHE": {k for k in _OPENSSL_TO_IANA if "ECDHE" in k},
    "kECDHE": {k for k in _OPENSSL_TO_IANA if "ECDHE" in k},
    "aECDSA": {k for k in _OPENSSL_TO_IANA if "ECDSA" in k},
    "aRSA": {k for k in _OPENSSL_TO_IANA if "RSA" in k},
    "AESGCM": {k for k in _OPENSSL_TO_IANA if "AES" in k and "GCM" in k},
    "AES128": {k for k in _OPENSSL_TO_IANA if "AES128" in k},
    "AES256": {k for k in _OPENSSL_TO_IANA if "AES256" in k},
    "AES": {k for k in _OPENSSL_TO_IANA if "AES" in k},
    "CHACHA20": {k for k in _OPENSSL_TO_IANA if "CHACHA20" in k},
    # These groups contain nothing in rustls (not supported)
    "aNULL": set(),
    "eNULL": set(),
    "NULL": set(),
    "MD5": set(),
    "RC4": set(),
    "3DES": set(),
    "DES": set(),
    "EXPORT": set(),
    "LOW": set(),
    "MEDIUM": set(),
    "DH": set(),  # DHE not supported
    "DHE": set(),
    "kDHE": set(),
    "aDSS": set(),
    "DSS": set(),
    "SEED": set(),
    "IDEA": set(),
    "CAMELLIA": set(),
    "CAMELLIA128": set(),
    "CAMELLIA256": set(),
    "PSK": set(),
    "SRP": set(),
    "GOST": set(),
    "ARIA": set(),
    "ARIA128": set(),
    "ARIA256": set(),
    "CCM": set(),
    "CCM8": set(),
}


def parse_cipher_string(cipher_string: str) -> list[str]:
    """
    Parse an OpenSSL cipher string and return a list of rustls IANA suite names.

    Supports:
    - Individual cipher names: ECDHE-RSA-AES128-GCM-SHA256
    - Group aliases: HIGH, ECDH+AESGCM, ALL
    - Exclusions: !aNULL, !MD5, -3DES
    - Additions: +ECDHE
    - @SECLEVEL=N (recognized but no-op)
    - + joining operator for intersections: ECDHE+AESGCM
    - : or space as separator

    Unknown/unsupported ciphers are silently dropped.
    """
    if not cipher_string:
        return list(_OPENSSL_TO_IANA.values())

    # Normalize separator
    cipher_string = cipher_string.replace(" ", ":")

    # Start with empty result
    result: list[str] = []
    excluded: set[str] = set()

    for token in cipher_string.split(":"):
        token = token.strip()
        if not token:
            continue

        # Handle @SECLEVEL=N, @STRENGTH, etc.
        if token.startswith("@"):
            continue

        # Handle exclusion
        if token.startswith("!") or token.startswith("-"):
            group_name = token[1:]
            excluded |= _resolve_cipher_group(group_name)
            continue

        # Handle addition prefix
        if token.startswith("+"):
            token = token[1:]

        # Handle intersection: ECDHE+AESGCM means ECDHE AND AESGCM
        if "+" in token:
            parts = token.split("+")
            sets = [_resolve_cipher_group(p) for p in parts]
            if sets:
                intersection = sets[0]
                for s in sets[1:]:
                    intersection &= s
                for cipher in intersection:
                    iana = _OPENSSL_TO_IANA.get(cipher)
                    if iana and iana not in result:
                        result.append(iana)
            continue

        # Try as individual cipher name
        if token in _OPENSSL_TO_IANA:
            iana = _OPENSSL_TO_IANA[token]
            if iana not in result:
                result.append(iana)
            continue

        # Try as group alias
        group = _resolve_cipher_group(token)
        if group:
            for cipher in group:
                iana = _OPENSSL_TO_IANA.get(cipher)
                if iana and iana not in result:
                    result.append(iana)
            continue

        # DHE-RSA-* and other unsupported ciphers: silently skip

    # Apply exclusions
    excluded_iana = set()
    for cipher in excluded:
        iana = _OPENSSL_TO_IANA.get(cipher)
        if iana:
            excluded_iana.add(iana)

    result = [s for s in result if s not in excluded_iana]

    # If nothing matched AND the input was non-trivial, raise an error.
    # This matches OpenSSL behavior: set_ciphers("^$:,;?*'dorothyx") raises.
    if not result:
        from ._exceptions import SSLError

        raise SSLError(1, f"[SSL] No ciphers can be selected from '{cipher_string}'")

    return result


def _resolve_cipher_group(name: str) -> set[str]:
    """Resolve a group name or individual cipher to a set of OpenSSL cipher names."""
    # Direct group lookup
    if name in _GROUP_ALIASES:
        return _GROUP_ALIASES[name].copy()

    # Individual cipher
    if name in _OPENSSL_TO_IANA:
        return {name}

    # Try case-insensitive match on groups
    name_upper = name.upper()
    for group_name, members in _GROUP_ALIASES.items():
        if group_name.upper() == name_upper:
            return members.copy()

    return set()


def get_default_ciphers() -> list[dict[str, object]]:
    """Return the default ciphers in ssl.SSLContext.get_ciphers() format."""
    result = []

    for openssl_name, iana_name in _OPENSSL_TO_IANA.items():
        is_tls13 = iana_name.startswith("TLS13_")
        result.append(
            {
                "name": openssl_name,
                "id": 0,  # We don't have OpenSSL NID
                "protocol": "TLSv1.3" if is_tls13 else "TLSv1.2",
                "description": iana_name,
                "strength_bits": _get_strength_bits(openssl_name),
                "alg_bits": _get_strength_bits(openssl_name),
            }
        )

    # Add TLS 1.3 suites
    for openssl_name, iana_name in _TLS13_SUITES.items():
        result.append(
            {
                "name": openssl_name,
                "id": 0,
                "protocol": "TLSv1.3",
                "description": iana_name,
                "strength_bits": _get_strength_bits(openssl_name),
                "alg_bits": _get_strength_bits(openssl_name),
            }
        )

    return result


def _get_strength_bits(cipher_name: str) -> int:
    """Get the strength bits for a cipher suite."""
    if "AES128" in cipher_name or "AES_128" in cipher_name:
        return 128
    if "AES256" in cipher_name or "AES_256" in cipher_name:
        return 256
    if "CHACHA20" in cipher_name:
        return 256
    return 0
