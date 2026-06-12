"""
GeoIP lookup with caching.
Configuration (whitelists, command) loaded from config.json via config.py.
"""

import subprocess

from config import COUNTRY_WHITELIST, IP_WHITELIST, GEOIP_CMD, GEOIP_RE

_cache = {}


def lookup(ip: str) -> str | None:
    """Return 2-letter country code for an IP, or None if not found."""
    if ip in _cache:
        return _cache[ip]

    try:
        result = subprocess.run(
            [GEOIP_CMD, ip],
            capture_output=True, text=True, timeout=2,
        )
        m = GEOIP_RE.search(result.stdout)
        code = m.group(1) if m else None
        # "IP" means "IP Address not found" — not a real country
        if code == "IP":
            code = None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        code = None

    _cache[ip] = code
    return code


def is_country_whitelisted(ip: str) -> bool:
    """Check if IP belongs to a whitelisted country."""
    code = lookup(ip)
    return code is not None and code in COUNTRY_WHITELIST


def is_ip_whitelisted(ip: str) -> bool:
    """Check if IP is in the explicit IP whitelist."""
    return ip in IP_WHITELIST
