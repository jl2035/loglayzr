"""
Shared GeoIP lookup with caching. Uses system `geoiplookup` command.
Install: sudo apt install geoip-bin geoip-database
"""

import re
import subprocess

_cache = {}

# Whitelisted countries — matches from these get skipped entirely
COUNTRY_WHITELIST = {"CN", "IN", "LK"}

# Whitelisted IP addresses — matches from these get skipped entirely
IP_WHITELIST = {"192.168.1.2"}

# Regex to extract country code from: "GeoIP Country Edition: US, United States"
_RE = re.compile(r"GeoIP Country Edition:\s*([A-Z]{2})")


def lookup(ip: str) -> str | None:
    """Return 2-letter country code for an IP, or None if not found."""
    if ip in _cache:
        return _cache[ip]

    try:
        result = subprocess.run(
            ["geoiplookup", ip],
            capture_output=True, text=True, timeout=2,
        )
        m = _RE.search(result.stdout)
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
