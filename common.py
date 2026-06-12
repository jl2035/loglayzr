"""
Shared logic for analyze.py and browse.py.
Provides static-load filtering and match construction.
"""

from geoip import lookup as geo_lookup                               # noqa: F401
from config import STATIC_EXTS, COUNTRY_WHITELIST, IP_WHITELIST     # noqa: F401


# ─── Static asset noise filter ───────────────────────────────────────────────

def _is_static_load(entry: dict) -> bool:
    """True if this is a GET for a static file with a non-empty referrer."""
    if entry["method"] != "GET":
        return False
    ref = entry["referrer"]
    if not ref or ref == "-":
        return False
    url_lower = entry["url"].lower()
    for ext in STATIC_EXTS:
        if url_lower.endswith(ext) or (ext + "?") in url_lower:
            return True
    return False


# ─── Entry filtering ─────────────────────────────────────────────────────────

def should_skip(entry: dict) -> bool:
    """Return True if this entry should be excluded from results.
    Checks: static load, IP whitelist, country whitelist."""
    if _is_static_load(entry):
        return True
    if entry["ip"] in IP_WHITELIST:
        return True
    cc = geo_lookup(entry["ip"])
    if cc and cc in COUNTRY_WHITELIST:
        return True
    return False


# ─── Match construction ──────────────────────────────────────────────────────

def build_match(entry: dict, pattern: dict, **extra) -> dict:
    """Build a match dict from a parsed log entry and pattern.
    Adds 'cc' field for non-whitelisted, resolvable IPs.
    Extra kwargs are merged into the dict.
    """
    match = {
        "ts":  entry["ts"],
        "ip":  entry["ip"],
        "m":   entry["method"],
        "url": entry["url"],
        "st":  entry["status"],
        "sz":  entry["size"],
        "pat": pattern["name"],
        "cat": pattern["category"],
        "sev": pattern["severity"],
    }
    match.update(extra)

    cc = geo_lookup(entry["ip"])
    if cc and cc not in COUNTRY_WHITELIST:
        match["cc"] = cc

    return match
