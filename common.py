"""
Shared logic for analyze.py and browse.py.
Provides static-load filtering, match construction, and log file resolution.
"""

import gzip
import os
from pathlib import Path

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


# ─── Log file resolution and reading ──────────────────────────────────────────

# Extensions to skip — known binaries, not log files
_SKIP_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
              ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".webm",
              ".pyc", ".pyo", ".so", ".o", ".a", ".dylib", ".exe", ".dll",
              ".zip", ".tgz", ".bz2", ".xz", ".7z", ".rar",
              ".pdf", ".doc", ".docx", ".xls", ".xlsx",
              ".db", ".sqlite", ".sqlite3"}


def _is_binary_ext(path: Path) -> bool:
    """Skip files with known binary extensions (except .gz which is handled)."""
    return path.suffix.lower() in _SKIP_EXTS


def resolve_log_paths(path: Path) -> list[Path]:
    """
    Given a file or directory, return all log file paths to process.
    Directories are walked recursively. Hidden files/dirs are skipped.
    """
    paths = []
    if path.is_file():
        paths.append(path)
    elif path.is_dir():
        for root, dirs, files in os.walk(path):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for name in sorted(files):
                if name.startswith("."):
                    continue
                fp = Path(root) / name
                if _is_binary_ext(fp):
                    continue
                paths.append(fp)
    return paths


def iter_log_lines(path: Path):
    """
    Open a log file and yield stripped lines.
    Handles .gz files transparently via gzip decompression.
    """
    if path.suffix == ".gz":
        f = gzip.open(path, "rt", errors="replace")
    else:
        f = open(path, "r", errors="replace")

    with f:
        for line in f:
            line = line.strip()
            if line:
                yield line

