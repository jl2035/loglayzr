"""
Load configuration from config.json with sensible defaults.
Import this module to access all settings as module-level variables.
"""

import json
import re
from pathlib import Path

_CONFIG_DIR = Path(__file__).resolve().parent
_CONFIG_PATH = _CONFIG_DIR / "config.json"

# ── Defaults (used if config.json is missing or incomplete) ───────────────────

_DEFAULTS = {
    "log_format": {
        "regex": r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d{3}) (\S+) "([^"]*)" "([^"]*)"',
        "timestamp_format": "%d/%b/%Y:%H:%M:%S %z",
    },
    "patterns_file": "patterns.json",
    "whitelists": {
        "countries": [],
        "ips": [],
    },
    "geoip": {
        "command": "geoiplookup",
        "regex_search": r"GeoIP Country Edition:\s*([A-Z]{2})",
    },
    "filters": {
        "static_extensions": [
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
            ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".webm",
            ".pdf", ".zip", ".gz", ".tar",
        ],
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def _load() -> dict:
    """Load config.json, merge with defaults, return resolved config."""
    cfg = json.loads(json.dumps(_DEFAULTS))  # deep copy
    if _CONFIG_PATH.is_file():
        try:
            with open(_CONFIG_PATH) as f:
                user = json.load(f)
            _deep_merge(cfg, user)
        except (json.JSONDecodeError, OSError):
            pass
    return cfg


_cfg = _load()

# ─── Log format ──────────────────────────────────────────────────────────────

LOG_RE = re.compile(_cfg["log_format"]["regex"])
TS_FMT = _cfg["log_format"]["timestamp_format"]

# ─── Paths ───────────────────────────────────────────────────────────────────

# Resolve relative to config directory
_patterns_raw = _cfg["patterns_file"]
PATTERNS_FILE = Path(_patterns_raw) if Path(_patterns_raw).is_absolute() \
    else _CONFIG_DIR / _patterns_raw

# ─── Whitelists ──────────────────────────────────────────────────────────────

COUNTRY_WHITELIST = set(_cfg["whitelists"]["countries"])
IP_WHITELIST = set(_cfg["whitelists"]["ips"])

# ─── GeoIP ───────────────────────────────────────────────────────────────────

GEOIP_CMD = _cfg["geoip"]["command"]
GEOIP_RE = re.compile(_cfg["geoip"]["regex_search"])

# ─── Filters ─────────────────────────────────────────────────────────────────

STATIC_EXTS = tuple(_cfg["filters"]["static_extensions"])
