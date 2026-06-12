#!/usr/bin/env python3
"""
|Log analyzer for Apache/Nginx combined-format access logs.
|Matches entries against suspicious patterns defined in patterns.json.
|Accepts a file or a directory (walked recursively, .gz supported).
|
|Usage:
|    python3 analyze.py <logfile>
|    python3 analyze.py <directory>

    # Screen review (summary first, then JSONL details scroll)
    python3 analyze.py example.com.access.log | less

    # Save report
    python3 analyze.py example.com.access.log > reports/example.com.report.txt

    # Pipeline: only critical hits
    python3 analyze.py access.log | grep '"sev":"CRITICAL"'

    # Pipeline: aggregate by IP
    python3 analyze.py access.log | grep '^{' | jq -s 'group_by(.ip) | map({ip:.[0].ip, count:length})'
"""

import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from common import should_skip, build_match, COUNTRY_WHITELIST
from common import geo_lookup  # for summary display
from common import resolve_log_paths, iter_log_lines
from config import LOG_RE, TS_FMT, PATTERNS_FILE

# ─── Helpers ─────────────────────────────────────────────────────────────────
def parse_timestamp(raw: str) -> str:
    """Convert Apache log timestamp to ISO 8601."""
    try:
        dt = datetime.strptime(raw, TS_FMT)
        return dt.isoformat()
    except ValueError:
        return raw


def parse_line(line: str):
    """Parse a combined-format log line. Returns dict or None."""
    m = LOG_RE.match(line)
    if not m:
        return None
    return {
        "ip":          m.group(1),
        "ts":          parse_timestamp(m.group(2)),
        "method":      m.group(3),
        "url":         m.group(4),
        "protocol":    m.group(5),
        "status":      int(m.group(6)),
        "size":        int(m.group(7)) if m.group(7) != "-" else 0,
        "referrer":    m.group(8),
        "user_agent":  m.group(9),
    }


def match_patterns(entry: dict, patterns: list) -> list:
    """Return list of matching pattern dicts (with name/sev/cat)."""
    hits = []
    for p in patterns:
        field_val = entry.get(p["field"], "")
        field_val = str(field_val)
        if p.get("type") == "length_check":
            threshold = p.get("threshold", 500)
            if len(field_val) > threshold:
                hits.append(p)
        elif p["regex"] is not None:
            if re.search(p["regex"], field_val):
                hits.append(p)
    return hits


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <logfile>", file=sys.stderr)
        sys.exit(1)

    log_path = Path(sys.argv[1])
    if not log_path.exists():
        print(f"Error: not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    print()
    print(f"==========================================================")
    print(f"====================== LOGLAYZR ==========================")
    print(f"==========================================================\n")

    log_paths = resolve_log_paths(log_path)
    if not log_paths:
        print(f"Error: no log files found: {log_path}", file=sys.stderr)
        sys.exit(1)

    # Load patterns
    try:
        with open(PATTERNS_FILE) as f:
            patterns = json.load(f)
    except FileNotFoundError:
        print(f"Error: patterns file not found: {PATTERNS_FILE}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON in patterns file: {e}", file=sys.stderr)
        sys.exit(1)

    # Process log(s)
    parsed = 0
    skipped = 0
    matches = []                        # list of flat dicts for JSONL output
    hits_by_sev = Counter()             # severity counts
    hits_by_cat = Counter()             # category counts
    hits_by_pattern = Counter()         # pattern name counts
    hits_by_ip = Counter()              # IP → total matches
    hits_by_country = Counter()         # country → match count (non-whitelisted)
    ip_patterns = defaultdict(Counter)  # IP → {pattern_name: count}

    print()
    print(f"Loaded {len(patterns)} patterns from {PATTERNS_FILE}")
    print()

    for i, log_path in enumerate(log_paths, 1):
        print(f"\r\x1b[K  [{i:>3}/{len(log_paths)}] {log_path.name} ... ", end="", flush=True, file=sys.stderr)
        file_lines = 0
        for line in iter_log_lines(log_path):
            entry = parse_line(line)
            if entry is None:
                skipped += 1
                continue
            parsed += 1
            file_lines += 1

            # Apply all filters (static load, IP whitelist, country whitelist)
            if should_skip(entry):
                continue

            hits = match_patterns(entry, patterns)
            if not hits:
                continue

            for pat in hits:
                match = build_match(entry, pat, ua=entry["user_agent"])
                matches.append(match)

                hits_by_sev[pat["severity"]] += 1
                hits_by_cat[pat["category"]] += 1
                hits_by_pattern[pat["name"]] += 1
                hits_by_ip[entry["ip"]] += 1
                ip_patterns[entry["ip"]][pat["name"]] += 1
                if "cc" in match:
                    hits_by_country[match["cc"]] += 1

        print(f"\r\x1b[K  [{i:>3}/{len(log_paths)}] {log_path.name}  {file_lines:>8,} lines \u2713", file=sys.stderr)


    # ── Summary ──────────────────────────────────────────────────────────────
    print()
    if len(log_paths) == 1:
        print(f"=== SUMMARY: {log_paths[0].name} ===")
    else:
        print(f"=== SUMMARY: {log_paths[0].parent.name}/ ({len(log_paths)} files) ===")
    print()

    print(f"Lines parsed:    {parsed:,}")
    print(f"Lines skipped:   {skipped:,}")
    print(f"Suspicious hits: {len(matches):,}")
    print()

    if matches:
        # Severity breakdown
        print("  By severity:")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            count = hits_by_sev.get(sev, 0)
            if count:
                print(f"    {sev:>8}:  {count}")

        print(f"\n  By category (top 10):")
        for cat, count in hits_by_cat.most_common(10):
            print(f"    {cat:<20} {count}")

        print(f"\n  Top attacking IPs:")
        for ip, count in hits_by_ip.most_common(10):
            top_pats = ip_patterns[ip].most_common(3)
            pat_str = ", ".join(f"{n}×{c}" for n, c in top_pats)
            cc = geo_lookup(ip)
            cc_str = f" [{cc}]" if cc and cc not in COUNTRY_WHITELIST else ""
            print(f"    {ip:<20} {count:>4}{cc_str}  ({pat_str})")

        print(f"\n  Top patterns:")
        for name, count in hits_by_pattern.most_common(15):
            print(f"    {name:<35} {count}")

        if hits_by_country:
            print(f"\n  By country (non-whitelisted):")
            for cc, count in hits_by_country.most_common(15):
                print(f"    {cc:<6} {count}")

        print()

if __name__ == "__main__":
    main()
