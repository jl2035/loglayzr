#!/usr/bin/env python3
"""
Interactive match browser for access log analysis.
Select a category and pattern, then browse suspicious hits one at a time.
Accepts a file or a directory (walked recursively, .gz supported).

Usage:
    python3 browse.py <logfile>
    python3 browse.py <directory>

Keys in browse mode:
    N / Enter / Right  →  next match
    P / Left            →  previous match
    B                   →  back to menu (change category/pattern)
    Q / Ctrl+C          →  quit
"""

import json
import sys
import termios
import tty
from collections import Counter, defaultdict
from pathlib import Path

# Import shared parsing logic from analyze.py
from analyze import parse_line, match_patterns, PATTERNS_FILE
from common import should_skip, build_match, COUNTRY_WHITELIST
from common import geo_lookup  # for summary display
from common import resolve_log_paths, iter_log_lines

# ─── Terminal helpers ────────────────────────────────────────────────────────

def getch():
    """Read a single character without waiting for Enter. Returns lowercase."""
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        return ch.lower()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def clear_screen():
    print("\033[2J\033[H", end="")


_QUIT = object()  # sentinel returned when user presses Q at a menu


def select_from_list(items, prompt, all_label="All"):
    """
    Show a numbered list and return:
      None       → 'All' selected (0)
      <value>    → specific item chosen
      _QUIT      → user pressed Q to exit
    Each item is (label, value, count) — count is shown in parens.
    """
    print(f"\n{prompt}")
    print(f"  0. {all_label}")
    for i, (label, value, count) in enumerate(items, 1):
        print(f"  {i}. {label}  ({count} match{'es' if count != 1 else ''})")

    while True:
        try:
            raw = input(f"\nChoice [0-{len(items)}, Q to quit]: ").strip()
            if not raw:
                continue
            if raw.lower() == 'q':
                return _QUIT
            idx = int(raw)
            if idx == 0:
                return None
            if 1 <= idx <= len(items):
                return items[idx - 1][1]   # return the value, not the label
        except (ValueError, IndexError):
            pass
        print("Invalid choice, try again.")


# ─── Match display ───────────────────────────────────────────────────────────

SEV_COLORS = {
    "CRITICAL": "\033[1;41m",  # bright red bg
    "HIGH":     "\033[1;31m",  # bright red
    "MEDIUM":   "\033[1;33m",  # yellow
    "LOW":      "\033[1;36m",  # cyan
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def display_match(match: dict, idx: int, total: int):
    """Print one match in a readable format."""
    sev_color = SEV_COLORS.get(match["sev"], "")
    pat_color = SEV_COLORS.get(match["sev"], "")

    clear_screen()

    # Header bar
    print(f"{BOLD}── Match {idx} of {total} ──{RESET}\n")

    # Severity badge + pattern name
    print(f"  Severity:  {sev_color} {match['sev']:>8} {RESET}")
    print(f"  Category:  {match['cat']}")
    print(f"  Pattern:   {BOLD}{match['pat']}{RESET}")
    print(f"  {DIM}→ {match['desc']}{RESET}")
    print()

    # Log entry details
    print(f"  {BOLD}Timestamp:{RESET}  {match['ts']}")
    print(f"  {BOLD}IP:{RESET}         {match['ip']}", end="")
    cc = match.get("cc")
    if cc:
        print(f"  {sev_color}[{cc}]{RESET}", end="")
    print()
    print(f"  {BOLD}Method:{RESET}     {match['m']}")
    print(f"  {BOLD}URL:{RESET}        {match['url']}")
    print(f"  {BOLD}Status:{RESET}     {match['st']}")
    print(f"  {BOLD}Size:{RESET}       {match['sz']:,}")
    print(f"  {BOLD}Referrer:{RESET}   {match['ref']}")
    print(f"  {BOLD}User-Agent:{RESET} {match['ua']}")
    print()

    # Controls
    print(f"  {DIM}[N] next  [P] prev  [B] back  [Q] quit{RESET}")


# ─── Load patterns with lookup ───────────────────────────────────────────────

def load_patterns():
    """Return (list_of_patterns, dict_of_name→pattern)."""
    with open(PATTERNS_FILE) as f:
        patterns = json.load(f)
    lookup = {p["name"]: p for p in patterns}
    return patterns, lookup


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <logfile>", file=sys.stderr)
        sys.exit(1)

    log_path = Path(sys.argv[1])
    if not log_path.exists():
        print(f"Error: not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    log_paths = resolve_log_paths(log_path)
    if not log_paths:
        print(f"Error: no log files found: {log_path}", file=sys.stderr)
        sys.exit(1)

    patterns, pat_lookup = load_patterns()
    print(f"Loaded {len(patterns)} patterns from {PATTERNS_FILE}")

    # ── Parse log(s), collect enriched matches ────────────────────────────────

    parsed = 0
    skipped = 0
    matches = []              # full match dicts for browsing

    for log_path in log_paths:
        file_parsed = 0
        for line in iter_log_lines(log_path):
            entry = parse_line(line)
            if entry is None:
                skipped += 1
                continue
            file_parsed += 1
            parsed += 1

            # Apply all filters (static load, IP whitelist, country whitelist)
            if should_skip(entry):
                continue

            hits = match_patterns(entry, patterns)
            for pat in hits:
                match = build_match(entry, pat,
                    ref=entry["referrer"],
                    ua=entry["user_agent"],
                    desc=pat.get("description", ""),
                )
                matches.append(match)

        print(f"  {log_path.name}: {file_parsed} lines", flush=True)

    print(f" done. {len(matches)} total matches across {len(log_paths)} file(s).")

    if not matches:
        print("No suspicious activity found. Clean logs!")
        return

    # ── Selection + browse loop ────────────────────────────────────────────────

    while True:
        # Category counts (from full matches, recalculated each iteration)
        cat_counts = Counter(m["cat"] for m in matches)
        pat_counts_all = Counter(m["pat"] for m in matches)

        # ── Step 1: pick category ─────────────────────────────────────────────

        cats_sorted = sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)
        cat_items = [(c, c, n) for c, n in cats_sorted]

        chosen_cat = select_from_list(
            cat_items,
            "Select category:",
            all_label="All categories",
        )
        if chosen_cat is _QUIT:
            clear_screen()
            print("Bye.")
            return

        # ── Step 2: pick pattern (filtered by category) ───────────────────────

        if chosen_cat:
            cat_matches = [m for m in matches if m["cat"] == chosen_cat]
            pat_in_cat = Counter(m["pat"] for m in cat_matches)
            pat_sorted = sorted(pat_in_cat.items(), key=lambda x: x[1], reverse=True)
            pat_items = [(p, p, n) for p, n in pat_sorted]
        else:
            pat_sorted_all = sorted(pat_counts_all.items(), key=lambda x: x[1], reverse=True)
            pat_items = [(p, p, n) for p, n in pat_sorted_all]

        chosen_pat = select_from_list(
            pat_items,
            "Select pattern:",
            all_label="All patterns",
        )
        if chosen_pat is _QUIT:
            clear_screen()
            print("Bye.")
            return

        # ── Filter ────────────────────────────────────────────────────────────

        if chosen_cat and chosen_pat:
            filtered = [m for m in matches if m["cat"] == chosen_cat and m["pat"] == chosen_pat]
        elif chosen_cat:
            filtered = [m for m in matches if m["cat"] == chosen_cat]
        elif chosen_pat:
            filtered = [m for m in matches if m["pat"] == chosen_pat]
        else:
            filtered = matches

        if not filtered:
            print("No matches for that selection.")
            continue

        # ── Browse mode ───────────────────────────────────────────────────────

        idx = 0
        total = len(filtered)

        while True:
            display_match(filtered[idx], idx + 1, total)

            ch = getch()

            if ch in ('q', '\x03'):          # Q or Ctrl+C
                clear_screen()
                print("Bye.")
                return
            elif ch in ('b',):               # B — back to menu
                break
            elif ch in ('n', '\r', '\n', ' ', '\x1b[c'):
                idx = (idx + 1) % total
            elif ch in ('p', '\x7f', '\b', '\x1b[d'):
                idx = (idx - 1) % total
            # Ignore other keys


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        clear_screen()
        print("Interrupted.")
        sys.exit(0)
