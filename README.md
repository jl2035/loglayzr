# loglayzr

**L**og **L**ayzr — flag the noise, find the attacks.

A zero-dependency Python toolkit for scanning Apache/Nginx combined-format access logs for suspicious activity. Uses signature-based pattern matching, GeoIP enrichment, and interactive browsing to surface reconnaissance, exploitation attempts, and brute-force attacks hiding in your logs.

## Features

- **57 built-in detection patterns** covering SQL injection, command injection, path traversal, web shells, CVE probes, WordPress attacks, credential stuffing, config scraping, XSS, scanner user-agents, and more
- **GeoIP enrichment** — tags matches with country codes; whitelist your own countries to suppress noise
- **IP whitelist** — ignore known-safe IPs (internal servers, monitoring)
- **Static asset noise filter** — skips legitimate CSS/JS/image loads from real page views
- **Two interfaces** — summary report (`analyze.py`) and interactive browser (`browse.py`)
- **Pipeline-friendly** — JSONL output, pipe to `jq`, `grep`, or any Unix tool

## Requirements

- Python 3.12+
- `geoiplookup` from the `geoip-bin` package (for GeoIP lookups)

```bash
sudo apt install geoip-bin geoip-database
```

No Python packages outside the standard library.

## Quick start

```bash
# Summary of all suspicious activity
python3 analyze.py logs/access.log

# Save to a report file
python3 analyze.py logs/access.log > reports/site.report.txt

# Only critical hits
python3 analyze.py logs/access.log | grep '"sev":"CRITICAL"'

# Browse matches interactively (select category → pattern → P/N/Q)
python3 browse.py logs/access.log

# Aggregate by country
python3 analyze.py logs/access.log | grep '^{' | \
    jq -s 'group_by(.cc) | map({cc: .[0].cc, count: length}) | sort_by(-.count)'
```

## analyze.py — summary report

```
python3 analyze.py <logfile>
```

Outputs a plain-text summary header followed by JSONL match lines.

**Summary header:**
```
=== SUMMARY: access.log ===
Lines parsed:    9,277
Suspicious hits: 1,613

  By severity:
    CRITICAL:  80
        HIGH:  388
      MEDIUM:  230
         LOW:  915

  By category (top 10):
    config_scraping      534
    wordpress            407
    ...

  Top attacking IPs:
    136.109.155.86     58 [US]  (env_file_probe×28, ...)
    213.209.159.175    58 [US]  (env_file_probe×58)

  By country (non-whitelisted):
    US     1234
    CN      456
    ...
```

**JSONL match lines** (after the summary):
```json
{"ts":"2026-06-11T06:31:33+02:00","ip":"136.109.155.86","m":"GET","url":"/symfony/.env","st":301,"sz":194,"pat":"env_file_probe","cat":"config_scraping","sev":"HIGH","cc":"US","ua":"Mozilla/5.0 ..."}
```

## browse.py — interactive investigation

```
python3 browse.py <logfile>
```

1. Choose a **category** (or All)
2. Choose a **pattern** (or All)
3. Browse matches one at a time

| Key | Action |
|-----|--------|
| `N` / `Enter` / `Space` | Next match |
| `P` / `Backspace` | Previous match |
| `Q` / `Ctrl+C` | Quit |

Each match shows severity, pattern description, full log entry, and country code for non-whitelisted IPs.

## Patterns

Detection rules live in `patterns.json`. Each pattern has:

| Field | Description |
|-------|-------------|
| `name` | Unique identifier (e.g. `env_file_probe`) |
| `category` | Grouping label (`config_scraping`, `sqli`, `rce`, …) |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` |
| `regex` | Python regex applied to the target field (or `null` for length checks) |
| `field` | Which log field to match: `url`, `user_agent`, `status`, `method`, `referrer` |
| `type` | `"length_check"` (optional) — instead of regex, flags entries where the field exceeds `threshold` characters |
| `description` | Human-readable explanation shown in browse mode |

**57 patterns across 13 categories:** config_scraping (10), recon (8), wordpress (6), cve_exploit (6), sqli (5), rce (5), anomaly (4), xss (3), admin_panel (3), evasion (3), path_traversal (2), backdoor (1), php_exploit (1).

Add new patterns by editing `patterns.json` — no code changes needed.

## Whitelists

Configured in `geoip.py`:

```python
# Countries to ignore (no matches from these IPs)
COUNTRY_WHITELIST = {"CN", "IN", "LK"}

# IPs to ignore (no matches from these addresses)
IP_WHITELIST = {"192.168.1.2"}
```

Matches from whitelisted countries or IPs are silently dropped.

## File structure

```
loglayzr/
├── analyze.py        # Summary report script
├── browse.py         # Interactive match browser
├── common.py         # Shared filtering + match construction
├── geoip.py          # GeoIP lookups + whitelist configuration
├── patterns.json     # Suspicious pattern definitions (57 rules)
├── LICENSE           # GPLv3
└── README.md
```

## Filter pipeline

Each log line passes through filters in order before pattern matching:

1. **Static load** — GET + static extension (`.js`, `.css`, `.png`, …) + non-empty referrer → skip
2. **IP whitelist** — IP in `IP_WHITELIST` → skip
3. **Country whitelist** — IP resolves to a country in `COUNTRY_WHITELIST` → skip
4. **Pattern matching** — remaining entries checked against all 57 patterns

Filters are defined in `common.py` — add new ones in `should_skip()`.

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).
