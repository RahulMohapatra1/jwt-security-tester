#!/usr/bin/env python3
"""
JWT Wordlist Updater
---------------------
Downloads the latest JWT secret wordlists from trusted public security
repositories and merges them into a single deduplicated file.

Sources used (all MIT/public domain licensed):
  1. SecLists/scraped-JWT-secrets.txt  — danielmiessler/SecLists (103k+ secrets)
  2. wallarm/jwt-secrets               — source of the SecLists JWT list
  3. Our curated common_secrets.txt    — hand-picked high-probability secrets

Usage:
  python3 wordlists/update_wordlists.py

Output:
  wordlists/jwt-secrets-full.txt  — merged, deduplicated, sorted by length
"""

import urllib.request
import urllib.error
import os
import sys
import time

# ── Colour codes ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ── Output directory (same folder as this script) ─────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE  = os.path.join(SCRIPT_DIR, "jwt-secrets-full.txt")
CURATED_FILE = os.path.join(SCRIPT_DIR, "common_secrets.txt")

# ── Public wordlist sources ───────────────────────────────────────────────────
# All sources are MIT licensed public security research repositories.
# These are the same lists used by tools like hashcat, john, and jwt_tool.
SOURCES = [
    {
        "name":    "SecLists — scraped-JWT-secrets.txt",
        "url":     "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/scraped-JWT-secrets.txt",
        "credit":  "github.com/danielmiessler/SecLists (MIT License)",
    },
    {
        "name":    "Wallarm JWT Secrets",
        "url":     "https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list",
        "credit":  "github.com/wallarm/jwt-secrets",
    },
]


def print_header():
    DOT = "\xb7"
    print(f"\n  {CYAN}{BOLD}{DOT * 48}{RESET}")
    print(f"  {BOLD}JWT Wordlist Updater{RESET}")
    print(f"  {CYAN}{DOT * 48}{RESET}\n")


def download(url: str, name: str) -> set:
    """
    Download a wordlist from a URL and return its lines as a set.
    Uses only Python stdlib — no pip packages needed for this script.
    """
    print(f"  {CYAN}[FETCH]{RESET} {name}")
    print(f"          {url}")

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "JWT-Security-Tester-Wordlist-Updater/2.0"}
        )
        start = time.time()
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw   = resp.read().decode("utf-8", errors="ignore")
            lines = {l.strip() for l in raw.splitlines() if l.strip()}
            elapsed = time.time() - start
            print(f"  {GREEN}[OK]{RESET}    {len(lines):,} secrets fetched in {elapsed:.1f}s\n")
            return lines

    except urllib.error.URLError as e:
        print(f"  {YELLOW}[SKIP]{RESET}  Could not fetch — {e.reason}")
        print(f"          Continuing without this source.\n")
        return set()

    except Exception as e:
        print(f"  {RED}[ERROR]{RESET} {e}\n")
        return set()


def load_curated() -> set:
    """Load our hand-curated list of high-probability secrets."""
    if not os.path.exists(CURATED_FILE):
        print(f"  {YELLOW}[WARN]{RESET} curated file not found: {CURATED_FILE}")
        return set()
    with open(CURATED_FILE, "r", encoding="utf-8", errors="ignore") as f:
        lines = {l.strip() for l in f
                 if l.strip() and not l.strip().startswith("#")}
    print(f"  {GREEN}[OK]{RESET}    {len(lines):,} secrets from curated list\n")
    return lines


def save_merged(all_secrets: set):
    """
    Save merged secrets sorted by length (shortest first).
    Sorting by length means common short secrets like 'secret', 'password'
    are tested first — maximises chance of early hit in brute force.
    """
    sorted_secrets = sorted(all_secrets, key=lambda x: (len(x), x.lower()))
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted_secrets) + "\n")
    size_kb = os.path.getsize(OUTPUT_FILE) / 1024
    print(f"  {GREEN}{BOLD}[SAVED]{RESET} {OUTPUT_FILE}")
    print(f"          {len(sorted_secrets):,} unique secrets  |  {size_kb:.0f} KB")
    print(f"          Sorted shortest-first for maximum brute force efficiency.\n")


def main():
    print_header()

    print(f"  {BOLD}Sources:{RESET}")
    print(f"  1. Our curated common_secrets.txt")
    for i, s in enumerate(SOURCES, 2):
        print(f"  {i}. {s['name']}")
        print(f"     Credit: {s['credit']}")
    print()

    # ── Load curated list ──────────────────────────────────────────────────────
    print(f"  {BOLD}Loading curated list...{RESET}")
    merged = load_curated()

    # ── Download each source ───────────────────────────────────────────────────
    print(f"  {BOLD}Downloading sources...{RESET}")
    for source in SOURCES:
        fetched = download(source["url"], source["name"])
        before  = len(merged)
        merged |= fetched   # Union: add all new unique secrets
        added   = len(merged) - before
        if fetched:
            print(f"  {CYAN}[MERGE]{RESET} +{added:,} new unique secrets from this source\n")

    # ── Save ───────────────────────────────────────────────────────────────────
    print(f"  {BOLD}Saving merged wordlist...{RESET}")
    save_merged(merged)

    # ── Usage tip ──────────────────────────────────────────────────────────────
    print(f"  {BOLD}Use with jwt_tester.py:{RESET}")
    print(f"  {CYAN}python3 jwt_tester.py -t <token> -w wordlists/jwt-secrets-full.txt{RESET}\n")

    DOT = "\xb7"
    print(f"  {CYAN}{DOT * 48}{RESET}")
    print(f"  {YELLOW}All sources are MIT licensed public security research repos.{RESET}")
    print(f"  {YELLOW}Use only for authorised security testing.{RESET}")
    print(f"  {CYAN}{DOT * 48}{RESET}\n")


if __name__ == "__main__":
    main()
