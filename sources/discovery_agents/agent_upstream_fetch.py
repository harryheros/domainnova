#!/usr/bin/env python3
"""
agent_upstream_fetch.py - Upstream list fetcher for DomainNova discovery layer.

Pulls domains from public Chinese domain lists, filters out already-known
domains, and appends new candidates to sources/manual/discovery.txt.

Sources:
  1. v2fly/domain-list-community (cn category)
  2. felixonmars/dnsmasq-china-list

Safety limits:
  - Max new domains added per run:     200
  - Max discovery.txt capacity:        2000 (enforced by build_domains.py)
  - Run frequency:                     monthly (enforced by update.yml)
  - No active scanning, passive only

Usage:
  python sources/discovery_agents/agent_upstream_fetch.py
"""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path
from typing import List, Set

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MAX_NEW_PER_RUN = 200   # hard limit on new domains added per run

UPSTREAM_SOURCES = [
    {
        "name":    "v2fly-cn",
        "url":     "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/cn",
        "parser":  "v2fly",
    },
    {
        "name":    "felixonmars-accelerated",
        "url":     "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf",
        "parser":  "dnsmasq",
    },
]

USER_AGENT = "DomainNova/DiscoveryAgent (+https://github.com/harryheros/domainnova)"

# Valid domain pattern
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$"
)

# Domains to always exclude (non-CN or problematic)
EXCLUDE_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "twitter.com",
    "instagram.com", "whatsapp.com", "telegram.org",
    "bing.com", "microsoft.com", "apple.com", "icloud.com",
    "amazonaws.com", "cloudflare.com", "fastly.com",
}


# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------
def make_session() -> requests.Session:
    retry = Retry(
        total=3,
        backoff_factor=1.0,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": USER_AGENT})
    return session


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------
def parse_v2fly(content: str) -> List[str]:
    """
    Parse v2fly domain-list-community format.
    Lines starting with 'full:', 'regexp:', 'include:' are skipped.
    Plain domain lines and 'domain:xxx' lines are extracted.
    """
    domains: List[str] = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Skip special prefixes
        if any(line.startswith(p) for p in ("regexp:", "include:", "full:")):
            continue
        # Strip 'domain:' prefix if present
        if line.startswith("domain:"):
            line = line[7:].strip()
        # Strip inline comments
        if " " in line:
            line = line.split()[0]
        line = line.lower().rstrip(".")
        if DOMAIN_RE.match(line):
            domains.append(line)
    return domains


def parse_dnsmasq(content: str) -> List[str]:
    """
    Parse dnsmasq conf format.
    Example line: server=/example.com/114.114.114.114
    """
    domains: List[str] = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Format: server=/domain/dns
        if line.startswith("server=/"):
            parts = line.split("/")
            if len(parts) >= 2:
                domain = parts[1].lower().rstrip(".")
                if DOMAIN_RE.match(domain):
                    domains.append(domain)
    return domains


PARSERS = {
    "v2fly":   parse_v2fly,
    "dnsmasq": parse_dnsmasq,
}


# ---------------------------------------------------------------------------
# Discovery file helpers
# ---------------------------------------------------------------------------
def load_existing(repo_root: Path) -> Set[str]:
    """Load all known domains across all three tiers."""
    known: Set[str] = set()
    for rel in (
        "sources/manual/seed_cn.txt",
        "sources/manual/extended.txt",
        "sources/manual/discovery.txt",
    ):
        path = repo_root / rel
        if not path.exists():
            continue
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip().lower()
            if line and not line.startswith("#"):
                known.add(line.rstrip("."))
    return known


def discovery_count(repo_root: Path) -> int:
    """Count current domains in discovery.txt."""
    path = repo_root / "sources" / "manual" / "discovery.txt"
    if not path.exists():
        return 0
    return sum(
        1 for l in path.read_text(encoding="utf-8").splitlines()
        if l.strip() and not l.strip().startswith("#")
    )


def append_to_discovery(repo_root: Path, domains: List[str], source_name: str) -> int:
    """Append new domains to discovery.txt. Returns count added."""
    path = repo_root / "sources" / "manual" / "discovery.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("# DomainNova - Discovery Layer\n", encoding="utf-8")

    with path.open("a", encoding="utf-8") as f:
        f.write(f"\n# --- upstream:{source_name} {time.strftime('%Y-%m-%d')} ---\n")
        for d in domains:
            f.write(d + "\n")
    return len(domains)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def run(repo_root: Path) -> None:
    session = make_session()
    existing = load_existing(repo_root)
    current_count = discovery_count(repo_root)

    print(f"[+] Known domains across all tiers: {len(existing)}")
    print(f"[+] Current discovery.txt count: {current_count}")

    # How much room is left before hitting 2000 cap
    # (build_domains.py enforces the hard cap, but we respect it here too)
    from build_domains import DISCOVERY_MAX  # reuse the constant
    capacity_left = max(0, DISCOVERY_MAX - current_count)
    budget = min(MAX_NEW_PER_RUN, capacity_left)

    if budget == 0:
        print("[!] discovery.txt is at capacity. Skipping fetch.")
        return

    print(f"[+] Budget for this run: {budget} new domains")

    total_added = 0
    for source in UPSTREAM_SOURCES:
        if total_added >= budget:
            break

        remaining = budget - total_added
        print(f"\n[+] Fetching {source['name']}...")

        try:
            resp = session.get(source["url"], timeout=30)
            resp.raise_for_status()
        except requests.RequestException as exc:
            print(f"  [warn] Failed to fetch {source['name']}: {exc}")
            continue

        parser = PARSERS.get(source["parser"])
        if not parser:
            print(f"  [warn] Unknown parser: {source['parser']}")
            continue

        all_domains = parser(resp.text)
        print(f"  Parsed {len(all_domains)} domains from {source['name']}")

        # Filter: not already known, not in exclude list
        new_domains = [
            d for d in all_domains
            if d not in existing
            and d not in EXCLUDE_DOMAINS
            and "." in d
        ]

        # Shuffle to avoid always picking the same domains
        import random
        random.shuffle(new_domains)

        # Take only what budget allows
        to_add = new_domains[:remaining]

        if to_add:
            added = append_to_discovery(repo_root, to_add, source["name"])
            # Update existing set so next source doesn't add duplicates
            existing.update(to_add)
            total_added += added
            print(f"  Added {added} new domains from {source['name']}")
        else:
            print(f"  No new domains from {source['name']}")

        # Brief pause between sources
        time.sleep(2)

    print(f"\n[+] Done. Total new domains added to discovery: {total_added}")
    print(f"[+] discovery.txt now has ~{current_count + total_added} domains")


if __name__ == "__main__":
    # Resolve repo root (two levels up from sources/discovery_agents/)
    repo_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repo_root / "sources" / "scripts"))
    try:
        run(repo_root)
    except KeyboardInterrupt:
        sys.exit(130)
