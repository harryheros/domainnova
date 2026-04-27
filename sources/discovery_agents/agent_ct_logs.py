#!/usr/bin/env python3
"""
agent_ct_logs.py - Certificate Transparency log discovery for DomainNova.

Queries crt.sh to find domains with CN-related certificates:
  - Domains ending in .cn TLDs
  - Domains belonging to known CN organizations
  - Subdomains of known CN seed domains

This catches newly registered or updated CN infrastructure before it appears
in other public lists.

Safety limits:
  - Max queries per run:           5  (each returns up to ~100 results)
  - Max new domains added per run: 150
  - Rate limit: 3s between queries
  - Run frequency: monthly
"""

from __future__ import annotations

import json
import random
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
MAX_QUERIES_PER_RUN  = 5     # crt.sh queries per run
MAX_NEW_PER_RUN      = 150   # hard limit on new domains added
SLEEP_BETWEEN_QUERIES = 3.0  # seconds between crt.sh requests
DISCOVERY_MAX         = 2000

CRTSH_URL  = "https://crt.sh/"
USER_AGENT = "DomainNova/DiscoveryAgent (+https://github.com/harryheros/domainnova)"

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$"
)

# CN TLDs to search for new registrations
CN_TLDS = [".cn", ".com.cn", ".net.cn", ".org.cn", ".gov.cn"]

# Known CN organizations to search certificates for
CN_ORGS = [
    "Alibaba",
    "Tencent",
    "Baidu",
    "ByteDance",
    "Huawei",
    "Xiaomi",
    "JD.com",
    "Meituan",
    "NetEase",
    "China Telecom",
    "China Unicom",
    "China Mobile",
]

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
        backoff_factor=2.0,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": USER_AGENT})
    return session


# ---------------------------------------------------------------------------
# crt.sh queries
# ---------------------------------------------------------------------------
def query_crtsh(query: str, session: requests.Session) -> List[str]:
    """
    Query crt.sh for certificates matching the given pattern.
    Returns list of unique domain names found.
    """
    try:
        resp = session.get(
            CRTSH_URL,
            params={"q": query, "output": "json"},
            timeout=30,
        )
        if resp.status_code != 200:
            print(f"  [warn] crt.sh returned {resp.status_code} for {query}")
            return []

        data = resp.json()
        domains: Set[str] = set()

        for entry in data:
            # Each entry may have multiple names in name_value
            name_value = entry.get("name_value", "")
            for name in name_value.splitlines():
                name = name.strip().lower().lstrip("*.")
                if DOMAIN_RE.match(name):
                    domains.add(name)

        return list(domains)

    except (requests.RequestException, json.JSONDecodeError) as exc:
        print(f"  [warn] crt.sh query failed for {query}: {exc}")
        return []


def build_queries(repo_root: Path) -> List[str]:
    """
    Build a list of crt.sh queries based on:
    1. Random CN TLD patterns (recent 90 days)
    2. Random CN organization names
    3. Random seed domain subdomains
    """
    queries: List[str] = []

    # TLD-based: pick random CN TLDs
    tld_queries = [f"%.{tld.lstrip('.')}" for tld in CN_TLDS]
    random.shuffle(tld_queries)
    queries.extend(tld_queries[:2])

    # Org-based: pick random CN organizations
    org_queries = list(CN_ORGS)
    random.shuffle(org_queries)
    queries.extend(org_queries[:2])

    # Seed-based: pick random seed domains for subdomain discovery
    seed_path = repo_root / "sources" / "manual" / "seed_cn.txt"
    if seed_path.exists():
        seed_domains = [
            l.strip().lower()
            for l in seed_path.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]
        random.shuffle(seed_domains)
        queries.extend([f"%.{d}" for d in seed_domains[:1]])

    return queries[:MAX_QUERIES_PER_RUN]


# ---------------------------------------------------------------------------
# Discovery file helpers
# ---------------------------------------------------------------------------
def load_existing(repo_root: Path) -> Set[str]:
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
    path = repo_root / "sources" / "manual" / "discovery.txt"
    if not path.exists():
        return 0
    return sum(
        1 for l in path.read_text(encoding="utf-8").splitlines()
        if l.strip() and not l.strip().startswith("#")
    )


def append_to_discovery(
    repo_root: Path, domains: List[str], source_tag: str
) -> int:
    path = repo_root / "sources" / "manual" / "discovery.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("# DomainNova - Discovery Layer\n", encoding="utf-8")
    with path.open("a", encoding="utf-8") as f:
        f.write(f"\n# --- ct-logs:{source_tag} {time.strftime('%Y-%m-%d')} ---\n")
        for d in domains:
            f.write(d + "\n")
    return len(domains)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def run(repo_root: Path) -> None:
    session  = make_session()
    existing = load_existing(repo_root)
    current_disc = discovery_count(repo_root)

    print(f"[+] Known domains: {len(existing)}")
    print(f"[+] Current discovery.txt: {current_disc}")

    capacity_left = max(0, DISCOVERY_MAX - current_disc)
    budget = min(MAX_NEW_PER_RUN, capacity_left)

    if budget == 0:
        print("[!] discovery.txt at capacity. Skipping.")
        return

    print(f"[+] Budget: {budget} new domains")

    queries = build_queries(repo_root)
    print(f"[+] Running {len(queries)} crt.sh queries: {queries}")

    total_added = 0

    for query in queries:
        if total_added >= budget:
            break

        print(f"\n  Querying crt.sh: {query}")
        found = query_crtsh(query, session)
        print(f"  Found {len(found)} domains in certificates")

        new = [
            d for d in found
            if d not in existing
            and d not in EXCLUDE_DOMAINS
            and "." in d
        ]

        # Shuffle to avoid always picking the same results
        random.shuffle(new)

        if new:
            remaining = budget - total_added
            to_add = new[:remaining]
            added = append_to_discovery(repo_root, to_add, query)
            existing.update(to_add)
            total_added += added
            print(f"  +{added} new domains from '{query}'")
        else:
            print(f"  No new domains from '{query}'")

        time.sleep(SLEEP_BETWEEN_QUERIES)

    print(f"\n[+] Done. Added {total_added} new domains to discovery.txt")
    print(f"[+] discovery.txt now ~{current_disc + total_added} domains")


if __name__ == "__main__":
    repo_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repo_root / "sources" / "scripts"))
    try:
        run(repo_root)
    except KeyboardInterrupt:
        sys.exit(130)
