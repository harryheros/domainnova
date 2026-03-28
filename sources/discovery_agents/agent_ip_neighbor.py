#!/usr/bin/env python3
"""
agent_ip_neighbor.py - Reverse IP neighbor discovery for DomainNova.

Resolves seed domains to their CN IPs via Google DoH + ECS, then queries
HackerTarget Reverse IP API to find co-hosted domains on the same server.
These neighbors are high-confidence CN candidates since they share CN infrastructure.

Safety limits:
  - Max IPs queried per run:           50  (HackerTarget free: 100/day)
  - Max new domains added per run:     100
  - Max discovery.txt capacity:        2000 (enforced by build_domains.py)
  - Run frequency:                     monthly (enforced by update.yml)
  - Passive only, no active scanning

Usage:
  python sources/discovery_agents/agent_ip_neighbor.py
"""

from __future__ import annotations

import ipaddress
import random
import re
import sys
import time
from pathlib import Path
from typing import List, Optional, Set

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MAX_IPS_PER_RUN  = 50    # stay well within HackerTarget free limit (100/day)
MAX_NEW_PER_RUN  = 100   # hard limit on new domains added per run
SLEEP_BETWEEN_QUERIES = 2.5  # seconds between HackerTarget requests

DOH_URL    = "https://dns.google/resolve"
ECS_SUBNET = "114.114.114.0/24"

HACKERTARGET_URL = "https://api.hackertarget.com/reverseiplookup/"

USER_AGENT = "DomainNova/DiscoveryAgent (+https://github.com/harryheros/domainnova)"

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$"
)

EXCLUDE_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "twitter.com",
    "instagram.com", "whatsapp.com", "telegram.org",
    "bing.com", "microsoft.com", "apple.com", "icloud.com",
    "amazonaws.com", "cloudflare.com", "fastly.com",
    "akamai.com", "akamaiedge.net", "edgekey.net",
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
# DoH resolution
# ---------------------------------------------------------------------------
def resolve_to_ipv4(domain: str, session: requests.Session) -> List[str]:
    """Resolve domain to IPv4 addresses via Google DoH + ECS."""
    params = {
        "name":               domain,
        "type":               "A",
        "edns_client_subnet": ECS_SUBNET,
    }
    try:
        time.sleep(random.uniform(0.05, 0.15))
        resp = session.get(DOH_URL, params=params, timeout=10)
        if resp.status_code != 200:
            return []
        data = resp.json()
        return [
            ans["data"]
            for ans in data.get("Answer", [])
            if ans.get("type") == 1
        ]
    except requests.RequestException:
        return []


# ---------------------------------------------------------------------------
# ipnova CIDR check (reuse build_domains logic)
# ---------------------------------------------------------------------------
def fetch_cn_cidrs(session: requests.Session) -> List[ipaddress.IPv4Network]:
    url = "https://raw.githubusercontent.com/harryheros/ipnova/main/output/CN.txt"
    resp = session.get(url, timeout=30)
    resp.raise_for_status()
    networks = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            networks.append(ipaddress.IPv4Network(line, strict=False))
        except ValueError:
            continue
    return networks


def build_cidr_set(networks: List[ipaddress.IPv4Network]) -> set:
    """Build a flat set of network objects for membership testing."""
    return set(networks)


def is_cn_ip(ip_str: str, networks: List[ipaddress.IPv4Network]) -> bool:
    """Check if an IPv4 address falls within any CN CIDR."""
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in networks)


# ---------------------------------------------------------------------------
# HackerTarget Reverse IP
# ---------------------------------------------------------------------------
def reverse_ip_lookup(ip: str, session: requests.Session) -> List[str]:
    """
    Query HackerTarget Reverse IP API.
    Returns list of domains co-hosted on the given IP.
    Free tier returns up to 10 domains per IP.
    """
    try:
        resp = session.get(
            HACKERTARGET_URL,
            params={"q": ip},
            timeout=15,
        )
        if resp.status_code != 200:
            return []

        text = resp.text.strip()

        # HackerTarget returns "error" messages as plain text
        if text.startswith("error") or "API count exceeded" in text:
            print(f"  [warn] HackerTarget API limit hit: {text[:80]}")
            return []

        domains = []
        for line in text.splitlines():
            line = line.strip().lower()
            if DOMAIN_RE.match(line):
                domains.append(line)
        return domains

    except requests.RequestException as exc:
        print(f"  [warn] HackerTarget query failed for {ip}: {exc}")
        return []


# ---------------------------------------------------------------------------
# Discovery file helpers
# ---------------------------------------------------------------------------
def load_existing(repo_root: Path) -> Set[str]:
    known: Set[str] = set()
    for rel in (
        "sources/manual/seed.txt",
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
        f.write(f"\n# --- ip-neighbor:{source_tag} {time.strftime('%Y-%m-%d')} ---\n")
        for d in domains:
            f.write(d + "\n")
    return len(domains)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def run(repo_root: Path) -> None:
    session = make_session()

    print("[+] Fetching CN CIDR list from ipnova...")
    cn_networks = fetch_cn_cidrs(session)
    print(f"[+] Loaded {len(cn_networks)} CN CIDRs")

    existing     = load_existing(repo_root)
    current_disc = discovery_count(repo_root)

    print(f"[+] Known domains: {len(existing)}")
    print(f"[+] Current discovery.txt: {current_disc}")

    # Capacity check
    DISCOVERY_MAX = 2000
    capacity_left = max(0, DISCOVERY_MAX - current_disc)
    budget = min(MAX_NEW_PER_RUN, capacity_left)

    if budget == 0:
        print("[!] discovery.txt at capacity. Skipping.")
        return

    print(f"[+] Budget: {budget} new domains")

    # Load seed domains as the source of CN IPs to probe
    seed_path = repo_root / "sources" / "manual" / "seed.txt"
    if not seed_path.exists():
        print("[!] seed.txt not found. Exiting.")
        return

    seed_domains = [
        l.strip().lower()
        for l in seed_path.read_text(encoding="utf-8").splitlines()
        if l.strip() and not l.strip().startswith("#")
    ]

    # Shuffle seed domains for variety across runs
    random.shuffle(seed_domains)

    # Collect CN IPs from seed domains
    print(f"[+] Resolving seed domains to find CN IPs...")
    cn_ips: List[str] = []
    seen_ips: Set[str] = set()

    for domain in seed_domains:
        if len(cn_ips) >= MAX_IPS_PER_RUN:
            break
        ips = resolve_to_ipv4(domain, session)
        for ip in ips:
            if ip not in seen_ips and is_cn_ip(ip, cn_networks):
                seen_ips.add(ip)
                cn_ips.append(ip)

    print(f"[+] Found {len(cn_ips)} CN IPs to probe")

    if not cn_ips:
        print("[!] No CN IPs found. Exiting.")
        return

    # Query HackerTarget for each CN IP
    all_new: List[str] = []
    total_added = 0

    for ip in cn_ips:
        if total_added >= budget:
            break

        print(f"  Querying neighbors of {ip}...")
        neighbors = reverse_ip_lookup(ip, session)

        new = [
            d for d in neighbors
            if d not in existing
            and d not in EXCLUDE_DOMAINS
            and d not in all_new
            and "." in d
        ]

        if new:
            remaining = budget - total_added
            to_add = new[:remaining]
            added = append_to_discovery(repo_root, to_add, ip)
            existing.update(to_add)
            all_new.extend(to_add)
            total_added += added
            print(f"    +{added} new domains from {ip}")
        else:
            print(f"    No new domains from {ip}")

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
