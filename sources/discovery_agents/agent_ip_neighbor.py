#!/usr/bin/env python3
"""
agent_ip_neighbor.py - Reverse IP neighbor discovery for DomainNova.

Resolves seed domains to their CN IPs via Google DoH + ECS, then queries
Reverse IP APIs to find co-hosted domains on the same server.

Primary:  HackerTarget Reverse IP API (100 free queries/day)
Fallback: ViewDNS.info Reverse IP API  (automatic if HackerTarget fails)

Safety limits:
  - Max IPs queried per run:       50
  - Max new domains added per run: 100
  - Passive only, no active scanning
  - Run frequency: monthly
"""

from __future__ import annotations

import ipaddress
import random
import re
import sys
import time
from pathlib import Path
from typing import List, Optional, Set

# Shared agent helpers.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (  # noqa: E402
    DOMAIN_RE,
    EXCLUDE_DOMAINS,
    USER_AGENT,
    append_to_discovery,
    discovery_count,
    load_existing,
    make_session,
)

import requests  # noqa: E402

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MAX_IPS_PER_RUN       = 50
MAX_NEW_PER_RUN       = 100
SLEEP_BETWEEN_QUERIES = 2.5
DISCOVERY_MAX         = 2000

DOH_URL    = "https://dns.google/resolve"
ECS_SUBNET = "114.114.114.0/24"

HACKERTARGET_URL = "https://api.hackertarget.com/reverseiplookup/"
VIEWDNS_URL      = "https://api.viewdns.info/reverseip/"
VIEWDNS_APIKEY   = ""  # leave empty to use free web scrape fallback


# ---------------------------------------------------------------------------
# DoH resolution
# ---------------------------------------------------------------------------
def resolve_to_ipv4(domain: str, session: requests.Session) -> List[str]:
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
# ipnova CIDR check
# ---------------------------------------------------------------------------
def fetch_cn_cidrs(session: requests.Session) -> List[ipaddress.IPv4Network]:
    # IPNova v3.2.1+ ships header-free CIDR lists under output/plain/.
    # Older output/CN.txt still works (parser strips '#' lines), but the
    # plain/ variant is the canonical post-v3.2 path; using it keeps this
    # agent in lockstep with build_domains.py.
    url = "https://raw.githubusercontent.com/harryheros/ipnova/main/output/plain/CN.txt"
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


def is_cn_ip(ip_str: str, networks: List[ipaddress.IPv4Network]) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in networks)


# ---------------------------------------------------------------------------
# Reverse IP backends
# ---------------------------------------------------------------------------
def _parse_domains(text: str) -> List[str]:
    """Extract valid domains from plain-text response."""
    domains = []
    for line in text.splitlines():
        line = line.strip().lower()
        if DOMAIN_RE.match(line):
            domains.append(line)
    return domains


def hackertarget_lookup(ip: str, session: requests.Session) -> Optional[List[str]]:
    """
    Query HackerTarget. Returns domain list or None if limit hit / error.
    """
    try:
        resp = session.get(HACKERTARGET_URL, params={"q": ip}, timeout=15)
        if resp.status_code != 200:
            return None
        text = resp.text.strip()
        if "API count exceeded" in text or "error" in text[:30].lower():
            print(f"  [warn] HackerTarget limit/error: {text[:80]}")
            return None
        return _parse_domains(text)
    except requests.RequestException as exc:
        print(f"  [warn] HackerTarget failed for {ip}: {exc}")
        return None


def viewdns_lookup(ip: str, session: requests.Session) -> Optional[List[str]]:
    """
    Query ViewDNS.info Reverse IP.
    Uses JSON API if VIEWDNS_APIKEY is set, otherwise scrapes the free HTML page.
    """
    try:
        if VIEWDNS_APIKEY:
            # JSON API (requires key)
            resp = session.get(
                VIEWDNS_URL,
                params={"ip": ip, "apikey": VIEWDNS_APIKEY, "output": "json"},
                timeout=15,
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            domains = [
                entry.get("name", "").lower().strip()
                for entry in data.get("response", {}).get("domains", [])
            ]
            return [d for d in domains if DOMAIN_RE.match(d)]
        else:
            # Free HTML page scrape
            resp = session.get(
                "https://viewdns.info/reverseip/",
                params={"host": ip, "t": "1"},
                timeout=15,
            )
            if resp.status_code != 200:
                return None
            # Extract domains from HTML table cells
            found = re.findall(
                r'<td>([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?'
                r'(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)</td>',
                resp.text.lower()
            )
            return [d for d in found if DOMAIN_RE.match(d)]
    except requests.RequestException as exc:
        print(f"  [warn] ViewDNS failed for {ip}: {exc}")
        return None


def reverse_ip_lookup(ip: str, session: requests.Session) -> List[str]:
    """
    Try HackerTarget first, fall back to ViewDNS if needed.
    Returns empty list if both fail.
    """
    result = hackertarget_lookup(ip, session)
    if result is not None:
        return result

    print(f"  [info] Falling back to ViewDNS for {ip}...")
    time.sleep(1.0)
    result = viewdns_lookup(ip, session)
    if result is not None:
        return result

    print(f"  [warn] Both sources failed for {ip}")
    return []


# ---------------------------------------------------------------------------
# Discovery file helpers — provided by _common module.
# ---------------------------------------------------------------------------


def append_to_discovery_ipn(
    repo_root: Path, domains: List[str], source_tag: str
) -> int:
    """Thin wrapper over _common.append_to_discovery that prefixes the
    section tag with 'ip-neighbor:' for audit-trail clarity in discovery.txt."""
    return append_to_discovery(repo_root, domains, f"ip-neighbor:{source_tag}")


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

    capacity_left = max(0, DISCOVERY_MAX - current_disc)
    budget = min(MAX_NEW_PER_RUN, capacity_left)

    if budget == 0:
        print("[!] discovery.txt at capacity. Skipping.")
        return

    print(f"[+] Budget: {budget} new domains")

    seed_path = repo_root / "sources" / "manual" / "seed_cn.txt"
    if not seed_path.exists():
        print("[!] seed_cn.txt not found. Exiting.")
        return

    seed_domains = [
        l.strip().lower()
        for l in seed_path.read_text(encoding="utf-8").splitlines()
        if l.strip() and not l.strip().startswith("#")
    ]
    random.shuffle(seed_domains)

    print("[+] Resolving seed domains to find CN IPs...")
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
            and "." in d
        ]

        if new:
            remaining = budget - total_added
            to_add = new[:remaining]
            added = append_to_discovery_ipn(repo_root, to_add, ip)
            existing.update(to_add)
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
