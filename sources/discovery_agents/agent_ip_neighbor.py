#!/usr/bin/env python3
"""
agent_ip_neighbor.py - Reverse IP neighbor discovery for DomainNova.

Resolves seed domains to their in-region IPs (through our own resolver
when DOMAINNOVA_DOH_URL is set, else Google DoH, with the China Telecom
client subnet), then queries Reverse IP APIs to find co-hosted domains on
the same server.

v3.9: every region in REGION_SLOTS, not only CN. The free reverse-IP quota
allows about 50 queries a run; they used to go to CN servers only, so HK,
MO, SG and TW grew only through link crawl. Each region now resolves its
own seeds (seed_<region>.txt) and keeps only addresses in its own IPNova
ranges; slots a region cannot fill go to the others, and queries alternate
between regions so that one region cannot spend the whole budget of new
domains. Seeds of every region are resolved with the same client subnet
as the build: an address the build would not place in the region (a CDN
edge that answers only clients there) would only find neighbours that
fail the build's own check.

Primary:  HackerTarget Reverse IP API (free tier, small daily quota)
Fallback: ViewDNS.info Reverse IP **JSON API**, only when the
          VIEWDNS_APIKEY environment variable is set (e.g. a repo secret).

v3.5: the key-less fallback used to scrape viewdns.info's HTML web page.
Automated scraping of a website from shared CI runners is the kind of
traffic that gets accounts flagged, and it was triggered for every IP once
HackerTarget's quota ran out. It has been removed. When the HackerTarget
quota is exhausted and no ViewDNS key is configured, the run stops early.

Safety limits:
  - Max IPs queried per run:       50, shared by region (REGION_SLOTS)
  - Max new domains added per run: 100
  - Shared hosting skipped (v3.8): an IP serving SHARED_HOST_MIN or more
    unrelated registrable domains is a virtual-hosting server, and its
    neighbours are strangers to the seed (hundreds of small, unrelated
    sites, many of them site farms); only IPs a few sites share are used
  - Passive only, no active scanning (never contacts the IPs themselves)
  - Run frequency: weekly (v3.6; was monthly)
"""

from __future__ import annotations

import bisect
import ipaddress
import os
import random
import struct
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Shared agent helpers.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (  # noqa: E402
    DOMAIN_RE,
    append_to_discovery,
    DISCOVERY_MAX,
    discovery_count,
    filter_candidates,
    load_existing,
    make_session,
    registrable,
)

import requests  # noqa: E402

import constants  # noqa: E402  (sources/scripts, put on sys.path by _common)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MAX_IPS_PER_RUN       = 50
MAX_NEW_PER_RUN       = 100
SLEEP_BETWEEN_QUERIES = 2.5
SHARED_HOST_MIN       = 20   # distinct registrable neighbours => shared hosting

# Reverse-IP queries per region (sum = MAX_IPS_PER_RUN). The smaller
# regions get more than their share of the dataset; CN has the most seeds
# and is also covered by link crawl. Unfilled slots go to other regions.
REGION_SLOTS: Dict[str, int] = {
    "CN": 15,
    "HK": 10,
    "SG": 10,
    "MO": 6,
    "TW": 6,
    "JP": 3,
}

DOH_URL    = "https://dns.google/resolve"
ECS_SUBNET = "114.114.114.0/24"
# A DNSNova server's ecs.client_path (RFC 8484), asked instead of Google
OWN_DOH    = os.environ.get("DOMAINNOVA_DOH_URL", "").strip()

HACKERTARGET_URL = "https://api.hackertarget.com/reverseiplookup/"
VIEWDNS_URL      = "https://api.viewdns.info/reverseip/"
VIEWDNS_APIKEY   = os.environ.get("VIEWDNS_APIKEY", "").strip()


class QuotaExhausted(Exception):
    """Raised when every configured reverse-IP backend is out of quota."""


# ---------------------------------------------------------------------------
# DoH resolution
# ---------------------------------------------------------------------------
def resolve_to_ipv4(domain: str, session: requests.Session,
                    subnet: str = ECS_SUBNET) -> List[str]:
    if OWN_DOH:
        return _resolve_own(domain, session, subnet)
    params = {
        "name":               domain,
        "type":               "A",
        "edns_client_subnet": subnet,
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


def _wire_query(domain: str, subnet: str) -> bytes:
    """An RFC 1035 A query with an EDNS Client Subnet option (RFC 7871)."""
    net = ipaddress.ip_network(subnet, strict=False)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in domain.strip(".").split(".")) + b"\x00"
    header = struct.pack(">HHHHHH", random.getrandbits(16), 0x0100, 1, 0, 0, 1)
    addr = net.network_address.packed[: (net.prefixlen + 7) // 8]
    ecs = struct.pack(">HBB", 1, net.prefixlen, 0) + addr
    opt = struct.pack(">HH", 8, len(ecs)) + ecs
    return header + qname + struct.pack(">HH", 1, 1) + b"\x00" + struct.pack(">HHIH", 41, 4096, 0, len(opt)) + opt


def _answer_ipv4(data: bytes) -> List[str]:
    """The A records in the answer section of a DNS response."""
    if len(data) < 12 or data[3] & 0x0F:
        return []
    qd, an = struct.unpack(">HH", data[4:8])
    pos = 12

    def skip_name(p: int) -> int:
        while p < len(data):
            n = data[p]
            if n == 0:
                return p + 1
            if n & 0xC0:
                return p + 2
            p += n + 1
        return p

    for _ in range(qd):
        pos = skip_name(pos) + 4
    out = []
    for _ in range(an):
        pos = skip_name(pos)
        if pos + 10 > len(data):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        if rtype == 1 and rdlen == 4 and pos + 4 <= len(data):
            out.append(".".join(str(b) for b in data[pos:pos + 4]))
        pos += rdlen
    return out


def _resolve_own(domain: str, session: requests.Session,
                 subnet: str = ECS_SUBNET) -> List[str]:
    try:
        time.sleep(random.uniform(0.05, 0.15))
        resp = session.post(OWN_DOH, data=_wire_query(domain, subnet), timeout=10,
                            headers={"Content-Type": "application/dns-message",
                                     "Accept": "application/dns-message"})
        if resp.status_code != 200:
            return []
        return _answer_ipv4(resp.content)
    except (requests.RequestException, ValueError):
        return []


# ---------------------------------------------------------------------------
# ipnova CIDR check
# ---------------------------------------------------------------------------
def fetch_region_cidrs(session: requests.Session, region: str) -> List[ipaddress.IPv4Network]:
    # The same IPNova plain/ lists build_domains.py uses (constants).
    url = constants.REGION_CIDR_URLS[region]
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


def fetch_cn_cidrs(session: requests.Session) -> List[ipaddress.IPv4Network]:
    return fetch_region_cidrs(session, "CN")


_NET_INDEX: dict = {}


def in_ranges(ip_str: str, networks: List[ipaddress.IPv4Network]) -> bool:
    """Binary-search membership test (v3.4 scanned ~5,600 networks per IP).
    The list is collapsed once and cached, so members are disjoint and the
    only candidate is the rightmost network starting at or below the IP."""
    try:
        addr = int(ipaddress.IPv4Address(ip_str))
    except ValueError:
        return False
    cached = _NET_INDEX.get(id(networks))
    if cached is None or cached[0] is not networks:
        nets = sorted(ipaddress.collapse_addresses(networks),
                      key=lambda n: int(n.network_address))
        cached = (networks,
                  [int(n.network_address) for n in nets],
                  [int(n.broadcast_address) for n in nets])
        _NET_INDEX[id(networks)] = cached
    _, starts, ends = cached
    i = bisect.bisect_right(starts, addr) - 1
    return i >= 0 and ends[i] >= addr


is_cn_ip = in_ranges  # the name before v3.9


def pick_ips(seeds: Dict[str, List[str]],
             networks: Dict[str, List[ipaddress.IPv4Network]],
             session) -> List[Tuple[str, str]]:
    """(region, ip) pairs to query, at most MAX_IPS_PER_RUN, alternating
    between regions. Each region resolves its own seeds and keeps only
    addresses in its own ranges, up to its slots; then regions with seeds
    left fill the slots others could not."""
    regions = [r for r in REGION_SLOTS if seeds.get(r) and networks.get(r)]
    pending = {r: list(seeds[r]) for r in regions}
    found: Dict[str, List[str]] = {r: [] for r in regions}
    seen: Set[str] = set()

    def take(region: str, want: int) -> None:
        while len(found[region]) < want and pending[region]:
            for ip in resolve_to_ipv4(pending[region].pop(0), session):
                if len(found[region]) >= want:
                    break
                if ip not in seen and in_ranges(ip, networks[region]):
                    seen.add(ip)
                    found[region].append(ip)

    for r in regions:
        take(r, REGION_SLOTS[r])
    left = MAX_IPS_PER_RUN - sum(len(v) for v in found.values())
    for r in regions:  # slots another region could not fill
        if left <= 0:
            break
        before = len(found[r])
        take(r, before + left)
        left -= len(found[r]) - before

    picked: List[Tuple[str, str]] = []
    for i in range(max((len(v) for v in found.values()), default=0)):
        picked += [(r, found[r][i]) for r in regions if i < len(found[r])]
    return picked[:MAX_IPS_PER_RUN]


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
        if "API count exceeded" in text:
            print(f"  [warn] HackerTarget quota exhausted: {text[:80]}")
            raise QuotaExhausted(text[:80])
        if "error" in text[:30].lower():
            print(f"  [warn] HackerTarget error: {text[:80]}")
            return None
        return _parse_domains(text)
    except requests.RequestException as exc:
        print(f"  [warn] HackerTarget failed for {ip}: {exc}")
        return None


def viewdns_lookup(ip: str, session: requests.Session) -> Optional[List[str]]:
    """
    Query the ViewDNS.info Reverse IP JSON API. Requires VIEWDNS_APIKEY;
    returns None without making any request when no key is configured.
    """
    if not VIEWDNS_APIKEY:
        return None
    try:
        resp = session.get(
            VIEWDNS_URL,
            params={"host": ip, "apikey": VIEWDNS_APIKEY, "output": "json"},
            timeout=15,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        domains = [
            str(entry.get("name", "")).lower().strip()
            for entry in (data.get("response", {}) or {}).get("domains", []) or []
            if isinstance(entry, dict)
        ]
        return [d for d in domains if DOMAIN_RE.match(d)]
    except (requests.RequestException, ValueError) as exc:
        print(f"  [warn] ViewDNS failed for {ip}: {exc}")
        return None


def reverse_ip_lookup(ip: str, session: requests.Session) -> List[str]:
    """
    Try HackerTarget first, then the ViewDNS JSON API (if a key is set).
    Raises QuotaExhausted when HackerTarget is out of quota and there is
    no ViewDNS key, so the caller stops instead of continuing to query.
    """
    try:
        result = hackertarget_lookup(ip, session)
    except QuotaExhausted:
        if not VIEWDNS_APIKEY:
            raise
        result = None
    if result is not None:
        return result

    if VIEWDNS_APIKEY:
        print(f"  [info] Falling back to ViewDNS API for {ip}...")
        time.sleep(1.0)
        result = viewdns_lookup(ip, session)
        if result is not None:
            return result

    print(f"  [warn] No reverse-IP result for {ip}")
    return []


def is_shared_host(neighbors: List[str]) -> bool:
    """True when the neighbours span SHARED_HOST_MIN or more registrable
    domains: a virtual-hosting server, not one organisation's machine."""
    return len({registrable(d) or d for d in neighbors}) >= SHARED_HOST_MIN


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

    manual = repo_root / "sources" / "manual"
    seeds: Dict[str, List[str]] = {}
    networks: Dict[str, List[ipaddress.IPv4Network]] = {}
    for region in REGION_SLOTS:
        path = manual / f"seed_{region.lower()}.txt"
        if not path.exists():
            continue
        try:
            networks[region] = fetch_region_cidrs(session, region)
        except (requests.RequestException, OSError, ValueError) as exc:
            print(f"[!] {region} ranges unavailable ({exc}); skipping {region}")
            continue
        listed = [
            l.strip().lower()
            for l in path.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]
        random.shuffle(listed)
        seeds[region] = listed
        print(f"[+] {region}: {len(listed)} seeds, {len(networks[region])} ranges")

    print("[+] Resolving seed domains to find in-region IPs...")
    targets = pick_ips(seeds, networks, session)
    by_region: Dict[str, int] = {}
    for r, _ in targets:
        by_region[r] = by_region.get(r, 0) + 1
    print(f"[+] Found {len(targets)} IPs to probe: "
          + ", ".join(f"{r} {n}" for r, n in by_region.items()))

    if not targets:
        print("[!] No in-region IPs found. Exiting.")
        return

    total_added = 0
    for region, ip in targets:
        if total_added >= budget:
            break

        print(f"  Querying neighbors of {ip} ({region})...")
        try:
            neighbors = reverse_ip_lookup(ip, session)
        except QuotaExhausted:
            print("[!] Reverse-IP quota exhausted and no VIEWDNS_APIKEY "
                  "configured; stopping early.")
            break

        if is_shared_host(neighbors):
            print(f"    Skipped {ip}: shared hosting "
                  f"({len({registrable(d) or d for d in neighbors})} unrelated domains)")
            time.sleep(SLEEP_BETWEEN_QUERIES)
            continue

        new = filter_candidates(neighbors, existing)

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
