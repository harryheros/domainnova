#!/usr/bin/env python3
"""
build_domains.py - DomainNova unified build pipeline.

v6.0 - Reliability & Accuracy Overhaul

Three-tier architecture:
  Core      (seed.txt)       read-only, manually curated, absolute trust
  Reliable  (extended.txt)   read-only by default, receives auto-promotions
  Discovery (discovery.txt)  read-write, auto-managed lifecycle

Discovery lifecycle rules:
  - Max capacity:    2000 domains (oldest purged when exceeded)
  - Auto-purge:      removed after 5 consecutive *definitive* CN-check failures
                     (empty DNS results are NOT counted as failures)
  - Auto-promote:    moved to extended after 4 consecutive CN-check passes
  - Promote suspend: when extended.txt reaches 3000 domains

Performance boundaries:
  - Max domains per run: 1500 (seed+extended full + discovery sample 300)
  - DoH workers:         20 threads
  - Per-request jitter:  0.05-0.15s
  - Discovery sample:    300 domains per run (rotated)

DNS: Google DoH (primary) + Cloudflare DoH + Quad9 ECS DoH (fallback)
     with ECS using CN Telecom DNS IPs for accurate GeoDNS.
     Note: Cloudflare does not support custom ECS param (privacy policy)
           but its anycast PoPs in CN still provide useful results.
IP classification: ipnova APNIC-sourced CN CIDR dataset

Scoring:
  - dns_cn=1 (≥60% of IPs in CN CIDR): base 60 pts + bonus
  - CN TLD fallback (.cn etc, requires ICP filing): 60 pts (included in dist)
  - No signal: 0 pts
"""

from __future__ import annotations

import concurrent.futures
import csv
import ipaddress
import json
import os
import random
import sys
import time
from collections import Counter
from dataclasses import dataclass, asdict, fields
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Hard limits (do not exceed these values)
# ---------------------------------------------------------------------------
DISCOVERY_MAX        = 2000   # max domains in discovery.txt
DISCOVERY_SAMPLE     = 300    # domains sampled from discovery per run
EXTENDED_MAX         = 3000   # suspend auto-promote when extended reaches this
PURGE_AFTER_FAILURES = 5      # consecutive CN failures before purge
PROMOTE_AFTER_PASSES = 4      # consecutive CN passes before promotion
DEAD_STREAK_THRESHOLD = 6     # consecutive empty-DNS runs before NS confirmation
MAX_WORKERS          = 20     # DoH thread pool size
JITTER_MIN           = 0.05   # seconds
JITTER_MAX           = 0.15   # seconds

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
IPNOVA_CN_URL = "https://raw.githubusercontent.com/harryheros/ipnova/main/output/CN.txt"

# DoH upstreams - primary Google, fallback Cloudflare & Quad9 ECS
# Note: Cloudflare (1.1.1.1) does NOT support custom edns_client_subnet param
#       but is included as a fallback for availability; its CN PoPs still help.
#       Quad9 ECS (dns11.quad9.net) follows Google's JSON schema and supports ECS.
# DoH upstreams - tiered by ECS capability
# Tier 0: self-hosted HK node with CN DNS upstream - rescues CN-only domains
#         whose authoritative servers refuse queries from overseas recursors.
# Primary pool: upstreams that honor our edns_client_subnet parameter.
#               These are queried first (round-robin) for accurate GeoDNS.
# Fallback pool: upstreams that ignore ECS but still resolve DNS.
#                Only used if ALL primaries fail for a given domain.
DOH_RESCUE = "https://nova.iohope.com/query"  # HK node, CN upstreams

DOH_PRIMARIES = [
    "https://dns.google/resolve",           # Google JSON API (ECS)
    "https://dns11.quad9.net/dns-query",    # Quad9 Secure with ECS
]

DOH_FALLBACKS = [
    "https://cloudflare-dns.com/dns-query", # Cloudflare (no ECS, privacy)
]

# Combined list (rescue + primaries + fallbacks) - for iteration/reference
DOH_UPSTREAMS = [DOH_RESCUE] + DOH_PRIMARIES + DOH_FALLBACKS

# Which upstreams support the edns_client_subnet query parameter?
DOH_ECS_SUPPORT = {
    DOH_RESCUE:                                  True,   # self-hosted, passes through
    "https://dns.google/resolve":                True,
    "https://dns11.quad9.net/dns-query":         True,
    "https://cloudflare-dns.com/dns-query":      False,
}

# Runtime-detected mode for the rescue endpoint: "json", "wire", or None (untested)
# Auto-detected on first use, then locked for the rest of the run.
_rescue_mode: Optional[str] = None
_rescue_mode_lock = Lock()

# ECS subnets - use actual China Telecom recursive DNS IPs as ECS hints.
# These are real ISP DNS server addresses that accurately represent
# the geographic location for GeoDNS purposes.
ECS_SUBNETS = [
    "219.141.140.0/24",  # Beijing Telecom DNS
    "116.228.111.0/24",  # Shanghai Telecom DNS
    "202.96.128.0/24",   # Guangdong Telecom DNS
]

DNS_WEIGHT        = 60
REGISTRAR_WEIGHT  = 20
REGISTRANT_WEIGHT = 20
CN_TLD_WEIGHT     = 10
INCLUDE_THRESHOLD = 60
CN_TLD_FALLBACK_SCORE = 60  # .cn requires ICP filing → strong CN signal

ENABLE_RDAP = os.getenv("DOMAINNOVA_RDAP", "0") == "1"

CN_TLDS = (".cn", ".xn--fiqs8s", ".xn--55qx5d", ".xn--io0a7i")

USER_AGENT = "DomainNova/BuildPipeline (+https://github.com/harryheros/domainnova)"

PRINT_LOCK   = Lock()
COUNTER_LOCK = Lock()
_doh_index   = 0


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class DomainRecord:
    domain:        str
    dns_cn:        int
    dns_cn_count:  int
    dns_total:     int
    registrar_cn:  int
    registrant_cn: int
    cn_tld:        int
    score:         int
    resolved_ips:  str
    matched_cidr:  str
    source:        str
    updated:       str
    sticky:        int = 0   # 1 if score was retained from previous run (DNS flake protection)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def log(msg: str) -> None:
    with PRINT_LOCK:
        print(msg, flush=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def normalize_domain(domain: str) -> str:
    raw = (domain or "").strip().rstrip(".").lower()
    if not raw:
        return raw
    try:
        return raw.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return raw


def cn_tld_flag(domain: str) -> int:
    return int(normalize_domain(domain).endswith(CN_TLDS))


def make_session() -> requests.Session:
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("https://", adapter)
    # Accept header is set per-request (JSON vs wireformat differs)
    session.headers.update({"User-Agent": USER_AGENT})
    return session


def next_doh_upstream() -> str:
    """Round-robin across ECS-capable primary DoH upstreams."""
    global _doh_index
    with COUNTER_LOCK:
        url = DOH_PRIMARIES[_doh_index % len(DOH_PRIMARIES)]
        _doh_index += 1
    return url


def random_ecs_subnet() -> str:
    """Pick a random CN ISP subnet for ECS to get region-accurate GeoDNS responses."""
    return random.choice(ECS_SUBNETS)


# ---------------------------------------------------------------------------
# ipnova CIDR loader
# ---------------------------------------------------------------------------
def fetch_cn_cidrs(session: requests.Session) -> List[ipaddress.IPv4Network]:
    log("[+] Fetching CN CIDR list from ipnova...")
    resp = session.get(IPNOVA_CN_URL, timeout=30)
    resp.raise_for_status()
    networks: List[ipaddress.IPv4Network] = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            networks.append(ipaddress.IPv4Network(line, strict=False))
        except ValueError:
            continue
    log(f"[+] Loaded {len(networks)} CN CIDRs")
    return networks


def build_cidr_lookup(networks: List[ipaddress.IPv4Network]) -> dict:
    from collections import defaultdict
    by_prefix: dict = defaultdict(list)
    for net in networks:
        by_prefix[net.prefixlen].append(
            (int(net.network_address), int(net.broadcast_address), str(net))
        )
    for pl in by_prefix:
        by_prefix[pl].sort()
    return dict(by_prefix)


def ip_in_cn_cidrs(ip_str: str, cidr_lookup: dict) -> Optional[str]:
    import bisect
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return None
    addr_int = int(addr)
    for prefix_len in sorted(cidr_lookup.keys(), reverse=True):
        entries = cidr_lookup[prefix_len]
        idx = bisect.bisect_right(entries, (addr_int, addr_int, "~")) - 1
        if idx >= 0:
            net_start, net_end, cidr_str = entries[idx]
            if net_start <= addr_int <= net_end:
                return cidr_str
    return None


# ---------------------------------------------------------------------------
# Three-tier source loader
# ---------------------------------------------------------------------------
def load_file_domains(path: Path) -> List[str]:
    """Load domains from a single source file, preserving order."""
    if not path.exists():
        return []
    out: List[str] = []
    seen: set = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        domain = normalize_domain(line)
        if domain and domain not in seen:
            seen.add(domain)
            out.append(domain)
    return out


def load_all_sources(repo_root: Path) -> List[Tuple[str, str]]:
    """
    Load all three tiers with priority deduplication (seed > extended > discovery).
    Discovery is sampled to DISCOVERY_SAMPLE domains per run (rotated by offset).
    Total domains processed per run is capped at seed+extended full + 300 discovery.
    """
    seed_path      = repo_root / "sources" / "manual" / "seed.txt"
    extended_path  = repo_root / "sources" / "manual" / "extended.txt"
    discovery_path = repo_root / "sources" / "manual" / "discovery.txt"

    seed_domains     = load_file_domains(seed_path)
    extended_domains = load_file_domains(extended_path)
    discovery_all    = load_file_domains(discovery_path)

    log(f"[+] Sources: seed={len(seed_domains)} extended={len(extended_domains)} "
        f"discovery={len(discovery_all)}")

    # Load rotation offset from stats
    stats_path = repo_root / "data" / "discovery_stats.json"
    stats = {}
    if stats_path.exists():
        try:
            stats = json.loads(stats_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass

    offset = stats.get("discovery_offset", 0)
    if discovery_all:
        offset = offset % len(discovery_all)
        # Rotate and sample
        rotated = discovery_all[offset:] + discovery_all[:offset]
        discovery_sample = rotated[:DISCOVERY_SAMPLE]
        next_offset = (offset + DISCOVERY_SAMPLE) % len(discovery_all)
    else:
        discovery_sample = []
        next_offset = 0

    stats["discovery_offset"] = next_offset

    # Priority deduplication
    domain_map: Dict[str, str] = {}
    for domain in seed_domains:
        domain_map[domain] = "seed"
    for domain in extended_domains:
        if domain not in domain_map:
            domain_map[domain] = "extended"
    for domain in discovery_sample:
        if domain not in domain_map:
            domain_map[domain] = "discovery"

    # Save updated offset
    stats_path.parent.mkdir(parents=True, exist_ok=True)
    stats_path.write_text(
        json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    result = list(domain_map.items())
    log(f"[+] This run: {len(result)} domains "
        f"(discovery sample {len(discovery_sample)}/{len(discovery_all)}, "
        f"offset {offset}→{next_offset})")
    return result


# ---------------------------------------------------------------------------
# DNS resolution (Rescue + Google / Quad9 / Cloudflare DoH + ECS)
# ---------------------------------------------------------------------------
def _encode_dns_wire_query(domain: str, ecs_subnet: Optional[str] = None) -> bytes:
    """
    Build a minimal RFC 1035 DNS query for A record, with optional ECS (RFC 7871).
    Returns raw wireformat bytes suitable for RFC 8484 DoH POST/GET.
    """
    import struct
    # Header: ID=0 (DoH caches by content), flags=0x0100 (RD), QD=1, AN=0, NS=0, AR=1 if ECS else 0
    ar_count = 1 if ecs_subnet else 0
    header = struct.pack(">HHHHHH", 0, 0x0100, 1, 0, 0, ar_count)

    # Question section: QNAME + QTYPE(A=1) + QCLASS(IN=1)
    qname = b""
    for label in domain.rstrip(".").split("."):
        lb = label.encode("ascii")
        qname += bytes([len(lb)]) + lb
    qname += b"\x00"
    question = qname + struct.pack(">HH", 1, 1)

    # Optional OPT RR with ECS option
    additional = b""
    if ecs_subnet:
        ip_str, _, prefix_str = ecs_subnet.partition("/")
        prefix = int(prefix_str) if prefix_str else 32
        ip_bytes = ipaddress.IPv4Address(ip_str).packed
        # Truncate address bytes to cover the prefix (round up to whole bytes)
        addr_bytes_needed = (prefix + 7) // 8
        addr_payload = ip_bytes[:addr_bytes_needed]
        # ECS option data: family(IPv4=1) + source_prefix + scope_prefix(0) + address
        ecs_data = struct.pack(">HBB", 1, prefix, 0) + addr_payload
        # OPT option: code(ECS=8) + length + data
        opt_rdata = struct.pack(">HH", 8, len(ecs_data)) + ecs_data
        # OPT RR: name=root + type=OPT(41) + class=udp_size(4096)
        #         + ttl(ext_rcode+version+flags=0) + rdlength + rdata
        additional = b"\x00" + struct.pack(">HHIH", 41, 4096, 0, len(opt_rdata)) + opt_rdata

    return header + question + additional


def _decode_dns_wire_answer(data: bytes) -> List[str]:
    """
    Parse a DNS wireformat response and extract A record IPs.
    Minimal implementation - handles name compression for answer names.
    """
    import struct
    if len(data) < 12:
        return []
    _id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(">HHHHHH", data[:12])
    # Check RCODE (low 4 bits of flags) - non-zero means error
    if flags & 0x000F:
        return []
    pos = 12

    # Skip question section
    for _ in range(qdcount):
        # Skip QNAME
        while pos < len(data):
            length = data[pos]
            if length == 0:
                pos += 1
                break
            if length & 0xC0:  # compression pointer
                pos += 2
                break
            pos += length + 1
        pos += 4  # QTYPE + QCLASS

    # Parse answer section
    ips: List[str] = []
    for _ in range(ancount):
        if pos + 12 > len(data):
            break
        # Skip NAME (may be a pointer)
        if data[pos] & 0xC0:
            pos += 2
        else:
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    pos += 1
                    break
                if length & 0xC0:
                    pos += 2
                    break
                pos += length + 1
        if pos + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        if rtype == 1 and rdlength == 4 and pos + 4 <= len(data):
            ip = ".".join(str(b) for b in data[pos:pos + 4])
            ips.append(ip)
        pos += rdlength
    return sorted(set(ips))


def _resolve_via_json(domain: str, upstream: str, session: requests.Session,
                     use_ecs: bool) -> Tuple[bool, List[str]]:
    """
    Query a DoH upstream using JSON API format.
    Returns (http_ok, ips). http_ok=False means the server rejected JSON mode.
    """
    params: dict = {"name": domain, "type": "A"}
    if use_ecs:
        params["edns_client_subnet"] = random_ecs_subnet()
    try:
        time.sleep(random.uniform(JITTER_MIN, JITTER_MAX))
        resp = session.get(upstream, params=params, timeout=10,
                           headers={"Accept": "application/dns-json"})
        if resp.status_code != 200:
            return False, []
        data = resp.json()
        ips = sorted(set(
            ans["data"]
            for ans in data.get("Answer", [])
            if ans.get("type") == 1
        ))
        return True, ips
    except (requests.RequestException, ValueError):
        return False, []


def _resolve_via_wire(domain: str, upstream: str, session: requests.Session,
                      use_ecs: bool) -> Tuple[bool, List[str]]:
    """
    Query a DoH upstream using RFC 8484 wireformat (POST).
    Returns (http_ok, ips).
    """
    ecs = random_ecs_subnet() if use_ecs else None
    try:
        wire = _encode_dns_wire_query(domain, ecs_subnet=ecs)
        time.sleep(random.uniform(JITTER_MIN, JITTER_MAX))
        resp = session.post(upstream, data=wire, timeout=10,
                            headers={
                                "Accept":       "application/dns-message",
                                "Content-Type": "application/dns-message",
                            })
        if resp.status_code != 200:
            return False, []
        return True, _decode_dns_wire_answer(resp.content)
    except requests.RequestException:
        return False, []


def _resolve_rescue(domain: str, session: requests.Session) -> List[str]:
    """
    Query the rescue (self-hosted HK) DoH endpoint.
    Auto-detects JSON vs wireformat mode on first successful call, then locks.
    """
    global _rescue_mode
    mode = _rescue_mode
    use_ecs = DOH_ECS_SUPPORT.get(DOH_RESCUE, False)

    if mode == "json":
        _ok, ips = _resolve_via_json(domain, DOH_RESCUE, session, use_ecs)
        return ips
    if mode == "wire":
        _ok, ips = _resolve_via_wire(domain, DOH_RESCUE, session, use_ecs)
        return ips

    # Mode not yet detected - try JSON first, then wire
    ok, ips = _resolve_via_json(domain, DOH_RESCUE, session, use_ecs)
    if ok:
        with _rescue_mode_lock:
            if _rescue_mode is None:
                _rescue_mode = "json"
                log(f"  [info] Rescue endpoint mode detected: JSON API")
        return ips
    ok, ips = _resolve_via_wire(domain, DOH_RESCUE, session, use_ecs)
    if ok:
        with _rescue_mode_lock:
            if _rescue_mode is None:
                _rescue_mode = "wire"
                log(f"  [info] Rescue endpoint mode detected: RFC 8484 wireformat")
        return ips
    return []


def _do_resolve(domain: str, upstream: str, session: requests.Session) -> List[str]:
    """Single-upstream resolve attempt (JSON API mode, for public DoH)."""
    _ok, ips = _resolve_via_json(
        domain, upstream, session, DOH_ECS_SUPPORT.get(upstream, False)
    )
    return ips


def resolve_domain(domain: str, session: requests.Session) -> List[str]:
    domain = normalize_domain(domain)
    if not domain:
        return []
    # Tier 0: self-hosted HK rescue endpoint (CN upstreams, highest priority)
    ips = _resolve_rescue(domain, session)
    if ips:
        return ips
    # Tier 1: try ECS-capable primary (round-robin selection)
    primary = next_doh_upstream()
    ips = _do_resolve(domain, primary, session)
    if ips:
        return ips
    # Tier 2: try the other ECS-capable primary
    for upstream in DOH_PRIMARIES:
        if upstream == primary:
            continue
        ips = _do_resolve(domain, upstream, session)
        if ips:
            return ips
    # Tier 3: fallback to non-ECS upstreams (Cloudflare etc.)
    # These won't have GeoDNS accuracy but prevent total resolution failure.
    for upstream in DOH_FALLBACKS:
        ips = _do_resolve(domain, upstream, session)
        if ips:
            return ips
    log(f"  [warn] All DoH upstreams failed for {domain}")
    return []


# ---------------------------------------------------------------------------
# Signal aggregation
# ---------------------------------------------------------------------------
def build_dns_signal(
    ips: List[str], cidr_lookup: dict
) -> Tuple[int, int, int, str]:
    if not ips:
        return 0, 0, 0, ""
    cn_count = 0
    matched_cidrs: List[str] = []
    ipv4_total = 0
    for ip in ips:
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        ipv4_total += 1
        cidr = ip_in_cn_cidrs(ip, cidr_lookup)
        if cidr:
            cn_count += 1
            matched_cidrs.append(cidr)
    dns_total = len(ips)
    dns_cn    = int(ipv4_total > 0 and (cn_count / ipv4_total) >= 0.60)
    matched   = "|".join(list(dict.fromkeys(matched_cidrs))[:5])
    return dns_cn, cn_count, dns_total, matched


def score_record(
    dns_cn: int, registrar_cn: int, registrant_cn: int, cn_tld: int,
    has_ips: bool = True,
) -> int:
    """
    Scoring model:
      Normal path (dns_cn=1): 60 + up to 40 bonus = max 100
      CN TLD fallback (dns_cn=0, cn_tld=1): CN_TLD_FALLBACK_SCORE (60)
        - .cn domains require ICP filing under MIIT regulation,
          confirming mainland CN business entity regardless of CDN placement.
        - Score 60 includes them in dist/domains.txt (ICP is strong signal).
      No signal: 0
    """
    if dns_cn:
        return min(100,
            dns_cn        * DNS_WEIGHT
            + registrar_cn  * REGISTRAR_WEIGHT
            + registrant_cn * REGISTRANT_WEIGHT
            + cn_tld        * CN_TLD_WEIGHT
        )
    if cn_tld:
        # ICP-backed fallback: .cn requires government filing → strong CN signal
        return CN_TLD_FALLBACK_SCORE
    return 0


# ---------------------------------------------------------------------------
# Previous-run loader (for sticky score fallback on DNS flakes)
# ---------------------------------------------------------------------------
def load_previous_rows(path: Path) -> Dict[str, DomainRecord]:
    """
    Load the previous run's data/domains.csv into a {domain: DomainRecord} map.

    Used by process_domain() to protect against DNS flakes: if a domain that
    previously scored >= INCLUDE_THRESHOLD suddenly fails to resolve in the
    current run, we retain the previous score and mark the row as sticky=1
    instead of dropping it from dist/domains.txt.

    Returns an empty dict if the file does not exist or is unreadable, so the
    first-ever build (or a wiped data dir) still works.
    """
    if not path.exists():
        return {}
    prev: Dict[str, DomainRecord] = {}
    try:
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    prev[row["domain"]] = DomainRecord(
                        domain=row["domain"],
                        dns_cn=int(row.get("dns_cn", 0) or 0),
                        dns_cn_count=int(row.get("dns_cn_count", 0) or 0),
                        dns_total=int(row.get("dns_total", 0) or 0),
                        registrar_cn=int(row.get("registrar_cn", 0) or 0),
                        registrant_cn=int(row.get("registrant_cn", 0) or 0),
                        cn_tld=int(row.get("cn_tld", 0) or 0),
                        score=int(row.get("score", 0) or 0),
                        resolved_ips=row.get("resolved_ips", "") or "",
                        matched_cidr=row.get("matched_cidr", "") or "",
                        source=row.get("source", "") or "",
                        updated=row.get("updated", "") or "",
                        sticky=int(row.get("sticky", 0) or 0),
                    )
                except (ValueError, KeyError):
                    # Skip malformed row; never let one bad line break the build
                    continue
    except OSError:
        return {}
    return prev


# ---------------------------------------------------------------------------
# Per-domain processor (runs in thread pool)
# ---------------------------------------------------------------------------
def process_domain(
    domain: str,
    source: str,
    session: requests.Session,
    cidr_lookup: dict,
    updated: str,
    previous: Optional[Dict[str, DomainRecord]] = None,
) -> DomainRecord:
    ips = resolve_domain(domain, session)
    dns_cn, dns_cn_count, dns_total, matched_cidr = build_dns_signal(ips, cidr_lookup)
    tld_flag = cn_tld_flag(domain)
    score    = score_record(dns_cn, 0, 0, tld_flag, has_ips=bool(ips))

    # Sticky fallback: if this run couldn't resolve any IPs AND the previous
    # run had the domain qualified (score >= threshold), keep the old signals.
    # This prevents transient DNS outages from wiping good domains out of dist.
    # We only stick on a hard resolution failure (no IPs) — if we DID resolve
    # IPs but they're no longer in CN CIDRs, that's a real signal change and
    # we let it through.
    sticky_flag = 0
    if previous and not ips:
        prev = previous.get(domain)
        if prev and prev.score >= INCLUDE_THRESHOLD:
            return DomainRecord(
                domain=domain,
                dns_cn=prev.dns_cn,
                dns_cn_count=prev.dns_cn_count,
                dns_total=prev.dns_total,
                registrar_cn=prev.registrar_cn,
                registrant_cn=prev.registrant_cn,
                cn_tld=prev.cn_tld,
                score=prev.score,
                resolved_ips=prev.resolved_ips,
                matched_cidr=prev.matched_cidr,
                source=source,          # source may have been reclassified
                updated=prev.updated,   # keep stale date to signal non-refresh
                sticky=1,
            )

    return DomainRecord(
        domain=domain,
        dns_cn=dns_cn,
        dns_cn_count=dns_cn_count,
        dns_total=dns_total,
        registrar_cn=0,
        registrant_cn=0,
        cn_tld=tld_flag,
        score=score,
        resolved_ips="|".join(ips),
        matched_cidr=matched_cidr,
        source=source,
        updated=updated,
        sticky=sticky_flag,
    )


# ---------------------------------------------------------------------------
# Discovery lifecycle management
# ---------------------------------------------------------------------------
def load_discovery_stats(repo_root: Path) -> dict:
    path = repo_root / "data" / "discovery_stats.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_discovery_stats(repo_root: Path, stats: dict) -> None:
    path = repo_root / "data" / "discovery_stats.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(stats, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def manage_discovery_lifecycle(
    repo_root: Path,
    rows: List[DomainRecord],
) -> Tuple[List[str], List[str]]:
    """
    Apply auto-purge and auto-promote rules to discovery domains.

    Purge rules:
      - PURGE_AFTER_FAILURES consecutive CN failures -> remove from discovery.txt

    Promote rules:
      - PROMOTE_AFTER_PASSES consecutive CN passes -> move to extended.txt
      - Suspended when extended.txt has >= EXTENDED_MAX domains

    Returns: (purged_list, promoted_list)
    """
    discovery_path = repo_root / "sources" / "manual" / "discovery.txt"
    extended_path  = repo_root / "sources" / "manual" / "extended.txt"

    if not discovery_path.exists():
        return [], []

    stats = load_discovery_stats(repo_root)
    hit_counts  = stats.get("hit_counts",  {})   # domain -> consecutive passes
    fail_counts = stats.get("fail_counts", {})   # domain -> consecutive failures

    # Check extended capacity
    extended_domains = load_file_domains(extended_path)
    promote_suspended = len(extended_domains) >= EXTENDED_MAX
    if promote_suspended:
        log(f"  [info] Auto-promote suspended: extended.txt at {len(extended_domains)} "
            f"(limit {EXTENDED_MAX})")

    purged:   List[str] = []
    promoted: List[str] = []

    for row in rows:
        if row.source != "discovery":
            continue
        domain = row.domain

        if row.dns_cn == 1:
            # Passed CN check
            hit_counts[domain]  = hit_counts.get(domain, 0) + 1
            fail_counts.pop(domain, None)

            if not promote_suspended and hit_counts[domain] >= PROMOTE_AFTER_PASSES:
                promoted.append(domain)
                hit_counts.pop(domain, None)
                fail_counts.pop(domain, None)
        elif row.dns_total == 0:
            # DNS returned nothing (timeout / NXDOMAIN / all upstreams failed)
            # Treat as "unknown" — do NOT count as a failure.
            # This prevents legitimate domains with flaky DNS from being purged.
            pass
        else:
            # Resolved to IPs but none matched CN CIDRs → definitive failure
            fail_counts[domain] = fail_counts.get(domain, 0) + 1
            hit_counts.pop(domain, None)

            if fail_counts[domain] >= PURGE_AFTER_FAILURES:
                purged.append(domain)
                fail_counts.pop(domain, None)

    to_remove = set(purged) | set(promoted)

    # Rewrite discovery.txt
    if to_remove:
        lines = discovery_path.read_text(encoding="utf-8").splitlines()
        kept = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                kept.append(line)
            elif normalize_domain(stripped) not in to_remove:
                kept.append(line)
        discovery_path.write_text("\n".join(kept) + "\n", encoding="utf-8")

    # Enforce DISCOVERY_MAX capacity (remove oldest entries)
    remaining = load_file_domains(discovery_path)
    if len(remaining) > DISCOVERY_MAX:
        excess = len(remaining) - DISCOVERY_MAX
        to_evict = set(remaining[:excess])  # oldest are at the top
        lines = discovery_path.read_text(encoding="utf-8").splitlines()
        kept = []
        evicted_count = 0
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                kept.append(line)
            elif normalize_domain(stripped) in to_evict and evicted_count < excess:
                evicted_count += 1  # drop this line
            else:
                kept.append(line)
        discovery_path.write_text("\n".join(kept) + "\n", encoding="utf-8")
        log(f"  [info] Evicted {evicted_count} oldest discovery domains "
            f"(capacity limit {DISCOVERY_MAX})")

    # Append promoted domains to extended.txt
    if promoted:
        with extended_path.open("a", encoding="utf-8") as f:
            f.write(f"\n# ===== Auto-promoted {time.strftime('%Y-%m-%d')} =====\n")
            for d in sorted(promoted):
                f.write(d + "\n")

    # Save updated stats
    stats["hit_counts"]  = hit_counts
    stats["fail_counts"] = fail_counts
    save_discovery_stats(repo_root, stats)

    return purged, promoted


# ---------------------------------------------------------------------------
# Dead domain auto-detection
# ---------------------------------------------------------------------------
def _query_ns_record(domain: str, session: requests.Session) -> bool:
    """
    Check if a domain has ANY NS record via overseas DoH.
    Returns True if NS records exist (domain is registered), False otherwise.

    NS records are returned by the TLD servers themselves, so they are NOT
    subject to the geo-blocking that affects A records. If Google DoH cannot
    find any NS record for a domain, it means the domain is truly dead
    (expired, deleted, or never existed).

    Uses Google DoH JSON API directly (type=NS). Short timeout to avoid
    blocking the pipeline on dead domains.
    """
    try:
        time.sleep(random.uniform(JITTER_MIN, JITTER_MAX))
        resp = session.get(
            "https://dns.google/resolve",
            params={"name": domain, "type": "NS"},
            timeout=5,
            headers={"Accept": "application/dns-json"},
        )
        if resp.status_code != 200:
            return True  # On HTTP error, play safe and assume alive
        data = resp.json()
        # Status 0 = NOERROR, 3 = NXDOMAIN
        status = data.get("Status", 0)
        if status == 3:
            return False  # NXDOMAIN: definitively dead
        # Look for NS records in Answer or Authority section
        # (some TLDs return NS in Authority rather than Answer)
        for section in ("Answer", "Authority"):
            for rec in data.get(section, []):
                if rec.get("type") == 2:  # NS record type
                    return True
        return False
    except (requests.RequestException, ValueError):
        # On network error, play safe and assume alive (don't accidentally purge)
        return True


def detect_dead_domains(
    repo_root: Path,
    rows: List[DomainRecord],
    session: requests.Session,
) -> List[str]:
    """
    Detect and remove truly dead domains from extended.txt and discovery.txt.

    Dead = dns_total==0 for DEAD_STREAK_THRESHOLD consecutive runs AND
           NS record confirmation also fails (domain not registered at all).

    Seed.txt is NEVER touched - seed is hand-curated, absolute trust.

    Returns: list of removed domain names.
    """
    stats = load_discovery_stats(repo_root)
    dead_streak: dict = stats.get("dead_streak", {})

    # 1. Update dead_streak counters based on this run's results
    candidates_for_ns_check: List[str] = []
    for row in rows:
        if row.source == "seed":
            continue  # Never touch seed
        if row.source not in ("extended", "discovery"):
            continue

        domain = row.domain
        if row.sticky:
            # Sticky rows are protected: this run had a DNS flake but we
            # retained the previous qualified score. Do NOT count this as
            # a dead-streak increment, otherwise transient resolver issues
            # (e.g. a VPS line change) will accumulate and trigger physical
            # removal from extended.txt / discovery.txt.
            dead_streak.pop(domain, None)
            continue
        if row.dns_total == 0:
            # No IPs at all this run
            dead_streak[domain] = dead_streak.get(domain, 0) + 1
            if dead_streak[domain] >= DEAD_STREAK_THRESHOLD:
                candidates_for_ns_check.append(domain)
        else:
            # Got some IPs - definitely alive, reset streak
            dead_streak.pop(domain, None)

    if not candidates_for_ns_check:
        stats["dead_streak"] = dead_streak
        save_discovery_stats(repo_root, stats)
        return []

    log(f"[+] Dead domain check: {len(candidates_for_ns_check)} candidates "
        f"(streak >= {DEAD_STREAK_THRESHOLD})")

    # 2. Parallel NS queries to confirm which are truly dead
    confirmed_dead: List[str] = []
    rescued: List[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_map = {
            executor.submit(_query_ns_record, d, session): d
            for d in candidates_for_ns_check
        }
        for future in concurrent.futures.as_completed(future_map):
            domain = future_map[future]
            try:
                has_ns = future.result()
            except Exception:
                has_ns = True  # On error, play safe
            if has_ns:
                # Domain is registered, just geo-blocked. Rescue it.
                rescued.append(domain)
                dead_streak.pop(domain, None)
            else:
                # NS query confirmed: domain is truly dead
                confirmed_dead.append(domain)
                dead_streak.pop(domain, None)

    if rescued:
        log(f"  [info] Rescued {len(rescued)} domains (NS records exist, "
            f"treating as geo-blocked not dead)")

    if not confirmed_dead:
        stats["dead_streak"] = dead_streak
        save_discovery_stats(repo_root, stats)
        return []

    # 3. Remove confirmed-dead domains from extended.txt and discovery.txt
    dead_set = set(confirmed_dead)
    dead_by_source: Dict[str, List[str]] = {"extended": [], "discovery": []}
    for row in rows:
        if row.domain in dead_set and row.source in dead_by_source:
            dead_by_source[row.source].append(row.domain)

    for source_name, file_name in [("extended", "extended.txt"),
                                    ("discovery", "discovery.txt")]:
        to_remove = set(dead_by_source[source_name])
        if not to_remove:
            continue
        path = repo_root / "sources" / "manual" / file_name
        if not path.exists():
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        kept = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                kept.append(line)
            elif normalize_domain(stripped) not in to_remove:
                kept.append(line)
        path.write_text("\n".join(kept) + "\n", encoding="utf-8")
        log(f"  [info] Removed {len(to_remove)} dead domains from {file_name}")

    # 4. Append to dead_domains.log for audit trail
    log_path = repo_root / "data" / "dead_domains.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())
    with log_path.open("a", encoding="utf-8") as f:
        for domain in sorted(confirmed_dead):
            # Find the source this domain came from
            src = next((s for s in ("extended", "discovery")
                        if domain in dead_by_source[s]), "unknown")
            f.write(f"{timestamp}\t{src}\t{domain}\n")

    stats["dead_streak"] = dead_streak
    save_discovery_stats(repo_root, stats)
    return confirmed_dead


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------
def write_csv(path: Path, rows: List[DomainRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[fd.name for fd in fields(rows[0])])
        writer.writeheader()
        for r in rows:
            writer.writerow(asdict(r))


def write_dist(path: Path, rows: List[DomainRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    included = [r.domain for r in rows if r.score >= INCLUDE_THRESHOLD]
    path.write_text(
        "\n".join(included) + ("\n" if included else ""), encoding="utf-8"
    )


def write_stats(path: Path, rows: List[DomainRecord], extra: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    score_bands:   Counter = Counter()
    source_counts: Counter = Counter()
    for r in rows:
        source_counts[r.source] += 1
        if r.score >= 60:
            if r.dns_cn == 1:
                score_bands["cn_dns"] += 1
            else:
                score_bands["cn_tld"] += 1  # .cn ICP-backed, included in dist
        elif r.score >= 30:
            score_bands["gray"] += 1
        else:
            score_bands["non_cn"] += 1
    payload = {
        "total_domains":     len(rows),
        "dist_domains":      sum(1 for r in rows if r.score >= INCLUDE_THRESHOLD),
        "seed_domains":      source_counts.get("seed", 0),
        "extended_domains":  source_counts.get("extended", 0),
        "discovery_domains": source_counts.get("discovery", 0),
        "score_bands":       dict(score_bands),
        "source_counts":     dict(source_counts),
        "generated_at":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **extra,
    }
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
def build(repo_root: Path) -> None:
    data_csv   = repo_root / "data" / "domains.csv"
    stats_json = repo_root / "data" / "stats.json"
    dist_txt   = repo_root / "dist" / "domains.txt"

    session     = make_session()
    cn_networks = fetch_cn_cidrs(session)
    cidr_lookup = build_cidr_lookup(cn_networks)

    # Load previous run for sticky fallback (protects against DNS flakes)
    previous = load_previous_rows(data_csv)
    if previous:
        log(f"[+] Loaded {len(previous)} previous records for sticky fallback")

    domains = load_all_sources(repo_root)
    log(f"[+] Processing {len(domains)} domains with {MAX_WORKERS} workers...")

    updated = time.strftime("%Y-%m-%d")
    rows:   List[DomainRecord] = []
    errors = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {
            executor.submit(
                process_domain, domain, source, session, cidr_lookup, updated, previous
            ): domain
            for domain, source in domains
        }
        done = 0
        for future in concurrent.futures.as_completed(future_map):
            done += 1
            try:
                rows.append(future.result())
                if done % 200 == 0:
                    log(f"  [{done}/{len(domains)}] processed...")
            except Exception as exc:
                errors += 1
                log(f"  [error] {future_map[future]}: {exc}")

    # Sort: seed first, then extended, then discovery; alphabetical within each
    source_order = {"seed": 0, "extended": 1, "discovery": 2}
    rows.sort(key=lambda r: (source_order.get(r.source, 9), r.domain))

    # Discovery lifecycle
    purged, promoted = manage_discovery_lifecycle(repo_root, rows)
    if purged:
        log(f"[+] Purged {len(purged)} discovery domains (failed CN check)")
    if promoted:
        log(f"[+] Promoted {len(promoted)} discovery domains -> extended")

    # Dead domain auto-detection (NS-confirmed)
    dead = detect_dead_domains(repo_root, rows, session)
    if dead:
        log(f"[+] Removed {len(dead)} dead domains (NS confirmed non-existent)")

    write_csv(data_csv, rows)
    write_dist(dist_txt, rows)
    sticky_count = sum(1 for r in rows if r.sticky)
    write_stats(stats_json, rows, extra={
        "auto_purged":        len(purged),
        "auto_promoted":      len(promoted),
        "auto_dead_removed":  len(dead),
        "processing_errors":  errors,
        "sticky_retained":    sticky_count,
        "workers":            MAX_WORKERS,
        "discovery_sample":   DISCOVERY_SAMPLE,
    })

    dist_count = sum(1 for r in rows if r.score >= INCLUDE_THRESHOLD)
    log(f"[+] Build complete: {dist_count} CN domains -> dist/domains.txt")
    if sticky_count:
        log(f"[+] {sticky_count} rows retained via sticky fallback (DNS flake protection)")


if __name__ == "__main__":
    try:
        build(Path(__file__).resolve().parents[2])
    except KeyboardInterrupt:
        sys.exit(130)
