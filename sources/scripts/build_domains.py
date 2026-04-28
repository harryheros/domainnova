#!/usr/bin/env python3
"""
build_domains.py - DomainNova unified build pipeline.

v6.0 - Reliability & Accuracy Overhaul

Three-tier architecture:
  Core      (seed_cn.txt)       read-only, manually curated, absolute trust
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

# P1 multi-region: bucket constants. Imported lazily-tolerant — if the script
# is invoked from an unusual cwd, fall back to a path-based import.
try:
    from constants import (
        TLD_TO_BUCKET,
        REGION_BUCKETS,
        REGION_CIDR_URLS,
        IPNOVA_MIN_LINES,
        IPNOVA_MIN_LINES_PER_BUCKET,
    )
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from constants import (  # type: ignore[no-redef]
        TLD_TO_BUCKET,
        REGION_BUCKETS,
        REGION_CIDR_URLS,
        IPNOVA_MIN_LINES,
        IPNOVA_MIN_LINES_PER_BUCKET,
    )

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

# P2.A: symmetric TLD bonus weight for HK/MO/TW (mirrors CN_TLD_WEIGHT intent
# but set to 20 per §2.3: "DNS=60, TLD=20" for the non-CN symmetric model).
# CN keeps its existing CN_TLD_WEIGHT=10 so existing CN score arithmetic is
# byte-identical. XX_TLD_WEIGHT is ONLY used in score_record_for_bucket for
# HK/MO/TW buckets.
XX_TLD_WEIGHT     = 20

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
    bucket:        str = ""  # P1: "CN" | "HK" | "MO" | "TW" | "JP" | "KR" | "SG" | "" (unclassified). See decide_bucket().
    # P2.A: per-region DNS majority flags (symmetric with dns_cn).
    # 1 iff resolved IPv4 IPs in that region's CIDR ≥ 60%; 0 otherwise.
    dns_hk:        int = 0
    dns_mo:        int = 0
    dns_tw:        int = 0


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
# P1 Multi-region: ipnova multi-region CIDR loader (Step 4)
# ---------------------------------------------------------------------------
# Type alias for the per-region lookup map: {bucket: cidr_lookup}
# where cidr_lookup is the structure produced by build_cidr_lookup().
RegionLookup = Dict[str, dict]


def _parse_cidr_text(text: str) -> List[ipaddress.IPv4Network]:
    """Parse a newline-delimited CIDR list (ipnova format). Lines starting
    with '#' or blank are skipped. Invalid CIDRs are silently dropped."""
    networks: List[ipaddress.IPv4Network] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            networks.append(ipaddress.IPv4Network(line, strict=False))
        except ValueError:
            continue
    return networks


def _count_cidr_lines(text: str) -> int:
    """Count non-blank, non-comment lines for the sanity-check threshold."""
    n = 0
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            n += 1
    return n


def _fetch_one_region_cidrs(
    session: requests.Session, bucket: str, url: str
) -> List[ipaddress.IPv4Network]:
    """Fetch and parse one region's CIDR list, applying the sanity-check
    fuse. Returns [] on any failure or sanity violation; never raises.

    Sanity check: if line count < IPNOVA_MIN_LINES, treat as transport
    corruption (truncated 502, partial response, etc.) and degrade the
    bucket to empty for this build. Logged at WARN level (ERROR for CN
    because it impacts the existing pipeline).
    """
    severity = "ERROR" if bucket == "CN" else "WARN"
    try:
        resp = session.get(url, timeout=30)
        resp.raise_for_status()
    except (requests.RequestException, OSError) as e:
        log(f"[{severity}] ipnova {bucket}.txt fetch failed: {e}; bucket degraded to empty")
        return []

    line_count = _count_cidr_lines(resp.text)
    # Per-bucket threshold: MO is naturally tiny (tens of CIDRs), so reusing
    # a single global floor would falsely discard legitimate MO data.
    min_lines = IPNOVA_MIN_LINES_PER_BUCKET.get(bucket, IPNOVA_MIN_LINES)
    if line_count < min_lines:
        log(
            f"[{severity}] ipnova {bucket}.txt sanity-check failed: "
            f"{line_count} lines < {min_lines}; bucket degraded to empty"
        )
        return []

    networks = _parse_cidr_text(resp.text)
    log(f"[+] Loaded {len(networks)} {bucket} CIDRs from ipnova")
    return networks


def fetch_region_cidrs(
    session: requests.Session,
) -> Dict[str, List[ipaddress.IPv4Network]]:
    """Fetch all four region CIDR lists from ipnova. Each region is
    independent — failure of one does not abort the others or the build.

    Returns: {bucket: [networks]} for each bucket in REGION_BUCKETS.
             Degraded buckets map to an empty list.
    """
    log("[+] Fetching ipnova multi-region CIDR lists (CN/HK/MO/TW/JP/KR/SG)...")
    out: Dict[str, List[ipaddress.IPv4Network]] = {}
    # Fetch in deterministic order so logs read CN→HK→MO→TW.
    for bucket in ("CN", "HK", "MO", "TW", "JP", "KR", "SG"):
        url = REGION_CIDR_URLS.get(bucket)
        if not url:
            log(f"[ERROR] REGION_CIDR_URLS missing entry for {bucket}; degraded to empty")
            out[bucket] = []
            continue
        out[bucket] = _fetch_one_region_cidrs(session, bucket, url)
    return out


def build_region_lookup(
    region_cidrs: Dict[str, List[ipaddress.IPv4Network]],
) -> RegionLookup:
    """Wrap existing build_cidr_lookup() per bucket. Empty buckets produce
    an empty lookup dict (still valid input to ip_in_cn_cidrs)."""
    return {bucket: build_cidr_lookup(nets) for bucket, nets in region_cidrs.items()}


def ip_to_bucket(ip_str: str, region_lookup: RegionLookup) -> str:
    """Resolve an IPv4 address to its region bucket using the per-region
    ipnova CIDR lookups.

    Priority order CN > HK > MO > TW: ipnova outputs are mutually exclusive
    APNIC delegations in practice, but we enforce deterministic precedence
    as defensive tie-breaking. First-match wins.

    Returns: "CN" | "HK" | "MO" | "TW" | "" (no match in any region)
    """
    for bucket in ("CN", "HK", "MO", "TW", "JP", "KR", "SG"):
        lookup = region_lookup.get(bucket)
        if not lookup:
            continue
        if ip_in_cn_cidrs(ip_str, lookup) is not None:
            return bucket
    return ""


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


# ---------------------------------------------------------------------------
# P1 Step 7: Seed health check
# ---------------------------------------------------------------------------
SEED_HEALTH_FILES: List[Tuple[str, str]] = [
    ("seed_cn.txt", "CN"),
    ("seed_hk.txt", "HK"),
    ("seed_mo.txt", "MO"),
    ("seed_tw.txt", "TW"),
    ("seed_jp.txt", "JP"),
    ("seed_kr.txt", "KR"),
    ("seed_sg.txt", "SG"),
]
SEED_HEALTH_SAMPLE_SIZE = 20
SEED_HEALTH_MIN_FOR_CHECK = 3  # below this, mark as 'skipped'


def _classify_health(rate: float) -> str:
    """Pure function. Maps self-consistency rate to status label.
    Thresholds per PROPOSAL §4.1: < 0.3 -> error, < 0.6 -> warn, else ok."""
    if rate < 0.3:
        return "error"
    if rate < 0.6:
        return "warn"
    return "ok"


def seed_health_check(
    repo_root: Path,
    region_lookup: RegionLookup,
    session: requests.Session,
    rng: Optional[random.Random] = None,
) -> dict:
    """
    P1 Step 7: sample each seed file and verify the resolved IPs land in the
    bucket the file claims. Writes data/seed_health.json and returns the
    payload. NEVER raises — any exception is caught and logged ERROR.

    Per PROPOSAL §4: alerts only, no auto-fix, no build abort. The CN seed
    is the same legacy seed_cn.txt; HK/MO/TW/JP/KR/SG use their respective seed_xx.txt.

    Args:
        repo_root:     repo root for path resolution
        region_lookup: ipnova region lookup (already built by caller)
        session:       requests session for DoH calls
        rng:           injectable Random for deterministic tests; defaults to module random

    Returns:
        the payload dict that was written to data/seed_health.json
    """
    if rng is None:
        rng = random.Random()

    payload: dict = {
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "results": {},
    }

    try:
        for filename, expected_region in SEED_HEALTH_FILES:
            path = repo_root / "sources" / "manual" / filename
            entry: dict = {
                "region":     expected_region,
                "sampled":    0,
                "consistent": 0,
                "rate":       0.0,
                "status":     "skipped",
            }

            try:
                domains = load_file_domains(path) if path.exists() else []
            except OSError as e:
                log(f"[ERROR] seed_health: cannot read {filename}: {e}")
                payload["results"][filename] = entry
                continue

            if len(domains) < SEED_HEALTH_MIN_FOR_CHECK:
                log(f"[+] seed_health: {filename} has {len(domains)} domains (< "
                    f"{SEED_HEALTH_MIN_FOR_CHECK}); marked skipped")
                payload["results"][filename] = entry
                continue

            sample_size = min(SEED_HEALTH_SAMPLE_SIZE, len(domains))
            sample = rng.sample(domains, sample_size)

            # P1 fix v2.1: concurrent DoH probes. Sampling 20 domains serially
            # through resolve_domain's rescue+3-DoH fallback chain costs 20-40s
            # per seed file. With a small thread pool this drops to ~2-5s since
            # most queries complete in parallel. Keeps behavior identical:
            # same sample, same stats, same error handling — just faster.
            def _probe(d):
                try:
                    ips = resolve_domain(d, session)
                    return (d, ips, None)
                except Exception as e:  # noqa: BLE001
                    return (d, [], e)

            consistent = 0
            resolved   = 0
            workers = min(10, sample_size)
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                for d, ips, err in ex.map(_probe, sample):
                    if err is not None:
                        log(f"[WARN] seed_health: resolve {d} raised "
                            f"{type(err).__name__}: {err}")
                        continue
                    if not ips:
                        continue
                    resolved += 1
                    bucket = ip_to_bucket(ips[0], region_lookup)
                    if bucket == expected_region:
                        consistent += 1

            if resolved == 0:
                log(f"[WARN] seed_health: {filename} sampled {sample_size}, "
                    "0 resolved; marked skipped")
                entry.update({"sampled": sample_size, "consistent": 0,
                              "rate": 0.0, "status": "skipped"})
                payload["results"][filename] = entry
                continue

            rate = consistent / resolved
            status = _classify_health(rate)
            entry.update({
                "sampled":    sample_size,
                "resolved":   resolved,
                "consistent": consistent,
                "rate":       round(rate, 4),
                "status":     status,
            })
            payload["results"][filename] = entry

            level = {"ok": "+", "warn": "WARN", "error": "ERROR"}[status]
            log(f"[{level}] seed_health: {filename} ({expected_region}) "
                f"{consistent}/{resolved} consistent (rate={rate:.2f}, status={status})")

        # Persist payload
        out_path = repo_root / "data" / "seed_health.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except Exception as e:  # noqa: BLE001 — defense in depth, never abort build
        log(f"[ERROR] seed_health_check failed unexpectedly: {type(e).__name__}: {e}")

    return payload


def load_all_sources(repo_root: Path) -> List[Tuple[str, str]]:
    """
    Load all three tiers with priority deduplication (seed > extended > discovery).
    Discovery is sampled to DISCOVERY_SAMPLE domains per run (rotated by offset).
    Total domains processed per run is capped at seed+extended full + 300 discovery.
    """
    seed_path      = repo_root / "sources" / "manual" / "seed_cn.txt"
    seed_hk_path   = repo_root / "sources" / "manual" / "seed_hk.txt"
    seed_mo_path   = repo_root / "sources" / "manual" / "seed_mo.txt"
    seed_tw_path   = repo_root / "sources" / "manual" / "seed_tw.txt"
    seed_jp_path   = repo_root / "sources" / "manual" / "seed_jp.txt"
    seed_kr_path   = repo_root / "sources" / "manual" / "seed_kr.txt"
    seed_sg_path   = repo_root / "sources" / "manual" / "seed_sg.txt"
    extended_path  = repo_root / "sources" / "manual" / "extended.txt"
    discovery_path = repo_root / "sources" / "manual" / "discovery.txt"

    seed_domains      = load_file_domains(seed_path)
    seed_hk_domains   = load_file_domains(seed_hk_path)
    seed_mo_domains   = load_file_domains(seed_mo_path)
    seed_tw_domains   = load_file_domains(seed_tw_path)
    seed_jp_domains   = load_file_domains(seed_jp_path)
    seed_kr_domains   = load_file_domains(seed_kr_path)
    seed_sg_domains   = load_file_domains(seed_sg_path)
    extended_domains  = load_file_domains(extended_path)
    discovery_all     = load_file_domains(discovery_path)

    log(
        f"[+] Sources: seed={len(seed_domains)} "
        f"hk={len(seed_hk_domains)} mo={len(seed_mo_domains)} tw={len(seed_tw_domains)} "
        f"jp={len(seed_jp_domains)} kr={len(seed_kr_domains)} sg={len(seed_sg_domains)} "
        f"extended={len(extended_domains)} discovery={len(discovery_all)}"
    )

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

    # Priority deduplication. Region-specific seeds (seed_hk/mo/tw) take the
    # HIGHEST priority because they encode an explicit jurisdictional claim
    # that overrides the legacy mainland seed if a domain ever appears in both.
    # Order: seed_hk > seed_mo > seed_tw > seed_jp > seed_kr > seed_sg > seed (CN) > extended > discovery.
    domain_map: Dict[str, str] = {}
    for domain in seed_hk_domains:
        domain_map[domain] = "seed_hk"
    for domain in seed_mo_domains:
        if domain not in domain_map:
            domain_map[domain] = "seed_mo"
    for domain in seed_tw_domains:
        if domain not in domain_map:
            domain_map[domain] = "seed_tw"
    for domain in seed_jp_domains:
        if domain not in domain_map:
            domain_map[domain] = "seed_jp"
    for domain in seed_kr_domains:
        if domain not in domain_map:
            domain_map[domain] = "seed_kr"
    for domain in seed_sg_domains:
        if domain not in domain_map:
            domain_map[domain] = "seed_sg"
    for domain in seed_domains:
        if domain not in domain_map:
            domain_map[domain] = "seed_cn"
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


def build_region_signals(
    ips: List[str], region_lookup: RegionLookup
) -> Tuple[List[str], Dict[str, int], int, int, str]:
    """
    Multi-region successor to build_dns_signal().

    P2.A: returns region_dns_flags dict instead of bare dns_cn int, so callers
    can compute per-bucket scores. Existing legacy fields (dns_cn_count,
    dns_total, matched_cidr) are unchanged for DomainRecord backward compat.

    Returns:
      - per_ip_buckets:    list[str] aligned with ips; one of "CN"|"HK"|"MO"|"TW"|""
      - region_dns_flags:  {"CN": 0|1, "HK": 0|1, "MO": 0|1, "TW": 0|1}
                           flag[b] = 1 iff ipv4_total > 0 AND
                           bucket_hit_count[b] / ipv4_total >= 0.60
                           Equivalence guarantee: region_dns_flags["CN"] is
                           ALWAYS equal to the old dns_cn return value.
      - dns_cn_count:      count of CN-bucket IPs (== old cn_count)
      - dns_total:         len(ips), matching old behavior
      - matched_cidr:      pipe-joined dedup list of up to 5 CN CIDRs

    The first three return values are the inputs decide_bucket() needs;
    dns_cn_count / dns_total / matched_cidr keep DomainRecord backward compat.
    """
    if not ips:
        return [], {"CN": 0, "HK": 0, "MO": 0, "TW": 0}, 0, 0, ""

    per_ip_buckets: List[str] = []
    bucket_hit_counts: Dict[str, int] = {"CN": 0, "HK": 0, "MO": 0, "TW": 0}
    ipv4_total = 0
    matched_cn_cidrs: List[str] = []
    cn_lookup = region_lookup.get("CN") or {}

    for ip in ips:
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            per_ip_buckets.append("")  # keep positional alignment
            continue
        ipv4_total += 1
        bucket = ip_to_bucket(ip, region_lookup)
        per_ip_buckets.append(bucket)
        if bucket in bucket_hit_counts:
            bucket_hit_counts[bucket] += 1
        if bucket == "CN":
            # Reproduce old build_dns_signal's matched_cidr field exactly:
            # we need the CIDR string, not just the bucket label.
            cidr = ip_in_cn_cidrs(ip, cn_lookup)
            if cidr:
                matched_cn_cidrs.append(cidr)

    dns_total = len(ips)
    # Compute per-region dns flags; all use the same 60% threshold.
    region_dns_flags: Dict[str, int] = {
        b: int(ipv4_total > 0 and (bucket_hit_counts[b] / ipv4_total) >= 0.60)
        for b in ("CN", "HK", "MO", "TW")
    }
    # Legacy alias — kept for DomainRecord.dns_cn_count field (CN only)
    cn_count = bucket_hit_counts["CN"]
    matched  = "|".join(list(dict.fromkeys(matched_cn_cidrs))[:5])
    return per_ip_buckets, region_dns_flags, cn_count, dns_total, matched


def score_record_for_bucket(
    bucket: str,
    dns_flag: int,
    tld_flag: int,
) -> int:
    """
    P2.A: Compute a domain's confidence score for its assigned bucket.

    CN path (byte-identical to pre-P2.A score_record when called with
    registrar_cn=0, registrant_cn=0):
      dns_cn=1  -> DNS_WEIGHT(60) + up to CN_TLD_WEIGHT(10) tld bonus = max 70
      cn_tld=1  -> CN_TLD_FALLBACK_SCORE(60)
      else      -> 0

    HK/MO/TW path (P2.A new, symmetric structure):
      dns_xx=1  -> DNS_WEIGHT(60) + up to XX_TLD_WEIGHT(20) tld bonus = max 80
      else      -> 0  (no TLD fallback — .hk/.mo/.tw lack ICP equivalent)

    Unclassified / unknown bucket:
      -> 0
    """
    if bucket == "CN":
        if dns_flag:
            return min(100, DNS_WEIGHT + (tld_flag * CN_TLD_WEIGHT))
        if tld_flag:
            return CN_TLD_FALLBACK_SCORE
        return 0

    if bucket in ("HK", "MO", "TW"):
        if dns_flag:
            return min(100, DNS_WEIGHT + (tld_flag * XX_TLD_WEIGHT))
        return 0

    return 0  # unclassified or unknown bucket


def score_record(
    dns_cn: int, registrar_cn: int, registrant_cn: int, cn_tld: int,
    has_ips: bool = True,
) -> int:
    """
    Backward-compatible wrapper. New code should call score_record_for_bucket().

    Kept so all existing callers (tests, external tooling) remain valid without
    modification. registrar_cn / registrant_cn were always passed as 0 by
    process_domain and are deliberately ignored here (P3 scope per §2.3).

    Scoring:
      Normal path (dns_cn=1): 60 + up to 10 tld bonus = max 70
      CN TLD fallback (dns_cn=0, cn_tld=1): CN_TLD_FALLBACK_SCORE (60)
        - .cn domains require ICP filing under MIIT regulation,
          confirming mainland CN business entity regardless of CDN placement.
        - Score 60 includes them in dist/domains.txt (ICP is strong signal).
      No signal: 0
    """
    # registrar_cn / registrant_cn intentionally not forwarded (always 0 in
    # practice; kept in signature for API compatibility only).
    return score_record_for_bucket("CN", dns_cn, cn_tld)


# ---------------------------------------------------------------------------
# P1 Multi-region: pure bucket assignment
# ---------------------------------------------------------------------------
# Source-name prefix → bucket (rule 2.2.1, "Seed forced assignment").
# Only manual seed_xx files force a bucket; extended/discovery do not.
_SEED_SOURCE_TO_BUCKET: dict[str, str] = {
    "seed_cn": "CN",
    "seed_hk": "HK",
    "seed_mo": "MO",
    "seed_tw": "TW",
    "seed_jp": "JP",
    "seed_kr": "KR",
    "seed_sg": "SG",
    # Mainland seed is now forced to CN, symmetric with the region seeds.
    # Rationale: ipnova CIDR tables have occasional overlap or mis-collection
    # (seen in production: mainland IPs leaking into HK.txt caused Netease
    # domains like 163.net and mainland seed domains like meituanmaicai.com to
    # get mis-bucketed). Forcing `seed` -> CN guarantees the dist is robust to
    # single-IP-level noise. seed_health_check remains the independent drift
    # detector and still runs against actual ipnova classifications, so we
    # haven't lost the ability to notice seed_cn.txt rot.
}


def decide_bucket(
    domain: str,
    source: str,
    ip_buckets: List[str],
    dns_cn: int,
) -> str:
    """
    Pure function. Assigns a domain to exactly one of CN/HK/MO/TW/JP/KR/SG or "" (unclassified).

    Implements docs/PROPOSAL_MULTI_REGION.md §2.2 decision tree (v1.1):
      1. Seed forced assignment (seed_hk/mo/tw/jp/kr/sg)
      2. Resolution-failure handling is the CALLER's job (sticky fallback);
         this function returns "" if there are no signals.
      3. Per-IP voting using pre-resolved bucket labels from ipnova CIDR lookup
      4. dns_cn flag (CN CIDR ≥60% majority) adds +2 to CN
      5. TLD adds +1 vote to its matching bucket
      6. Majority decision; tie-break order CN > HK > MO > TW

    Args:
        domain:     normalized domain (lowercase, no scheme).
        source:     "seed_cn" | "seed_hk" | "seed_mo" | "seed_tw" | "seed_jp" | "seed_kr" | "seed_sg" | "extended" | "discovery".
        ip_buckets: list of pre-resolved bucket labels, one per resolved IP. Each
                    element is "CN" | "HK" | "MO" | "TW" | "" produced by
                    ip_to_bucket() against the ipnova region lookup. Empty string
                    means the IP did not match any region table.
        dns_cn:     1 if build_region_signals flagged CN-CIDR-majority, else 0.

    Returns:
        "CN" | "HK" | "MO" | "TW" | "JP" | "KR" | "SG" | "" (unclassified)
    """
    # ---- Rule 1: seed forced assignment --------------------------------------
    forced = _SEED_SOURCE_TO_BUCKET.get(source)
    if forced:
        return forced

    # ---- Rule 3: per-IP voting -----------------------------------------------
    votes: dict[str, int] = {"CN": 0, "HK": 0, "MO": 0, "TW": 0, "JP": 0, "KR": 0, "SG": 0}
    for b in ip_buckets:
        if b in votes:
            votes[b] += 1

    # ---- Rule 4: dns_cn boosts CN -------------------------------------------
    # CN CIDR majority is a strong, curated signal. +2 outweighs a single
    # HK/TW false positive from a CDN edge node.
    if dns_cn:
        votes["CN"] += 2

    # ---- Rule 5: TLD vote (+1) -----------------------------------------------
    d = domain.lower()
    for suffix, bucket in TLD_TO_BUCKET.items():
        if d.endswith(suffix):
            votes[bucket] += 1
            break  # only one TLD can match

    # ---- Rule 6: majority + tie-break ----------------------------------------
    max_vote = max(votes.values())
    if max_vote == 0:
        return ""  # unclassified — no positive signal at all

    # Tie-break order: CN > HK > MO > TW
    for bucket in ("CN", "HK", "MO", "TW", "JP", "KR", "SG"):
        if votes[bucket] == max_vote:
            return bucket
    return ""  # unreachable, but keeps type-checkers happy


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
                        bucket=(row.get("bucket", "") or "").strip().upper(),
                        # P2.A: graceful fallback for old CSV without these columns
                        dns_hk=int(row.get("dns_hk", 0) or 0),
                        dns_mo=int(row.get("dns_mo", 0) or 0),
                        dns_tw=int(row.get("dns_tw", 0) or 0),
                    )
                except (ValueError, KeyError):
                    # Skip malformed row; never let one bad line break the build
                    continue
    except OSError:
        return {}
    return prev


# ---------------------------------------------------------------------------
# P2.A: TLD flag helper for per-bucket scoring
# ---------------------------------------------------------------------------
def _tld_flag_for_bucket(domain: str, bucket: str) -> int:
    """
    Return 1 if `domain` ends with the canonical TLD for `bucket`, else 0.
    Pure function; used by process_domain to compute tld_flag per assigned bucket.
    Returns 0 for unclassified ("") bucket.
    """
    if not bucket:
        return 0
    suffix_map = {"CN": CN_TLDS, "HK": (".hk",), "MO": (".mo",), "TW": (".tw",)}
    suffixes = suffix_map.get(bucket)
    if not suffixes:
        return 0
    d = normalize_domain(domain)
    return int(d.endswith(suffixes))


# ---------------------------------------------------------------------------
# Per-domain processor (runs in thread pool)
# ---------------------------------------------------------------------------
def process_domain(
    domain: str,
    source: str,
    session: requests.Session,
    region_lookup: RegionLookup,
    updated: str,
    previous: Optional[Dict[str, DomainRecord]] = None,
) -> DomainRecord:
    ips = resolve_domain(domain, session)
    per_ip_buckets, region_dns_flags, dns_cn_count, dns_total, matched_cidr = \
        build_region_signals(ips, region_lookup)

    # P2.A: extract individual dns flags for DomainRecord fields
    dns_cn = region_dns_flags["CN"]
    dns_hk = region_dns_flags["HK"]
    dns_mo = region_dns_flags["MO"]
    dns_tw = region_dns_flags["TW"]

    bucket = decide_bucket(domain, source, per_ip_buckets, dns_cn)

    # P2.A: compute score for the assigned bucket using per-bucket TLD flag.
    # For CN bucket this is byte-identical to the old score_record(dns_cn, 0, 0, tld_flag).
    tld_flag = _tld_flag_for_bucket(domain, bucket)
    dns_flag_for_bucket = region_dns_flags.get(bucket, 0)
    score    = score_record_for_bucket(bucket, dns_flag_for_bucket, tld_flag)

    # Legacy cn_tld field: keep recording the raw .cn TLD flag for DomainRecord
    # (used in write_stats score_bands and for the CN fallback path).
    cn_tld_value = cn_tld_flag(domain)

    # P1 fix v2: ALL seed-prefixed sources (including mainland) are human-
    # curated and get full trust regardless of IP-based scoring. This makes
    # seed behavior symmetric across all four buckets and protects the dist
    # from single-IP misclassification (e.g., ipnova CIDR table overlap
    # causing a known-CN domain to compute score=0 because decide_bucket
    # forced CN but the IP landed in HK).
    if source in ("seed_cn", "seed_hk", "seed_mo", "seed_tw", "seed_jp", "seed_kr", "seed_sg"):
        score = 100

    # Sticky fallback: if this run couldn't resolve any IPs AND the previous
    # run had the domain qualified (score >= threshold), keep the old signals.
    # This prevents transient DNS outages from wiping good domains out of dist.
    # We only stick on a hard resolution failure (no IPs) — if we DID resolve
    # IPs but they're no longer in CN CIDRs, that's a real signal change and
    # we let it through. Per PROPOSAL §6.1, sticky also restores prev.bucket
    # so domains don't flicker between buckets on DoH jitter.
    sticky_flag = 0
    if previous and not ips:
        prev = previous.get(domain)
        if prev and prev.score >= INCLUDE_THRESHOLD:
            # P1 fix v2.1: if the sticky record has an empty bucket (legacy
            # CSV migration residue, or a sticky chain that spans the P1 upgrade
            # from before bucket existed), re-apply the seed-force rule using
            # the CURRENT source. This recovers domains that persistently fail
            # DoH but are known-good seeds. Non-seed sources stay unclassified
            # because we have no way to re-derive their bucket without IPs.
            sticky_bucket = prev.bucket
            if source in _SEED_SOURCE_TO_BUCKET:
                sticky_bucket = _SEED_SOURCE_TO_BUCKET[source]
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
                bucket=sticky_bucket,   # restore (and possibly repair) bucket
                dns_hk=prev.dns_hk,
                dns_mo=prev.dns_mo,
                dns_tw=prev.dns_tw,
            )

    return DomainRecord(
        domain=domain,
        dns_cn=dns_cn,
        dns_cn_count=dns_cn_count,
        dns_total=dns_total,
        registrar_cn=0,
        registrant_cn=0,
        cn_tld=cn_tld_value,
        score=score,
        resolved_ips="|".join(ips),
        matched_cidr=matched_cidr,
        source=source,
        updated=updated,
        sticky=sticky_flag,
        bucket=bucket,
        dns_hk=dns_hk,
        dns_mo=dns_mo,
        dns_tw=dns_tw,
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
        if row.source == "seed_cn":
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


def write_dist_buckets(dist_dir: Path, rows: List[DomainRecord]) -> Dict[str, int]:
    """
    P1 Step 6: write four parallel region dist files.

    For each bucket in CN/HK/MO/TW/JP/KR/SG, write `domains_{bucket}.txt` containing
    domains that satisfy `r.bucket == bucket AND r.score >= INCLUDE_THRESHOLD`,
    sorted alphabetically. Empty buckets still get an empty file with header,
    so subscription endpoints never 404.

    Returns: {bucket_lower: included_count} for use by write_stats.
    """
    dist_dir.mkdir(parents=True, exist_ok=True)
    counts: Dict[str, int] = {}
    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    for bucket in ("CN", "HK", "MO", "TW", "JP", "KR", "SG"):
        # P1 fix v2: ALL buckets use INCLUDE_THRESHOLD symmetrically.
        # Because process_domain now forces score=100 for all seed* sources,
        # seed-curated entries always pass. extended/discovery entries with
        # score=0 (no CN scoring signal) are kept out of dist regardless of
        # which bucket decide_bucket assigned them to — this prevents ipnova
        # CIDR table noise from leaking into HK/MO/TW buckets.
        included = sorted(
            r.domain for r in rows
            if r.bucket == bucket and r.score >= INCLUDE_THRESHOLD
        )
        path = dist_dir / f"domains_{bucket.lower()}.txt"
        header = (
            f"# DomainNova - {bucket} domains\n"
            f"# Generated: {generated_at}\n"
            f"# Count: {len(included)}\n"
        )
        body = "\n".join(included) + ("\n" if included else "")
        path.write_text(header + body, encoding="utf-8")
        counts[bucket.lower()] = len(included)
        log(f"[+] Wrote {len(included):>5} domains -> dist/domains_{bucket.lower()}.txt")

    # P1 v1.1: dist/domains.txt is removed. Clean up the legacy file if a
    # previous build created it, so the working tree doesn't carry stale state.
    legacy = dist_dir / "domains.txt"
    if legacy.exists():
        try:
            legacy.unlink()
            log("[+] Removed legacy dist/domains.txt (P1 v1.1: replaced by domains_cn.txt)")
        except OSError as e:
            log(f"[WARN] Could not remove legacy dist/domains.txt: {e}")

    return counts


def write_stats(
    path: Path,
    rows: List[DomainRecord],
    extra: dict,
    bucket_counts: Optional[Dict[str, int]] = None,
) -> None:
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

    # P1 Step 6: per-bucket totals. `included` is computed by write_dist_buckets
    # (passed via bucket_counts) so the two are guaranteed to agree. `gray` and
    # `total` are computed here from rows for completeness.
    buckets_payload: Dict[str, Dict[str, int]] = {}
    unclassified_count = 0
    for r in rows:
        if not r.bucket:
            unclassified_count += 1
            continue
        b = r.bucket.lower()
        slot = buckets_payload.setdefault(b, {"included": 0, "gray": 0, "total": 0})
        slot["total"] += 1
        if r.score >= INCLUDE_THRESHOLD:
            pass  # 'included' is overwritten below from bucket_counts
        elif r.score >= 30:
            slot["gray"] += 1
    # Ensure all region buckets always present, even when empty
    # P1 fix v3: expanded to all REGION_BUCKETS so JP/KR/SG show correct included counts.
    for b in {rb.lower() for rb in REGION_BUCKETS}:
        buckets_payload.setdefault(b, {"included": 0, "gray": 0, "total": 0})
        if bucket_counts is not None:
            buckets_payload[b]["included"] = bucket_counts.get(b, 0)
        else:
            # Fallback: mirror write_dist_buckets exactly. ALL buckets use the
            # symmetric INCLUDE_THRESHOLD gate after the P1 fix v2.
            buckets_payload[b]["included"] = sum(
                1 for r in rows
                if r.bucket.lower() == b and r.score >= INCLUDE_THRESHOLD
            )
    buckets_payload["unclassified"] = unclassified_count  # type: ignore[assignment]

    # `dist_domains` semantic per PROPOSAL v1.1 §5.3: sum of included across
    # all four buckets (was: CN-only count). Old dashboards continue to read
    # this key without 404, but the value now reflects total dist size.
    total_included = sum(
        buckets_payload[b]["included"] for b in ("cn", "hk", "mo", "tw")
    )

    payload = {
        "total_domains":     len(rows),
        "dist_domains":      total_included,
        "seed_domains":      source_counts.get("seed_cn", 0),
        "extended_domains":  source_counts.get("extended", 0),
        "discovery_domains": source_counts.get("discovery", 0),
        "score_bands":       dict(score_bands),
        "source_counts":     dict(source_counts),
        "buckets":           buckets_payload,
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
    dist_dir   = repo_root / "dist"

    session     = make_session()
    cn_networks = fetch_cn_cidrs(session)
    cidr_lookup = build_cidr_lookup(cn_networks)

    # P1 Step 5: multi-region lookup. Reuses the CN networks already fetched
    # above to avoid double download; HK/MO/TW are fetched fresh via ipnova.
    # Failure of any non-CN region degrades that bucket to empty (logged WARN);
    # CN failure is logged ERROR but build continues. See PROPOSAL §3.2.
    region_cidrs_extra = fetch_region_cidrs(session)
    # Override CN with the already-loaded list (single source of truth, also
    # avoids a redundant HTTP call when CN.txt is the same upstream URL).
    region_cidrs_extra["CN"] = cn_networks
    region_lookup = build_region_lookup(region_cidrs_extra)

    # P1 Step 7: seed health check. Samples each seed file and verifies
    # resolved IPs land in the expected bucket. Pure diagnostic — never
    # aborts build, never modifies seed files. See PROPOSAL §4.
    seed_health_check(repo_root, region_lookup, session)

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
                process_domain, domain, source, session, region_lookup, updated, previous
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
    source_order = {"seed_cn": 0, "extended": 1, "discovery": 2}
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
    bucket_counts = write_dist_buckets(dist_dir, rows)
    sticky_count = sum(1 for r in rows if r.sticky)
    write_stats(stats_json, rows, extra={
        "auto_purged":        len(purged),
        "auto_promoted":      len(promoted),
        "auto_dead_removed":  len(dead),
        "processing_errors":  errors,
        "sticky_retained":    sticky_count,
        "workers":            MAX_WORKERS,
        "discovery_sample":   DISCOVERY_SAMPLE,
    }, bucket_counts=bucket_counts)

    total_dist = sum(bucket_counts.values())
    log(
        f"[+] Build complete: {total_dist} domains across "
        f"CN={bucket_counts.get('cn',0)} HK={bucket_counts.get('hk',0)} "
        f"MO={bucket_counts.get('mo',0)} TW={bucket_counts.get('tw',0)} "
        f"JP={bucket_counts.get('jp',0)} KR={bucket_counts.get('kr',0)} "
        f"SG={bucket_counts.get('sg',0)}"
    )
    if sticky_count:
        log(f"[+] {sticky_count} rows retained via sticky fallback (DNS flake protection)")


if __name__ == "__main__":
    try:
        build(Path(__file__).resolve().parents[2])
    except KeyboardInterrupt:
        sys.exit(130)
