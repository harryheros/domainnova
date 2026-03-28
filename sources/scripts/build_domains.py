#!/usr/bin/env python3
"""
build_domains.py - DomainNova unified build pipeline.

v5.0 - Stable Production Release

Three-tier architecture:
  Core      (seed.txt)       read-only, manually curated, absolute trust
  Reliable  (extended.txt)   read-only by default, receives auto-promotions
  Discovery (discovery.txt)  read-write, auto-managed lifecycle

Discovery lifecycle rules:
  - Max capacity:    2000 domains (oldest purged when exceeded)
  - Auto-purge:      removed after 2 consecutive CN-check failures
  - Auto-promote:    moved to extended after 4 consecutive CN-check passes
  - Promote suspend: when extended.txt reaches 3000 domains

Performance boundaries:
  - Max domains per run: 1500 (seed+extended full + discovery sample 300)
  - DoH workers:         20 threads
  - Per-request jitter:  0.05-0.15s
  - Discovery sample:    300 domains per run (rotated)

DNS: Google DoH + Cloudflare DoH (round-robin) with ECS 114.114.114.0/24
IP classification: ipnova APNIC-sourced CN CIDR dataset
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
PURGE_AFTER_FAILURES = 2      # consecutive CN failures before purge
PROMOTE_AFTER_PASSES = 4      # consecutive CN passes before promotion
MAX_WORKERS          = 20     # DoH thread pool size
JITTER_MIN           = 0.05   # seconds
JITTER_MAX           = 0.15   # seconds

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
IPNOVA_CN_URL = "https://raw.githubusercontent.com/harryheros/ipnova/main/output/CN.txt"

# DoH upstreams - round-robin to distribute load
DOH_UPSTREAMS = [
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
]
ECS_SUBNET = "114.114.114.0/24"

DNS_WEIGHT        = 60
REGISTRAR_WEIGHT  = 20
REGISTRANT_WEIGHT = 20
CN_TLD_WEIGHT     = 10
INCLUDE_THRESHOLD = 60

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
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent":  USER_AGENT,
        "Accept":      "application/dns-json",
    })
    return session


def next_doh_upstream() -> str:
    """Round-robin across DoH upstreams."""
    global _doh_index
    with COUNTER_LOCK:
        url = DOH_UPSTREAMS[_doh_index % len(DOH_UPSTREAMS)]
        _doh_index += 1
    return url


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
# DNS resolution (Google/Cloudflare DoH + ECS)
# ---------------------------------------------------------------------------
def resolve_domain(domain: str, session: requests.Session) -> List[str]:
    domain = normalize_domain(domain)
    if not domain:
        return []
    upstream = next_doh_upstream()
    params = {
        "name":               domain,
        "type":               "A",
        "edns_client_subnet": ECS_SUBNET,
    }
    try:
        time.sleep(random.uniform(JITTER_MIN, JITTER_MAX))
        resp = session.get(upstream, params=params, timeout=10)
        if resp.status_code != 200:
            return []
        data = resp.json()
        ips = [
            ans["data"]
            for ans in data.get("Answer", [])
            if ans.get("type") == 1
        ]
        return sorted(set(ips))
    except requests.RequestException as exc:
        log(f"  [warn] DoH failed for {domain}: {exc}")
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
    dns_cn: int, registrar_cn: int, registrant_cn: int, cn_tld: int
) -> int:
    """
    Scoring model:
      Normal path (dns_cn=1): 60 + up to 40 bonus = max 100
      CN TLD fallback (dns_cn=0, cn_tld=1): fixed 40 pts
        - .cn domains require ICP filing under MIIT regulation,
          confirming mainland CN business entity regardless of CDN placement.
        - Score 40 keeps them in domains.csv for reference but below the
          dist threshold (60), so they do NOT appear in dist/domains.txt.
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
        # ICP-backed fallback: retained in CSV, excluded from dist
        return 40
    return 0


# ---------------------------------------------------------------------------
# Per-domain processor (runs in thread pool)
# ---------------------------------------------------------------------------
def process_domain(
    domain: str,
    source: str,
    session: requests.Session,
    cidr_lookup: dict,
    updated: str,
) -> DomainRecord:
    ips = resolve_domain(domain, session)
    dns_cn, dns_cn_count, dns_total, matched_cidr = build_dns_signal(ips, cidr_lookup)
    tld_flag = cn_tld_flag(domain)
    score    = score_record(dns_cn, 0, 0, tld_flag)
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
        else:
            # Failed CN check
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
            score_bands["cn"] += 1
        elif r.score == 40:
            score_bands["cn_tld_fallback"] += 1  # .cn ICP-backed, not in dist
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

    domains = load_all_sources(repo_root)
    log(f"[+] Processing {len(domains)} domains with {MAX_WORKERS} workers...")

    updated = time.strftime("%Y-%m-%d")
    rows:   List[DomainRecord] = []
    errors = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {
            executor.submit(
                process_domain, domain, source, session, cidr_lookup, updated
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

    write_csv(data_csv, rows)
    write_dist(dist_txt, rows)
    write_stats(stats_json, rows, extra={
        "auto_purged":        len(purged),
        "auto_promoted":      len(promoted),
        "processing_errors":  errors,
        "workers":            MAX_WORKERS,
        "discovery_sample":   DISCOVERY_SAMPLE,
    })

    dist_count = sum(1 for r in rows if r.score >= INCLUDE_THRESHOLD)
    log(f"[+] Build complete: {dist_count} CN domains -> dist/domains.txt")


if __name__ == "__main__":
    try:
        build(Path(__file__).resolve().parents[2])
    except KeyboardInterrupt:
        sys.exit(130)
