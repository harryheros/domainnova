#!/usr/bin/env python3
"""
build_domains.py - DomainNova unified build pipeline.

v3.1 Upgrades:
- Integrated Google DoH (DNS over HTTPS) with EDNS Client Subnet (ECS).
- Uses a simulated CN subnet (114.114.114.0/24) to fetch CN-accurate IPs.
- Zero Chinese characters in source for clean environment compliance.
- Removed local UDP DNS fallback to prevent plain-text leakage.
- Direct CIDR matching via ipnova local database (memory-mapped).

v3.2 Fixes:
- dist/ and data/ directories created before writing (prevents crash on first run).
- Guard against empty rows before accessing fields(rows[0]).
- stats.json restored to full structure (seed_domains, extended_domains, score_bands).
- resolve_domain_stealth logs warnings instead of silently swallowing errors.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import os
import socket
import sys
import time
import random
from collections import Counter
from dataclasses import dataclass, asdict, fields
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
IPNOVA_CN_URL      = "https://raw.githubusercontent.com/harryheros/ipnova/main/output/CN.txt"
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

# Google DoH with EDNS Client Subnet (ECS)
# Simulates a CN Telecom client to trigger GeoDNS CN responses.
# Avoids plain-text UDP 53 to CN DNS servers (leak / rate-limit / attribution risk).
DOH_URL    = "https://dns.google/resolve"
ECS_SUBNET = "114.114.114.0/24"

DNS_WEIGHT        = 60
REGISTRAR_WEIGHT  = 20
REGISTRANT_WEIGHT = 20
CN_TLD_WEIGHT     = 10

INCLUDE_THRESHOLD = 60

# Toggle RDAP via environment variable: DOMAINNOVA_RDAP=1
ENABLE_RDAP = os.getenv("DOMAINNOVA_RDAP", "0") == "1"

# ASCII-only encoding-safe IDN TLDs
CN_TLDS = (".cn", ".xn--fiqs8s", ".xn--55qx5d", ".xn--io0a7i")

USER_AGENT = "DomainNova/BuildPipeline (+https://github.com/harryheros/domainnova)"


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


def load_domains(path: Path) -> List[str]:
    if not path.exists():
        print(f"  [warn] {path} not found - skipping.")
        return []
    items: List[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        items.append(normalize_domain(line))
    seen: set[str] = set()
    out: List[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def make_session() -> requests.Session:
    retry = Retry(
        total=3,
        backoff_factor=1.0,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": USER_AGENT})
    return session


# ---------------------------------------------------------------------------
# ipnova CIDR matching
# ---------------------------------------------------------------------------
def fetch_cn_cidrs(session: requests.Session) -> List[ipaddress.IPv4Network]:
    print("[+] Fetching CN CIDR list from ipnova...")
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
    print(f"[+] Loaded {len(networks)} CN CIDRs")
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
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return None
    addr_int = int(addr)
    import bisect
    for prefix_len in sorted(cidr_lookup.keys(), reverse=True):
        entries = cidr_lookup[prefix_len]
        idx = bisect.bisect_right(entries, (addr_int, addr_int, "~")) - 1
        if idx >= 0:
            net_start, net_end, cidr_str = entries[idx]
            if net_start <= addr_int <= net_end:
                return cidr_str
    return None


# ---------------------------------------------------------------------------
# Stealth DNS Resolution (Google DoH + EDNS Client Subnet)
# ---------------------------------------------------------------------------
def resolve_domain_stealth(domain: str, session: requests.Session) -> List[str]:
    """
    Resolve domain via Google DoH with ECS (EDNS Client Subnet).
    Simulates a request from a CN Telecom IP to get GeoDNS-accurate results.
    Avoids plain-text UDP 53 to CN resolvers (leak / rate-limit / attribution risk).
    """
    domain = normalize_domain(domain)
    if not domain:
        return []

    params = {
        "name": domain,
        "type": "A",
        "edns_client_subnet": ECS_SUBNET,
    }

    try:
        time.sleep(random.uniform(0.05, 0.2))  # jitter to avoid mechanical patterns
        resp = session.get(DOH_URL, params=params, timeout=10)
        if resp.status_code != 200:
            print(f"  [warn] DoH returned {resp.status_code} for {domain}")
            return []
        data = resp.json()
        ips = [
            ans["data"]
            for ans in data.get("Answer", [])
            if ans.get("type") == 1  # A record only
        ]
        return sorted(set(ips))
    except requests.RequestException as exc:
        print(f"  [warn] DoH failed for {domain}: {exc}")
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


# ---------------------------------------------------------------------------
# RDAP (opt-in)
# ---------------------------------------------------------------------------
def fetch_rdap_bootstrap(session: requests.Session) -> dict:
    return session.get(RDAP_BOOTSTRAP_URL, timeout=30).json()


def rdap_lookup(
    domain: str, session: requests.Session, bootstrap: dict
) -> Optional[dict]:
    ascii_domain = normalize_domain(domain)
    tld  = ascii_domain.rsplit(".", 1)[-1].lower()
    base = None
    for service in bootstrap.get("services", []):
        suffixes, urls = service
        if tld in suffixes and urls:
            base = urls[0]
            break
    if not base:
        return None
    try:
        resp = session.get(base.rstrip("/") + "/domain/" + ascii_domain, timeout=20)
        return resp.json() if resp.status_code == 200 else None
    except requests.RequestException:
        return None


def extract_rdap_text(rdap: dict) -> str:
    parts: List[str] = []
    def _walk(node):
        if isinstance(node, dict):
            for v in node.values(): _walk(v)
        elif isinstance(node, list):
            for v in node: _walk(v)
        elif isinstance(node, str):
            parts.append(node)
    _walk(rdap)
    return " ".join(parts).upper()


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
    path.write_text("\n".join(included) + ("\n" if included else ""), encoding="utf-8")


def write_stats(path: Path, rows: List[DomainRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    score_bands:   Counter = Counter()
    source_counts: Counter = Counter()
    for r in rows:
        source_counts[r.source] += 1
        if r.score >= 60:
            score_bands["cn"] += 1
        elif r.score >= 30:
            score_bands["gray"] += 1
        else:
            score_bands["non_cn"] += 1
    payload = {
        "total_domains":    len(rows),
        "dist_domains":     sum(1 for r in rows if r.score >= INCLUDE_THRESHOLD),
        "seed_domains":     source_counts.get("seed", 0),
        "extended_domains": source_counts.get("extended", 0),
        "score_bands":      dict(score_bands),
        "source_counts":    dict(source_counts),
        "generated_at":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
def build(repo_root: Path) -> None:
    seed_path     = repo_root / "sources" / "manual" / "seed.txt"
    extended_path = repo_root / "sources" / "manual" / "extended.txt"
    data_csv      = repo_root / "data"  / "domains.csv"
    stats_json    = repo_root / "data"  / "stats.json"
    dist_txt      = repo_root / "dist"  / "domains.txt"

    session     = make_session()
    cn_networks = fetch_cn_cidrs(session)
    cidr_lookup = build_cidr_lookup(cn_networks)

    domains: List[Tuple[str, str]] = []
    seen: set[str] = set()
    for d in load_domains(seed_path):
        if d not in seen:
            domains.append((d, "seed"))
            seen.add(d)
    for d in load_domains(extended_path):
        if d not in seen:
            domains.append((d, "extended"))
            seen.add(d)

    print(f"[+] Processing {len(domains)} unique domains...")

    bootstrap = fetch_rdap_bootstrap(session) if ENABLE_RDAP else None
    rows: List[DomainRecord] = []
    updated = time.strftime("%Y-%m-%d")

    for domain, source in domains:
        ips = resolve_domain_stealth(domain, session)
        dns_cn, dns_cn_count, dns_total, matched_cidr = build_dns_signal(ips, cidr_lookup)

        registrar_cn  = 0
        registrant_cn = 0
        if ENABLE_RDAP and bootstrap:
            rdap = rdap_lookup(domain, session, bootstrap)
            if rdap:
                txt = extract_rdap_text(rdap)
                if any(h in txt for h in ["ALIBABA", "HICHINA", "XINNET", "WEST.CN", "DNSPOD", "CNNIC"]):
                    registrar_cn = 1
                if " COUNTRY CN " in f" {txt} " or ' "CN" ' in f" {txt} ":
                    registrant_cn = 1

        tld_flag = cn_tld_flag(domain)
        score    = 0
        if dns_cn:
            score = min(100, dns_cn * 60 + registrar_cn * 20 + registrant_cn * 20 + tld_flag * 10)

        rows.append(DomainRecord(
            domain=domain, dns_cn=dns_cn, dns_cn_count=dns_cn_count,
            dns_total=dns_total, registrar_cn=registrar_cn,
            registrant_cn=registrant_cn, cn_tld=tld_flag, score=score,
            resolved_ips="|".join(ips), matched_cidr=matched_cidr,
            source=source, updated=updated,
        ))

    write_csv(data_csv, rows)
    write_dist(dist_txt, rows)
    write_stats(stats_json, rows)

    dist_count = sum(1 for r in rows if r.score >= INCLUDE_THRESHOLD)
    print(f"[+] Build complete. {dist_count} CN domains -> dist/domains.txt")


if __name__ == "__main__":
    try:
        build(Path(__file__).resolve().parents[2])
    except KeyboardInterrupt:
        sys.exit(130)
