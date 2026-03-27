#!/usr/bin/env python3
"""
build_domains.py – DomainNova unified build pipeline.

Reads:
  sources/manual/seed.txt
  sources/manual/extended.txt

Writes:
  data/domains.csv
  data/stats.json
  dist/domains.txt

DNS -> CN判斷方式 (v3):
  直接對照 ipnova 的 CN.txt CIDR 列表（APNIC官方數據），
  完全替代原來的 ip-api.com 外部接口 + constants.py ASN表。
  兩個庫使用同一個權威數據源，口徑完全一致。

Scoring model:
  dns_cn        -> 60 pts  (hard requirement; no CN infra = score 0)
  registrar_cn  -> 20 pts  (RDAP, opt-in)
  registrant_cn -> 20 pts  (RDAP, opt-in)
  cn_tld        -> 10 pts  (bonus)
  Threshold: score >= 60 -> included in dist/domains.txt

UPGRADES (v3):
- ip-api.com 完全移除，改用 ipnova CN.txt CIDR 直接匹配
- ipaddress 標準庫，零額外依賴
- CN CIDR 列表啟動時拉取一次，緩存在記憶體，全程復用
- 保留 RDAP opt-in（DOMAINNOVA_RDAP=1）
- as_org 字段改為記錄匹配到的 CIDR（便於審計）
- IPv6 解析結果單獨處理（ipnova CN.txt 只含 IPv4）
"""

from __future__ import annotations

import csv
import ipaddress
import json
import os
import socket
import sys
import time
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
IPNOVA_CN_URL    = "https://raw.githubusercontent.com/harryheros/ipnova/main/output/CN.txt"
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

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
    matched_cidr:  str   # replaces as_org; shows which CN CIDR matched
    source:        str
    updated:       str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def chunked(items: List[str], size: int) -> Iterable[List[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def normalize_domain(domain: str) -> str:
    """Lowercase + IDNA-encode. Falls back to raw lowercase on encoding error."""
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
        print(f"  [warn] {path} not found – skipping.")
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
        allowed_methods=["GET", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": USER_AGENT})
    return session


# ---------------------------------------------------------------------------
# ipnova CIDR loader
# ---------------------------------------------------------------------------
def fetch_cn_cidrs(session: requests.Session) -> List[ipaddress.IPv4Network]:
    """
    Fetch CN.txt from ipnova and parse into a list of IPv4Network objects.
    Lines starting with '#' and blank lines are skipped.
    """
    print(f"[+] Fetching CN CIDR list from ipnova …")
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
            print(f"  [warn] skipping invalid CIDR: {line}")

    print(f"[+] Loaded {len(networks)} CN CIDRs from ipnova")
    return networks


def build_cidr_lookup(networks: List[ipaddress.IPv4Network]) -> dict:
    """
    Build a prefix-length-keyed lookup for fast CIDR matching.
    Returns dict: {prefix_len -> sorted list of (network_address_int, broadcast_int, cidr_str)}
    """
    from collections import defaultdict
    by_prefix: dict = defaultdict(list)
    for net in networks:
        by_prefix[net.prefixlen].append(
            (int(net.network_address), int(net.broadcast_address), str(net))
        )
    # Sort each list for binary search
    for pl in by_prefix:
        by_prefix[pl].sort()
    return dict(by_prefix)


def ip_in_cn_cidrs(ip_str: str, cidr_lookup: dict) -> Optional[str]:
    """
    Check if an IPv4 address falls within any CN CIDR.
    Returns the matched CIDR string, or None if no match.
    Uses prefix-length bucketing for efficiency.
    """
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return None  # IPv6 or invalid – skip

    addr_int = int(addr)

    import bisect
    for prefix_len in sorted(cidr_lookup.keys(), reverse=True):
        entries = cidr_lookup[prefix_len]
        # Binary search: find rightmost entry where network_address <= addr_int
        idx = bisect.bisect_right(entries, (addr_int, addr_int, "~")) - 1
        if idx >= 0:
            net_start, net_end, cidr_str = entries[idx]
            if net_start <= addr_int <= net_end:
                return cidr_str

    return None


# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------
def resolve_domain(domain: str) -> List[str]:
    domain = normalize_domain(domain)
    ips: set[str] = set()
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
            for info in infos:
                sockaddr = info[4]
                if sockaddr:
                    ips.add(sockaddr[0])
        except OSError:
            pass
    return sorted(ips)


# ---------------------------------------------------------------------------
# DNS CN signal (using ipnova CIDRs)
# ---------------------------------------------------------------------------
def build_dns_signal(
    ips: List[str], cidr_lookup: dict
) -> Tuple[int, int, int, str]:
    """
    Returns: (dns_cn, cn_count, dns_total, matched_cidrs_str)
    Only IPv4 addresses are checked against CN CIDRs.
    IPv6 addresses are counted in dns_total but not as CN hits.
    """
    if not ips:
        return 0, 0, 0, ""

    cn_count = 0
    matched_cidrs: List[str] = []
    ipv4_total = 0

    for ip in ips:
        # Skip IPv6
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        ipv4_total += 1
        cidr = ip_in_cn_cidrs(ip, cidr_lookup)
        if cidr:
            cn_count += 1
            matched_cidrs.append(cidr)

    # Gate on IPv4 count; if no IPv4 at all, dns_cn = 0
    dns_total = len(ips)
    dns_cn    = int(ipv4_total > 0 and (cn_count / ipv4_total) >= 0.60)
    matched   = "|".join(list(dict.fromkeys(matched_cidrs))[:5])

    return dns_cn, cn_count, dns_total, matched


# ---------------------------------------------------------------------------
# RDAP (opt-in)
# ---------------------------------------------------------------------------
def fetch_rdap_bootstrap(session: requests.Session) -> dict:
    response = session.get(RDAP_BOOTSTRAP_URL, timeout=30)
    response.raise_for_status()
    return response.json()


def find_rdap_base(domain: str, bootstrap: dict) -> Optional[str]:
    ascii_domain = normalize_domain(domain)
    if "." not in ascii_domain:
        return None
    tld = ascii_domain.rsplit(".", 1)[-1].lower()
    for service in bootstrap.get("services", []):
        suffixes, urls = service
        if tld in suffixes and urls:
            return urls[0]
    return None


def rdap_lookup(
    domain: str, session: requests.Session, bootstrap: dict
) -> Optional[dict]:
    ascii_domain = normalize_domain(domain)
    base = find_rdap_base(ascii_domain, bootstrap)
    if not base:
        return None
    url = base.rstrip("/") + "/domain/" + ascii_domain
    try:
        response = session.get(url, timeout=25)
        if response.status_code == 200:
            return response.json()
    except requests.RequestException:
        pass
    return None


def _collect_strings(node, parts: List[str]) -> None:
    if isinstance(node, dict):
        for v in node.values():
            _collect_strings(v, parts)
    elif isinstance(node, list):
        for v in node:
            _collect_strings(v, parts)
    elif isinstance(node, str):
        parts.append(node)


def extract_rdap_text(rdap: dict) -> str:
    parts: List[str] = []
    _collect_strings(rdap, parts)
    return " ".join(parts).upper()


CN_REGISTRAR_HINTS = (
    "ALIBABA", "HICHINA", "XINNET", "XIN NET", "WEST263", "WEST.CN",
    "DNSPOD", "BIZCN", "ENAME", "22.CN", "CNNIC", "CHINA",
    "BEIJING", "SHANGHAI", "GUANGZHOU", "SHENZHEN", "HANGZHOU",
)
CN_REGISTRAR_LINK_TOKENS = (
    "cnnic", "west.cn", "xinnet", "dns.com.cn", "alidns", "hichina",
)
COUNTRY_HITS = (
    " COUNTRY CN ", '"CN"', " CHINA ",
    " PEOPLE'S REPUBLIC OF CHINA ", " PRC ",
)


def registrar_cn_signal(rdap: Optional[dict]) -> int:
    if not rdap:
        return 0
    text = extract_rdap_text(rdap)
    if any(hint in text for hint in CN_REGISTRAR_HINTS):
        return 1
    for link in rdap.get("links", []) or []:
        host = urlparse(str(link.get("href", ""))).netloc.lower()
        if any(tok in host for tok in CN_REGISTRAR_LINK_TOKENS):
            return 1
    return 0


def registrant_cn_signal(rdap: Optional[dict]) -> int:
    if not rdap:
        return 0
    wrapped = f" {extract_rdap_text(rdap)} "
    return int(any(hit in wrapped for hit in COUNTRY_HITS))


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
def score_record(
    dns_cn: int, registrar_cn: int, registrant_cn: int, cn_tld: int
) -> int:
    if not dns_cn:
        return 0
    raw = (
        dns_cn        * DNS_WEIGHT
        + registrar_cn  * REGISTRAR_WEIGHT
        + registrant_cn * REGISTRANT_WEIGHT
        + cn_tld        * CN_TLD_WEIGHT
    )
    return min(raw, 100)


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------
def write_csv(path: Path, rows: List[DomainRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = [f.name for f in fields(rows[0])]
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def write_dist(path: Path, rows: List[DomainRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    included = [row.domain for row in rows if row.score >= INCLUDE_THRESHOLD]
    path.write_text(
        "\n".join(included) + ("\n" if included else ""), encoding="utf-8"
    )


def write_stats(path: Path, rows: List[DomainRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    score_bands: Counter = Counter()
    source_counts: Counter = Counter()

    for row in rows:
        source_counts[row.source] += 1
        if row.score >= 60:
            score_bands["cn"] += 1
        elif row.score >= 30:
            score_bands["gray"] += 1
        else:
            score_bands["non_cn"] += 1

    dist_count = sum(1 for row in rows if row.score >= INCLUDE_THRESHOLD)

    payload = {
        "total_domains":    len(rows),
        "dist_domains":     dist_count,
        "seed_domains":     source_counts.get("seed", 0),
        "extended_domains": source_counts.get("extended", 0),
        "score_bands":      dict(score_bands),
        "source_counts":    dict(source_counts),
        "generated_at":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
def build(repo_root: Path) -> None:
    seed_path     = repo_root / "sources" / "manual" / "seed.txt"
    extended_path = repo_root / "sources" / "manual" / "extended.txt"
    data_csv      = repo_root / "data"  / "domains.csv"
    stats_json    = repo_root / "data"  / "stats.json"
    dist_txt      = repo_root / "dist"  / "domains.txt"

    seed_domains     = load_domains(seed_path)
    extended_domains = load_domains(extended_path)

    combined: List[Tuple[str, str]] = []
    seen: set[str] = set()
    for domain in seed_domains:
        if domain not in seen:
            combined.append((domain, "seed"))
            seen.add(domain)
    for domain in extended_domains:
        if domain not in seen:
            combined.append((domain, "extended"))
            seen.add(domain)

    print(f"[+] {len(combined)} unique domains "
          f"({len(seed_domains)} seed + {len(extended_domains)} extended)")

    # ---- Fetch ipnova CN CIDRs ----
    session     = make_session()
    cn_networks = fetch_cn_cidrs(session)
    cidr_lookup = build_cidr_lookup(cn_networks)

    # ---- DNS resolution ----
    resolved_ips_by_domain: Dict[str, List[str]] = {}
    for domain, _ in combined:
        resolved_ips_by_domain[domain] = resolve_domain(domain)
    all_ip_count = sum(len(v) for v in resolved_ips_by_domain.values())
    print(f"[+] DNS resolved – {all_ip_count} IP records across all domains")

    # ---- RDAP (opt-in) ----
    bootstrap: Optional[dict] = None
    if ENABLE_RDAP:
        print("[+] RDAP enabled – fetching bootstrap …")
        try:
            bootstrap = fetch_rdap_bootstrap(session)
        except requests.RequestException as exc:
            print(f"  [warn] RDAP bootstrap failed: {exc} – RDAP signals will be 0")

    # ---- Assemble records ----
    updated = time.strftime("%Y-%m-%d")
    rows: List[DomainRecord] = []

    for domain, source in combined:
        ips = resolved_ips_by_domain[domain]
        dns_cn, dns_cn_count, dns_total, matched_cidr = build_dns_signal(
            ips, cidr_lookup
        )

        if ENABLE_RDAP and bootstrap:
            rdap          = rdap_lookup(domain, session, bootstrap)
            registrar_cn  = registrar_cn_signal(rdap)
            registrant_cn = registrant_cn_signal(rdap)
            time.sleep(0.3)
        else:
            registrar_cn  = 0
            registrant_cn = 0

        tld_flag = cn_tld_flag(domain)
        score    = score_record(dns_cn, registrar_cn, registrant_cn, tld_flag)

        rows.append(
            DomainRecord(
                domain=domain,
                dns_cn=dns_cn,
                dns_cn_count=dns_cn_count,
                dns_total=dns_total,
                registrar_cn=registrar_cn,
                registrant_cn=registrant_cn,
                cn_tld=tld_flag,
                score=score,
                resolved_ips="|".join(ips),
                matched_cidr=matched_cidr,
                source=source,
                updated=updated,
            )
        )

    write_csv(data_csv, rows)
    write_stats(stats_json, rows)
    write_dist(dist_txt, rows)

    dist_count = sum(1 for row in rows if row.score >= INCLUDE_THRESHOLD)
    summary = {
        "seed_count":      len(seed_domains),
        "extended_count":  len(extended_domains),
        "total_unique":    len(rows),
        "dist_count":      dist_count,
        "cn_domains":      sum(1 for row in rows if row.score >= 60),
        "gray_domains":    sum(1 for row in rows if 30 <= row.score < 60),
        "non_cn_domains":  sum(1 for row in rows if row.score < 30),
        "cidr_count":      len(cn_networks),
        "rdap_enabled":    ENABLE_RDAP,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    build(repo_root)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
