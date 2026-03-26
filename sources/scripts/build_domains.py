#!/usr/bin/env python3
"""
DomainNova unified build pipeline.

Reads:
- sources/manual/seed.txt
- sources/manual/extended.txt

Writes:
- data/domains.csv
- data/stats.json
- dist/domains.txt

Scoring:
- dns_cn: 60
- registrar_cn: 20
- registrant_cn: 20

Notes:
- ASN classification uses constants.py as the source of truth.
- IDNs are normalized to ASCII (IDNA / punycode) before processing.
- CN_TLDS uses ASCII-only punycode labels to avoid encoding issues.
"""

from __future__ import annotations

import csv
import json
import socket
import sys
import time
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from constants import CN_BACKBONE, CN_CLOUD_ASNS, NON_MAINLAND_REGIONS

IP_API_BATCH_URL = "http://ip-api.com/batch"
IP_API_FIELDS = "status,message,country,countryCode,as,asname,query"
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

DNS_WEIGHT = 60
REGISTRAR_WEIGHT = 20
REGISTRANT_WEIGHT = 20

# ASCII-only, encoding-safe IDN TLDs:
# .xn--fiqs8s  -> .中国
# .xn--55qx5d  -> .公司
# .xn--io0a7i  -> .网络
CN_TLDS = (".cn", ".xn--fiqs8s", ".xn--55qx5d", ".xn--io0a7i")

USER_AGENT = "DomainNova/BuildPipeline (+https://github.com/harryheros/domainnova)"


@dataclass
class DomainRecord:
    domain: str
    dns_cn: int
    dns_cn_count: int
    dns_total: int
    registrar_cn: int
    registrant_cn: int
    score: int
    resolved_ips: str
    as_org: str
    source: str
    updated: str


def chunked(items: List[str], size: int) -> Iterable[List[str]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


def normalize_asn(value: str) -> str:
    text = (value or "").strip().upper()
    if text.startswith("AS"):
        text = text[2:]
    return "".join(ch for ch in text if ch.isdigit())


def normalize_domain(domain: str) -> str:
    """
    Normalize a domain to lowercase ASCII using IDNA.
    Returns the original lowercase value if IDNA conversion fails.
    """
    raw = (domain or "").strip().rstrip(".").lower()
    if not raw:
        return raw
    try:
        return raw.encode("idna").decode("ascii")
    except UnicodeError:
        return raw


def is_cn_asn(asn_text: str) -> bool:
    asn = normalize_asn(asn_text)
    return asn in CN_BACKBONE or asn in CN_CLOUD_ASNS


def is_non_mainland_country(country_code: str) -> bool:
    return (country_code or "").upper() in set(NON_MAINLAND_REGIONS)


def cn_tld(domain: str) -> int:
    ascii_domain = normalize_domain(domain)
    return int(ascii_domain.endswith(CN_TLDS))


def load_domains(path: Path) -> List[str]:
    if not path.exists():
        return []

    items: List[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        items.append(normalize_domain(line))

    seen = set()
    out: List[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def resolve_domain(domain: str) -> List[str]:
    domain = normalize_domain(domain)
    ips = set()
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
            for info in infos:
                sockaddr = info[4]
                if sockaddr:
                    ips.add(sockaddr[0])
        except socket.gaierror:
            pass
    return sorted(ips)


def ip_api_lookup(ips: List[str], session: requests.Session) -> Dict[str, dict]:
    result: Dict[str, dict] = {}
    for batch in chunked(ips, 100):
        payload = [{"query": ip, "fields": IP_API_FIELDS} for ip in batch]
        response = session.post(IP_API_BATCH_URL, json=payload, timeout=30)
        response.raise_for_status()
        rows = response.json()
        for row in rows:
            query = row.get("query")
            if query:
                result[query] = row
        time.sleep(1.6)
    return result


def fetch_rdap_bootstrap(session: requests.Session) -> dict:
    response = session.get(RDAP_BOOTSTRAP_URL, headers={"User-Agent": USER_AGENT}, timeout=30)
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


def rdap_lookup(domain: str, session: requests.Session, bootstrap: dict) -> Optional[dict]:
    ascii_domain = normalize_domain(domain)
    base = find_rdap_base(ascii_domain, bootstrap)
    if not base:
        return None
    url = base.rstrip("/") + "/domain/" + ascii_domain
    try:
        response = session.get(url, headers={"User-Agent": USER_AGENT}, timeout=25)
        if response.status_code == 200:
            return response.json()
    except requests.RequestException:
        return None
    return None


def extract_rdap_text(rdap: dict) -> str:
    parts: List[str] = []

    def collect(node):
        if isinstance(node, dict):
            for value in node.values():
                collect(value)
        elif isinstance(node, list):
            for value in node:
                collect(value)
        elif isinstance(node, str):
            parts.append(value_to_ascii(node))

    collect(rdap)
    return " ".join(parts).upper()


def value_to_ascii(value: str) -> str:
    try:
        return value.encode("utf-8", errors="ignore").decode("utf-8", errors="ignore")
    except Exception:
        return value


def registrar_cn_signal(rdap: Optional[dict]) -> int:
    if not rdap:
        return 0

    text = extract_rdap_text(rdap)
    cn_hints = (
        "ALIBABA",
        "HICHINA",
        "XINNET",
        "XIN NET",
        "WEST263",
        "WEST.CN",
        "DNSPOD",
        "BIZCN",
        "ENAME",
        "22.CN",
        "CNNIC",
        "CHINA",
        "BEIJING",
        "SHANGHAI",
        "GUANGZHOU",
        "SHENZHEN",
        "HANGZHOU",
    )
    if any(hint in text for hint in cn_hints):
        return 1

    for link in rdap.get("links", []) or []:
        href = str(link.get("href", ""))
        host = urlparse(href).netloc.lower()
        if any(token in host for token in ("cnnic", "west.cn", "xinnet", "dns.com.cn", "alidns", "hichina")):
            return 1

    return 0


def registrant_cn_signal(rdap: Optional[dict]) -> int:
    if not rdap:
        return 0

    text = extract_rdap_text(rdap)
    wrapped = f" {text} "
    country_hits = (
        " COUNTRY CN ",
        '"CN"',
        " CHINA ",
        " PEOPLE'S REPUBLIC OF CHINA ",
        " PRC ",
    )
    return int(any(hit in wrapped for hit in country_hits))


def build_dns_signal(ips: List[str], ip_meta: Dict[str, dict]) -> Tuple[int, int, int, str]:
    if not ips:
        return 0, 0, 0, ""

    cn_count = 0
    as_orgs = []

    for ip in ips:
        meta = ip_meta.get(ip, {})
        country_code = (meta.get("countryCode") or "").upper()
        as_text = meta.get("as") or ""
        as_name = meta.get("asname") or ""
        org = as_name or as_text
        if org:
            as_orgs.append(org)

        if is_cn_asn(as_text) and not is_non_mainland_country(country_code):
            cn_count += 1

    dns_total = len(ips)
    dns_cn = int(dns_total > 0 and (cn_count / dns_total) >= 0.60)
    as_org = "|".join(sorted(dict.fromkeys(as_orgs))[:5])

    return dns_cn, cn_count, dns_total, as_org


def score_record(dns_cn: int, registrar_cn: int, registrant_cn: int) -> int:
    return (
        dns_cn * DNS_WEIGHT
        + registrar_cn * REGISTRAR_WEIGHT
        + registrant_cn * REGISTRANT_WEIGHT
    )


def write_csv(path: Path, rows: List[DomainRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(asdict(rows[0]).keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def write_dist(path: Path, rows: List[DomainRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    domains = [row.domain for row in rows if row.score >= 60]
    path.write_text("\n".join(domains) + ("\n" if domains else ""), encoding="utf-8")


def write_stats(path: Path, rows: List[DomainRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    score_bands = Counter()
    source_counts = Counter()

    for row in rows:
        source_counts[row.source] += 1
        if row.score >= 60:
            score_bands["cn"] += 1
        elif row.score >= 30:
            score_bands["gray"] += 1
        else:
            score_bands["non_cn"] += 1

    payload = {
        "total_domains": len(rows),
        "score_bands": dict(score_bands),
        "source_counts": dict(source_counts),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def build(repo_root: Path) -> None:
    seed_path = repo_root / "sources" / "manual" / "seed.txt"
    extended_path = repo_root / "sources" / "manual" / "extended.txt"
    data_csv = repo_root / "data" / "domains.csv"
    stats_json = repo_root / "data" / "stats.json"
    dist_txt = repo_root / "dist" / "domains.txt"

    seed_domains = load_domains(seed_path)
    extended_domains = load_domains(extended_path)

    combined: List[Tuple[str, str]] = []
    seen = set()
    for domain in seed_domains:
        if domain not in seen:
            combined.append((domain, "seed"))
            seen.add(domain)
    for domain in extended_domains:
        if domain not in seen:
            combined.append((domain, "extended"))
            seen.add(domain)

    resolved_ips_by_domain: Dict[str, List[str]] = {}
    all_ips = set()

    for domain, _source in combined:
        ips = resolve_domain(domain)
        resolved_ips_by_domain[domain] = ips
        all_ips.update(ips)

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    ip_meta = ip_api_lookup(sorted(all_ips), session) if all_ips else {}
    bootstrap = fetch_rdap_bootstrap(session)

    updated = time.strftime("%Y-%m-%d")
    rows: List[DomainRecord] = []

    for domain, source in combined:
        ips = resolved_ips_by_domain[domain]
        dns_cn, dns_cn_count, dns_total, as_org = build_dns_signal(ips, ip_meta)
        rdap = rdap_lookup(domain, session, bootstrap)
        registrar_cn = registrar_cn_signal(rdap)
        registrant_cn = registrant_cn_signal(rdap)
        _cn_tld = cn_tld(domain)

        score = score_record(dns_cn, registrar_cn, registrant_cn)

        rows.append(
            DomainRecord(
                domain=domain,
                dns_cn=dns_cn,
                dns_cn_count=dns_cn_count,
                dns_total=dns_total,
                registrar_cn=registrar_cn,
                registrant_cn=registrant_cn,
                score=score,
                resolved_ips="|".join(ips),
                as_org=as_org,
                source=source,
                updated=updated,
            )
        )

    write_csv(data_csv, rows)
    write_stats(stats_json, rows)
    write_dist(dist_txt, rows)

    summary = {
        "seed_count": len(seed_domains),
        "extended_count": len(extended_domains),
        "total_unique": len(rows),
        "cn_domains": sum(1 for row in rows if row.score >= 60),
        "gray_domains": sum(1 for row in rows if 30 <= row.score < 60),
        "non_cn_domains": sum(1 for row in rows if row.score < 30),
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
