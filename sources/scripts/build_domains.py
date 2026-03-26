#!/usr/bin/env python3
"""
DomainNova v2 builder
Repository-aligned pipeline for:
- sources/manual/seed.txt
- sources/manual/extended.txt

Outputs:
- data/domains.csv
- data/stats.json
- dist/domains.txt

Signals:
- dns_cn   (0/1)
- whois_cn (0/1)
- cn_tld   (0/1)
- score

Notes:
- DNS/ASN is primary and weighted at 60.
- WHOIS/RDAP is conservative and optional.
- Designed to fit the current DomainNova repo structure.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import socket
import time
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import requests

IP_API_BATCH_URL = "http://ip-api.com/batch"
IP_API_FIELDS = "status,message,country,countryCode,as,asname,query"

RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"

DNS_CN_WEIGHT = 60
WHOIS_CN_WEIGHT = 30
CN_TLD_WEIGHT = 10

CN_COUNTRY_CODES = {"CN"}

CN_ASN_HINTS = (
    "CHINA TELECOM",
    "CHINA UNICOM",
    "CHINA MOBILE",
    "ALIBABA",
    "TENCENT",
    "BAIDU",
    "HUAWEI",
    "UCLOUD",
    "KINGSOFT",
    "WANGSU",
    "CHINANETCENTER",
    "CERNET",
    "CSTNET",
    "CTGNET",
)

CN_TLDS = (".cn", ".中国", ".公司", ".网络")

CN_REGISTRAR_HINTS = (
    "ALIBABA",
    "XIN NET",
    "XINNET",
    "WEST263",
    "WEST",
    "DNSPOD",
    "EJEE",
    "35 TECHNOLOGY",
    "HICHINA",
    "WANWANG",
    "BIZCN",
    "ENAME",
    "22.CN",
    "CNNIC",
    "BEIJING",
    "SHANGHAI",
    "HANGZHOU",
    "GUANGZHOU",
    "SHENZHEN",
    "CHINA",
)

CN_RDAP_HOST_HINTS = (
    ".cn",
    "cnnic",
    "alidns",
    "west.cn",
    "xinnet",
    "dns.com.cn",
    "hichina",
)

USER_AGENT = "DomainNova/2.0 (+https://github.com/harryheros/domainnova)"


@dataclass
class DomainRow:
    domain: str
    dns_cn: int
    whois_cn: int
    cn_tld: int
    score: int
    resolved_ips: str
    as_org: str
    source: str
    updated: str
    reasons: str


def chunked(items: List[str], size: int) -> Iterable[List[str]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


def load_domains(path: Path) -> List[str]:
    domains: List[str] = []
    if not path.exists():
        return domains
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        domains.append(line.lower())
    seen = set()
    out = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def resolve_domain(domain: str, family: int) -> List[str]:
    ips = set()
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
    results: Dict[str, dict] = {}
    for batch in chunked(ips, 100):
        payload = [{"query": ip, "fields": IP_API_FIELDS} for ip in batch]
        resp = session.post(IP_API_BATCH_URL, json=payload, timeout=30)
        resp.raise_for_status()
        rows = resp.json()
        for row in rows:
            query = row.get("query")
            if query:
                results[query] = row
        time.sleep(1.6)
    return results


def cn_tld(domain: str) -> int:
    return int(domain.endswith(CN_TLDS))


def is_cn_asn(as_text: str, asname: str) -> bool:
    hay = f"{as_text} {asname}".upper()
    return any(hint in hay for hint in CN_ASN_HINTS)


def dns_cn_signal(ips: List[str], ip_meta: Dict[str, dict]) -> Tuple[int, str, str]:
    if not ips:
        return 0, "", "no_dns"

    cn_hits = 0
    as_orgs = []
    reasons = []

    for ip in ips:
        meta = ip_meta.get(ip, {})
        cc = meta.get("countryCode", "")
        as_text = meta.get("as", "")
        asname = meta.get("asname", "")
        org = asname or as_text
        if org:
            as_orgs.append(org)
        if cc in CN_COUNTRY_CODES or is_cn_asn(as_text, asname):
            cn_hits += 1

    ratio = cn_hits / max(len(ips), 1)
    if ratio >= 0.6:
        reasons.append(f"dns_cn_ratio={ratio:.2f}")
        return 1, ";".join(ips), ";".join(sorted(set(as_orgs))[:5]), ";".join(reasons)

    if ratio > 0:
        reasons.append(f"partial_dns_cn_ratio={ratio:.2f}")
    else:
        reasons.append("dns_not_cn")
    return 0, ";".join(ips), ";".join(sorted(set(as_orgs))[:5]), ";".join(reasons)


def fetch_rdap_bootstrap(session: requests.Session) -> dict:
    resp = session.get(RDAP_BOOTSTRAP, headers={"User-Agent": USER_AGENT}, timeout=30)
    resp.raise_for_status()
    return resp.json()


def find_rdap_base(domain: str, bootstrap: dict) -> Optional[str]:
    labels = domain.lower().split(".")
    tld = labels[-1]
    service_entries = bootstrap.get("services", [])
    for entry in service_entries:
        suffixes, urls = entry
        if tld in suffixes and urls:
            return urls[0]
    return None


def rdap_lookup(domain: str, session: requests.Session, bootstrap: dict) -> Optional[dict]:
    base = find_rdap_base(domain, bootstrap)
    if not base:
        return None
    url = base.rstrip("/") + "/domain/" + domain
    try:
        resp = session.get(url, headers={"User-Agent": USER_AGENT}, timeout=25)
        if resp.status_code == 200:
            return resp.json()
    except requests.RequestException:
        return None
    return None


def whois_cn_signal(domain: str, rdap: Optional[dict]) -> Tuple[int, str]:
    reasons: List[str] = []
    if domain.endswith(".cn"):
        reasons.append("cn_tld_registrar_context")

    if not rdap:
        return 0, "no_rdap"

    entities = rdap.get("entities", []) or []
    registrarish = []
    for ent in entities:
        vcard = ent.get("vcardArray", [])
        if isinstance(vcard, list) and len(vcard) == 2:
            fields = vcard[1]
            for field in fields:
                if not isinstance(field, list) or len(field) < 4:
                    continue
                key = str(field[0]).lower()
                value = field[3]
                if key in {"fn", "org"}:
                    registrarish.append(str(value))
                if key == "adr":
                    registrarish.append(json.dumps(value, ensure_ascii=False))
                if key == "email":
                    registrarish.append(str(value))

    text = " ".join(registrarish).upper()
    if any(h in text for h in CN_REGISTRAR_HINTS):
        reasons.append("rdap_cn_entity")
        return 1, ";".join(reasons)

    links = rdap.get("links", []) or []
    for link in links:
        href = str(link.get("href", ""))
        host = urlparse(href).netloc.lower()
        if any(h in host for h in CN_RDAP_HOST_HINTS):
            reasons.append("rdap_cn_host")
            return 1, ";".join(reasons)

    return 0, "rdap_non_cn_or_unknown"


def build_rows(
    seed_domains: List[str],
    extended_domains: List[str],
    session: requests.Session,
) -> List[DomainRow]:
    combined: List[Tuple[str, str]] = []
    seen = set()

    for d in seed_domains:
        if d not in seen:
            combined.append((d, "seed"))
            seen.add(d)
    for d in extended_domains:
        if d not in seen:
            combined.append((d, "extended"))
            seen.add(d)

    resolved: Dict[str, List[str]] = {}
    all_ips = set()

    for domain, _source in combined:
        a = resolve_domain(domain, socket.AF_INET)
        aaaa = resolve_domain(domain, socket.AF_INET6)
        ips = sorted(set(a + aaaa))
        resolved[domain] = ips
        all_ips.update(ips)

    ip_meta = ip_api_lookup(sorted(all_ips), session) if all_ips else {}
    bootstrap = fetch_rdap_bootstrap(session)

    updated = time.strftime("%Y-%m-%d")
    rows: List[DomainRow] = []

    for domain, source in combined:
        ips = resolved[domain]
        dns_cn, resolved_ips, as_org, dns_reason = dns_cn_signal(ips, ip_meta)
        rdap = rdap_lookup(domain, session, bootstrap)
        whois_cn, whois_reason = whois_cn_signal(domain, rdap)
        tld_sig = cn_tld(domain)

        score = dns_cn * DNS_CN_WEIGHT + whois_cn * WHOIS_CN_WEIGHT + tld_sig * CN_TLD_WEIGHT

        reasons = [dns_reason, whois_reason]
        if tld_sig:
            reasons.append("cn_tld")

        rows.append(
            DomainRow(
                domain=domain,
                dns_cn=dns_cn,
                whois_cn=whois_cn,
                cn_tld=tld_sig,
                score=score,
                resolved_ips=resolved_ips,
                as_org=as_org,
                source=source,
                updated=updated,
                reasons=";".join(x for x in reasons if x),
            )
        )

    return rows


def write_csv(path: Path, rows: List[DomainRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(rows[0]).keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def write_dist(path: Path, rows: List[DomainRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    domains = [r.domain for r in rows if r.score >= 60]
    path.write_text("\n".join(domains) + ("\n" if domains else ""), encoding="utf-8")


def write_stats(path: Path, rows: List[DomainRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    score_bands = Counter()
    source_counts = Counter()
    for r in rows:
        source_counts[r.source] += 1
        if r.score >= 60:
            score_bands["cn"] += 1
        elif r.score >= 30:
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--seed", type=Path, default=None)
    parser.add_argument("--extended", type=Path, default=None)
    parser.add_argument("--data-csv", type=Path, default=None)
    parser.add_argument("--stats-json", type=Path, default=None)
    parser.add_argument("--dist-txt", type=Path, default=None)
    args = parser.parse_args()

    repo = args.repo_root.resolve()

    seed_path = args.seed or (repo / "sources" / "manual" / "seed.txt")
    extended_path = args.extended or (repo / "sources" / "manual" / "extended.txt")
    data_csv = args.data_csv or (repo / "data" / "domains.csv")
    stats_json = args.stats_json or (repo / "data" / "stats.json")
    dist_txt = args.dist_txt or (repo / "dist" / "domains.txt")

    seed_domains = load_domains(seed_path)
    extended_domains = load_domains(extended_path)

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    rows = build_rows(seed_domains, extended_domains, session)
    write_csv(data_csv, rows)
    write_stats(stats_json, rows)
    write_dist(dist_txt, rows)

    summary = {
        "seed_count": len(seed_domains),
        "extended_count": len(extended_domains),
        "total_unique": len(rows),
        "cn_domains": sum(1 for r in rows if r.score >= 60),
        "gray_domains": sum(1 for r in rows if 30 <= r.score < 60),
        "non_cn_domains": sum(1 for r in rows if r.score < 30),
        "data_csv": str(data_csv),
        "stats_json": str(stats_json),
        "dist_txt": str(dist_txt),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
