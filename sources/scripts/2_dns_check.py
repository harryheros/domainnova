#!/usr/bin/env python3
"""
2_dns_check.py - Advanced DNS Intelligence & Asset Profiling

For each domain:
  1. Resolve to IP(s) via DNS
  2. Query ASN/org via ip-api.com (free, no API key required)
  3. Cross-reference with constants.py to tag provider and infrastructure layer
  4. Flag dns_cn=1 only if MAJORITY of IPs are in mainland CN
     (excludes HK/MO/TW and known non-mainland regions)
"""

import csv
import json
import socket
import sys
import time
import urllib.request
from pathlib import Path
from datetime import date

sys.path.insert(0, str(Path(__file__).parent))
from constants import CN_BACKBONE, CN_CLOUD_ASNS, NON_MAINLAND_REGIONS

ROOT       = Path(__file__).resolve().parents[2]
INPUT_CSV  = ROOT / "data" / "domains.csv"
OUTPUT_CSV = ROOT / "data" / "domains.csv"
SEED_FILE  = ROOT / "sources" / "manual" / "seed.txt"

IP_API_BATCH          = "http://ip-api.com/batch"
BATCH_SIZE            = 100
SLEEP_BETWEEN_BATCHES = 1.5


def load_existing(path: Path) -> dict:
    rows = {}
    if not path.exists():
        return rows
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows[row["domain"]] = row
    return rows


def load_seeds(*paths: Path) -> list[str]:
    domains = []
    for path in paths:
        if not path.exists():
            print(f"  [info] {path.name} not found, skipping.")
            continue
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.append(line.lower())
    return domains


def resolve_domain(domain: str) -> list[str]:
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        return list({r[4][0] for r in results})
    except Exception:
        return []


def query_ips_batch(ips: list[str]) -> dict[str, dict]:
    payload = json.dumps([{"query": ip} for ip in ips]).encode()
    req = urllib.request.Request(
        IP_API_BATCH,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            results = json.loads(resp.read().decode())
        return {r["query"]: r for r in results if "query" in r}
    except Exception as e:
        print(f"  [warn] ip-api batch failed: {e}")
        return {}


def get_asset_profile(as_str: str, domain: str) -> dict:
    as_num = as_str.split()[0].replace("AS", "") if as_str else ""

    profile = {
        "provider":     "Generic_CN",
        "infra_layer":  "Edge",
        "is_strategic": "0",
    }

    if as_num in CN_BACKBONE:
        entry = CN_BACKBONE[as_num]
        profile["provider"]    = entry["isp"]
        profile["infra_layer"] = entry.get("level", "Core")
    elif as_num in CN_CLOUD_ASNS:
        profile["provider"]    = CN_CLOUD_ASNS[as_num]
        profile["infra_layer"] = "Cloud"

    if (domain.endswith(".gov.cn") or domain == "gov.cn"
            or domain.endswith(".edu.cn") or domain == "edu.cn"):
        profile["is_strategic"] = "1"

    return profile


def run():
    today    = date.today().isoformat()
    existing = load_existing(INPUT_CSV)
    seeds = load_seeds(
        SEED_FILE,
        ROOT / "sources" / "manual" / "extended.txt",
    )

    all_domains = list(dict.fromkeys(seeds + list(existing.keys())))
    print(f"Total domains to process: {len(all_domains)}")

    results = {}

    for i in range(0, len(all_domains), BATCH_SIZE):
        batch = all_domains[i : i + BATCH_SIZE]
        print(f"Batch {i // BATCH_SIZE + 1}: resolving {len(batch)} domains...")

        domain_ips: dict[str, list[str]] = {}
        all_ips: list[str] = []
        for domain in batch:
            ips = resolve_domain(domain)
            domain_ips[domain] = ips
            all_ips.extend(ips)

        unique_ips = list(set(all_ips))
        ip_data: dict[str, dict] = {}
        if unique_ips:
            for j in range(0, len(unique_ips), 100):
                ip_data.update(query_ips_batch(unique_ips[j : j + 100]))

        for domain in batch:
            ips          = domain_ips[domain]
            cn_count     = 0
            as_orgs      = set()
            providers    = set()
            infra_layers = set()
            is_strategic = "0"

            for ip in ips:
                info    = ip_data.get(ip, {})
                country = info.get("countryCode", "")
                org     = info.get("org", info.get("as", ""))

                if country == "CN" and country not in NON_MAINLAND_REGIONS:
                    profile = get_asset_profile(info.get("as", ""), domain)
                    cn_count += 1
                    providers.add(profile["provider"])
                    infra_layers.add(profile["infra_layer"])
                    if profile["is_strategic"] == "1":
                        is_strategic = "1"

                if org:
                    as_orgs.add(org)

            # Also flag strategic even if dns_cn=0 (e.g. gov.cn behind CDN)
            if (domain.endswith(".gov.cn") or domain == "gov.cn"
                    or domain.endswith(".edu.cn") or domain == "edu.cn"):
                is_strategic = "1"

            dns_cn = (cn_count / len(ips) > 0.5) if ips else False

            prev = existing.get(domain, {})

            results[domain] = {
                "domain":        domain,
                "dns_cn":        "1" if dns_cn else "0",
                "dns_cn_count":  str(cn_count),
                "dns_total":     str(len(ips)),
                "provider":      "; ".join(sorted(providers)) if providers else "",
                "infra_layer":   "; ".join(sorted(infra_layers)) if infra_layers else "",
                "is_strategic":  is_strategic,
                "resolved_ips":  "|".join(ips[:3]),
                "as_org":        "; ".join(sorted(as_orgs)[:2]),
                "registrar_cn":  prev.get("registrar_cn", ""),
                "registrant_cn": prev.get("registrant_cn", ""),
                "score":         "",
                "source":        prev.get("source", "seed"),
                "updated":       today,
            }

        time.sleep(SLEEP_BETWEEN_BATCHES)

    fieldnames = [
        "domain", "dns_cn", "dns_cn_count", "dns_total",
        "provider", "infra_layer", "is_strategic",
        "registrar_cn", "registrant_cn", "score",
        "resolved_ips", "as_org", "source", "updated",
    ]
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for domain in all_domains:
            if domain in results:
                writer.writerow(results[domain])

    cn_count = sum(1 for r in results.values() if r["dns_cn"] == "1")
    print(f"\nDone. {cn_count}/{len(results)} domains have majority mainland CN IPs.")
    print(f"Output: {OUTPUT_CSV}")


if __name__ == "__main__":
    run()
