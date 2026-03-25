#!/usr/bin/env python3
"""
2_dns_check.py - DNS resolution + ASN lookup for China detection

For each domain:
  1. Resolve to IP(s) via DNS
  2. Query ASN/org via ip-api.com (free, no API key required)
  3. Flag dns_cn=1 only if MAJORITY of resolved IPs are in CN ASN
     (not just any single IP - avoids false positives from CDN edge nodes)

Output: updates data/domains.csv
"""

import csv
import json
import socket
import time
import urllib.request
from pathlib import Path
from datetime import date

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


def load_seeds(path: Path) -> list[str]:
    domains = []
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


def run():
    today    = date.today().isoformat()
    existing = load_existing(INPUT_CSV)
    seeds    = load_seeds(SEED_FILE)

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
            ips = domain_ips[domain]
            cn_count = 0
            as_orgs  = set()

            for ip in ips:
                info    = ip_data.get(ip, {})
                country = info.get("countryCode", "")
                org     = info.get("org", info.get("as", ""))
                if country == "CN":
                    cn_count += 1
                if org:
                    as_orgs.add(org)

            # Require MAJORITY of resolved IPs to be CN
            # Single IP: must be CN. Multiple IPs: more than half must be CN.
            if len(ips) > 0:
                dns_cn = (cn_count / len(ips)) > 0.5
            else:
                dns_cn = False

            prev = existing.get(domain, {})

            results[domain] = {
                "domain":        domain,
                "dns_cn":        "1" if dns_cn else "0",
                "dns_cn_count":  str(cn_count),
                "dns_total":     str(len(ips)),
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
        "registrar_cn", "registrant_cn", "score",
        "resolved_ips", "as_org", "source", "updated"
    ]
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for domain in all_domains:
            if domain in results:
                writer.writerow(results[domain])

    cn_count = sum(1 for r in results.values() if r["dns_cn"] == "1")
    print(f"\nDone. {cn_count}/{len(results)} domains have majority CN IPs.")
    print(f"Output: {OUTPUT_CSV}")


if __name__ == "__main__":
    run()
