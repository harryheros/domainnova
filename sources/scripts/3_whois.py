#!/usr/bin/env python3
"""
3_whois.py - WHOIS/RDAP lookup for China detection

Uses RDAP (modern replacement for WHOIS) - no external libraries needed.
IANA bootstrap file maps TLDs to their RDAP servers.

Two separate signals:
  registrar_cn  - the domain registrar is a known Chinese company
  registrant_cn - the domain registrant/owner claims CN country
"""

import csv
import json
import time
import urllib.request
from pathlib import Path
from datetime import date

ROOT     = Path(__file__).resolve().parents[2]
DATA_CSV = ROOT / "data" / "domains.csv"

CN_REGISTRAR_KEYWORDS = [
    "alibaba", "aliyun", "hichina", "wanwang",
    "tencent", "dnspod",
    "huawei",
    "godaddy china", "west.cn", "west263",
    "xinnet", "35.com", "22.cn", "ename",
    "cndns", "now.cn", "bizcn",
]

RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
SLEEP = 1.0


def fetch_json(url: str, timeout: int = 10) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        print(f"  [warn] fetch failed {url}: {e}")
        return None


def build_rdap_map(bootstrap: dict) -> dict[str, str]:
    tld_map = {}
    for service in bootstrap.get("services", []):
        tlds, urls = service
        if urls:
            base = urls[0].rstrip("/")
            for tld in tlds:
                tld_map[tld.lower()] = base
    return tld_map


def rdap_lookup(domain: str, tld_map: dict) -> dict:
    parts = domain.rsplit(".", 1)
    if len(parts) < 2:
        return {}
    base = tld_map.get(parts[1].lower())
    if not base:
        return {}
    return fetch_json(f"{base}/domain/{domain}") or {}


def extract_signals(rdap: dict) -> tuple[bool, bool]:
    """
    Returns (registrar_cn, registrant_cn).
    registrar_cn  = True if the domain registrar is a Chinese company
    registrant_cn = True if the registrant country is CN
    """
    if not rdap:
        return False, False

    registrar_cn  = False
    registrant_cn = False

    for entity in rdap.get("entities", []):
        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray", [])
        name    = ""
        country = ""

        if isinstance(vcard, list) and len(vcard) > 1:
            for field in vcard[1]:
                if isinstance(field, list):
                    label = field[0] if field else ""
                    val   = field[3] if len(field) > 3 else ""
                    if label == "fn":
                        name = str(val)
                    if label == "adr" and isinstance(val, list) and val:
                        country = str(val[-1]).upper()

        if "registrar" in roles:
            name_lower = name.lower()
            if any(kw in name_lower for kw in CN_REGISTRAR_KEYWORDS):
                registrar_cn = True
            elif country == "CN":
                registrar_cn = True

        if "registrant" in roles and country == "CN":
            registrant_cn = True

    return registrar_cn, registrant_cn


def run():
    if not DATA_CSV.exists():
        print("No data/domains.csv found. Run 2_dns_check.py first.")
        return

    with open(DATA_CSV, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        print("Empty CSV.")
        return

    print("Fetching RDAP bootstrap from IANA...")
    bootstrap = fetch_json(RDAP_BOOTSTRAP)
    if not bootstrap:
        print("Failed to fetch RDAP bootstrap. Skipping.")
        return
    tld_map = build_rdap_map(bootstrap)
    print(f"Loaded {len(tld_map)} TLD -> RDAP server mappings.")

    today   = date.today().isoformat()
    updated = 0

    for i, row in enumerate(rows):
        domain = row["domain"]

        already_checked = (
            row.get("registrar_cn") != "" and
            row.get("registrant_cn") != "" and
            row.get("updated") == today
        )
        if already_checked:
            continue

        if i % 20 == 0:
            print(f"  RDAP {i}/{len(rows)}: {domain}")

        rdap = rdap_lookup(domain, tld_map)
        registrar_cn, registrant_cn = extract_signals(rdap)

        row["registrar_cn"]  = "1" if registrar_cn  else "0"
        row["registrant_cn"] = "1" if registrant_cn else "0"
        row["updated"]       = today
        updated += 1

        time.sleep(SLEEP)

    fieldnames = list(rows[0].keys()) if rows else []
    with open(DATA_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    reg_cn  = sum(1 for r in rows if r.get("registrar_cn")  == "1")
    regt_cn = sum(1 for r in rows if r.get("registrant_cn") == "1")
    print(f"\nDone. registrar_cn={reg_cn}, registrant_cn={regt_cn}, updated={updated} rows.")


if __name__ == "__main__":
    run()
