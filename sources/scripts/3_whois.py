#!/usr/bin/env python3
"""
3_whois.py - WHOIS/RDAP registrar lookup for China detection

Uses RDAP (modern replacement for WHOIS) - no external libraries needed.
IANA bootstrap file tells us which RDAP server handles each TLD.

Signals checked:
  - Registrar country == CN
  - Registrar name matches known Chinese registrars
  - Registrant country == CN
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
    tld = parts[1].lower()
    base = tld_map.get(tld)
    if not base:
        return {}
    return fetch_json(f"{base}/domain/{domain}") or {}


def extract_cn_signals(rdap: dict) -> tuple[bool, str]:
    if not rdap:
        return False, ""

    for entity in rdap.get("entities", []):
        roles  = entity.get("roles", [])
        vcard  = entity.get("vcardArray", [])
        name   = ""
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
                return True, name
            if country == "CN":
                return True, name

        if "registrant" in roles and country == "CN":
            return True, f"registrant:CN ({name})"

    return False, ""


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

        if row.get("whois_cn") and row.get("updated") == today:
            continue

        if i % 20 == 0:
            print(f"  WHOIS {i}/{len(rows)}: {domain}")

        rdap   = rdap_lookup(domain, tld_map)
        is_cn, registrar = extract_cn_signals(rdap)

        row["whois_cn"] = "1" if is_cn else "0"
        if registrar and not row.get("as_org"):
            row["as_org"] = registrar
        row["updated"] = today
        updated += 1

        time.sleep(SLEEP)

    fieldnames = list(rows[0].keys()) if rows else []
    with open(DATA_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nDone. Updated {updated} rows.")


if __name__ == "__main__":
    run()
