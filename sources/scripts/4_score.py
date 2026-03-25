#!/usr/bin/env python3
"""
4_score.py - Strategic Asset Scoring & Distribution Generation

Scoring Model (Intelligence-Led):
  - Physical Location (dns_cn=1) -> REQUIRED (Base 60 pts)
  - Infrastructure Layer:
    - Core/Premium Backbone  -> +20 pts
    - Cloud/Academic/Generic -> +10 pts
  - Strategic Identity (is_strategic=1) -> +20 pts
  - Business Identity (registrar_cn=1)  -> +10 pts

Threshold: score >= 60 -> included in dist/domains.txt
Note: dns_cn=1 is a hard requirement. No CN infrastructure = score 0.
"""

import csv
import json
from pathlib import Path
from datetime import date

ROOT       = Path(__file__).resolve().parents[2]
DATA_CSV   = ROOT / "data" / "domains.csv"
DIST_TXT   = ROOT / "dist" / "domains.txt"
STATS_JSON = ROOT / "data" / "stats.json"

INCLUDE_THRESHOLD = 60


def compute_strategic_score(row: dict) -> int:
    # Hard requirement: must have mainland CN infrastructure
    if row.get("dns_cn") != "1":
        return 0

    score = 60

    layer = row.get("infra_layer", "")
    if "Core" in layer or "Premium" in layer:
        score += 20
    elif "Cloud" in layer or "Academic" in layer:
        score += 10
    else:
        # Generic CN infrastructure - still valid, give base bonus
        score += 10

    if row.get("is_strategic") == "1":
        score += 20

    if row.get("registrar_cn") == "1":
        score += 10

    return min(score, 100)


def run():
    if not DATA_CSV.exists():
        print(f"Error: {DATA_CSV} not found.")
        return

    with open(DATA_CSV, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    today    = date.today().isoformat()
    included = []

    stats = {
        "total":           len(rows),
        "providers":       {},
        "layers":          {},
        "strategic_count": 0,
    }

    for row in rows:
        s = compute_strategic_score(row)
        row["score"] = str(s)

        if s >= INCLUDE_THRESHOLD:
            included.append(row["domain"])
            p = row.get("provider", "Unknown") or "Unknown"
            l = row.get("infra_layer", "Edge") or "Edge"
            stats["providers"][p] = stats["providers"].get(p, 0) + 1
            stats["layers"][l]    = stats["layers"].get(l, 0) + 1
            if row.get("is_strategic") == "1":
                stats["strategic_count"] += 1

    fieldnames = list(rows[0].keys()) if rows else []
    with open(DATA_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    DIST_TXT.parent.mkdir(parents=True, exist_ok=True)
    with open(DIST_TXT, "w", encoding="utf-8") as f:
        f.write(f"# DomainNova - Mainland China Strategic Assets\n")
        f.write(f"# Generated: {today}\n")
        f.write(f"# Total: {len(included)} high-confidence domains\n")
        f.write(f"# Criteria: Mainland DNS + Infrastructure Verified\n")
        f.write(f"# Source: https://github.com/harryheros/domainnova\n#\n")
        for d in sorted(included):
            f.write(d + "\n")

    with open(STATS_JSON, "w", encoding="utf-8") as f:
        json.dump({
            "updated":   today,
            "summary":   stats,
            "threshold": INCLUDE_THRESHOLD,
        }, f, indent=2)

    print(f"Update complete: {len(included)} domains verified as mainland assets.")


if __name__ == "__main__":
    run()
