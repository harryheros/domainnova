#!/usr/bin/env python3
"""
4_score.py - Multi-signal scoring + generate dist/domains.txt

Scoring model (0-100):
  dns_cn   = 1  ->  +60 pts  (server physically resolves to China IP)
  whois_cn = 1  ->  +30 pts  (registrar/registrant is a Chinese entity)
  cn_tld        ->  +10 pts  (domain uses a Chinese TLD)

Threshold: score >= 60 -> included in dist/domains.txt
"""

import csv
import json
from pathlib import Path
from datetime import date

ROOT       = Path(__file__).resolve().parents[2]
DATA_CSV   = ROOT / "data" / "domains.csv"
DIST_TXT   = ROOT / "dist" / "domains.txt"
STATS_JSON = ROOT / "data" / "stats.json"

CN_TLDS = {
    "cn", "xn--fiqs8sirgfmh", "xn--fiqz9s",  # .中国 punycode variants
    "xn--55qx5d", "xn--io0a7i",               # .公司 .网络
}

SCORE_WEIGHTS = {
    "dns_cn":   60,
    "whois_cn": 30,
    "cn_tld":   10,
}

INCLUDE_THRESHOLD = 60


def get_tld(domain: str) -> str:
    parts = domain.rsplit(".", 1)
    return parts[-1].lower() if len(parts) > 1 else ""


def compute_score(row: dict) -> int:
    score = 0
    if row.get("dns_cn") == "1":
        score += SCORE_WEIGHTS["dns_cn"]
    if row.get("whois_cn") == "1":
        score += SCORE_WEIGHTS["whois_cn"]
    if get_tld(row.get("domain", "")) in CN_TLDS:
        score += SCORE_WEIGHTS["cn_tld"]
    return min(score, 100)


def run():
    if not DATA_CSV.exists():
        print("No data/domains.csv found.")
        return

    with open(DATA_CSV, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    today    = date.today().isoformat()
    included = []
    score_dist = {"100": 0, "90": 0, "60": 0, "30": 0, "0": 0}

    for row in rows:
        s = compute_score(row)
        row["score"] = str(s)

        if s >= 100:   score_dist["100"] += 1
        elif s >= 90:  score_dist["90"]  += 1
        elif s >= 60:  score_dist["60"]  += 1
        elif s >= 30:  score_dist["30"]  += 1
        else:          score_dist["0"]   += 1

        if s >= INCLUDE_THRESHOLD:
            included.append(row["domain"])

    fieldnames = list(rows[0].keys()) if rows else []
    if "score" not in fieldnames:
        fieldnames.append("score")

    with open(DATA_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    DIST_TXT.parent.mkdir(parents=True, exist_ok=True)
    with open(DIST_TXT, "w", encoding="utf-8") as f:
        f.write(f"# DomainNova - dist\n")
        f.write(f"# Generated: {today}\n")
        f.write(f"# Total: {len(included)} domains (score >= {INCLUDE_THRESHOLD})\n")
        f.write(f"# Source: https://github.com/harryheros/domainnova\n")
        f.write("#\n")
        for d in sorted(included):
            f.write(d + "\n")

    stats = {
        "generated":        today,
        "total_domains":    len(rows),
        "included_in_dist": len(included),
        "threshold":        INCLUDE_THRESHOLD,
        "score_distribution": score_dist,
        "signals": {
            "dns_cn":   sum(1 for r in rows if r.get("dns_cn")   == "1"),
            "whois_cn": sum(1 for r in rows if r.get("whois_cn") == "1"),
        }
    }
    with open(STATS_JSON, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)

    print(f"Scored {len(rows)} domains.")
    print(f"Included in dist: {len(included)} (score >= {INCLUDE_THRESHOLD})")
    print(f"Score distribution: {score_dist}")
    print(f"Output: {DIST_TXT}")


if __name__ == "__main__":
    run()
