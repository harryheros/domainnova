#!/usr/bin/env python3
"""
validate_manual_sources.py – Validate DomainNova manual domain sources.

Checks:
  - duplicate domains within each source file
  - cross-source overlaps between seed and extended
  - cross-region duplicates between regional seed files
  - syntactic validity for each domain label (RFC 1123)
  - domains not under any named section header

Output: JSON to stdout  +  data/manual_source_validation.json

FIXES (v3):
  - Also validates regional seed files (seed_hk/mo/tw/jp/kr/sg).
  - Reports cross-region duplicates between regional seeds.
  - Reports foxconn-style conflicts (domain in both CN seed and regional seed).
  - Exit code 1 only for genuine errors (duplicates within a file, invalid format).
  - Cross-source overlap is NOT an error – build_domains.py deduplicates automatically.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Primary files (checked for duplicates + cross-overlap)
CORE_FILES = {
    "seed_cn":     ROOT / "sources" / "manual" / "seed_cn.txt",
    "extended": ROOT / "sources" / "manual" / "extended.txt",
}

# Regional seed files (checked for duplicates + cross-region conflicts)
REGIONAL_FILES = {
    "seed_hk":      ROOT / "sources" / "manual" / "seed_hk.txt",
    "seed_mo":      ROOT / "sources" / "manual" / "seed_mo.txt",
    "seed_tw":      ROOT / "sources" / "manual" / "seed_tw.txt",
    "seed_jp":      ROOT / "sources" / "manual" / "seed_jp.txt",
    "seed_kr":      ROOT / "sources" / "manual" / "seed_kr.txt",
    "seed_sg":      ROOT / "sources" / "manual" / "seed_sg.txt",
    "seed_offshore": ROOT / "sources" / "manual" / "seed_offshore.txt",
}

OUT_JSON = ROOT / "data" / "manual_source_validation.json"

HEADER_RE = re.compile(r"^#\s*=+\s*(.*?)\s*=+\s*$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$"
)


def parse(path: Path) -> dict:
    if not path.exists():
        return {"error": f"{path} not found"}

    section      = "Unsectioned"
    domains:     list[tuple[str, str]] = []
    invalid:     list[str] = []
    unsectioned: list[str] = []
    counts:      Counter = Counter()

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            m = HEADER_RE.match(line)
            if m:
                section = m.group(1).strip()
            continue
        domain = line.lower().rstrip(".")
        domains.append((domain, section))
        counts[domain] += 1
        if not DOMAIN_RE.match(domain):
            invalid.append(domain)
        if section == "Unsectioned":
            unsectioned.append(domain)

    duplicates = sorted(d for d, c in counts.items() if c > 1)
    return {
        "count":       len(domains),
        "duplicates":  duplicates,
        "invalid":     sorted(set(invalid)),
        "unsectioned": sorted(set(unsectioned)),
    }


def load_domain_set(path: Path) -> set[str]:
    if not path.exists():
        return set()
    items: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        items.add(line.lower().rstrip("."))
    return items


def main() -> None:
    all_files = {**CORE_FILES, **REGIONAL_FILES}
    parsed = {name: parse(path) for name, path in all_files.items()}

    # Cross-source overlap (seed_cn.txt vs extended.txt)
    seed_set     = load_domain_set(CORE_FILES["seed_cn"])
    extended_set = load_domain_set(CORE_FILES["extended"])
    overlaps = sorted(seed_set & extended_set)

    # Cross-region duplicates between regional seeds
    regional_sets = {name: load_domain_set(path) for name, path in REGIONAL_FILES.items()}
    regional_names = list(regional_sets.keys())
    cross_region: dict[str, list[str]] = {}
    for i in range(len(regional_names)):
        for j in range(i + 1, len(regional_names)):
            a, b = regional_names[i], regional_names[j]
            overlap = sorted(regional_sets[a] & regional_sets[b])
            if overlap:
                cross_region[f"{a} ∩ {b}"] = overlap

    # CN seed vs regional seeds conflicts
    cn_regional_conflicts: dict[str, list[str]] = {}
    for name, rset in regional_sets.items():
        conflict = sorted(seed_set & rset)
        if conflict:
            cn_regional_conflicts[f"seed_cn ∩ {name}"] = conflict

    result = {
        "seed_cn":                    parsed.get("seed_cn", {}),
        "extended":                parsed.get("extended", {}),
        "regional":                {k: parsed.get(k, {}) for k in REGIONAL_FILES},
        "cross_source_overlap":    overlaps,
        "cross_region_duplicates": cross_region,
        "cn_regional_conflicts":   cn_regional_conflicts,
    }

    output = json.dumps(result, ensure_ascii=False, indent=2)
    print(output)

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(output + "\n", encoding="utf-8")

    # Collect all errors
    has_errors = (
        bool(result.get("seed_cn",     {}).get("duplicates"))
        or bool(result.get("extended", {}).get("duplicates"))
        or bool(result.get("seed_cn",     {}).get("invalid"))
        or bool(result.get("extended", {}).get("invalid"))
        or any(v.get("duplicates") for v in result["regional"].values())
        or any(v.get("invalid")    for v in result["regional"].values())
        or bool(cross_region)
        or bool(cn_regional_conflicts)
    )

    if overlaps:
        print(f"\n[i] {len(overlaps)} domain(s) in both seed and extended "
              f"(deduplicated at build time, seed wins).", file=sys.stderr)
    if cross_region:
        print(f"\n[!] Cross-region duplicates found: {cross_region}", file=sys.stderr)
    if cn_regional_conflicts:
        print(f"\n[!] CN seed conflicts with regional seeds: {cn_regional_conflicts}", file=sys.stderr)
    if has_errors:
        print("\n[!] Validation found errors – see above.", file=sys.stderr)
        sys.exit(1)
    else:
        print("\n[✓] All checks passed.", file=sys.stderr)


if __name__ == "__main__":
    main()
