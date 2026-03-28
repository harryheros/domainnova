#!/usr/bin/env python3
"""
validate_manual_sources.py – Validate DomainNova manual domain sources.

Checks:
  - duplicate domains within each source file
  - cross-source overlaps between seed and extended
  - syntactic validity for each domain label (RFC 1123)
  - domains not under any named section header

Output: JSON to stdout  +  data/manual_source_validation.json

FIXES (v2):
  - Also writes result to data/manual_source_validation.json.
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
FILES = {
    "seed":     ROOT / "sources" / "manual" / "seed.txt",
    "extended": ROOT / "sources" / "manual" / "extended.txt",
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


def main() -> None:
    parsed = {name: parse(path) for name, path in FILES.items()}

    # Cross-source overlap
    domain_sets: dict[str, set[str]] = {}
    for name, path in FILES.items():
        if not path.exists():
            domain_sets[name] = set()
            continue
        items: set[str] = set()
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            items.add(line.lower().rstrip("."))
        domain_sets[name] = items

    overlaps = sorted(
        domain_sets.get("seed", set()) & domain_sets.get("extended", set())
    )

    result = {
        "seed":                 parsed.get("seed", {}),
        "extended":             parsed.get("extended", {}),
        "cross_source_overlap": overlaps,
    }

    output = json.dumps(result, ensure_ascii=False, indent=2)
    print(output)

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(output + "\n", encoding="utf-8")

    # Exit 1 only for genuine errors: duplicates within a file, or invalid format.
    # Cross-source overlap is NOT an error – build_domains.py deduplicates (seed wins).
    has_errors = (
        bool(result.get("seed",     {}).get("duplicates"))
        or bool(result.get("extended", {}).get("duplicates"))
        or bool(result.get("seed",     {}).get("invalid"))
        or bool(result.get("extended", {}).get("invalid"))
    )
    if overlaps:
        print(f"\n[i] {len(overlaps)} domain(s) in both seed and extended "
              f"(deduplicated at build time, seed wins).", file=sys.stderr)
    if has_errors:
        print("\n[!] Validation found errors – see above.", file=sys.stderr)
        sys.exit(1)
    else:
        print("\n[✓] All checks passed.", file=sys.stderr)


if __name__ == "__main__":
    main()
