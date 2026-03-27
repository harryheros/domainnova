#!/usr/bin/env python3
"""
build_metadata.py – Build structured metadata from DomainNova's manual sources.

This script is intentionally additive and non-invasive:
  - preserves manual/curated source files as the source of truth
  - derives a metadata layer from section headers and domain patterns
  - emits machine-readable artifacts without altering DomainNova's worldview

Outputs:
  data/domains_metadata.json
  data/domains_metadata.yaml
  data/domains_metadata.csv
  data/metadata_stats.json
  data/manual_source_validation.json
  dist/seed_domains.txt
  dist/extended_domains.txt

FIXES / UPGRADES (v2):
  - YAML output no longer depends on PyYAML; uses a lightweight inline writer
    so the script runs in any plain Python 3.9+ environment without extras.
  - Validation report now written to data/manual_source_validation.json
    (was only printed to stdout; now also saved as a file).
  - Section override map expanded with missing entries seen in extended.txt.
  - Added --validate-only flag: run validation and exit without writing outputs.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable

ROOT          = Path(__file__).resolve().parents[2]
SEED_FILE     = ROOT / "sources" / "manual" / "seed.txt"
EXTENDED_FILE = ROOT / "sources" / "manual" / "extended.txt"

OUT_JSON       = ROOT / "data" / "domains_metadata.json"
OUT_YAML       = ROOT / "data" / "domains_metadata.yaml"
OUT_CSV        = ROOT / "data" / "domains_metadata.csv"
OUT_STATS      = ROOT / "data" / "metadata_stats.json"
OUT_VALIDATION = ROOT / "data" / "manual_source_validation.json"
DIST_SEED      = ROOT / "dist" / "seed_domains.txt"
DIST_EXTENDED  = ROOT / "dist" / "extended_domains.txt"

HEADER_RE = re.compile(r"^#\s*=+\s*(.*?)\s*=+\s*$")
DOM_RE    = re.compile(r"^[A-Za-z0-9.-]+$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$"
)

SECTION_OVERRIDES: dict[str, dict] = {
    "Alibaba Ecosystem":           {"ecosystem": "alibaba",           "entity": "Alibaba Group / Ant Group", "category": "platform"},
    "Tencent Ecosystem":           {"ecosystem": "tencent",           "entity": "Tencent",                   "category": "platform"},
    "Baidu Ecosystem":             {"ecosystem": "baidu",             "entity": "Baidu",                     "category": "platform"},
    "ByteDance Ecosystem":         {"ecosystem": "bytedance",         "entity": "ByteDance",                 "category": "platform"},
    "JD.com Ecosystem":            {"ecosystem": "jd",                "entity": "JD.com",                    "category": "platform"},
    "Xiaomi Ecosystem":            {"ecosystem": "xiaomi",            "entity": "Xiaomi",                    "category": "consumer_tech"},
    "Huawei Ecosystem":            {"ecosystem": "huawei",            "entity": "Huawei",                    "category": "cloud_device"},
    "Consumer Devices":            {"ecosystem": "consumer-devices",  "entity": "Multi-brand",               "category": "consumer_device"},
    "Pinduoduo":                   {"ecosystem": "pinduoduo",         "entity": "Pinduoduo",                 "category": "platform"},
    "Cloud & IDC":                 {"ecosystem": "cloud-idc",         "entity": "Multi-operator",            "category": "cloud_idc"},
    "CDN & Storage":               {"ecosystem": "cdn-storage",       "entity": "Multi-provider",            "category": "cdn_storage"},
    "DNS & Domain":                {"ecosystem": "dns-domain",        "entity": "Multi-provider",            "category": "dns_domain"},
    "Telecom & Backbone":          {"ecosystem": "telecom-backbone",  "entity": "National Backbone",         "category": "telecom_backbone"},
    "Security & Network Equipment":{"ecosystem": "security-network",  "entity": "Multi-vendor",              "category": "security_network"},
    "Developer Platforms":         {"ecosystem": "developer-platforms","entity": "Multi-platform",           "category": "developer_platform"},
    "Central Government":          {"ecosystem": "government-cn",     "entity": "PRC Central Government",    "category": "government"},
    "Finance & Banking":           {"ecosystem": "finance-banking",   "entity": "Multi-institution",         "category": "finance"},
    "Media & Entertainment":       {"ecosystem": "media-entertainment","entity": "Multi-brand",              "category": "media"},
    "E-Commerce":                  {"ecosystem": "ecommerce",         "entity": "Multi-brand",               "category": "ecommerce"},
    "Travel & Hospitality":        {"ecosystem": "travel",            "entity": "Multi-brand",               "category": "travel"},
    "Healthcare":                  {"ecosystem": "healthcare",        "entity": "Multi-institution",         "category": "healthcare"},
    "Education":                   {"ecosystem": "education",         "entity": "Multi-institution",         "category": "education"},
    "Gaming":                      {"ecosystem": "gaming",            "entity": "Multi-brand",               "category": "gaming"},
}


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------
@dataclass
class DomainMeta:
    domain:    str
    source:    str
    section:   str
    ecosystem: str
    entity:    str
    category:  str


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def parse_source(path: Path, source_name: str) -> list[DomainMeta]:
    if not path.exists():
        print(f"  [warn] {path} not found – skipping.")
        return []

    section   = "Unsectioned"
    overrides = {}
    entries: list[DomainMeta] = []

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            m = HEADER_RE.match(line)
            if m:
                section   = m.group(1).strip()
                overrides = SECTION_OVERRIDES.get(section, {})
            continue

        domain = line.lower().rstrip(".")
        if not DOM_RE.match(domain):
            continue

        entries.append(
            DomainMeta(
                domain    = domain,
                source    = source_name,
                section   = section,
                ecosystem = overrides.get("ecosystem", "unknown"),
                entity    = overrides.get("entity",    "Unknown"),
                category  = overrides.get("category",  "uncategorized"),
            )
        )

    return entries


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def validate(path: Path) -> dict:
    if not path.exists():
        return {"error": f"{path.name} not found"}

    section   = "Unsectioned"
    domains:   list[tuple[str, str]] = []
    invalid:   list[str]  = []
    unsectioned: list[str] = []
    counts:    Counter = Counter()

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


# ---------------------------------------------------------------------------
# Lightweight YAML writer (no PyYAML dependency)
# ---------------------------------------------------------------------------
def _yaml_str(value: str) -> str:
    """Quote a string if it contains special YAML characters."""
    if any(ch in value for ch in (':',  '#', "'", '"', '\n', '{')):
        escaped = value.replace('"', '\\"')
        return f'"{escaped}"'
    return value


def entries_to_yaml(entries: list[DomainMeta]) -> str:
    lines = ["---"]
    for e in entries:
        lines.append(f"- domain:    {_yaml_str(e.domain)}")
        lines.append(f"  source:    {_yaml_str(e.source)}")
        lines.append(f"  section:   {_yaml_str(e.section)}")
        lines.append(f"  ecosystem: {_yaml_str(e.ecosystem)}")
        lines.append(f"  entity:    {_yaml_str(e.entity)}")
        lines.append(f"  category:  {_yaml_str(e.category)}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def run(write_all: bool = True, validate_only: bool = False) -> None:
    seed_entries     = parse_source(SEED_FILE,     "seed")
    extended_entries = parse_source(EXTENDED_FILE, "extended")

    # ---- Validation ----
    validation_report = {
        "seed":     validate(SEED_FILE),
        "extended": validate(EXTENDED_FILE),
    }
    # Cross-source overlap
    seed_set     = {e.domain for e in seed_entries}
    extended_set = {e.domain for e in extended_entries}
    validation_report["cross_source_overlap"] = sorted(seed_set & extended_set)

    print(json.dumps(validation_report, ensure_ascii=False, indent=2))

    if validate_only:
        return

    # ---- Deduplicate (seed wins over extended) ----
    seen:    set[str]       = set()
    entries: list[DomainMeta] = []
    for e in seed_entries + extended_entries:
        if e.domain not in seen:
            seen.add(e.domain)
            entries.append(e)

    if not write_all:
        return

    # ---- Write outputs ----
    ROOT.joinpath("data").mkdir(parents=True, exist_ok=True)
    ROOT.joinpath("dist").mkdir(parents=True, exist_ok=True)

    # JSON
    OUT_JSON.write_text(
        json.dumps([asdict(e) for e in entries], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    # YAML (no external dependency)
    OUT_YAML.write_text(entries_to_yaml(entries), encoding="utf-8")

    # CSV
    with OUT_CSV.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["domain","source","section","ecosystem","entity","category"])
        writer.writeheader()
        for e in entries:
            writer.writerow(asdict(e))

    # Validation report
    OUT_VALIDATION.write_text(
        json.dumps(validation_report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    # Stats
    eco_counts  = Counter(e.ecosystem for e in entries)
    cat_counts  = Counter(e.category  for e in entries)
    src_counts  = Counter(e.source    for e in entries)
    stats = {
        "total":      len(entries),
        "by_source":  dict(src_counts),
        "by_ecosystem": dict(eco_counts.most_common()),
        "by_category":  dict(cat_counts.most_common()),
    }
    OUT_STATS.write_text(
        json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    # dist plain lists
    DIST_SEED.write_text(
        "\n".join(e.domain for e in entries if e.source == "seed") + "\n",
        encoding="utf-8",
    )
    DIST_EXTENDED.write_text(
        "\n".join(e.domain for e in entries if e.source == "extended") + "\n",
        encoding="utf-8",
    )

    print(f"\n[+] Wrote {len(entries)} entries to data/ and dist/")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build DomainNova metadata artifacts.")
    parser.add_argument("--all",           dest="write_all",     action="store_true",
                        help="Write all output files (default when flag present).")
    parser.add_argument("--validate-only", dest="validate_only", action="store_true",
                        help="Run validation checks only; do not write any files.")
    args = parser.parse_args()
    run(write_all=args.write_all, validate_only=args.validate_only)


if __name__ == "__main__":
    main()
