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
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable

# Shared regex + iteration primitives (HEADER_RE, DOMAIN_RE, iter_source_entries).
import sys as _sys
_sys.path.insert(0, str(Path(__file__).resolve().parent))
from _source_parser import (  # noqa: E402
    DOMAIN_RE,
    HEADER_RE,
    UNSECTIONED,
    iter_source_entries,
)

ROOT          = Path(__file__).resolve().parents[2]
SEED_FILES = {
    "seed_cn": ROOT / "sources" / "manual" / "seed_cn.txt",
    "seed_hk": ROOT / "sources" / "manual" / "seed_hk.txt",
    "seed_mo": ROOT / "sources" / "manual" / "seed_mo.txt",
    "seed_tw": ROOT / "sources" / "manual" / "seed_tw.txt",
    "seed_jp": ROOT / "sources" / "manual" / "seed_jp.txt",
    "seed_kr": ROOT / "sources" / "manual" / "seed_kr.txt",
    "seed_sg": ROOT / "sources" / "manual" / "seed_sg.txt",
}
EXTENDED_FILE = ROOT / "sources" / "manual" / "extended.txt"

OUT_JSON       = ROOT / "data" / "domains_metadata.json"
OUT_YAML       = ROOT / "data" / "domains_metadata.yaml"
OUT_CSV        = ROOT / "data" / "domains_metadata.csv"
OUT_STATS      = ROOT / "data" / "metadata_stats.json"
OUT_VALIDATION = ROOT / "data" / "manual_source_validation.json"

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
    # ── Region seed top-level headers ──────────────────────────────────────
    # These are the file-level titles in each seed_xx.txt. Without entries here
    # they fall through as ecosystem=unknown; mapping them to their region's
    # infrastructure identity gives correct metadata for the whole seed file.
    "DomainNova - Seed Domains (Hong Kong)":        {"ecosystem": "infrastructure-hk", "entity": "Hong Kong Infrastructure",  "category": "infrastructure"},
    "DomainNova - Seed Domains (Macau)":            {"ecosystem": "infrastructure-mo", "entity": "Macau Infrastructure",      "category": "infrastructure"},
    "DomainNova - Seed Domains (Taiwan - Expanded)":{"ecosystem": "infrastructure-tw", "entity": "Taiwan Infrastructure",     "category": "infrastructure"},
    "DomainNova - Seed Domains (Japan - Expanded)": {"ecosystem": "infrastructure-jp", "entity": "Japan Infrastructure",      "category": "infrastructure"},
    "DomainNova - Seed Domains (South Korea)":      {"ecosystem": "infrastructure-kr", "entity": "South Korea Infrastructure","category": "infrastructure"},
    "DomainNova - Seed Domains (Singapore)":        {"ecosystem": "infrastructure-sg", "entity": "Singapore Infrastructure",  "category": "infrastructure"},
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

    entries: list[DomainMeta] = []
    # Track most recent section's overrides; updated implicitly as the
    # iterator yields entries from successive sections.
    last_section = UNSECTIONED
    overrides = SECTION_OVERRIDES.get(last_section, {})

    for section, domain in iter_source_entries(path):
        if section != last_section:
            last_section = section
            overrides = SECTION_OVERRIDES.get(section, {})
        if not DOMAIN_RE.match(domain):
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

    domains:   list[tuple[str, str]] = []
    invalid:   list[str]  = []
    unsectioned: list[str] = []
    counts:    Counter = Counter()

    for section, domain in iter_source_entries(path):
        domains.append((domain, section))
        counts[domain] += 1
        if not DOMAIN_RE.match(domain):
            invalid.append(domain)
        if section == UNSECTIONED:
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
    seed_entries_by_source = {
        source: parse_source(path, source)
        for source, path in SEED_FILES.items()
    }
    seed_entries = [e for entries in seed_entries_by_source.values() for e in entries]
    extended_entries = parse_source(EXTENDED_FILE, "extended")

    # ---- Validation ----
    validation_report = {
        source: validate(path)
        for source, path in SEED_FILES.items()
    }
    validation_report["extended"] = validate(EXTENDED_FILE)

    # Cross-source overlap
    seed_set     = {e.domain for e in seed_entries}
    extended_set = {e.domain for e in extended_entries}
    validation_report["cross_source_overlap"] = sorted(seed_set & extended_set)

    # Cross-seed overlap: regional seed files are forced buckets, so overlap
    # should be visible in metadata validation rather than silently hidden.
    seed_domains_by_source = {
        source: {e.domain for e in entries}
        for source, entries in seed_entries_by_source.items()
    }
    seed_overlap = {}
    sources = list(seed_domains_by_source)
    for i, left in enumerate(sources):
        for right in sources[i + 1:]:
            overlap = sorted(seed_domains_by_source[left] & seed_domains_by_source[right])
            if overlap:
                seed_overlap[f"{left} ∩ {right}"] = overlap
    validation_report["cross_seed_overlap"] = seed_overlap

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

    print(f"\n[+] Wrote {len(entries)} entries to data/")


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
