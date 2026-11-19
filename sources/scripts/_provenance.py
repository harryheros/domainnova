"""
_provenance.py - where each domain in DomainNova came from.

A domain enters the dataset in one of three ways:
  - manual curation: the seed_*.txt files (origin "manual");
  - nomination by a discovery agent into discovery.txt, under a dated
    header such as "# --- ct-logs:%.cn 2026-10-26 ---", then promotion to
    extended.txt after passing the regional check on consecutive builds;
  - added to extended.txt by hand (origin "manual"); for domains added
    before v3.8.0 the origin was rebuilt from git by backfill_provenance.py.

The first nomination of every extended.txt domain is kept in
sources/manual/provenance.csv (domain, origin, origin_detail, nominated).
Whatever nominated a domain, it is published only on the strength of the
build's own DNS and IP checks; the origin says how it was found, not why
it is listed.
"""
from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Dict, Iterable, Tuple

FIELDS = ["domain", "origin", "origin_detail", "nominated"]

# "# --- <tag> <YYYY-MM-DD> ---", written by discovery_agents/_common.py
HEADER_RE = re.compile(r"^#\s*---\s*(\S+)\s+(\d{4}-\d{2}-\d{2})\s*---\s*$")

# Discovery tags of agents that no longer exist, by what they read.
_UPSTREAM_TAGS = {
    "felixonmars-accelerated": ("dnsmasq-china-list", "accelerated-domains"),
}

Origin = Tuple[str, str, str]  # (origin, origin_detail, nominated date)


def path(repo_root: Path) -> Path:
    return repo_root / "sources" / "manual" / "provenance.csv"


def parse_tag(tag: str) -> Tuple[str, str]:
    """'ct-logs:%.cn' -> ('ct-logs', '%.cn'); historical upstream tags by list name."""
    kind, _, detail = tag.partition(":")
    if kind == "upstream":
        return _UPSTREAM_TAGS.get(detail, ("upstream-list", detail))
    return kind, detail


def discovery_sections(discovery_path: Path) -> Dict[str, Origin]:
    """Map every domain in discovery.txt to the header it is listed under."""
    out: Dict[str, Origin] = {}
    if not discovery_path.exists():
        return out
    current: Origin = ("unknown", "", "")
    for line in discovery_path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s:
            continue
        m = HEADER_RE.match(s)
        if m:
            current = (*parse_tag(m.group(1)), m.group(2))
            continue
        if s.startswith("#"):
            continue
        out.setdefault(s.lower().rstrip("."), current)
    return out


def load(repo_root: Path) -> Dict[str, Origin]:
    p = path(repo_root)
    if not p.exists():
        return {}
    with p.open(encoding="utf-8", newline="") as f:
        return {
            r["domain"]: (r.get("origin", "") or "unknown", r.get("origin_detail", "") or "", r.get("nominated", "") or "")
            for r in csv.DictReader(f)
            if r.get("domain")
        }


def record(repo_root: Path, entries: Iterable[Tuple[str, str, str, str]]) -> int:
    """Add (domain, origin, origin_detail, nominated) rows. The first nomination
    of a domain is kept; later ones are ignored. Returns the number added."""
    rows = load(repo_root)
    added = 0
    for domain, origin, detail, nominated in entries:
        if domain not in rows:
            rows[domain] = (origin, detail, nominated)
            added += 1
    if not added and path(repo_root).exists():
        return 0
    p = path(repo_root)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(FIELDS)
        for domain in sorted(rows):
            w.writerow([domain, *rows[domain]])
    return added
