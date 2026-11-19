#!/usr/bin/env python3
"""
clean_agent_domains.py - apply the v3.8 nomination rules to existing data.

The discovery agents now refuse junk, reduce names to their registrable
domain and skip shared-hosting IPs (see _quality.py and the agents). This
script applies the same rules to what they nominated before, in
extended.txt and discovery.txt. Domains curated by hand (origin "manual" in
provenance.csv, or no provenance row) are never touched.

For each agent-nominated domain, in file order:
  1. junk (_quality.junk_reason)                         -> removed
  2. nominated by IP-neighbor from a shared-hosting IP    -> removed
     (an IP that nominated SHARED_HOST_MIN or more distinct registrable
     domains, counting provenance.csv and discovery.txt together)
  3. a subdomain whose registrable name (or a parent) is
     already listed                                       -> removed
  4. any other subdomain                                  -> replaced by its
     registrable name, which keeps the nomination

Every removal and replacement is appended to sources/manual/removed.csv
(domain, origin, origin_detail, reason, removed), so the dataset's history
stays auditable. provenance.csv follows extended.txt. Running it again
changes nothing.

Usage:
    python sources/scripts/clean_agent_domains.py [--dry-run]
"""
from __future__ import annotations

import argparse
import csv
import datetime as _dt
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _provenance as prov  # noqa: E402
from _quality import junk_reason, registrable  # noqa: E402

SHARED_HOST_MIN = 20  # same threshold as agent_ip_neighbor.SHARED_HOST_MIN
REMOVED_FIELDS = ["domain", "origin", "origin_detail", "reason", "removed"]
SECTION_PREFIXES = ("# ---", "# =====")


def _domains(path: Path) -> List[str]:
    if not path.exists():
        return []
    return [l.strip().lower() for l in path.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.strip().startswith("#")]


def _covering(domain: str, known: Set[str]) -> Optional[str]:
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        cand = ".".join(labels[i:])
        if cand in known:
            return cand
    return None


def _shared_ips(origins: Dict[str, Tuple[str, str, str]]) -> Set[str]:
    regs: Dict[str, Set[str]] = defaultdict(set)
    for d, (origin, detail, _) in origins.items():
        if origin == "ip-neighbor":
            regs[detail].add(registrable(d) or d)
    return {ip for ip, s in regs.items() if len(s) >= SHARED_HOST_MIN}


def _rewrite(path: Path, replace: Dict[str, Optional[str]]) -> None:
    """Rewrite a domain file: replace[d] is the new name, or None to drop.
    Section headers left with no domains are dropped too."""
    out: List[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip().lower()
        if s and not s.startswith("#") and s in replace:
            if replace[s] is None:
                continue
            line = replace[s]
        out.append(line)
    tidy: List[str] = []
    for i, line in enumerate(out):
        if line.startswith(SECTION_PREFIXES):
            nxt = next((l for l in out[i + 1:] if l.strip()), "")
            if not nxt or nxt.startswith(SECTION_PREFIXES):
                continue
        tidy.append(line)
    while len(tidy) > 1 and not tidy[-1].strip():
        tidy.pop()
    text = "\n".join(tidy) + "\n"
    while "\n\n\n" in text:
        text = text.replace("\n\n\n", "\n\n")
    path.write_text(text, encoding="utf-8")


def _decide(domains: List[str], origins, shared: Set[str], known: Set[str]):
    """-> (replace map, removal log rows without date). Updates `known`."""
    replace: Dict[str, Optional[str]] = {}
    log: List[List[str]] = []
    # Registrable names first, so a subdomain met before its own registrable
    # name is found covered rather than listed twice.
    for d in sorted(domains, key=lambda x: (registrable(x) or x) != x):
        origin, detail, _ = origins.get(d, ("manual", "", ""))
        if origin == "manual":
            continue
        reason = junk_reason(d)
        if not reason and origin == "ip-neighbor" and detail in shared:
            reason = "shared-host"
        reg = registrable(d) or d
        if not reason and reg != d:
            cover = _covering(reg, known)
            reason = f"covered-by:{cover}" if cover else None
            if not cover:
                replace[d] = reg
                known.add(reg)
                log.append([d, origin, detail, f"reduced-to:{reg}"])
                continue
        if not reason and d in known:
            reason = f"covered-by:{d}"  # listed twice
        if reason:
            replace[d] = None
            log.append([d, origin, detail, reason])
        else:
            known.add(d)
    return replace, log


def clean(repo_root: Path, today: Optional[str] = None, dry_run: bool = False) -> dict:
    today = today or _dt.date.today().isoformat()
    manual = repo_root / "sources" / "manual"
    ext_path, disc_path = manual / "extended.txt", manual / "discovery.txt"

    reg_rows = prov.load(repo_root)
    disc_origins = prov.discovery_sections(disc_path) if disc_path.exists() else {}
    shared = _shared_ips({**disc_origins, **reg_rows})

    ext = _domains(ext_path)
    known: Set[str] = set()
    for seed in sorted(manual.glob("seed_*.txt")):
        known.update(_domains(seed))
    known.update(d for d in ext if reg_rows.get(d, ("manual",))[0] == "manual")

    ext_replace, ext_log = _decide(ext, reg_rows, shared, known)
    disc = _domains(disc_path)
    disc_replace, disc_log = _decide(disc, disc_origins, shared, known)

    log = ext_log + disc_log
    summary = {
        "removed": sum(1 for r in log if not r[3].startswith("reduced-to:")),
        "reduced": sum(1 for r in log if r[3].startswith("reduced-to:")),
    }
    counts: Dict[str, int] = defaultdict(int)
    for r in log:
        counts[r[3].split(":")[0]] += 1
    summary["by_reason"] = dict(sorted(counts.items()))
    if dry_run or not log:
        return summary

    if ext_replace:
        _rewrite(ext_path, ext_replace)
    if disc_replace:
        _rewrite(disc_path, disc_replace)

    # provenance.csv follows extended.txt; a reduced name keeps the
    # nomination of the first subdomain it replaced.
    new_rows: Dict[str, Tuple[str, str, str]] = {
        d: row for d, row in reg_rows.items() if d not in ext_replace}
    for d, new in ext_replace.items():
        if new and new not in new_rows and d in reg_rows:
            new_rows[new] = reg_rows[d]
    with prov.path(repo_root).open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(prov.FIELDS)
        for d in sorted(new_rows):
            w.writerow([d, *new_rows[d]])

    removed_path = manual / "removed.csv"
    fresh = not removed_path.exists()
    with removed_path.open("a", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        if fresh:
            w.writerow(REMOVED_FIELDS)
        for row in log:
            w.writerow([*row, today])
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dry-run", action="store_true", help="report only, change nothing")
    args = ap.parse_args()
    summary = clean(Path(__file__).resolve().parents[2], dry_run=args.dry_run)
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
