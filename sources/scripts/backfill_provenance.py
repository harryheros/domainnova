#!/usr/bin/env python3
"""
backfill_provenance.py - rebuild the origin of extended.txt domains from git history.

Promotions record their origin in sources/manual/provenance.csv since v3.8.0.
For domains promoted before that, this script reads every past version of
discovery.txt (each batch is listed under a header naming the agent that
nominated it) and of extended.txt, and records for every current extended.txt
domain:

  - the header it was first listed under in discovery.txt, if any;
  - otherwise "manual": extended.txt is otherwise edited only by hand
    (the first version of the file was curated by hand, and later hand
    additions came in with manual syncs), with the date it first appeared.

Needs the full history (not a shallow clone). Existing rows are kept.

    python sources/scripts/backfill_provenance.py [--repo .] [--dry-run]
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _provenance  # noqa: E402

DISCOVERY = "sources/manual/discovery.txt"
EXTENDED = "sources/manual/extended.txt"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout


def _domains(text: str) -> list[str]:
    return [s.strip().lower().rstrip(".") for s in text.splitlines() if s.strip() and not s.strip().startswith("#")]


def _versions(repo: Path, rel: str) -> list[tuple[str, str]]:
    """(commit, date) of every commit touching rel, oldest first."""
    out = _git(repo, "log", "--reverse", "--format=%H %cs", "--", rel)
    return [tuple(line.split()) for line in out.splitlines() if line.strip()]  # type: ignore[misc]


def reconstruct(repo: Path) -> dict[str, tuple[str, str, str]]:
    """Origin of every domain currently in extended.txt."""
    nominated: dict[str, tuple[str, str, str]] = {}
    tmp = repo / ".git" / "backfill-discovery.txt"
    for commit, _ in _versions(repo, DISCOVERY):
        tmp.write_text(_git(repo, "show", f"{commit}:{DISCOVERY}"), encoding="utf-8")
        for domain, origin in _provenance.discovery_sections(tmp).items():
            nominated.setdefault(domain, origin)
    tmp.unlink(missing_ok=True)

    first_seen: dict[str, str] = {}
    initial: set[str] = set()
    for i, (commit, date) in enumerate(_versions(repo, EXTENDED)):
        listed = _domains(_git(repo, "show", f"{commit}:{EXTENDED}"))
        if i == 0:
            initial = set(listed)
            initial_date = date
        for d in listed:
            first_seen.setdefault(d, date)

    out: dict[str, tuple[str, str, str]] = {}
    for d in _domains((repo / EXTENDED).read_text(encoding="utf-8")):
        if d in initial:
            out[d] = ("manual", "first extended.txt, curated by hand", initial_date)
        elif d in nominated:
            out[d] = nominated[d]
        else:
            out[d] = ("manual", "added by hand", first_seen.get(d, ""))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    ap.add_argument("--dry-run", action="store_true", help="print the counts only")
    args = ap.parse_args(argv)

    if _git(args.repo, "rev-parse", "--is-shallow-repository").strip() == "true":
        print("needs the full history: git fetch --unshallow", file=sys.stderr)
        return 1
    origins = reconstruct(args.repo)
    for origin, n in Counter(o for o, _, _ in origins.values()).most_common():
        print(f"{n:6}  {origin}")
    print(f"{len(origins):6}  extended.txt domains")
    if not args.dry_run:
        added = _provenance.record(args.repo, [(d, *o) for d, o in sorted(origins.items())])
        print(f"{added} rows added to {_provenance.path(args.repo).relative_to(args.repo)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
