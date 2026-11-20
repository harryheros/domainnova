#!/usr/bin/env python3
"""
data_tag.py — give each published data build a fixed name.

After a build that changed the data has been pushed, the workflow runs
this script: it tags the pushed commit `data-YYYY-MM-DD` (UTC), so a
paper, an audit or another tool can cite one exact version of the lists:

    https://raw.githubusercontent.com/harryheros/domainnova/data-2026-11-23/dist/domains_cn.txt

A tag is never moved. A second build on the same day that changes the
data again is tagged `data-YYYY-MM-DD.2`, then `.3`, and so on. The tag is
annotated; its message records the published counts, the build time and
the code version, from data/stats.json.

    python sources/scripts/data_tag.py            # tag HEAD and push
    python sources/scripts/data_tag.py --dry-run  # print the tag only
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import constants  # noqa: E402

ROOT = HERE.parents[1]
STATS = ROOT / "data" / "stats.json"
REGIONS = ("cn", "hk", "mo", "tw", "jp", "kr", "sg")
PREFIX = "data-"
PUSH_ATTEMPTS = 3


def tag_name(day: str, existing: set[str]) -> str:
    """The first free name for `day` (YYYY-MM-DD): data-<day>, then .2, .3 …"""
    name = f"{PREFIX}{day}"
    n = 1
    while name in existing:
        n += 1
        name = f"{PREFIX}{day}.{n}"
    return name


def tag_message(name: str, stats: dict) -> str:
    buckets = stats.get("buckets", {})
    per_region = ", ".join(
        f"{r.upper()} {buckets[r]['included']:,}"
        for r in REGIONS
        if isinstance(buckets.get(r), dict) and "included" in buckets[r]
    )
    lines = [f"DomainNova {name}", ""]
    if "dist_domains" in stats:
        lines.append(f"Published: {stats['dist_domains']:,} domains ({per_region})")
    if stats.get("generated_at"):
        lines.append(f"Built: {stats['generated_at']}")
    lines.append(f"Code: v{constants.__version__}")
    return "\n".join(lines) + "\n"


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout


def remote_tags(remote: str, cwd: Path) -> set[str]:
    out = _git("ls-remote", "--tags", "--refs", remote, f"refs/tags/{PREFIX}*", cwd=cwd)
    return {line.split("refs/tags/", 1)[1] for line in out.splitlines() if "refs/tags/" in line}


def head_tag(cwd: Path) -> str | None:
    """A data tag already on HEAD (a rerun after a failed tag push)."""
    out = _git("tag", "--points-at", "HEAD", "--list", f"{PREFIX}*", cwd=cwd)
    tags = [t for t in out.split() if re.fullmatch(rf"{PREFIX}\d{{4}}-\d\d-\d\d(\.\d+)?", t)]
    return tags[0] if tags else None


def run(remote: str = "origin", cwd: Path = ROOT, day: str | None = None,
        dry_run: bool = False) -> str:
    day = day or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    stats = json.loads(STATS.read_text(encoding="utf-8")) if STATS.exists() else {}
    existing = remote_tags(remote, cwd)

    already = head_tag(cwd)
    if already and already in existing:
        print(f"[=] HEAD is already {already}")
        return already

    for _ in range(PUSH_ATTEMPTS):
        name = tag_name(day, existing)
        if dry_run:
            print(f"[dry-run] would tag HEAD {name}")
            print(tag_message(name, stats), end="")
            return name
        _git("tag", "-a", name, "-m", tag_message(name, stats), "HEAD", cwd=cwd)
        try:
            _git("push", remote, f"refs/tags/{name}", cwd=cwd)
        except subprocess.CalledProcessError as e:
            # Someone pushed that name meanwhile: take the next one.
            _git("tag", "-d", name, cwd=cwd)
            print(f"[!] push of {name} rejected: {e.stderr.strip()}")
            existing = remote_tags(remote, cwd) | {name}
            continue
        print(f"[+] tagged {name}")
        return name
    raise SystemExit(f"[x] could not push a data tag after {PUSH_ATTEMPTS} attempts")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--remote", default="origin")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    run(remote=args.remote, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
