#!/usr/bin/env python3
"""
expand_domains.py – Shared-IP candidate expansion.

Resolves all seed domains, groups them by resolved IP, and emits
domains that share an IP with at least one other seed domain.
These are *candidates* for manual review – not automatic additions.

FIXES (v2):
  - Replaced bare `except:` with explicit `except (socket.gaierror, OSError)`
    so KeyboardInterrupt and other system signals are not swallowed.
  - Added IPv6 resolution (AF_INET6) alongside IPv4.
  - Prints a summary at the end.
"""
from __future__ import annotations

import socket
from collections import defaultdict
from pathlib import Path

SEED_PATH = Path("sources/manual/seed_cn.txt")
OUT_PATH  = Path("sources/generated/expanded_candidates.txt")


def load_domains(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def resolve(domain: str) -> list[str]:
    ips: set[str] = set()
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            for info in socket.getaddrinfo(domain, None, family):
                ips.add(info[4][0])
        except (socket.gaierror, OSError):
            pass
    return sorted(ips)


def main() -> None:
    seeds = load_domains(SEED_PATH)
    print(f"[+] resolving {len(seeds)} domains…")

    ip_to_domains: defaultdict[str, set[str]] = defaultdict(set)
    for d in seeds:
        for ip in resolve(d):
            ip_to_domains[ip].add(d)

    candidates = {d for ds in ip_to_domains.values() if len(ds) >= 2 for d in ds}

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text("\n".join(sorted(candidates)) + "\n", encoding="utf-8")

    print(f"[+] {len(candidates)} candidate domains written to {OUT_PATH}")
    print(f"[+] {len(ip_to_domains)} unique IPs seen across all seeds")


if __name__ == "__main__":
    main()
