#!/usr/bin/env python3
"""
compare_resolvers.py - does our own resolver place domains where Google does?

Resolves every published domain twice, with the same China Telecom client
subnet: through our own resolver (a DNSNova server's ecs.client_path,
which asks each domain's own name servers) and through Google DoH. Each
answer is placed in a region the way the build does (60% of its addresses
in one region's IPNova ranges), and the two placements are compared.

The point: before the build stops using public resolvers, measure how
often the answers differ, and for which domains. A name server that only
honours client subnets from resolvers it knows (Google is one) shows up
here as a disagreement.

Usage (from the repository root):
    DOMAINNOVA_DOH_URL=https://dns.novaod.com/ecs-... \\
        python sources/scripts/compare_resolvers.py [--sample 500] [--workers 8]

Writes data/resolver_compare.json and prints a summary. Read-only: it
changes no source list and no published file.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import random
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402

from build_domains import (  # noqa: E402
    ECS_SUBNETS,
    REGION_ORDER,
    RegionLookup,
    _decode_dns_wire_answer,
    _encode_dns_wire_query,
    build_region_lookup,
    fetch_region_cidrs,
    ip_to_bucket,
)

GOOGLE = "https://dns.google/resolve"
SHARE = 0.6  # the build's rule: at least 60% of addresses in one region

Resolver = Callable[[str, str], Optional[List[str]]]  # (name, subnet) -> IPs, None on failure


def region_of(ips: List[str], lookup: RegionLookup) -> str:
    """The region holding at least 60% of ips, or "" (none, or no answer)."""
    if not ips:
        return ""
    counts = Counter(ip_to_bucket(ip, lookup) for ip in ips)
    for bucket in REGION_ORDER:
        if counts[bucket] / len(ips) >= SHARE:
            return bucket
    return ""


def subnet_for(domain: str) -> str:
    """The same client subnet for a domain every time, spread over the list."""
    return ECS_SUBNETS[sum(domain.encode()) % len(ECS_SUBNETS)]


def own_resolver(url: str, session: requests.Session) -> Resolver:
    def resolve(name: str, subnet: str) -> Optional[List[str]]:
        # asked twice when the first gives nothing, as the build does
        ips = once(name, subnet)
        return ips if ips else once(name, subnet)

    def once(name: str, subnet: str) -> Optional[List[str]]:
        try:
            r = session.post(url, data=_encode_dns_wire_query(name, ecs_subnet=subnet), timeout=15,
                             headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"})
        except requests.RequestException:
            return None
        if r.status_code != 200:
            return None
        return _decode_dns_wire_answer(r.content)
    return resolve


def google_resolver(session: requests.Session) -> Resolver:
    def resolve(name: str, subnet: str) -> Optional[List[str]]:
        try:
            r = session.get(GOOGLE, params={"name": name, "type": "A", "edns_client_subnet": subnet}, timeout=15,
                            headers={"Accept": "application/dns-json"})
            if r.status_code != 200:
                return None
            return sorted({a["data"] for a in r.json().get("Answer", []) if a.get("type") == 1})
        except (requests.RequestException, ValueError):
            return None
    return resolve


def resolve_like_build(resolve: Resolver, domain: str, subnet: str) -> Tuple[Optional[List[str]], str]:
    """The bare name, then www.<name> when it has no address (as the build does)."""
    ips = resolve(domain, subnet)
    if ips:
        return ips, domain
    if ips is not None and not domain.startswith("www."):
        www = resolve("www." + domain, subnet)
        if www:
            return www, "www." + domain
        if www is None:
            return None, ""
    return ips, domain


def compare_one(domain: str, listed: str, own: Resolver, google: Resolver, lookup: RegionLookup) -> dict:
    subnet = subnet_for(domain)
    own_ips, own_name = resolve_like_build(own, domain, subnet)
    g_ips, g_name = resolve_like_build(google, domain, subnet)
    own_region, g_region = region_of(own_ips or [], lookup), region_of(g_ips or [], lookup)
    if own_ips is None:
        outcome = "own_failed"
    elif g_ips is None:
        outcome = "google_failed"
    elif own_region == g_region:
        outcome = "agree"
    elif not own_ips:
        outcome = "own_no_answer"
    else:
        outcome = "differ"
    return {"domain": domain, "listed": listed, "subnet": subnet, "outcome": outcome,
            "own": {"name": own_name, "ips": own_ips or [], "region": own_region},
            "google": {"name": g_name, "ips": g_ips or [], "region": g_region}}


def load_published(repo_root: Path) -> List[Tuple[str, str]]:
    out = []
    for bucket in REGION_ORDER:
        f = repo_root / "dist" / f"domains_{bucket.lower()}.txt"
        if not f.exists():
            continue
        for line in f.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                out.append((line, bucket))
    return out


def summarise(results: List[dict]) -> dict:
    outcomes = Counter(r["outcome"] for r in results)
    compared = outcomes["agree"] + outcomes["differ"] + outcomes["own_no_answer"]
    by_region: Dict[str, Counter] = {}
    for r in results:
        by_region.setdefault(r["listed"], Counter())[r["outcome"]] += 1
    return {
        "domains": len(results),
        "outcomes": dict(outcomes),
        # of the domains both resolvers could be asked about, how many land in the same region
        "agreement": round(outcomes["agree"] / compared, 4) if compared else None,
        "by_listed_region": {k: dict(v) for k, v in sorted(by_region.items())},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--own", default=os.environ.get("DOMAINNOVA_DOH_URL", ""), help="our resolver's DoH URL (default: $DOMAINNOVA_DOH_URL)")
    ap.add_argument("--sample", type=int, default=0, help="compare this many random domains (default: all)")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--out", default="data/resolver_compare.json")
    args = ap.parse_args()
    if not args.own:
        print("Set DOMAINNOVA_DOH_URL or pass --own: the ecs.client_path URL of our DNSNova server.", file=sys.stderr)
        return 2
    repo_root = Path(__file__).resolve().parents[2]
    session = requests.Session()
    session.headers["User-Agent"] = "domainnova-compare/1 (+https://github.com/harryheros/domainnova)"
    lookup = build_region_lookup(fetch_region_cidrs(session))
    domains = load_published(repo_root)
    if args.sample and args.sample < len(domains):
        domains = random.sample(domains, args.sample)
    own, google = own_resolver(args.own, session), google_resolver(session)
    start = time.time()
    results: List[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for r in pool.map(lambda d: compare_one(d[0], d[1], own, google, lookup), domains):
            results.append(r)
    summary = summarise(results)
    summary["seconds"] = round(time.time() - start, 1)
    summary["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    report = {"summary": summary, "not_agreeing": [r for r in results if r["outcome"] != "agree"]}
    out = repo_root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"Details of every domain that does not agree: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
