#!/usr/bin/env python3
"""
agent_link_crawl.py - find new domains in the links of known sites' home pages.

Each run reads the home pages of a rotating slice of the domains already in
the dataset (seed files and extended.txt), collects every host they link to
or load resources from, reduces each to its registrable domain, and adds the
new ones to discovery.txt under a header naming the page they were found on:

    # --- link-crawl:<site> <date> ---

Candidates go through the same weekly DNS and IP checks as every other
discovery domain; being linked from a site in the region says nothing by
itself. Regional ccTLDs are queued first.

Etiquette:
  - robots.txt is honoured for "/" (no robots.txt, or an unreadable one,
    means allowed, as usual)
  - one request per site per run (plus robots.txt), at most 1 MB read,
    a few sites at a time, the agents' User-Agent with a contact URL

Usage:
    python sources/discovery_agents/agent_link_crawl.py
"""
from __future__ import annotations

import concurrent.futures
import datetime as _dt
import ipaddress
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional
from urllib import robotparser

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (  # noqa: E402
    DISCOVERY_MAX,
    USER_AGENT,
    append_to_discovery,
    discovery_count,
    filter_candidates,
    load_existing,
    make_session,
)

PAGES_PER_RUN = 300        # home pages read per run
MAX_NEW_PER_RUN = 500      # new discovery domains per run
MAX_PAGE_BYTES = 1_000_000
WORKERS = 8
TIMEOUT = (5, 10)          # connect, read (seconds)

REGIONAL_TLDS = ("cn", "hk", "mo", "tw", "jp", "kr", "sg")

# Second-level labels under which names are registered (public suffixes),
# for the region's ccTLDs. Elsewhere the registrable domain is the last two
# labels, which is right for the generic TLDs these pages mostly link to.
_SECOND_LEVEL = {
    "cn": {"ac", "com", "edu", "gov", "mil", "net", "org",
           "ah", "bj", "cq", "fj", "gd", "gs", "gz", "gx", "ha", "hb", "he", "hi", "hk", "hl",
           "hn", "jl", "js", "jx", "ln", "mo", "nm", "nx", "qh", "sc", "sd", "sh", "sn", "sx",
           "tj", "tw", "xj", "xz", "yn", "zj"},
    "hk": {"com", "edu", "gov", "idv", "net", "org"},
    "mo": {"com", "edu", "gov", "net", "org"},
    "tw": {"club", "com", "ebiz", "edu", "game", "gov", "idv", "mil", "net", "org"},
    "jp": {"ac", "ad", "co", "ed", "go", "gr", "lg", "ne", "or"},
    "kr": {"ac", "co", "es", "go", "hs", "kg", "mil", "ms", "ne", "or", "pe", "re", "sc"},
    "sg": {"com", "edu", "gov", "net", "org", "per"},
    "uk": {"ac", "co", "gov", "ltd", "me", "net", "org", "plc"},
    "au": {"com", "edu", "gov", "net", "org"},
}

_LINK_RE = re.compile(r"""(?:href|src)\s*=\s*["']?(?:https?:)?//([^/"'\s?#>]+)""", re.IGNORECASE)


def registrable(host: str) -> Optional[str]:
    """news.sina.com.cn -> sina.com.cn; None for a bare suffix or no dot."""
    labels = host.strip().lower().rstrip(".").split(".")
    if len(labels) < 2 or not all(labels):
        return None
    if labels[-2] in _SECOND_LEVEL.get(labels[-1], ()):
        return ".".join(labels[-3:]) if len(labels) >= 3 else None
    return ".".join(labels[-2:])


def hosts_in(html: str) -> List[str]:
    """Hosts of absolute and scheme-relative links and resources, in order."""
    out = []
    for raw in _LINK_RE.findall(html):
        host = raw.split("@")[-1].split(":")[0].strip().lower().rstrip(".")
        if not host or "." not in host:
            continue
        try:
            ipaddress.ip_address(host)
            continue  # an IP address, not a name
        except ValueError:
            pass
        out.append(host)
    return out


def pick_pages(domains: List[str], n: int, week: int) -> List[str]:
    """The week's slice of the sorted domain list; consecutive weeks continue
    where the last stopped, so every site is read in turn."""
    if not domains:
        return []
    ordered = sorted(domains)
    start = (week * n) % len(ordered)
    return [ordered[(start + i) % len(ordered)] for i in range(min(n, len(ordered)))]


def prioritise(domains: Iterable[str]) -> List[str]:
    """Regional ccTLDs first (stable within each group)."""
    domains = list(domains)
    return [d for d in domains if d.rsplit(".", 1)[-1] in REGIONAL_TLDS] + \
           [d for d in domains if d.rsplit(".", 1)[-1] not in REGIONAL_TLDS]


def _allowed(session, site: str) -> bool:
    """robots.txt over https, or over http when https does not answer."""
    for scheme in ("https", "http"):
        try:
            r = session.get(f"{scheme}://{site}/robots.txt", timeout=TIMEOUT, allow_redirects=True)
        except Exception:
            continue
        if r.status_code != 200:
            return True
        rp = robotparser.RobotFileParser()
        rp.parse(r.text.splitlines())
        return rp.can_fetch(USER_AGENT, f"{scheme}://{site}/")
    return True


def _read(session, url: str) -> Optional[str]:
    try:
        r = session.get(url, timeout=TIMEOUT, stream=True, allow_redirects=True)
    except Exception:
        return None
    try:
        if r.status_code != 200 or "html" not in r.headers.get("Content-Type", ""):
            return None
        data = b""
        for chunk in r.iter_content(65536):
            data += chunk
            if len(data) >= MAX_PAGE_BYTES:
                break
        return data.decode(r.encoding or "utf-8", errors="replace")
    finally:
        r.close()


def crawl_site(session, site: str) -> List[str]:
    """Hosts linked from one site's home page ([] if disallowed or unreachable)."""
    if not _allowed(session, site):
        return []
    html = _read(session, f"https://{site}/") or _read(session, f"http://{site}/")
    return hosts_in(html) if html else []


def run(repo_root: Path, pages: int = PAGES_PER_RUN, max_new: int = MAX_NEW_PER_RUN,
        week: Optional[int] = None) -> int:
    budget = min(max_new, max(0, DISCOVERY_MAX - discovery_count(repo_root)))
    if budget == 0:
        print("[!] discovery.txt at capacity. Skipping.")
        return 0
    manual = repo_root / "sources" / "manual"
    sources = []
    for path in sorted(manual.glob("seed_*.txt")) + [manual / "extended.txt"]:
        if path.exists():
            sources += [l.strip().lower() for l in path.read_text(encoding="utf-8").splitlines()
                        if l.strip() and not l.strip().startswith("#")]
    if week is None:
        week = _dt.date.today().isocalendar()[1]
    sites = pick_pages(sorted(set(sources)), pages, week)
    print(f"[+] Reading {len(sites)} home pages (budget {budget} new domains)")

    session = make_session(total_retries=1)
    found: Dict[str, List[str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for site, hosts in zip(sites, pool.map(lambda s: crawl_site(session, s), sites), strict=True):
            found[site] = hosts

    known = load_existing(repo_root)
    referrer: Dict[str, str] = {}
    for site in sites:  # first site that links to a domain is its referrer
        for host in found.get(site, []):
            d = registrable(host)
            if d and d not in referrer and d != registrable(site):
                referrer[d] = site
    chosen = prioritise(filter_candidates(referrer, known))[:budget]

    by_site: Dict[str, List[str]] = {}
    for d in chosen:
        by_site.setdefault(referrer[d], []).append(d)
    added = 0
    for site in sites:
        if by_site.get(site):
            added += append_to_discovery(repo_root, by_site[site], f"link-crawl:{site}")
    print(f"[+] {sum(1 for s in sites if found.get(s))} pages read, {added} new domains added")
    return added


if __name__ == "__main__":
    run(Path(__file__).resolve().parents[2])
