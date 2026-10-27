"""
_common.py — shared helpers for DomainNova discovery agents.

Both agents (agent_ct_logs, agent_ip_neighbor)
historically maintained their own copies of:
  - DOMAIN_RE              (re-exported from sources/scripts/_source_parser)
  - EXCLUDE_DOMAINS
  - make_session()
  - load_existing()
  - discovery_count()
  - append_to_discovery()

Keeping these aligned across three files relied on manual discipline.
This module is the single source of truth; each agent imports from here.

Note on DOMAIN_RE: the actual definition lives one layer down in
sources/scripts/_source_parser.py so the script layer (build_metadata,
validate_manual_sources) and the discovery agent layer share *literally*
the same regex object — there is no second copy to keep in sync.

Pure helpers (no module-load network I/O) so importing this is cheap.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Iterable, List, Set

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Single source of truth for DOMAIN_RE lives in sources/scripts/_source_parser.py
# (the lowest-level module that needs it; pure-stdlib so importing it from here
# is cheap). The discovery agent layer re-exports it under the same name so
# callers don't have to know about the directory split. Two-copy parity used
# to be guarded by a test; now there is genuinely one copy.
_SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
from _source_parser import DOMAIN_RE  # noqa: E402  (re-exported)


USER_AGENT = "DomainNova/DiscoveryAgent (+https://github.com/harryheros/domainnova)"

# Capacity of discovery.txt. Must match DISCOVERY_MAX in
# sources/scripts/build_domains.py (guarded by a unit test).
# v3.6: 2000 -> 5000 (every discovery domain is now checked on every build).
DISCOVERY_MAX = 5000


# Domains intentionally never added to discovery.txt:
# - globally dominant non-CN services that appear in many enumeration sources
# - CDN root domains that don't represent a single origin region
EXCLUDE_DOMAINS = frozenset({
    "google.com", "youtube.com", "facebook.com", "twitter.com",
    "instagram.com", "whatsapp.com", "telegram.org",
    "bing.com", "microsoft.com", "apple.com", "icloud.com",
    "amazonaws.com", "cloudflare.com", "fastly.com",
    "akamai.com", "akamaiedge.net", "edgekey.net",
})


def make_session(
    *,
    backoff_factor: float = 1.0,
    total_retries: int = 3,
    user_agent: str = USER_AGENT,
) -> requests.Session:
    """Build a `requests.Session` with the agents' standard retry policy
    and User-Agent. `backoff_factor` is the only knob individual agents
    have historically tuned (ct_logs wanted 2.0, others 1.0)."""
    retry = Retry(
        total=total_retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": user_agent})
    return session


_DISCOVERY_RELATIVE = (
    "sources/manual/extended.txt",
    "sources/manual/discovery.txt",
)


def load_existing(repo_root: Path) -> Set[str]:
    """Return the union of all known domains across every seed file,
    extended and discovery. Used by every agent to dedupe candidates."""
    known: Set[str] = set()
    manual = repo_root / "sources" / "manual"
    paths = sorted(manual.glob("seed_*.txt")) + [repo_root / rel for rel in _DISCOVERY_RELATIVE]
    for path in paths:
        if not path.exists():
            continue
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip().lower()
            if line and not line.startswith("#"):
                known.add(line.rstrip("."))
    return known


def is_covered(domain: str, known: Set[str]) -> bool:
    """True if `domain` or one of its parent domains is already known.

    Rule sets match by domain suffix, so `news.example.cn` adds nothing
    when `example.cn` is already listed. v3.5 compared exact names only,
    and about a third of discovery.txt was subdomains of known domains.
    """
    labels = domain.split(".")
    return any(".".join(labels[i:]) in known for i in range(len(labels) - 1))


def filter_candidates(candidates: Iterable[str], known: Set[str]) -> List[str]:
    """Normalise and filter agent results before they enter discovery.txt.

    - lower-case, trailing dot removed, a leading "www." removed (the bare
      domain covers it; build_domains falls back to www.<domain> when the
      bare name has no address record)
    - must look like a domain, not excluded, not already covered by a known
      domain or one of its parents; duplicates removed, order kept
    """
    out: List[str] = []
    seen: Set[str] = set()
    for raw in candidates:
        d = str(raw).strip().lower().rstrip(".")
        if d.startswith("www."):
            d = d[4:]
        if not d or "." not in d or d in seen:
            continue
        if d in EXCLUDE_DOMAINS or not DOMAIN_RE.match(d):
            continue
        if is_covered(d, known):
            continue
        seen.add(d)
        out.append(d)
    return out


def discovery_count(repo_root: Path) -> int:
    """Count current non-comment, non-blank lines in discovery.txt."""
    path = repo_root / "sources" / "manual" / "discovery.txt"
    if not path.exists():
        return 0
    return sum(
        1 for l in path.read_text(encoding="utf-8").splitlines()
        if l.strip() and not l.strip().startswith("#")
    )


def append_to_discovery(
    repo_root: Path,
    domains: Iterable[str],
    source_tag: str,
) -> int:
    """Append new domains to discovery.txt with a dated section header.
    Returns the number of domains written. Creates the file if missing."""
    path = repo_root / "sources" / "manual" / "discovery.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("# DomainNova - Discovery Layer\n", encoding="utf-8")
    domain_list: List[str] = list(domains)
    with path.open("a", encoding="utf-8") as f:
        f.write(f"\n# --- {source_tag} {time.strftime('%Y-%m-%d')} ---\n")
        for d in domain_list:
            f.write(d + "\n")
    return len(domain_list)
