"""
constants.py - shared settings of the DomainNova build pipeline.

Project version, region buckets, the IPNova data URLs and their sanity
thresholds, global CDN ASNs (provider detection) and TLD-to-region votes.
"""

# DomainNova project version (SemVer). Bump on every release.
# Single source of truth: README badge, workflow logs, any future
# release tag scripts must read from here rather than embedding a
# hard-coded literal.
__version__ = "3.9.2"


# Global CDN providers — domains behind these are CDN-masked;
# origin region cannot be determined from A records alone.
GLOBAL_CDN_ASNS: dict[int, str] = {
    13335: "Cloudflare",
    20940: "Akamai",
    54113: "Fastly",
    16509: "Amazon CloudFront",
    15169: "Google Cloud CDN",
    8075:  "Microsoft Azure CDN",
}

# ---------------------------------------------------------------------------
# Region buckets
# ---------------------------------------------------------------------------
# The set of recognized region buckets. A domain is assigned to exactly one
# of these (or to "" / unclassified).
REGION_BUCKETS: set[str] = {"CN", "HK", "MO", "TW", "JP", "KR", "SG"}

# IPNova multi-region CIDR data. Our own upstream, so the main branch is
# used without pinning.
IPNOVA_BASE: str = "https://raw.githubusercontent.com/harryheros/ipnova/main/output"

REGION_CIDR_URLS: dict[str, str] = {
    # plain/ variants have no comment header (the parser skips '#' lines anyway)
    "CN": f"{IPNOVA_BASE}/plain/CN.txt",
    "HK": f"{IPNOVA_BASE}/plain/HK.txt",
    "MO": f"{IPNOVA_BASE}/plain/MO.txt",
    "TW": f"{IPNOVA_BASE}/plain/TW.txt",
    "JP": f"{IPNOVA_BASE}/plain/JP.txt",
    "KR": f"{IPNOVA_BASE}/plain/KR.txt",
    "SG": f"{IPNOVA_BASE}/plain/SG.txt",
}

# Sanity-check threshold: ipnova region files with fewer than this many lines
# are treated as transport corruption (truncated 502, partial response, etc.)
# and the affected bucket is degraded to empty for the current build.
#
# Rationale: MO is naturally very small (tens of CIDRs), so a global threshold
# would falsely reject MO as corrupt. Per-bucket thresholds are sized to accept
# known-legitimate minima while still catching transport-level truncation
# (which typically produces zero or single-digit line counts from HTML error
# pages parsed as CIDR text).
IPNOVA_MIN_LINES: int = 10  # legacy global floor, retained as ultimate fallback

IPNOVA_MIN_LINES_PER_BUCKET: dict[str, int] = {
    "CN": 3000,
    "HK": 500,
    "TW": 100,
    "MO": 5,
    "JP": 2000,
    "KR": 800,
    "SG": 200,
}

# Map TLD suffix -> bucket. Used as +1 vote in decide_bucket().
TLD_TO_BUCKET: dict[str, str] = {
    ".cn": "CN",
    ".hk": "HK",
    ".mo": "MO",
    ".tw": "TW",
    ".jp": "JP",
    ".kr": "KR",
    ".sg": "SG",
}
