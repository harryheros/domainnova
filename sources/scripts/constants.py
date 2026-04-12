"""
constants.py - Mainland China Digital Asset Intelligence Database

Categorizes ASNs and infrastructure for the DomainNova build pipeline.

FIXES (v2):
- Removed duplicate ASN keys in CN_BACKBONE ("24400" was both China Mobile
  and CSTNET; Python silently kept only the last entry).
- Removed duplicate ASN key in CN_CLOUD_ASNS ("45090" was both Alibaba and
  Tencent; correct owner is Alibaba).
- Added missing Tencent Cloud ASN (132203).
- Expanded NON_MAINLAND_REGIONS to cover more common non-CN country codes
  that appear in ip-api responses for HK/TW/overseas CDN pops.
"""

# ---------------------------------------------------------------------------
# Tier 1 – State-Owned Backbone
# ---------------------------------------------------------------------------
CN_BACKBONE: dict[str, dict] = {
    # China Telecom
    "4134":  {"isp": "China Telecom", "name": "CHINANET-BACKBONE",      "level": "Core"},
    "4809":  {"isp": "China Telecom", "name": "CN2-GIA",                "level": "Premium"},
    "23724": {"isp": "China Telecom", "name": "CHINANET-IDC",           "level": "Core"},
    "58563": {"isp": "China Telecom", "name": "CHINANET-HB",            "level": "Core"},
    "24139": {"isp": "China Telecom", "name": "CHINANET-FJ",            "level": "Core"},
    "4812":  {"isp": "China Telecom", "name": "CHINANET-SH",            "level": "Core"},
    "4816":  {"isp": "China Telecom", "name": "CHINANET-GD",            "level": "Core"},

    # China Unicom
    "4837":  {"isp": "China Unicom",  "name": "CHINA-UNICOM-BACKBONE",  "level": "Core"},
    "9929":  {"isp": "China Unicom",  "name": "CU-VIP",                 "level": "Premium"},
    "4808":  {"isp": "China Unicom",  "name": "CU-BEIJING",             "level": "Core"},
    "17621": {"isp": "China Unicom",  "name": "CU-SHANGHAI",            "level": "Core"},
    "9800":  {"isp": "China Unicom",  "name": "CU-GUANGDONG",           "level": "Core"},

    # China Mobile
    "9808":  {"isp": "China Mobile",  "name": "CMNET-BACKBONE",         "level": "Core"},
    "56048": {"isp": "China Mobile",  "name": "CMNET-IDC",              "level": "Core"},
    "24400": {"isp": "China Mobile",  "name": "CMNET-GUANGDONG",        "level": "Core"},
    # NOTE: ASN 58453 is CMNET-HK (Hong Kong PoP); excluded – HK is in NON_MAINLAND_REGIONS.

    # Education & Research
    "4538":  {"isp": "CERNET",        "name": "China Education Network","level": "Academic"},
    "7497":  {"isp": "CSTNET",        "name": "China Science Network",  "level": "Research"},

    # Sina
    "37936": {"isp": "Sina",          "name": "SINA-CN",                "level": "Core"},
}

# ---------------------------------------------------------------------------
# Tier 2 – Major Cloud Providers
# ---------------------------------------------------------------------------
CN_CLOUD_ASNS: dict[str, str] = {
    # Alibaba Cloud
    "45090":  "Alibaba_Cloud_CN",   # correct owner; was incorrectly duplicated for Tencent
    "37963":  "Alibaba_Cloud_CN",

    # Tencent Cloud
    "132203": "Tencent_Cloud_CN",   # primary Tencent Cloud mainland ASN
    "132132": "Tencent_Cloud_CN",

    # Huawei Cloud
    "55990":  "Huawei_Cloud_CN",

    # Baidu Cloud
    "38365":  "Baidu_Cloud_CN",

    # JD Cloud
    "131486": "JD_Cloud_CN",
    "58807":  "JD_Cloud_CN",

    # Other CN Clouds
    "136188": "Kingsoft_Cloud_CN",
    "135371": "UCloud_CN",
    "23724":  "ChinaTelecom_Cloud_CN",
}

# ---------------------------------------------------------------------------
# Tier 3 – Infrastructure Function Tags (keyword-based, used by 2_dns_check.py)
# ---------------------------------------------------------------------------
INFRA_KEYWORDS: dict[str, list[str]] = {
    "CDN": ["wangsu", "chinacache", "baishan", "qiniu", "upyun", "fastweb"],
    "GOV": ["government", "gov", "agency", "ministry", "state"],
    "FIN": ["bank", "icbc", "ccb", "abc", "unionpay", "insurance"],
}

# ---------------------------------------------------------------------------
# Geo-Fencing: Negative Signals (for the CN bucket only)
#
# Country codes that should NOT be counted as mainland CN even if ASN is CN.
# As of P1 (multi-region), HK/MO/TW are REMOVED from this list — they are no
# longer "negative" signals globally; they are positive signals for their own
# buckets and only negative for the CN bucket. The CN scoring path treats this
# whole list as "definitely-not-CN" countries; bucket assignment (decide_bucket)
# uses HK/MO/TW positively.
# ---------------------------------------------------------------------------
NON_MAINLAND_REGIONS: list[str] = [
    "US",  # United States
    "JP",  # Japan
    "SG",  # Singapore
    "KR",  # South Korea
    "DE",  # Germany
    "GB",  # United Kingdom
    "NL",  # Netherlands
    "AU",  # Australia
    "CA",  # Canada
    "FR",  # France
]

# ---------------------------------------------------------------------------
# P1 Multi-region: Bucket definitions
# ---------------------------------------------------------------------------
# The set of recognized region buckets. A domain is assigned to exactly one
# of these (or to "" / unclassified). See docs/PROPOSAL_MULTI_REGION.md §2.
REGION_BUCKETS: set[str] = {"CN", "HK", "MO", "TW"}

# ipnova multi-region CIDR data source. Self-owned upstream → use main branch;
# no supply-chain pinning required (see PROPOSAL §3.1).
IPNOVA_BASE: str = "https://raw.githubusercontent.com/harryheros/ipnova/main/output"

REGION_CIDR_URLS: dict[str, str] = {
    "CN": f"{IPNOVA_BASE}/CN.txt",
    "HK": f"{IPNOVA_BASE}/HK.txt",
    "MO": f"{IPNOVA_BASE}/MO.txt",
    "TW": f"{IPNOVA_BASE}/TW.txt",
}

# Sanity-check threshold: ipnova region files with fewer than this many lines
# are treated as transport corruption (truncated 502, partial response, etc.)
# and the affected bucket is degraded to empty for the current build.
# Macao is the smallest legitimate region; even MO.txt has hundreds of CIDRs.
IPNOVA_MIN_LINES: int = 50

# Map TLD suffix -> bucket. Used as +1 vote in decide_bucket().
TLD_TO_BUCKET: dict[str, str] = {
    ".cn": "CN",
    ".hk": "HK",
    ".mo": "MO",
    ".tw": "TW",
}
