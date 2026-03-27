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
# Geo-Fencing: Negative Signals
# Country codes that should NOT be counted as mainland CN even if ASN is CN.
# Expanded to cover common overseas CDN PoP country codes seen in ip-api results.
# ---------------------------------------------------------------------------
NON_MAINLAND_REGIONS: list[str] = [
    "HK",  # Hong Kong
    "MO",  # Macao
    "TW",  # Taiwan
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
