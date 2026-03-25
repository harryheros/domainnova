"""
constants.py - Mainland China Digital Asset Intelligence Database
Categorizes ASNs and Infrastructure for professional data analysis.
"""

# === Tier 1: State-Owned Backbone (The Digital Border) ===
CN_BACKBONE = {
    "4134":  {"isp": "China Telecom", "name": "CHINANET-BACKBONE",             "level": "Core"},
    "4809":  {"isp": "China Telecom", "name": "CN2-GIA",                       "level": "Premium"},
    "4837":  {"isp": "China Unicom",  "name": "CHINA-UNICOM-BACKBONE",         "level": "Core"},
    "9929":  {"isp": "China Unicom",  "name": "CU-VIP",                        "level": "Premium"},
    "9808":  {"isp": "China Mobile",  "name": "CMNET-BACKBONE",                "level": "Core"},
    "4538":  {"isp": "CERNET",        "name": "China Education Network",       "level": "Academic"},
    "24400": {"isp": "CSTNET",        "name": "China Science & Technology Network", "level": "Research"},
}

# === Tier 2: Major Cloud Providers (Data Residency) ===
CN_CLOUD_ASNS = {
    "45090":  "Alibaba_Cloud_CN",
    "132132": "Tencent_Cloud_CN",
    "55990":  "Huawei_Cloud_CN",
    "37963":  "Baidu_Cloud_CN",
    "58807":  "JD_Cloud_CN",
    "136188": "Kingsoft_Cloud_CN",
    "135371": "UCloud_CN",
}

# === Tier 3: Infrastructure Function Tags ===
INFRA_KEYWORDS = {
    "CDN": ["wangsu", "chinacache", "baishan", "qiniu", "upyun", "fastweb"],
    "GOV": ["government", "gov", "agency", "ministry", "state"],
    "FIN": ["bank", "icbc", "ccb", "abc", "unionpay", "insurance"],
}

# === Geo-Fencing: Negative Signals ===
# IPs in these regions are NOT considered mainland China infrastructure.
NON_MAINLAND_REGIONS = ["HK", "MO", "TW", "US", "JP", "SG"]
