"""
constants.py - Mainland China Digital Asset Intelligence Database
Categorizes ASNs and Infrastructure for professional data analysis.
"""

# === Tier 1: State-Owned Backbone ===
CN_BACKBONE = {
    # China Telecom
    "4134":  {"isp": "China Telecom", "name": "CHINANET-BACKBONE",       "level": "Core"},
    "4809":  {"isp": "China Telecom", "name": "CN2-GIA",                 "level": "Premium"},
    "23724": {"isp": "China Telecom", "name": "CHINANET-IDC",            "level": "Core"},
    "58563": {"isp": "China Telecom", "name": "CHINANET-HB",             "level": "Core"},
    "24139": {"isp": "China Telecom", "name": "CHINANET-FJ",             "level": "Core"},
    "4812":  {"isp": "China Telecom", "name": "CHINANET-SH",             "level": "Core"},
    "4816":  {"isp": "China Telecom", "name": "CHINANET-GD",             "level": "Core"},

    # China Unicom
    "4837":  {"isp": "China Unicom",  "name": "CHINA-UNICOM-BACKBONE",   "level": "Core"},
    "9929":  {"isp": "China Unicom",  "name": "CU-VIP",                  "level": "Premium"},
    "4808":  {"isp": "China Unicom",  "name": "CU-BEIJING",              "level": "Core"},
    "17621": {"isp": "China Unicom",  "name": "CU-SHANGHAI",             "level": "Core"},
    "9800":  {"isp": "China Unicom",  "name": "CU-GUANGDONG",            "level": "Core"},

    # China Mobile
    "9808":  {"isp": "China Mobile",  "name": "CMNET-BACKBONE",          "level": "Core"},
    "56048": {"isp": "China Mobile",  "name": "CMNET-IDC",               "level": "Core"},
    "24400": {"isp": "China Mobile",  "name": "CMNET-GUANGDONG",         "level": "Core"},
    "58453": {"isp": "China Mobile",  "name": "CMNET-HK",                "level": "Core"},

    # Education & Research
    "4538":  {"isp": "CERNET",        "name": "China Education Network", "level": "Academic"},
    "24400": {"isp": "CSTNET",        "name": "China Science Network",   "level": "Research"},

    # Sina
    "37936": {"isp": "Sina",          "name": "SINA-CN",                 "level": "Core"},
}

# === Tier 2: Major Cloud Providers ===
CN_CLOUD_ASNS = {
    # Alibaba
    "45090":  "Alibaba_Cloud_CN",
    "37963":  "Alibaba_Cloud_CN",

    # Tencent
    "132132": "Tencent_Cloud_CN",
    "45090":  "Tencent_Cloud_CN",

    # Huawei
    "55990":  "Huawei_Cloud_CN",

    # Baidu
    "38365":  "Baidu_Cloud_CN",

    # JD Cloud
    "131486": "JD_Cloud_CN",
    "58807":  "JD_Cloud_CN",

    # Other CN Clouds
    "136188": "Kingsoft_Cloud_CN",
    "135371": "UCloud_CN",
    "23724":  "ChinaTelecom_Cloud_CN",
}

# === Tier 3: Infrastructure Function Tags ===
INFRA_KEYWORDS = {
    "CDN": ["wangsu", "chinacache", "baishan", "qiniu", "upyun", "fastweb"],
    "GOV": ["government", "gov", "agency", "ministry", "state"],
    "FIN": ["bank", "icbc", "ccb", "abc", "unionpay", "insurance"],
}

# === Geo-Fencing: Negative Signals ===
NON_MAINLAND_REGIONS = ["HK", "MO", "TW", "US", "JP", "SG"]
