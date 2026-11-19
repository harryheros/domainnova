"""
_quality.py - what a discovery agent may nominate, and what may be promoted.

DomainNova lists broadly-used domains, one registrable name each (a rule set
matches by suffix, so the name covers its subdomains). Three kinds of name
never belong in it, whichever agent found them:

  - a name under a free subdomain or dynamic-DNS service (x.dpdns.org,
    y.3322.org): the registrable name belongs to the service, not the site,
    and the site behind the subdomain can change owner at any time;
  - adult and gambling sites;
  - numeric throwaway names on low-cost TLDs (0026.cc, 8686868.vip) and
    phone-number names (01083531111.com), the usual shape of spam and
    gambling site farms.

junk_reason() says which rule a name breaks, or None. Pure stdlib; imported
by the discovery agents (through _common) and by build_domains (promotion).
"""
from __future__ import annotations

import re
from typing import Optional

# Second-level labels under which names are registered (public suffixes),
# for the region's ccTLDs and a few common others. Elsewhere the registrable
# domain is the last two labels.
SECOND_LEVEL = {
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

# Free subdomain, dynamic-DNS and app-hosting services: anyone can take a
# name under these, so a name under them says nothing about a site.
FREE_SUBDOMAIN_SUFFIXES = frozenset({
    "dpdns.org", "ggff.net", "us.kg", "eu.org", "qzz.io", "kurl.cc",
    "3322.org", "f3322.net", "oray.net", "vicp.net", "vicp.cc", "gicp.net",
    "imwork.net", "eicp.net", "xicp.net", "cpolar.cn", "cpolar.top",
    "duckdns.org", "ddns.net", "no-ip.org", "nip.io", "sslip.io",
    "github.io", "gitee.io", "vercel.app", "netlify.app", "pages.dev",
    "workers.dev", "herokuapp.com", "ngrok.io", "ngrok-free.app",
})

# Low-cost TLDs on which numeric names are almost always site-farm throwaways.
CHEAP_TLDS = frozenset({
    "xyz", "cc", "top", "vip", "live", "club", "site", "online", "shop", "icu",
    "fun", "store", "buzz", "win", "bid", "loan", "work", "ltd", "pw", "tk",
    "ml", "ga", "cf", "gq", "cyou", "sbs", "cfd", "lol", "game", "games",
})

# TLDs that are themselves adult or gambling.
ADULT_GAMBLING_TLDS = frozenset({"bet", "casino", "poker", "porn", "xxx", "sex", "adult"})

# Words (and pinyin) of adult and gambling sites. Kept to forms that do not
# occur inside ordinary words: "jav" only when not "java", "bet" only next
# to digits (bet365, 365bet), never "alphabet" or "better".
ADULT_GAMBLING_RE = re.compile(
    r"casino|bocai|caipiao|lecai|qipai|dubo|baijiale|porn|xxx|hentai"
    r"|jav(?!a)|bet\d|\dbet"
)


def registrable(host: str) -> Optional[str]:
    """news.sina.com.cn -> sina.com.cn; None for a bare suffix or no dot."""
    labels = host.strip().lower().rstrip(".").split(".")
    if len(labels) < 2 or not all(labels):
        return None
    if labels[-2] in SECOND_LEVEL.get(labels[-1], ()):
        return ".".join(labels[-3:]) if len(labels) >= 3 else None
    return ".".join(labels[-2:])


def under_free_service(domain: str) -> bool:
    labels = domain.strip().lower().rstrip(".").split(".")
    return any(".".join(labels[i:]) in FREE_SUBDOMAIN_SUFFIXES for i in range(len(labels)))


def junk_reason(domain: str) -> Optional[str]:
    """The rule `domain` breaks ('free-subdomain', 'adult-gambling',
    'numeric-throwaway'), or None when it may be listed."""
    d = domain.strip().lower().rstrip(".")
    if under_free_service(d):
        return "free-subdomain"
    reg = registrable(d) or d
    first, tld = reg.split(".")[0], reg.rsplit(".", 1)[-1]
    if tld in ADULT_GAMBLING_TLDS or ADULT_GAMBLING_RE.search(d):
        return "adult-gambling"
    digits = sum(c.isdigit() for c in first)
    if tld in CHEAP_TLDS and digits >= 3 and digits * 2 >= len(first):
        return "numeric-throwaway"
    if first.isdigit() and len(first) >= 8:
        return "numeric-throwaway"
    return None
