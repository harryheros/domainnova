# Session Changelog

## Session 4 (v3.5.0 — pipeline reliability)

CI / infrastructure:
  - Actions upgraded: checkout v4 → v7, setup-python v5 → v6 (Python 3.13,
    pip cache), cache v4 → v5, github-script v7 → v9. v7 ran on Node 20,
    which GitHub removed from hosted runners on 2026-09-16, so the failure
    notifier could no longer run. Added `concurrency`, `timeout-minutes`,
    push-with-rebase retry, and a unit-test step (tests existed but CI
    never ran them).
  - **Pipeline state now actually persists.** `data/discovery_stats.json`
    was cached under a fixed key; Actions caches are immutable, so every
    save after the first was rejected and the same stale snapshot was
    restored every week. Discovery rotation, purge and dead-domain streaks
    never advanced. State is now saved under a per-run key (restored by
    prefix), only after a fully successful run, with a Thursday keep-alive
    against GitHub's 7-day cache eviction.
  - **Sticky fallback now works in CI.** It reads the previous
    `data/domains.csv`, which is gitignored and was never cached, so it was
    always empty on CI (`sticky_retained` was always 0). It is now part of
    the persisted state. Missing state is logged and reported in
    `stats.json` (`state_restored`).

DNS:
  - Quad9 is queried in RFC 8484 wireformat. Its JSON API (port 5053 only)
    was retired on 2025-05-05, so every Quad9 lookup — half of all primary
    lookups under round-robin — had been failing since.
  - Circuit breaker for the self-hosted rescue DoH node: after 15
    consecutive transport failures it is skipped for the rest of the run
    (`rescue_disabled` in `stats.json`). Previously a down node cost every
    domain JSON + wire attempts with retries and 10s timeouts.

Data safety:
  - Dead-domain check fixed: only an authoritative NXDOMAIN counts as dead.
    The old check also treated "no NS record" as dead, which is the normal
    answer for every subdomain and CNAME name (~380 extended.txt entries).
    It was latent only because the broken state cache kept the 6-run streak
    from ever accumulating.
  - Provider detection falls through to the prefix heuristics when the
    IPNova ASN lookup misses. Restores provider tagging for APNIC blocks
    that IPNova v3.5 correctly relabelled `source: apnic` (no ASN), and
    makes `cdn_masked` work at all (IPNova excludes global-CDN ranges, so
    the ASN path could never match them).

Discovery agents:
  - CT logs: dropped whole-TLD wildcard queries (`%.cn` — crt.sh cannot
    answer them and they were retried with backoff) and free-text
    organisation searches (which pulled spam such as
    `www.xiaomi--kursk.online` into discovery.txt). Queries are now
    `%.<seed>` over unexpired certificates, results restricted to the seed.
  - IP neighbor: removed the key-less ViewDNS HTML scraping fallback; the
    ViewDNS JSON API is used only if a `VIEWDNS_APIKEY` secret is set. The
    agent stops once the HackerTarget quota is exhausted. CN-range lookup
    uses binary search.

Discovery lifecycle:
  - EXTENDED_MAX raised 3,000 -> 5,000. extended.txt (3,007) had passed the
    old cap, so auto-promote was suspended; it resumes with this release.

## Session 3 (v3.4.0 — discovery source cleanup)

Removed the upstream-list discovery agent and its lineage:
  - Deleted `agent_upstream_fetch.py` (pulled from v2fly/domain-list-community
    and felixonmars/dnsmasq-china-list). Those lists originate as proxy-routing
    rule sources, and their upstream licenses are not compatible with
    redistribution inside this CC BY-NC-SA dataset.
  - Purged 1975 upstream-sourced candidates from `discovery.txt`
    (2165 → 91 lines); kept the 25 candidates from neutral sources
    (IP-neighbor + CT logs). Already-promoted domains in extended.txt / dist
    are untouched — they live by the build pipeline's own DNS/IP verification,
    independent of how they were first nominated.
  - `update.yml` now runs only the two neutral agents (IP-neighbor over
    IPNova's own CN ranges, and crt.sh CT logs).

Discovery candidate volume will rebuild over time from the two neutral agents
(~250/month combined); the dataset core (seed_*.txt + extended.txt) is
unaffected.

README: removed "proxy routing" framing from the project description and the
Nova-toolkit table; reordered Use Cases so compliance / supply-chain / OSINT
lead; restated "What this is" to make explicit this is a dataset, not a
routing product, and that downstream use is the consumer's responsibility.

Version: 3.3.0 → 3.4.0 (constants.py + README badge).

## Session 1 (initialization)
seed.txt: 701 → 696 (moved alipay.hk / tmall.hk / jd.hk to seed_hk.txt;
bytedance.com / wechat.com to seed_offshore.txt).
Created: seed_hk.txt (3) / seed_mo.txt (empty) / seed_tw.txt (empty) /
seed_offshore.txt (2).

## Session 2 (seed expansion)
seed_sg.txt: flat layout → categorized layout, added Regulatory,
Infrastructure, Logistics sections.
  Added: acra / edb / enterprise / mas / judiciary / sgnic / sgix /
         spgroup / pub / psa / caas / tech / csa / smrt / sbstransit (+14).

seed_tw.txt: expanded from ~65 → 125 domains.
  Added: twnic / edu.tw registry anchors; all 22 county/city governments;
         science parks; B2B industry-association hubs;
         7-eleven / hi-life / familymart retail; mediatek / acer / foxconn /
         quanta manufacturing; fubon restored; ndc / msa central government.

seed_kr.txt: ~80 → 111 domains.
  Added: kisa registry; kepco / kwater / korail / airport.kr infrastructure;
         gyeonggi / sejong local government; skbroadband telecom; nate portal;
         lotteon / cjlogistics / hanjin e-commerce + logistics;
         edaily / mt.co.kr media; krx / kofia / kfb finance;
         kia / posco / hanwha / doosan manufacturing;
         etri / kist R&D; hanyang / skku.ac.kr education;
         hybecorp / jype / smtown / ygfamily entertainment;
         moef / nhis government supplements.
  Fixed: skku.edu → skku.ac.kr (wrong domain); removed krnic.or.kr
         (merged into KISA).

seed_jp.txt: ~85 → 120 domains.
  Added: jprs / jpix IXP backbone; fsa (Financial Services Agency);
         tepco / kepco / chuden electric utilities; tokyogas energy;
         kuronekoyamato / sagawa / nipponexpress / jr-central / jreast / westjr
         logistics and rail; tokyometro / jal / ana transport and aviation;
         jpx (Japan Exchange); nec / fujitsu / mitsubishielectric / hitachi /
         canon / toshiba manufacturing; keidanren / jetro / jcci business
         associations; isct.ac.jp (new domain for Tokyo Institute of Science);
         riken research.
  Fixed: removed duplicate chuden.co.jp; removed internet.ne.jp
         (not infrastructure).

seed_hk.txt: flat ~70 → categorized 85 domains.
  Fixed: removed non-existent hknic.hk; hke.com.hk → hkelectric.com;
         removed incorrect bankofchina.com.hk.
  Restored: octopus / aastocks / hkstp / fwd / winglungbank / yesstyle;
            added hongkongairlines.

seed_mo.txt: flat ~65 → categorized 68 domains.
  Fixed: removed bankofchina.com.hk (HK domain leaked in);
         removed turbojet.com.hk (cross-border domain).
  Restored: ipim / mbe / ces / ocm;
  Added: gaming-inspection.gov.mo; new Gaming / Hospitality section
         (sands / galaxyentertainment).

seed_offshore.txt: 2 → 7 domains.
  Added: tiktok / tiktokcdn / aliexpress / shein / temu;
  Added categorized layout.

## Session 2 technical fixes
- seed.txt: removed foxconn.com (cross-region duplicate with seed_tw.txt;
  correct attribution is TW).
- validate_manual_sources.py v2 → v3: added regional-seed validation,
  cross-region duplicate detection, and CN ∩ regional conflict checks.
- update.yml: stats output expanded to all 7 regions (previously displayed
  only cn / hk / mo / tw and silently omitted jp / kr / sg).
