# Session Changelog

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
