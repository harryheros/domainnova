# Session Changelog

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
