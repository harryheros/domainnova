# DomainNova Changelog

Releases, newest first. The weekly data updates are the
`chore: auto-update` commits; current statistics are in
[data/stats.json](./data/stats.json).

## 3.9.1 (2026-11-23)

- **The regional view asks from where the region's people are.** Its
  first build asked each region from the first /24 of its largest IPNova
  range, which for SG was a cloud provider's 43.0.0.0/9 and for HK a
  transit operator's 63.216.0.0/13: addresses used worldwide, so
  geographic DNS answered as for a client somewhere else, and only 2 of
  73 SG seeds (and 41 of 126 HK seeds) were found in their own region.
  Each region is now asked from a block of its main consumer ISP (HK
  113.252.0.0/14, MO 60.246.0.0/16, TW 1.160.0.0/12, JP 126.0.0.0/8, KR
  121.128.0.0/10, SG 116.14.0.0/15) while IPNova has it in the region,
  and from the largest range otherwise; QUALITY.md says which.
- **Why seeds are not found.** The calibration table on QUALITY.md now
  says which guard stopped the seeds that were not found, and
  `data/stats.json` → `local_view.seed_examples` lists a few of each, so
  the next build shows where the view goes wrong instead of only how
  often. Nothing from the view is published yet.

## 3.9.0 (2026-11-19)

- **Discovery looks for the smaller regions too.** The IP-neighbor agent
  resolved only the CN seeds and kept only CN addresses, so all of its
  reverse-IP lookups (about 50 a week, the free quota) went to CN
  servers, and HK, MO, SG and TW grew only through link crawl. The
  lookups are now shared between regions (CN 15, HK 10, SG 10, MO 6,
  TW 6, JP 3): each region resolves its own seeds and keeps only
  addresses in its own IPNova ranges; slots a region cannot fill go to
  the others, and lookups alternate between regions so that one region
  cannot spend the week's budget of new domains. Seeds of every region
  are resolved with the same client subnet as the build, so the agent
  only looks next to servers the build itself places in the region.
- **Link crawl reads the smaller regions' sites more often.** 100 of the
  300 home pages read each week are a rotating slice of the HK, MO, SG
  and TW seeds (about 410 sites, so each is read every four weeks
  instead of every eight; the other 2,000 or so known sites, every ten
  weeks instead of eight), and candidates are queued by regional ccTLD,
  scarcest region first (`.mo`, `.sg`, `.hk`, `.tw`, then `.jp`, `.kr`,
  `.cn`), so the budget is not spent on `.cn` names first. A domain
  linked from several sites is credited to the first site read, now
  more often one of these seeds. `--all` is unchanged.
- **On trial: the regional view (nothing published from it).** The
  build resolves every domain as a client in China would, and asked that
  way only 1 to 3 of every 20 sampled HK, MO, SG, TW, JP and KR seeds
  land in their own region; the rest are there only because they are
  curated. Each build now also asks seeds and names under those regions'
  ccTLDs as a client in their own region (`_local_view.py`), through
  public resolvers that pass the subnet on (Quad9, then Google; never
  our own resolver, whose location would answer for every subnet when a
  name server ignores it; skipped with `DOMAINNOVA_PUBLIC_DOH=off`).
  A global service also answers from its node in the region asked that
  way, so an answer counts only if it is not on a network where the
  control names (global services, and global CDNs' customers) answer
  that region, not on a global CDN, not placed elsewhere by the build,
  and does not follow the asker (asked from a probe region, it answers
  there), and only after two weeks in a row. The result goes to
  `data/stats.json` → `local_view` and a section of `QUALITY.md`: how
  many seeds the view finds, how many control checks get through (it
  should be none), the verdicts, and what it would add. Whether it may
  change the lists will be decided on that record.
- **Every data version can be cited.** Each build that changes the data
  is now tagged `data-YYYY-MM-DD` (UTC) after it is pushed, so a paper,
  an audit or another tool can pin the exact lists it used:
  `https://raw.githubusercontent.com/harryheros/domainnova/data-2026-11-23/dist/domains_cn.txt`.
  Tags are never moved: a second build on the same day that changes the
  data again gets `.2`, `.3` and so on. The tag message records the
  published counts, the build time and the code version
  (`sources/scripts/data_tag.py`). A failed tag push does not fail the
  build.
- **A public data-quality page, `data/QUALITY.md`**, rewritten by every
  build from its own outputs (`build_quality_report.py`): published
  domains by region and tier, how they were found (`origin`), which
  resolver answered, the foreign-service networks and the domains held
  back because of them, seed health, this build's promotions and
  removals, and the domains removed on review by reason. As of the
  2026-11-19 build: 4,985 published, 38.6% curated by hand and 53.4%
  found by link crawl; our own resolver answered 92% of all domains
  checked.
- README: `data/domains.csv` was listed among the published files, but it
  is the build's working file and is not committed; the README now says
  so.

## 3.8.1 (2026-11-19)

- **Registrable names come from the Public Suffix List.** 3.8.0 reduced
  every candidate to its registrable name with a hand-written table that
  knew only a few ccTLDs (CN, HK, MO, TW, JP, KR, SG, UK, AU) and took the
  last two labels elsewhere, so a link to `abc.com.my` was nominated as
  `com.my`. Two such names were published: `com.my` in SG and
  `sakura.ne.jp` (a shared-hosting suffix) in JP. The
  [Public Suffix List](https://publicsuffix.org/) is now kept in the
  repository (`sources/third_party/`, MPL-2.0) and read with the standard
  library (`sources/scripts/_psl.py`), wildcard and exception rules
  included: `www.city.nagoya.jp` reduces to `city.nagoya.jp`, which the
  old table would have made `nagoya.jp`.
- **A public suffix is never nominated or promoted**, nor is a name under
  a suffix of the list's private section (`x.sakura.ne.jp`,
  `shop.myshopify.com`, `x.ccwu.cc`): those are names that a hosting or
  subdomain service hands out to its users, like the free subdomain
  services already refused. A discovery name purged by these rules is also
  left out of that build's lists; before, it was published once more on
  its way out.
- **The data was cleaned with the same rules** (`clean_agent_domains.py`):
  29 agent-nominated public suffixes were removed, `ccwu.cc` from
  `extended.txt` and 28 from `discovery.txt` (`com.my`, `sakura.ne.jp`,
  `googleapis.com`, `myshopify.com`, `blogspot.com`, `com.br`, `com.tr`,
  `edu.my`, `ac.ae`, `tokyo.jp` and others), each logged in
  `sources/manual/removed.csv`. Domains curated by hand were not touched,
  so `gov.cn`, `edu.cn`, `gov.hk`, `gov.mo`, `gov.sg`, `gov.tw` and
  `edu.tw`, which are listed on purpose, stay. `com.my` and `sakura.ne.jp`
  leave the published lists at the next build.
- 3.8.0 entry below corrected: the clean-up came before the full crawl,
  and its published totals are given as measured.

## 3.8.0 (2026-11-18)

- **Every domain records how it was found.** `data/domains_metadata.*`
  now covers all three tiers (discovery domains were missing, so about 200
  published domains had no metadata row) and adds `origin` and
  `origin_detail`: `manual` for domains curated by hand, or the discovery
  agent that nominated them (`ip-neighbor` with the IP whose neighbours
  were listed, `link-crawl` with the linking site, `ct-logs` with the
  query). The origins of `extended.txt` domains are kept in
  `sources/manual/provenance.csv`; each promotion adds its domains, with
  the discovery.txt header they were listed under.
- **The history was rebuilt from git** (`backfill_provenance.py`) for the
  4,027 `extended.txt` domains: 774 curated by hand (the first version of
  the file and later hand additions), 1,325 found by IP-neighbor discovery,
  248 by CT logs, and 1,680 nominated between 2026-03-28 and 2026-05-07 by
  a former agent that copied candidates from public proxy-routing lists
  (v2fly/domain-list-community and felixonmars/dnsmasq-china-list).
- **Those 1,680 domains are removed.** They had passed this dataset's own
  checks, but a list made for proxy routing is not a source this dataset
  wants to depend on. The published CN list goes from 4,436 to about 2,890
  domains, HK loses 14 and SG 52; the other regions are unchanged. Any of
  them that the dataset's own discovery finds again comes back under that
  origin.
- **New discovery agent, link crawl**
  (`sources/discovery_agents/agent_link_crawl.py`): each week it reads the
  home pages of a rotating slice of known sites (300 per run, robots.txt
  honoured, one request per site) and adds up to 500 linked domains, under a
  header naming the linking site. It runs with the IP-neighbor agent; one
  failing no longer stops the other. Its first run added 500 candidates,
  317 of which passed the checks at once (KR went from 165 to 262 domains).
- **One-off full crawl**: a manual run with `full_crawl=yes` makes link
  crawl read the home page of every known site at once (`--all`, up to
  3,000 new candidates) instead of the weekly slice, which takes about ten
  weeks to cover the same sites. It is meant to refill discovery after the
  clean-up below; the etiquette is unchanged (one request per site,
  robots.txt honoured). A site whose connection breaks off mid-page no
  longer stops the run: the first full crawl ended on one such site with
  nothing written, as the weekly 300-page slice had never met one. The
  full crawl read 2,436 sites and added 3,000 candidates; the build after it
  published 2,199 more domains (CN 1,407, KR 549, JP 88, TW 76, SG 44,
  HK 31, MO 4), for 4,991 in all.
- **More global services are never added to discovery**: Google's tag,
  ad and API domains, LinkedIn, X, Wix, WordPress, GitHub and the common
  public CDNs. Pages embed them everywhere, and some resolve to in-country
  edges for the region's users: the first link crawl placed
  googletagmanager.com, googletagservices.com, googleadservices.com,
  linkedin.com and google.cn in CN, and the full crawl googleoptimize.com.
  Those six were taken out of discovery.txt.
- **What an agent may nominate.** A review of the first promotions found
  site farms, gambling and adult sites, and hundreds of unrelated small
  sites, almost all from IP-neighbor discovery on shared-hosting IPs. The
  rules are now (`sources/scripts/_quality.py`):
  - every candidate is reduced to its registrable name
    (`0757jiafa.cn.alibaba.com` → `alibaba.com`), as suffix matching
    covers the subdomains;
  - names under free subdomain and dynamic-DNS services (`dpdns.org`,
    `3322.org`, `github.io` …), adult and gambling sites, and numeric
    throwaway names on low-cost TLDs (`0026.cc`, `8686868.vip`) are
    refused;
  - the IP-neighbor agent skips an IP that serves 20 or more unrelated
    registrable domains: its neighbours are strangers to the seed, not
    the seed's own services.
  A discovery domain that breaks these rules is purged instead of promoted.
- **Promotion counts weeks, not runs.** A discovery domain's streak counts
  at most one build per ISO week, so manual runs cannot promote a domain
  early. Two manual runs on 2026-11-19 had promoted 8 domains seen for
  less than a week, five of them from one shared server.
- **The existing data was cleaned with the same rules**
  (`clean_agent_domains.py`). Domains curated by hand were not touched.
  From `extended.txt` and `discovery.txt`, 1,547 agent-nominated names were
  removed: 801 from shared-hosting IPs, 704 subdomains already covered by
  a listed domain, 20 numeric throwaway names, 12 under free subdomain
  services and 10 adult or gambling sites. Another 182 subdomains were
  replaced by their registrable name. Every removal and replacement is
  logged, with its reason, in `sources/manual/removed.csv`.
  `extended.txt` now holds 1,116 domains (774 by hand, 174 from
  IP-neighbor, 168 from CT logs). The clean-up came before the full crawl
  above: the build after it published 2,777 domains (from 4,123), 1,807 of
  them in CN (from 3,201), and the full crawl then brought the total to
  4,991. (This entry first gave an estimate of 2,400 to 2,600 for the
  clean-up and placed it after the crawl.)
- **Global services' in-country edges are not regional evidence.** Each
  build resolves a few sentinel domains of global companies (Google,
  YouTube, LinkedIn, Facebook, X; never CDNs) and treats the /24s of their
  in-region answers as foreign edges, unless a seed domain also uses that
  /24 (a shared CDN serves real regional sites too). A domain that reaches
  its region only through foreign edges is not published, and the
  discovery lifecycle counts it as a failure. `data/stats.json` →
  `foreign_edge` lists the networks and the domains held back. This
  catches the next case without anyone checking the lists by hand; the
  root cause of the Google cases, Google's edge in China (AS24424) in
  IPNova's CN list, is fixed in IPNova 4.1.1.
- **Which resolver answered**: each domain in `data/domains.csv` has a
  `resolver` column (`own`, `public`, `fallback`, or empty when nothing
  answered in this build), and `data/stats.json` → `resolver` counts them.
- Correction to 3.4.0: it said the lists behind the former upstream agent
  had licenses incompatible with this dataset. dnsmasq-china-list is under
  the WTFPL, which allows any use; the agent was removed because those lists
  are made for proxy routing, which this dataset is not.
- Contributing: pull requests are accepted under this repository's license
  and the author's commercial licenses.

## 3.7.1 (2026-11-15)

- **Our own resolver is asked again only when it failed.** Since 3.7.0
  every name was asked twice when the first answer had no address,
  including NXDOMAIN and names that simply have no A record, so such a
  name cost two lookups at our resolver, and with the `www.` fallback four,
  before the public resolvers were asked. A second try is now made only
  when there was no answer to use (no HTTP answer, SERVFAIL, REFUSED), the
  case it exists for: a lossy path to a domain's name servers.
- `constants.py`: removed tables that nothing used any more (carrier and
  cloud ASNs, CN CDN providers, infrastructure keywords, non-mainland
  countries). Some of their entries and comments were wrong, such as the
  file header naming Alibaba as the holder of AS45090 (it is Tencent).
- Release history moved from `docs/CHANGELOG_SESSION.md` to this file;
  outdated comments corrected; unused imports and variables removed.
- No change to scoring or to the published data.

## 3.7.0 (2026-11-12)

- **Own resolver first.** With the repository secret `DOMAINNOVA_DOH_URL`
  set, every domain is first resolved through a
  [DNSNova](https://github.com/harryheros/dnsnova) server's
  `ecs.client_path`, which resolves from the domain's own name servers
  with our client subnet; Google and Quad9 (with client subnet) are asked
  only when it has no answer. Without the secret (a fork, a local run) the
  public resolvers are used directly. `DOMAINNOVA_PUBLIC_DOH=off` turns the
  public resolvers off: a domain then keeps its last placement until our
  resolver answers again.
- The IP-neighbor discovery agent uses the same resolver when it is set.
- Removed the third-party rescue DoH node (coodns).
- `sources/scripts/compare_resolvers.py`: resolves every published domain
  through our resolver and Google with the same client subnet and reports,
  in `data/resolver_compare.json`, how often they agree on the region.
- Commercial use now includes use inside a company beyond research;
  inquiries go to [novaod.com/licensing](https://novaod.com/licensing).
- The tagged commit still reported 3.6.1 in `constants.py`; corrected in
  the next commit.

## 3.6.1 (2026-11-03)

- `data/seed_review.json` listed CDN and API domains (`hdslb.com`,
  `byteimg.com`, `douyinvod.com`, …) as unresolved: they publish
  addresses only on subdomains, so all 32 entries in Nov 2026 were
  false alarms. Listed seeds now get the NS check already used for
  dead-domain detection; registered domains go to `subdomain_only`
  (keep), and `domains` holds only names that do not exist (NXDOMAIN).
- Seed lists cleaned by hand: renamed domains updated, defunct names and
  subdomains already covered by a listed parent (`*.gov.mo`, `*.gov.tw`)
  removed.

## 3.6.0 (2026-10-27)

- **Every discovery domain is checked on every build.** v3.5 checked a
  rotating 300-domain sample, so a discovery domain was in `dist/` only
  in the weeks it was sampled: between the July and October snapshots
  ~150 domains left and ~100 joined the CN list for no reason other than
  the rotation. Promotion needs 4 consecutive passes, which took
  4 × len(discovery)/300 weeks (≈11 at 825 domains) and is now 4 weeks.
- **`www.` fallback.** A domain whose bare name has no address record
  (common for government sites: `soumu.go.jp`, `dsat.gov.mo`) was treated
  as unresolvable — seed health reported 35–70 % resolve failures for
  CN/TW/JP/MO and such discovery/extended domains drifted towards the
  dead-domain purge. The resolver now tries `www.<domain>`;
  `seed_health.json` reports how many samples needed it (`via_www`).
- **Discovery intake.** The IP-neighbor agent runs weekly (was monthly).
  Candidates covered by a known domain or a parent of one are skipped and
  a leading `www.` is removed — about a third of discovery.txt was
  subdomains of known domains. The CT-log agent is no longer scheduled
  (it can only find such subdomains). `DISCOVERY_MAX` 2000 → 5000, now
  defined once for the agents and checked against the build by a test.
- discovery.txt cleaned once: 307 entries that were subdomains of a
  seed/extended domain (or of another discovery entry) were removed;
  their parent domains already cover them. extended.txt is unchanged.
- **Seed review report.** `data/seed_review.json` lists seeds that
  resolved to nothing (bare name and `www.`) for 3+ consecutive weekly
  builds, e.g. names that are wrong or unused (`guangdong.gov.cn` — the
  province uses `gd.gov.cn`). Seeds are curated by hand, so nothing is
  changed automatically. `stats.json` gains `seeds_needing_review`.
- **Look-alike filter.** Discovery candidates with `--` inside a label
  (not the `xn--` IDN prefix) are rejected, e.g. `xiaomi--kursk.online`.
- discovery.txt cleaned once more: 61 entries that resolved to nothing in
  the 2026-10-27 build AND were obvious junk (look-alike `--` hosts,
  random-string hosts such as `fc1k34xp.huanleu.com`, all-digit names,
  vanity TLDs) were removed instead of waiting for the 6-run auto-purge.

## 3.5.0 (2026-09-25)

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

## 3.4.0 (2026-06-08)

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

## 3.3.0 and earlier

Seed lists (2026-04/05):

seed.txt: 701 → 696 (moved alipay.hk / tmall.hk / jd.hk to seed_hk.txt;
bytedance.com / wechat.com to seed_offshore.txt).
Created: seed_hk.txt (3) / seed_mo.txt (empty) / seed_tw.txt (empty) /
seed_offshore.txt (2).

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

Technical fixes:

- seed.txt: removed foxconn.com (cross-region duplicate with seed_tw.txt;
  correct attribution is TW).
- validate_manual_sources.py v2 → v3: added regional-seed validation,
  cross-region duplicate detection, and CN ∩ regional conflict checks.
- update.yml: stats output expanded to all 7 regions (previously displayed
  only cn / hk / mo / tw and silently omitted jp / kr / sg).
