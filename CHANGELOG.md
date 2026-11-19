# DomainNova Changelog

Releases, newest first. The weekly data updates are the
`chore: auto-update` commits; current statistics are in
[data/stats.json](./data/stats.json).

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
  nothing written, as the weekly 300-page slice had never met one.
- **More global services are never added to discovery**: Google's tag,
  ad and API domains, LinkedIn, X, Wix, WordPress, GitHub and the common
  public CDNs. Pages embed them everywhere, and some resolve to in-country
  edges for the region's users: the first link crawl placed
  googletagmanager.com, googletagservices.com, googleadservices.com,
  linkedin.com and google.cn in CN. Those five were taken out of
  discovery.txt.
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
  IP-neighbor, 168 from CT logs). After the next build the published lists
  hold about 2,400 to 2,600 domains, about 1,500 to 1,700 of them in CN;
  outside CN, HK loses 4 and SG 1.
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
