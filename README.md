# DomainNova

> Self-evolving dataset of domains hosted on Asia-Pacific infrastructure, ranked by confidence.

[![Version](https://img.shields.io/badge/version-v3.9.2-blue)](https://github.com/harryheros/domainnova/releases)
[![License](https://img.shields.io/badge/license-CC%20BY--NC--SA%204.0-blue.svg)](#license)
[![Data](https://img.shields.io/badge/data-updated%20weekly-brightgreen)](data/QUALITY.md)
[![Weekly build](https://img.shields.io/github/actions/workflow/status/harryheros/domainnova/update.yml?label=weekly%20build)](https://github.com/harryheros/domainnova/actions/workflows/update.yml)

DomainNova answers one question: **is this domain's infrastructure hosted in region X?** — for CN, HK, TW, MO, JP, KR and SG. It attributes infrastructure, not corporate ownership, and it is a dataset, not a routing or filtering product. It serves compliance and jurisdiction audits, vendor and supply-chain risk, OSINT and network intelligence, and traffic classification.

Unlike static lists, it discovers, verifies and retires domains every week. How the current data was found, checked and cleaned: [`data/QUALITY.md`](data/QUALITY.md).

> **License**: [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) for all versions, including historical commits. Commercial use requires a separate written license — see [COMMERCIAL_LICENSE.md](./COMMERCIAL_LICENSE.md).

## Get the data

One list per region, one domain per line: [CN](dist/domains_cn.txt) · [HK](dist/domains_hk.txt) · [MO](dist/domains_mo.txt) · [TW](dist/domains_tw.txt) · [JP](dist/domains_jp.txt) · [KR](dist/domains_kr.txt) · [SG](dist/domains_sg.txt). The latest:

```text
https://raw.githubusercontent.com/harryheros/domainnova/main/dist/domains_cn.txt
```

To pin the exact lists a paper, an audit or a tool used, use the commit of that week's update. Each data update is one `chore: auto-update` commit ([history of `dist/`](https://github.com/harryheros/domainnova/commits/main/dist)), and its `data/QUALITY.md` and `data/stats.json` describe that build:

```text
https://raw.githubusercontent.com/harryheros/domainnova/<commit>/dist/domains_cn.txt
```

Release tags (`vX.Y.Z`) mark code changes, not data.

Files:

- `dist/domains_{region}.txt` — the published lists (score ≥ 60).
- `data/domains_metadata.{json,yaml,csv}` — every domain in the three tiers: tier, origin (how it was found), entity, category and ecosystem.
- `data/QUALITY.md` — the quality page: published domains by tier and origin, resolver shares, foreign edges held back, seed health, removals.
- `data/stats.json` — build statistics, lifecycle counters, and which resolver answered (`resolver`).
- `data/seed_review.json` — curated domains whose name no longer exists, for manual review.

## How a domain is placed

Each domain is scored separately for every region; 60 or more publishes it there.

| Signal | Points | Meaning |
|---|---|---|
| `dns_xx` | 60 | 60% or more of its addresses in the region's [IPNova](https://github.com/harryheros/ipnova) ranges |
| `xx_tld` | +20 | The region's ccTLD (`.hk` `.mo` `.tw` `.jp` `.kr` `.sg`), with `dns_xx` |
| `cn_tld` | +10 | `.cn`, with `dns_cn` |
| `.cn` fallback | 60 | `.cn` without a DNS match: ICP filing is a strong signal |

- Only `.cn` has a fallback: no other region has a mandatory filing system.
- A domain under 60 stays in the build's working file `data/domains.csv` (every domain with all signals, score, region, provider and CDN flag), which a local run writes and the repository does not publish.
- **Seeds**, curated by hand in `sources/manual/seed_{region}.txt`, are placed in their own region directly, so a single misattributed address cannot move a well-known domain. Each week a sample of every seed list is checked against IPNova and recorded in `data/seed_health.json`; seeds are never moved automatically.

## How domains are resolved

- **Our own resolver first**, when one is set up (see [Run it yourself](#run-it-yourself)): it asks each domain's own name servers with a rotating EDNS Client Subnet of Chinese carrier networks, so results match what users in the region see, without querying DNS servers in China. A failed first try is repeated once (a lossy path to the name servers).
- **Public resolvers** with client subnet support (Google, Quad9) answer only when ours has no address.
- **`www.<domain>`** is checked when the bare name has no record, which is common for government sites.
- **On trial: the regional view.** Asked as a client in China, many sites in the other regions do not answer from where they are hosted (geographic DNS sends Chinese users elsewhere), so those regions rely mostly on seeds. Each build also asks their seeds and ccTLD names as a client in their own region (a client subnet of the region's main consumer ISP), through public resolvers that pass the subnet on. An answer counts only if it is not on a network where global services answer that region's clients, not on a global CDN, not placed elsewhere by the build, and not one that follows the asker (a client in another region getting an answer in its own region), and only after two weeks in a row. Nothing from it is published yet; the results, including how many seeds it finds and whether any global service gets through, are on the quality page and in `data/stats.json` → `local_view`.

## How the dataset evolves

```text
Core       sources/manual/seed_{region}.txt   curated by hand
Reliable   sources/manual/extended.txt        stable and promoted domains
Discovery  sources/manual/discovery.txt       found automatically (max 5000)
                   │
                   ▼
weekly build: resolve → match IPNova ranges → score → dist/
                   │
       discovery: pass 4 weeks in a row → promoted to extended
                  fail 5 times → removed
```

- **Discovery**: two agents add candidates each week.
  - *Reverse IP* (HackerTarget, or the ViewDNS API when a key is set): the other domains on the in-region addresses of seed domains, up to 100 a week. The 50 lookups a week are shared between regions, with more than their share for HK, MO, SG and TW, and shared-hosting IPs (20 or more unrelated domains) are skipped.
  - *Link crawl*: the links on the home pages of a rotating slice of known sites, up to 500 a week (robots.txt honoured, one request per site). A third of the pages read each week are HK, MO, SG and TW seeds, and regional ccTLDs are queued scarcest region first.
- **What is refused**: every candidate is reduced to its registrable name by the [Public Suffix List](https://publicsuffix.org/) (suffix matching covers the subdomains). Public suffixes themselves (`com.my`), names under free subdomain and hosting services (the list's private section, such as `sakura.ne.jp`), adult and gambling sites, and numeric throwaway names are refused. Global services that answer from in-region edges (found each build through sentinel domains of Google, LinkedIn, Meta and X) are not counted as regional.
- **Promotion**: a candidate is published only after passing the same checks as the rest, and moves to `extended.txt` after passing in 4 different weeks, however often the build runs. Promotion pauses when `extended.txt` reaches 5,000 domains.
- **Provenance**: every domain records how it was first found, in the `origin` column of `domains_metadata.*`: `manual` (curated by hand) or the agent that nominated it (`ip-neighbor`, `link-crawl`, `ct-logs`), with the IP, linking site or query in `origin_detail`. Origins of `extended.txt` domains are kept in [`sources/manual/provenance.csv`](sources/manual/provenance.csv); promotions add to it, and `backfill_provenance.py` rebuilt the history from git. Totals: `data/metadata_stats.json` → `by_origin`. Domains removed by a later review are logged with the reason in [`sources/manual/removed.csv`](sources/manual/removed.csv). Whatever the origin, a domain is published only on this build's own DNS and IP checks.
- **Resolver counts**: `data/stats.json` → `resolver` counts the domains answered by our own resolver (`own`), a public resolver (`public`) or the last-resort fallback (`fallback`) in the latest build (per domain in a local run's `data/domains.csv`).
- **Seed review**: a seed with no address for 3+ weeks is listed in `seed_review.json` if the name no longer exists; CDN and API domains that serve only subdomains are kept apart under `subdomain_only`.

## Schedule

- Every Monday 02:00 UTC: discovery and a full build. Thursday: cache keep-alive.
- Manual runs build only, or also run discovery with `run_agents=yes`. `full_crawl=yes` is a one-off catch-up: link crawl reads every known site's home page in one run (up to 3,000 new candidates) instead of the weekly slice.

## Run it yourself

- Build: `python sources/scripts/build_domains.py`, then `build_metadata.py --all`; check the hand-curated files with `validate_manual_sources.py`.
- Tests: `cd sources/scripts && python -m unittest discover -p "test_*.py"`.
- Our resolver: with the repository secret `DOMAINNOVA_DOH_URL` set to a [DNSNova](https://github.com/harryheros/dnsnova) server's `ecs.client_path`, the build resolves through it; without it (a fork, a local run) the public resolvers are asked directly. `DOMAINNOVA_PUBLIC_DOH=off` turns the public resolvers off: a domain then keeps its last placement until our resolver answers again, and the regional view is skipped.
- Before turning public resolvers off, `python sources/scripts/compare_resolvers.py` resolves every published domain through ours and Google with the same client subnet, and reports in `data/resolver_compare.json` how often they place it in the same region and which domains differ.
- Design records: [`docs/`](docs/). Release history: [CHANGELOG.md](./CHANGELOG.md).

## Contributing

Add domains to `sources/manual/seed_{region}.txt` or `sources/manual/extended.txt` and open a pull request; for `extended.txt`, add a `provenance.csv` row too (origin `manual`, and in `origin_detail` how you found it). `discovery.txt` is managed automatically; do not edit it by hand. By opening a pull request you agree that your contribution may be distributed under this repository's license and under the author's commercial licenses.

## License

- **Non-commercial use**: permitted under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/).
- **Commercial use** (SaaS, API resale, redistribution, paid products, use inside a company beyond research): requires prior written authorization — see [COMMERCIAL_LICENSE.md](./COMMERCIAL_LICENSE.md), or ask at [novaod.com/licensing](https://novaod.com/licensing).
- `sources/third_party/public_suffix_list.dat` is the [Public Suffix List](https://publicsuffix.org/), under the [Mozilla Public License 2.0](https://mozilla.org/MPL/2.0/); see [sources/third_party/README.md](sources/third_party/README.md).

Part of the [Nova infrastructure toolkit](https://github.com/harryheros).
