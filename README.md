# DomainNova

> Dataset of domains hosted on Asia-Pacific infrastructure, discovered, verified and retired every week.

[![Version](https://img.shields.io/github/v/release/harryheros/domainnova?label=version&color=blue)](https://github.com/harryheros/domainnova/releases)
[![License](https://img.shields.io/badge/license-CC%20BY--NC--SA%204.0-blue.svg)](#license)
[![Weekly build](https://img.shields.io/github/actions/workflow/status/harryheros/domainnova/update.yml?label=weekly%20build)](https://github.com/harryheros/domainnova/actions/workflows/update.yml)
[![Data quality](https://img.shields.io/badge/data-quality%20report-brightgreen)](data/QUALITY.md)

[Get the data](#get-the-data) · [How a domain is placed](#how-a-domain-is-placed) · [How it works](#how-it-works) · [Changelog](./CHANGELOG.md) · [License](#license)

DomainNova answers one question: **is this domain's infrastructure hosted in region X?** — for CN, HK, TW, MO, JP, KR and SG. It attributes infrastructure, not corporate ownership, and it is a dataset, not a routing or filtering product.

It serves compliance and jurisdiction audits, vendor and supply-chain risk, OSINT and network intelligence, and traffic classification. Unlike static lists, it discovers, verifies and retires domains every week; how the current data was found, checked and cleaned is on the quality page, [`data/QUALITY.md`](data/QUALITY.md).

> [!NOTE]
> **License**: [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) for all versions, including historical commits. Commercial use requires a separate written license — see [COMMERCIAL_LICENSE.md](./COMMERCIAL_LICENSE.md).

## Get the data

One list per region, one domain per line: [CN](dist/domains_cn.txt) · [HK](dist/domains_hk.txt) · [MO](dist/domains_mo.txt) · [TW](dist/domains_tw.txt) · [JP](dist/domains_jp.txt) · [KR](dist/domains_kr.txt) · [SG](dist/domains_sg.txt). The latest:

```text
https://raw.githubusercontent.com/harryheros/domainnova/main/dist/domains_cn.txt
```

**Pin a version.** To fix the exact lists a paper, an audit or a tool used, use the commit of that week's update. Each data update is one `chore: auto-update` commit ([history of `dist/`](https://github.com/harryheros/domainnova/commits/main/dist)), and its `data/QUALITY.md` and `data/stats.json` describe that build:

```text
https://raw.githubusercontent.com/harryheros/domainnova/<commit>/dist/domains_cn.txt
```

Release tags (`vX.Y.Z`) mark code changes, not data.

What each build publishes:

- `dist/domains_{region}.txt`: the published lists (score 60 or more).
- `data/domains_metadata.{json,yaml,csv}`: every domain in the three tiers, with its tier, origin (how it was found), entity, category and ecosystem.
- `data/QUALITY.md`: the quality page — published domains by tier and origin, resolver shares, foreign edges held back, seed health, removals.
- `data/stats.json`: build statistics, lifecycle counters, and which resolver answered (`resolver`).
- `data/seed_review.json`: curated domains whose name no longer exists, for manual review.

## How a domain is placed

Each domain is scored separately for every region; 60 points or more publishes it there.

- **60** — `dns_xx`: 60% or more of its addresses are in the region's [IPNova](https://github.com/harryheros/ipnova) ranges.
- **+20** — `xx_tld`: the region's ccTLD (`.hk` `.mo` `.tw` `.jp` `.kr` `.sg`), together with `dns_xx`.
- **+10** — `cn_tld`: `.cn`, together with `dns_cn`.
- **60** — `.cn` fallback: `.cn` without a DNS match, since ICP filing is a strong signal. Only `.cn` has a fallback: no other region has a mandatory filing system.

A domain under 60 stays in the build's working file `data/domains.csv` (every domain with all signals, score, region, provider and CDN flag), which a local run writes and the repository does not publish.

**Seeds**, curated by hand in `sources/manual/seed_{region}.txt`, are placed in their own region directly, so a single misattributed address cannot move a well-known domain. Each week a sample of every seed list is checked against IPNova and recorded in `data/seed_health.json`; seeds are never moved automatically.

## How it works

Every Monday the build resolves every domain, matches its addresses to IPNova's ranges, scores it and publishes the lists; discovery adds candidates the same day. The full method: [docs/how-it-works.md](docs/how-it-works.md).

- **Resolving**: our own resolver first, which asks each domain's own name servers with a client subnet of Chinese carrier networks; public resolvers (Google, Quad9) only when it has no address; `www.<domain>` when the bare name has no record.
- **Three tiers**: hand-curated seeds, a reliable extended list, and discovery candidates found each week by reverse-IP lookups and a link crawl.
- **What is refused**: public suffixes, names under free subdomain and hosting services, adult, gambling and throwaway names, and global services answering from in-region edges.
- **Promotion**: a candidate moves to the extended list after passing in 4 different weeks; one that fails 5 times is removed.
- **Provenance**: every domain records how it was first found (`origin`), and removals are logged with their reason in [`sources/manual/removed.csv`](sources/manual/removed.csv).
- **On trial**: a regional view that asks each region's names as a client in that region. Nothing from it is published yet; its results are on the quality page.

## Run it yourself

- **Build**: `python sources/scripts/build_domains.py`, then `build_metadata.py --all`; check the hand-curated files with `validate_manual_sources.py`.
- **Tests**: `cd sources/scripts && python -m unittest discover -p "test_*.py"`.
- **Our resolver**: with the repository secret `DOMAINNOVA_DOH_URL` set to a [DNSNova](https://github.com/harryheros/dnsnova) server's `ecs.client_path`, the build resolves through it; without it (a fork, a local run) the public resolvers are asked directly. `DOMAINNOVA_PUBLIC_DOH=off` turns the public resolvers off: a domain then keeps its last placement until our resolver answers again, and the regional view is skipped.
- **Compare resolvers**: before turning public resolvers off, `python sources/scripts/compare_resolvers.py` resolves every published domain through ours and Google with the same client subnet, and reports in `data/resolver_compare.json` how often they place it in the same region and which domains differ.
- **More**: the method in [docs/how-it-works.md](docs/how-it-works.md), design records in [`docs/`](docs/), release history in [CHANGELOG.md](./CHANGELOG.md).

## Contributing

Add domains to `sources/manual/seed_{region}.txt` or `sources/manual/extended.txt` and open a pull request; for `extended.txt`, add a `provenance.csv` row too (origin `manual`, and in `origin_detail` how you found it). `discovery.txt` is managed automatically; do not edit it by hand. By opening a pull request you agree that your contribution may be distributed under this repository's license and under the author's commercial licenses.

## License

- **Non-commercial use**: permitted under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/).
- **Commercial use** (SaaS, API resale, redistribution, paid products, use inside a company beyond research): requires prior written authorization — see [COMMERCIAL_LICENSE.md](./COMMERCIAL_LICENSE.md), or ask at [novaod.com/licensing](https://novaod.com/licensing).
- `sources/third_party/public_suffix_list.dat` is the [Public Suffix List](https://publicsuffix.org/), under the [Mozilla Public License 2.0](https://mozilla.org/MPL/2.0/); see [sources/third_party/README.md](sources/third_party/README.md).

Part of the [Nova infrastructure toolkit](https://github.com/harryheros).
