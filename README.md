# DomainNova

> Self-evolving dataset of domains hosted on Asia-Pacific infrastructure, ranked by confidence.

[![Update](https://github.com/harryheros/domainnova/actions/workflows/update.yml/badge.svg)](https://github.com/harryheros/domainnova/actions/workflows/update.yml)
[![Version](https://img.shields.io/badge/version-v3.8.0-blue)](https://github.com/harryheros/domainnova/releases)

DomainNova answers one question: **is this domain's infrastructure physically hosted in region X?** — for CN, HK, TW, MO, JP, KR and SG. It attributes infrastructure, not corporate ownership, and it is a dataset, not a routing or filtering product.

Unlike static lists, it discovers, verifies and retires domains automatically every week. Current statistics: [`data/stats.json`](data/stats.json).

> **License**: [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) for all versions, including historical commits. Commercial use requires a separate written license — see [COMMERCIAL_LICENSE.md](./COMMERCIAL_LICENSE.md).

---

## Output

| File | Contents |
|---|---|
| `dist/domains_{cn,hk,tw,mo,jp,kr,sg}.txt` | One domain per line, score ≥ 60 |
| `data/domains.csv` | Every domain with all signals, score, region, provider and CDN flag |
| `data/domains_metadata.{json,yaml,csv}` | Every domain in the three tiers: tier, origin (how it was found), entity, category and ecosystem |
| `data/stats.json` | Build statistics, lifecycle counters, and which resolver answered (`resolver`) |
| `data/seed_review.json` | Curated domains whose name no longer exists, for manual review |

```text
https://raw.githubusercontent.com/harryheros/domainnova/main/dist/domains_cn.txt
```

---

## Scoring

Each domain is scored separately for every region.

| Signal | Points | Meaning |
|---|---|---|
| `dns_xx` | 60 | ≥ 60% of resolved IPs are in the region's ranges ([IPNova](https://github.com/harryheros/ipnova)) |
| `xx_tld` | +20 | `.hk`, `.mo`, `.tw` — only together with `dns_xx` |
| `cn_tld` | +10 | `.cn` together with `dns_cn` |
| `.cn` fallback | 60 | `.cn` without a DNS match still scores 60 — ICP filing is a strong signal |

Only `.cn` has a fallback: other regional TLDs have no mandatory filing system. Score ≥ 60 goes to `dist/`; everything else stays in `domains.csv` only.

Hand-curated seeds (`sources/manual/seed_{region}.txt`) are the exception: each is placed in its own region directly, so a single misattributed address cannot move a well-known domain. Each week a sample of every seed list is checked against IPNova, and how many still land in their region is recorded in `data/seed_health.json`; seeds are never moved automatically.

DNS goes to our own resolver first when one is set up, with a rotating EDNS Client Subnet of Chinese carrier networks, so results match what users in the region see, without querying DNS servers in China. With the repository secret `DOMAINNOVA_DOH_URL` set, that resolver is a [DNSNova](https://github.com/harryheros/dnsnova) server's `ecs.client_path`, which resolves from each domain's own name servers; without it (a fork, a local run), the public resolvers below are used directly. Our resolver is asked a second time when its first try fails (a lossy path to a domain's name servers); public resolvers with client subnet support (Google, Quad9) answer only when it has no address, and `DOMAINNOVA_PUBLIC_DOH=off` turns them off: a domain then keeps its last placement until our resolver answers again. A domain with no record on its bare name, common for government sites, is checked through `www.<domain>`.

To check our resolver against Google before turning public resolvers off, `python sources/scripts/compare_resolvers.py` resolves every published domain through both with the same client subnet and reports, in `data/resolver_compare.json`, how often they place it in the same region and which domains differ.

---

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

- **Discovery**: each week, two agents find new candidates. Reverse-IP lookups over IPNova's CN ranges (HackerTarget, optional ViewDNS API) add up to 100; the links on the home pages of a rotating slice of known sites add up to 500 (robots.txt honoured, one request per site). Subdomains of known domains are skipped, since suffix matching already covers them. Every candidate is published only after passing the same checks as the rest.
- Promotion pauses when `extended.txt` reaches 5000 domains.
- **Provenance**: every domain records how it was first found, in the `origin` column of `domains_metadata.*`: `manual` (curated by hand), or the discovery agent that nominated it (`ip-neighbor`, `link-crawl`, `ct-logs`), with the IP, linking site or query in `origin_detail`. Origins of `extended.txt` domains are kept in [`sources/manual/provenance.csv`](sources/manual/provenance.csv); promotions add to it, and `backfill_provenance.py` rebuilt the history from git. Totals: `data/metadata_stats.json` → `by_origin`. Whatever the origin, a domain is published only on this build's own DNS and IP checks.
- **Resolver**: `data/stats.json` → `resolver` counts the domains answered by our own resolver (`own`), by a public resolver (`public`) or the last-resort fallback (`fallback`) in the latest build; `data/domains.csv` has it per domain.
- Seeds are never changed automatically. One that has no address for 3+ weeks is listed in `seed_review.json` if the name no longer exists; CDN and API domains that serve only subdomains are kept apart under `subdomain_only`.

---

## Schedule

- Every Monday 02:00 UTC: discovery + full build. Thursday: cache keep-alive.
- Manual runs build only, or also run discovery with `run_agents=yes`.

---

## Use cases

Compliance and jurisdiction audits, vendor and supply-chain risk, OSINT and network intelligence, traffic classification.

---

## Contributing

Add domains to `sources/manual/seed_{region}.txt` or `sources/manual/extended.txt` and open a pull request; for `extended.txt`, add a `provenance.csv` row too (origin `manual`, and in `origin_detail` how you found it). `discovery.txt` is managed automatically; do not edit it by hand. By opening a pull request you agree that your contribution may be distributed under this repository's license and under the author's commercial licenses.

Local tools: `python sources/scripts/build_domains.py`, `build_metadata.py --all`, `validate_manual_sources.py`. Tests: `cd sources/scripts && python -m unittest discover -p "test_*.py"`. Design records: [`docs/`](docs/).

Release history: [CHANGELOG.md](./CHANGELOG.md).

---

## License

- **Non-commercial use**: permitted under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/).
- **Commercial use** (SaaS, API resale, redistribution, paid products, use inside a company beyond research): requires prior written authorization — see [COMMERCIAL_LICENSE.md](./COMMERCIAL_LICENSE.md), or ask at [novaod.com/licensing](https://novaod.com/licensing).

Part of the [Nova infrastructure toolkit](https://github.com/harryheros).
