# DomainNova

> Self-evolving dataset of domains hosted on Asia-Pacific infrastructure, ranked by confidence.

[![Update](https://github.com/harryheros/domainnova/actions/workflows/update.yml/badge.svg)](https://github.com/harryheros/domainnova/actions/workflows/update.yml)
[![Version](https://img.shields.io/badge/version-v3.7.0-blue)](https://github.com/harryheros/domainnova/releases)

DomainNova answers one question: **is this domain's infrastructure physically hosted in region X?** — for CN, HK, TW, MO, JP, KR and SG. It attributes infrastructure, not corporate ownership, and it is a dataset, not a routing or filtering product.

Unlike static lists, it discovers, verifies and retires domains automatically every week. Current statistics: [`data/stats.json`](data/stats.json).

> **License**: [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) for all versions, including historical commits. Commercial use requires a separate written license — see [COMMERCIAL_LICENSE.md](./COMMERCIAL_LICENSE.md).

---

## Output

| File | Contents |
|---|---|
| `dist/domains_{cn,hk,tw,mo,jp,kr,sg}.txt` | One domain per line, score ≥ 60 |
| `data/domains.csv` | Every domain with all signals, score, region, provider and CDN flag |
| `data/domains_metadata.{json,yaml,csv}` | Entity, category and ecosystem per domain |
| `data/stats.json` | Build statistics and lifecycle counters |
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

DNS goes to our own resolver first when one is set up, with a rotating EDNS Client Subnet of Chinese carrier networks, so results match what users in the region see, without querying DNS servers in China. With the repository secret `DOMAINNOVA_DOH_URL` set, that resolver is a [DNSNova](https://github.com/harryheros/dnsnova) server's `ecs.client_path`, which resolves from each domain's own name servers; without it (a fork, a local run), the public resolvers below are used directly. Public resolvers with client subnet support (Google, Quad9) answer only when it does not, and `DOMAINNOVA_PUBLIC_DOH=off` turns them off: a domain then keeps its last placement until our resolver answers again. A domain with no record on its bare name, common for government sites, is checked through `www.<domain>`.

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

- **Discovery**: each week, reverse-IP lookups over IPNova's CN ranges (HackerTarget, optional ViewDNS API) find up to 100 new candidates. Subdomains of known domains are skipped, since suffix matching already covers them.
- Promotion pauses when `extended.txt` reaches 5000 domains.
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

Add domains to `sources/manual/seed_{region}.txt` or `sources/manual/extended.txt` and open a pull request. `discovery.txt` is managed automatically; do not edit it by hand.

Local tools: `python sources/scripts/build_domains.py`, `build_metadata.py --all`, `validate_manual_sources.py`. Development notes: [`docs/`](docs/).

---

## License

- **Non-commercial use**: permitted under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/).
- **Commercial use** (SaaS, API resale, redistribution, paid products, use inside a company beyond research): requires prior written authorization — see [COMMERCIAL_LICENSE.md](./COMMERCIAL_LICENSE.md), or ask at [novaod.com/licensing](https://novaod.com/licensing).

Part of the [Nova infrastructure toolkit](https://github.com/harryheros).
