# How DomainNova works

The full method behind the weekly build. The [README](../README.md) has the short version; the current numbers are on the quality page, [`data/QUALITY.md`](../data/QUALITY.md).

## How domains are resolved

- **Our own resolver first**, when one is set up (see [Run it yourself](../README.md#run-it-yourself)): it asks each domain's own name servers with a rotating EDNS Client Subnet of Chinese carrier networks, so results match what users in the region see, without querying DNS servers in China. A failed first try is repeated once (a lossy path to the name servers).
- **Public resolvers** with client subnet support (Google, Quad9) answer only when ours has no address.
- **`www.<domain>`** is checked when the bare name has no record, which is common for government sites.
- **Resolver counts**: `data/stats.json` → `resolver` counts the domains answered by our own resolver (`own`), a public resolver (`public`) or the last-resort fallback (`fallback`) in the latest build (per domain in a local run's `data/domains.csv`).

### On trial: the regional view

Asked as a client in China, many sites in the other regions do not answer from where they are hosted (geographic DNS sends Chinese users elsewhere), so those regions rely mostly on seeds. Each build also asks their seeds and ccTLD names as a client in their own region (a client subnet of the region's main consumer ISP), through public resolvers that pass the subnet on.

An answer counts only if it is:

- not on a network where global services answer that region's clients,
- not on a global CDN,
- not placed elsewhere by the build,
- not one that follows the asker (a client in another region getting an answer in its own region),

and only after two weeks in a row. Nothing from it is published yet; the results, including how many seeds it finds and whether any global service gets through, are on the quality page and in `data/stats.json` → `local_view`.

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

### Discovery

Two agents add candidates each week.

- **Reverse IP** (HackerTarget, or the ViewDNS API when a key is set): the other domains on the in-region addresses of seed domains, up to 100 a week. The 50 lookups a week are shared between regions, with more than their share for HK, MO, SG and TW, and shared-hosting IPs (20 or more unrelated domains) are skipped.
- **Link crawl**: the links on the home pages of a rotating slice of known sites, up to 500 a week (robots.txt honoured, one request per site). A third of the pages read each week are HK, MO, SG and TW seeds, and regional ccTLDs are queued scarcest region first.

### What is refused

Every candidate is reduced to its registrable name by the [Public Suffix List](https://publicsuffix.org/) (suffix matching covers the subdomains). Refused:

- public suffixes themselves (`com.my`);
- names under free subdomain and hosting services (the list's private section, such as `sakura.ne.jp`);
- adult and gambling sites, and numeric throwaway names.

Global services that answer from in-region edges (found each build through sentinel domains of Google, LinkedIn, Meta and X) are not counted as regional.

### Promotion

A candidate is published only after passing the same checks as the rest, and moves to `extended.txt` after passing in 4 different weeks, however often the build runs. Promotion pauses when `extended.txt` reaches 5,000 domains.

### Provenance

Every domain records how it was first found, in the `origin` column of `domains_metadata.*`: `manual` (curated by hand) or the agent that nominated it (`ip-neighbor`, `link-crawl`, `ct-logs`), with the IP, linking site or query in `origin_detail`.

- Origins of `extended.txt` domains are kept in [`sources/manual/provenance.csv`](../sources/manual/provenance.csv); promotions add to it, and `backfill_provenance.py` rebuilt the history from git.
- Totals: `data/metadata_stats.json` → `by_origin`.
- Domains removed by a later review are logged with the reason in [`sources/manual/removed.csv`](../sources/manual/removed.csv).

Whatever the origin, a domain is published only on this build's own DNS and IP checks.

### Seed review

A seed with no address for 3+ weeks is listed in `data/seed_review.json` if the name no longer exists; CDN and API domains that serve only subdomains are kept apart under `subdomain_only`.

## Schedule

- Every Monday 02:00 UTC: discovery and a full build. Thursday: cache keep-alive.
- Manual runs build only, or also run discovery with `run_agents=yes`. `full_crawl=yes` is a one-off catch-up: link crawl reads every known site's home page in one run (up to 3,000 new candidates) instead of the weekly slice.
