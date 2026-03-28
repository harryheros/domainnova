# DomainNova

> Multi-signal dataset of domains associated with Chinese internet infrastructure, ranked by confidence.

[![Update](https://github.com/harryheros/domainnova/actions/workflows/update.yml/badge.svg)](https://github.com/harryheros/domainnova/actions/workflows/update.yml)

---

## What this is

A **data asset**, not a proxy ruleset.

Each domain is evaluated across multiple independent signals to assess whether its infrastructure is physically located in mainland China or operated by a Chinese-registered entity. The goal is infrastructure attribution, not corporate ownership attribution.

| Signal | Weight | Description |
|--------|--------|-------------|
| `dns_cn` | 60 | Majority of resolved IPs fall within CN CIDR ranges (via [IPNova](https://github.com/harryheros/ipnova)) |
| `registrar_cn` | 20 | Domain registrar is a known Chinese company (RDAP, opt-in) |
| `registrant_cn` | 20 | Registrant country is listed as CN in RDAP (opt-in) |
| `cn_tld` | 10 | Domain uses a Chinese TLD (`.cn` etc.) |

**Score >= 60 -> included in `dist/domains.txt`**

A domain scored 60 has strong infrastructure evidence (majority CN IPs).
A domain scored 40 has only registrar/registrant signals but no CN infrastructure — it is retained in `data/domains.csv` for reference but excluded from `dist/`.

DNS resolution uses **Google DoH with EDNS Client Subnet** (`114.114.114.0/24`) to obtain GeoDNS-accurate results. IP classification is performed against IPNova's APNIC-sourced CN CIDR dataset.

---

## Files

```
data/domains.csv                    full structured database (all signals + score)
data/stats.json                     summary statistics
data/domains_metadata.json          structured metadata layer (domain -> entity/category/ecosystem)
data/domains_metadata.yaml          YAML export of the metadata layer
data/domains_metadata.csv           tabular export of the metadata layer
data/metadata_stats.json            metadata coverage statistics
data/manual_source_validation.json  duplicate / overlap / format checks for manual sources
dist/domains.txt                    plain domain list (score >= 60), updated weekly
sources/manual/seed.txt             manually curated seed domains
sources/manual/extended.txt         extended candidate domains
sources/scripts/                    pipeline scripts
```

---

## Data format

`data/domains.csv`:

```
domain,dns_cn,dns_cn_count,dns_total,registrar_cn,registrant_cn,cn_tld,score,resolved_ips,matched_cidr,source,updated
baidu.com,1,3,3,0,0,0,60,110.242.68.66|...,1.0.1.0/24,seed,2026-03-27
alibaba.com,1,2,2,0,0,0,60,47.246.136.156|...,1.0.2.0/23,seed,2026-03-27
```

Key fields:
- `dns_cn` — 1 if majority of resolved IPs are in CN CIDRs
- `matched_cidr` — the CN CIDR range(s) that matched (pipe-separated, up to 5)
- `score` — composite score; >= 60 means included in dist/

---

## Metadata layer

DomainNova ships with an **additive metadata layer** derived from the curated manual sources.

Each metadata record includes:

- `section`: the original curated section in `seed.txt`
- `ecosystem`: normalized ecosystem slug (e.g. `alibaba`, `tencent`)
- `category`: infrastructure / institutional category
- `entity`: best-effort entity anchor

Generate metadata artifacts:

```bash
python sources/scripts/build_metadata.py --all
```

Validate the manual source lists:

```bash
python sources/scripts/validate_manual_sources.py
```

---

## Use cases

- **Supply chain / vendor risk**: verify whether a dependency resolves to CN infrastructure
- **OSINT / network intelligence**: identify CN-hosted services in traffic analysis
- **Traffic filtering / routing**: geo-classify domains by infrastructure origin
- **Compliance**: audit exposure to mainland China-hosted services

---

## Updates

Automated weekly via GitHub Actions every Monday. The pipeline:

1. Fetches CN CIDR list from [IPNova](https://github.com/harryheros/ipnova)
2. Resolves DNS via Google DoH + EDNS Client Subnet (GeoDNS-accurate, no plain-text leakage)
3. Classifies IPs against CN CIDRs
4. Optionally queries RDAP for registrar/registrant signals (`DOMAINNOVA_RDAP=1`)
5. Scores each domain and outputs `dist/`

---

## Contributing

To add domains: edit `sources/manual/seed.txt` or `sources/manual/extended.txt` and open a PR.

---

## License

Data: [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) — public domain.
Scripts: MIT.

---

## Related projects

- [IPNova](https://github.com/harryheros/ipnova) — companion CN IP CIDR dataset
