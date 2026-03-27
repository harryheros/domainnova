# DomainNova

> Multi-signal dataset of domains associated with Chinese internet infrastructure, ranked by confidence.

[![Update](https://github.com/harryheros/domainnova/actions/workflows/update.yml/badge.svg)](https://github.com/harryheros/domainnova/actions/workflows/update.yml)

---

## What this is

A **data asset**, not a proxy ruleset.

Each domain is evaluated across multiple independent signals to assess whether its infrastructure is physically located in mainland China or operated by a Chinese-registered entity. The goal is infrastructure attribution, not corporate ownership attribution.

| Signal | Weight | Description |
|--------|--------|-------------|
| `dns_cn` | 60 | Majority of resolved IPs belong to a CN ASN |
| `registrar_cn` | 20 | Domain registrar is a known Chinese company |
| `registrant_cn` | 20 | Registrant country is listed as CN in RDAP |
| `cn_tld` | 10 | Domain uses a Chinese TLD (`.cn` etc.) |

**Score >= 60 -> included in `dist/domains.txt`**

A domain scored 60 has strong infrastructure evidence (majority CN IPs).
A domain scored 40 has only registrar/registrant signals but no CN infrastructure - it is retained in `data/domains.csv` for reference but excluded from `dist/`.

---

## Files

```
data/domains.csv            full structured database (all signals + score)
data/stats.json             summary statistics
data/domains_metadata.json   structured metadata layer (domain -> entity/category/ecosystem)
data/domains_metadata.yaml   YAML export of the metadata layer
data/domains_metadata.csv    tabular export of the metadata layer
data/metadata_stats.json     metadata coverage statistics
data/manual_source_validation.json duplicate / overlap / format checks for manual sources
dist/domains.txt            plain domain list (score >= 60), updated weekly
dist/seed_domains.txt       deduplicated seed source set
dist/extended_domains.txt   deduplicated extended-only source set
sources/manual/seed.txt     manually curated seed domains
sources/scripts/            pipeline scripts
```

---

## Data format

`data/domains.csv`:

```
domain,dns_cn,dns_cn_count,dns_total,registrar_cn,registrant_cn,score,resolved_ips,as_org,source,updated
baidu.com,1,3,3,0,0,60,110.242.68.66|...,Chinanet HE,seed,2026-03-25
alibaba.com,0,0,3,1,0,20,47.246.136.156|...,Alibaba Cloud LLC,seed,2026-03-25
```

---


## Metadata layer

DomainNova now ships with an **additive metadata layer** derived from the curated manual sources.
This does **not** change the project into a proxy or routing ruleset. Instead, it preserves the
existing institution/ecosystem-first worldview while making the corpus programmable.

Each metadata record can include:

- `source_set`: `seed` or `extended`
- `section`: the original curated section in `seed.txt`
- `ecosystem`: normalized ecosystem slug
- `category`: infrastructure / institutional category
- `entity`: best-effort entity anchor
- `confidence`: `high` for seed, `candidate` for extended

Generate metadata artifacts:

```bash
python sources/scripts/build_metadata.py --all
```

Validate the manual source lists:

```bash
python sources/scripts/validate_manual_sources.py
```

## Use cases

- **Supply chain / vendor risk**: verify whether a dependency resolves to CN infrastructure
- **OSINT / network intelligence**: identify CN-hosted services in traffic analysis
- **Ad/traffic analytics**: geo-classify domains by infrastructure origin
- **Compliance**: audit exposure to mainland China-hosted services

---

## Updates

Automated weekly via GitHub Actions every Monday. The pipeline:

1. Expands known brand domain families
2. Resolves DNS and checks majority-CN ASN
3. Queries RDAP for registrar and registrant signals
4. Scores each domain and outputs `dist/`

---

## Contributing

To add domains: edit `sources/manual/seed.txt` and open a PR.
To add a brand family cluster: edit `sources/scripts/1_expand.py`.

---

## License

Data: [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) - public domain.
Scripts: MIT.

---

## Related projects

- [IPNova](https://github.com/harryheros/ipnova) - companion IP dataset
