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
dist/domains.txt            plain domain list (score >= 60), updated weekly
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
