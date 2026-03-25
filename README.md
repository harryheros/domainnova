# DomainNova

> A structured, multi-signal database of domains operated by Chinese internet entities.

[![Update](https://github.com/harryheros/domainnova/actions/workflows/update.yml/badge.svg)](https://github.com/harryheros/domainnova/actions/workflows/update.yml)

---

## What this is

A **data asset**, not a proxy ruleset.

Each domain is evaluated across multiple signals to determine whether it is operated by a Chinese entity — meaning the infrastructure, registrant, or organization behind it is based in mainland China.

| Signal | Weight | Description |
|--------|--------|-------------|
| `dns_cn` | 60 | DNS resolves to a mainland China IP (by ASN) |
| `whois_cn` | 30 | Registrar or registrant is a Chinese entity |
| `cn_tld` | 10 | Domain uses a Chinese TLD (`.cn`, `.中国`, etc.) |

**Score ≥ 60 → included in `dist/domains.txt`**

---

## Files

```
data/domains.csv            full structured database (domain + all signals + score)
data/stats.json             summary statistics
dist/domains.txt            plain domain list (score >= 60), updated weekly
sources/manual/seed.txt     manually curated seed domains
sources/scripts/            pipeline scripts
```

---

## Data format

`data/domains.csv`:

```
domain,dns_cn,whois_cn,score,resolved_ips,as_org,source,updated
baidu.com,1,1,90,220.181.38.148,...,AS23724 IDC...,seed,2025-03-01
github.com,0,0,0,...,...,seed,2025-03-01
```

---

## Use cases

- **Supply chain / vendor risk**: check if a software dependency resolves to CN infrastructure
- **OSINT / network intelligence**: identify Chinese-operated services in traffic analysis
- **Ad/traffic analytics**: geo-classify domains by operator origin, not just IP
- **Compliance**: audit network assets for Chinese infrastructure exposure

---

## Updates

Automated weekly via GitHub Actions every Monday. The pipeline:

1. Expands known brand domain families
2. Resolves DNS and maps IPs to ASNs
3. Queries RDAP/WHOIS for registrar origin
4. Scores each domain and outputs `dist/`

---

## Contributing

To add domains: edit `sources/manual/seed.txt` and open a PR.  
To add a brand family cluster: edit `sources/scripts/1_expand.py`.

---

## License

Data: [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) — public domain.  
Scripts: MIT.

---

## Related projects

- [IPNova](https://github.com/harryheros/ipnova) — companion IP dataset
