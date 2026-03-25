# DomainNova

> Multi-signal dataset for identifying domains hosted on mainland China internet infrastructure, ranked by confidence.

[![Update](https://github.com/harryheros/domainnova/actions/workflows/update.yml/badge.svg)](https://github.com/harryheros/domainnova/actions/workflows/update.yml)

---

## What this is

DomainNova is a **structured data asset**, not a proxy or filtering ruleset.

It focuses on **infrastructure attribution** — determining whether a domain is physically hosted on mainland China network infrastructure, independent of corporate ownership or branding.

---

## Scoring

Domains are evaluated using independent signals, with **physical infrastructure (dns_cn)** as the primary gate.

| Signal | Weight | Description |
|--------|--------|-------------|
| `dns_cn` | 60 | Majority of resolved IPs belong to mainland China ASNs |
| `is_strategic` | 20 | Government or education domains (`.gov.cn`, `.edu.cn`) |
| `registrar_cn` | 10 | Registered via a Chinese registrar |
| `infra_layer` | tag | Core / Premium / Cloud / Edge classification |

- `dns_cn = 1` is **mandatory** — domains without mainland infrastructure are excluded  
- **Score ≥ 60** → included in `dist/domains.txt`  
- Lower-score domains remain in `data/domains.csv` for reference

---

## Files

```
data/domains.csv        structured dataset (all signals + score)
data/stats.json         aggregated statistics
dist/domains.txt        filtered domain list (score ≥ 60)
sources/manual/seed.txt curated seed domains
sources/scripts/        pipeline scripts
```

---

## Data format

`data/domains.csv`:

```
domain,dns_cn,dns_cn_count,dns_total,provider,infra_layer,is_strategic,registrar_cn,registrant_cn,score,resolved_ips,as_org,source,updated
baidu.com,1,3,3,China Mobile,Core,0,0,0,70,110.242.68.66|...,Chinanet HE,seed,2026-03-25
www.miit.gov.cn,1,1,1,Generic_CN,Edge,1,0,0,80,..,,seed,2026-03-25
alibaba.com,0,0,3,,,0,1,0,0,47.246.136.156|...,Alibaba Cloud LLC,seed,2026-03-25
```

---

## Use cases

- **Supply chain / vendor risk** — verify whether dependencies resolve to mainland CN infrastructure  
- **OSINT / network intelligence** — identify CN-hosted services in traffic datasets  
- **Compliance / data residency** — assess exposure to mainland-hosted infrastructure  
- **Traffic analytics** — classify domains by infrastructure geography  

---

## Updates

Automated weekly via GitHub Actions (every Monday).

Pipeline:

1. Expand domain families from seed set  
2. DNS resolution + majority-CN ASN validation  
3. RDAP lookup for registrar / registrant signals  
4. Scoring and export to `dist/`  

---

## Contributing

- Add domains → `sources/manual/seed.txt`  
- Improve expansion logic → `sources/scripts/1_expand.py`  

Pull requests are welcome.

---

## License

Data: [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) — public domain  
Scripts: MIT  

---

## Related projects

- [IPNova](https://github.com/harryheros/ipnova) — companion IP dataset
