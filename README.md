# DomainNova

> Self-evolving dataset of domains associated with Chinese internet infrastructure, ranked by confidence.

DomainNova is an open intelligence dataset and tooling layer for domain, network, and infrastructure analysis.  
Core data infrastructure, large-scale scanning systems, and attribution engine are not open-sourced.

[![Update](https://github.com/harryheros/domainnova/actions/workflows/update.yml/badge.svg)](https://github.com/harryheros/domainnova/actions/workflows/update.yml)
[![Version](https://img.shields.io/badge/version-v2.0-blue)](https://github.com/harryheros/domainnova/releases/tag/v2.0)

---

## What this is

A **self-evolving intelligence dataset for infrastructure attribution**, not a proxy or filtering ruleset.

Each domain is evaluated across multiple independent signals to assess whether its infrastructure is physically located in mainland China or operated by a Chinese-registered entity. The goal is infrastructure attribution, not corporate ownership attribution.

Unlike static domain lists, DomainNova operates a three-tier data architecture with automated discovery, verification, and lifecycle management. The dataset grows and self-cleanses over time.

---

## Scoring Model

| Signal | Weight | Description |
|--------|--------|-------------|
| `dns_cn` | 60 | Majority of resolved IPs fall within CN CIDR ranges (via [IPNova](https://github.com/harryheros/ipnova)) |
| `registrar_cn` | 20 | Domain registrar is a known Chinese company (RDAP, opt-in) |
| `registrant_cn` | 20 | Registrant country is listed as CN in RDAP (opt-in) |
| `cn_tld` | 10 | Domain uses a Chinese TLD (`.cn` etc.) |

**Thresholds:**

| Score | Meaning | Output |
|-------|---------|--------|
| >= 60 | Strong CN infrastructure evidence | Included in `dist/domains.txt` |
| 40 | CN TLD with ICP filing (CDN may obscure DNS) | Retained in `domains.csv` only |
| < 40 | Insufficient signal | Excluded |

DNS resolution uses **Google DoH with rotating EDNS Client Subnet** (Beijing/Shanghai/Guangdong Telecom + Beijing Unicom) to obtain GeoDNS-accurate results without exposing query traffic to CN DNS infrastructure.

IP classification is performed against [IPNova](https://github.com/harryheros/ipnova)'s APNIC-sourced CN CIDR dataset.

---

## Three-Tier Architecture

```text
┌──────────────────────────────────────────────────┐
│  Core      (seed.txt)       - manually curated   │
│  Reliable  (extended.txt)   - stable + promoted  │
│  Discovery (discovery.txt)  - auto-harvested     │
└──────────────────────────────────────────────────┘
              │ seed > extended > discovery
              ▼
┌──────────────────────────────────────────────────┐
│  Build Pipeline (parallel, 20 workers)           │
│  Google DoH + ECS -> ipnova CIDR match -> score  │
└──────────────────────────────────────────────────┘
              │
      ┌───────┴────────┐
      ▼                ▼
┌─────────────┐  ┌──────────────────────┐
│ dist/       │  │ Discovery Lifecycle  │
│ domains.txt │  │ fail ×2 → purge      │
│ score >= 60 │  │ pass ×4 → promote    │
└─────────────┘  └──────────────────────┘
```

**Discovery capacity limits:**
- Max 2000 domains in `discovery.txt`
- Max 300 domains sampled per weekly build (rotated)
- Auto-promote suspended when `extended.txt` reaches 3000 domains

---

## Discovery Agents

Three agents run monthly to harvest new CN domain candidates:

| Agent | Source | Max per run |
|-------|--------|-------------|
| `agent_upstream_fetch.py` | v2fly domain list, felixonmars dnsmasq-china-list | 200 |
| `agent_ip_neighbor.py` | HackerTarget Reverse IP (fallback: ViewDNS.info) | 100 |
| `agent_ct_logs.py` | crt.sh Certificate Transparency logs | 150 |

All agent output feeds into `discovery.txt` and is verified by the build pipeline before reaching `dist/`.

---

## Files

```text
dist/domains.txt                    plain domain list (score >= 60), updated weekly
data/domains.csv                    full structured database (all signals + score)
data/stats.json                     build statistics and lifecycle counters
data/domains_metadata.json          structured metadata (domain → entity/category/ecosystem)
data/domains_metadata.yaml          YAML export of the metadata layer
data/domains_metadata.csv           tabular export of the metadata layer
data/metadata_stats.json            metadata coverage statistics
data/manual_source_validation.json  duplicate / overlap / format checks
data/discovery_stats.json           discovery lifecycle state (hit/fail counts, offset)
sources/manual/seed.txt             manually curated core domains
sources/manual/extended.txt         stable verified domains + auto-promoted
sources/manual/discovery.txt        auto-harvested candidates (managed lifecycle)
sources/scripts/                    build pipeline scripts
sources/discovery_agents/           discovery agent scripts
```

---

## Data Format

```csv
domain,dns_cn,dns_cn_count,dns_total,registrar_cn,registrant_cn,cn_tld,score,resolved_ips,matched_cidr,source,updated
baidu.com,1,3,3,0,0,0,60,110.242.68.66|...,1.0.1.0/24,seed,2026-03-28
gov.cn,0,0,0,0,0,1,40,,,seed,2026-03-28
```

Key fields:
- `dns_cn` — 1 if majority of resolved IPs are in CN CIDRs
- `matched_cidr` — the CN CIDR range(s) matched (pipe-separated, up to 5)
- `cn_tld` — 1 if domain uses a CN TLD (`.cn`, `.中国`, etc.)
- `score` — composite score; 60+ in dist, 40 = ICP fallback, 0 = excluded
- `source` — `seed`, `extended`, or `discovery`

---

## Update Schedule

| Trigger | Frequency | Action |
|---------|-----------|--------|
| Scheduled | Every Monday 02:00 UTC | Full build pipeline |
| Scheduled | 1st of month 03:00 UTC | Discovery agents + build |
| Manual | On demand | Build only (or agents if `run_agents=yes`) |

---

## Metadata Layer

DomainNova ships with an additive metadata layer derived from curated manual sources.

Each record includes `section`, `ecosystem`, `entity`, and `category` fields for programmatic use.

```bash
# Generate metadata artifacts
python sources/scripts/build_metadata.py --all

# Validate manual source files
python sources/scripts/validate_manual_sources.py
```

---

## Use Cases

- **Traffic filtering / routing** — geo-classify domains by CN infrastructure origin
- **Supply chain / vendor risk** — verify whether dependencies resolve to CN infrastructure
- **OSINT / network intelligence** — identify CN-hosted services in traffic analysis
- **Compliance** — audit exposure to mainland China-hosted services
- **Commercial intelligence** — infrastructure attribution for enterprise and government use

---

## Contributing

To add domains, edit `sources/manual/seed.txt` or `sources/manual/extended.txt` and open a PR.

Discovery candidates are managed automatically — do not edit `sources/manual/discovery.txt` manually.

---

## License

Data: [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) — public domain.  
Scripts: MIT.

This repository contains the public dataset and tooling layer of DomainNova.  
Core data infrastructure, large-scale scanning systems, and attribution engine are not open-sourced.

---

## Related Projects

- [IPNova](https://github.com/harryheros/ipnova) — companion CN IP CIDR dataset (APNIC-sourced)
