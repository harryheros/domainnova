# DomainNova

> Self-evolving dataset of domains associated with Asia-Pacific internet infrastructure, ranked by confidence.

DomainNova is an open intelligence dataset and tooling layer for domain, network, and infrastructure analysis across the Asia-Pacific region.

[![Update](https://github.com/harryheros/domainnova/actions/workflows/update.yml/badge.svg)](https://github.com/harryheros/domainnova/actions/workflows/update.yml)
[![Version](https://img.shields.io/badge/version-v3.1-blue)](https://github.com/harryheros/domainnova/releases/tag/v3.0)

---

## What this is

A **self-evolving intelligence dataset for infrastructure attribution**, not a proxy or filtering ruleset.

Each domain is evaluated across multiple independent signals to assess whether its infrastructure is physically located in a target Asia-Pacific region. The goal is infrastructure attribution, not corporate ownership attribution.

Unlike static domain lists, DomainNova operates a three-tier data architecture with automated discovery, verification, and lifecycle management. The dataset grows and self-cleanses over time.

---

## Scoring Model

DomainNova uses a **symmetric multi-region scoring model** (P2.A) that evaluates domains independently for each target region (CN, HK, MO, TW, JP, KR, SG).

### Per-Region Signals

| Signal | Weight | Description |
|--------|--------|-------------|
| `dns_xx` | 60 | ≥60% of resolved IPs fall within the region's CIDR ranges (via [IPNova](https://github.com/harryheros/ipnova)) |
| `xx_tld` | 20 | Domain uses a region-specific TLD (`.hk`, `.mo`, `.tw`) — bonus only when `dns_xx=1` |
| `cn_tld` | 10 | Domain uses `.cn` TLD — bonus when `dns_cn=1` |
| `cn_tld` fallback | 60 | `.cn` domains without DNS signal still score 60 (ICP filing is a strong administrative signal) |

> **Asymmetry note**: Only `.cn` has a TLD-only fallback path (score=60 without DNS confirmation). `.hk`, `.mo`, `.tw` TLDs do **not** trigger fallback because they lack an ICP-equivalent mandatory filing system. This reflects real-world signal strength differences, not an implementation shortcut.

### Output Files

| File | Contents |
|------|----------|
| `dist/domains_cn.txt` | Mainland China domains (score ≥ 60) |
| `dist/domains_hk.txt` | Hong Kong domains (score ≥ 60) |
| `dist/domains_tw.txt` | Taiwan domains (score ≥ 60) |
| `dist/domains_mo.txt` | Macau domains (score ≥ 60) |
| `dist/domains_jp.txt` | Japan domains (score ≥ 60) |
| `dist/domains_kr.txt` | South Korea domains (score ≥ 60) |
| `dist/domains_sg.txt` | Singapore domains (score ≥ 60) |

**Thresholds:**

| Score | Meaning | Output |
|-------|---------|--------|
| >= 60 | Strong infrastructure evidence | Included in `dist/domains_{region}.txt` |
| 40 | CN TLD with ICP filing (CDN may obscure DNS) | Retained in `domains.csv` only |
| < 40 | Insufficient signal | Excluded |

DNS resolution uses **Google DoH with rotating EDNS Client Subnet** (Beijing/Shanghai/Guangdong Telecom + Beijing Unicom) to obtain GeoDNS-accurate results without exposing query traffic to CN DNS infrastructure.

IP classification is performed against [IPNova](https://github.com/harryheros/ipnova)'s APNIC-sourced Asia-Pacific CIDR dataset.

---

## Three-Tier Architecture

```text
┌──────────────────────────────────────────────────┐
│  Core      (seed_{region}.txt) - manually curated│
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
│ domains_xx  │  │ fail ×2 → purge      │
│ score >= 60 │  │ pass ×4 → promote    │
└─────────────┘  └──────────────────────┘
```

**Discovery capacity limits:**
- Max 2000 domains in `discovery.txt`
- Max 300 domains sampled per weekly build (rotated)
- Auto-promote suspended when `extended.txt` reaches 3000 domains

---

## Discovery Agents

Three agents run monthly to harvest new domain candidates:

| Agent | Source | Max per run |
|-------|--------|-------------|
| `agent_upstream_fetch.py` | v2fly domain list, felixonmars dnsmasq-china-list | 200 |
| `agent_ip_neighbor.py` | HackerTarget Reverse IP (fallback: ViewDNS.info) | 100 |
| `agent_ct_logs.py` | crt.sh Certificate Transparency logs | 150 |

All agent output feeds into `discovery.txt` and is verified by the build pipeline before reaching `dist/`.

---

## Files

```text
dist/domains_cn.txt                 CN domain list (score >= 60), updated weekly
dist/domains_hk.txt                 HK domain list (score >= 60)
dist/domains_tw.txt                 TW domain list (score >= 60)
dist/domains_mo.txt                 MO domain list (score >= 60)
dist/domains_jp.txt                 JP domain list (score >= 60)
dist/domains_kr.txt                 KR domain list (score >= 60)
dist/domains_sg.txt                 SG domain list (score >= 60)
data/domains.csv                    full structured database (all signals + score)
data/stats.json                     build statistics and lifecycle counters
data/domains_metadata.json          structured metadata (domain → entity/category/ecosystem)
data/domains_metadata.yaml          YAML export of the metadata layer
data/domains_metadata.csv           tabular export of the metadata layer
data/metadata_stats.json            metadata coverage statistics
data/manual_source_validation.json  duplicate / overlap / format checks
data/discovery_stats.json           discovery lifecycle state (hit/fail counts, offset)
sources/manual/seed_cn.txt             manually curated core domains (CN)
sources/manual/seed_hk.txt             manually curated core domains (HK)
sources/manual/seed_tw.txt             manually curated core domains (TW)
sources/manual/seed_mo.txt             manually curated core domains (MO)
sources/manual/seed_jp.txt             manually curated core domains (JP)
sources/manual/seed_kr.txt             manually curated core domains (KR)
sources/manual/seed_sg.txt             manually curated core domains (SG)
sources/manual/seed_offshore.txt       offshore PRC-company domains
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

- **Traffic filtering / routing** — geo-classify domains by regional infrastructure origin
- **Supply chain / vendor risk** — verify whether dependencies resolve to specific regional infrastructure
- **OSINT / network intelligence** — identify regionally-hosted services in traffic analysis
- **Compliance** — audit exposure to specific jurisdiction-hosted services
- **Commercial intelligence** — infrastructure attribution for enterprise and government use

---

## Contributing

To add domains, edit the appropriate `sources/manual/seed_{region}.txt` or `sources/manual/extended.txt` and open a PR.

Discovery candidates are managed automatically — do not edit `sources/manual/discovery.txt` manually.

---

## License

Data: [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) — public domain.  
Scripts: MIT.

---

## Nova Toolkit

DomainNova is part of the Nova infrastructure toolkit:

| Project | Layer | Description |
|---|---|---|
| [IPNova](https://github.com/harryheros/ipnova) | IP | Routing-aware IPv4 dataset for Asia-Pacific infrastructure classification and traffic control |
| **DomainNova** | **Domain (Data)** | **High-precision domain dataset for proxy routing and network intelligence** |
| [ShieldNova](https://github.com/harryheros/shieldnova) | Domain (Filter) | Compatibility-first domain intelligence for privacy, ad blocking, security and traffic routing |
| [HarryWrt](https://github.com/harryheros/harrywrt) | Device | Clean OpenWrt-based firmware for x86_64 and aarch64 (BIOS & UEFI) |
| [OSNova](https://github.com/harryheros/osnova) | System | System deployment and reinstallation engine for VPS and bare-metal servers |
---

Part of the [Nova infrastructure toolkit](https://github.com/harryheros).
