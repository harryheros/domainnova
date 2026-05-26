# DomainNova P2.A Multi-Region Score Model Specification v1.0

> **v1.1 update (2026-04)**: model extended to JP/KR/SG; all symmetric
> signal logic applies equally to the new regions.

> Status: Implemented · 2026-04-21
> Prerequisite: P1 v1.1 + P1 fix v2.1 deployed (symmetric bucketing,
> symmetric thresholds, sticky repair).
> Scope: `sources/scripts/build_domains.py`, `sources/scripts/constants.py`.
> Goal: let extended/discovery domains qualify for HK/MO/TW buckets
> automatically based on IP signals, without requiring manual seeding.

---

## 1. Problem Statement

P1 introduced symmetric bucketing and thresholds, but `score_record()`'s
signal inputs only encoded CN signals. HK/MO/TW domains whose IPs landed
in the corresponding IPNova region still scored 0 and could never enter
the dist files.

## 2. Design Decisions

### 2.1 Symmetric signal model

Each bucket computes its own boolean signal independently:
`dns_cn / dns_hk / dns_mo / dns_tw` + `cn_tld / hk_tld / mo_tld / tw_tld`.

### 2.2 Asymmetric TLD fallback

| Region | TLD fallback | Rationale |
|---|---|---|
| CN | yes (score = 60) | `.cn` requires ICP filing; TLD is a strong administrative signal |
| HK/MO/TW | no | No equivalent compulsory filing regime |

### 2.3 Signal weights

`DNS_WEIGHT = 60`, `CN_TLD_WEIGHT = 10`, `XX_TLD_WEIGHT = 20`,
`CN_TLD_FALLBACK_SCORE = 60`. `INCLUDE_THRESHOLD` stays at 60
symmetrically across all buckets.

### 2.4 No registrar / registrant signal (P3 scope)

These are deferred to a later milestone.

### 2.5 Seed-force unchanged (`score = 100` override)

Manually-curated seed entries continue to bypass IP-based scoring.

## 3. Technical Changes

- `DomainRecord` gains three fields: `dns_hk`, `dns_mo`, `dns_tw`.
- `build_region_signals` returns a `region_dns_flags` dict.
- New pure function `score_record_for_bucket(bucket, dns_flag, tld_flag)`.
- `score_record` is now a backward-compatible wrapper around the per-bucket
  version.
- `process_domain` computes the score against its assigned bucket.
- New helper `_tld_flag_for_bucket`.
- CSV gains three columns; `load_previous_rows` has a fallback for older
  CSVs without these columns.

## 4. Testing

- `test_p2a_score.py`: equivalence guarantees, four-bucket scoring,
  `process_domain` integration, CSV compatibility.
- All pre-existing tests continue to pass.

## 5. Measured Results (2026-04-21)

The first P2.A run automatically promoted 17 Taiwanese domains into
`dist/domains_tw.txt` without manual seeding. 36 non-seed HK domains also
auto-qualified. CN behaviour is byte-identical to the pre-P2.A baseline.
