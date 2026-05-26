# DomainNova Multi-Region Specification v1.1 (P1)

> Status: P1 specification finalized at v1.1, revised.
> Scope: `sources/scripts/build_domains.py`,
>        `sources/scripts/constants.py`,
>        `sources/manual/seed_*.txt`, `dist/`.
>
> **Changes vs v1.0:**
> - Dropped the `dist/domains.txt` alias — no external consumers, pure
>   overhead.
> - CIDR data source switched to `harryheros/ipnova`'s four regional files.
> - Dropped `HK_ASNS` / `TW_ASNS` / `MO_ASNS` — IPNova is a more
>   authoritative APNIC-derived dataset.
> - Simplified `decide_bucket` signature to `(domain, source, ip_buckets, dns_cn)`.
> - Sticky cache adopts Option B: in-memory only, no persistence.
>
> Default decisions: mutually-exclusive bucketing, four-file output,
> no alias, IPNova consumed from main branch, sanity-line-count fuse.

---

## 1. Goal

Extend the output from a single CN list to four mutually-exclusive
regional buckets (CN/HK/MO/TW), backed by the IPNova multi-region
CIDR dataset. The existing CN pipeline behaviour is **byte-identical**
to the pre-change baseline.

---

## 2. Mutually Exclusive Bucket Model

### 2.1 Bucket definitions

| Bucket | Code | Primary signal | Jurisdiction |
|---|---|---|---|
| Mainland China | `CN` | IP ∈ ipnova/CN.txt | PRC Cyberlaw |
| Hong Kong      | `HK` | IP ∈ ipnova/HK.txt | PDPO |
| Macau          | `MO` | IP ∈ ipnova/MO.txt | Macau PDPA |
| Taiwan         | `TW` | IP ∈ ipnova/TW.txt | Taiwan PDPA |
| Unclassified   | `""` | Kept only in CSV; never written to any dist file | — |

### 2.2 Decision tree (top-down, first match wins)

1. **Seed forcing**: domains from `seed_hk.txt` / `seed_mo.txt` /
   `seed_tw.txt` go to their respective buckets. `seed_cn.txt` (CN)
   is **not** forced and still goes through voting.
2. **Resolution failure**: no IPs → caller may apply sticky to carry
   forward the previous bucket; otherwise `""`.
3. **Per-IP voting**: each IP is classified via `ip_to_bucket` against
   the four IPNova CIDR lookups, yielding `"CN"|"HK"|"MO"|"TW"|""`.
4. **`dns_cn` boost**: `dns_cn=1` (CN-CIDR majority ≥ 60%) adds +2 votes
   to the CN bucket.
5. **TLD vote**: `.cn` / `.hk` / `.mo` / `.tw` adds +1 vote to the
   matching bucket.
6. **Majority + tie-break**: highest vote wins; ties broken in the
   order `CN > HK > MO > TW`.

The four IPNova tables are mutually exclusive by APNIC delegation, so
per-IP lookups should not hit multiple buckets. `ip_to_bucket` still
checks in the order `CN > HK > MO > TW` as a defensive fallback.

### 2.3 Scoring

The `score` field semantics are unchanged; `score_record` is unchanged.
A new field `bucket: str = ""` is added to `DomainRecord`.
`INCLUDE_THRESHOLD` is applied per bucket independently.

---

## 3. IPNova Data Source Integration

### 3.1 URL

```
https://raw.githubusercontent.com/harryheros/ipnova/main/output/plain/{CN,HK,MO,TW}.txt
```

We track the `main` branch directly because IPNova is a self-owned repo;
there is no supply-chain risk that would warrant tag pinning.

### 3.2 Fetch and sanity check

`fetch_region_cidrs(session) -> dict[str, list[IPv4Network]]`:

1. Fetches each bucket sequentially (4 HTTP calls).
2. After each successful fetch, line-count check:
   - **lines ≥ per-bucket minimum** → parsed into `IPv4Network` list,
     counted into the result.
   - **lines < minimum** → log WARN ("ipnova {bucket}.txt anomaly:
     {n} lines, treating as empty"); the bucket is degraded to an
     empty list.
   - **HTTP failure** → log WARN; bucket degraded to empty.
3. Any single-bucket degradation does not abort the build. A CN
   degradation logs ERROR (largest impact on the existing pipeline).

Sticky cache policy: Option B, in-memory only, no persistence.
Degraded buckets recover on the next build run automatically.
CI runs daily, so single-run degradation has limited blast radius.

### 3.3 Lookup structure

```python
RegionLookup = dict[str, dict]  # bucket -> CIDR octet-keyed lookup
                                #          (same shape as build_cidr_lookup)

def build_region_lookup(region_cidrs) -> RegionLookup: ...
def ip_to_bucket(ip_str, region_lookup) -> str: ...
# returns "CN" | "HK" | "MO" | "TW" | ""
```

`ip_to_bucket` checks buckets in `CN > HK > MO > TW` order; first match
returns immediately.

---

## 4. Seed Health Check

### 4.1 Mechanism

Before each build, `seed_health_check(repo_root, region_lookup)`:

1. Samples `min(20, len)` random domains from each of `seed_cn.txt` /
   `seed_hk.txt` / `seed_mo.txt` / `seed_tw.txt`.
2. Resolves each sample using the existing DoH path, taking the first
   A record only.
3. Tags the resolved IP via `ip_to_bucket`.
4. Computes self-consistency rate = (tagged region == file's claimed
   region) / sample size.
5. **Alert**: < 0.6 → WARN; < 0.3 → ERROR. Never aborts the build.
6. Writes results to `data/seed_health.json`.

### 4.2 Output format

```json
{
  "checked_at": "2026-04-11T12:00:00Z",
  "results": {
    "seed_cn.txt": {"region": "CN", "sampled": 20, "consistent": 19, "rate": 0.95,  "status": "ok"},
    "seed_hk.txt": {"region": "HK", "sampled": 8,  "consistent": 7,  "rate": 0.875, "status": "ok"},
    "seed_mo.txt": {"region": "MO", "sampled": 5,  "consistent": 5,  "rate": 1.0,   "status": "ok"},
    "seed_tw.txt": {"region": "TW", "sampled": 5,  "consistent": 2,  "rate": 0.4,   "status": "warn"}
  }
}
```

`status ∈ {ok, warn, error, skipped}`; `skipped` is used when the
file has fewer than 3 domains or all samples failed to resolve.
The check is advisory only — it never modifies seed files automatically.

---

## 5. Parallel Four-File Output

### 5.1 dist/ structure

```
dist/
├── domains_cn.txt     # Mainland China
├── domains_hk.txt     # Hong Kong
├── domains_mo.txt     # Macau
└── domains_tw.txt     # Taiwan
```

**`dist/domains.txt` is removed.** CI workflow and consumers must update
accordingly.

### 5.2 Write rules

`write_dist_buckets(dist_dir, rows)`: for each `b ∈ {CN, HK, MO, TW}`,
filter `r.bucket == b ∧ r.score >= INCLUDE_THRESHOLD`, sort
alphabetically by domain, write to `domains_{b.lower()}.txt`. Empty
buckets still emit a header-only file to prevent subscriber 404s.

### 5.3 stats.json extension

```json
{
  "buckets": {
    "cn": {"included": 1234, "gray": 50, "total": 1300},
    "hk": {"included": 42,   "gray": 3,  "total": 50},
    "mo": {"included": 5,    "gray": 0,  "total": 5},
    "tw": {"included": 18,   "gray": 2,  "total": 22},
    "unclassified": 7
  }
}
```

The `dist_domains` field persists for backward compatibility with old
dashboards, but its semantics change to "sum of all four buckets'
included counts".

---

## 6. constants.py Changes

```python
# Removed: HK / MO / TW are no longer negative signals globally.
NON_MAINLAND_REGIONS = ["US","JP","SG","KR","DE","GB","NL","AU","CA","FR"]

# Added: bucket set
REGION_BUCKETS = {"CN", "HK", "MO", "TW"}

# Added: IPNova multi-region CIDR sources
IPNOVA_BASE = "https://raw.githubusercontent.com/harryheros/ipnova/main/output"
REGION_CIDR_URLS = {
    "CN": f"{IPNOVA_BASE}/plain/CN.txt",
    "HK": f"{IPNOVA_BASE}/plain/HK.txt",
    "MO": f"{IPNOVA_BASE}/plain/MO.txt",
    "TW": f"{IPNOVA_BASE}/plain/TW.txt",
}

# TLD → bucket vote
TLD_TO_BUCKET = {".cn": "CN", ".hk": "HK", ".mo": "MO", ".tw": "TW"}

# Line-count sanity fuse
IPNOVA_MIN_LINES = 50
```

**Deleted**: `HK_ASNS` / `TW_ASNS` / `MO_ASNS` / `COUNTRY_TO_BUCKET`
(drafted in v1.0, all removed in v1.1). `CN_BACKBONE` /
`CN_CLOUD_ASNS` / `INFRA_KEYWORDS` are untouched.

---

## 7. build_domains.py Change Surface

| Function | Change |
|---|---|
| `DomainRecord` | New `bucket: str = ""` ✓ (Step 2 complete) |
| `decide_bucket` | Pure function with signature `(domain, source, ip_buckets, dns_cn) -> str` ✓ (Step 3 complete; awaiting Step 4 signature simplification) |
| `fetch_cn_cidrs` | Refactored into `fetch_region_cidrs() -> dict[str, list[IPv4Network]]` with sanity check |
| `build_cidr_lookup` | Unchanged; new `build_region_lookup` wraps per-bucket |
| `ip_in_cn_cidrs` | Renamed `ip_in_cidrs(ip, lookup)`; new `ip_to_bucket(ip, region_lookup)` |
| `build_dns_signal` | Refactored into `build_region_signals(ips, region_lookup)` returning `(per_ip_buckets, dns_cn, dns_total, matched)` |
| `process_domain` | Calls `decide_bucket(domain, source, per_ip_buckets, dns_cn)`; bucket written into record |
| `score_record` | Completely unchanged |
| `write_dist` | Refactored into `write_dist_buckets` |
| `write_stats` | Adds `buckets` section |
| `build` | Calls `seed_health_check` at start; calls `write_dist_buckets` at end; no longer writes `domains.txt` |
| `load_previous_rows` | bucket read-back added ✓ (Step 2 complete) |
| Sticky | bucket and score are carried forward together |

---

## 8. Tests and Acceptance

1. **Regression**: `domains_cn.txt` entry count ≥ 95% of the old
   `domains.txt`.
2. **Mutual exclusivity**: pairwise intersection of the four files is
   empty.
3. **Seed health**: CN self-consistency rate ≥ 0.9.
4. **Empty bucket produces a file**: temporarily empty `seed_mo.txt`,
   run a build, confirm `domains_mo.txt` is produced (header only).
5. **Sanity fuse**: temporarily point `REGION_CIDR_URLS["HK"]` at a
   non-existent URL; the HK bucket must degrade to empty and the
   build must not abort.
6. **stats parity**: `stats.json.buckets.cn.included` must equal
   non-comment line count of `domains_cn.txt`.

---

## 9. Out of P1 Scope

- ❌ Region-aware discovery agents (deferred to P2)
- ❌ HK/MO/TW ICP-equivalent ground truth (deferred to P2)
- ❌ IPv6 (existing limitation retained)
- ❌ Persistent sticky cache Option A (decided not to adopt)

---

## 10. Change Impact Table

| File | Action | Risk |
|---|---|---|
| `docs/PROPOSAL_MULTI_REGION.md` | v1.1 rewrite | none |
| `sources/scripts/constants.py` | Split NON_MAINLAND_REGIONS; add REGION_BUCKETS / REGION_CIDR_URLS / TLD_TO_BUCKET / IPNOVA_MIN_LINES | low |
| `sources/scripts/build_domains.py` | IPNova multi-region integration; simplify `decide_bucket` signature; refactor `process_domain` / `write_dist` | medium |
| `sources/manual/seed_*.txt` | Unchanged | none |
| `dist/domains.txt` | **Deleted** | medium (CI workflow + consumers need updating) |
| `dist/domains_{cn,hk,mo,tw}.txt` | Added | none |
| `data/seed_health.json` | Added | none |
| `.github/workflows/update.yml` | commit paths updated to `dist/domains_*.txt`; add `data/seed_health.json` | low |
| `sources/scripts/test_decide_bucket.py` | Signature change, full rewrite | none |

---

## 11. Implementation Order (v1.1)

1. ✅ constants.py split + bucket set (Step 1 complete; pending v1.1
   additions of REGION_CIDR_URLS / IPNOVA_MIN_LINES)
2. ✅ DomainRecord gains `bucket` (Step 2 complete)
3. ✅ `decide_bucket` pure function + unit tests (Step 3 complete;
   v1.1 signature simplification and test rewrite)
4. **Step 4**: `fetch_region_cidrs` / `build_region_lookup` /
   `ip_to_bucket` / sanity fuse
5. **Step 5**: `build_region_signals` + `process_domain` integration
6. **Step 6**: `write_dist_buckets` + remove `domains.txt`
7. **Step 7**: `seed_health_check`
8. **Step 8**: `write_stats` extension
9. **Step 9**: CI workflow commit-path update
10. **Step 10**: full build run + acceptance verification

---

_Document version: v1.1, specification finalized._
