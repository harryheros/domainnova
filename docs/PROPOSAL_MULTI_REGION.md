# DomainNova 多地區改造規範書 v1.1（P1）

> 狀態：P1 規範定稿 v1.1 ‧ 已修訂
> 範圍：`sources/scripts/build_domains.py`、`sources/scripts/constants.py`、`sources/manual/seed_*.txt`、`dist/`
>
> **v1.1 變更（vs v1.0）**：
> - 砍掉 `dist/domains.txt` alias（無外部消費者，alias 純 overhead）
> - CIDR 數據源切換為 `harryheros/ipnova` 的 4 個地區檔案
> - 砍掉 `HK_ASNS`/`TW_ASNS`/`MO_ASNS`（ipnova 是更權威的 APNIC 衍生數據）
> - `decide_bucket` 簽名簡化為 `(domain, source, ip_buckets, dns_cn)`
> - sticky cache 採方案 B：純記憶體、不持久化
>
> 預設決策：互斥分桶 / 四檔輸出 / 無 alias / ipnova 用 main 分支 / sanity 保險絲

---

## 1. 目標

將輸出維度從單一 CN 名單擴展為 CN/HK/MO/TW 四個互斥地區桶，並接入 ipnova 多地區 CIDR 數據源。既有 CN pipeline 行為**位元組級保持**。

---

## 2. 互斥分桶模型

### 2.1 桶定義

| 桶 | 代號 | 主信號 | 司法管轄 |
|---|---|---|---|
| 中國大陸 | `CN` | IP ∈ ipnova/CN.txt | PRC Cyberlaw |
| 香港 | `HK` | IP ∈ ipnova/HK.txt | PDPO |
| 澳門 | `MO` | IP ∈ ipnova/MO.txt | Macau PDPA |
| 台灣 | `TW` | IP ∈ ipnova/TW.txt | Taiwan PDPA |
| 未分類 | `""` | 不寫入任何 dist 檔，僅保留於 CSV | — |

### 2.2 決策樹（由上而下首次命中即定案）

1. **Seed 強制**：domain 來自 `seed_hk.txt` / `seed_mo.txt` / `seed_tw.txt` → 對應桶。`seed_cn.txt`（CN）**不**強制，仍須走投票。
2. **解析失敗**：無 IP → 由呼叫端套 sticky 沿用上輪 bucket，否則 `""`。
3. **per-IP 投票**：每個 IP 用 `ip_to_bucket` 查 4 張 ipnova CIDR 表，得到 `"CN"|"HK"|"MO"|"TW"|""`。
4. **dns_cn 加權**：`dns_cn=1`（CN CIDR ≥60% 命中）→ CN 桶 +2 票。
5. **TLD 加權**：`.cn/.hk/.mo/.tw` → 對應桶 +1 票。
6. **多數決 + 平票破除**：最高票勝出；平票按 `CN > HK > MO > TW` 字面順序。

ipnova 4 張表理論上互斥（APNIC delegation），所以 per-IP 結果不會同時命中多桶。`ip_to_bucket` 仍按 `CN > HK > MO > TW` 順序檢查作為防禦性兜底。

### 2.3 評分

`score` 欄位語意不變、`score_record` 不動。新增 `bucket: str = ""`。`INCLUDE_THRESHOLD` 在每桶內獨立判定。

---

## 3. ipnova 數據源接入

### 3.1 URL

```
https://raw.githubusercontent.com/harryheros/ipnova/main/output/{CN,HK,MO,TW}.txt
```

用 `main` 分支：ipnova 為自有 repo，無供應鏈風險。

### 3.2 Fetch 與 sanity check

`fetch_region_cidrs(session) -> dict[str, list[IPv4Network]]`：

1. 對每個 bucket 順序 fetch（4 次 HTTP）
2. 每個檔案 fetch 成功後檢查行數：
   - **行數 ≥ 50** → 解析為 IPv4Network 列表，計入結果
   - **行數 < 50** → log WARN「ipnova {bucket}.txt 異常: {n} lines, treating as empty」，該桶降級為空 list
   - **HTTP 失敗** → log WARN，該桶降級為空 list
3. 任一桶降級不中斷 build；CN 桶降級時警示為 ERROR（因為對既有 pipeline 影響最大）

sticky cache 策略：方案 B，純記憶體、不持久化。本輪降級的桶在下一輪 build 重試自動恢復；CI 是 daily 故單輪降級影響有限。

### 3.3 lookup 結構

```python
RegionLookup = dict[str, dict]  # bucket -> CIDR octet-keyed lookup (既有 build_cidr_lookup 結構)

def build_region_lookup(region_cidrs) -> RegionLookup: ...
def ip_to_bucket(ip_str, region_lookup) -> str: ...  # 回傳 "CN"|"HK"|"MO"|"TW"|""
```

`ip_to_bucket` 按 `CN > HK > MO > TW` 順序查表，首次命中即返回。

---

## 4. Seed 健康檢查

### 4.1 機制

每次 build 開始前 `seed_health_check(repo_root, region_lookup)`：

1. 對 `seed_cn.txt` / `seed_hk.txt` / `seed_mo.txt` / `seed_tw.txt`，隨機抽 `min(20, len)` 條
2. 對抽樣 domain 執行一次輕量解析（沿用既有 DoH，僅取首個 A 記錄）
3. 用 `ip_to_bucket` 打標籤
4. 統計自洽率 = (標籤 == 檔名地區) / 樣本數
5. **告警**：< 0.6 → WARN；< 0.3 → ERROR；不中斷 build
6. 結果寫 `data/seed_health.json`

### 4.2 輸出格式

```json
{
  "checked_at": "2026-04-11T12:00:00Z",
  "results": {
    "seed_cn.txt":    {"region": "CN", "sampled": 20, "consistent": 19, "rate": 0.95, "status": "ok"},
    "seed_hk.txt": {"region": "HK", "sampled": 8,  "consistent": 7,  "rate": 0.875,"status": "ok"},
    "seed_mo.txt": {"region": "MO", "sampled": 5,  "consistent": 5,  "rate": 1.0,  "status": "ok"},
    "seed_tw.txt": {"region": "TW", "sampled": 5,  "consistent": 2,  "rate": 0.4,  "status": "warn"}
  }
}
```

`status ∈ {ok, warn, error, skipped}`；`skipped` 用於 < 3 條或全部解析失敗。不自動修正 seed，僅告警。

---

## 5. 四文件並列輸出

### 5.1 dist/ 結構

```
dist/
├── domains_cn.txt     # 中國大陸
├── domains_hk.txt     # 香港
├── domains_mo.txt     # 澳門
└── domains_tw.txt     # 台灣
```

**`dist/domains.txt` 移除**。CI workflow 與消費端需相應更新。

### 5.2 寫入規則

`write_dist_buckets(dist_dir, rows)`：對每個 `b ∈ {CN, HK, MO, TW}`，篩選 `r.bucket == b ∧ r.score >= INCLUDE_THRESHOLD`，按 domain 字母序排序，寫入 `domains_{b.lower()}.txt`。空桶仍寫檔頭，避免訂閱端 404。

### 5.3 stats.json 擴充

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

`dist_domains` 欄位繼續存在以兼容舊看板，語意改為「四桶 included 總和」。

---

## 6. constants.py 變更

```python
# 移除：HK / MO / TW 不再是負信號
NON_MAINLAND_REGIONS = ["US","JP","SG","KR","DE","GB","NL","AU","CA","FR"]

# 新增：bucket 集合
REGION_BUCKETS = {"CN", "HK", "MO", "TW"}

# 新增：ipnova 多地區 CIDR 來源
IPNOVA_BASE = "https://raw.githubusercontent.com/harryheros/ipnova/main/output"
REGION_CIDR_URLS = {
    "CN": f"{IPNOVA_BASE}/CN.txt",
    "HK": f"{IPNOVA_BASE}/HK.txt",
    "MO": f"{IPNOVA_BASE}/MO.txt",
    "TW": f"{IPNOVA_BASE}/TW.txt",
}

# TLD → bucket 投票
TLD_TO_BUCKET = {".cn": "CN", ".hk": "HK", ".mo": "MO", ".tw": "TW"}

# 行數保險絲
IPNOVA_MIN_LINES = 50
```

**刪除**：`HK_ASNS` / `TW_ASNS` / `MO_ASNS` / `COUNTRY_TO_BUCKET`（v1.0 草擬中存在，v1.1 全部移除）。`CN_BACKBONE` / `CN_CLOUD_ASNS` / `INFRA_KEYWORDS` 不動。

---

## 7. build_domains.py 變更面

| 函式 | 變更 |
|---|---|
| `DomainRecord` | 新增 `bucket: str = ""` ✓ (Step 2 完成) |
| `decide_bucket` | 純函式，簽名 `(domain, source, ip_buckets, dns_cn) -> str` ✓ (Step 3 完成，待 Step 4 簽名簡化) |
| `fetch_cn_cidrs` | 重構為 `fetch_region_cidrs() -> dict[str, list[IPv4Network]]`，含 sanity check |
| `build_cidr_lookup` | 不動，新增 `build_region_lookup` 包一層 |
| `ip_in_cn_cidrs` | 改名 `ip_in_cidrs(ip, lookup)`；新增 `ip_to_bucket(ip, region_lookup)` |
| `build_dns_signal` | 重構為 `build_region_signals(ips, region_lookup)`，回傳 `(per_ip_buckets, dns_cn, dns_total, matched)` |
| `process_domain` | 套 `decide_bucket(domain, source, per_ip_buckets, dns_cn)`，bucket 寫入 record |
| `score_record` | 完全不動 |
| `write_dist` | 重構為 `write_dist_buckets` |
| `write_stats` | 加 `buckets` 段 |
| `build` | 開頭呼叫 `seed_health_check`；尾段呼叫 `write_dist_buckets`；不再寫 `domains.txt` |
| `load_previous_rows` | 已加 bucket 讀取 ✓ (Step 2 完成) |
| sticky 機制 | bucket 與 score 一起沿用上輪值 |

---

## 8. 測試與驗收

1. **回歸**：`domains_cn.txt` 條目數 ≥ 舊 `domains.txt` × 95%
2. **互斥**：四檔 set 兩兩交集為空
3. **Seed 健康**：CN 自洽率 ≥ 0.9
4. **空桶可生**：暫清空 `seed_mo.txt` 跑一次，產出空 `domains_mo.txt`（含檔頭）
5. **保險絲**：暫把 `REGION_CIDR_URLS["HK"]` 指向不存在的 URL，HK 桶應降級為空、build 不中斷
6. **stats 對拍**：`stats.json.buckets.cn.included` 應等於 `domains_cn.txt` 行數（去除註解）

---

## 9. 不在 P1 範圍

- ❌ discovery agents 區分地區（P2）
- ❌ HK/MO/TW ICP 等價 ground truth（P2）
- ❌ IPv6（沿用既有限制）
- ❌ sticky cache 持久化方案 A（已決策不採用）

---

## 10. 變更影響表

| 檔案 | 動作 | 風險 |
|---|---|---|
| `docs/PROPOSAL_MULTI_REGION.md` | v1.1 改寫 | 無 |
| `sources/scripts/constants.py` | 拆 NON_MAINLAND_REGIONS、加 REGION_BUCKETS / REGION_CIDR_URLS / TLD_TO_BUCKET / IPNOVA_MIN_LINES | 低 |
| `sources/scripts/build_domains.py` | 接入 ipnova 多地區、`decide_bucket` 簽名簡化、`process_domain` / `write_dist` 改造 | 中 |
| `sources/manual/seed_*.txt` | 不變 | 無 |
| `dist/domains.txt` | **刪除** | 中（CI workflow 與消費端需更新） |
| `dist/domains_{cn,hk,mo,tw}.txt` | 新增 | 無 |
| `data/seed_health.json` | 新增 | 無 |
| `.github/workflows/update.yml` | commit 路徑改為 `dist/domains_*.txt`，加 `data/seed_health.json` | 低 |
| `sources/scripts/test_decide_bucket.py` | 簽名變更，全部重寫 | 無 |

---

## 11. 實作順序（v1.1）

1. ✅ constants.py 拆分 + bucket 集合（Step 1 完成；待 v1.1 補 REGION_CIDR_URLS / IPNOVA_MIN_LINES）
2. ✅ DomainRecord 加 bucket（Step 2 完成）
3. ✅ decide_bucket 純函式 + 單元測試（Step 3 完成；v1.1 簽名簡化、測試重寫）
4. **Step 4**：fetch_region_cidrs / build_region_lookup / ip_to_bucket / 保險絲
5. **Step 5**：build_region_signals + process_domain 接入
6. **Step 6**：write_dist_buckets + 砍 domains.txt
7. **Step 7**：seed_health_check
8. **Step 8**：write_stats 擴充
9. **Step 9**：CI workflow commit 路徑更新
10. **Step 10**：full build 跑一次、比對驗收項

---

_文件版本：v1.1 ‧ 規範定稿。_
