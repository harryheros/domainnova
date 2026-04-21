# DomainNova P2.A 多地區評分模型規範書 v1.0

> 狀態：已實施 · 2026-04-21
> 前置條件：P1 v1.1 + P1 fix v2.1 已部署（對稱分桶、對稱閾值、sticky repair）
> 範圍：`sources/scripts/build_domains.py`、`sources/scripts/constants.py`
> 目標：讓 extended/discovery 來源的非 CN 域名能自動基於 IP 信號獲得 HK/MO/TW 桶入選資格

---

## 1. 問題陳述

P1 實作了對稱分桶與閾值，但 `score_record()` 的信號輸入只編碼 CN 信號。HK/MO/TW 域名即使 IP 落在對應 ipnova 表，依然 score=0，無法進入 dist。

## 2. 設計決策

### 2.1 對稱信號模型

每個桶獨立計算布爾信號：`dns_cn / dns_hk / dns_mo / dns_tw` + `cn_tld / hk_tld / mo_tld / tw_tld`。

### 2.2 TLD fallback 非對稱

| 地區 | TLD fallback | 原因 |
|---|---|---|
| CN | 有（score=60）| `.cn` 強制 ICP 備案，TLD 是強信號 |
| HK/MO/TW | 無 | 無等價強制備案制度 |

### 2.3 信號權重

DNS_WEIGHT=60, CN_TLD_WEIGHT=10, XX_TLD_WEIGHT=20, CN_TLD_FALLBACK_SCORE=60。INCLUDE_THRESHOLD 統一 60。

### 2.4 不引入 registrar/registrant 信號（P3 範圍）

### 2.5 seed-force 不變（score=100 覆蓋）

## 3. 技術改造

- `DomainRecord` 新增 `dns_hk, dns_mo, dns_tw` 三欄位
- `build_region_signals` 返回 `region_dns_flags` dict
- 新增 `score_record_for_bucket(bucket, dns_flag, tld_flag)` 純函式
- `score_record` 改為向後兼容 wrapper
- `process_domain` 按桶計算 score
- 新增 `_tld_flag_for_bucket` 輔助函式
- CSV 新增 3 欄，`load_previous_rows` 有 fallback

## 4. 測試

- `test_p2a_score.py`：等價性保證、四桶評分、process_domain 整合、CSV 兼容
- 既有測試全部保持綠色

## 5. 實測結果（2026-04-21）

首次跑 P2.A 後，17 個台灣域名通過自動評分進入 dist/domains_tw.txt（不依賴手工 seed）。HK 非 seed 域名 36 個自動拿分。CN 行為位元組級不變。
