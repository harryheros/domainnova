# 本輪會話改動審計

## Session 1（初始化）
seed.txt: 701 -> 696（移出 alipay.hk/tmall.hk/jd.hk → seed_hk.txt；bytedance.com/wechat.com → seed_offshore.txt）
新建：seed_hk.txt(3) / seed_mo.txt(空) / seed_tw.txt(空) / seed_offshore.txt(2)

## Session 2（種子庫全面擴充）
seed_sg.txt: 舊版扁平結構 → 分類結構，新增 Regulatory、Infrastructure、Logistics 分類
  新增：acra/edb/enterprise/mas/judiciary/sgnic/sgix/spgroup/pub/psa/caas/tech/csa/smrt/sbstransit（+14）

seed_tw.txt: 大幅擴充，從舊版 ~65 → 125 個域名
  新增：twnic/edu.tw registry 錨點；22縣市政府全覆蓋；科學園區；工業協會 B2B hubs；
        7-eleven/hi-life/familymart Retail 分類；mediatek/acer/foxconn/quanta 製造業；
        fubon 補回；ndc/msa 中央政府補充

seed_kr.txt: 舊版 ~80 → 111 個域名
  新增：kisa registry；kepco/kwater/korail/airport.kr 基礎設施；gyeonggi/sejong 地方政府；
        skbroadband telecom；nate 入口；lotteon/cjlogistics/hanjin 電商物流；
        edaily/mt.co.kr 媒體；krx/kofia/kfb 金融；kia/posco/hanwha/doosan 製造業；
        etri/kist R&D；hanyang/skku.ac.kr 教育；hybecorp/jype/smtown/ygfamily 娛樂；
        moef/nhis 政府補充
  修正：skku.edu → skku.ac.kr（錯誤域名）；移除 krnic.or.kr（已併入 KISA）

seed_jp.txt: 舊版 ~85 → 120 個域名
  新增：jprs/jpix IXP backbone；fsa 金融廳；tepco/kepco/chuden 電力；tokyogas 能源；
        kuronekoyamato/sagawa/nipponexpress/jr-central/jreast/westjr 物流交通；
        tokyometro/jal/ana 交通航空；jpx 交易所；nec/fujitsu/mitsubishielectric/hitachi/canon/toshiba 製造；
        keidanren/jetro/jcci 經濟團體；isct.ac.jp（東工大新域名）；riken 研究機構
  修正：移除重複 chuden.co.jp；移除 internet.ne.jp（非基礎設施）

seed_hk.txt: 舊版扁平 ~70 → 分類結構 85 個域名
  修正：移除不存在的 hknic.hk；hke.com.hk → hkelectric.com；移除錯誤的 bankofchina.com.hk
  補回：octopus/aastocks/hkstp/fwd/winglungbank/yesstyle；新增 hongkongairlines

seed_mo.txt: 舊版扁平 ~65 → 分類結構 68 個域名
  修正：移除 bankofchina.com.hk（香港域名混入）；移除 turbojet.com.hk（跨境域名）
  補回：ipim/mbe/ces/ocm；新增 gaming-inspection.gov.mo；新增 Gaming/Hospitality 分類（sands/galaxyentertainment）

seed_offshore.txt: 2 → 7 個域名
  新增：tiktok/tiktokcdn/aliexpress/shein/temu；補充分類結構

## Session 2 技術修正
- seed.txt: 移除 foxconn.com（與 seed_tw.txt 跨區重複，歸屬應為 TW）
- validate_manual_sources.py v2 → v3：新增區域種子驗證、跨區域重複偵測、CN∩Regional 衝突檢查
- update.yml：stats 輸出擴充為全 7 個區域（原本只顯示 cn/hk/mo/tw，漏掉 jp/kr/sg）
