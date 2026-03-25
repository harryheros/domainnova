#!/usr/bin/env python3
"""
1_expand.py - Expand seed domains into brand domain clusters

Strategy:
  For each known Chinese brand, maintain a curated list of all associated
  domains (CDN, API, static assets, subsidiaries, international arms).
  Merge into seed.txt, deduplicate.

  Conservative by design - only adds domains with HIGH confidence of
  belonging to the same entity. Expand BRAND_FAMILIES over time via PRs.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEED_FILE = ROOT / "sources" / "manual" / "seed.txt"

BRAND_FAMILIES: dict[str, list[str]] = {

    # Alibaba / Ant Group
    "alibaba": [
        "alibaba.com", "alibabacloud.com", "alibabagroup.com",
        "alicdn.com", "alicdngslb.com",
        "aliyun.com", "aliyun-inc.com", "aliyuncs.com", "aliyundrive.com",
        "alipay.com", "alipay.hk", "alipay.net", "alipayplus.com",
        "alipayobjects.com",
        "taobao.com", "taobao.net",
        "tmall.com", "tmallgenie.com",
        "1688.com", "lazada.com", "daraz.pk",
        "mybank.cn", "antgroup.com", "ant.design",
    ],

    # Tencent
    "tencent": [
        "tencent.com", "tencent.net",
        "tencentcloud.com", "tencentcloudapi.com",
        "tencentcos.com", "tencentclb.com",
        "tencentmeeting.com", "tencentmusic.com", "tencentvideo.com",
        "qq.com", "qq.net",
        "wechat.com", "wechatpay.com", "weixin.com",
        "qcloud.com", "dnspod.com", "dnspod.cn",
        "tencent-cloud.com", "tencent-cloud.net",
        "tencentgames.com", "pgyer.com",
    ],

    # Baidu
    "baidu": [
        "baidu.com", "baidu.jp",
        "baidubce.com", "baiducloud.com",
        "bdstatic.com", "baidupcs.com", "baidupcs.net",
        "iqiyi.com", "qianfan.cloud", "wenxin.cloud",
    ],

    # ByteDance
    "bytedance": [
        "bytedance.com", "bytedance.net",
        "douyin.com", "douyincdn.com", "douyinstatic.com", "douyinvod.com",
        "iesdouyin.com", "iesdouyin.net",
        "tiktok.com", "toutiao.com", "ixigua.com",
        "feishu.cn", "larksuite.com", "capcut.com", "ulikecam.com",
    ],

    # JD.com
    "jd": [
        "jd.com", "jd.hk",
        "jdcloud.com", "jdcloudapi.com",
        "jdpay.com", "jdl.com", "jdcdn.com",
        "jddj.com", "360buy.com",
    ],

    # Xiaomi
    "xiaomi": [
        "xiaomi.com", "xiaomi.net", "mi.com",
        "miui.com", "mipush.com", "miwifi.com", "mi-img.com",
        "xiaoai.com", "mihoyo.com", "mihoyogame.com", "hoyolab.com",
    ],

    # Huawei
    "huawei": [
        "huawei.com", "huawei.eu", "huawei.ru",
        "huaweicloud.com", "myhuaweicloud.com",
        "hicloud.com", "huaweidevice.com",
        "vmall.com", "appgallery.cloud",
    ],

    # Meituan
    "meituan": [
        "meituan.com", "meituan.net",
        "sankuai.com", "meituanmaicai.com", "dianping.com",
    ],

    # NetEase
    "netease": [
        "163.com", "126.com", "netease.com",
        "yeah.net", "163yun.com", "qiyukf.com",
    ],

    # Sina / Weibo
    "weibo": [
        "weibo.com", "weibo.cn",
        "sina.com", "sina.com.cn",
        "sinaimg.cn", "sinajs.cn", "sinaimgfx.com", "weibocdn.com",
    ],

    # Bilibili
    "bilibili": [
        "bilibili.com", "bilibili.net", "bilibili.tv",
        "bilicomic.com", "bilicomics.com",
        "biligame.com", "biligame.net",
        "hdslb.com", "acgvideo.com", "biliapi.com",
    ],

    # DJI
    "dji": [
        "dji.com", "djistatic.com", "djicreator.com",
    ],

    # Pinduoduo / Temu
    "pinduoduo": [
        "pinduoduo.com", "pinduoduo.net",
        "yangkeduo.com", "temu.com",
    ],

    # Kuaishou
    "kuaishou": [
        "kuaishou.com", "ksapisrv.com",
        "kuaishoucdn.com", "gifshow.com", "kwai.com",
    ],

    # Zhihu
    "zhihu": [
        "zhihu.com", "zhimg.com",
    ],

    # Xiaohongshu (RED)
    "xiaohongshu": [
        "xiaohongshu.com", "xhscdn.com", "xhslink.com",
    ],

    # iQIYI
    "iqiyi": [
        "iqiyi.com", "iqiyipic.com", "qiyi.com", "qiyipic.com",
    ],
}


def load_existing_seeds(path: Path) -> list[str]:
    domains = []
    if not path.exists():
        return domains
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                domains.append(line.lower())
    return domains


def run():
    existing = set(load_existing_seeds(SEED_FILE))
    new_domains = set()

    for brand, domains in BRAND_FAMILIES.items():
        for d in domains:
            d = d.lower().strip()
            if d not in existing:
                new_domains.add(d)

    if not new_domains:
        print("No new domains to add.")
        return

    print(f"Adding {len(new_domains)} new domains from brand families.")

    with open(SEED_FILE, "a", encoding="utf-8") as f:
        f.write("\n# === Auto-expanded from brand families ===\n")
        for d in sorted(new_domains):
            f.write(d + "\n")

    print(f"Updated: {SEED_FILE}")


if __name__ == "__main__":
    run()
