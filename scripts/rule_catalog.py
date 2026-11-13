#!/usr/bin/env python3
"""Curated rule catalog shared by build_subscription.py and audit_subscription.py.

Contains zero personal credentials, node addresses, or subscription URLs.
All lists follow the 9-layer priority model documented in references/curated_domains.md,
with explicit platform divergence between Shadowrocket (iOS) and FlClash/Mihomo (Win/Android).
"""

from __future__ import annotations

PUBLIC_SR_WHITELIST_URL = (
    "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_top500_whitelist_ad.conf"
)

BUILTIN_MIHOMO_ACTIONS = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}

# ---------------------------------------------------------------------------
# Layer 0: Base network / DNS / Sniffer templates
# ---------------------------------------------------------------------------
SR_GENERAL_LINES = (
    "[General]",
    "ipv6 = false",
    "bypass-system = true",
    "skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, "
    "127.0.0.0/8, 169.254.0.0/16, fe80::/10, fc00::/7, localhost, *.local, *.lan, "
    "*.internal, *.home.arpa, captive.apple.com, sequoia.apple.com, "
    "seed-sequoia.siri.apple.com, *.ls.apple.com, *.push.apple.com",
    "bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,"
    "192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,"
    "198.51.100.0/24,203.0.113.0/24,233.252.0.0/24,224.0.0.0/4,255.255.255.255/32,"
    "::1/128,::ffff:0:0/96,::ffff:0:0:0/96,64:ff9b::/96,64:ff9b:1::/48,100::/64,"
    "2001::/32,2001:20::/28,2001:db8::/32,2002::/16,3fff::/20,5f00::/16,fc00::/7,"
    "fe80::/10,ff00::/8",
    "dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query",
    "fallback-dns-server = https://dns.google/dns-query, https://1.1.1.1/dns-query",
    "hijack-dns = *:53",
    "block-quic = all-proxy",
    "always-real-ip = *.lan, *.local, localhost, *.localhost, *.home.arpa, "
    "*.msftconnecttest.com, *.msftncsi.com, *.srv.nintendo.net, "
    "*.stun.playstation.net, xbox.*.microsoft.com, *.xboxlive.com",
)

FLCLASH_FAKE_IP_FILTER_BASE = (
    "rule-set:cn-domain",
    "rule-set:private",
    "+.lan",
    "+.local",
    "localhost",
    "+.localhost",
    "+.msftconnecttest.com",
    "+.msftncsi.com",
    "+.stun.*.*",
    "+.stun.*.*.*",
)

FLCLASH_DEFAULT_NAMESERVER = ("223.5.5.5", "119.29.29.29")
FLCLASH_DOMESTIC_DOH = ("https://dns.alidns.com/dns-query", "https://doh.pub/dns-query")
FLCLASH_PROXY_SERVER_NAMESERVER = (
    "https://223.5.5.5/dns-query",
    "https://1.12.12.12/dns-query",
)
FLCLASH_SNIFFER_SKIP = ("+.mijia.cloud", "+.push.apple.com")

# Provider expected behaviors in Mihomo
PROVIDER_EXPECTED_BEHAVIOR = {
    "ads": "domain",
    "cn-domain": "domain",
    "private": "domain",
    "cn-ip": "ipcidr",
    "apple": "classical",
    "claude": "classical",
    "facebook": "classical",
    "gemini": "classical",
    "google": "classical",
    "github": "classical",
    "instagram": "classical",
    "line": "classical",
    "microsoft": "classical",
    "openai": "classical",
    "speedtest": "classical",
    "telegram": "classical",
    "tiktok": "classical",
    "whatsapp": "classical",
    "youtube": "classical",
}

# ---------------------------------------------------------------------------
# Layer 1: LAN / Private networks
# ---------------------------------------------------------------------------
LAN_EXACT_DOMAINS = ("localhost",)
LAN_SUFFIXES = ("localhost", "lan", "local", "home.arpa")
LAN_IPV4_CIDRS = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
)
LAN_IPV6_CIDRS = ("::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8")

SR_LAN_INLINE_DOMAINS = (
    "instant.arubanetworks.com",
    "setmeup.arubanetworks.com",
    "asusrouter.com",
    "router.asus.com",
    "www.asusrouter.com",
    "oasisauth.h3c.com",
    "routerlogin.com",
    "www.routerlogin.com",
    "localhost.weixin.qq.com",
    "localhost.work.weixin.qq.com",
    "tplogin.cn",
    "miwifi.com",
    "www.miwifi.com",
    "local.adguard.org",
)
SR_LAN_INLINE_SUFFIXES = (
    "internal",
    "localdomain",
    "example",
    "invalid",
    "test",
    "router.ctc",
    "my.router",
    "zte.home",
    "tplinkwifi.net",
    "tendawifi.com",
    "plex.direct",
    "in-addr.arpa",
    "ip6.arpa",
)

# ---------------------------------------------------------------------------
# Layer 1.5: QUIC blocking + Shadowrocket QQ/WeChat UDP whitelist
# ---------------------------------------------------------------------------
SR_TENCENT_UDP_SUFFIXES = (
    "qq.com",
    "wechat.com",
    "weixin.com",
    "tenpay.com",
    "servicewechat.com",
    "qpic.cn",
    "qlogo.cn",
    "wechatapp.com",
)

# ---------------------------------------------------------------------------
# Layer 2: AI Platforms & Parent Immunity (with Scheme B pinpoint Google REJECT)
# ---------------------------------------------------------------------------
OPENAI_SUFFIXES = (
    "openai.com",
    "chatgpt.com",
    "ai.com",
    "chat.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "sora.com",
    "livekit.cloud",
    "arkoselabs.com",
    "openaiapi-site.azureedge.net",
    "openaicom.imgix.net",
)
OPENAI_COMPANION_SUFFIXES = (
    "algolia.net",
    "api.statsig.com",
    "events.statsigapi.net",
    "featuregates.org",
    "identrust.com",
    "intercom.io",
    "intercomcdn.com",
    "launchdarkly.com",
    "observeit.net",
    "segment.io",
    "sentry.io",
    "stripe.com",
)
OPENAI_BROAD_AUTH0 = ("auth0.com",)
OPENAI_KEYWORDS = ("openai",)
OPENAI_EXACT_DOMAINS = (
    "browser-intake-datadoghq.com",
    "chat.openai.com.cdn.cloudflare.net",
    "openaicom-api-bdcpf8c6d2e9atf6.z01.azurefd.net",
    "openaicomproductionae4b.blob.core.windows.net",
    "production-openaicom-storage.azureedge.net",
    "static.cloudflareinsights.com",
)
OPENAI_IPV4_CIDRS = ("24.199.123.28/32", "64.23.132.171/32")
OPENAI_ASNS = ("20473",)

ANTHROPIC_SUFFIXES = (
    "anthropic.com",
    "claude.ai",
    "claude.com",
    "clau.de",
    "claudeusercontent.com",
)
ANTHROPIC_KEYWORDS = ("claude", "anthropic")
ANTHROPIC_EXACT_DOMAINS = ("cdn.usefathom.com",)

# Scheme B: pinpoint Google own-domain ad/crash endpoints REJECTED above Layer 2.3
# so Google parent domains stay in Layer 2.3 without shielding known ad endpoints.
SCHEME_B_GOOGLE_REJECT_DOMAINS = (
    "adservice.google.com",
    "analytics.google.com",
    "crashlyticsreports-pa.googleapis.com",
)

GOOGLE_AI_AND_PARENT_SUFFIXES = (
    "gemini.google.com",
    "gemini.google",
    "gemini.gstatic.com",
    "antigravity.google",
    "antigravity-unleash.goog",
    "ai.studio",
    "aistudio.google.com",
    "makersuite.google.com",
    "ai.google.dev",
    "google.dev",
    "deepmind.com",
    "deepmind.google",
    "generativeai.google",
    "jules.google",
    "jules.google.com",
    "labs.google",
    "labs.google.com",
    "notebooklm.google",
    "notebooklm.google.com",
    "notebook.google",
    "notebook.google.com",
    "opal.google",
    "opal.google.com",
    "flow.google",
    "flow.google.com",
    "bard.google.com",
    "stitch.withgoogle.com",
    "cloudcode-pa.googleapis.com",
    "proactivebackend-pa.googleapis.com",
    "aisandbox-pa.googleapis.com",
    "google.com",
    "google",
    "goog",
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "ggpht.com",
    "withgoogle.com",
    "1e100.net",
    "gvt1.com",
    "gvt2.com",
    "recaptcha.net",
)
GOOGLE_AI_KEYWORDS = ("generativelanguage", "alkalimakersuite", "antigravity")

MICROSOFT_AI_SUFFIXES = (
    "copilot.microsoft.com",
    "copilot.cloud.microsoft",
    "designer.microsoft.com",
    "copilotstudio.microsoft.com",
)
META_COPILOT_SUFFIXES = (
    "muse.ai",
    "meta.ai",
    "llama.com",
    "ai.meta.com",
    "meta.com",
    "facebook.com",
    "fb.com",
    "fb.me",
    "fbcdn.net",
    *MICROSOFT_AI_SUFFIXES,
    "forefront.ai",
    "devv.ai",
)
META_ASNS = ("32934",)

XAI_SUFFIXES = ("grok.com", "x.ai")

OTHER_AI_SUFFIXES = (
    "perplexity.ai",
    "pplx.ai",
    "groq.com",
    "midjourney.com",
    "cursor.com",
    "cursor.sh",
    "cursorapi.com",
)

LAYER25_PROTECTION_SUFFIXES = (
    "statsig.com",
    "statsigapi.net",
    "statsigcdn.com",
    "segment.com",
    "sentry.io",
    "disneyplus.bn5x.net",
)

# ---------------------------------------------------------------------------
# Layer 3: Adblock rules & strict domain-label protection boundaries
# ---------------------------------------------------------------------------
GOOGLE_CN_AD_VARIANTS = (
    "googlesyndication-cn.com",
    "google-analytics-cn.com",
    "googletagmanager-cn.com",
    "googletagservices-cn.com",
    "googletraveladservices-cn.com",
    "googlevads-cn.com",
    "doubleclick-cn.net",
    "doubleclick.cn",
    "admob-cn.com",
    "2mdn-cn.net",
    "app-measurement-cn.com",
    "googleads-cn.com",
    "googleadservices-cn.com",
    "googleadsserving.cn",
)

CORE_AD_SUFFIXES = (
    "doubleclick.net",
    "doubleclick.com",
    "admob.com",
    "2mdn.net",
    "googlesyndication.com",
    "googleadservices.com",
    "google-analytics.com",
    "googleanalytics.com",
    "googleads.com",
    "googletraveladservices.com",
    "googletagmanager.com",
    "googletagservices.com",
    "app-measurement.com",
    *GOOGLE_CN_AD_VARIANTS,
    "adjust.com",
    "adjust.io",
    "flurry.com",
    "appsflyer.com",
    "appsflyersdk.com",
    "branch.io",
    "bn5x.net",
    "omtrdc.net",
    "2o7.net",
    "demdex.net",
    "everesttech.net",
    "scorecardresearch.com",
    "quantserve.com",
    "taboola.com",
    "outbrain.com",
    "criteo.com",
    "criteo.net",
    "rubiconproject.com",
    "pubmatic.com",
    "openx.net",
    "adnxs.com",
    "adsrvr.org",
    "advertising.com",
    "moatads.com",
    "iasds01.com",
    "adsafeprotected.com",
    "unityads.unity3d.com",
    "applovin.com",
    "applvn.com",
    "vungle.com",
    "chartboost.com",
    "inmobi.com",
    "ironsrc.com",
    "supersonicads.com",
    "pangleglobal.com",
    "pangle.io",
    "pangle.com",
    "pangolin-sdk-toutiao.com",
    "byteoversea.com",
    "mintegral.com",
    "miaozhen.com",
    "mmstat.com",
    "cnzz.com",
    "tanx.com",
    "alimama.alicdn.com",
    "gdt.qq.com",
    "mobads.baidu.com",
    "mobads-logs.baidu.com",
    "ada.baidu.com",
    "crs.baidu.com",
    "kstj.baidu.com",
    "adgeo.163.com",
    "cm.jd.com",
    "market.aliyun.com",
    "adview.cn",
    "cupid.iqiyi.com",
    "ad.12306.cn",
    "vortex.data.microsoft.com",
    "ogma.iad.appboy.com",
    "amazon-adsystem.com",
    "awstrack.me",
)

# Strict label-boundary suffixes protected from Layer 3 REJECT stripping/insertion
# (deduplicated cleanly since sentry.io appears in both 2.1 OpenAI companion and 2.5 guard)
AI_PROTECTED_SUFFIXES = tuple(
    dict.fromkeys(
        (
            *OPENAI_SUFFIXES,
            *OPENAI_COMPANION_SUFFIXES,
            *ANTHROPIC_SUFFIXES,
            *GOOGLE_AI_AND_PARENT_SUFFIXES,
            *META_COPILOT_SUFFIXES,
            *XAI_SUFFIXES,
            *OTHER_AI_SUFFIXES,
            *LAYER25_PROTECTION_SUFFIXES,
            "fabric.io",
        )
    )
)
AI_PROTECTED_EXACT = (*OPENAI_EXACT_DOMAINS, *ANTHROPIC_EXACT_DOMAINS)

# ---------------------------------------------------------------------------
# Layer 4: Global mainstream platforms & platform-divergent Apple rules
# ---------------------------------------------------------------------------
PLATFORM_41_TWITTER = (
    "x.com",
    "twitter.com",
    "twimg.com",
    "t.co",
    "twitpic.com",
    "periscope.tv",
    "vine.co",
    "twitter.jp",
    "twttr.com",
)
PLATFORM_42_YOUTUBE = (
    "youtube.com",
    "youtu.be",
    "ytimg.com",
    "googlevideo.com",
    "youtube-nocookie.com",
)
PLATFORM_43_META_SOCIAL = (
    "instagram.com",
    "cdninstagram.com",
    "threads.net",
    "whatsapp.com",
    "whatsapp.net",
)
PLATFORM_44_MSG = (
    "t.me",
    "telegram.org",
    "telegram.me",
    "tdesktop.com",
    "telegra.ph",
    "telesco.pe",
    "discord.com",
    "discord.gg",
    "discordapp.com",
    "discordapp.net",
    "discordcdn.com",
)
PLATFORM_45_DEV_COMMUNITY = (
    "github.com",
    "github.io",
    "githubusercontent.com",
    "githubassets.com",
    "github.dev",
    "huggingface.co",
    "hf.co",
    "docker.com",
    "docker.io",
    "v2ex.com",
    "reddit.com",
    "redd.it",
    "redditmedia.com",
    "redditstatic.com",
    "wikipedia.org",
    "wikimedia.org",
    "wikidata.org",
    "wiktionary.org",
    "quora.com",
    "medium.com",
    "github-avatars.oss-cn-hongkong.aliyuncs.com",
)
PLATFORM_46_STREAMING = (
    "netflix.com",
    "nflxvideo.net",
    "nflximg.net",
    "nflxext.com",
    "nflxso.net",
    "disney.com",
    "disneyplus.com",
    "bamgrid.com",
    "dssott.com",
    "spotify.com",
    "scdn.co",
    "pscdn.co",
    "twitch.tv",
    "ttvnw.net",
    "jtvnw.net",
    "pixiv.net",
    "pximg.net",
    "fanbox.cc",
)

# Shadowrocket Situation A (default on iOS): ONLY US-exclusive Apple services go PROXY in Layer 4.7
APPLE_SR_US_ONLY_SUFFIXES = (
    "apple-relay.akamaized.net",
    "apple-relay.cloudflare.com",
    "apple-relay.fastly-edge.com",
    "cp4.cloudflare.com",
    "guzzoni.apple.com",
    "smoot.apple.com",
    "apple.news",
    "news-edge.apple.com",
    "apple.comscoreresearch.com",
    "tv.apple.com",
    "play-edge.itunes.apple.com",
    "uts-api.itunes.apple.com",
    "np-edge.itunes.apple.com",
    "play-cdn.itunes-apple.com.akadns.net",
)

# Common Apple domains (PROXY in FlClash Layer 4.7; DIRECT in Shadowrocket Situation A Layer 6.0)
APPLE_COMMON_SUFFIXES = (
    "apple.com",
    "icloud.com",
    "icloud-content.com",
    "mzstatic.com",
    "cdn-apple.com",
    "aaplimg.com",
    "apple-dns.net",
    "apple-mapkit.com",
)
APPLE_SR_DIRECT_EXTRA_SUFFIXES = (
    "itunes-apple.com.akadns.net",
    "origin-apple.com.akadns.net",
    "push-apple.com.akadns.net",
    "apple-support.akadns.net",
)
APPLE_SR_DIRECT_KEYWORDS = (
    "apple-support.akadns.net",
    "apple.com.akadns.net",
    "apple.com.edgekey.net",
    "buy.itunes.apple.com",
    "smp-device",
    "testflight",
    "icloud.com.akadns.net",
)
APPLE_CIDRS_V4 = (
    "139.178.128.0/18",
    "144.178.0.0/19",
    "144.178.36.0/22",
    "144.178.48.0/20",
    "17.0.0.0/8",
    "192.35.50.0/24",
    "198.183.17.0/24",
    "205.180.175.0/24",
    "63.92.224.0/19",
    "65.199.22.0/23",
)
APPLE_CIDRS_V6 = ("2403:300::/32", "2620:149::/32", "2a01:b740::/32")

# ---------------------------------------------------------------------------
# Layer 5: 36 IP / DNS / WebRTC diagnostic checker domains
# ---------------------------------------------------------------------------
CHECKER_DOMAINS_36 = (
    "1ms.dog",
    "ipqs.com",
    "iplocate.io",
    "ipinfo.io",
    "ip.sb",
    "ping0.cc",
    "ip-api.com",
    "ipapi.co",
    "ipapi.is",
    "ipapi.com",
    "ipwho.is",
    "ipwhois.app",
    "ipdata.co",
    "ipgeolocation.io",
    "ifconfig.me",
    "ifconfig.co",
    "icanhazip.com",
    "ipify.org",
    "ident.me",
    "myexternalip.com",
    "ipchicken.com",
    "whatismyipaddress.com",
    "whatismyip.com",
    "wtfismyip.com",
    "whatismyip.akamai.com",
    "checkip.amazonaws.com",
    "ip.me",
    "ip.gs",
    "ipcheck.ing",
    "ip.skk.moe",
    "db-ip.com",
    "myip.com",
    "dnsleaktest.com",
    "ipleak.net",
    "browserleaks.com",
    "browserleaks.org",
)

# ---------------------------------------------------------------------------
# Layer 6 & Layer 7: Microsoft exceptions, Top500 direct adjustments, Layer 7 filters
# ---------------------------------------------------------------------------
MS_61_DIRECT = ("cn.bing.com",)
MS_61_PROXY_8 = (
    "bing.com",
    "api.onedrive.com",
    "dm.files.1drv.com",
    "skyapi.live.net",
    "odc.officeapps.live.com",
    "centralus1.mediap.svc.ms",
    "mobile.pipe.aria.microsoft.com",
    "location.microsoft.com",
)

SR_DIRECT_SKIP_EXACT = {
    "cn",
    "cloudflare.com",
    "blog.google",
    "forms.gle",
    "storage.googleapis.com",
    "tools.google.com",
    "disney.com",
    "bing.com",
    "amazon.com",
    "amazon.ca",
    "amazon.co.uk",
    "amazon.es",
    "amazon.fr",
    "alexa.com",
    "aol.com",
    "yahoo.com",
    "www.yahoo.com",
    "news.yahoo.com",
    "sports.yahoo.com",
    "finance.yahoo.com",
    "mail.yahoo.com",
    "zoom.us",
}

LAYER7_REMOVED_KEYWORDS = ("aws", "amazon")
LAYER7_REMOVED_KEYWORD_REASONS = {
    "aws": "causes false positives (e.g. draws.io / laws.com)",
    "amazon": "overrides .cn DIRECT rules (hijacks amazonaws.cn / amazonpay.cn / z.cn)",
}

# ---------------------------------------------------------------------------
# Layer 8: Domestic non-.cn + Domestic AI + CDN list & shared audit anchors
# ---------------------------------------------------------------------------
CN_DOMESTIC_AI_SUFFIXES = (
    "deepseek.com",
    "doubao.com",
    "volcengine.com",
    "volccdn.com",
    "kimi.com",
    "tongyi.com",
    "qianwen.com",
    "minimaxi.com",
    "hailuoai.com",
    "baichuan-ai.com",
    "sensetime.com",
    "lingyiwanwu.com",
    "stepfun.com",
)
CN_DOMESTIC_DEV_EXTRA = ("yuque.com",)

SR_CN_NON_CN_235 = (
    # Tencent / WeChat / DNSPod
    "tencent.com", "tencent-cloud.net", "wechat.com", "weixin.com", "servicewechat.com",
    "wechatapp.com", "myqcloud.com", "qcloud.com", "tenpay.com", "dnspod.com",
    "dnspod.net", "ddnspod.com", "dns.pub", "doh.pub", "dot.pub", "gtimg.com",
    "weiyun.com", "foxmail.com", "soso.com", "wetv.vip", "wetvinfo.com", "smtcdns.com",
    "smtcdns.net", "cdntips.com", "cdntips.net",
    # Alibaba / Taobao / Alipay / Amap / Youku / Yuque
    "tmall.com", "tmall.hk", "alipay.com", "alipayobjects.com", "alicdn.com",
    "aliyun.com", "aliyuncs.com", "alidns.com", "alibabacloud.com", "alibabagroup.com",
    "1688.com", "amap.com", "autonavi.com", "ele.me", "dingtalk.com", "yuque.com",
    "youku.com", "ykimg.com", "tudou.com", "cainiao.com", "fliggy.com", "ucweb.com",
    "xiami.com", "aliapp.org", "kunluncan.com",
    # ByteDance / Qishui / Log-verified misses
    "qishui.com", "ecombdpage.com",
    # Baidu / JD / NetEase
    "bdstatic.com", "baidustatic.com", "bcebos.com", "baidupcs.com", "baidubce.com",
    "bdimg.com", "yunjiasu-cdn.net", "nuomi.com", "shifen.com", "jomodns.com",
    "jd.com", "360buyimg.com", "360buy.com", "jdcloud.com", "jcloudstatic.com",
    "163.com", "126.com", "126.net", "127.net", "netease.com", "ydstatic.com",
    "youdao.com", "lofter.com",
    # Video / Social / News / Community
    "bilivideo.com", "biliapi.net", "hdslb.com", "acg.tv", "iqiyi.com", "iqiyipic.com",
    "qy.net", "71.am", "71edge.com", "mgtv.com", "hunantv.com", "hitv.com", "imgo.tv",
    "sohu.com", "sohucs.com", "sogou.com", "sogo.com", "sina.com", "sinaapp.com",
    "weibocdn.com", "zhihu.com", "zhimg.com", "douban.com", "doubanio.com",
    "xiaohongshu.com", "xhscdn.com", "hupu.com", "ngabbs.com", "chiphell.com",
    "smzdm.com", "ithome.com", "jianshu.com", "36kr.com", "huxiu.com", "sspai.com",
    "ifanr.com", "caixin.com", "guokr.com", "kuaishou.com", "yximgs.com",
    # Life / E-commerce / Travel / Jobs
    "meituan.com", "meituan.net", "sankuai.com", "dianping.com", "pinduoduo.com",
    "yangkeduo.com", "didiglobal.com", "xiaojukeji.com", "udache.com", "ctrip.com",
    "qunar.com", "elong.com", "ly.com", "mafengwo.com", "suning.com", "vip.com",
    "dangdang.com", "dewu.com", "poizon.com", "sf-express.com", "zto.com",
    "yundaex.com", "kuaidi100.com", "58.com", "anjuke.com", "ke.com", "lianjia.com",
    "zhipin.com", "bosszhipin.com", "zhaopin.com", "liepin.com",
    # OEM / Office / Cloud Disk / Push
    "mi.com", "miui.com", "xiaomi.com", "xiaomi.net", "hicloud.com", "dbankcdn.com",
    "vmall.com", "myhuaweicloud.com", "huaweicloud.com", "hwclouds-dns.com",
    "oppo.com", "oppomobile.com", "heytap.com", "vivo.com", "meizu.com", "lenovo.com",
    "wps.com", "kingsoft.com", "360.com", "360safe.com", "qhimg.com", "qhres.com",
    "115.com", "xunlei.com", "sandai.net", "lanzou.com", "ctfile.com", "getui.com",
    # Gaming / Audio / Live
    "mihoyo.com", "miyoushe.com", "tapimg.com", "kugou.com", "ximalaya.com",
    "xmcdn.com", "lizhi.fm", "yy.com", "huya.com", "douyu.com", "3dmgame.com",
    "gamersky.com", "ali213.net", "4399.com", "7k7k.com", "papegames.com",
    "kurogame.com", "hypergryph.com",
    # Cloud CDN / Dev / Finance / Study
    "ksyungslb.com", "ksyun.com", "ks-cdn.com", "cmbchina.com", "ccb.com",
    "abchina.com", "bankcomm.com", "pingan.com", "unionpay.com", "95516.com",
    "10086.com", "cctv.com", "xinhuanet.com", "csdn.net", "gitee.com", "cnblogs.com",
    "segmentfault.com", "oschina.net", "nowcoder.com", "npmmirror.com", "cnpmjs.org",
    "qiniucdn.com", "qiniudn.com", "clouddn.com", "qbox.me", "upyun.com",
    "upaiyun.com", "wangsu.com", "wscdns.com", "chinacache.com", "ourdvs.com",
    "bootcss.com", "staticfile.org", "114dns.com", "ipip.net", "chaoxing.com",
    "cnki.net", "icourse163.org", "xuetangx.com", "xueqiu.com", "eastmoney.com",
    "keep.com", "gotokeep.com",
)
# Backward-compatible aliases for external callers still importing legacy tuple names
SR_CN_NON_CN_233 = SR_CN_NON_CN_235
SR_CN_NON_CN_232 = SR_CN_NON_CN_235

BYTEDANCE_COMMON_SUFFIXES = (
    "bytedance.com",
    "bytednsdoc.com",
    "douyin.com",
    "toutiao.com",
    "feishu.cn",
    "amemv.com",
    "byteimg.com",
    "ibytedtos.com",
    "ixigua.com",
    "pstatp.com",
    "snssdk.com",
    "volces.com",
    "zjcdn.com",
)

MICROSOFT_COMMON_SUFFIXES = (
    "microsoft.com",
    "live.com",
    "msn.com",
    "office.com",
    "office365.com",
    "outlook.com",
    "windows.com",
    "windowsupdate.com",
    "xbox.com",
    "skype.com",
    "sharepoint.com",
    "onedrive.com",
    "visualstudio.com",
    "bing.net",
)

REQUIRED_AI_PROXY_DOMAINS = (
    "openai.com",
    "chatgpt.com",
    "anthropic.com",
    "claude.ai",
    "claude.com",
    "gemini.google.com",
    "antigravity.google",
    "muse.ai",
    "meta.ai",
    "grok.com",
    "x.ai",
    "copilot.microsoft.com",
    "copilot.cloud.microsoft",
    "perplexity.ai",
    "groq.com",
    "midjourney.com",
    "cursor.com",
    "statsig.com",
    "featuregates.org",
    "disneyplus.bn5x.net",
)

EXPECTED_SR_DOMESTIC_NON_CN = (
    "tencent.com",
    "servicewechat.com",
    "wechatapp.com",
    "iqiyi.com",
    "xiaohongshu.com",
    "dnspod.com",
    "ddnspod.com",
    "qishui.com",
    "getui.com",
    "ecombdpage.com",
    "yuque.com",
    "deepseek.com",
    "doubao.com",
    "kimi.com",
)

EXPECTED_AMAZON_CN_DIRECT = ("amazonaws.cn", "amazonpay.cn", "z.cn")
EXPECTED_CN_DOMESTIC_AI_AUDIT = ("deepseek.com", "doubao.com", "kimi.com", "tongyi.com")


def domain_matches(domain: str, suffix: str) -> bool:
    """Return True if domain matches suffix on a strict DNS label boundary."""
    d = domain.lower().strip(".")
    s = suffix.lower().strip(".")
    return d == s or d.endswith("." + s)


def domain_in_suffix_set(domain: str, suffixes: set[str] | tuple[str, ...]) -> bool:
    """Fast DNS label-boundary lookup for domain against a suffix collection."""
    d = domain.lower().strip(".")
    if not d:
        return False
    suf_set = suffixes if isinstance(suffixes, set) else set(suffixes)
    parts = d.split(".")
    for i in range(len(parts)):
        if ".".join(parts[i:]) in suf_set:
            return True
    return False
