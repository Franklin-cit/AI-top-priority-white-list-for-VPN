#!/usr/bin/env python3
"""Curated guardrails, Layer 0 templates, and Delta lists shared across scripts.

Contains zero personal credentials, node addresses, or subscription URLs.
All backbone classification is driven by v2fly/domain-list-community (via dlc_catalog.py);
this module holds only Layer 0/1/1.5 templates, Layer 2 essential AI companions, Layer 3
telemetry/PCDN/Scheme-B guards, platform-specific Apple/Microsoft exceptions, and slim
local Delta lists automatically subtracted against the latest DLC snapshot at build time.
"""

from __future__ import annotations

BUILTIN_MIHOMO_ACTIONS = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}

# ---------------------------------------------------------------------------
# Layer 0: Base network / DNS / Sniffer templates
# ---------------------------------------------------------------------------
SR_GENERAL_LINES = (
    "[General]",
    "ipv6 = false",
    "prefer-ipv6 = false",
    "bypass-system = true",
    "skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, "
    "127.0.0.0/8, 169.254.0.0/16, fe80::/10, fc00::/7, localhost, *.local, *.lan, "
    "*.internal, *.home.arpa, captive.apple.com, sequoia.apple.com, "
    "seed-sequoia.siri.apple.com, *.ls.apple.com, *.push.apple.com",
    "bypass-tun = 10.0.0.0/8,100.64.0.0/10,169.254.0.0/16,172.16.0.0/12,"
    "192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,"
    "198.51.100.0/24,203.0.113.0/24,233.252.0.0/24,224.0.0.0/4,255.255.255.255/32,"
    "::ffff:0:0/96,::ffff:0:0:0/96,64:ff9b::/96,64:ff9b:1::/48,100::/64,"
    "2001::/32,2001:20::/28,2001:db8::/32,2002::/16,3fff::/20,5f00::/16,fc00::/7,"
    "fe80::/10,ff00::/8",
    "dns-server = https://223.5.5.5/dns-query#no-h3",
    "fallback-dns-server = https://223.6.6.6/dns-query#no-h3",
    "dns-direct-fallback-proxy = false",
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
FLCLASH_DOMESTIC_DOH = ("https://223.5.5.5/dns-query", "https://223.6.6.6/dns-query")
FLCLASH_OVERSEAS_DOH_BASES = ("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query")
FLCLASH_DNS_ARPA_SUFFIXES = ("in-addr.arpa", "ip6.arpa")
FLCLASH_DNS_AD_REJECT_EXACT = (
    "applog.zijieapi.com",
)
FLCLASH_DNS_AD_REJECT_SUFFIXES = (
    "log.zijieapi.com",
    "a.market.xiaomi.com",
    "ad.xiaomi.com",
    "tracking.miui.com",
    "adv.sec.miui.com",
    "sentry.d.xiaomi.net",
    "ctobsnssdk.com",
    "pangolin-sdk-toutiao1.com",
    "pangolin-sdk-toutiao.com",
    "pangolin-dsp-toutiao.com",
    "mcdn.bilivideo.cn",
    "rmonitor.qq.com",
)
FLCLASH_PROXY_SERVER_NAMESERVER = (
    "https://223.5.5.5/dns-query",
    "https://223.6.6.6/dns-query",
    "tls://223.5.5.5:853",
)
FLCLASH_SNIFFER_SKIP = (
    "+.mijia.cloud",
    "+.push.apple.com",
    "+.mcdn.bilivideo.cn",
    "data.bilibili.com",
    "www.codebuddy.cn",
    "www.workbuddy.cn",
    "copilot.tencent.com",
    "long.weixin.qq.com",
    "short.weixin.qq.com",
    "extshort.weixin.qq.com",
    "dns.weixin.qq.com.cn",
    "paydns.wechatpay.cn",
    "conna.gj.qq.com",
    "oth.eve.mdt.qq.com",
    "masterconn2.qq.com",
)
FLCLASH_NCSI_IPV6_REJECT = ("ipv6.msftconnecttest.com", "ipv6.msftncsi.com")
FLCLASH_NCSI_DIRECT_SUFFIXES = ("msftconnecttest.com", "msftncsi.com")

PROVIDER_EXPECTED_BEHAVIOR = {
    "cn-domain": "domain",
    "private": "domain",
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

# ---------------------------------------------------------------------------
# Layer 1.5: QUIC blocking + QQ/WeChat UDP whitelist
# ---------------------------------------------------------------------------
SR_TENCENT_UDP_REJECT_SUFFIXES = (
    "gdt.qq.com",
    "e.qq.com",
    "bugly.qq.com",
)
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
FLCLASH_TENCENT_UDP_PROCESSES = (
    "Weixin.exe",
    "WeChat.exe",
    "WXWork.exe",
    "QQ.exe",
    "TIM.exe",
    "com.tencent.mm",
    "com.tencent.wework",
    "com.tencent.mobileqq",
    "com.tencent.tim",
)

# ---------------------------------------------------------------------------
# Layer 2: AI Platforms & Essential Companions (Group 1 only) + Scheme B
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
# Only essential feature-flag, captcha, cert, payment & chat-support companions (no segment/sentry)
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
    "stripe.com",
)
OPENAI_BROAD_AUTH0 = ("auth0.com",)
OPENAI_KEYWORDS = ("openai",)
# browser-intake-datadoghq.com intentionally moved to Layer 3 telemetry REJECT
OPENAI_EXACT_DOMAINS = (
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

# Scheme B: pinpoint Google own-domain ad/telemetry endpoints REJECTED above Layer 2.3
# Deliberately exempts video-stats.video.google.com (YouTube playback telemetry / watch progress).
SCHEME_B_GOOGLE_REJECT_DOMAINS = (
    "adservice.google.com",
    "analytics.google.com",
    "crashlyticsreports-pa.googleapis.com",
    "clientmetrics-pa.googleapis.com",
    "imasdk.googleapis.com",
    "mail-ads.google.com",
    "ogads-pa.googleapis.com",
    "pagead.l.google.com",
    "partnerad.l.google.com",
    "proxy-safebrowsing.googleapis.com",
    "www-google-analytics.l.google.com",
)
SCHEME_B_EXEMPT_DOMAINS = ("video-stats.video.google.com",)

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
    "metaaivm.com",
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
    "character.ai",
    # Chinese-owned international AI domains follow DLC category-ai-!cn
    "kimi.ai",
    "moonshot.ai",
    "minimax.io",
)

# Only essential feature-flag & streaming shortlink protections (segment/sentry removed)
LAYER25_PROTECTION_SUFFIXES = (
    "statsig.com",
    "statsigapi.net",
    "statsigcdn.com",
    "disneyplus.bn5x.net",
)

# ---------------------------------------------------------------------------
# Layer 3: Lightweight High-Precision Adblock, Telemetry & PCDN Guards
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
    "e.qq.com",
    "bugly.qq.com",
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
    "app-analytics-services.com",
    "app-analytics-services-att.com",
    "app-ads-services.com",
    "umeng.com",
    "zefrdata.com",
    "ampaeservices.com",
    "checktrustworthiness.com",
    "braze.com",
    "hightouch-events.com",
    "umengcloud.com",
    "pangolin-sdk-toutiao1.com",
    "pangolin-sdk-toutiao-b.com",
    "ctobsnssdk.com",
    "zztfly.com",
    "csjplatform.com",
    "dv.tech",
    "doubleverify.com",
    "crazyegg.com",
    "ethicalads.io",
    "hsadspixel.net",
    "hs-analytics.net",
    "collect.wpsmail.net",
)

LAYER3_EXACT_REJECT_DOMAINS = (
    "status-ipv6.jpush.cn",
    "hilo.bilibili.com",
    "hif-dliq.deepseek.com",
    "aweme.snssdk.com%28null%29",
    "api-c.dutils.com",
    "api-d.dutils.com",
    "m-adnet.dutils.com",
    "devs-data.dutils.com",
    "log-verify.dutils.com",
    "applog.zijieapi.com",
    "log.snssdk.com",
    "apmplus.volces.com",
    "unitelogreport.reader.qq.com",
    "dw-online.ksosoft.com",
    "shuc-android.ksord.com",
    "pre-api.miui.security.xiaomi.com",
)

# Group 3 client telemetry & survey endpoints explicitly routed to Layer 3 REJECT
LAYER3_TELEMETRY_REJECT_DOMAINS = (
    "browser-intake-datadoghq.com",
    "browser-intake-us5-datadoghq.com",
    "http-intake.logs.us5.datadoghq.com",
    "o33249.ingest.sentry.io",
    "o33249.ingest.us.sentry.io",
    "o1158394.ingest.us.sentry.io",
    "copilot-telemetry-service.githubusercontent.com",
    "copilot-telemetry.githubusercontent.com",
    "openai.qualtrics.com",
)

# Functional APIs / push endpoints tagged @ads in DLC that must NOT be blocked
LAYER3_AD_EXEMPT_DOMAINS = (
    "graph.instagram.com",
    "graph-fallback.instagram.com",
    "push.qq.com",
    "mpush.qq.com",
    "cloudpush.iqiyi.com",
    "mipcache.bdstatic.com",
)

SR_PCDN_NOISE_EXACT = (
    "stun.chat.bilibili.com",
    "stun6.chat.bilibili.com",
    "stun-1.chat.bilibili.com",
    "stun-2.chat.bilibili.com",
    "stun-3.chat.bilibili.com",
    "stun-4.chat.bilibili.com",
    "stun-5.chat.bilibili.com",
    "tracker.chat.bilibili.com",
    "vc-brain-lf.ndcpp.com",
    "vcl-brain.ndcpp.com",
    "vc-brain-http.ndcpp.com",
    "vc-brain.ndcpp.com",
    "vc-brain-v6-lf.ndcpp.com",
    "vc-mirror.ndcpp.com",
)
SR_PCDN_NOISE_SUFFIXES = (
    "xinqiucc.com",
    "qiezibenpao.com",
    "kuiniuca.com",
    "mcdn.bilivideo.cn",
    "szbdyd.com",
    "pkoplink.com",
    "wmzfylgdsz.com",
    "qrstuvwxyzab.com",
    "ydycdn.com",
    "zzcdnx.com",
    "nexusedgeio.com",
    "tianwenca.com",
    "comfylink.com",
    "qtaeixd.com",
    "bvgtm.com",
    "cjjd14.com",
    "bdgp.cc",
    "cfogc.com",
    "ak005.com",
    "ankltoken.com",
    "yingt.fun",
)
SR_PCDN_NOISE_KEYWORDS = (
    "live-p2p-tracker",
    "ccc-live-tracker",
)

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
# Layer 4, 5, 6: Special exceptions, Apple Situation A/B, Microsoft split, Checkers
# ---------------------------------------------------------------------------
APPLE_SAFEBROWSING_OHTTP_SUFFIXES = (
    "safebrowsing.apple",
    "ohttp-relay1.fastly-edge.com",
)

APPLE_SR_US_ONLY_SUFFIXES = (
    *APPLE_SAFEBROWSING_OHTTP_SUFFIXES,
    "apple-relay.akamaized.net",
    "apple-relay.cloudflare.com",
    "apple-relay.fastly-edge.com",
    "apple-relay.apple.com",
    "apple-relay.mask.apple-dns.net",
    "gspe1-ssl.ls.apple.com",
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

CHECKER_DELTA_DOMAINS = ("1ms.dog", "1msapp.com", "1ms.one")

# 37 diagnostic anchors retained for audit_subscription.py verification
CHECKER_DOMAINS = (
    "1ms.dog",
    "ipqs.com",
    "ipquery.io",
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
AMAZON_CN_DIRECT = ("amazon.cn",)

MICROSOFT_COMMON_SUFFIXES = (
    "microsoft.com",
    "live.com",
    "msn.com",
    "office.com",
    "office365.com",
    "outlook.com",
    "windows.com",
    "windowsupdate.com",
    "msftconnecttest.com",
    "msftncsi.com",
    "xbox.com",
    "skype.com",
    "sharepoint.com",
    "onedrive.com",
    "visualstudio.com",
    "bing.net",
    "msedge.net",
    "a-msedge.net",
    "c-msedge.net",
    "s-msedge.net",
    "t-msedge.net",
    "windows.net",
    "msftauth.net",
    "msft.net",
)

# ---------------------------------------------------------------------------
# Layer 4/7/8 Delta lists (auto-subtracted against live DLC snapshot)
# ---------------------------------------------------------------------------
PLATFORM_44_LOG_VERIFIED_DELTAS = (
    "github-avatars.oss-cn-hongkong.aliyuncs.com",
    "ibyteimg.com",
    "line-website.com",
    "oklink.com",
    "pipopayment.us",
    "tiktokpangle-cdn-us.com",
)

OVERSEAS_PROXY_DELTA_DOMAINS = (
    "gate.hockeyapp.net",
    "aiv-delivery.net",
    "amazonuniversity.jobs",
    "awscloud.com",
    "vpnunlimited.com",
    "whrq.net",
    "txt.fyi",
    "aol.com",
    "mc-heads.net",
    "apt.thebigboss.org",
    "repo.chariz.com",
    "alibabacloud.com",
    "cnpmjs.org",
)

LAYER7_REMOVED_KEYWORDS = ("aws", "amazon")
LAYER7_REMOVED_KEYWORD_REASONS = {
    "aws": "causes false positives (e.g. draws.io / laws.com)",
    "amazon": "overrides .cn DIRECT rules (hijacks amazonaws.cn / amazonpay.cn / z.cn)",
}

CN_DOMESTIC_DEV_EXTRA = ("yuque.com",)

CN_DOMESTIC_AI_DELTA_SUFFIXES = (
    "xfyun.com",
    "stepfun.com",
    "lingyiwanwu.com",
    "lingyi.org",
    "minimax.chat",
    "baichuan.tech",
    "chatglm.site",
)

CN_DOMESTIC_DELTA_SUFFIXES = (
    "wechatapp.com",
    "ddnspod.com",
    "wetv.vip",
    "wetvinfo.com",
    "tmall.hk",
    "aliyuncs.com",
    "aliyuncsslb.com",
    "aliapp.com",
    "aliappcdn.com",
    "sjxydc.com",
    "bjmxy.net",
    "manlaxycloud.com",
    "gxcould.com",
    "ccgslb.com",
    "ccgslb.net",
    "baidupcs.net",
    "baiducloudapi.com",
    "baiduyun.com",
    "yunjiasu-cdn.net",
    "jd.hk",
    "163.net",
    "163img.com",
    "163nos.com",
    "hdslb.net",
    "didiglobal.com",
    "getui.vip",
    "10086.com",
    "ourdvs.com",
    "114dns.com",
    "miinsurtech.com",
    "dittocdn.com",
    "geevisit.com",
    "weshineapp.com",
)

BYTEDANCE_CN_DELTA_SUFFIXES = (
    "doupay.com", "byteeffecttos.com", "ibytedtos.com", "ecombdpage.com",
    "2333333333333.com", "aigcarena.com", "artistrylab.net", "bcy.net",
    "bcyimg.com", "bqtalk.com", "byte-ticket.com", "byteapk.com",
    "bytedanceoss.net", "bytedancevod.com", "bytesfield.com", "bytesmanager.com",
    "bytesyscdn.com", "capturetheflag.fun", "cdn-build.com", "cdn-build.net",
    "dou.top", "douyinclips.com", "douyinhanyu.com", "douyinmusicclips.com",
    "douyinmusicvideo.com", "douyinshortvideo.com", "douyinvideo.net",
    "dymusictape.com", "dymusicvideo.com", "dyshortvideo.com", "dyvideotape.com",
    "ecom-lightapp.com", "faceu.net", "feiliao.com", "fullluckcalendar.com",
    "goodluckcalendar.com", "healthybaike.com", "heycan.com", "hijackorg.net",
    "hotsoonapp.com", "hotsoonapp.net", "hotsoonvideo.com", "hotsoonvideo.net",
    "hotsoonzb.com", "hotsoonzb.net", "ieshs.com", "ieshs.net",
    "ieshuoshan.com", "ieshuoshan.net", "inluckcalendar.com", "jinritemai-inc.com",
    "jinritoutiao.com", "jiyi.biz", "jiyi.top", "jiyunhudong.com",
    "jiyunhudong.net", "juliangyinqing.com", "juliangyinqing.net", "knightedge.com",
    "luckforcalendar.com", "luckincalendar.com", "maidouke.com", "muyewx.com",
    "neihancommunity.com", "neihancommunity.net", "neihandiantai.com", "neihanshequ.com",
    "pacmantwo.com", "qmoji.mobi", "qmoji.net", "qwconnect.top",
    "samasty.com", "tekkenthree.com", "temaiapi.com", "tetrisone.com",
    "toutiaowap.com", "toutiaowap.net", "ttbyte.com", "ttbyte.net",
    "ugurl.cc", "varchserverqa.com", "vireala.com", "vireala.net",
    "xiguashipin.net", "xiguavideo.net", "yhgfb-cn-static.com", "youdianyisi.com",
)

# Domains excluded from DLC/cn direct routing due to overseas relocation or ad status
DLC_CN_EXCLUDED_DOMAINS = {
    "alibabacloud.com",
    "cnpmjs.org",
    "kimi.ai",
    "moonshot.ai",
    "minimax.io",
    "csjplatform.com",
}

# ---------------------------------------------------------------------------
# Audit anchors
# ---------------------------------------------------------------------------
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
    "metaaivm.com",
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
    "kimi.ai",
    "moonshot.ai",
    "minimax.io",
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
    "getui.net",
    "gepush.com",
    "ecombdpage.com",
    "ecombdapi.com",
    "douyinpic.com",
    "douyinvod.com",
    "zijieapi.com",
    "bdurl.net",
    "wasu.tv",
    "coolapk.com",
    "biliapi.com",
    "gxcould.com",
    "yuque.com",
    "deepseek.com",
    "doubao.com",
    "kimi.com",
    "moonshot.cn",
    "mijia.tech",
    "yuewen.com",
    "fengkongcloud.com",
    "bbdc.cn",
    "bubei.com.cn",
    "weshineapp.com",
)

EXPECTED_CRYPTO_PROXY_AUDIT = ("binance.com", "okx.com", "bybit.com", "coinbase.com", "oklink.com")
EXPECTED_AMAZON_CN_DIRECT = ("amazonaws.cn", "amazonpay.cn", "z.cn")
EXPECTED_CN_DOMESTIC_AI_AUDIT = (
    "deepseek.com",
    "doubao.com",
    "kimi.com",
    "moonshot.cn",
    "minimaxi.com",
    "tongyi.com",
    "qwen.ai",
    "yiyan.baidu.com",
)
EXPECTED_RELOCATED_PROXY_AUDIT = ("alibabacloud.com", "cnpmjs.org", "zoom.us", "ieee.org")
EXPECTED_TELEMETRY_REJECT_AUDIT = (
    *LAYER3_TELEMETRY_REJECT_DOMAINS,
    "segment.io",
    "segment.com",
    "csjplatform.com",
)


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
