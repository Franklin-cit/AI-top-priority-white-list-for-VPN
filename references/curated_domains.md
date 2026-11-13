# 核心规则模板与精筛域名清单 (Curated Rules & Domains)

> 本文档严格按照代理核心 **自上而下、命中即停** 的实际生效优先级，完整收录 **前置清洗基线 → 第 0 层底层配置 → 第 1 ~ 9 层分流流水线 → Shadowrocket 配置末尾段**。所有规则均已剔除个人节点与隐私信息；FlClash 示例中使用 `<PROXY_GROUP>` 代表主代理策略组（如 `🚀 节点选择` 或 `PROXY`），Shadowrocket 统一使用内置策略名 `PROXY`。
>
> **双端平台非对称约定**：
> - **FlClash / Mihomo（Windows 桌面端 & Android 移动端）**：默认启用 **Apple 情况 B（桌面端通用 Apple 全走代理）** + `RULE-SET,ads` 差集去重 + `RULE-SET,cn-domain` / `RULE-SET,cn-ip`。
> - **Shadowrocket（iOS 端）**：默认启用 **Apple 情况 A**（仅 Apple Intelligence / Siri AI / Apple News / Apple TV+ 在第 4.7 层走代理；美区 App Store、iCloud 与 Apple CIDR 在第 6.0 层走 `DIRECT`，并在第 7 层剔除通用 Apple CDN 残留），并附带第 1.5 层 QQ/微信 UDP 白名单，以及第 8.1 层 235 条高频非 `.cn` 国内域名（不含头部 Top500 覆盖项，含与 1.5 层对齐的 `servicewechat.com`/`wechatapp.com`）、13 条国产 AI 与 `DOMAIN-SUFFIX,cn,DIRECT` 共 249 条直连规则（注：下方字节括号提及的 5 个兜底域由第 8.0 层统一输出）。

---

## 前置：上游白名单规则基线与清洗原则

- **白名单去广告源**：`https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_top500_whitelist_ad.conf`
- **合并与清洗原则（建议统一由 `scripts/build_subscription.py` 确定性构建）**：
  1. 提取原文件中的 `[Rule]` 按动作分类；`[URL Rewrite]` 与 `[MITM]` 不放在规则前面，统一保留在 Shadowrocket 第 9 层 `FINAL,PROXY` 之后的**配置末尾段**。
  2. **FlClash / Mihomo（Win/Android）**：若订阅已含 `RULE-SET,ads`（`behavior: domain`），先将上游 `REJECT` 列表与 `ads` 做对比去重（通常重合度 > 99%，仅保留独有补充项），并按 **严格 DNS 标签边界** 从中剔除第 2 层涉及的 AI 保护域（但保留 Google 第三方隔离广告变体与点穴广告域）；同时清理 `Top500 DIRECT` 与 `PROXY` 列表中与第 2、4、5、6 层冲突的条目（如将 `cloudflare.com` 从直连移至代理、移除过宽的 `DOMAIN-KEYWORD,aws`、确保 `amazon.cn,DIRECT` 在海外亚马逊规则之前）。
  3. **Shadowrocket（iOS）**：极速轻量版仅保留精选核心广告联盟（88 条核心 `CORE_AD_SUFFIXES` `REJECT`，含 2.3/1.5 层共 92 条拦截规则）；完整无冲突版保留去重清洗后的全量去广告列表（约 5.2~5.4 万条 `REJECT`，随上游库浮动）；默认执行 Apple 情况 A；均**只保留 LF (`\n`) 换行与 UTF-8 无 BOM 编码**，剔除 iOS 不支持的 `PROCESS-NAME`。
  4. **防误杀同动作去重原则**：构建器仅当祖先规则与当前规则**动作完全相同**时跳过冗余子域；绝不跨动作静默吞掉 `DIRECT` / `REJECT` / `PROXY` 例外项。

---

## 第 0 层：底层网络、DNS 与嗅探模板（规则匹配前生效）

### 1. FlClash / Mihomo (`config.yaml` 头部参考)
```yaml
mixed-port: 7890
mode: rule
log-level: info
ipv6: false
unified-delay: true

dns:
    enable: true
    ipv6: false
    enhanced-mode: fake-ip
    fake-ip-range: 198.18.0.1/16
    fake-ip-filter:
        - rule-set:cn-domain       # 必须为 behavior: domain
        - rule-set:private         # 必须为 behavior: domain
        - +.lan
        - +.local
        - localhost
        - +.localhost
        - +.msftconnecttest.com
        - +.msftncsi.com
        - +.stun.*.*
        - +.stun.*.*.*
    default-nameserver:
        - 223.5.5.5
        - 119.29.29.29
    nameserver:
        - "https://dns.google/dns-query#<PROXY_GROUP>"
        - "https://1.1.1.1/dns-query#<PROXY_GROUP>"
    nameserver-policy:
        # 1) 必应中国直连优先；Copilot + 6.1 微软代理特例 + Apple(--apple b) 强制走代理 DoH
        "+.cn.bing.com":
            - https://dns.alidns.com/dns-query
            - https://doh.pub/dns-query
        "+.copilot.microsoft.com":
            - "https://dns.google/dns-query#<PROXY_GROUP>"
            - "https://1.1.1.1/dns-query#<PROXY_GROUP>"
        # (...其余 Copilot / 6.1 微软代理特例与 Apple 后缀同上走代理 DoH)
        # 2) 通用微软后缀走国内 DoH（不放进 fake-ip-filter，直连微软免受美国边缘 CDN 高延迟）
        "+.microsoft.com":
            - https://dns.alidns.com/dns-query
            - https://doh.pub/dns-query
        # (...其余 MICROSOFT_COMMON_SUFFIXES 同上走国内 DoH)
        # 3) 兜底规则集（必须为 behavior: domain）
        "rule-set:cn-domain":      # 必须为 behavior: domain
            - https://dns.alidns.com/dns-query
            - https://doh.pub/dns-query
        "rule-set:private":        # 必须为 behavior: domain
            - https://dns.alidns.com/dns-query
            - https://doh.pub/dns-query
    proxy-server-nameserver:
        - https://223.5.5.5/dns-query
        - https://1.12.12.12/dns-query

sniffer:
    enable: true
    parse-pure-ip: true
    sniff:
        HTTP:
            ports: ["80", 8080-8880]
        QUIC:
            ports: ["443", "8443"]
        TLS:
            ports: ["443", "8443"]
    skip-domain:
        - +.mijia.cloud             # 注意不可写作带空格的 "Mijia Cloud"
        - +.push.apple.com
```
> **`rule-providers` `behavior` 与头部端口自检要点**：`ads`、`cn-domain`、`private` 需确认为 `domain`（若远端是纯域名）；`cn-ip` 为 `ipcidr`；`apple`、`claude`、`facebook`、`gemini`、`google`、`microsoft`、`openai`、`speedtest`、`telegram`、`tiktok`、`whatsapp`、`youtube` 等混合规则集需按实际返回内容准确设为 `classical`（或 `domain`），切忌将 `classical` 规则集塞进 `fake-ip-filter` / `nameserver-policy`。同时 `build_subscription.py` 会重置顶层标量并默认剥离原订阅中的 `allow-lan`、`port`、`socks-port`，减小局域网暴露面。

### 2. Shadowrocket (`[General]` 段)
```ini
[General]
ipv6 = false
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, fe80::/10, fc00::/7, localhost, *.local, *.lan, *.internal, *.home.arpa, captive.apple.com, sequoia.apple.com, seed-sequoia.siri.apple.com, *.ls.apple.com, *.push.apple.com
bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,233.252.0.0/24,224.0.0.0/4,255.255.255.255/32,::1/128,::ffff:0:0/96,::ffff:0:0:0/96,64:ff9b::/96,64:ff9b:1::/48,100::/64,2001::/32,2001:20::/28,2001:db8::/32,2002::/16,3fff::/20,5f00::/16,fc00::/7,fe80::/10,ff00::/8
dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query
fallback-dns-server = https://dns.google/dns-query, https://1.1.1.1/dns-query
hijack-dns = *:53
block-quic = all-proxy
always-real-ip = *.lan, *.local, localhost, *.localhost, *.home.arpa, *.msftconnecttest.com, *.msftncsi.com, *.srv.nintendo.net, *.stun.playstation.net, xbox.*.microsoft.com, *.xboxlive.com
```
> Shadowrocket 的 `[URL Rewrite]` 与 `[MITM]` 位于 `[Rule]` 最底部（见文末 **配置末尾段**）。

---

## 第 1 层：局域网 / 私有地址（双端最高优先级 `DIRECT`）

- **基础域名（双端共用）**：`DOMAIN,localhost,DIRECT`、`DOMAIN-SUFFIX,localhost,DIRECT`、`DOMAIN-SUFFIX,lan,DIRECT`、`DOMAIN-SUFFIX,local,DIRECT`、`DOMAIN-SUFFIX,home.arpa,DIRECT`
- **IPv4 私有网段（双端共用，全部带 `,no-resolve`）**：`0.0.0.0/8`、`10.0.0.0/8`、`100.64.0.0/10`、`127.0.0.0/8`、`169.254.0.0/16`、`172.16.0.0/12`、`192.168.0.0/16`、`224.0.0.0/4`、`240.0.0.0/4`
- **IPv6 私有网段（必须使用 `IP-CIDR6`，全部带 `,no-resolve`）**：`::/128`、`::1/128`、`fc00::/7`、`fe80::/10`、`ff00::/8`
- **FlClash 追加**：`RULE-SET,private,DIRECT`
- **Shadowrocket 内联补充（替代 `private` 规则集）**：
  - `DOMAIN` 路由器/微信：
    `instant.arubanetworks.com`, `setmeup.arubanetworks.com`, `asusrouter.com`, `router.asus.com`, `www.asusrouter.com`, `oasisauth.h3c.com`, `routerlogin.com`, `www.routerlogin.com`, `localhost.weixin.qq.com`, `localhost.work.weixin.qq.com`, `tplogin.cn`, `miwifi.com`, `www.miwifi.com`, `local.adguard.org`
  - `DOMAIN-SUFFIX` 后缀：
    `internal`, `localdomain`, `example`, `invalid`, `test`, `router.ctc`, `my.router`, `zte.home`, `tplinkwifi.net`, `tendawifi.com`, `plex.direct`（以及标准 RFC 反向解析 `.in-addr.arpa` 与 `.ip6.arpa` 域段）

---

## 第 1.5 层：QUIC 拦截与 QQ / 微信 UDP 白名单

### 1. FlClash 写法
```yaml
  - "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"
```
> **设计说明**：FlClash 仅阻断 UDP 443 促发 HTTP/3→TCP 回退，不影响 QQ/微信 `:8000`/`:80` 原生 UDP；刻意不加腾讯系 UDP 白名单，避免 `gdt.qq.com` 等广告埋点借 UDP 443 绕过第 3 层 `REJECT`。

### 2. Shadowrocket 写法（配合 `[General] block-quic = all-proxy`）
> **严格先放行后拦截**：仅放行腾讯 QQ / 微信直连 UDP，腾讯系 TCP 埋点与广告仍继续向下落入第 3 层 `REJECT`。
```ini
# 1) 放行腾讯 QQ / 微信 UDP 通信（语音/信令/短连接）
AND,((PROTOCOL,UDP),(DOMAIN-SUFFIX,qq.com)),DIRECT
AND,((PROTOCOL,UDP),(DOMAIN-SUFFIX,wechat.com)),DIRECT
AND,((PROTOCOL,UDP),(DOMAIN-SUFFIX,weixin.com)),DIRECT
AND,((PROTOCOL,UDP),(DOMAIN-SUFFIX,tenpay.com)),DIRECT
AND,((PROTOCOL,UDP),(DOMAIN-SUFFIX,servicewechat.com)),DIRECT
AND,((PROTOCOL,UDP),(DOMAIN-SUFFIX,qpic.cn)),DIRECT
AND,((PROTOCOL,UDP),(DOMAIN-SUFFIX,qlogo.cn)),DIRECT
AND,((PROTOCOL,UDP),(DOMAIN-SUFFIX,wechatapp.com)),DIRECT
# 2) 拦截其余所有非 QQ/微信的 UDP 443（QUIC），强制浏览器/App 回退至 TCP
AND,((PROTOCOL,UDP),(DEST-PORT,443)),REJECT-NO-DROP
```

---

## 第 2 层：主流 AI 全平台及母公司根域置顶（全部指向代理）

> 在 FlClash 中，2.1 / 2.2 / 2.3 末尾各自挂载 `RULE-SET,openai,<PROXY_GROUP>,no-resolve`、`RULE-SET,claude,<PROXY_GROUP>,no-resolve`、`RULE-SET,gemini,<PROXY_GROUP>,no-resolve`（`classical` 规则集一律带 `,no-resolve`）；**不要将 `RULE-SET,google` 放进第 2 层**（放进第 4.2 层；同时第 2.3 层采用**方案 B**：保留 `google.com`/`googleapis.com`/`gstatic.com` 等母域保障 Google AI 与未来新子域不断流，但紧贴其正上方点穴置顶 3 条谷歌自有广告/统计拦截规则）。Shadowrocket 默认内联以下所有精筛条目及 `--sr-source` 中的补充域名；若通过 `--rulesets-dir <目录>` 提供本地缓存的 `openai.yaml` / `claude.yaml` / `gemini.yaml` 等规则集，则会一并展开内联。

### 2.1 OpenAI (ChatGPT Web / App / Windows 客户端 / Codex CLI / Sora)
- `DOMAIN-SUFFIX`: `openai.com`, `chatgpt.com`, `ai.com`, `chat.com`, `oaistatic.com`, `oaiusercontent.com`, `sora.com`, `livekit.cloud`, `arkoselabs.com`, `openaiapi-site.azureedge.net`, `openaicom.imgix.net`
- `DOMAIN-KEYWORD`: `openai`
- `DOMAIN`: `browser-intake-datadoghq.com`, `chat.openai.com.cdn.cloudflare.net`, `openaicom-api-bdcpf8c6d2e9atf6.z01.azurefd.net`, `openaicomproductionae4b.blob.core.windows.net`, `production-openaicom-storage.azureedge.net`, `static.cloudflareinsights.com`
- `DOMAIN-SUFFIX`（上游 OpenAI 规则集内嵌配套组件）: `algolia.net`, `api.statsig.com`, `events.statsigapi.net`, `featuregates.org`, `identrust.com`, `intercom.io`, `intercomcdn.com`, `launchdarkly.com`, `observeit.net`, `segment.io`, `sentry.io`, `stripe.com`
  - *关于 `auth0.com` 的按需取舍*：上游 `openai` 规则集通常包含 `DOMAIN-SUFFIX,auth0.com`；但因为 `auth0.openai.com` 已被 `openai.com` 覆盖，放通整个 `auth0.com` 会使使用 Auth0 登录的所有第三方网站均走代理。对代理范围要求严格时可加 `--strict-auth0` 参数自动剔除裸 `auth0.com`。
- OpenAI 官方 IP/ASN（带 `,no-resolve`）：`IP-CIDR,24.199.123.28/32`, `IP-CIDR,64.23.132.171/32`, `IP-ASN,20473`
- FlClash 追加：`RULE-SET,openai,<PROXY_GROUP>,no-resolve`

### 2.2 Anthropic (Claude Web / App / Claude Code CLI)
- `DOMAIN-SUFFIX`: `anthropic.com`, `claude.ai`, `claude.com`, `clau.de`, `claudeusercontent.com`
- `DOMAIN-KEYWORD`: `claude`, `anthropic`
- `DOMAIN`: `cdn.usefathom.com`
- FlClash 追加：`RULE-SET,claude,<PROXY_GROUP>,no-resolve`

### 2.3 Google AI 及 Google 全系母域名（Gemini / Antigravity / AI Studio / DeepMind，含方案 B 点穴拦截）
- **方案 B 点穴置顶拦截（必须排在下方 `google.com` 与 `googleapis.com` 正上方，`REJECT`）**：
  - `DOMAIN-SUFFIX,adservice.google.com,REJECT`
  - `DOMAIN-SUFFIX,analytics.google.com,REJECT`
  - `DOMAIN-SUFFIX,crashlyticsreports-pa.googleapis.com,REJECT`
  > 设计原因：保留下方 `google.com`、`googleapis.com`、`gstatic.com` 等母域在第 2.3 层走向 `PROXY`，可确保 Gemini / Antigravity / AI Studio 的静态资源与未来新子域不会被第三方 `ads` 规则集误杀；同时通过上述 3 条精确子域规则率先截断 Google 自家下沉到主域上的广告与崩溃遥测，而独立域名形态的 Google 广告联盟（如 `doubleclick.net`、`googlesyndication.com`、`googleadservices.com`）与 `-cn` 变体本就不在母域范围内，会正常进入第 3 层 `REJECT`。
- **其余均为 `PROXY`**：
- `DOMAIN-SUFFIX`:
  `gemini.google.com`, `gemini.google`, `gemini.gstatic.com`, `antigravity.google`, `antigravity-unleash.goog`, `ai.studio`, `aistudio.google.com`, `makersuite.google.com`, `ai.google.dev`, `google.dev`, `deepmind.com`, `deepmind.google`, `generativeai.google`, `jules.google`, `jules.google.com`, `labs.google`, `labs.google.com`, `notebooklm.google`, `notebooklm.google.com`, `notebook.google`, `notebook.google.com`, `opal.google`, `opal.google.com`, `flow.google`, `flow.google.com`, `bard.google.com`, `stitch.withgoogle.com`, `cloudcode-pa.googleapis.com`, `proactivebackend-pa.googleapis.com`, `aisandbox-pa.googleapis.com`, `google.com`, `google`, `goog`, `googleapis.com`, `gstatic.com`, `googleusercontent.com`, `ggpht.com`, `withgoogle.com`, `1e100.net`, `gvt1.com`, `gvt2.com`, `recaptcha.net`
- `DOMAIN-KEYWORD`: `generativelanguage`, `alkalimakersuite`, `antigravity`
- FlClash 追加：`RULE-SET,gemini,<PROXY_GROUP>,no-resolve`

### 2.4 Meta AI、Meta 全系母域 & Microsoft Copilot 专属入口
- `DOMAIN-SUFFIX`:
  `muse.ai`, `meta.ai`, `llama.com`, `ai.meta.com`, `meta.com`, `facebook.com`, `fb.com`, `fb.me`, `fbcdn.net`,
  `copilot.microsoft.com`, `copilot.cloud.microsoft`, `designer.microsoft.com`, `copilotstudio.microsoft.com`,
  `forefront.ai`, `devv.ai`
- Meta 官方 ASN 网段（双端共用，带 `,no-resolve`）：`IP-ASN,32934`（FlClash 与 Shadowrocket 均会在本层补充输出）

### 2.4.1 xAI (Grok)
- `DOMAIN-SUFFIX`: `grok.com`, `x.ai`

### 2.4.2 其他主流独立 AI 服务（Perplexity / Groq / Midjourney / Cursor）
- `DOMAIN-SUFFIX`: `perplexity.ai`, `pplx.ai`, `groq.com`, `midjourney.com`, `cursor.com`, `cursor.sh`, `cursorapi.com`

### 2.5 AI 特性开关防误杀 & 流媒体短链保护（紧接第 3 层 `REJECT` 正上方）
- `DOMAIN-SUFFIX`: `statsig.com`, `statsigapi.net`, `statsigcdn.com`, `segment.com`, `sentry.io`, `disneyplus.bn5x.net`（其中 `sentry.io` 已先于 2.1 层置顶，`build_subscription.py` 生成时自动去重）
  > 说明：`disneyplus.bn5x.net` 会被第 3 层 `ads` 中的 `+.bn5x.net` 误拦，必须紧贴在 `ads` 正上方（放在第 4 层依然会被第 3 层截胡）。

---

## 第 3 层：广告拦截（`REJECT`）

- **FlClash / Mihomo**：
  - 核心主体：`RULE-SET,ads,REJECT`
  - 差集补全：当订阅已含 `RULE-SET,ads` 且**不传** `--ads-ruleset` 时，构建器直接信任 `ads` 规则集仅内联 88 条核心差集（总规则最精简，约 1,000 条）；若**传入**新鲜本地 `ads.yaml` 执行差集比对，则会将上游约 5.2~5.4 万条 `REJECT` 中 `ads.yaml` 尚未收录的独有条目一并内联（通常约 4,300~4,500 条，含 `17u.cn`、`ada.baidu.com`、`adgeo.163.com`、`alimama.alicdn.com`、`click.discord.com`、`click.redditmail.com`、`cm.jd.com`、`crs.baidu.com`、`kstj.baidu.com`、`market.aliyun.com`、Google `-cn` 广告变体及少数广告商 CIDR `,REJECT,no-resolve`），在远低于 5.2 万条全量体积的前提下补齐拦截盲区。
- **Shadowrocket（内联 `REJECT`）**：
  - **极速轻量版**：保留精选核心广告联盟与常见国内埋点（含独立 Google 广告域、`GOOGLE_CN_AD_VARIANTS`、`miaozhen.com`、`mmstat.com`、`cnzz.com`、`mintegral.com`、`gdt.qq.com`、`mobads.baidu.com`、`tanx.com`、`alimama.alicdn.com`、`pangolin-sdk-toutiao.com` 等 **88 条**核心 `CORE_AD_SUFFIXES` `REJECT` 规则，另含第 2.3 层 3 条精准拦截与第 1.5 层 QUIC 拦截）。
  - **完整无冲突版**：保留经冲突清理后的完整去广告库（约 5.2~5.4 万条 `REJECT`，随上游浮动）并补全上述核心项（含 `miaozhen.com` 等）。
- **必须保留的 Google `-cn` 与独立 Google 广告域（不得当成 `google` 代理白名单误清理）**：
  `googlesyndication-cn.com`, `google-analytics-cn.com`, `googletagmanager-cn.com`, `googletagservices-cn.com`, `googletraveladservices-cn.com`, `googlevads-cn.com`, `doubleclick-cn.net`, `doubleclick.cn`, `admob-cn.com`, `2mdn-cn.net`, `app-measurement-cn.com`, `googleads-cn.com`, `googleadservices-cn.com`, `googleadsserving.cn`, `doubleclick.com`, `admob.com`, `2mdn.net`, `googleanalytics.com`, `googleads.com`, `googletraveladservices.com`
- **必须遵守的三项清洗规范**：
  1. **严格 DNS 标签边界剔除第 2 层 AI 保护域**：使用精确后缀/域边界判定（`dom == sfx or dom.endswith("." + sfx)`），不得用粗放子串匹配（否则误删第三方 `openai`/`meta`/`google` 命名广告域）；仅保护第 2 层 AI 域与方案 B 已点穴规则外条目；
  2. **保留非四大 AI 第三方广告/埋点**：不扩大白名单范围，保留其余第三方统计与广告追踪拦截；
  3. **零散广告子域升级为精确父域**：例如将 `api.cupid.iqiyi.com` 升级为 `DOMAIN-SUFFIX,cupid.iqiyi.com,REJECT`，同步拦截 `t7z.cupid.iqiyi.com` 等贴片广告分支。

---

## 第 4 层：全球主流国外平台与苹果生态分支（全部指向代理）

> 所有条目指向 `PROXY`（Shadowrocket）或 `<PROXY_GROUP>`（FlClash）。

### 4.1 Twitter / X 全家桶
- `DOMAIN-SUFFIX`: `x.com`, `twitter.com`, `twimg.com`, `t.co`, `twitpic.com`, `periscope.tv`, `vine.co`, `twitter.jp`, `twttr.com`

### 4.2 YouTube & Google 扩展生态（Google 核心母域已在第 2.3 层置顶）
- `DOMAIN-SUFFIX`: `youtube.com`, `youtu.be`, `ytimg.com`, `googlevideo.com`, `youtube-nocookie.com`
- FlClash 追加：`RULE-SET,google,<PROXY_GROUP>,no-resolve`、`RULE-SET,youtube,<PROXY_GROUP>,no-resolve`

### 4.3 Instagram / Threads / WhatsApp（Meta/Facebook 核心母域已在第 2.4 层置顶）
- `DOMAIN-SUFFIX`: `instagram.com`, `cdninstagram.com`, `threads.net`, `whatsapp.com`, `whatsapp.net`
- FlClash 追加：`RULE-SET,facebook,<PROXY_GROUP>,no-resolve`、`RULE-SET,instagram,<PROXY_GROUP>,no-resolve`、`RULE-SET,whatsapp,<PROXY_GROUP>,no-resolve`

### 4.4 Telegram / Discord / Line / TikTok
- Telegram `DOMAIN-SUFFIX`: `t.me`, `telegram.org`, `telegram.me`, `tdesktop.com`, `telegra.ph`, `telesco.pe`
- Discord `DOMAIN-SUFFIX`: `discord.com`, `discord.gg`, `discordapp.com`, `discordapp.net`, `discordcdn.com`
- FlClash 追加：`RULE-SET,telegram,<PROXY_GROUP>,no-resolve`、`RULE-SET,tiktok,<PROXY_GROUP>,no-resolve`、`RULE-SET,line,<PROXY_GROUP>,no-resolve`（Shadowrocket 若传入包含对应 `.yaml` 的 `--rulesets-dir` 则一并展开内联；默认仅含上述内置 Telegram / Discord 条目与 `--sr-source` 中已有补充规则）

### 4.5 GitHub / HuggingFace / Docker / Reddit / Wikipedia / 开发者与知识社区
- `DOMAIN-SUFFIX`:
  `github.com`, `github.io`, `githubusercontent.com`, `githubassets.com`, `github.dev`,
  `huggingface.co`, `hf.co`, `docker.com`, `docker.io`, `v2ex.com`,
  `reddit.com`, `redd.it`, `redditmedia.com`, `redditstatic.com`,
  `wikipedia.org`, `wikimedia.org`, `wikidata.org`, `wiktionary.org`, `quora.com`, `medium.com`
- **Shadowrocket 必补域名**（须位于第 8.1 层 `aliyuncs.com,DIRECT` 之上）：
  `DOMAIN-SUFFIX,github-avatars.oss-cn-hongkong.aliyuncs.com,PROXY`
- FlClash 追加：`RULE-SET,github,<PROXY_GROUP>,no-resolve`

### 4.6 海外流媒体与测速
- Netflix `DOMAIN-SUFFIX`: `netflix.com`, `nflxvideo.net`, `nflximg.net`, `nflxext.com`, `nflxso.net`
- Disney+ `DOMAIN-SUFFIX`: `disney.com`, `disneyplus.com`, `bamgrid.com`, `dssott.com`
- Spotify `DOMAIN-SUFFIX`: `spotify.com`, `scdn.co`, `pscdn.co`
- Twitch `DOMAIN-SUFFIX`: `twitch.tv`, `ttvnw.net`, `jtvnw.net`
- Pixiv `DOMAIN-SUFFIX`: `pixiv.net`, `pximg.net`, `fanbox.cc`
- 测速（FlClash）：`RULE-SET,speedtest,<PROXY_GROUP>,no-resolve`

### 4.7 Apple 生态分支（双端按使用场景分叉）
- **A. Shadowrocket（iPhone 情况 A 主推：第 4.7 层仅美区独占内容走 `PROXY`）**：
  - Apple Intelligence / Siri AI：`apple-relay.akamaized.net`, `apple-relay.cloudflare.com`, `apple-relay.fastly-edge.com`, `cp4.cloudflare.com`, `guzzoni.apple.com`, `smoot.apple.com`
  - Apple News：`apple.news`, `news-edge.apple.com`, `apple.comscoreresearch.com`
  - Apple TV+：`tv.apple.com`, `play-edge.itunes.apple.com`, `uts-api.itunes.apple.com`, `np-edge.itunes.apple.com`, `play-cdn.itunes-apple.com.akadns.net`
  > 注意：App Store、iCloud 与 Apple CIDR 不放此处，移交下方 **第 6.0 层**走 `DIRECT`。
- **B. FlClash（Windows / Android 桌面端：第 4.7 层全量 Apple 走 `<PROXY_GROUP>`）**：
  - `DOMAIN-SUFFIX`: `apple.com`, `icloud.com`, `icloud-content.com`, `mzstatic.com`, `cdn-apple.com`, `aaplimg.com`, `apple-dns.net`, `apple-mapkit.com` + `RULE-SET,apple,<PROXY_GROUP>,no-resolve`
  > 配合第 0 层 `dns.nameserver-policy` 将 Apple 常见后缀强制指定代理 DoH（`#<PROXY_GROUP>`），避免被 `cn-domain` 规则集中残留的 Apple/`mzstatic` 条目截胡到国内 DoH。

---

## 第 5 层：IP / DNS / WebRTC 检测站清单（36 条，强制代理）

> 必须排在 **第 6 层直连白名单** 与 **第 8 层 `GEOIP,CN`** 之前，确保检测站直接走代理、不触发本机或直连探测。全部使用 `DOMAIN-SUFFIX,<domain>,<PROXY>`：

`1ms.dog`, `ipqs.com`, `iplocate.io`, `ipinfo.io`, `ip.sb`, `ping0.cc`, `ip-api.com`, `ipapi.co`, `ipapi.is`, `ipapi.com`, `ipwho.is`, `ipwhois.app`, `ipdata.co`, `ipgeolocation.io`, `ifconfig.me`, `ifconfig.co`, `icanhazip.com`, `ipify.org`, `ident.me`, `myexternalip.com`, `ipchicken.com`, `whatismyipaddress.com`, `whatismyip.com`, `wtfismyip.com`, `whatismyip.akamai.com`, `checkip.amazonaws.com`, `ip.me`, `ip.gs`, `ipcheck.ing`, `ip.skk.moe`, `db-ip.com`, `myip.com`, `dnsleaktest.com`, `ipleak.net`, `browserleaks.com`, `browserleaks.org`

---

## 第 6 层：Apple 直连（仅情况 A）+ 微软特例 + Top500 直连白名单

### 6.0 Apple / App Store / iCloud 兜底直连（仅 Shadowrocket 情况 A，→ `DIRECT`）
- `DOMAIN-SUFFIX`: `apple.com`, `icloud.com`, `icloud-content.com`, `mzstatic.com`, `cdn-apple.com`, `aaplimg.com`, `apple-dns.net`, `apple-mapkit.com`, `itunes-apple.com.akadns.net`, `origin-apple.com.akadns.net`, `push-apple.com.akadns.net`, `apple-support.akadns.net`
- `DOMAIN-KEYWORD`: `apple-support.akadns.net`, `apple.com.akadns.net`, `apple.com.edgekey.net`, `buy.itunes.apple.com`, `smp-device`, `testflight`, `icloud.com.akadns.net`
- Apple 官方 IPv4 / IPv6（全部带 `,no-resolve`）：
  - `IP-CIDR`: `139.178.128.0/18`, `144.178.0.0/19`, `144.178.36.0/22`, `144.178.48.0/20`, `17.0.0.0/8`, `192.35.50.0/24`, `198.183.17.0/24`, `205.180.175.0/24`, `63.92.224.0/19`, `65.199.22.0/23`
  - `IP-CIDR6`: `2403:300::/32`, `2620:149::/32`, `2a01:b740::/32`

### 6.1 微软特定分流（双端一致，须排在第 8 层 `microsoft` 前）
- `DOMAIN-SUFFIX,cn.bing.com,DIRECT`
- 以下 8 条走代理（`PROXY` / `<PROXY_GROUP>`）：
  `bing.com`, `api.onedrive.com`, `dm.files.1drv.com`, `skyapi.live.net`, `odc.officeapps.live.com`, `centralus1.mediap.svc.ms`, `mobile.pipe.aria.microsoft.com`, `location.microsoft.com`

### 6.2 Top500 可直连网站白名单及必调修正（→ `DIRECT`）
- **移除 `cloudflare.com` 直连**：将 `DOMAIN-SUFFIX,cloudflare.com` 从 Top500 直连白名单**改为走代理**（防 Cloudflare Turnstile 与 `stun.cloudflare.com` WebRTC 泄露本机 IP）。
- **开头保底 `DOMAIN-SUFFIX,amazon.cn,DIRECT`**：确保排在第 7 层亚马逊海外规则之上。
- **可选项 `DOMAIN-SUFFIX,zoom.us,DIRECT`**：国内参会保持 `DIRECT`；若主要参与海外 Zoom 会议且直连卡顿时可改为代理。

---

## 第 7 层：其余海外网站代理列表（全部指向代理）

> 承接上游 `sr_top500_whitelist_ad.conf` 剔除冲突后的其余海外域名与少量海外 IP/CIDR（所有 `IP-CIDR` / `IP-CIDR6` 必须带 `,no-resolve`），包括 `cloudflare.com` 代理保障及长尾海外媒体/开发/AWS 明确域/流媒体（如 `cloudfront.net`、Disney 各国子域、Kindle / PrimeVideo 等）。

- **必须执行的清洗规则**：
  1. **剔除过宽关键词 `DOMAIN-KEYWORD,aws` 与 `DOMAIN-KEYWORD,amazon`**：实测 `aws` 会误杀 `draws.io`、`laws.com` 等非 AWS 域名；`amazon` 会在第 7 层截胡 `.cn` 规则，导致 `amazonaws.cn`、`amazonpay.cn`、`z.cn` 绕美（海外 Amazon 各国域已有显式后缀规则及第 9 层兜底）；
  2. **剔除已被第 3 层 `ads` 截胡的冗余广告项**，且从 `PROXY` 中剔除 Google `-cn` 广告变体与核心广告后缀，避免无效重复或从 `google.yaml` 泄露；
  3. **若为 Shadowrocket 情况 A（iOS 默认）**，必须按精确后缀边界从中剔除第 6.0 层已设为 `DIRECT` 的通用 Apple 域名（如通用 `*.apple.com.akadns.net`、`itunes-apple.com.akadns.net`、`icloud.com`、`cdn-apple.com` 等），保留的仅为美区独占条目（已在第 4.7 层置前）。

---

## 第 8 层：国内分流（`DIRECT`）

### 8.0 基础国内规则集与大厂直连
- **`.cn` 顶级域直连**：`DOMAIN-SUFFIX,cn,DIRECT`（FlClash 位于 8.0 开头；Shadowrocket 位于第 8.1 层末尾、`GEOIP,CN` 正上方）
- **FlClash / Mihomo 追加**：
  - `RULE-SET,microsoft,DIRECT,no-resolve`（Microsoft 通用服务直连；第 2.4 层 Copilot 4 域与第 6.1 层国际版 Bing / OneDrive 等 8 域，合计 12 域已在前面优先走代理）
  - 字节跳动系规则集（若原生订阅含字节/抖音相关 provider 则引用并带 `,no-resolve`，否则自动内联 13 条 `BYTEDANCE_COMMON_SUFFIXES` 兜底 `DIRECT`）
  - 国产 AI 与高频办公直连补充（`yuque.com` 及下方国产 AI 后缀，排在 `cn-domain` 前保障低延迟直连）
  - `RULE-SET,cn-domain,DIRECT`
- **Shadowrocket 说明**：iOS PacketTunnel 扩展受严格系统内存配额约束，不能内联 11 万条 `cn-domain`，于 **8.0 层**先内联微软通用（14 条或可选 `microsoft.yaml`）与字节系（13 条），再由下方 **8.1 层**精筛 235 条高频非 `.cn` 国内域名（在 `--sr-source` Top500 之外拾遗补缺）、13 条国产 AI 及 `DOMAIN-SUFFIX,cn,DIRECT` 合计 249 条规则承接。

### 8.1 Shadowrocket 国内主流 `.com`/`.net`、国产 AI 与 CDN 直连补全

> 用于弥补 iOS 无法内联 11 万条 `cn-domain` 且 `GEOIP,CN,DIRECT,no-resolve` 不再预解析域名的问题，紧接在第 8.0 层之后、第 8.2 层 `GEOIP,CN,DIRECT,no-resolve` 正上方（对应代码 `SR_CN_NON_CN_235` 含 235 域——含与 1.5 层对齐的 `servicewechat.com`、`wechatapp.com`——并与 13 条国产 AI 及 `DOMAIN-SUFFIX,cn` 构成 **8.1 段共 249 条规则**；`baidu.com`/`taobao.com`/`qq.com`/`bilibili.com` 等头部大站依赖 `--sr-source` Top500 在第 6.2 层兜底，下方字节括号提及的 5 个兜底域则由**第 8.0 层** `BYTEDANCE_COMMON_SUFFIXES` 输出）。如与第 4.5 层的 `github-avatars.oss-cn-hongkong.aliyuncs.com`（跨动作例外）或前序白名单、`bytedance.com` / `bytednsdoc.com` 等条目存在重叠，`scripts/build_subscription.py` 的同动作去重器仅跳过**动作完全相同**的冗余规则，绝不误杀跨动作例外规则。

- **国产 AI（双端共用，统一走 `DIRECT` 免绕美/防海外 IP 限流）**：`deepseek.com`, `doubao.com`, `volcengine.com`, `volccdn.com`, `kimi.com`, `tongyi.com`, `qianwen.com`, `minimaxi.com`, `hailuoai.com`, `baichuan-ai.com`, `sensetime.com`, `lingyiwanwu.com`, `stepfun.com`（`.cn` AI 站点如 `moonshot.cn`、`bigmodel.cn`、`chatglm.cn`、`coze.cn` 由 `.cn,DIRECT` 一并覆盖）
- **腾讯 / 微信 / DNSPod / 视频与云**：`tencent.com`, `tencent-cloud.net`, `wechat.com`, `weixin.com`, `servicewechat.com`, `wechatapp.com`, `myqcloud.com`, `qcloud.com`, `tenpay.com`, `dnspod.com`, `dnspod.net`, `ddnspod.com`, `dns.pub`, `doh.pub`, `dot.pub`, `gtimg.com`, `weiyun.com`, `foxmail.com`, `soso.com`, `wetv.vip`, `wetvinfo.com`, `smtcdns.com`, `smtcdns.net`, `cdntips.com`, `cdntips.net`
- **阿里 / 淘宝 / 支付宝 / 高德 / 优酷 / 语雀**：`tmall.com`, `tmall.hk`, `alipay.com`, `alipayobjects.com`, `alicdn.com`, `aliyun.com`, `aliyuncs.com`, `alidns.com`, `alibabacloud.com`, `alibabagroup.com`, `1688.com`, `amap.com`, `autonavi.com`, `ele.me`, `dingtalk.com`, `yuque.com`, `youku.com`, `ykimg.com`, `tudou.com`, `cainiao.com`, `fliggy.com`, `ucweb.com`, `xiami.com`, `aliapp.org`, `kunluncan.com`
- **字节 / 汽水 / 电商（含除字节规则集外的日志实测漏网项）**：`qishui.com`, `ecombdpage.com`（若订阅无字节规则集则还需保留 `bytedance.com`, `bytednsdoc.com`, `douyin.com`, `toutiao.com`, `feishu.cn` 等）
- **百度 / 京东 / 网易**：`bdstatic.com`, `baidustatic.com`, `bcebos.com`, `baidupcs.com`, `baidubce.com`, `bdimg.com`, `yunjiasu-cdn.net`, `nuomi.com`, `shifen.com`, `jomodns.com`, `jd.com`, `360buyimg.com`, `360buy.com`, `jdcloud.com`, `jcloudstatic.com`, `163.com`, `126.com`, `126.net`, `127.net`, `netease.com`, `ydstatic.com`, `youdao.com`, `lofter.com`
- **视频 / 社交 / 资讯 / 社区**：`bilivideo.com`, `biliapi.net`, `hdslb.com`, `acg.tv`, `iqiyi.com`, `iqiyipic.com`, `qy.net`, `71.am`, `71edge.com`, `mgtv.com`, `hunantv.com`, `hitv.com`, `imgo.tv`, `sohu.com`, `sohucs.com`, `sogou.com`, `sogo.com`, `sina.com`, `sinaapp.com`, `weibocdn.com`, `zhihu.com`, `zhimg.com`, `douban.com`, `doubanio.com`, `xiaohongshu.com`, `xhscdn.com`, `hupu.com`, `ngabbs.com`, `chiphell.com`, `smzdm.com`, `ithome.com`, `jianshu.com`, `36kr.com`, `huxiu.com`, `sspai.com`, `ifanr.com`, `caixin.com`, `guokr.com`, `kuaishou.com`, `yximgs.com`
- **生活 / 电商 / 出行 / 招聘**：`meituan.com`, `meituan.net`, `sankuai.com`, `dianping.com`, `pinduoduo.com`, `yangkeduo.com`, `didiglobal.com`, `xiaojukeji.com`, `udache.com`, `ctrip.com`, `qunar.com`, `elong.com`, `ly.com`, `mafengwo.com`, `suning.com`, `vip.com`, `dangdang.com`, `dewu.com`, `poizon.com`, `sf-express.com`, `zto.com`, `yundaex.com`, `kuaidi100.com`, `58.com`, `anjuke.com`, `ke.com`, `lianjia.com`, `zhipin.com`, `bosszhipin.com`, `zhaopin.com`, `liepin.com`
- **手机厂商 / 办公 / 网盘 / 推送**：`mi.com`, `miui.com`, `xiaomi.com`, `xiaomi.net`, `hicloud.com`, `dbankcdn.com`, `vmall.com`, `myhuaweicloud.com`, `huaweicloud.com`, `hwclouds-dns.com`, `oppo.com`, `oppomobile.com`, `heytap.com`, `vivo.com`, `meizu.com`, `lenovo.com`, `wps.com`, `kingsoft.com`, `360.com`, `360safe.com`, `qhimg.com`, `qhres.com`, `115.com`, `xunlei.com`, `sandai.net`, `lanzou.com`, `ctfile.com`, `getui.com`
- **游戏 / 音频 / 直播**：`mihoyo.com`, `miyoushe.com`, `tapimg.com`, `kugou.com`, `ximalaya.com`, `xmcdn.com`, `lizhi.fm`, `yy.com`, `huya.com`, `douyu.com`, `3dmgame.com`, `gamersky.com`, `ali213.net`, `4399.com`, `7k7k.com`, `papegames.com`, `kurogame.com`, `hypergryph.com`
- **金山云 / 七牛 / 又拍 / 网宿 / 公共 CDN / 开发 / 金融 / 学习**：`ksyungslb.com`, `ksyun.com`, `ks-cdn.com`, `cmbchina.com`, `ccb.com`, `abchina.com`, `bankcomm.com`, `pingan.com`, `unionpay.com`, `95516.com`, `10086.com`, `cctv.com`, `xinhuanet.com`, `csdn.net`, `gitee.com`, `cnblogs.com`, `segmentfault.com`, `oschina.net`, `nowcoder.com`, `npmmirror.com`, `cnpmjs.org`, `qiniucdn.com`, `qiniudn.com`, `clouddn.com`, `qbox.me`, `upyun.com`, `upaiyun.com`, `wangsu.com`, `wscdns.com`, `chinacache.com`, `ourdvs.com`, `bootcss.com`, `staticfile.org`, `114dns.com`, `ipip.net`, `chaoxing.com`, `cnki.net`, `icourse163.org`, `xuetangx.com`, `xueqiu.com`, `eastmoney.com`, `keep.com`, `gotokeep.com`

### 8.2 国内 IP 兜底与防泄露（全部带 `,no-resolve`）
- **FlClash / Mihomo**：
  - `RULE-SET,cn-ip,DIRECT,no-resolve`
  - `GEOIP,CN,DIRECT,no-resolve`（若已配备最新 `cn-ip` 规则集且处于 iOS Clash Mi 等极端低内存环境需节省 5–8MB 内存，可按需省略重复的 `GEOIP,CN`）
- **Shadowrocket**：
  - `GEOIP,CN,DIRECT,no-resolve`

---

## 第 9 层：终极兜底规则（其余未知海外网站一律走代理）

- **FlClash / Mihomo**：
  ```yaml
  - "MATCH,<PROXY_GROUP>"
  ```
- **Shadowrocket**：
  ```ini
  FINAL,PROXY
  ```

---

## 配置末尾段（仅 Shadowrocket：`[URL Rewrite]` 与 `[MITM]`）

> 严格位于 `[Rule]` 第 9 层 `FINAL,PROXY` 之后，仅针对 `google.cn` 执行 302 重定向。

```ini
[URL Rewrite]
^https?://(www.)?(g|google)\.cn https://www.google.com 302

[MITM]
hostname = *.google.cn
```
