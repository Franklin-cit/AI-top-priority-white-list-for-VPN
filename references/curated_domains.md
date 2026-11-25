# 核心规则模板与精筛域名清单 (Curated Rules & Domains)

> 本文档按实际 **自上而下、命中即停** 的生效顺序，完整描述以 **`v2fly/domain-list-community`（DLC）** 为唯一骨干底层构建的第 0 层底层模板与第 1–9 层分流流水线。所有示例均已剥离个人节点与隐私信息；FlClash 示例中 `<PROXY_GROUP>` 代表主代理策略组，Shadowrocket 使用内置策略名 `PROXY`。

---

## 前置：DLC 数据源与跨层清洗原则

- **唯一骨干数据源**：官方 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)（支持 Release `dlc.dat_plain.yml` + `.sha256sum` 校验，或本地克隆 `data/` 目录）。不再依赖旧版外部大型白名单规则文件或远端 HTTP `rule-providers`。
- **同动作安全去重（`RuleEmitter`）**：仅当祖先规则与当前规则**动作完全相同**时省略冗余规则；绝不跨动作吞并例外规则。所有 `IP-CIDR` / `IP-CIDR6` 入库前统一按 `ipaddress.ip_network(..., strict=False)` 归零主机位。
- **DLC 正则转义与量词展开**：读取 `dlc.dat_plain.yml` 时自动将 YAML 双引号中的 `\\S` / `\\.` 解码为单反斜杠 `\S` / `\.`；输出 Shadowrocket 规则时自动将 `{m,n}` / `{m,}` 量词展开消除逗号（避免逗号分隔解析器截断），输出 FlClash YAML 规则时使用单引号 `'DOMAIN-REGEX,...'` 直接保留原始正则避免二次转义。

---

## 第 0 层：底层网络、DNS 与嗅探模板

### 1. FlClash / Mihomo (`config.yaml` 头部模板)
- `ipv6: false`、`unified-delay: true`、`tcp-concurrent: true`、`keep-alive-interval: 15`、`keep-alive-idle: 600`、`log-level: info`、`mode: rule`、`profile: { store-selected: true, store-fake-ip: true }`；
- `dns`：`enable: true`、`ipv6: false`、`enhanced-mode: fake-ip`、`fake-ip-range: 198.18.0.1/16`；
  - `default-nameserver`：国内纯 IPv4 引导解析器 **`223.5.5.5`** 与 **`119.29.29.29`**（禁止填写域名、IPv6 或海外/废弃 DNS）；
  - `fake-ip-filter` 包含 `rule-set:cn-domain`、`rule-set:private`（均引用文内 `type: inline, behavior: domain` 规则集）与 `+.lan`/`+.local`/`localhost`/`+.localhost`/`+.msftconnecttest.com`/`+.msftncsi.com`/`+.stun.*.*`/`+.stun.*.*.*`；
  - 默认 `nameserver`：纯 IP 加密 DoH **`https://1.1.1.1/dns-query#<PROXY_GROUP>`** 与 **`https://8.8.8.8/dns-query#<PROXY_GROUP>`**（规避域名型 `dns.google` 触发国内明文查询污染风险）；
  - `nameserver-policy` 按 **最精确优先** 分流：
    1. 高频国内刷屏广告域前置 `0ms` 短路（共 13 域：精确单主机 `FLCLASH_DNS_AD_REJECT_EXACT` `applog.zijieapi.com` + 12 条后缀 `FLCLASH_DNS_AD_REJECT_SUFFIXES`：`+.log.zijieapi.com`、`+.a.market.xiaomi.com`、`+.ad.xiaomi.com`、`+.tracking.miui.com`、`+.adv.sec.miui.com`、`+.sentry.d.xiaomi.net`、`+.ctobsnssdk.com`、`+.pangolin-sdk-toutiao1.com`、`+.pangolin-sdk-toutiao.com`、`+.pangolin-dsp-toutiao.com`、`+.mcdn.bilivideo.cn`、`+.rmonitor.qq.com`）→ `rcode://name_error`
    2. `+.cn.bing.com` 与 `DLC/bing@cn`（共 8 域：`+.cn.bing.com`、`+.bing.com.cn`、`+.bj1.api.bing.com`、`+.cn.bing.net`、`+.cn.mm.bing.net`、`+.ditu.live.com`、`+.r.bing.com`、`+.th.bing.com`）→ `https://223.5.5.5/dns-query`、`https://223.6.6.6/dns-query`
    3. Copilot（`MICROSOFT_AI_SUFFIXES` 4 域）+ 第 6.1 层微软代理 8 域 + Apple（`--apple b` 为 `APPLE_COMMON_SUFFIXES` + `APPLE_SAFEBROWSING_OHTTP_SUFFIXES` 共 10 域；`--apple a` 仅美区独占 `APPLE_SR_US_ONLY_SUFFIXES` 19 域，通用 Apple/iCloud 走国内 DoH）→ 代理 DoH `#<PROXY_GROUP>`
    4. 通用微软（`MICROSOFT_COMMON_SUFFIXES` 24 域，含 `microsoft.com`/`windowsupdate.com`/`msftconnecttest.com`/`msftncsi.com`/`office.com`/`msedge.net`）→ 国内 DoH `223.5.5.5`/`223.6.6.6`
    5. `+.in-addr.arpa` / `+.ip6.arpa` → `rcode://name_error`
    6. `rule-set:cn-domain` & `rule-set:private` → 国内 DoH `223.5.5.5`/`223.6.6.6`
  - `proxy-server-nameserver`：`https://223.5.5.5/dns-query`、`https://223.6.6.6/dns-query` 与 `tls://223.5.5.5:853`（高可用阿里纯 IP DoH/DoT 组合，替换在移动端易超时的 `1.12.12.12`）；
- `sniffer`：`enable: true`、`force-dns-mapping: true`、`parse-pure-ip: true`，`HTTP` 仅限 `["80", "8080"]`，`QUIC`/`TLS` 监听 `["443", "8443"]`，`skip-domain` 含 `+.mijia.cloud`、`+.push.apple.com`、`+.mcdn.bilivideo.cn`、`data.bilibili.com`、`www.workbuddy.cn`、`long.weixin.qq.com` 等 15 条；
- `proxies`：为 `type: vless` 节点统一升级/补齐 `packet-encoding: xudp`；
- `proxy-groups`：自动将 `http://` 测速链接升级为 `https://`，`url-test`/`fallback`/`load-balance` 组补全 `lazy: true` 与 `interval >= 300s`，并自动扁平化仅含单一节点的冗余测速子组及不可达孤儿组；
- `rule-providers`：仅保留本地 **`private`** 与 **`cn-domain`**（均为 `type: inline, behavior: domain`；含 `DLC/cn` + `DLC/category-ai-cn` + 自动差集 Delta `113` 域，自动剥离 `DLC_CN_EXCLUDED_DOMAINS` 6 域及第 3 层广告/PCDN 域以免污染 `fake-ip-filter`，正则表达式不在 `payload:` 中而是写到 `rules:`）。

### 2. Shadowrocket (`[General]` 段)
- `ipv6 = false`、`prefer-ipv6 = false`、`bypass-system = true`、`hijack-dns = *:53`、`block-quic = all-proxy`、`dns-direct-fallback-proxy = false`；
- `dns-server = https://223.5.5.5/dns-query#no-h3`；
- `fallback-dns-server = https://223.6.6.6/dns-query#no-h3`（已移除移动网络 100% 超时的 `1.12.12.12`）。

---

## 第 1 层：局域网 / 私有地址（`DIRECT`）

- 9 个 IPv4 私有网段 + 5 个 IPv6 私有网段（`IP-CIDR6`，全带 `,no-resolve`）+ `localhost`/`*.lan`/`*.local`/`*.home.arpa`；
- FlClash 追加 `RULE-SET,private,DIRECT` + `DLC/private` 正则规则；Shadowrocket 全量内联 `DLC/private` 域与正则规则。

---

## 第 1.5 层：QUIC / PCDN 拦截与 QQ / 微信 UDP 白名单

1. 前置阻止腾讯广告 UDP：`gdt.qq.com`、`e.qq.com`、`bugly.qq.com`（FlClash 限 UDP 443 -> `REJECT`；SR 限 `PROTOCOL,UDP` -> `REJECT-NO-DROP`）；
2. 放行腾讯系 UDP：`qq.com`、`wechat.com`、`weixin.com`、`tenpay.com`、`servicewechat.com`、`qpic.cn`、`qlogo.cn`、`wechatapp.com`（FlClash 额外带 9 个微信/QQ 进程 `+ (GEOIP,CN,no-resolve)` 兜底 -> `DIRECT`）；
3. 拦截其余非 QQ/微信 HTTP/3 QUIC（UDP 443）与抖音 PCDN 端口 `:8567`（FlClash 同时拦截 `SRC-PORT,8567` 与 `DST-PORT,8567`；SR 拦截 `DEST-PORT,8567`）。

---

## 第 2 层：AI 全平台与组 ① 必要组件（`PROXY`，置顶于第 3 层之上）

> **三大隔离原则**：只将 **组 ① 必要功能组件** 放入第 2 层；Google/OpenAI 明确遥测与广告采用顶部精确拦截（**组 ②**）`REJECT`；客户端报错与问卷遥测（**组 ③**）全数落入第 3 层 `REJECT`。

- **2.1 OpenAI（含 `DLC/openai` `@-ads,@-telemetry` + 组 ① 组件）**：
  - 顶部精确拦截：`DOMAIN,openai.qualtrics.com,REJECT`（防被 `DOMAIN-KEYWORD,openai` 放行）
  - 核心：`openai.com`、`chatgpt.com`、`ai.com`、`chat.com`、`oaistatic.com`、`oaiusercontent.com`、`sora.com`、`livekit.cloud`、`arkoselabs.com`、`openaiapi-site.azureedge.net`、`openaicom.imgix.net`、`DOMAIN-KEYWORD,openai` + 5 条精确域名 + `DLC/openai`
  - 组 ① 配套：`algolia.net`、`api.statsig.com`、`events.statsigapi.net`、`featuregates.org`、`identrust.com`、`intercom.io`、`intercomcdn.com`、`launchdarkly.com`、`observeit.net`、`stripe.com`（`auth0.openai.com` 已由 `openai.com` 覆盖；仅传 `--broad-auth0` 才加宽 `auth0.com`）
  - OpenAI IP/ASN（`,no-resolve`）：`24.199.123.28/32`、`64.23.132.171/32`、`IP-ASN,20473`
- **2.2 Anthropic（含 `DLC/anthropic` `@-ads,@-telemetry`）**：
  - `anthropic.com`、`claude.ai`、`claude.com`、`clau.de`、`claudeusercontent.com`、`DOMAIN-KEYWORD` (`claude`/`anthropic`)、`DOMAIN,cdn.usefathom.com`
- **2.3 Google AI & 母域（方案 B 顶部精确拦截 + `DLC/google-deepmind` `@-ads,@-telemetry`）**：
  - **方案 B 顶部精确置顶 `REJECT`（11 条固定锚点 + `DLC/google@ads/@telemetry` 内 Google 母域条目，故意豁免 `video-stats.video.google.com`）**：
    `adservice.google.com`, `analytics.google.com`, `crashlyticsreports-pa.googleapis.com`, `clientmetrics-pa.googleapis.com`, `imasdk.googleapis.com`, `mail-ads.google.com`, `ogads-pa.googleapis.com`, `pagead.l.google.com`, `partnerad.l.google.com`, `proxy-safebrowsing.googleapis.com`, `www-google-analytics.l.google.com`（及 DLC `adtrafficquality.google`、`mobileads.google.com`、`firebaselogging*.googleapis.com` 等）
  - 其余 AI 与 Google 母域（`GOOGLE_AI_AND_PARENT_SUFFIXES` 42 条后缀 + 3 条关键词 + `DLC/google-deepmind` 49 条）全部 `PROXY`。
- **2.4 Meta AI / Copilot / xAI / 独立 AI + `DLC/category-ai-!cn`（`@-ads,@-telemetry`）**：
  - `META_COPILOT_SUFFIXES`（共 16 条）+ `IP-ASN,32934,PROXY,no-resolve`：
    - Meta AI + Meta 母域 + 独立 AI（12 条：`muse.ai`、`meta.ai`、`metaaivm.com`、`llama.com`、`ai.meta.com`、`meta.com`、`facebook.com`、`fb.com`、`fb.me`、`fbcdn.net`、`forefront.ai`、`devv.ai`）
    - 微软 AI（4 条：`copilot.microsoft.com`、`copilot.cloud.microsoft`、`designer.microsoft.com`、`copilotstudio.microsoft.com`，不代理 `m365.cloud.microsoft`）
  - xAI & 独立/国际 AI：`grok.com`、`x.ai`、`perplexity.ai`、`pplx.ai`、`groq.com`、`midjourney.com`、`cursor.com`、`cursor.sh`、`cursorapi.com`、`character.ai`、**`kimi.ai`、`moonshot.ai`、`minimax.io`**
- **2.5 特性开关 & 流媒体短链保护**：
  - `statsig.com`、`statsigapi.net`、`statsigcdn.com`、`disneyplus.bn5x.net`（紧贴第 3 层 `REJECT` 正上方；`sentry.io`/`segment.io` 已移至第 3 层）。

---

## 第 3 层：轻量高精准去广告 + 客户端遥测 + PCDN（双端约 978 条 `REJECT`）

- **广告与遥测合并清单**：
  - **组 ③ 客户端遥测（9 条）**：`browser-intake-datadoghq.com`、`browser-intake-us5-datadoghq.com`、`http-intake.logs.us5.datadoghq.com`、`o33249.ingest.sentry.io`、`o33249.ingest.us.sentry.io`、`o1158394.ingest.us.sentry.io`、`copilot-telemetry-service.githubusercontent.com`、`copilot-telemetry.githubusercontent.com`、`openai.qualtrics.com`
  - **112 条核心联盟后缀 `CORE_AD_SUFFIXES`**：含 Google 独立广告域与 14 条 `-cn` 广告变体、Apple/ByteDance/Tencent/Baidu/Alibaba/Umeng/Segment/CSJ/DoubleVerify/追踪广告网络（`csjplatform.com`、`segment.io`、`segment.com`、`umeng.com`、`umengcloud.com`、`gdt.qq.com`、`e.qq.com`、`bugly.qq.com`、`pangolin-sdk-toutiao*.com`、`dv.tech`、`doubleverify.com`、`crazyegg.com`、`ethicalads.io`、`hsadspixel.net`、`hs-analytics.net`、`collect.wpsmail.net` 等）
  - **16 条精确遥测/死域/畸形端 `LAYER3_EXACT_REJECT_DOMAINS`**：含 `status-ipv6.jpush.cn`、`hilo.bilibili.com`、`hif-dliq.deepseek.com`、`aweme.snssdk.com%28null%29`、精确 `dutils.com` 上报子域（豁免 `api-verify.dutils.com` 与 `sdk-push.dutils.com`）、以及纯遥测/死域主机名（`applog.zijieapi.com`、`log.snssdk.com`、`apmplus.volces.com`、`unitelogreport.reader.qq.com`、`dw-online.ksosoft.com`、`shuc-android.ksord.com`、`pre-api.miui.security.xiaomi.com`）
  - **DLC 高精准广告**：`DLC/category-ads-all` + 15 家主流厂商 `@ads`（`google`、`bytedance`、`tencent`、`xiaomi`、`apple`、`baidu`、`alibaba`、`meta`、`microsoft`、`netease`、`jd`、`iqiyi`、`kuaishou`、`bilibili`、`qihoo360`）
  - **严格豁免（永不拦截）**：`DLC/category-httpdns-cn`（如 `httpdns.bilivideo.com`、`dns.weixin.qq.com.cn`）+ 6 条功能 API/推送（`graph.instagram.com`、`graph-fallback.instagram.com`、`push.qq.com`、`mpush.qq.com`、`cloudpush.iqiyi.com`、`mipcache.bdstatic.com`）+ 第 2 层 AI 保护集（`domain_in_suffix_set` 严格标签边界）
- **3.1 P2P/STUN 刷屏降噪（37 条）**：14 条精确 `DOMAIN`（B 站 STUN/Tracker + 6 条火山引擎 `ndcpp.com` 脑控域）+ 21 条边缘 PCDN 后缀（`mcdn.bilivideo.cn`、`pkoplink.com`、抖音轮换 `ankltoken.com`/`yingt.fun` 等）+ 2 条关键词（`live-p2p-tracker`、`ccc-live-tracker`）。

---

## 第 4 ~ 5 层：平台补充、`DLC/github`、Apple 分支与检测站（`PROXY`）

- **第 4 层**：6 条日志验证增量（`github-avatars.oss-cn-hongkong.aliyuncs.com`、`ibyteimg.com`、`line-website.com`、`oklink.com`、`pipopayment.us`、`tiktokpangle-cdn-us.com`）+ `DLC/github`（`@-ads,@-telemetry`）+ `DLC/apple-intelligence` + Safari OHTTP（`safebrowsing.apple`、`ohttp-relay1.fastly-edge.com`）；
  - `--apple a`（SR 默认）：加 `DLC/apple-tvplus` 与 `APPLE_SR_US_ONLY_SUFFIXES`（19 域）；
  - `--apple b`（FlClash 默认）：加 `APPLE_COMMON_SUFFIXES`、`DLC/apple`、`DLC/icloud`（`@-ads,@-telemetry`）。
- **第 5 层（37 个审计锚点）**：`1ms.dog`、`1msapp.com`、`1ms.one` + `DLC/category-ip-geo-detect`（`@-cn,@-ads`）。

---

## 第 6 层：Apple 直连（仅 A）+ 微软特例与 Amazon.cn 边界

- **6.0（仅 `--apple a`）**：`DLC/apple`+`DLC/icloud`（剔除美区独占与 `@ads`/`@telemetry`）+ 通用 Apple 关键词 + 13 条 Apple CIDR（`,no-resolve`）→ `DIRECT`。
- **6.1 微软分流与边界（双端，排在第 7/8 层前）**：
  - 直连：`amazon.cn`、`cn.bing.com`、`DLC/bing@cn`、`msftconnecttest.com`、`msftncsi.com`、及 `DLC/microsoft` 中寄宿在 `.akamaized.net`/`.akadns.net`/`.edgekey.net`/`.edgesuite.net` 的专用 CDN 主机（防止被第 7 层 `akamaized.net` 遮蔽）
  - 拦截：`ipv6.msftconnecttest.com`、`ipv6.msftncsi.com` → `REJECT`
  - 代理（8 域 `MS_61_PROXY_8`）：`bing.com`、`api.onedrive.com`、`dm.files.1drv.com`、`skyapi.live.net`、`odc.officeapps.live.com`、`centralus1.mediap.svc.ms`、`mobile.pipe.aria.microsoft.com`、`location.microsoft.com`
- *注：旧 6.2 层 Top500 海外白名单已删除，`zoom.us` 与 `ieee.org` 随第 7 层走代理。*

---

## 第 7 层：清洗版海外主干（`PROXY`）

- 来源：`OVERSEAS_PROXY_DELTA_DOMAINS`（13 域与 `DLC/geolocation-!cn` 自动差集自校准，当前由 `L7-Delta` 输出 11 域；已获 `geolocation-!cn` 收录的 `alibabacloud.com`、`cnpmjs.org` 随 `L7-DLC` 输出）+ 清洗版 `DLC/geolocation-!cn`；
- 自动减除：① `@cn`/`@ads`/`@telemetry`；② 第 2/3/5 层与方案 B 已覆盖域（含 `CORE_AD_SUFFIXES`、`GOOGLE_CN_AD_VARIANTS`、`LAYER3_TELEMETRY_REJECT_DOMAINS`）；③ `LAYER7_REMOVED_KEYWORDS`（`aws`/`amazon`）；④ **全部第 8 层微软直连域**（`windowsupdate.com`、`microsoft.com`、`office.com`、`msedge.net` 等，确保 Windows 更新不走代理）；⑤ `--apple a` 时同步减除第 6.0 层通用 Apple 域。

---

## 第 8 ~ 9 层：国内直连、微软直连与终极兜底

- **8.0 微软通用直连**：清洗版 `DLC/microsoft`（剔除 GitHub、Bing、Copilot/OpenAI 代理域及 `@ads`/`@telemetry`，`windowsupdate.com`、`microsoft.com` 等在此直连）；
- **8.1 国内总集与自动差集 Delta**：
  - 骨干：`DLC/cn`（剔除 `DLC_CN_EXCLUDED_DOMAINS` 与 `@ads`/`@telemetry`）+ `DLC/category-ai-cn`（含 `deepseek.com`/`doubao.com`/`kimi.com`/`moonshot.cn`/`minimaxi.com`/`qwen.ai`/`qwenlm.ai`/`tongyi.com`/`yiyan.baidu.com` 等）；
  - 自动差集 Delta（仅输出当前 DLC 尚未覆盖的条目，当前 **113 条**）：`BYTEDANCE_CN_DELTA_SUFFIXES`（87 条）+ `CN_DOMESTIC_DELTA_SUFFIXES`（33 条，含 `weshineapp.com`）+ `CN_DOMESTIC_AI_DELTA_SUFFIXES`（7 条：`xfyun.com`/`stepfun.com`/`lingyiwanwu.com`/`lingyi.org`/`minimax.chat`/`baichuan.tech`/`chatglm.site`）+ `yuque.com`；
  - FlClash 将非正则域打入 `rule-providers.cn-domain`（`type: inline`），正则表达式留在 `rules:` 的 `L8.1-Regex`；Shadowrocket 全量内联于 `rules` 并补 `DOMAIN-SUFFIX,cn,DIRECT`。
- **8.2 国内 IP 兜底**：`GEOIP,CN,DIRECT,no-resolve`（FlClash 可传 `--drop-geoip-cn` 省略）。
- **第 9 层**：FlClash 为 `MATCH,<PROXY_GROUP>`；Shadowrocket 为 `FINAL,PROXY` 后接 `[URL Rewrite]` 与 `[MITM]`（`*.google.cn`）。
