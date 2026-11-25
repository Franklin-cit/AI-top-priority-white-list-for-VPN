---
name: subscription-hardener
description: >
  Enhance and harden raw airport proxy subscriptions into conflict-free, leak-proof configurations for
  either Shadowrocket (iOS .conf: Full Conflict-Free pure-DLC) or FlClash / Mihomo (.yaml: Windows Desktop & Android inline),
  plus complete in-app settings recommendations and automated static/runtime verification.
  Use when the user asks to convert, fix, deduplicate, harden, or audit a raw airport subscription
  (Shadowrocket .conf or Clash/FlClash/Mihomo .yaml) with top-priority AI proxy immunity, high-precision DLC adblocking,
  anti-DNS/WebRTC leaks, QUIC mitigation, and domestic direct routing.
---

# Subscription Hardener (纯 DLC 订阅规则硬化指南)

将机场原生订阅（Clash/Mihomo `.yaml` 或 Shadowrocket `.conf`）重构为**完全基于 `v2fly/domain-list-community`（DLC）+ 精准增量补丁**的防误杀、防 DNS/WebRTC 泄露、屏蔽 QUIC 断流、无规则冲突、兼顾低延迟与轻量内存占用的单文件生产级配置，并附带客户端应用内推荐设置。

> **隐私与安全红线**：本 Skill 及其配套脚本与文档**严禁写入任何个人隐私或敏感凭据**（包括机场订阅 URL、机场品牌名、节点域名/IP、端口、密码/UUID、本地用户名路径）。处理用户本地订阅时，只保留或迁移用户原文件中的节点 `proxies:` 与策略组 `proxy-groups:`，不对外固化任何节点信息。

---

## 第一步：确认目标端与偏好选项

开始改写任何订阅前，确认以下选择（若用户已在消息中明确指定则跳过）：

1. **目标客户端（必选）**：
   - **选项 A：Shadowrocket（iOS 小火箭 `.conf`）**：单一精简完整版（约 3.3 万行，`DLC` 全量内联，纯 LF `\n` 无 BOM）。
   - **选项 B：FlClash / Mihomo（Windows 桌面端 / Android 手机端 `.yaml`）**：**零外部 `rule-providers` 单文件内联版**——写入 `profile` 状态持久化（`store-selected: true`、`store-fake-ip: true`），对输入配置**仅保留 `proxies:`、`proxy-groups:`（若原配置使用节点集则一并保留 `proxy-providers:`）**（测速 `url` 自动升 HTTPS、`interval >= 300s`、自动补充 `lazy: true` 并扁平化冗余单节点测速子组）；彻底丢弃原文件全部自带 `rules:`、远端 HTTP `rule-providers:`、`dns:` 及杂项字段，规则 100% 由官方 `v2fly/domain-list-community` 与 `rule_catalog.py` 组装，并将 `private` 与 `cn-domain` 转为 Mihomo 原生 `type: inline, behavior: domain` 规则集（正则表达式写入 `rules:` 为 `DOMAIN-REGEX`），第 2–8 层规则全部就地清洗内联。
   - **选项 C：双端分别按平台特性生成**：以各自独立 `-o` 依次运行 `--mode sr` 与 `--mode flclash`（默认 `--apple auto` 按端非对称映射：`SR -> 情况 A`，`FlClash -> 情况 B`）。
2. **细分与边界开关**：
   - **Apple / iCloud 策略（`--apple auto|a|b`）**：
     - **情况 A（iOS 默认 `--apple a`）**：Apple Intelligence / Siri AI / Apple News / Apple TV+ / Safari Safe Browsing OHTTP 中继（`safebrowsing.apple`、`ohttp-relay1.fastly-edge.com`）在第 4.7 层走 `PROXY`；美区 App Store 下载 CDN、iCloud 与 Apple CIDR 在第 6.0 层走 `DIRECT`（并在第 7 层剔除通用 Apple CDN）。
     - **情况 B（FlClash Win/Android 默认 `--apple b`）**：Apple 全生态走 `PROXY`。
   - **OpenAI Auth0 收窄（默认严格；按需 `--broad-auth0`）**：默认仅通过 `openai.com` 放行 `auth0.openai.com`，避免第三方站点误走代理；仅当需要全量 Auth0 SaaS 走代理时才传 `--broad-auth0`。
   - **FlClash 低内存兜底（可选 `--drop-geoip-cn`）**：默认在末尾保留 `GEOIP,CN,DIRECT,no-resolve`；极端低内存环境可省略之，仅保留 `inline cn-domain`。

---

## 第二步：审计原生订阅常见缺陷（先诊断，再动手）

1. **外部规则集失效与隐性污染**：常见机场 `.yaml` 依赖 10 余个远端 HTTP `rule-providers`，存在 `ads` 误杀国内 HTTPDNS/推送、规则集 `behavior` 标错静默失效（`RuleCount=0`）、更新超时或镜像停更风险；本 Skill 改为直接消费官方 **`v2fly/domain-list-community`**（支持 `dlc.dat_plain.yml` + SHA-256 校验，或原生 `data/` 目录）。
2. **父子域 / 关键词遮蔽与遥测策略混合**：
   - 原生订阅若将 `microsoft` 排在 `openai` 前会截胡 OpenAI Azure 接口；若将客户端遥测混入第 2 层 AI 保护组件则放行上报；反之若直接上全量去广告又可能误杀鉴权/特性开关；
   - **三分法精准隔离**：
     - ① **第 2 层必保组件**：`statsig*`、`featuregates.org`、`auth0.openai.com`（由 `openai.com` 覆盖，不放宽裸 `auth0.com`）、`arkoselabs.com`、`stripe.com`、`identrust.com`、`algolia.net`、`intercom*`、`launchdarkly.com`、`observeit.net`、`livekit.cloud`、`cdn.usefathom.com`、`disneyplus.bn5x.net`。
     - ② **第 2.3 层方案 B（Google 顶部精确拦截）**：顶部置顶 **11 条**及 DLC `google@ads/@telemetry` 精确广告/遥测节点 → `REJECT`（故意豁免 `video-stats.video.google.com`），紧接保留 `google.com`/`googleapis.com`/`gstatic.com` 等母域 → `PROXY`；同时在 2.1 层顶部将 `openai.qualtrics.com` 置顶为 `REJECT`，避免被 `DOMAIN-KEYWORD,openai` 放行。
     - ③ **第 3 层轻量高精准去广告 + 客户端遥测 + PCDN**：完全剔除 5 万+旧白名单广告，改为 `DLC/category-ads-all` + 主流厂商 `@ads` + **112 条** `CORE_AD_SUFFIXES`（含 `csjplatform.com`、`segment.io`/`segment.com`、`umeng*`、`crazyegg.com`/`ethicalads.io`/`hsadspixel.net`/`hs-analytics.net`/`collect.wpsmail.net` 等）+ **16 条** `LAYER3_EXACT_REJECT_DOMAINS` + **9 条**第 3 组客户端遥测（`browser-intake-datadoghq.com`、`browser-intake-us5-datadoghq.com`、`http-intake.logs.us5.datadoghq.com`、`o33249.ingest.sentry.io`、`o33249.ingest.us.sentry.io`、`o1158394.ingest.us.sentry.io`、`copilot-telemetry-service.githubusercontent.com`、`copilot-telemetry.githubusercontent.com`、`openai.qualtrics.com`）+ **37 条** PCDN/STUN/Tracker 降噪（含 `ankltoken.com`、`yingt.fun`），同时豁免 `DLC/category-httpdns-cn`（如 `httpdns.bilivideo.com`、`dns.weixin.qq.com.cn`）与 6 条功能性 API/推送（`graph.instagram.com`、`push.qq.com` 等）。
3. **DNS、WebRTC 与微软系统更新边界**：
   - 第 7 层彻底剔除过宽 `DOMAIN-KEYWORD,aws`/`amazon`、`cn` 标签域及全部 `DLC/microsoft` 非代理直连域（如 `windowsupdate.com`、`microsoft.com`、`office.com`、`msedge.net`），防止第 7 层把 Windows 更新劫持走代理；并将 `DLC/microsoft` 中寄宿在 Akamai 的专用 CDN 域名（`*.akamaized.net` / `*.akadns.net`）置于第 6.1 层直连，免受第 7 层 `akamaized.net,PROXY` 遮蔽。
   - 删除旧第 6.2 层 Top500 海外白名单；`zoom.us`、`ieee.org`、`alibabacloud.com`、`cnpmjs.org` 回归代理（`geolocation-!cn` / 增量 `OVERSEAS_PROXY_DELTA_DOMAINS`），`kimi.ai`、`moonshot.ai`、`minimax.io` 随 `DLC/category-ai-!cn` 归属第 2 层代理，仅 `kimi.com`/`moonshot.cn`/`minimaxi.com`/`qwen.ai`/`deepseek.com`/`doubao.com`/`yiyan.baidu.com` 等留第 8 层国内直连。
4. **QUIC 拥塞与 QQ/微信 UDP 兼容**：第 1.5 层前置封杀腾讯广告 UDP 443 与 `:8567` PCDN 打洞，再放行 QQ/微信 UDP（FlClash 含 9 个微信/QQ 进程裸 IP 兜底），最后封堵其余 UDP 443（HTTP/3 QUIC）。

完整背景与决策依据见 [references/requirements_and_implementation.md](references/requirements_and_implementation.md)。

---

## 第三步：构建第 0 层与 9 层纯 DLC 分流漏斗

按“从上到下、命中即停”由 [scripts/build_subscription.py](scripts/build_subscription.py) 与 [scripts/dlc_catalog.py](scripts/dlc_catalog.py) 确定性生成，详细清单元见 [references/curated_domains.md](references/curated_domains.md)：

| 层级 | 核心功能与动作 | FlClash (`.yaml`) | Shadowrocket (`.conf`) |
|---|---|---|---|
| **第 0 层** | 禁 IPv6、DNS 防泄露、Sniffer 与连接硬化 | `ipv6: false`、`tcp-concurrent: true`、`keep-alive-interval: 15`、`keep-alive-idle: 600`、`profile` 持久化（`store-selected`/`store-fake-ip`）、`enhanced-mode: fake-ip`、`default-nameserver` 国内纯 IPv4（`223.5.5.5`/`119.29.29.29`）、纯 IP 海外 DoH（`1.1.1.1`/`8.8.8.8` `#<代理组>`）、阿里纯 IP DoH/DoT（`proxy-server-nameserver`: `223.5.5.5`/`223.6.6.6`/`tls://223.5.5.5:853`）、`nameserver-policy`（置顶 13 域高频广告 `rcode://name_error`：精确 `applog.zijieapi.com` + 12 后缀 → `cn.bing` → 微软特例/Apple 代理 → 通用微软/NCSI 国内 → `.arpa` `rcode://name_error` → `inline cn-domain`/`private`）、`sniffer.force-dns-mapping: true` & `skip-domain`（含 `long.weixin.qq.com` 等 15 条）、`vless` 统一升级 `packet-encoding: xudp`、HTTPS+`lazy: true` 精简测速组与 `proxy-providers` 测速硬化 | `ipv6 = false`、`prefer-ipv6 = false`、`hijack-dns = *:53`、`dns-server = https://223.5.5.5/dns-query#no-h3`、`fallback-dns-server = https://223.6.6.6/dns-query#no-h3`（移除在移动网络超时的 `1.12.12.12`）、`dns-direct-fallback-proxy = false`、`block-quic = all-proxy` |
| **第 1 层** | 局域网 / 私有地址 → `DIRECT` | 内联 LAN + `RULE-SET,private,DIRECT`（`type: inline`）+ `private` 正则 | 内联 `LAN` + `DLC/private` 全量域/正则 + 全量 RFC1918/IPv6 CIDR（`,no-resolve`） |
| **第 1.5 层** | QUIC 与 PCDN `:8567` 拦截 + 腾讯 UDP | 腾讯广告 UDP 443 `REJECT` → QQ/微信域名与进程 UDP 443 `DIRECT` → 其余 UDP 443 & `:8567`（`SRC`/`DST`）`REJECT` | 腾讯广告 UDP `REJECT-NO-DROP` → QQ/微信 8 域 UDP `DIRECT` → 其余 UDP 443 & `DEST-PORT,8567` `REJECT-NO-DROP` |
| **第 2 层** | AI 巨头 + ① 必要组件 + ② 方案 B → `PROXY` | 2.1 `openai.qualtrics.com` 顶部精确拦截 + `DLC/openai`（剔除 `@ads`/`@telemetry`）+ ① 鉴权组件；2.2 `DLC/anthropic`；2.3 方案 B 谷歌广告 `REJECT`（豁免 `video-stats`）+ Google 母域；2.4 Meta/Copilot/xAI/独立 AI + `DLC/category-ai-!cn`（含 `kimi.ai`/`moonshot.ai`/`minimax.io`）；2.5 `statsig*`/`disneyplus.bn5x.net`（含 ASN `,no-resolve`） | 与 FlClash 完全一致（纯内联，正则是单反斜杠 `DOMAIN-REGEX` 且自动展开 `{m,n}` 防逗号切分） |
| **第 3 层** | ③ 轻量高精准去广告 + 遥测 + PCDN → `REJECT` | `DLC/category-ads-all` + 大厂 `@ads` + **112** `CORE_AD_SUFFIXES` + **16** 精确埋点 + **9** 第 3 组遥测 + **37** PCDN/STUN（排除 `category-httpdns-cn` 与 6 条功能端点），总计约 **978 条** | 与 FlClash 同一套轻量高精准集合（约 **978 条**，彻底摆脱 5.4 万条老旧列表与 Jetsam 压力） |
| **第 4 层** | 平台、GitHub、`Apple` 分支与测速 → `PROXY` | 4.4 日志增量 + `DLC/github` + `DLC/apple-intelligence` + Safari OHTTP + 4.7（`--apple b` 含全量 `DLC/apple` + `DLC/icloud`） | 4.4 增量 + `DLC/github` + `DLC/apple-intelligence` + Safari OHTTP + 4.7（`--apple a` 含 `DLC/apple-tvplus` 与美区 Siri） |
| **第 5 层** | IP / DNS / WebRTC 检测站 → `PROXY` | `1ms.dog`/`1msapp.com`/`1ms.one` + `DLC/category-ip-geo-detect`（非 `@cn`/非 `@ads`），含 37 个审计锚点 | 同左 |
| **第 6 层** | Apple 直连（仅 A）+ 微软边界/`amazon.cn` | `--apple a` 启用 6.0；6.1 `cn.bing.com`/`DLC bing@cn`/`amazon.cn`/Windows NCSI/微软 Akamai CDN 直连 + `bing.com`/OneDrive 8 域代理 | 默认启用 6.0 美区 App Store/iCloud（`DLC/apple`+`icloud` 去美区专属）直连 + 6.1 边界 |
| **第 7 层** | 海外主干 → `PROXY` | 清洗版 `DLC/geolocation-!cn`（自动剔除 AI/L3/微软直连/Apple 直连/`@cn`）+ 海外增量（含 `alibabacloud.com`/`cnpmjs.org`/`zoom.us`/`ieee.org`） | 同左（若 6.0 启用则同步剔除通用 Apple 域） |
| **第 8 层** | 国内直连与微软系统更新 → `DIRECT` | `DLC/microsoft`（非代理非遥测部分，`windowsupdate.com` 等在此直连）+ `RULE-SET,cn-domain,DIRECT`（`inline`: `DLC/cn` + `category-ai-cn` + 自动差集 113 域）+ `cn` 正则 + `GEOIP,CN,DIRECT,no-resolve` | 内联 `DLC/microsoft` 清洁直连域 + 113 条自动差集（清洁字节域 + 非 `.cn` 国内域 + 国产 AI 补充）+ 清洗版 `DLC/cn` + `category-ai-cn` + `DOMAIN-SUFFIX,cn` + `GEOIP,CN,DIRECT,no-resolve` |
| **第 9 层** | 终极兜底 → `PROXY` | `MATCH,<主代理组>` | `FINAL,PROXY` + `[URL Rewrite]` + `[MITM]`（`*.google.cn`） |

---

## 第四步：确定性构建、静态校验与运行验证

### 1. 构建命令

```bash
# 首次拉取并 SHA-256 校验官方 dlc.dat_plain.yml 后，生成 FlClash 纯内联 .yaml（自建 VPS 可追加 --direct-cidr <VPS_IP>/32 防回环）
python -B scripts/build_subscription.py --mode flclash --dlc-source path/to/dlc.dat_plain.yml --fetch-dlc --base path/to/base.yaml --direct-cidr <VPS_IP>/32 -o path/to/out_flclash.yaml

# 使用已缓存的 dlc.dat_plain.yml（或 domain-list-community/data 目录）生成 Shadowrocket .conf
python -B scripts/build_subscription.py --mode sr --dlc-source path/to/dlc.dat_plain.yml --direct-cidr <VPS_IP>/32 -o path/to/out_sr.conf
```

### 2. 静态严格体检（构建结束会自动执行，也可单独运行）

```bash
python -B scripts/audit_subscription.py --mode flclash --strict path/to/out_flclash.yaml
python -B scripts/audit_subscription.py --mode sr --profile full --strict path/to/out_sr.conf
```

`audit_subscription.py` 会校验：零外部/非白名单 `rule-providers`（仅允许内联 `private`/`cn-domain` 且 `payload` 非空无正则）、`default-nameserver` / `nameserver` / `proxy-server-nameserver` / `fake-ip-filter` / `nameserver-policy` 合规、`proxy-groups[].use` 与 `proxy-providers` 测速硬化（HTTPS、`interval >= 300s`、`lazy: true`）、`CORE_AD_SUFFIXES`（112）与 `EXPECTED_TELEMETRY_REJECT_AUDIT`（12）全数 `REJECT`、`video-stats.video.google.com` 与 6 条 `LAYER3_AD_EXEMPT_DOMAINS` + 代表性国内 HTTPDNS（`httpdns.bilivideo.com`、`dns.weixin.qq.com.cn`）不被误拦、`windowsupdate.com`/`microsoft.com`/`office.com` 等微软域直连不被 L7 劫持、`kimi.ai`/`moonshot.ai`/`minimax.io`/`zoom.us`/`ieee.org`/`alibabacloud.com`/`cnpmjs.org` 正确走代理、纯 LF 无 BOM、无悬空 YAML 别名与零重复规则；`--strict` 下遇任何错误或警告均返回非零退出码。

> **注意**：`--mode sr --user-conf` 仅用于合并少量个人内置 `PROXY`/`DIRECT`/`REJECT` 补充规则，**切勿传入机场原生 `.conf`**（脚本会自动拦截非法策略组动作与覆盖第 8 层微软/国内基准的规则）。

### 3. Mihomo 语法与无头 3 路探测（可选）

1. 先用官方内核做配置语法体检：`mihomo -t -f path/to/out_flclash.yaml -d <geoip_dir>`。
2. 如需运行 `scripts/verify_runtime.py`：脚本**仅将 `tun.enable` 改为 `false`**，保留 `dns:` 与 `sniffer:` 原样；本地 Mihomo API 查询会自动绕过终端 `HTTP_PROXY`。在真实网络环境中先用 `--prepare-env` 缓存 `geoip.metadb` 再执行 `python -B scripts/verify_runtime.py --config path/to/out_flclash.yaml`。

---

## 第五步：客户端应用内设置推荐

每次交付配置后，务必向用户同步 [references/app_settings_guide.md](references/app_settings_guide.md) 中的核心设置要点：
- **FlClash**：Windows 开 **TUN**（管理员权限）、关 `追加系统DNS`、开 `绕过私有路由地址`；Android 务必手动开启 **`VPN -> DNS 劫持`**、关闭系统「私人 DNS」与 `VPN -> IPv6`；日志日常 `info`、排查临时 `debug`。
- **Shadowrocket**：全局路由选 **`配置`**、切新配置后开关**飞行模式 5 秒**清缓存；节点 `i` 开启 **UDP 转发**、保持 **禁用 STUN**，IPv6 由配置 **`[General]`（App 路径：`配置 → 当前 .conf 右侧 i → 编辑配置 → 通用`）** 中的 `ipv6 = false` / `prefer-ipv6 = false` 控制；按日常场景推荐「按需连接」并删掉第三方加密 DNS 描述文件。
