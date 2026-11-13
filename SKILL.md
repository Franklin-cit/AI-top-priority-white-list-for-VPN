---
name: subscription-hardener
description: >
  Enhance and harden raw airport proxy subscriptions into conflict-free, leak-proof configurations for
  either Shadowrocket (iOS .conf: Lite or Full Conflict-Free) or FlClash / Mihomo (.yaml: Windows Desktop & Android),
  plus complete in-app settings recommendations and automated static/runtime verification.
  Use when the user asks to convert, fix, deduplicate, harden, or audit a raw airport subscription
  (Shadowrocket .conf or Clash/FlClash/Mihomo .yaml) with top-priority AI proxy immunity, whitelist adblocking,
  anti-DNS/WebRTC leaks, QUIC mitigation, and domestic direct routing.
---

# Subscription Hardener (机场原生订阅规则完善指南)

将机场原生订阅（Clash/Mihomo `.yaml` 或 Shadowrocket `.conf`）升级为**防误杀、防 DNS/WebRTC 泄露、屏蔽 QUIC 断流、无规则冲突、兼顾低延迟与内存限制**的生产级分流配置，并附带客户端应用内推荐设置。

> **隐私与安全红线**：本 Skill 及其配套脚本与文档**严禁写入任何个人隐私或敏感凭据**（包括机场订阅 URL、机场品牌名、节点域名/IP、端口、密码/UUID、本地用户名路径）。处理用户本地订阅时，只保留或迁移用户原文件中的节点与基础节点组，不对外固化任何节点信息。

---

## 第一步：确认目标端与偏好选项

开始改写任何订阅前，先向用户确认以下选择（若用户已在消息中明确指定则跳过对应提问）：

1. **目标客户端（必选）**：
   - **选项 A：Shadowrocket（iOS 小火箭 `.conf`）**
   - **选项 B：FlClash / Mihomo（Windows 桌面端 / Android 手机端 `.yaml`）**
   - **选项 C：双端分别按平台特性生成**（共享 9 层核心漏斗，但按 iOS 与桌面/Android 平台差异分别应用默认策略，**不强求双端完全同步**）
2. **细分版本与分流偏好**：
   - 若选 **Shadowrocket（iOS 专用）**：
     - **配置体量**（适配 iOS `NEPacketTunnelProvider` 扩展进程严格内存配额约束）：
       - **极速轻量版（主推，`--profile lite`）**：精选核心广告联盟（含 Google 独立与 `-cn` 广告域、`miaozhen.com` 与国内移动广告 SDK）+ 完整 9 层防泄露、方案 B 点穴拦截、QQ/微信 UDP 白名单与高频国内 `.com`/`.net`/国产 AI 补全，体量极小、低内存占用。
       - **完整无冲突版（`--profile full`）**：内联经严格标签边界清洗的完整去广告库（约 5.2~5.4 万条 `REJECT`，随上游浮动）+ 完整 9 层分流（**仍严禁内联 11 万条 `cn-domain`**，仅保留第 8.1 层高频国内域与国产 AI）。
     - **Apple / iCloud 策略（iOS 默认 `情况 A`）**：
       - **情况 A（iOS 主推，`--apple a`）**：美区独占服务（Apple Intelligence / Siri AI / Apple News / Apple TV+）在第 4.7 层走 `PROXY`；美区 App Store 下载 CDN、iCloud 与常规 Apple CIDR 在第 6.0 层走 `DIRECT`（第 7 层剔除通用 Apple CDN 残留）。
       - **情况 B（外区常驻且流量充足，`--apple b`）**：Apple 全系走 `PROXY`。
   - 若选 **FlClash / Mihomo（Windows & Android 专用）**：
     - **Apple 策略（Win/Android 默认 `情况 B`）**：Windows / Android 无本地 App Store 与 iCloud 下载分流需求，默认 `--apple b` 将 Apple 生态整体设为代理；仅当需要兼容 iOS Clash Mi 等多端共用时才改用 `--apple a`。
     - **可选微调项**：`zoom.us` 是否维持 `DIRECT`（`--zoom direct|proxy`，默认直连国内会议）；原生订阅自带的所有节点 `proxies:`、现有 `proxy-groups:`（含国旗/Emoji 命名及流媒体/Emby 等专项策略组）与合规规则将自动保留。

---

## 第二步：审计原生订阅常见缺陷（先诊断，再动手）

改写重大结构前，先对用户提供的原生订阅做快速体检并解释原因与方案：

1. **规则方向与策略组错误**：常见机场原生订阅会把 `RULE-SET,ads` 错误指向代理组（帮广告走流量）而非 `REJECT`。
2. **`behavior` 声明错误（FlClash / Mihomo）**：
   - `private` 规则集若写错为 `classical` 而远端内容是纯域名，会导致局域网规则全部失效；
   - `google`、`gemini` 若内容含 `DOMAIN,` / `PROCESS-NAME` 却写为 `domain`，会导致数百条规则静默失效；
   - `dns.fake-ip-filter` 与 `dns.nameserver-policy` 中引用的 `rule-set:` **只能**使用 `behavior: domain` 的规则集（如 `cn-domain`、`private`），否则触发 Mihomo 内核告警或报错。
3. **父子域 / 规则顺序遮蔽（Shadowing）**：
   - 原生订阅常将 `RULE-SET,microsoft,DIRECT` 放在 `RULE-SET,openai` 之前，导致 OpenAI 托管在 Azure Blob / Azure Edge 的接口与文件上传域名被截胡直连；
   - 去广告规则若排在 AI 规则前面，会误杀 AI 的鉴权与特性开关（`statsig`、`featuregates.org`、`segment.io`、`sentry.io`、`launchdarkly.com`）甚至新上线 AI 子域；反之，若将 Google 母域置于去广告层之上又不做**方案 B** 点穴拦截，则会顺手放行 `adservice.google.com` 等谷歌自有广告节点。
   - 粗放子串过滤去广告库（如直接判断 `"google" in dom`）会误放行 `googlesyndication-cn.com` 等国内谷歌广告变体；正确做法是使用**严格 DNS 标签边界匹配**与**仅限同动作的安全去重**。
4. **DNS 与 WebRTC 泄露隐患**：
   - 尾部 `GEOIP,CN,DIRECT`（及 FlClash 的 `RULE-SET,cn-ip,DIRECT`）、所有 `IP-CIDR` / `IP-CIDR6` / `IP-ASN` **以及 FlClash 中所有 `behavior: classical` / `ipcidr` 的 `RULE-SET`（如 `openai`、`google`、`apple`、`microsoft`）** 漏写 `,no-resolve`，会导致 Fake-IP 或未知海外域名触发本机 DoH 提前解析（甚至广告与代理域也会先查 DNS 再被规则截停）；
   - Top500 白名单中把 `cloudflare.com` 设为 `DIRECT`，导致 Turnstile 人机验证与 `stun.cloudflare.com` WebRTC 暴露中国 IP。
5. **TCP-over-TCP 协议下的 QUIC 拥塞与 QQ/微信兼容**：
   - 当节点使用 `anytls` / `Trojan` / `VLESS` 等 TCP 承载协议时，未拦截 QUIC（UDP 443）会产生双重重传掉速；
   - 但 Shadowrocket 若仅写 `[General] block-quic = all`，优先级高于 `[Rule]`，会误杀直连 QQ/微信的自定义 UDP（`:8000`/`:80`）。

完整背景与决策依据见 [references/requirements_and_implementation.md](references/requirements_and_implementation.md)。

---

## 第三步：构建 9 层分流漏斗 + 第 0 层底层防护

按“从上到下、命中即停”严格构建配置，详细规则清单见 [references/curated_domains.md](references/curated_domains.md)。

### 第 0 层：底层网络、DNS 与防泄露
- **FlClash (`.yaml`)**：
  - 全局与 `dns:` 均设 `ipv6: false`，开启 `unified-delay: true`、`log-level: info`；
  - `dns.enhanced-mode: fake-ip`，`default-nameserver` 与 `proxy-server-nameserver` 使用国内纯解析解析节点域与 DoH 服务器自身；
  - 默认 `nameserver`（Google/Cloudflare DoH）**强制挂载代理组后缀**（如 `#🚀 节点选择`）经代理隧道解析海外域名；
  - `nameserver-policy` 按**“最精确优先”**分段分流解析（同时**不污染 `fake-ip-filter`**）：① `+.cn.bing.com` → 国内 DoH；② Copilot / 第 6.1 层微软代理特例与 Apple（`--apple b`）→ 海外 `#<代理组>` DoH（避免被 `cn-domain` 里的 233 条 Apple/`mzstatic` 误拉国内节点 IP）；③ `+.microsoft.com` 等通用微软后缀 → 国内 DoH（解决微软直连域名解析到美国 Akamai 边缘导致 TLS 延迟 1.4~3 秒）；④ 兜底 `rule-set:cn-domain` 与 `rule-set:private`（均为 `behavior: domain`）→ `dns.alidns.com` / `doh.pub`；
  - 开启 `sniffer`（含 `parse-pure-ip: true`，跳过 `+.mijia.cloud`、`+.push.apple.com`）。
- **Shadowrocket (`.conf` `[General]`)**：
  - `ipv6 = false`、`bypass-system = true`、`hijack-dns = *:53`；
  - `dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query`（供命中 `DIRECT` 的国内域名就近解析）；
  - `fallback-dns-server = https://dns.google/dns-query, https://1.1.1.1/dns-query`；
  - `block-quic = all-proxy`（关键：只原生拦走代理的 QUIC，不误杀直连 QQ/微信 UDP，非腾讯系直连 HTTP/3 由第 1.5 层补充拦截）；
  - 配置完整的 `skip-proxy`（含 `captive.apple.com`、`*.push.apple.com`、`*.ls.apple.com`）、`bypass-tun` 与 `always-real-ip`。

### 第 1 ~ 9 层分流流水线
| 层级 | 目的与核心动作 | FlClash (`.yaml`) 要点 | Shadowrocket (`.conf`) 要点 |
|---|---|---|---|
| **第 1 层** | 局域网 / 私有地址 → `DIRECT` | 内联 LAN 域/IPv4/IPv6（全部带 `,no-resolve`）+ `RULE-SET,private,DIRECT` | 内联 LAN 域、常见路由器域、`.arpa` 反向域与全量私有 CIDR（全带 `,no-resolve`） |
| **第 1.5 层** | QUIC 拦截 + 腾讯 UDP 放行 | `- "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"`（仅拦 UDP 443，不阻断 QQ/微信原生端口且不放行广告 UDP 443） | 先放行 QQ/微信 `AND,((PROTOCOL,UDP),(DOMAIN-SUFFIX,...)),DIRECT`；紧接 `AND,((PROTOCOL,UDP),(DEST-PORT,443)),REJECT-NO-DROP` |
| **第 2 层** | AI 巨头 + 母域 + 组件置顶 → `PROXY` | 2.3 顶部置入**方案 B** 点穴拦截（`adservice.google.com`/`analytics.google.com`/`crashlyticsreports-pa.googleapis.com` → `REJECT`）；其余置顶 OpenAI、Anthropic、Google AI+Google 全系母域、Meta AI+Meta 全系母域、xAI(Grok)、微软 Copilot 4 个专属子域、**2.4.2 独立 AI（Perplexity / Groq / Midjourney / Cursor）**、AI 鉴权组件 + `disneyplus.bn5x.net` + `IP-ASN,20473` / `IP-ASN,32934` + `openai/claude/gemini` 规则集（全带 `,no-resolve`；注意：**国产 AI 归属第 8 层 `DIRECT`**） | 全量内联上述 2.1~2.5 规则（含方案 B 点穴拦截 `REJECT`）+ `IP-ASN,20473` / `IP-ASN,32934`（全部带 `,no-resolve`）；注意 **不想影响第三方 Auth0 登录时可加 `--strict-auth0` 剔除宽泛 `auth0.com`**（OpenAI 已由 `openai.com` 覆盖） |
| **第 3 层** | 去广告拦截 → `REJECT` | `RULE-SET,ads,REJECT` + 去重后的补充广告域（含独立 Google 广告域、`miaozhen.com` 与国内移动广告 SDK，严格按 DNS 标签边界剔除第 2 层 AI 保护域；升级 `cupid.iqiyi.com` 等父域） | 极速版内联精选核心广告联盟（含 `doubleclick.com`/`admob.com`/`2mdn.net`、Google `-cn` 变体、`miaozhen.com` 及国内高频移动广告 SDK）；无冲突版内联去重后的完整去广告库（约 5.2~5.4 万条，随上游浮动）+ 同上核心补全；均按标签边界保护 AI 域 |
| **第 4 层** | 全球主流平台 + 苹果分支 → `PROXY` | Twitter/X、YouTube、`RULE-SET,google,<PROXY_GROUP>,no-resolve`、`RULE-SET,facebook,<PROXY_GROUP>,no-resolve`、Instagram、Telegram、Discord、TikTok、GitHub 等；`4.7 Apple` 在 Win/Android 桌面与安卓端默认按**情况 B** 整套走代理 | 内联 `4.1~4.6` 平台（剔除冲突项）；`4.7` 在 iOS 端默认按**情况 A** 仅放美区 Apple 独占服务（Apple Intelligence / Siri AI / Apple News / Apple TV+） |
| **第 5 层** | IP / DNS / WebRTC 检测站 → `PROXY` | 包含 `1ms.dog`、`ipqs.com` 及 34 个常用 IP/DNS 检测站（共 36 个域） | 同左（确保检测站不落入后续 `GEOIP` 触发本机查询） |
| **第 6 层** | 苹果直连(仅情况A) + 微软特例 + Top500 白名单 | Windows/Android 默认情况 B 不启用 6.0 苹果直连；`6.1` `cn.bing.com,DIRECT` 与 `bing.com`/OneDrive 共 8 域走代理；`6.2` Top500 直连白名单（**已剔除 `cloudflare.com`**，保留 `amazon.cn,DIRECT`） | iOS 默认情况 A 在 **`6.0`** 置入 `Apple/App Store/iCloud` 直连域与 Apple CIDR（全部 `,no-resolve`）；再放 `6.1` 与 `6.2` Top500（**已剔除 `cloudflare.com` 与 Apple CDN**） |
| **第 7 层** | 其余海外网站代理列表 → `PROXY` | 合并海外长尾域名与必要代理 IP（**已剔除过宽关键字 `DOMAIN-KEYWORD,aws` 与 `amazon`、Google `-cn`/核心广告及已被 `ads` 截胡的冗余项**） | 同左（剔除 `amazon` 关键字可防止截胡 `amazonaws.cn`/`z.cn` 等 `.cn` 域名；iOS 情况 A 需同步按严格后缀边界剔除通用 Apple CDN） |
| **第 8 层** | 国内分流 → `DIRECT` | `DOMAIN-SUFFIX,cn,DIRECT`、`RULE-SET,microsoft,DIRECT,no-resolve`、字节跳动规则集（若原生不含则内联 13 条字节直连域，其中 `feishu.cn` 会被前面的 `.cn` 同动作吸收）、**国产 AI（DeepSeek / 豆包 / 火山 / Kimi / 通义 / MiniMax 等）+ `yuque.com`**、`RULE-SET,cn-domain,DIRECT`、`RULE-SET,cn-ip,DIRECT,no-resolve`、`GEOIP,CN,DIRECT,no-resolve` | 字节直连域 + **`8.1` 235 个主流非 `.cn` 国内域名（在 `--sr-source` Top500 之外拾遗补缺，含 `servicewechat.com`/`wechatapp.com`/`yuque.com`）、13 条国产 AI 与 `DOMAIN-SUFFIX,cn,DIRECT` 共 249 条规则**（含 `qishui.com`、`getui.com`、`ddnspod.com`、`ecombdpage.com` 等）+ `GEOIP,CN,DIRECT,no-resolve` |
| **第 9 层** | 终极兜底 → `PROXY` | `MATCH,<主代理组名>` | `FINAL,PROXY`，末尾保留 `[URL Rewrite]`（`google.cn -> 302`）与 `[MITM]`（`*.google.cn`） |

### 格式与工程硬性要求
- **Shadowrocket `.conf` 必须使用纯 LF（`\n`）换行与 UTF-8 无 BOM 编码**，严禁 `\r\n`（Windows CRLF 会导致 iOS 行尾 rule 解析异常）；不硬编码 `[Proxy]` 段，直接复用订阅里的策略名 `PROXY`。
- **使用确定性构建脚本 `scripts/build_subscription.py`**：双端共用 [scripts/rule_catalog.py](scripts/rule_catalog.py) 单一真源；执行严格 DNS 标签边界保护（`domain_in_suffix_set`）、**同动作安全去重**（仅当祖先规则与当前规则动作完全一致时跳过，绝不跨动作吞掉例外），并确保 FlClash 模式完整保留机场原始 `proxies:`、`proxy-groups:`、`rule-providers:` 与专项分组分流。
- **双端平台默认非对称**：
  - Shadowrocket (iOS) 默认 `--apple a`（美区 App Store/iCloud 直连、AI/News/TV+ 代理，第 1.5 层 QQ/微信 UDP 白名单，第 8.1 层高频非 `.cn`/国产 AI/CDN 直连补全）；
  - FlClash (Win/Android) 默认 `--apple b`（全套 Apple 代理 + `RULE-SET,ads` 差集去重 + 国产 AI/办公补充 + `RULE-SET,cn-domain` / `cn-ip`）。
- **所有 `IP-CIDR`、`IP-CIDR6`、`IP-ASN`、`GEOIP`、`RULE-SET,cn-ip`，以及 FlClash 中所有 `behavior: classical` / `ipcidr` 的 `RULE-SET` 一律强制加 `,no-resolve`**；IPv6 网段必须使用 `IP-CIDR6`。
- **Mihomo 规则去重（`--ads-ruleset` 语义）**：若订阅已含 `RULE-SET,ads` 且**不传** `--ads-ruleset`，构建器直接信任 `RULE-SET,ads`，仅内联 88 条核心差集（总规则约 1,000 条，体积最精简）；若**传入**新鲜本地 `ads.yaml`（缓存超 7 天会告警提示刷新），则会逐条对比上游约 5.2~5.4 万条 SR 去广告列表，把 `ads.yaml` 尚未收录的差集一并内联（通常约 4,300~4,500 条），用于兼顾拦截完整性与远低于全量的体积。

---

## 第四步：确定性构建、静态校验与真机验证

### 1. 确定性构建命令（按需执行）

```bash
# Shadowrocket iOS 极速轻量版（默认 --apple a 情况A）
python scripts/build_subscription.py --mode sr --profile lite --sr-source path/to/sr_top500_whitelist_ad.conf --fetch-sr -o output-lite.conf

# FlClash Win/Android 无冲突版（默认 --apple b 情况B，保留原订阅节点与策略组；不传 --ads-ruleset 则信任 RULE-SET,ads 仅 ~1k 规则，传入 ads.yaml 可补全漏网广告差集）
python scripts/build_subscription.py --mode flclash --sr-source path/to/sr_top500_whitelist_ad.conf --fetch-sr --base path/to/native-airport.yaml --ads-ruleset path/to/ads.yaml -o output-flclash.yaml
```
- **常用可选参数**（按需追加，完整说明可用 `--help` 查看）：
  - `--strict-auth0`：仅保留 `openai.com` 覆盖的 `auth0.openai.com`，不放通裸 `auth0.com`；
  - `--rulesets-dir <目录>`（SR 专用）：若本地已缓存 `openai.yaml` / `tiktok.yaml` / `line.yaml` 等规则集，构建 SR 时一并展开内联；`--user-conf <旧配置.conf>` 可保留原有自定义域名/IP 规则；`--name` / `--desc` 自定义配置头部说明；
  - `--proxy-group "<组名>"` / `--drop-geoip-cn`（FlClash 专用）：手动指定主策略组，或在已有最新 `cn-ip` 规则集且内存受限场景省略重复的 `GEOIP,CN`；
  - `--apple a|b` / `--zoom direct|proxy`：按需覆盖默认苹果分支与 `zoom.us` 直连/代理策略。

### 2. 静态严格体检（构建完成会自动触发，也可独立复检）

```bash
# Shadowrocket 配置严格体检
python scripts/audit_subscription.py --mode sr --profile lite --strict path/to/output-lite.conf

# FlClash / Mihomo 配置严格体检（有 PyYAML 时附加语法解析；默认零依赖校验顶层块结构、strategy group 存在性、方案 B 点穴规则顺序与 -cn 广告防漏，完整 YAML 语法由 mihomo -t 验证）
python scripts/audit_subscription.py --mode flclash --strict path/to/output-flclash.yaml
```

### 3. 若需运行 Mihomo 内核实测（可选，Windows/macOS/Linux 通用）
1. 禁止使用全局正则 `s/enable: true/enable: false/` 关闭 TUN 测试（会连带关闭 `dns.enable` 和 `sniffer.enable`，导致测出假绿灯！）。请使用 `scripts/verify_runtime.py`，其会自动调用块作用域解析仅禁用 `tun.enable` 并保持 `dns:` 与 `sniffer:` 100% 原样。
2. 在开启代理时先预下载 `geoip.metadb` 与 `rule-providers`，再在**无激活系统代理**的状态下验证三路真实探测（含方案 B 的 `adservice.google.com`）：

```bash
# 第一步（开代理时）：预下载 rulesets 与 geoip.metadb 到系统临时缓存（亦可用 --env-dir ./mihomo-env 自定义路径）
python scripts/verify_runtime.py --config path/to/output-flclash.yaml --prepare-env --proxy-url http://127.0.0.1:7890

# 第二步（关闭系统代理/FlClash TUN 后）：自动复用上述缓存校验 mihomo -t 及三路路由（若内核不在 PATH 中可加 --mihomo path/to/mihomo.exe；调试时按需加 --allow-active-proxy）
python scripts/verify_runtime.py --config path/to/output-flclash.yaml
```

### 4. iOS Shadowrocket 真机轻量验证清单
- 导入配置并将全局路由设为 **`配置`**，开关**飞行模式 5 秒**清理系统 DNS 缓存；
- 访问 `check.1ms.dog` 确认海外出口 IP 与 WebRTC 未暴露国内真实 IP，且无本地运营商明文 `UDP:53` / 海外域名国内 DNS 泄露（注：SR `[General]` 配置了 `alidns.com`/`doh.pub` 仅作直连域名加速 DoH，部分检测站同时列示国内与海外 DoH 属正常预期）；
- 实测 ChatGPT / Gemini（含 Google AI 静态资源）及 `adservice.google.com` / `miaozhen.com`（应命中 `REJECT`）、国产 AI（`deepseek.com`/`doubao.com`/`kimi.com`，直连）、美区 App Store 下载 / 国区常用 App（如汽水音乐/爱奇艺）、微信与 QQ 语音/UDP 连通性正常；
- 若使用完整无冲突版（约 5.4~5.5 万行，随上游规则库浮动），建议在 iOS `设置 → 隐私与安全性 → 分析与改进 → 分析数据` 留意是否出现 `JetsamEvent`（若偶发内存杀扩展进程则切换回极速轻量版）；如临时开过局域网「代理共享」测试，测完记得关闭。

---

## 第五步：提供客户端应用内设置推荐与后续排障

每次交付配置后，务必向用户提供对应客户端的应用内设置清单与复测方法，完整指南见 [references/app_settings_guide.md](references/app_settings_guide.md)：

- **FlClash 核心必选**：
  - **Windows**：必须开启 **TUN（虚拟网卡）**（需管理员模式运行）；桌面端不添加覆写项时默认即劫持 `any:53`；可选开启 **严格路由**；**关闭** `工具 → 常规 → 追加系统DNS`；保持 **绕过私有路由地址** 为**开启**；浏览器关闭自定义安全 DNS。
  - **Android**：开启 VPN 后，**必须手动进入 `工具 → 进阶配置 → 网络 → VPN → DNS 劫持` 并打开**（源码默认关闭）；保持 `VPN → IPv6` 与 `追加系统DNS` **关闭**；关闭系统「私人 DNS」。
  - **FlClash 日志级别**：日常选 **`info`**；导出日志供分析排障时临时切换 **`debug`**（同时含 DNS 与分流规则明细）；避免使用 `error`/`silent`。
- **Shadowrocket 核心必选**：
  - **全局路由**设为 **`配置`**；切到新配置后**开关飞行模式 5 秒**清 iOS DNS 缓存；
  - **保活/重连推荐用「按需连接」**（按网络环境默认连接、对认证 Wi-Fi 留余地，兼顾防切网断连与随手开关自由）；仅高风控防瞬时裸连场景改用「始终开启」；
  - 节点右侧 `i` 开启 **UDP 转发**（语音通话/WebRTC 正常且不与 QUIC 拦截冲突）；
  - iOS 系统关闭 **iCloud 专用代理**、Safari **限制 IP 地址跟踪**，并删除 VPN 与设备管理中的第三方加密 DNS 描述文件。
  - 若用户使用 `check.1ms.dog` 等检测站排查问题，帮助区分“可通过配置/设置修复（DNS 泄露、部分国内域名错走代理、QQ/微信 UDP 误拦、Zoom/Apple 策略）”与“节点 IP/物理距离/Router SQM 决定（跨太平洋 RTT 差、TCP 栈 OS 指纹、IPQS 标签、非目标区版权解锁）”。
