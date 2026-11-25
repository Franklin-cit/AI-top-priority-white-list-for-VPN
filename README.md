# AI Top Priority White List for VPN (`subscription-hardener`)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg)](https://www.python.org/)
[![Data Source: v2fly DLC](https://img.shields.io/badge/Rules-v2fly%2Fdomain--list--community-2ea44f.svg)](https://github.com/v2fly/domain-list-community)

本项目是一套用于 **Shadowrocket（iOS）** 与 **FlClash / Mihomo（Windows / Android）** 代理配置硬化与确定性构建的 **AI Agent Skill + 零第三方依赖 Python 工具链**。

以官方 **[v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)（DLC）** 为唯一骨干数据源，兼容**自建 VPS 节点**与**常见代理订阅**，可将原始配置重构为**零外部规则集依赖、AI 服务最高优先级免疫误杀、轻量高精准去广告与遥测隔离、严格防 DNS/WebRTC 泄露、兼顾 QUIC 抑制与国内直连低延迟**的单文件生产级配置，并配套静态严格审计（`audit_subscription.py --strict`）与无头 Mihomo 运行时 119 路实测脚本（`verify_runtime.py`）。

---

## 一、v2.0 架构核心升级

相较早期依赖外部 HTTP 规则集与 5 万+ 历史白名单广告库的方案，当前纯 DLC 架构实现了以下重构：

- **单一官方真源 + 零外部规则集依赖**：全部规则均由 **[v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)**（隶属于 V2Ray 目前的官方维护组织 [v2fly](https://github.com/v2fly)，关联 V2Fly 官方网站 [www.v2fly.org](https://www.v2fly.org)，支持 Release `dlc.dat_plain.yml` + `.sha256sum` 校验或本地 `data/` 目录）与项目内置精筛规则（`rule_catalog.py`）生成，不使用任何第三方或订阅源自带的规则与远端 HTTP `rule-providers`；构建 FlClash `.yaml` 时，对输入的基础配置**仅保留 `proxies`、`proxy-groups`（及节点集型订阅可选的 `proxy-providers`）**，彻底丢弃原文件中的所有 `rules`、`rule-providers`、`dns` 与杂项配置，并将 `private` 与清洗后的 `cn-domain` 转为 Mihomo 原生 `type: inline, behavior: domain` 内联规则集（正则自动拆至 `rules:` 作为单引号 `DOMAIN-REGEX`）。
- **AI 与客户端遥测「三分法」隔离**：
  1. **第 2 层必保组件（防第 3 层广告库误杀）**：除 AI 主域外，同层置顶保留 AI 平台依赖的功能基础设施（特性开关 `statsig*` / `featuregates.org` / `launchdarkly.com`、登录人机验证 `arkoselabs.com`、订阅支付 `stripe.com`、证书校验 `identrust.com`、客服工单 `intercom*`、ChatGPT 语音通道 `livekit.cloud` 等）及 1 条防广告误杀项 `disneyplus.bn5x.net`；默认仅通过 `openai.com` 放行 `auth0.openai.com`（按需 `--broad-auth0` 放宽）。
  2. **第 2.1 / 2.3 层顶部精确拦截（方案 B）**：在 `DOMAIN-KEYWORD,openai` 上方置顶拦截 `openai.qualtrics.com`；在 Google 母域上方置顶 **11 条固定锚点** + `DLC/google@ads/@telemetry` 精确拦截谷歌广告与遥测，同时刻意豁免 `video-stats.video.google.com` 以保护 YouTube 观看历史与进度同步。
  3. **第 3 层轻量高精准拦截（双端约 `978` 条 `REJECT`）**：整合 `DLC/category-ads-all`、15 家主流厂商 `@ads`、`112` 条核心广告/追踪后缀（`CORE_AD_SUFFIXES`）、`16` 条单主机遥测/死域（`LAYER3_EXACT_REJECT_DOMAINS`）、`9` 条客户端遥测（Datadog / Sentry / Copilot Telemetry / Qualtrics）与 `37` 条 PCDN/STUN/Tracker 降噪规则，严格豁免 `DLC/category-httpdns-cn`（如 `httpdns.bilivideo.com`、`dns.weixin.qq.com.cn`）及 6 条功能 API/推送接口。
- **双端 DNS、传输与自建节点深度硬化**：
  - **FlClash**：默认开启 `profile` 状态持久化（`store-selected` / `store-fake-ip`）、`tcp-concurrent: true`、`keep-alive-interval: 15`、`keep-alive-idle: 600`、`sniffer.force-dns-mapping: true` 与 15 条 `skip-domain`；海外 DoH 全纯 IP 写法（`1.1.1.1` / `8.8.8.8` `#<主代理组>`）规避域名型 DoH 的明文预解析；`nameserver-policy` 置顶 **13 个高频国内广告域 `rcode://name_error` 0ms 短路**（精确 `applog.zijieapi.com` + 12 条后缀），并从 `cn-domain` 内联规则集自动净除第 3 层广告域；`proxy-server-nameserver` 使用阿里纯 IP DoH/DoT（`223.5.5.5` / `223.6.6.6` / `tls://223.5.5.5:853`）；`type: vless` 节点自动统一升级 `packet-encoding: xudp`；测速组自动升级 HTTPS、`interval >= 300s`、`lazy: true` 并扁平化单节点冗余测速子组。
  - **Shadowrocket**：单一精简完整版（约 `3.3` 万行，纯 LF `\n` 无 BOM，适配 iOS `NEPacketTunnelProvider` 内存约束）；单主阿里纯 IP DoH（`https://223.5.5.5/dns-query#no-h3`）+ 加密备选（`https://223.6.6.6/dns-query#no-h3`，已移除在移动蜂窝易超时的 `1.12.12.12` 与明文 `system`），设 `dns-direct-fallback-proxy = false` 杜绝死域倒灌代理；支持 `--direct-cidr` 第 1 层置顶自建 VPS IP 防回环与安全的 `--user-conf` 自定义规则合并。

---

## 二、适用范围与双端默认策略

| 维度 | FlClash / Mihomo（Win / Android `.yaml`） | Shadowrocket（iOS `.conf`） |
|---|---|---|
| **产物形态** | 单文件纯内联 `.yaml`（仅 `private` + `cn-domain` 两个 `type: inline` 规则集） | 单一精简完整 `.conf`（纯 LF 无 BOM，不写死 `[Proxy]`，自动对接首页节点） |
| **Apple 默认分流** | **情况 B（`--apple b`）**：Apple 全生态走代理（可传 `--apple a` 切换） | **情况 A（`--apple a`）**：仅 Apple Intelligence / News / TV+ / Siri / Safari OHTTP 走代理，App Store 与 iCloud 直连 |
| **微软与 Windows 更新** | `cn.bing.com` / `bing@cn` / Windows NCSI / 微软 Akamai 专用 CDN / `windowsupdate.com` / `microsoft.com` / `office.com` 直连；国际 `bing.com` / Copilot / OneDrive 核心 8 域走代理 | 与 FlClash 保持一致的微软直连与代理精确拆分 |
| **QUIC 与微信/QQ UDP** | 第 1.5 层：腾讯广告 UDP 443 `REJECT` → QQ/微信 8 域及 9 个微信/QQ 进程裸 IP `GEOIP,CN` 白名单 `DIRECT` → 其余 UDP 443 与 `:8567`（`SRC`/`DST`）`REJECT` | `[General]` 设 `block-quic = all-proxy` + 第 1.5 层：腾讯广告 UDP `REJECT-NO-DROP` → QQ/微信 8 域 UDP `DIRECT` → 其余 UDP 443 与 `DEST-PORT,8567` `REJECT-NO-DROP` |
| **自建 VPS 防回环** | 支持 `--direct-cidr <VPS_IP>/32` 置顶第 1 层 `DIRECT,no-resolve` | 支持 `--direct-cidr <VPS_IP>/32` 置顶第 1 层 `DIRECT,no-resolve` |

---

## 三、9 层自上而下分流漏斗

代理内核严格按「**从上到下、首次命中即停**」执行；`RuleEmitter` 在构建期按同动作安全去重、自动规范化全部 `IP-CIDR`/`IP-CIDR6` 主机位，绝不跨动作静默吞并例外规则：

| 层级 | 核心职责与动作 | 关键内容摘要 |
|---|---|---|
| **第 0 层** | 底层网络、DNS 与嗅探 | 禁 IPv6；FlClash 纯 IP 海外 DoH（`1.1.1.1`/`8.8.8.8`）、13 域广告 DNS 0ms 短路、`sniffer.force-dns-mapping: true`、VLESS `xudp`、`profile` 持久化；SR 纯 IP `#no-h3` DoH、`dns-direct-fallback-proxy = false` |
| **第 1 层** | 局域网 / 私有地址 / VPS 防回环 → `DIRECT` | 可选 `--direct-cidr` + RFC1918 / IPv6 私有 CIDR（`,no-resolve`）+ `DLC/private` |
| **第 1.5 层** | QUIC 与 PCDN `:8567` 治理 + 腾讯 UDP 白名单 | 先拦 `gdt`/`e`/`bugly.qq.com` 广告 UDP，再放行 QQ/微信 UDP，最后拦截其余 HTTP/3（UDP 443）与 `:8567` |
| **第 2 层** | AI 全平台 + 组 ① 必保组件 + 组 ② 顶部精确拦截 → `PROXY` | `2.1` OpenAI（顶部精确拦截 `openai.qualtrics.com,REJECT`）；`2.2` Anthropic；`2.3` 方案 B 11 锚点 + Google 母域（豁免 `video-stats`）；`2.4` Meta AI / Copilot / xAI / 独立 AI / `DLC/category-ai-!cn`（含 `character.ai`、`kimi.ai`、`moonshot.ai`、`minimax.io`）；`2.5` `statsig*` / `disneyplus.bn5x.net` |
| **第 3 层** | 轻量高精准去广告 + 遥测 + PCDN → `REJECT` | `DLC/category-ads-all` + 15 家厂商 `@ads` + `112` 广告后缀 + `16` 单主机遥测/死域 + `9` 客户端遥测 + `37` PCDN/STUN/Tracker（含 `vc-brain*.ndcpp.com`、`mcdn.bilivideo.cn`、`ankltoken.com`、`yingt.fun`），豁免 HTTPDNS 与 6 条功能端点 |
| **第 4 层** | 平台补充、`DLC/github`、Apple 分支 → `PROXY` | 6 条日志验证增量 + `DLC/github` + `DLC/apple-intelligence` + Safari OHTTP + Apple 情况 A/B 分支 |
| **第 5 层** | IP / DNS / WebRTC 检测站 → `PROXY` | `1ms.dog` / `1msapp.com` / `1ms.one` + `DLC/category-ip-geo-detect`（非 `@cn`/非 `@ads`，覆盖 37 个审计锚点） |
| **第 6 层** | Apple 直连（仅 A）+ 微软边界 / `amazon.cn` | 情况 A 下 App Store/iCloud/CIDR 直连；`cn.bing.com` / `bing@cn` / `amazon.cn` / NCSI / 微软 Akamai CDN 直连、`ipv6.msft*` `REJECT`、国际 `bing.com`/OneDrive 8 域代理 |
| **第 7 层** | 清洗版海外主干 → `PROXY` | `DLC/geolocation-!cn`（自动剔除 `@cn`/`@ads`/`@telemetry`、宽关键词 `aws`/`amazon`、第 8 层微软直连域及情况 A Apple 域）+ 海外增量 |
| **第 8 层** | 微软系统更新 + 国内总集 + 国内 IP → `DIRECT` | 清洁 `DLC/microsoft` + 净除广告后的 `DLC/cn` + `category-ai-cn` + 自动差集校准 Delta（113 条）+ `GEOIP,CN,DIRECT,no-resolve` |
| **第 9 层** | 终极兜底 → `PROXY` | FlClash：`MATCH,<主代理组>`；Shadowrocket：`FINAL,PROXY` + `[URL Rewrite]` / `[MITM]`（`*.google.cn`） |

---

## 四、项目目录结构

```text
AI-top-priority-white-list-for-VPN/
├── LICENSE                                    # MIT 开源许可证
├── README.md                                  # 项目总览、架构说明与快速上手
├── SKILL.md                                   # AI Agent Skill 触发定义与五步标准工作流
├── .gitignore                                 # 忽略缓存、临时 DLC 文件与本地生成产物
├── references/
│   ├── requirements_and_implementation.md     # 需求总览（R1~R9）、实现方案与常见坑位对照
│   ├── app_settings_guide.md                  # FlClash (Win/Android) 与 Shadowrocket (iOS) 客户端设置清单
│   └── curated_domains.md                     # 第 0 层模板与第 1~9 层精筛域名明细
└── scripts/
    ├── dlc_catalog.py                         # v2fly/domain-list-community 解析器与 SHA-256 拉取器
    ├── rule_catalog.py                        # 双端共享规则与精筛域名真源（零隐私硬编码）
    ├── build_subscription.py                  # 配置组装器：DLC + rule_catalog.py + 节点（仅保留 proxies/proxy-groups/可选 proxy-providers）按 0–9 层生成配置
    ├── audit_subscription.py                  # 离线静态质检脚本：不启动代理内核即可全量校验，--strict 遇错/警告即拦截
    └── verify_runtime.py                      # 可选：无头 Mihomo 内核 119 路三向真实路由探测脚本
```

---

## 五、快速使用

### 1. 作为 AI Agent Skill 安装

将本仓库克隆到 AI 编程助手（如 Antigravity / Claude Code 等）的全局或工作区 `skills` 目录即可自动加载：

```bash
git clone https://github.com/Franklin-cit/AI-top-priority-white-list-for-VPN.git ~/.gemini/config/skills/subscription-hardener
```

### 2. 直接通过命令行构建与校验

依赖 **Python 3.10+**（主构建与静态审计脚本仅使用 Python 标准库，零第三方包依赖；推荐统一加 `-B` 避免产生 `__pycache__`）。两个核心脚本分工明确：

1. **`scripts/build_subscription.py`**：将 `v2fly/domain-list-community`（DLC）域名库 + 项目精筛规则（`rule_catalog.py`）与节点配置按第 0–9 层分流流水线自动组装生成最终可用的硬化配置文件；对 FlClash 输入的基础 `.yaml` **只保留 `proxies`、`proxy-groups`（及节点集型订阅可选的 `proxy-providers`）**，不使用原配置自带的任何 `dns`、`rules` 或外部 `rule-providers`。
2. **`scripts/audit_subscription.py`**：在不启动代理内核的情况下，对已经生成的 `.yaml`（FlClash）或 `.conf`（Shadowrocket）执行全量静态质检，配合 `--strict` 可在出现任何错误或警告时直接报错拦截。

```bash
# 1. 构建 Shadowrocket (iOS) 完整无冲突版（首次传 --fetch-dlc 自动拉取并校验官方 DLC SHA-256）
#    若使用自建 VPS，追加 --direct-cidr <你的VPS_IP>/32 置顶防回环
python -B scripts/build_subscription.py \
  --mode sr \
  --dlc-source path/to/dlc.dat_plain.yml --fetch-dlc \
  --direct-cidr <VPS_IP>/32 \
  -o path/to/out_sr.conf

# 2. 构建 FlClash / Mihomo (Win/Android) 单文件纯内联版（从 base.yaml 仅提取 proxies、proxy-groups 与可选 proxy-providers）
python -B scripts/build_subscription.py \
  --mode flclash \
  --dlc-source path/to/dlc.dat_plain.yml \
  --base path/to/base.yaml \
  --direct-cidr <VPS_IP>/32 \
  -o path/to/out_flclash.yaml

# 3. 独立执行离线静态严格质检（构建末尾也会自动跑一遍）
python -B scripts/audit_subscription.py --mode sr --profile full --strict path/to/out_sr.conf
python -B scripts/audit_subscription.py --mode flclash --strict path/to/out_flclash.yaml

# 4. 可选：调用本地 Mihomo 内核执行 119 路真实路由探测（仅关 tun.enable，不触动 dns/sniffer）
python -B scripts/verify_runtime.py --config path/to/out_flclash.yaml --prepare-env --proxy-url http://127.0.0.1:7890
python -B scripts/verify_runtime.py --config path/to/out_flclash.yaml --mihomo path/to/mihomo
```

> **常用可选参数**：
> - `build_subscription.py`：`--dlc-source`（支持 `dlc.dat_plain.yml` 或本地 `domain-list-community/data/` 目录）、`--direct-cidr <IP/CIDR>`（可多次传入，构建前强校验 IPv4/IPv6 格式）、`--apple auto|a|b`、`--proxy-group "<组名>"`、`--user-conf <个人补充.conf>`（SR 仅用于少量个人内置 `PROXY`/`DIRECT`/`REJECT` 补充规则，**切勿传入机场原生 `.conf`**）、`--broad-auth0`、`--drop-geoip-cn`、`--name` / `--desc`。
> - `verify_runtime.py`：`--env-dir <geoip目录>`、`--allow-active-proxy`（宿主机代理在线时启用）、`--expect-proxy` / `--expect-direct` / `--expect-reject`。

导入客户端前，请务必对照 [references/app_settings_guide.md](references/app_settings_guide.md) 核对应用内开关（如 Windows 开 TUN 关「追加系统DNS」、Android 手动开启 `VPN → DNS 劫持` 并关闭系统私人 DNS、iOS 全局路由选「配置」并在删旧重导后开关飞行模式 5 秒清缓存）。

---

## 六、数据来源、隐私红线与免责声明

- **规则与内核来源**：
  - 骨干域名分类：[v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)
  - 本地验证内核：[MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo)
- **零隐私承诺**：本仓库全部脚本与文档均不含任何代理服务器 IP、节点域名、订阅链接、UUID/密钥凭据、服务商名称或本地个人路径；请勿将包含个人实机节点凭据的产出 `.yaml` / `.conf` 提交至公开仓库。
- **免责声明**：本项目仅用于客户端分流规则清洗、冲突消除与配置审计验证，不提供任何代理服务器或网络接入服务。请使用者严格遵守所在国家与地区的法律法规。

## License

[MIT](LICENSE)
