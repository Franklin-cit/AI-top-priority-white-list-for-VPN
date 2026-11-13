# AI Top Priority White List for VPN (`subscription-hardener`)

本项目提供一套用于代理客户端订阅配置改造与确定性构建的 AI Agent 技能包（Skill）及配套 Python 工具脚本。它能够将常见的机场原生订阅（Clash / Mihomo `.yaml` 或 Shadowrocket `.conf`）转换为结构严谨、规则无冲突且可通过脚本验证的分流配置，确保主流 AI 服务优先通过代理连接，同时修复去广告规则失效、DNS 与 WebRTC 地址泄露、QUIC 协议拥塞以及国内常用服务高延迟绕行的问题。

---

## 一、应用范围

本项目同时支持 iOS 端 Shadowrocket 与桌面/移动端 FlClash（Mihomo 内核），两端的共用部分为 9 层核心优先级序列，其余策略则根据各平台客户端的运行限制与使用场景分别生成默认配置：

### 1. Shadowrocket（iOS 客户端，输出 `.conf`）
- **格式与兼容性**：强制使用纯 LF（`\n`）换行符与 UTF-8 无 BOM 编码，移除 iOS 不支持的 `PROCESS-NAME` 规则；不硬编码 `[Proxy]` 节点段，内置策略 `PROXY` 自动对接客户端首页当前选中的节点，更新订阅节点时不破坏规则结构。
- **内存与体量控制**：iOS 网络扩展进程（`NEPacketTunnelProvider`）受严格系统内存配额限制，本项目禁止将约 11 万条完整 `cn-domain` 域名列表直接内联写入 `.conf` 文件，并提供两个可选规格：
  - **极速轻量版（`--profile lite`，主推）**：内联 88 条核心广告联盟与移动广告后缀、235 条高频非 `.cn` 国内域名、13 条国产 AI 域名、第 2 层 AI 服务规则以及第 1.5 层微信/QQ UDP 例外规则。使用空上游占位测试时基线为 764 行 / 704 条规则，搭配标准白名单上游文件时通常在 1,300 行左右，内存占用极低。
  - **完整无冲突版（`--profile full`）**：在轻量版基础上内联经过冲突与边界清理的完整上游去广告规则库（约 5.2 至 5.4 万条 `REJECT` 规则，具体数量随上游规则库每日构建浮动）。
- **默认 Apple 分流策略（情况 A，`--apple a`）**：美区专属服务（Apple Intelligence、Siri 人工智能、Apple News、Apple TV+）在第 4.7 层通过代理访问；美区 App Store 安装包下载 CDN、iCloud 与 Apple IP 网段在第 6.0 层配置为直连，并在第 7 层代理列表中移除与之冲突的通用 Apple CDN 域名。

### 2. FlClash / Mihomo（Windows 桌面端与 Android 移动端，输出 `.yaml`）
- **配置重构与原生保留**：基于用户提供的原生机场 `.yaml` 订阅重新生成 `rules`、`dns` 与 `sniffer` 段，完整保留原文件中的节点列表 `proxies`、策略组 `proxy-groups`、面向非主策略组的专项分流规则（例如流媒体或 Emby 分组）以及远端 `rule-providers`。
- **Provider 类型自动修正**：自动检测并修正 `rule-providers` 中的 `behavior` 字段声明（例如 `private` 应为 `domain`，而包含混合规则语法的 `google`、`gemini`、`openai` 等应为 `classical`），避免 Mihomo 内核因声明错误跳过整组规则。
- **默认 Apple 分流策略（情况 B，`--apple b`）**：Windows 与 Android 端无本地 iOS App Store 与 iCloud 下载分流需求，默认将 Apple 相关规则归入第 4.7 层通过代理访问（如有多端共享配置需求，可传入 `--apple a` 切换为情况 A）。

---

## 二、分流机制

1. **自上而下顺序匹配与首次命中即停**
   代理内核按规则列表从第 1 条开始依次匹配；一旦请求的域名或目标 IP 命中任意一条规则，立即按照该规则指定的动作（`DIRECT`、`REJECT` 或代理策略组）处理并结束匹配流程。因此，配置必须将局域网地址直连、AI 服务代理与广告拦截依次排列在通用平台列表与末尾默认规则之前。

2. **AI 服务最高优先级与谷歌广告精确隔离（方案 B）**
   将 OpenAI、Anthropic、Google AI、Meta AI、xAI、Microsoft Copilot 及独立 AI 服务商（Perplexity、Groq、Midjourney、Cursor）的域名、关联母公司根域名以及 AI 鉴权/特性开关组件（如 `statsig.com`、`featuregates.org`、`segment.com`、`sentry.io`）统一置顶在第 2 层，使其优先于第 3 层广告规则生效，确保 AI 客户端及后续新增子域名不被阻断。同时，为防止将 `google.com`、`googleapis.com` 等根域名整体置于去广告层之前后导致谷歌自有广告同时通过，在第 2.3 层顶部优先放置三条精确 `REJECT` 规则（`adservice.google.com`、`analytics.google.com`、`crashlyticsreports-pa.googleapis.com`），从而兼顾 Google AI 服务的可用性与广告屏蔽能力。

3. **严格 DNS 标签边界清理与同动作安全去重**
   在清理第 3 层去广告规则、第 6.2 层 Top500 直连白名单与第 7 层海外代理规则之间的重复和冲突条目时，脚本严格基于完整域名标签边界（精确相等或带 `.` 前缀的子域后缀）判定，不使用宽泛的子字符串匹配，确保 `googlesyndication-cn.com` 等国内谷歌广告变体不被当成海外谷歌白名单清除。同时，规则去重仅当更靠前的祖先规则与当前规则**动作完全一致**时才跳过冗余子域；动作不同时（例如 `cn.bing.com` 直连排在国际版 `bing.com` 代理之前、`github-avatars.oss-cn-hongkong.aliyuncs.com` 代理排在 `aliyuncs.com` 直连之前）均予以完整保留。

4. **DNS 解析边界控制与防泄露机制**
   - 双端配置文件及 DNS 配置块内全部关闭 IPv6（`ipv6: false` / `ipv6 = false`），防止本机 IPv6 链路导致真实地址暴露或无出口超时。
   - 全部 `IP-CIDR`、`IP-CIDR6`、`IP-ASN`、`GEOIP`、`RULE-SET,cn-ip` 规则，以及 FlClash 中所有 `behavior: classical` / `ipcidr` 类型的 `RULE-SET` 统一附加 `,no-resolve`，防止未知域名触发本地 DNS 提前解析。
   - FlClash 使用 `dns.enhanced-mode: fake-ip`，默认 `nameserver`（Google / Cloudflare DoH）绑定主代理组后缀经代理通道查询；`nameserver-policy` 按最精确匹配优先原则分段处理：将 `+.cn.bing.com`、通用微软后缀 `+.microsoft.com` 等以及仅限 `behavior: domain` 的 `cn-domain`、`private` 规则集交由国内 DoH 解析，避免直连域名被解析到高延迟海外服务器；同时将 Copilot 相关域、第 6.1 层微软代理域与 Apple 域名（情况 B）显式指派至绑定代理组的海外 DoH。

5. **QUIC（UDP 443）拦截与微信/QQ 兼容性处理**
   - 使用基于 TCP 传输的节点协议（如 `anytls`、`Trojan`、`VLESS`）时，允许 UDP 443 的 QUIC 请求会在 TCP 代理通道内部再次进行拥塞控制与丢包重传，引发明显延迟与卡顿。
   - **FlClash 机制**：第 1.5 层直接使用 `AND,((NETWORK,UDP),(DST-PORT,443)),REJECT` 拦截 UDP 443，促使客户端改用基于 TCP 的 HTTPS 连接。该规则仅作用于 443 端口，不影响微信/QQ 原生端口（如 `8000` / `80`）的 UDP 通信，且不对腾讯系开放 UDP 443 白名单，防止 `gdt.qq.com` 等第 3 层广告域名通过 UDP 443 绕过拦截。
   - **Shadowrocket 机制**：在 `[General]` 中使用 `block-quic = all-proxy`（仅在底层抑制代理流量的 QUIC，避免全局阻断干扰直连微信/QQ UDP），再在第 1.5 层先显式放行 8 个微信与 QQ 关联域名的 UDP 请求，紧接着对其余 UDP 443 请求执行 `REJECT-NO-DROP`。

6. **FlClash 广告规则集去重选择（`--ads-ruleset` 参数行为）**
   当原订阅已包含 `RULE-SET,ads` 且构建时不传入 `--ads-ruleset` 时，构建器直接信任 `RULE-SET,ads` 承担主体去广告任务，仅保留 88 条核心广告后缀差集（总内联规则约 1,000 条左右，文件体积最小）；若传入本地最新的 `ads.yaml` 缓存文件，构建器会将上游约 5.2 至 5.4 万条 SR 广告列表与 `ads.yaml` 逐条比对，把尚未被 `ads.yaml` 收录的差集补充内联到第 3 层（总规则通常在 4,300 至 4,500 条左右），用于进一步提高广告拦截完整性。

---

## 三、分层情况

配置整体由第 0 层底层参数与第 1 层至第 9 层按顺序执行的分流规则组成：

| 层级 | 名称与核心目的 | 动作 | FlClash（Win / Android）包含内容 | Shadowrocket（iOS）包含内容 |
|---|---|---|---|---|
| **第 0 层** | 底层网络、DNS 与防泄露参数 | 运行前配置 | 关闭全局与 DNS IPv6；启用 `fake-ip`、`sniffer` 与 `unified-delay`；配置代理组绑定的海外 DoH 及分层 `nameserver-policy` | 设置 `ipv6 = false`、`hijack-dns = *:53`、`block-quic = all-proxy`、国内外 DoH、`skip-proxy`、`bypass-tun` 与 `always-real-ip` |
| **第 1 层** | 局域网与私有地址 | `DIRECT` | 内联局域网域名、路由器保留域名、私有 IPv4/IPv6 网段（全带 `,no-resolve`）及 `RULE-SET,private,DIRECT` | 内联局域网域名、路由器管理域、`.arpa` 反向解析域与全部私有 CIDR（全带 `,no-resolve`） |
| **第 1.5 层** | QUIC（UDP 443）拦截 | `REJECT` / 例外 `DIRECT` | `AND,((NETWORK,UDP),(DST-PORT,443)),REJECT` | 先对 8 个腾讯微信/QQ 关联域名放行 UDP `DIRECT`，随后对其余 `UDP 443` 执行 `REJECT-NO-DROP` |
| **第 2 层** | AI 平台、母域名与相关组件 | `PROXY`（2.3 顶部 3 条 `REJECT`） | 2.1 OpenAI、2.2 Anthropic、2.3 Google（含顶部 3 条方案 B `REJECT` 与 `googleapis`/`gstatic` 等）、2.4 Meta / xAI / Copilot 4 域 / 独立 AI 平台、2.5 防误阻断条目（含 `disneyplus.bn5x.net`）、ASN 与 `openai`/`claude`/`gemini` 规则集（国产 AI 不在此层） | 全量内联第 2.1 至 2.5 层规则与 OpenAI / Meta ASN（均带 `,no-resolve`）；支持 `--strict-auth0` 仅保留 `auth0.openai.com` 而不开放泛 `auth0.com` |
| **第 3 层** | 广告与追踪统计拦截 | `REJECT` | `RULE-SET,ads,REJECT` 结合核心或全量差集补充（严格保留 Google `-cn` 与独立广告变体） | 轻量版内联 88 条核心广告后缀（`CORE_AD_SUFFIXES`）；完整版内联清洗后的全量去广告规则（约 5.2 至 5.4 万条 `REJECT`） |
| **第 4 层** | 国际常用服务与 Apple 代理分支 | `PROXY` | 4.1 Twitter/X、4.2 YouTube 与 Google 规则集、4.3 Meta 社交、4.4 Telegram/Discord/TikTok/Line、4.5 GitHub 与开发社区、4.6 海外流媒体与测速；**4.7 默认情况 B** 将 Apple 全生态设为代理 | 内联 4.1 至 4.6 层规则（剔除冲突项）；**4.7 默认情况 A** 仅包含美区 Apple Intelligence / Siri AI / Apple News / Apple TV+ |
| **第 5 层** | IP、DNS 与 WebRTC 检测站 | `PROXY` | 强制代理 `1ms.dog`、`ipqs.com`、`ipinfo.io` 等 36 个常用网络诊断与环境检测域名 | 同左（确保检测站请求在到达第 8 层前已匹配代理） |
| **第 6 层** | Apple 直连分支、微软特定分流与 Top500 | `DIRECT`（6.1 含 8 域 `PROXY`） | 情况 B 下不生成 6.0；**6.1** 将 `cn.bing.com` 设为直连，国际版 `bing.com` 与 OneDrive 共 8 域设为代理；**6.2** `amazon.cn,DIRECT`、`zoom.us`（可选）及 Top500 直连白名单（已剔除 `cloudflare.com`） | **6.0（默认情况 A）** 将 App Store、iCloud 与 Apple CIDR（`,no-resolve`）设为直连；随后执行 **6.1** 与 **6.2**（同步剔除 `cloudflare.com` 与通用 Apple CDN） |
| **第 7 层** | 其余海外代理域名与 IP | `PROXY` | 合并保留原订阅专项策略组路由、`cloudflare.com` 与清洗后的上游海外代理域名（已移除过宽关键字 `aws`、`amazon` 与冲突广告项） | 同左（另按后缀边界清理情况 A 下的通用 Apple CDN 条目，并支持 `--user-conf` 合并旧自定义规则） |
| **第 8 层** | 国内服务与直连规则集 | `DIRECT` | **8.0** `.cn`、`RULE-SET,microsoft,DIRECT,no-resolve`、字节跳动规则集（或内联 13 条字节域，其中 `feishu.cn` 会被前面的 `.cn` 同动作跳过）、13 个国产 AI 主站与 `yuque.com`、`RULE-SET,cn-domain,DIRECT`；**8.2** `RULE-SET,cn-ip,DIRECT,no-resolve` 与 `GEOIP,CN,DIRECT,no-resolve`（可选 `--drop-geoip-cn` 省略后者） | **8.0** 内联微软常用 14 域（或展开本地 `microsoft.yaml`）与字节跳动 13 域；**8.1** 内联在 `--sr-source` Top500 之外补充的 235 条高频非 `.cn` 国内域名（含 `servicewechat.com`、`wechatapp.com` 与 `yuque.com`）、13 条国产 AI 与 `DOMAIN-SUFFIX,cn,DIRECT` 共 249 条规则；**8.2** `GEOIP,CN,DIRECT,no-resolve` |
| **第 9 层** | 未命中前序规则时的默认处理 | `PROXY` | `MATCH,<主代理组名称>` | `FINAL,PROXY`，规则段之后保留针对 `google.cn` 执行 302 跳转的 `[URL Rewrite]` 与 `[MITM]` |

---

## 四、项目目录结构

```text
AI-top-priority-white-list-for-VPN/
├── LICENSE                                    # MIT 开源许可证
├── README.md                                  # 项目说明（应用范围、分流机制、分层结构与命令）
├── SKILL.md                                   # AI Agent 技能工作流定义（五步构建与校验流程）
├── .gitignore                                 # 忽略 Python 缓存与本地临时输出文件
├── references/
│   ├── requirements_and_implementation.md     # 完整需求说明（R1~R9）、实测边界条件与常见错误记录
│   ├── app_settings_guide.md                  # FlClash (Win/Android) 与 Shadowrocket (iOS) 客户端设置清单
│   └── curated_domains.md                     # 第 0 层与第 1~9 层核心规则和域名明细文档
└── scripts/
    ├── rule_catalog.py                        # 双端共享规则与域名常量目录（无个人隐私信息）
    ├── build_subscription.py                  # 确定性配置构建器（清洗、边界判定与同动作去重）
    ├── audit_subscription.py                  # 静态规则结构检查脚本（支持 --profile 与 --strict）
    └── verify_runtime.py                      # 可选：调用无头 Mihomo 内核执行三路连通性测试
```

---

## 五、快速使用

### 1. 作为 AI Agent Skill 安装
将本仓库克隆到 AI 编程助手（如 Antigravity / Claude Code）的全局或工作区 `skills` 目录即可调用：

```bash
git clone https://github.com/Franklin-cit/AI-top-priority-white-list-for-VPN.git ~/.gemini/config/skills/subscription-hardener
```

### 2. 直接通过命令行构建与校验

依赖 Python 3.10+（主构建与静态审计脚本仅使用标准库，不依赖第三方包；若环境已安装 PyYAML，FlClash 静态体检会额外执行 `yaml.safe_load` 语法校验）：

```bash
# 1. 构建 Shadowrocket (iOS) 极速轻量版（自动拉取上游白名单去广告源）
python scripts/build_subscription.py --mode sr --profile lite --sr-source path/to/sr_top500_whitelist_ad.conf --fetch-sr -o path/to/shadowrocket-lite.conf

# 2. 构建 FlClash (Win/Android) 配置（保留原订阅节点与策略组；如需广告全量差集补充可追加 --ads-ruleset path/to/ads.yaml）
python scripts/build_subscription.py --mode flclash --sr-source path/to/sr_top500_whitelist_ad.conf --fetch-sr --base path/to/native-airport.yaml -o path/to/flclash.yaml

# 3. 静态严格校验
python scripts/audit_subscription.py --mode sr --profile lite --strict path/to/shadowrocket-lite.conf
python scripts/audit_subscription.py --mode flclash --strict path/to/flclash.yaml

# 4. 可选：使用本地 Mihomo 内核执行真实路由验证（仅禁用 tun.enable，保持 dns 与 sniffer 启用）
python scripts/verify_runtime.py --config path/to/flclash.yaml --prepare-env --proxy-url http://127.0.0.1:7890
python scripts/verify_runtime.py --config path/to/flclash.yaml
```

构建完成后，请参考 [references/app_settings_guide.md](references/app_settings_guide.md) 核对客户端内设置（例如 Windows 端开启虚拟网卡 TUN 并关闭「追加系统DNS」、Android 端手动开启 VPN「DNS 劫持」、iOS 端全局路由设为「配置」并在切换后开关飞行模式刷新系统 DNS 缓存）。

---

## 六、规则来源与免责声明

- **规则与内核来源**：上游白名单与广告规则来源为 [Johnshall/Shadowrocket-ADBlock-Rules-Forever](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever)，本地验证依赖内核为 [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo)。
- **隐私与免责声明**：本仓库所有脚本与文档均不包含任何代理节点服务器地址、订阅链接、账号凭据或本地个人路径；项目仅用于客户端配置转换、规则冲突清理与分流验证测试，不提供任何代理服务器或翻墙服务。使用者应确保遵守所在地区的法律法规。

## License

[MIT](LICENSE)
