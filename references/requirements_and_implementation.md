# 需求汇总与实现方式备忘录 (Requirements & Implementation Notes)

> 本文档整理自多轮真实订阅改造、自动化测试、日志取证（SQLite DNS/Proxy 日志）与检测站评测（`check.1ms.dog`）的完整实战闭环，明确列出每一项核心用户需求、问题根因以及在 **Shadowrocket（iOS）** 和 **FlClash / Mihomo（Windows / Android）** 上的落地实现方式。文档已彻底剥离个人节点、订阅地址、IP、品牌与本地路径信息。

---

## 一、 全景需求总览（按优先级与演进脉络）

| 编号 | 用户核心需求 | 解决的痛点 / 原生订阅缺陷 | 核心实现策略 |
|---|---|---|---|
| **R1** | **主流 AI 全平台 100% 强制代理与防误杀**<br>OpenAI（含 Codex / Sora / 语音）、Anthropic（含 Claude Code）、Google AI（Gemini / Antigravity / AI Studio + 母域）、Meta AI（Muse / Llama + Meta 母域）、xAI（Grok）、微软 Copilot 与 Perplexity / Groq / Midjourney / Cursor | ① 原生订阅将 `microsoft` 直连规则排在 `openai` 前，截胡 OpenAI Azure 接口<br>② 缺乏 `claude.com`、`muse.ai`、`meta.ai`、`grok.com`、`antigravity`、`perplexity.ai`、`cursor.com` 等域名<br>③ 去广告规则误杀 `statsig` / `segment` / `featuregates` / `sentry` 等鉴权组件或未来 AI 新子域；反之若仅放母域又可能误放行 Google 自有广告节点 | 构建 **第 2 层 AI 保护层并强行置顶在第 3 层去广告之前**；采用 **方案 B**：2.3 顶部点穴拦截 `adservice.google.com` / `analytics.google.com` / `crashlyticsreports-pa.googleapis.com` → `REJECT`，紧接保留 `google.com`/`googleapis.com`/`gstatic.com` 等母域 → `PROXY` 保全 AI 组件；以严格 DNS 标签边界在去广告层剔除 AI 域，同时保留 Google `-cn` 广告变体与非 AI 第三方拦截 |
| **R2** | **Top500 白名单可直连 + 国内网站直连，其余海外全代理**<br>消除分层内部冲突与规则静默失效 | ① 原生订阅将 `RULE-SET,ads` 指向代理组而非 `REJECT`<br>② Top500 直连与海外代理列表存在 15+ 处同域/父子域冲突<br>③ `private` 错标 `classical` 失效；`google`/`gemini` 错标 `domain` 致 896 条规则失效 | 采用严格自上而下 **9 层漏斗模型**；由 `build_subscription.py` 执行同动作安全去重与交叉冲突清理（不同动作例外绝不静音吞并）；精确匹配 Mihomo `behavior: domain` vs `classical` 类型；明确区分国内直连 `DIRECT`、拦截 `REJECT` 与 `MATCH`/`FINAL` 代理兜底 |
| **R3** | **局域网流量 100% 最高优先级直连** | 路由器后台、NAS、打印机、本地服务、内网反向解析落入代理或卡死，或重复写多段 LAN CIDR / IPv6 语法错写成 `IP-CIDR` | **第 1 层**统一置顶处理 `.lan` / `.local` / `.arpa` / 路由器域 / 全量 RFC1918 & IPv6 私有网段（使用 `IP-CIDR6` 且全带 `,no-resolve`）；客户端开启「绕过私有路由地址」从系统路由层直出物理网卡 |
| **R4** | **控制 DNS 解析边界与消除 WebRTC 泄露**（社媒/AI 风控防识别国内环境） | ① 规则末尾 `GEOIP,CN,DIRECT`、`cn-ip` 与 FlClash `classical` `RULE-SET` 漏写 `,no-resolve`，导致 Fake-IP/未知海外域名触发国内 DNS 提前解析<br>② `cn-domain` 含 233 条 Apple/`mzstatic` 且通用微软后缀走海外 DoH 会把微软直连域解析到美国边缘 CDN（1.4~3s 高延迟）<br>③ `cloudflare.com` 误留直连白名单致 WebRTC STUN 与 Turnstile 暴露国内 IP；检测站 `1ms.dog` / `ipqs.com` 掉进直连 | ① 全局禁 IPv6（`ipv6 = false` / `ipv6: false`）<br>② **全量 IP / GEOIP / ASN / `cn-ip` 及 FlClash 所有 `classical` `RULE-SET` 强制加 `,no-resolve`**<br>③ FlClash 用 `fake-ip` + `#<主代理组>` DoH 作为默认 `nameserver`；`nameserver-policy` 按**精确优先**分流（`+.cn.bing.com` 国内 → Copilot/6.1 微软特例 & Apple 代理 DoH → `+.microsoft.com` 国内 DoH → `cn-domain`/`private`），且不污染 `fake-ip-filter`<br>④ Shadowrocket 用 `hijack-dns = *:53` + 第 5 层纳管检测站<br>⑤ 将 `cloudflare.com` 迁入代理层 |
| **R5** | **解决 TCP 协议节点（如 `anytls`）套 QUIC 卡顿，且不破坏语音通话与微信/QQ UDP** | ① 浏览器/App 默认发 UDP 443（HTTP/3），套进 TCP 隧道引发双重拥塞重传卡顿<br>② Shadowrocket 全局写死 `block-quic = all` 优先级高于 `[Rule]`，导致 QQ/微信直连 UDP `:8000`/`:80` 被误杀为 `BLOCK-QUIC -> REJECT` | ① **FlClash**：第 1.5 层 `AND,((NETWORK,UDP),(DST-PORT,443)),REJECT`（仅拦 443，不伤语音 UDP 高位/3478 端口及腾讯 `:8000`/`:80`，且不加腾讯系 UDP 白名单以避免 `gdt.qq.com` 等广告 UDP 443 绕过第 3 层 `REJECT`）<br>② **Shadowrocket**：`[General]` 改 `block-quic = all-proxy` + **第 1.5 层**先放行 QQ/微信 `AND,((PROTOCOL,UDP),(DOMAIN-SUFFIX,...)),DIRECT`（不放行腾讯 TCP 埋点广告），紧接 `AND,((PROTOCOL,UDP),(DEST-PORT,443)),REJECT-NO-DROP` 拦截其余 QUIC（经实机 Shadowrocket SQLite 日志表 `dns-*.db` / `proxy-*.db` 复核：`all` 会将直连 QQ/微信 UDP 记为 `BLOCK-QUIC -> REJECT`，改 `all-proxy` + 第 1.5 层后语音与普通 UDP 正常）<br>③ 实测 ChatGPT / Gemini 实时语音与普通 UDP 转发（需开节点 UDP 转发）正常 |
| **R6** | **iPhone（Shadowrocket）国内常用服务免绕美 + 严控规则体量适配 iOS 扩展约束** | ① 带 `no-resolve` 的 `GEOIP,CN` 在无庞大国内域名集时，会让 `.com`/`.net` 国内站点（爱奇艺、腾讯视频、小米、小红书、汽水音乐、个推等）掉进 `FINAL,PROXY` 绕美致延迟 260ms+<br>② iOS PacketTunnel 扩展进程受严格系统内存配额约束，强行内联 11 万条 `cn-domain` 易显著推高扩展驻留内存与加载耗时 | ① 拒绝粗暴内联 11 万条 `cn-domain`，改在第 8.1 层精选内联 **235 条高频非 `.cn` 国内域名与基础 CDN**（约 8 KB 文本，含 SQLite 日志实测补全的 `qishui.com`、`getui.com`、`ddnspod.com`、`ecombdpage.com` 及与 1.5 层对齐的 `servicewechat.com`、`wechatapp.com`；注：`baidu.com`/`taobao.com`/`qq.com`/`bilibili.com` 等头部大站依赖 `--sr-source` Top500 提供，8.1 层专司中长尾拾遗补缺）<br>② 提供 Shadowrocket 双版本：**极速轻量版**（空规则上游最小基线 **764 行 / 704 条规则**，其中 `[Rule]` 段 745 行；叠加标准上游列表通常约 1,200~4,300 行级别；内含 88 条精选核心广告后缀 + 全套防泄露与 235 条国内域）与 **完整无冲突版**（需搭配含完整上游广告库的 `--sr-source` 通过 `>=10,000` 条 REJECT 审计校验，仍避开 11 万域名膨胀）<br>③ 强制 Shadowrocket `.conf` 使用纯 **LF (`\n`)** 换行，剔除 iOS 不支持的 `PROCESS-NAME` |
| **R7** | **Apple / 微软精细化分流（多端差异化）** | ① 美区 App Store 安装包与国区 iCloud（或日常同步）走代理极耗流量且限速<br>② 误以为直连 iCloud 会同步到云上贵州<br>③ `microsoft.com` / `cloud.microsoft` 覆盖了国际版 Bing、OneDrive API 与新版 Copilot | ① **归属地说明**：iCloud 数据归属只由 Apple ID 注册地决定，与直连或代理无关<br>② **Shadowrocket（iOS 默认情况 A）**：仅 Apple Intelligence / Siri AI / Apple News / Apple TV+ 在 **4.7 层**走代理；App Store、iCloud 与 Apple CIDR 在 **第 6 层**走 `DIRECT`（第 7 层同步按严格后缀边界剔除 Apple 通用 CDN 残留）<br>③ **FlClash（Windows/Android 默认情况 B）**：无本地 App Store 分流需求，**4.7 层**整套 Apple 走代理<br>④ **微软精确拆分**：`cn.bing.com` 直连；国际版 `bing.com`、OneDrive 相关等 **共 8 个核心域**与 `copilot.microsoft.com`、`copilot.cloud.microsoft`、`designer.microsoft.com`、`copilotstudio.microsoft.com` 置前代理，使 `m365.cloud.microsoft` 恢复直连 |
| **R8** | **极致去重与匹配加速 + 保留节点同步灵活性** | ① 上游去广告规则集（~19.5 万条 `ads`）与全量 SR 广告规则（约 5.2~5.4 万条，历史基线实测 53,890 条）**重合度高达 99.46%**<br>② 机场随时可能更新节点 IP，直接改订阅文件后易被覆盖或丢失结构 | ① FlClash 中删去重复内联广告：默认不传 `--ads-ruleset` 时直接信任 `RULE-SET,ads,REJECT` 仅内联 88 条核心差集（总规则约 1,000 条最精简）；若传入新鲜 `--ads-ruleset <ads.yaml>`（缓存超 7 天会提示刷新），则进一步比对并将 `ads.yaml` 漏收条目内联补充（约 4,300~4,500 条）<br>② 默认保留 `GEOIP,CN,DIRECT,no-resolve` 兜底；但在已有 `cn-ip.mrs` 的低内存场景下，提供 `--drop-geoip-cn` 参数按需省略冗余 `GEOIP,CN`（避免重复触发全局 GeoIP 数据库加载）<br>③ Shadowrocket 不写死 `[Proxy]`，自动调用首页订阅选中节点；FlClash 通过 `build_subscription.py` 完整保留机场原始 `proxies:`、`proxy-groups:` 与专项策略组（如流媒体/Emby） |
| **R9** | **可审计、可真机闭环验证、开源脱敏可分享** | ① 自动化测试脚本全局替换 `enable: true -> false` 时把 `dns.enable` 和 `sniffer.enable` 一起关掉导致“假通过”<br>② 检测站评分易引起焦虑，分不清配置问题与物理/节点问题<br>③ 用户需将 Skill 方案公开分享到 GitHub | ① 建立独立四脚本工程体系（`rule_catalog.py` + `build_subscription.py` + `audit_subscription.py --strict` + `verify_runtime.py`）；`verify_runtime.py` 使用**块作用域解析仅禁用 `tun.enable`**，保持 `dns:`/`sniffer:` 100% 原样并默认验证含 `adservice.google.com -> REJECT` 在内的三路探测<br>② 同步提供 iOS 真机核验清单与日志取证规范（FlClash 日常 `info` / 排障 `debug`）<br>③ 全套 Skill 模板、文档与脚本实现 **零个人隐私硬编码** |

---

## 二、 关键技术细节与常见坑位对照（Implementation Pitfalls）

### 1. Mihomo / FlClash 规则集 `behavior` 严密性
- `dns.fake-ip-filter` 与 `dns.nameserver-policy` 中引用的 `rule-set:` **仅支持 `behavior: domain` 的规则集**（例如 `cn-domain`、`private`）；若引用 `classical` 规则集，`mihomo -t` 会报警甚至拒绝生效。
- 反之，当远端规则集内容包含 `DOMAIN,xxx`、`DOMAIN-KEYWORD` 或 `PROCESS-NAME`（如常见的 `google`、`gemini`、`claude`、`apple`、`openai` 规则集），YAML 中**必须声明 `behavior: classical`**；若错写成 `domain`，整组规则会静默跳过不生效。

### 2. 微软与流媒体跨层误杀实证补丁
- **OpenAI Azure 依赖**：`RULE-SET,microsoft,DIRECT` 必须位于第 8 层；第 2 层先由 `RULE-SET,openai` 与显式域名接管 `*.blob.core.windows.net`、`*.azurefd.net`、`*.azureedge.net`。
- **Copilot vs M365 网页版**：不要把父域 `DOMAIN-SUFFIX,cloud.microsoft` 直接代理（会拖慢 `m365.cloud.microsoft` 办公），而是精确在第 2 层仅写 `copilot.cloud.microsoft`、`designer.microsoft.com`、`copilotstudio.microsoft.com`。
- **流媒体追踪短链**：`disneyplus.bn5x.net` 会被第 3 层 `ads` 中的 `+.bn5x.net` 误拦，必须放到第 2.5 层（第 3 层 `ads` 正上方），放在第 4 层依然会被截胡。
- **过度宽泛的关键字/域名**：
  - 第 7 层需剔除 `DOMAIN-KEYWORD,aws`（会误杀 `draws.io`、`laws.com`）与 `DOMAIN-KEYWORD,amazon`（会在第 7 层截胡 `.cn` 规则，导致 `amazonaws.cn`、`amazonpay.cn`、`z.cn` 绕美），保留准确后缀即可；
  - `DOMAIN-SUFFIX,auth0.com` 风险提示：OpenAI 登录用的是 `auth0.openai.com`（已被 `openai.com` 覆盖），放宽 `auth0.com` 会令大量无关第三方 SaaS 走代理；若需严格缩窄范围，构建时传入 `--strict-auth0` 即可自动剔除裸 `auth0.com`。
  - 第 3 层纳入 `doubleclick.com`、`admob.com`、`2mdn.net`、`miaozhen.com`、`mmstat.com`、`mintegral.com`、`gdt.qq.com`、`mobads.baidu.com` 等高频移动端与国内广告 SDK，并将零散广告子域升级为精确父域（如 `api.cupid.iqiyi.com` 升级为 `DOMAIN-SUFFIX,cupid.iqiyi.com,REJECT`）。
  - 第 8 层统一追加 `yuque.com` 与国产 AI 主站（`deepseek.com`、`doubao.com`、`volcengine.com`、`kimi.com`、`tongyi.com`、`minimaxi.com` 等）走向 `DIRECT`。

### 3. 自动化测试脚本中的 P0 正则陷阱（实测总结）
- 用 `mihomo.exe` 在无头关闭 TUN 模式下验证“真实代理效果”时，**严禁**执行 `re.sub(r"enable:\s*true", "enable: false", text)`。该操作会把 `dns.enable: true` 与 `sniffer.enable: true` 一并禁用，导致 Fake-IP 和域名嗅探失效，使测试失去意义。
- **正确改法**：仅解析到缩进归属 `tun:` 块内部修改 `enable: false`；若原文件没有 `tun:` 块，直接在配置末尾追加 `tun:\n  enable: false\n`，同时在失败时不删除临时目录与 `run.log` 以便定位规则行号。
- 预下载依赖注意**“先代理准备、再断代理实测”**的先后顺序：下载 `mihomo` 内核、`geoip.metadb`、`geosite.dat` 与所有 `rule-providers` 必须在代理畅通时完成；`verify_runtime.py --prepare-env` 预热完毕并落盘缓存（默认 `<temp>/flclash_test_env` 或 `--env-dir`）后，再关闭本地 Clash/FlClash 系统代理与 TUN（或按需加 `--allow-active-proxy` / `--mihomo <路径>`）启动隔离测试端口（自动分配可用端口）进行 `--expect-proxy`、`--expect-direct`、`--expect-reject` 三维拨测。

### 4. `check.1ms.dog` 与日志分析：如何区分“可修复配置问题”与“节点/物理限制”
- **可通过修改配置 / 软件设置改善的项**：
  1. **DNS 显示国内运营商**：漏加 `,no-resolve` / 未开 Android「DNS 劫持」/ 浏览器开了安全 DNS / iPhone 未开飞行模式清缓存或留有加密 DNS 描述文件。
  2. **Cloudflare WebRTC 显示国内**：`cloudflare.com` 被放进了第 6 层直连白名单，须迁回代理层。
  3. **爱奇艺、腾讯视频、QQ、小红书等国内服务延迟高或判海外**：Shadowrocket 缺少第 8.1 层高频 `.com`/`.net` 国内直连清单。
  4. **浏览器 HTTP/3 报错后频繁卡顿（`anytls` 节点）**：未拦截 UDP 443（QUIC）。
  5. **QQ/微信语音信令或短连接 UDP 被小火箭 `BLOCK-QUIC` 拦下**：改用 `block-quic = all-proxy` + 第 1.5 层 QQ/微信 UDP 白名单。
  6. **全端口 UDP 不通（如 3478/19302 失败）**：检查小火箭节点详情页「UDP 转发」是否打开；全通后不影响安全但可保障 ChatGPT/Gemini 实时语音。
  7. **浏览器时区警告**：客户端配置无法修改系统时钟，若高敏感账号需强一致，可在系统日期与时间设置中手动切至与出口一致的时区（日常 AI 使用一般无需切换）。
- **无法通过本地分流配置突破的物理/IP 属性限制**：
  1. **往返延迟差（浏览器 ~220ms vs 节点到 CF ~10–20ms）** 与 **TCP/OS 指纹差异（iOS/Android vs Linux 服务器）**：跨国代理隧道固有的物理特征。
  2. **非节点所在地区的流媒体解锁（如美国 IP 解锁日本/欧洲平台）** 或节点 IP 本身被部分美区流媒体（如 Paramount+、Sling TV）拉黑 / 服务器侧中转导致某平台识别为其他国家。
  3. **节点带宽上限、跨太平洋基础 RTT 与路由器 Bufferbloat**：需切换订阅中更低延迟节点，或在本地路由器开启 SQM（`fq_codel` / `CAKE`）。
