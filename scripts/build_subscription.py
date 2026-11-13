#!/usr/bin/env python3
"""Deterministic builder, cleaner, and action-scoped deduplicator for hardened subscriptions.

Supports both divergent platforms cleanly:
- Shadowrocket (--mode sr): iOS .conf with Lite/Full profiles, Apple Situation A (US-only
  AI/News/TV+ proxy + App Store/iCloud direct), QQ/WeChat UDP whitelist + QUIC block,
  235 domestic non-.cn + CDN rules, pure LF, no hardcoded [Proxy].
- FlClash / Mihomo (--mode flclash): Windows/Android .yaml hardening from an arbitrary
  airport base config, preserving proxies, proxy-groups, and specialized non-main group
  routes, fixing DNS/Sniffer/behavior, deduplicating ads, and checking proxy-groups.

All domain checks use strict DNS label boundaries and action-scoped deduplication so
cross-action exceptions (Scheme B Google REJECT, cn.bing.com, GitHub HK avatars,
iOS US-only Apple) are never swallowed silently.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
import time
import urllib.request

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from audit_subscription import (  # noqa: E402
    _extract_proxy_group_names,
    _extract_yaml_top_blocks,
    _strip_inline_comment,
    _strip_yaml_quotes,
    audit_flclash,
    audit_shadowrocket,
    format_report,
)
from rule_catalog import (  # noqa: E402
    AI_PROTECTED_EXACT,
    AI_PROTECTED_SUFFIXES,
    ANTHROPIC_EXACT_DOMAINS,
    ANTHROPIC_KEYWORDS,
    ANTHROPIC_SUFFIXES,
    APPLE_CIDRS_V4,
    APPLE_CIDRS_V6,
    APPLE_COMMON_SUFFIXES,
    APPLE_SR_DIRECT_EXTRA_SUFFIXES,
    APPLE_SR_DIRECT_KEYWORDS,
    APPLE_SR_US_ONLY_SUFFIXES,
    BUILTIN_MIHOMO_ACTIONS,
    BYTEDANCE_COMMON_SUFFIXES,
    CHECKER_DOMAINS_36,
    CN_DOMESTIC_AI_SUFFIXES,
    CN_DOMESTIC_DEV_EXTRA,
    CORE_AD_SUFFIXES,
    FLCLASH_DEFAULT_NAMESERVER,
    FLCLASH_DOMESTIC_DOH,
    FLCLASH_FAKE_IP_FILTER_BASE,
    FLCLASH_PROXY_SERVER_NAMESERVER,
    FLCLASH_SNIFFER_SKIP,
    GOOGLE_AI_AND_PARENT_SUFFIXES,
    GOOGLE_AI_KEYWORDS,
    GOOGLE_CN_AD_VARIANTS,
    LAN_EXACT_DOMAINS,
    LAN_IPV4_CIDRS,
    LAN_IPV6_CIDRS,
    LAN_SUFFIXES,
    LAYER7_REMOVED_KEYWORDS,
    LAYER25_PROTECTION_SUFFIXES,
    META_ASNS,
    META_COPILOT_SUFFIXES,
    MICROSOFT_AI_SUFFIXES,
    MICROSOFT_COMMON_SUFFIXES,
    MS_61_DIRECT,
    MS_61_PROXY_8,
    OPENAI_ASNS,
    OPENAI_BROAD_AUTH0,
    OPENAI_COMPANION_SUFFIXES,
    OPENAI_EXACT_DOMAINS,
    OPENAI_IPV4_CIDRS,
    OPENAI_KEYWORDS,
    OPENAI_SUFFIXES,
    OTHER_AI_SUFFIXES,
    PLATFORM_41_TWITTER,
    PLATFORM_42_YOUTUBE,
    PLATFORM_43_META_SOCIAL,
    PLATFORM_44_MSG,
    PLATFORM_45_DEV_COMMUNITY,
    PLATFORM_46_STREAMING,
    PROVIDER_EXPECTED_BEHAVIOR,
    PUBLIC_SR_WHITELIST_URL,
    SCHEME_B_GOOGLE_REJECT_DOMAINS,
    SR_CN_NON_CN_235,
    SR_DIRECT_SKIP_EXACT,
    SR_GENERAL_LINES,
    SR_LAN_INLINE_DOMAINS,
    SR_LAN_INLINE_SUFFIXES,
    SR_TENCENT_UDP_SUFFIXES,
    XAI_SUFFIXES,
    domain_in_suffix_set,
)

IP_NO_RESOLVE_TYPES = {"IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"}


def _flclash_ruleset_rule(
    rs_name: str,
    action: str,
    provider_behaviors: dict[str, str] | None = None,
) -> str:
    """Format a FlClash RULE-SET line with ',no-resolve' for ipcidr and classical sets."""
    beh = (
        PROVIDER_EXPECTED_BEHAVIOR.get(rs_name)
        or (provider_behaviors or {}).get(rs_name)
        or ("ipcidr" if rs_name.lower() in {"cn-ip", "geoip-cn"} else "classical")
    )
    if beh != "domain":
        return f"RULE-SET,{rs_name},{action},no-resolve"
    return f"RULE-SET,{rs_name},{action}"


class RuleEmitter:
    """Action-scoped, anti-false-kill rule emitter supporting Shadowrocket and YAML lines."""

    def __init__(self, platform: str) -> None:
        self.platform = platform
        self.lines: list[str] = []
        self.seen_exact: dict[tuple[str, str], tuple[str, str]] = {}
        self.seen_suffix_actions: dict[str, dict[str, str]] = {}
        self.notes: list[str] = []
        self.rule_count = 0

    def comment(self, text: str) -> None:
        prefix = "#" if self.platform == "sr" else "  #"
        self.lines.append(f"{prefix} {text}")

    def blank(self) -> None:
        self.lines.append("")

    def _format_rule(self, rule_text: str) -> str:
        if self.platform == "sr":
            return rule_text
        escaped = rule_text.replace('"', '\\"')
        return f'  - "{escaped}"'

    def add_raw(self, rule_text: str) -> None:
        self.lines.append(self._format_rule(rule_text))
        self.rule_count += 1

    def add(
        self,
        typ: str,
        value: str,
        action: str,
        layer: str,
        no_resolve: bool = False,
    ) -> bool:
        t = typ.strip().upper()
        v = value.strip()
        act = action.strip()
        if not t or not act:
            return False
        if self.platform == "sr" and t == "PROCESS-NAME":
            return False
        if t == "IP-CIDR" and ":" in v:
            t = "IP-CIDR6"

        v_low = v.lower()
        act_low = act.lower()
        key = (t, v_low)

        if key in self.seen_exact:
            prev_layer, prev_act = self.seen_exact[key]
            if prev_act.lower() != act_low:
                self.notes.append(
                    f"[{layer}] skipped exact unreachable '{t},{v},{act}' "
                    f"(overridden earlier by [{prev_layer}] '{prev_act}')"
                )
            return False

        # Guardrail 1: only deduplicate child domains against an ancestor with the SAME action.
        # Different-action ancestors are logged cleanly instead of silently eating exceptions.
        if t in {"DOMAIN", "DOMAIN-SUFFIX"}:
            parts = v_low.strip(".").split(".")
            for i in range(len(parts)):
                parent = ".".join(parts[i:])
                acts = self.seen_suffix_actions.get(parent)
                if acts:
                    if act_low in acts:
                        return False
                    prev_act, prev_layer = next(iter(acts.items()))
                    self.notes.append(
                        f"[{layer}] skipped shadowed '{t},{v},{act}' "
                        f"(shadowed by [{prev_layer}] 'DOMAIN-SUFFIX,{parent},{prev_act}')"
                    )
                    return False

        self.seen_exact[key] = (layer, act)
        if t == "DOMAIN-SUFFIX":
            self.seen_suffix_actions.setdefault(v_low.strip("."), {})[act_low] = layer

        needs_nr = no_resolve or t in IP_NO_RESOLVE_TYPES
        if t == "RULE-SET" and v_low in {"cn-ip", "geoip-cn"}:
            needs_nr = True
        rule_str = f"{t},{v},{act},no-resolve" if needs_nr else f"{t},{v},{act}"
        self.add_raw(rule_str)
        return True


def fetch_sr_whitelist(dest: pathlib.Path, url: str = PUBLIC_SR_WHITELIST_URL) -> pathlib.Path:
    """Download public upstream Shadowrocket whitelist conf when explicitly requested."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "subscription-hardener/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()
    if len(data) < 10_000 or b"[Rule]" not in data:
        raise ValueError(f"Downloaded upstream whitelist looks invalid ({len(data)} bytes)")
    dest.write_bytes(data)
    return dest


def parse_sr_upstream(
    sr_path: pathlib.Path,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]], list[tuple[str, str]], list[tuple[str, str]]]:
    """Parse upstream Shadowrocket [Rule] entries into (reject_dom, reject_ip, direct, proxy)."""
    reject_dom: list[tuple[str, str]] = []
    reject_ip: list[tuple[str, str]] = []
    direct: list[tuple[str, str]] = []
    proxy: list[tuple[str, str]] = []

    in_rule = False
    for raw in sr_path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = raw.strip()
        if s == "[Rule]":
            in_rule = True
            continue
        if s.startswith("[") and s.endswith("]"):
            in_rule = False
            continue
        if not in_rule or not s or s.startswith(("#", ";")):
            continue
        parts = [p.strip() for p in s.split(",")]
        if len(parts) < 3:
            continue
        typ = parts[0].upper()
        if parts[-1].lower() == "no-resolve":
            parts = parts[:-1]
        if len(parts) < 3:
            continue
        act = parts[-1].lower()
        val = ",".join(parts[1:-1]).strip()
        if typ in {"RULE-SET", "GEOIP", "FINAL", "MATCH", "URL-REGEX", "USER-AGENT"}:
            continue
        if typ in {"IP-CIDR", "IP-CIDR6"}:
            ip_typ = "IP-CIDR6" if ":" in val else "IP-CIDR"
            pair = (ip_typ, val)
            if act.startswith("reject"):
                reject_ip.append(pair)
            elif act == "direct":
                direct.append(pair)
            elif act == "proxy":
                proxy.append(pair)
        else:
            pair = (typ, val.lower())
            if act.startswith("reject"):
                reject_dom.append(pair)
            elif act == "direct":
                direct.append(pair)
            elif act == "proxy":
                proxy.append(pair)

    return (
        list(dict.fromkeys(reject_dom)),
        list(dict.fromkeys(reject_ip)),
        list(dict.fromkeys(direct)),
        list(dict.fromkeys(proxy)),
    )


def load_ads_domain_set(ads_path: pathlib.Path) -> tuple[set[str], set[str], list[str]]:
    """Load Clash ads ruleset (behavior: domain) and warn if cached file is older than 7 days."""
    warnings: list[str] = []
    age_days = (time.time() - ads_path.stat().st_mtime) / 86400.0
    if age_days > 7.0:
        warnings.append(
            f"ads ruleset '{ads_path}' is {age_days:.1f} days old; consider refreshing before deduplication"
        )
    suffixes: set[str] = set()
    exact: set[str] = set()
    for raw in ads_path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = raw.strip()
        if not s.startswith("- "):
            continue
        val = s[2:].strip().strip("'\"").lower()
        if val.startswith("+."):
            suffixes.add(val[2:])
        elif val.startswith("."):
            suffixes.add(val[1:])
        elif val:
            exact.add(val)
    return suffixes, exact, warnings


def is_in_ads_set(typ: str, val: str, ads_suffixes: set[str], ads_exact: set[str]) -> bool:
    v = val.lower()
    if typ == "DOMAIN-KEYWORD":
        return False
    if v in ads_exact or v in ads_suffixes:
        return True
    return domain_in_suffix_set(v, ads_suffixes)


_INLINE_RULESET_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"}


def load_clash_ruleset_entries(path: pathlib.Path) -> list[tuple[str, str]]:
    """Load Clash ruleset YAML (classical or domain) into normalized (TYPE, VALUE) tuples."""
    if not path.is_file():
        return []
    out: list[tuple[str, str]] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = raw.strip()
        if not s.startswith("- "):
            continue
        val = s[2:].strip().strip("'\"")
        if "," in val:
            parts = [p.strip() for p in val.split(",")]
            typ = parts[0].upper()
            v = parts[1]
            if typ not in _INLINE_RULESET_TYPES:
                continue
            if typ in {"IP-CIDR", "IP-CIDR6"}:
                typ = "IP-CIDR6" if ":" in v else "IP-CIDR"
            elif typ in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
                v = v.lower()
            out.append((typ, v))
        else:
            v = val.lower()
            if v.startswith("+."):
                out.append(("DOMAIN-SUFFIX", v[2:]))
            elif v.startswith("."):
                out.append(("DOMAIN-SUFFIX", v[1:]))
            elif v:
                out.append(("DOMAIN", v))
    return out


def is_ai_protected_reject_candidate(typ: str, val: str) -> bool:
    """Guardrail 2: strict DNS label-boundary protection for AI domains in Layer 3."""
    v = val.lower()
    if typ == "DOMAIN-KEYWORD":
        return v in set(OPENAI_KEYWORDS) | set(ANTHROPIC_KEYWORDS) | set(GOOGLE_AI_KEYWORDS)
    if v in AI_PROTECTED_EXACT:
        return True
    return domain_in_suffix_set(v, AI_PROTECTED_SUFFIXES)


def is_apple_direct_for_sr_a(typ: str, val: str) -> bool:
    """Strict label-boundary check for generic Apple CDN entries filtered from SR Situation A Layer 7."""
    apple_roots = {
        *APPLE_COMMON_SUFFIXES,
        *APPLE_SR_DIRECT_EXTRA_SUFFIXES,
        "apple.com.akadns.net",
        "apple.com.edgekey.net",
        "icloud.com.akadns.net",
    }
    v = val.lower()
    if typ == "DOMAIN-KEYWORD":
        return v in set(APPLE_SR_DIRECT_KEYWORDS)
    if domain_in_suffix_set(v, set(APPLE_SR_US_ONLY_SUFFIXES)):
        return False
    return domain_in_suffix_set(v, apple_roots)


def _expand_ruleset_into(
    emitter: RuleEmitter,
    rulesets_dir: pathlib.Path | None,
    name: str,
    target: str,
    layer: str,
    skip_domains: set[str] | None = None,
) -> int:
    if not rulesets_dir:
        return 0
    cnt = 0
    for typ, val in load_clash_ruleset_entries(rulesets_dir / f"{name}.yaml"):
        if skip_domains and typ in {"DOMAIN", "DOMAIN-SUFFIX"} and val.lower() in skip_domains:
            continue
        if emitter.add(typ, val, target, layer):
            cnt += 1
    return cnt


def _emit_common_layers_1_to_5(
    emitter: RuleEmitter,
    proxy_target: str,
    platform: str,
    sr_reject_dom: list[tuple[str, str]],
    sr_reject_ip: list[tuple[str, str]],
    strict_auth0: bool = False,
    rulesets_dir: pathlib.Path | None = None,
    ads_filter: tuple[set[str], set[str]] | None = None,
    lite_mode: bool = False,
    apple_mode: str = "a",
    available_providers: set[str] | None = None,
    provider_behaviors: dict[str, str] | None = None,
) -> dict[str, int]:
    """Emit Layers 1 through 5 cleanly for either Shadowrocket or FlClash."""
    counts = {"ad": 0}
    prov = available_providers or set()

    # --- Layer 1: LAN / Private ---
    emitter.comment("===== 1. 局域网 / 私有地址（最高优先级直连） =====")
    for d in LAN_EXACT_DOMAINS:
        emitter.add("DOMAIN", d, "DIRECT", "L1")
    for suf in LAN_SUFFIXES:
        emitter.add("DOMAIN-SUFFIX", suf, "DIRECT", "L1")
    for ip4 in LAN_IPV4_CIDRS:
        emitter.add("IP-CIDR", ip4, "DIRECT", "L1", no_resolve=True)
    for ip6 in LAN_IPV6_CIDRS:
        emitter.add("IP-CIDR6", ip6, "DIRECT", "L1", no_resolve=True)
    if platform == "flclash":
        if "private" in prov:
            emitter.add_raw(_flclash_ruleset_rule("private", "DIRECT", provider_behaviors))
    else:
        for d in SR_LAN_INLINE_DOMAINS:
            emitter.add("DOMAIN", d, "DIRECT", "L1")
        for suf in SR_LAN_INLINE_SUFFIXES:
            emitter.add("DOMAIN-SUFFIX", suf, "DIRECT", "L1")
        _expand_ruleset_into(emitter, rulesets_dir, "private", "DIRECT", "L1")

    # --- Layer 1.5: QUIC Blocking + SR QQ/WeChat UDP Whitelist ---
    emitter.blank()
    if platform == "sr":
        emitter.comment("===== 1.5 腾讯 QQ/微信 UDP 白名单与非 QQ/微信 QUIC (UDP 443) 拦截 =====")
        for suf in SR_TENCENT_UDP_SUFFIXES:
            emitter.add_raw(f"AND,((PROTOCOL,UDP),(DOMAIN-SUFFIX,{suf})),DIRECT")
        emitter.add_raw("AND,((PROTOCOL,UDP),(DEST-PORT,443)),REJECT-NO-DROP")
    else:
        emitter.comment("===== 1.5 屏蔽 QUIC（UDP 443），自动回退 TCP 防止 anytls/Trojan 套娃丢包 =====")
        emitter.add_raw("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT")

    # --- Layer 2: AI Platforms & Parent Immunity (with Scheme B pinpoint Google REJECT) ---
    emitter.blank()
    emitter.comment("===== 2. 主流 AI 全平台及母公司根域置顶代理（第 2 层保护，免疫第 3 层误杀） =====")
    emitter.comment("--- 2.1 OpenAI (ChatGPT Web / App / Codex CLI / Sora) ---")
    for suf in OPENAI_SUFFIXES:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L2.1")
    for kw in OPENAI_KEYWORDS:
        emitter.add("DOMAIN-KEYWORD", kw, proxy_target, "L2.1")
    for dom in OPENAI_EXACT_DOMAINS:
        emitter.add("DOMAIN", dom, proxy_target, "L2.1")
    for suf in OPENAI_COMPANION_SUFFIXES:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L2.1")
    if not strict_auth0:
        for suf in OPENAI_BROAD_AUTH0:
            emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L2.1")
    for ip4 in OPENAI_IPV4_CIDRS:
        emitter.add("IP-CIDR", ip4, proxy_target, "L2.1", no_resolve=True)
    for asn in OPENAI_ASNS:
        emitter.add("IP-ASN", asn, proxy_target, "L2.1", no_resolve=True)
    if platform == "flclash" and "openai" in prov:
        emitter.add_raw(_flclash_ruleset_rule("openai", proxy_target, provider_behaviors))
    elif platform == "sr":
        skip_auth0 = set(OPENAI_BROAD_AUTH0) if strict_auth0 else None
        _expand_ruleset_into(emitter, rulesets_dir, "openai", proxy_target, "L2.1", skip_domains=skip_auth0)

    emitter.comment("--- 2.2 Anthropic (Claude Web / App / Claude Code CLI) ---")
    for suf in ANTHROPIC_SUFFIXES:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L2.2")
    for kw in ANTHROPIC_KEYWORDS:
        emitter.add("DOMAIN-KEYWORD", kw, proxy_target, "L2.2")
    for dom in ANTHROPIC_EXACT_DOMAINS:
        emitter.add("DOMAIN", dom, proxy_target, "L2.2")
    if platform == "flclash" and "claude" in prov:
        emitter.add_raw(_flclash_ruleset_rule("claude", proxy_target, provider_behaviors))
    elif platform == "sr":
        _expand_ruleset_into(emitter, rulesets_dir, "claude", proxy_target, "L2.2")

    emitter.comment("--- 2.3 Google AI 及 Google 母域（方案 B：顶部精准拦截谷歌自家广告，母域免疫三方误杀） ---")
    for g_rej in SCHEME_B_GOOGLE_REJECT_DOMAINS:
        emitter.add("DOMAIN-SUFFIX", g_rej, "REJECT", "L2.3-SchemeB")
    for suf in GOOGLE_AI_AND_PARENT_SUFFIXES:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L2.3")
    for kw in GOOGLE_AI_KEYWORDS:
        emitter.add("DOMAIN-KEYWORD", kw, proxy_target, "L2.3")
    if platform == "flclash" and "gemini" in prov:
        emitter.add_raw(_flclash_ruleset_rule("gemini", proxy_target, provider_behaviors))
    elif platform == "sr":
        _expand_ruleset_into(emitter, rulesets_dir, "gemini", proxy_target, "L2.3")

    emitter.comment("--- 2.4 Meta AI、Meta 全系母域 & Microsoft Copilot 专属入口 ---")
    for suf in META_COPILOT_SUFFIXES:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L2.4")
    for asn in META_ASNS:
        emitter.add("IP-ASN", asn, proxy_target, "L2.4", no_resolve=True)

    emitter.comment("--- 2.4.1 xAI (Grok) ---")
    for suf in XAI_SUFFIXES:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L2.4.1")

    emitter.comment("--- 2.4.2 其他主流海外 AI 与编码工具（Perplexity / Groq / Midjourney / Cursor） ---")
    for suf in OTHER_AI_SUFFIXES:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L2.4.2")

    emitter.comment("--- 2.5 AI 特性开关防误杀 & 流媒体短链保护 ---")
    for suf in LAYER25_PROTECTION_SUFFIXES:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L2.5")

    # --- Layer 3: Adblock ---
    emitter.blank()
    if platform == "flclash":
        emitter.comment("===== 3. 广告拦截（ads 规则集 + 差集补充 + 谷歌 -cn 变体，严格剔除 AI 保护域） =====")
        if "ads" in prov:
            emitter.add_raw(_flclash_ruleset_rule("ads", "REJECT", provider_behaviors))
    elif lite_mode:
        emitter.comment("===== 3. 广告拦截（极速轻量版：精选核心广告联盟与独有去广告补充，已剔除 AI 保护域） =====")
    else:
        emitter.comment("===== 3. 广告拦截（完整无冲突版：全量去广告库 + 核心广告联盟，已剔除 AI 保护域） =====")

    ads_sfx, ads_exact = ads_filter if ads_filter else (set(), set())
    for suf in CORE_AD_SUFFIXES:
        if ads_filter and platform == "flclash" and "ads" in prov and is_in_ads_set("DOMAIN-SUFFIX", suf, ads_sfx, ads_exact):
            continue
        if emitter.add("DOMAIN-SUFFIX", suf, "REJECT", "L3"):
            counts["ad"] += 1

    # On FlClash with 'ads' provider, deduplicate against ads.yaml (or skip 52k bulk if ads.yaml not cached).
    # On Shadowrocket, Full includes all cleaned SR ad entries; Lite stays strictly curated via CORE_AD_SUFFIXES.
    include_bulk_sr = (
        (platform == "flclash" and (ads_filter is not None or "ads" not in prov))
        or (platform == "sr" and not lite_mode)
    )
    if include_bulk_sr:
        for typ, val in sr_reject_dom:
            if is_ai_protected_reject_candidate(typ, val):
                continue
            dom = "cupid.iqiyi.com" if val == "api.cupid.iqiyi.com" else val
            if ads_filter and is_in_ads_set(typ, dom, ads_sfx, ads_exact):
                continue
            if emitter.add(typ, dom, "REJECT", "L3"):
                counts["ad"] += 1
        for typ, ipval in sr_reject_ip:
            if emitter.add(typ, ipval, "REJECT", "L3", no_resolve=True):
                counts["ad"] += 1

    # --- Layer 4: Global Mainstream Platforms & Divergent Apple Branch ---
    emitter.blank()
    emitter.comment("===== 4. 全球主流国外平台强制代理 =====")
    emitter.comment("--- 4.1 Twitter / X 全家桶 ---")
    for suf in PLATFORM_41_TWITTER:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L4.1")

    emitter.comment("--- 4.2 YouTube & Google 扩展生态 ---")
    for suf in PLATFORM_42_YOUTUBE:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L4.2")
    if platform == "flclash":
        for rs in ("google", "youtube"):
            if rs in prov:
                emitter.add_raw(_flclash_ruleset_rule(rs, proxy_target, provider_behaviors))
    else:
        google_ad_skip_set = set(GOOGLE_CN_AD_VARIANTS) | set(CORE_AD_SUFFIXES)
        _expand_ruleset_into(emitter, rulesets_dir, "google", proxy_target, "L4.2", skip_domains=google_ad_skip_set)
        _expand_ruleset_into(emitter, rulesets_dir, "youtube", proxy_target, "L4.2")

    emitter.comment("--- 4.3 Instagram / Threads / WhatsApp ---")
    for suf in PLATFORM_43_META_SOCIAL:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L4.3")
    if platform == "flclash":
        for rs in ("facebook", "instagram", "whatsapp"):
            if rs in prov:
                emitter.add_raw(_flclash_ruleset_rule(rs, proxy_target, provider_behaviors))
    else:
        for rs in ("facebook", "instagram", "whatsapp"):
            _expand_ruleset_into(emitter, rulesets_dir, rs, proxy_target, "L4.3")

    emitter.comment("--- 4.4 Telegram / Discord / Line / TikTok ---")
    for suf in PLATFORM_44_MSG:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L4.4")
    if platform == "flclash":
        for rs in ("telegram", "tiktok", "line"):
            if rs in prov:
                emitter.add_raw(_flclash_ruleset_rule(rs, proxy_target, provider_behaviors))
    else:
        for rs in ("telegram", "tiktok", "line"):
            _expand_ruleset_into(emitter, rulesets_dir, rs, proxy_target, "L4.4")

    emitter.comment("--- 4.5 GitHub / HuggingFace / Docker / 开发者与知识社区 ---")
    for suf in PLATFORM_45_DEV_COMMUNITY:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L4.5")
    if platform == "flclash" and "github" in prov:
        emitter.add_raw(_flclash_ruleset_rule("github", proxy_target, provider_behaviors))
    elif platform == "sr":
        _expand_ruleset_into(emitter, rulesets_dir, "github", proxy_target, "L4.5")

    emitter.comment("--- 4.6 海外流媒体与测速 ---")
    for suf in PLATFORM_46_STREAMING:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L4.6")
    if platform == "flclash" and "speedtest" in prov:
        emitter.add_raw(_flclash_ruleset_rule("speedtest", proxy_target, provider_behaviors))
    elif platform == "sr":
        _expand_ruleset_into(emitter, rulesets_dir, "speedtest", proxy_target, "L4.6")

    if apple_mode == "a":
        emitter.comment("--- 4.7 美区 Apple 专属服务代理（Situation A：Apple Intelligence / News / TV+） ---")
        for suf in APPLE_SR_US_ONLY_SUFFIXES:
            emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L4.7")
    else:
        emitter.comment("--- 4.7 Apple 全生态代理（Situation B：Win/Android 或外区常驻） ---")
        for suf in APPLE_COMMON_SUFFIXES:
            emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L4.7")
        if platform == "flclash" and "apple" in prov:
            emitter.add_raw(_flclash_ruleset_rule("apple", proxy_target, provider_behaviors))
        elif platform == "sr":
            _expand_ruleset_into(emitter, rulesets_dir, "apple", proxy_target, "L4.7")

    # --- Layer 5: 36 Diagnostic Checkers ---
    emitter.blank()
    emitter.comment(f"===== 5. IP 与 DNS 检测站（{len(CHECKER_DOMAINS_36)} 条，强制走代理） =====")
    for dom in CHECKER_DOMAINS_36:
        emitter.add("DOMAIN-SUFFIX", dom, proxy_target, "L5")

    return counts


def _emit_common_layers_6_to_9(
    emitter: RuleEmitter,
    proxy_target: str,
    platform: str,
    sr_direct: list[tuple[str, str]],
    sr_proxy: list[tuple[str, str]],
    apple_mode: str = "a",
    zoom_mode: str = "direct",
    rulesets_dir: pathlib.Path | None = None,
    available_providers: set[str] | None = None,
    provider_behaviors: dict[str, str] | None = None,
    bytedance_provider: str | None = None,
    drop_geoip_cn: bool = False,
    custom_preserved_rules: list[str] | None = None,
) -> dict[str, int]:
    """Emit Layers 6 through 9 cleanly with platform-divergent Apple/CN handling."""
    prov = available_providers or set()
    counts = {"direct": 0, "proxy": 0}

    # --- Layer 6: Apple Situation A Direct + Microsoft 6.1 + Top500 Whitelist ---
    emitter.blank()
    if apple_mode == "a":
        emitter.comment("===== 6. Apple 下载/iCloud 直连 + 微软特例 + Top500 可直连白名单 =====")
        emitter.comment("--- 6.0 App Store / iCloud 与 Apple 通用服务直连（Situation A） ---")
        for suf in (*APPLE_COMMON_SUFFIXES, *APPLE_SR_DIRECT_EXTRA_SUFFIXES):
            emitter.add("DOMAIN-SUFFIX", suf, "DIRECT", "L6.0")
        for kw in APPLE_SR_DIRECT_KEYWORDS:
            emitter.add("DOMAIN-KEYWORD", kw, "DIRECT", "L6.0")
        for ip4 in APPLE_CIDRS_V4:
            emitter.add("IP-CIDR", ip4, "DIRECT", "L6.0", no_resolve=True)
        for ip6 in APPLE_CIDRS_V6:
            emitter.add("IP-CIDR6", ip6, "DIRECT", "L6.0", no_resolve=True)
        if platform == "sr":
            _expand_ruleset_into(emitter, rulesets_dir, "apple", "DIRECT", "L6.0")
        elif "apple" in prov:
            emitter.add_raw(_flclash_ruleset_rule("apple", "DIRECT", provider_behaviors))
    else:
        emitter.comment("===== 6. 微软特例 + Top500 可直连网站白名单 =====")

    emitter.comment("--- 6.1 微软特定分流（须排在第 8 层 microsoft 之前） ---")
    for dom in MS_61_DIRECT:
        emitter.add("DOMAIN-SUFFIX", dom, "DIRECT", "L6.1")
    for dom in MS_61_PROXY_8:
        emitter.add("DOMAIN-SUFFIX", dom, proxy_target, "L6.1")

    emitter.comment("--- 6.2 Top500 可直连网站白名单（已剔除 cloudflare.com，保留 amazon.cn） ---")
    if emitter.add("DOMAIN-SUFFIX", "amazon.cn", "DIRECT", "L6.2"):
        counts["direct"] += 1
    zoom_target = "DIRECT" if zoom_mode == "direct" else proxy_target
    emitter.add("DOMAIN-SUFFIX", "zoom.us", zoom_target, "L6.2")

    for typ, val in sr_direct:
        if val in SR_DIRECT_SKIP_EXACT:
            continue
        if typ in {"IP-CIDR", "IP-CIDR6"}:
            continue
        if emitter.add(typ, val, "DIRECT", "L6.2"):
            counts["direct"] += 1

    # --- Layer 7: Remaining Overseas Proxy Rules + Preserved Custom Airport Group Routes ---
    emitter.blank()
    emitter.comment("===== 7. 其余海外网站代理列表（含 cloudflare.com 代理保障，已剔除冲突项） =====")
    emitter.add("DOMAIN-SUFFIX", "cloudflare.com", proxy_target, "L7")
    cn_ad_set = set(GOOGLE_CN_AD_VARIANTS) | set(CORE_AD_SUFFIXES)

    if custom_preserved_rules:
        emitter.comment("--- 原生机场订阅保留的非主策略组自定义分流 ---")
        for raw_custom in custom_preserved_rules:
            emitter.add_raw(raw_custom)

    for typ, val in sr_proxy:
        if typ == "DOMAIN-KEYWORD" and val in LAYER7_REMOVED_KEYWORDS:
            continue
        if typ in {"DOMAIN", "DOMAIN-SUFFIX"} and domain_in_suffix_set(val, cn_ad_set):
            continue
        if apple_mode == "a" and is_apple_direct_for_sr_a(typ, val):
            continue
        if emitter.add(typ, val, proxy_target, "L7"):
            counts["proxy"] += 1

    # --- Layer 8: Domestic Routing ---
    emitter.blank()
    emitter.comment("===== 8. 国内分流（微软通用 / 字节系 / 国产 AI / 高频直连 / .cn / 国内 IP） =====")
    emitter.comment("--- 8.0 基础大厂直连与国内规则集 ---")
    if platform == "flclash":
        emitter.add("DOMAIN-SUFFIX", "cn", "DIRECT", "L8.0")
        if "microsoft" in prov:
            emitter.add_raw(_flclash_ruleset_rule("microsoft", "DIRECT", provider_behaviors))
        else:
            for suf in MICROSOFT_COMMON_SUFFIXES:
                emitter.add("DOMAIN-SUFFIX", suf, "DIRECT", "L8.0")
        if bytedance_provider and bytedance_provider in prov:
            emitter.add_raw(_flclash_ruleset_rule(bytedance_provider, "DIRECT", provider_behaviors))
        else:
            for suf in BYTEDANCE_COMMON_SUFFIXES:
                emitter.add("DOMAIN-SUFFIX", suf, "DIRECT", "L8.0")
        # Note: volces.com / volcengine.com bare roots have no public A record; traffic uses subdomains like ark.cn-beijing.volces.com
        for dom in (*CN_DOMESTIC_DEV_EXTRA, *CN_DOMESTIC_AI_SUFFIXES):
            emitter.add("DOMAIN-SUFFIX", dom, "DIRECT", "L8.0")
        if "cn-domain" in prov:
            emitter.add_raw(_flclash_ruleset_rule("cn-domain", "DIRECT", provider_behaviors))
    else:
        if rulesets_dir and (rulesets_dir / "microsoft.yaml").is_file():
            _expand_ruleset_into(emitter, rulesets_dir, "microsoft", "DIRECT", "L8.0")
        else:
            for suf in MICROSOFT_COMMON_SUFFIXES:
                emitter.add("DOMAIN-SUFFIX", suf, "DIRECT", "L8.0")
        for suf in BYTEDANCE_COMMON_SUFFIXES:
            emitter.add("DOMAIN-SUFFIX", suf, "DIRECT", "L8.0")

        emitter.comment("--- 8.1 Shadowrocket 国内主流 .com/.net、国产 AI 与 CDN 直连补全 ---")
        for dom in (*SR_CN_NON_CN_235, *CN_DOMESTIC_AI_SUFFIXES):
            emitter.add("DOMAIN-SUFFIX", dom, "DIRECT", "L8.1")
        emitter.add("DOMAIN-SUFFIX", "cn", "DIRECT", "L8.1")

    emitter.comment("--- 8.2 国内 IP 兜底与防泄露（全带 ,no-resolve） ---")
    if platform == "flclash":
        if "cn-ip" in prov:
            emitter.add_raw("RULE-SET,cn-ip,DIRECT,no-resolve")
        if not (drop_geoip_cn and "cn-ip" in prov):
            emitter.add_raw("GEOIP,CN,DIRECT,no-resolve")
    else:
        emitter.add_raw("GEOIP,CN,DIRECT,no-resolve")

    # --- Layer 9: Final Fallback ---
    emitter.blank()
    emitter.comment("===== 9. 终极兜底规则（其余未知海外网站一律走代理） =====")
    emitter.add_raw(f"FINAL,{proxy_target}" if platform == "sr" else f"MATCH,{proxy_target}")
    return counts


def _extract_sr_custom_user_rules(user_conf: pathlib.Path | None) -> list[str]:
    """Read non-empty custom rules from an existing Shadowrocket conf if supplied."""
    if not user_conf or not user_conf.is_file():
        return []
    in_rule = False
    out: list[str] = []
    for raw in user_conf.read_text(encoding="utf-8", errors="replace").splitlines():
        s = raw.strip()
        if s == "[Rule]":
            in_rule = True
            continue
        if s.startswith("[") and s.endswith("]"):
            in_rule = False
            continue
        if not in_rule or not s or s.startswith(("#", ";")):
            continue
        if s.upper().startswith(("FINAL,", "GEOIP,CN", "AND,((PROTOCOL,UDP)")):
            continue
        out.append(s)
    return out


def build_shadowrocket(
    out_path: pathlib.Path,
    sr_source: pathlib.Path,
    profile: str = "lite",
    apple_mode: str = "a",
    zoom_mode: str = "direct",
    strict_auth0: bool = False,
    rulesets_dir: pathlib.Path | None = None,
    ads_ruleset: pathlib.Path | None = None,
    user_conf: pathlib.Path | None = None,
    name: str = "Hardened-iOS-Shadowrocket",
    desc: str = "",
) -> int:
    """Build a hardened, pure-LF Shadowrocket .conf file and verify it with audit_subscription."""
    sr_reject_dom, sr_reject_ip, sr_direct, sr_proxy = parse_sr_upstream(sr_source)
    if ads_ruleset is not None:
        print("[INFO]  --ads-ruleset is only used in --mode flclash; ignored for Shadowrocket")
    # Shadowrocket has no RULE-SET,ads in generated configs; never strip SR ad entries against ads.yaml.
    ads_filter = None

    emitter = RuleEmitter("sr")
    custom_rules = _extract_sr_custom_user_rules(user_conf)
    if custom_rules:
        print(f"[INFO]  Parsed {len(custom_rules)} existing rule(s) from --user-conf; merging deduplicated non-conflicting rules into Layer 7")

    c15 = _emit_common_layers_1_to_5(
        emitter,
        proxy_target="PROXY",
        platform="sr",
        sr_reject_dom=sr_reject_dom,
        sr_reject_ip=sr_reject_ip,
        strict_auth0=strict_auth0,
        rulesets_dir=rulesets_dir,
        ads_filter=ads_filter,
        lite_mode=(profile == "lite"),
        apple_mode=apple_mode,
    )
    c69 = _emit_common_layers_6_to_9(
        emitter,
        proxy_target="PROXY",
        platform="sr",
        sr_direct=sr_direct,
        sr_proxy=sr_proxy,
        apple_mode=apple_mode,
        zoom_mode=zoom_mode,
        rulesets_dir=rulesets_dir,
        custom_preserved_rules=None,
    )

    if custom_rules:
        # Insert clean user custom domain/IP rules right above Layer 8 without breaking Layer 8/9
        insert_idx = next(
            (i for i, ln in enumerate(emitter.lines) if ln.startswith("# ===== 8.")),
            len(emitter.lines),
        )
        custom_added: list[str] = ["# --- Preserved custom user rules ---"]
        for cr in custom_rules:
            parts = [p.strip() for p in cr.split(",")]
            if len(parts) >= 3 and parts[0].upper() in {"DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "IP-CIDR6"}:
                typ = parts[0].upper()
                val = parts[1]
                act = parts[2] if parts[-1].lower() != "no-resolve" else parts[-2]
                if (typ, val.lower()) not in emitter.seen_exact:
                    if typ in {"IP-CIDR", "IP-CIDR6"}:
                        typ = "IP-CIDR6" if ":" in val else "IP-CIDR"
                        custom_added.append(f"{typ},{val},{act},no-resolve")
                    else:
                        custom_added.append(f"{typ},{val},{act}")
        if len(custom_added) > 1:
            emitter.lines[insert_idx:insert_idx] = custom_added + [""]

    profile_label = "极速轻量版" if profile == "lite" else "完整无冲突版"
    header_desc = desc or f"AI置顶防误杀(方案B) + {profile_label}去广告 + QQ/微信UDP直连 + Apple情况{apple_mode.upper()}"
    header = [
        f"#!name={name}",
        f"#!desc={header_desc}",
        "",
        *SR_GENERAL_LINES,
        "",
        "[Rule]",
    ]
    footer = [
        "",
        "[URL Rewrite]",
        r"^https?://(www.)?(g|google)\.cn https://www.google.com 302",
        "",
        "[MITM]",
        "hostname = *.google.cn",
        "",
    ]

    content = "\n".join(header + emitter.lines + footer)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(content.encode("utf-8"))

    print(
        f"[BUILD] Shadowrocket ({profile}, Apple={apple_mode.upper()}) -> {out_path} "
        f"(ads={c15['ad']}, top500_direct={c69['direct']}, sr_proxy={c69['proxy']}, rules={emitter.rule_count})"
    )
    for note in emitter.notes[:20]:
        print(f"[NOTE]  {note}")
    if len(emitter.notes) > 20:
        print(f"[NOTE]  ... and {len(emitter.notes) - 20} additional dedup/shadow notes")

    report = audit_shadowrocket(out_path, strict=True, profile=profile, apple_mode=apple_mode)
    print(format_report(report))
    return 1 if report.errors else 0


def _detect_primary_select_group(group_lines: list[tuple[int, str]]) -> str | None:
    """Detect the first `type: select` group name in FlClash/Mihomo proxy-groups."""
    cur_name: str | None = None
    for _, raw in group_lines[1:]:
        clean = _strip_inline_comment(raw).strip()
        if not clean:
            continue
        m_name = re.match(r"^(?:-\s+)?name\s*:\s*(.+)$", clean)
        if m_name:
            cur_name = _strip_yaml_quotes(m_name.group(1).strip())
            continue
        m_type = re.match(r"^type\s*:\s*(.+)$", clean)
        if m_type and cur_name:
            if _strip_yaml_quotes(m_type.group(1).strip()).lower() == "select":
                return cur_name
            cur_name = None
    names = sorted(_extract_proxy_group_names(group_lines))
    return names[0] if names else None


def _parse_provider_blocks(prov_lines: list[tuple[int, str]]) -> tuple[set[str], str | None, dict[str, str]]:
    """Return (provider_names, detected_bytedance_provider, effective_provider_behaviors)."""
    names: set[str] = set()
    behaviors: dict[str, str] = {}
    bytedance: str | None = None
    cur_name = ""
    base_indent = -1
    for _, raw in prov_lines[1:]:
        clean = _strip_inline_comment(raw)
        if not clean.strip():
            continue
        indent = len(clean) - len(clean.lstrip())
        s = clean.strip()
        if s.endswith(":") and (base_indent == -1 or indent <= base_indent):
            base_indent = indent
            cur_name = s[:-1].strip()
            names.add(cur_name)
            if cur_name in PROVIDER_EXPECTED_BEHAVIOR:
                behaviors[cur_name] = PROVIDER_EXPECTED_BEHAVIOR[cur_name]
            if "bytedance" in cur_name.lower():
                bytedance = cur_name
        elif cur_name:
            if s.startswith("behavior:") and cur_name not in PROVIDER_EXPECTED_BEHAVIOR:
                behaviors[cur_name] = s.split(":", 1)[1].strip().strip("\"'").lower()
            if "bytedance" in s.lower() or "douyin" in s.lower():
                bytedance = cur_name
    return names, bytedance, behaviors


def _rewrite_rule_providers_behavior(prov_lines: list[tuple[int, str]]) -> list[str]:
    """Fix mismatched provider behavior fields while preserving all custom airport providers."""
    if not prov_lines:
        return []
    out: list[str] = []
    cur_name = ""
    base_indent = -1
    for _, raw in prov_lines:
        clean = _strip_inline_comment(raw)
        s = clean.strip()
        if s and not raw.lstrip().startswith("#") and raw[0].isspace():
            indent = len(clean) - len(clean.lstrip())
            if s.endswith(":") and (base_indent == -1 or indent <= base_indent):
                base_indent = indent
                cur_name = s[:-1].strip()
            elif cur_name in PROVIDER_EXPECTED_BEHAVIOR and s.startswith("behavior:"):
                expected = PROVIDER_EXPECTED_BEHAVIOR[cur_name]
                leading = raw[: len(raw) - len(raw.lstrip())]
                out.append(f"{leading}behavior: {expected}")
                continue
        out.append(raw)
    return out


def _build_hardened_yaml_dns_and_sniffer(
    proxy_group: str,
    providers: set[str],
    existing_dns_lines: list[tuple[int, str]],
    apple_mode: str = "b",
) -> tuple[list[str], list[str]]:
    """Build hardened Layer 0 dns and sniffer YAML blocks with aligned Microsoft/Apple DoH routing."""
    # Preserve custom proxy-server-nameserver if present in airport config
    proxy_ns = list(FLCLASH_PROXY_SERVER_NAMESERVER)
    in_pns = False
    extracted_pns: list[str] = []
    for _, raw in existing_dns_lines:
        s = raw.strip()
        if s.startswith("proxy-server-nameserver:"):
            in_pns = True
            continue
        if in_pns:
            if s.startswith("- "):
                extracted_pns.append(s[2:].strip())
            elif s and not s.startswith("#"):
                in_pns = False
    if extracted_pns:
        proxy_ns = extracted_pns

    dns_lines = [
        "dns:",
        "    enable: true",
        "    ipv6: false",
        "    enhanced-mode: fake-ip",
        "    fake-ip-range: 198.18.0.1/16",
        "    fake-ip-filter:",
    ]
    for item in FLCLASH_FAKE_IP_FILTER_BASE:
        if item.startswith("rule-set:") and item.split(":", 1)[1] not in providers:
            continue
        dns_lines.append(f"        - {item}")

    dns_lines.append("    default-nameserver:")
    for ns in FLCLASH_DEFAULT_NAMESERVER:
        dns_lines.append(f"        - {ns}")

    overseas_doh = (
        f'"https://dns.google/dns-query#{proxy_group}"',
        f'"https://1.1.1.1/dns-query#{proxy_group}"',
    )
    dns_lines.append("    nameserver:")
    for srv in overseas_doh:
        dns_lines.append(f"        - {srv}")

    policy_entries: list[tuple[str, tuple[str, ...]]] = []
    seen_policy_keys: set[str] = set()

    def _add_ns_policy(key: str, servers: tuple[str, ...]) -> None:
        if key not in seen_policy_keys:
            seen_policy_keys.add(key)
            policy_entries.append((key, servers))

    # Order most-specific to broadest so exceptions cleanly override parent wildcards & cn-domain.
    for dom in MS_61_DIRECT:
        _add_ns_policy(f"+.{dom}", FLCLASH_DOMESTIC_DOH)
    for dom in (*MICROSOFT_AI_SUFFIXES, *MS_61_PROXY_8):
        _add_ns_policy(f"+.{dom}", overseas_doh)
    apple_overseas = APPLE_COMMON_SUFFIXES if apple_mode == "b" else APPLE_SR_US_ONLY_SUFFIXES
    for dom in apple_overseas:
        _add_ns_policy(f"+.{dom}", overseas_doh)
    for dom in MICROSOFT_COMMON_SUFFIXES:
        _add_ns_policy(f"+.{dom}", FLCLASH_DOMESTIC_DOH)
    for rs in ("cn-domain", "private"):
        if rs in providers:
            _add_ns_policy(f"rule-set:{rs}", FLCLASH_DOMESTIC_DOH)

    if policy_entries:
        dns_lines.append("    nameserver-policy:")
        for key, servers in policy_entries:
            dns_lines.append(f'        "{key}":')
            for srv in servers:
                dns_lines.append(f"            - {srv}")

    dns_lines.append("    proxy-server-nameserver:")
    for pns in proxy_ns:
        dns_lines.append(f"        - {pns}")

    sniffer_lines = [
        "sniffer:",
        "    enable: true",
        "    parse-pure-ip: true",
        "    sniff:",
        "        HTTP:",
        '            ports: ["80", 8080-8880]',
        "        QUIC:",
        '            ports: ["443", "8443"]',
        "        TLS:",
        '            ports: ["443", "8443"]',
        "    skip-domain:",
    ]
    for sk in FLCLASH_SNIFFER_SKIP:
        sniffer_lines.append(f"        - {sk}")

    return dns_lines, sniffer_lines


def _extract_specialized_airport_rules(
    rules_block: list[tuple[int, str]],
    main_group: str,
    defined_groups: set[str],
    provider_behaviors: dict[str, str] | None = None,
) -> list[str]:
    """Preserve non-main specialized proxy-group routes from base YAML (e.g. Emby/Streaming/Game)."""
    if not rules_block:
        return []
    specialized: list[str] = []
    ignored_targets = {main_group, *BUILTIN_MIHOMO_ACTIONS}
    for _, raw in rules_block[1:]:
        s = raw.strip()
        if not s or s.startswith("#") or not s.startswith("-"):
            continue
        item = _strip_yaml_quotes(_strip_inline_comment(s[1:].strip()))
        if not item:
            continue
        parts = [p.strip() for p in item.split(",")]
        if len(parts) < 2:
            continue
        act = parts[-2] if parts[-1].lower() == "no-resolve" and len(parts) >= 3 else parts[-1]
        act_clean = _strip_yaml_quotes(act)
        if act_clean in defined_groups and act_clean not in ignored_targets:
            if parts[0].upper() == "RULE-SET" and parts[-1].lower() != "no-resolve":
                item = _flclash_ruleset_rule(parts[1], act_clean, provider_behaviors)
            specialized.append(item)
    return specialized


def build_flclash(
    out_path: pathlib.Path,
    base_yaml: pathlib.Path,
    sr_source: pathlib.Path,
    ads_ruleset: pathlib.Path | None = None,
    proxy_group: str | None = None,
    apple_mode: str = "b",
    zoom_mode: str = "direct",
    strict_auth0: bool = False,
    drop_geoip_cn: bool = False,
) -> int:
    """Build a hardened FlClash/Mihomo .yaml for Win/Android preserving airport nodes and groups."""
    raw_lines = base_yaml.read_text(encoding="utf-8", errors="replace").splitlines()
    blocks = _extract_yaml_top_blocks(raw_lines)
    defined_groups = _extract_proxy_group_names(blocks.get("proxy-groups", []))
    target_group = proxy_group or _detect_primary_select_group(blocks.get("proxy-groups", []))
    if not target_group:
        raise ValueError("Could not auto-detect primary select proxy-group; pass --proxy-group explicitly")
    if defined_groups and target_group not in defined_groups:
        raise ValueError(f"Proxy group '{target_group}' not found in base YAML proxy-groups: {sorted(defined_groups)}")

    providers, bytedance_prov, provider_behaviors = _parse_provider_blocks(blocks.get("rule-providers", []))
    ads_filter = None
    if ads_ruleset and ads_ruleset.is_file():
        sfx, exact, cache_warns = load_ads_domain_set(ads_ruleset)
        for w in cache_warns:
            print(f"[WARN]  {w}")
        ads_filter = (sfx, exact)

    sr_reject_dom, sr_reject_ip, sr_direct, sr_proxy = parse_sr_upstream(sr_source)
    specialized_rules = _extract_specialized_airport_rules(
        blocks.get("rules", []),
        main_group=target_group,
        defined_groups=defined_groups,
        provider_behaviors=provider_behaviors,
    )
    if specialized_rules:
        print(f"[INFO]  Preserved {len(specialized_rules)} specialized airport rule(s) targeting non-main groups")

    # Assemble Layer 0 top blocks preserving proxies / proxy-groups / extra keys from base
    top_scalars = [
        "mixed-port: 7890",
        "mode: rule",
        "log-level: info",
        "ipv6: false",
        "unified-delay: true",
    ]
    dns_lines, sniffer_lines = _build_hardened_yaml_dns_and_sniffer(
        proxy_group=target_group,
        providers=providers,
        existing_dns_lines=blocks.get("dns", []),
        apple_mode=apple_mode,
    )
    prov_lines = _rewrite_rule_providers_behavior(blocks.get("rule-providers", []))

    head_lines: list[str] = [*top_scalars, ""]
    # Replace base top-level scalars cleanly and drop port/socks-port/allow-lan to minimize LAN exposure.
    handled_keys = {
        "mixed-port", "port", "socks-port", "allow-lan", "mode", "log-level",
        "ipv6", "unified-delay", "dns", "sniffer", "rule-providers", "rules",
    }
    head_lines.extend(dns_lines)
    head_lines.append("")
    head_lines.extend(sniffer_lines)
    head_lines.append("")

    for key, blk in blocks.items():
        if key in handled_keys:
            continue
        head_lines.extend(raw for _, raw in blk)
        if blk and blk[-1][1].strip():
            head_lines.append("")

    if prov_lines:
        head_lines.extend(prov_lines)
        if prov_lines[-1].strip():
            head_lines.append("")

    head_lines.append("rules:")

    emitter = RuleEmitter("flclash")
    c15 = _emit_common_layers_1_to_5(
        emitter,
        proxy_target=target_group,
        platform="flclash",
        sr_reject_dom=sr_reject_dom,
        sr_reject_ip=sr_reject_ip,
        strict_auth0=strict_auth0,
        ads_filter=ads_filter,
        lite_mode=False,
        apple_mode=apple_mode,
        available_providers=providers,
        provider_behaviors=provider_behaviors,
    )
    c69 = _emit_common_layers_6_to_9(
        emitter,
        proxy_target=target_group,
        platform="flclash",
        sr_direct=sr_direct,
        sr_proxy=sr_proxy,
        apple_mode=apple_mode,
        zoom_mode=zoom_mode,
        available_providers=providers,
        provider_behaviors=provider_behaviors,
        bytedance_provider=bytedance_prov,
        drop_geoip_cn=drop_geoip_cn,
        custom_preserved_rules=specialized_rules,
    )

    content = "\n".join(head_lines + emitter.lines) + "\n"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(content.encode("utf-8"))

    print(
        f"[BUILD] FlClash (group={target_group}, Apple={apple_mode.upper()}) -> {out_path} "
        f"(ad_extra={c15['ad']}, top500_direct={c69['direct']}, sr_proxy={c69['proxy']}, rules={emitter.rule_count})"
    )
    for note in emitter.notes[:20]:
        print(f"[NOTE]  {note}")
    if len(emitter.notes) > 20:
        print(f"[NOTE]  ... and {len(emitter.notes) - 20} additional dedup/shadow notes")

    report = audit_flclash(out_path, strict=True, apple_mode=apple_mode)
    print(format_report(report))
    return 1 if report.errors else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Deterministically build and harden Shadowrocket (.conf) or FlClash/Mihomo (.yaml) configs."
    )
    parser.add_argument("--mode", choices=["sr", "flclash"], required=True, help="Target platform config format")
    parser.add_argument("--sr-source", type=pathlib.Path, required=True, help="Path to sr_top500_whitelist_ad.conf")
    parser.add_argument(
        "--fetch-sr",
        action="store_true",
        help="Fetch public sr_top500_whitelist_ad.conf to --sr-source before building",
    )
    parser.add_argument(
        "--ads-ruleset",
        type=pathlib.Path,
        help="Optional cached Clash ads.yaml; omitted with native 'ads' provider keeps rules minimal (~1k), passed diffs upstream ad gaps",
    )
    parser.add_argument("--rulesets-dir", type=pathlib.Path, help="Optional cached Clash rulesets dir for SR inlining")
    parser.add_argument("--user-conf", type=pathlib.Path, help="Optional existing SR .conf to preserve custom rules")
    parser.add_argument("--base", type=pathlib.Path, help="Required for --mode flclash: native airport .yaml")
    parser.add_argument("--proxy-group", help="Override FlClash main select proxy group name")
    parser.add_argument("--profile", choices=["lite", "full"], default="lite", help="SR profile (default: lite)")
    parser.add_argument(
        "--apple",
        choices=["auto", "a", "b"],
        default="auto",
        help="Apple split strategy (auto: 'a' for SR iOS, 'b' for FlClash Win/Android)",
    )
    parser.add_argument("--zoom", choices=["direct", "proxy"], default="direct", help="zoom.us routing (default: direct)")
    parser.add_argument("--strict-auth0", action="store_true", help="Do not whitelist bare auth0.com in Layer 2.1")
    parser.add_argument(
        "--drop-geoip-cn",
        action="store_true",
        help="Omit redundant GEOIP,CN in FlClash when cn-ip provider exists (low-memory option)",
    )
    parser.add_argument("--name", default="Hardened-iOS-Shadowrocket", help="Shadowrocket #!name header")
    parser.add_argument("--desc", default="", help="Shadowrocket #!desc header")
    parser.add_argument("-o", "--out", type=pathlib.Path, required=True, help="Output file path")
    args = parser.parse_args(argv)

    if args.fetch_sr:
        fetch_sr_whitelist(args.sr_source)
    if not args.sr_source.is_file():
        print(f"[ERROR] --sr-source not found: {args.sr_source}", file=sys.stderr)
        return 2

    apple = args.apple
    if apple == "auto":
        apple = "a" if args.mode == "sr" else "b"

    if args.mode == "sr":
        return build_shadowrocket(
            out_path=args.out,
            sr_source=args.sr_source,
            profile=args.profile,
            apple_mode=apple,
            zoom_mode=args.zoom,
            strict_auth0=args.strict_auth0,
            rulesets_dir=args.rulesets_dir,
            ads_ruleset=args.ads_ruleset,
            user_conf=args.user_conf,
            name=args.name,
            desc=args.desc,
        )

    if not args.base or not args.base.is_file():
        print("[ERROR] --base <airport.yaml> is required for --mode flclash", file=sys.stderr)
        return 2
    return build_flclash(
        out_path=args.out,
        base_yaml=args.base,
        sr_source=args.sr_source,
        ads_ruleset=args.ads_ruleset,
        proxy_group=args.proxy_group,
        apple_mode=apple,
        zoom_mode=args.zoom,
        strict_auth0=args.strict_auth0,
        drop_geoip_cn=args.drop_geoip_cn,
    )


if __name__ == "__main__":
    raise SystemExit(main())
