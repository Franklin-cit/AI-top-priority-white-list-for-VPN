#!/usr/bin/env python3
"""Deterministic, zero-airport-rule builder driven by v2fly/domain-list-community.

Supports both platforms from a single DLC + Delta source of truth:
- Shadowrocket (--mode sr): iOS .conf (Full profile, Apple Situation A: US-only
  Intelligence/News/TV+/SafeBrowsing OHTTP proxy + App Store/iCloud direct), Layer 1.5
  Tencent ad UDP pre-reject + QQ/WeChat UDP whitelist + QUIC/PCDN block, lightweight
  high-precision DLC + telemetry REJECT, DLC geolocation-!cn overseas backbone, cleaned
  DLC cn + auto-subtracted Delta, hardened [General] DNS (#no-h3), pure LF.
- FlClash / Mihomo (--mode flclash): Win/Android single-file inline .yaml preserving ONLY
  proxies and proxy-groups from --base, stripping all remote HTTP rule-providers and
  replacing private/cn-domain with native Mihomo `type: inline, behavior: domain`
  providers for DNS fake-ip-filter / nameserver-policy + zero external file dependencies.
"""

from __future__ import annotations

import argparse
import ipaddress
import pathlib
import re
import sys

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from audit_subscription import (  # noqa: E402
    AUTO_TEST_GROUP_TYPES,
    _extract_proxy_entries,
    _extract_proxy_group_names,
    _extract_yaml_top_blocks,
    _parse_proxy_group_entries,
    _parse_proxy_provider_entries,
    _replace_flow_bracket_list,
    _split_inline_comment,
    _strip_inline_comment,
    audit_flclash,
    audit_shadowrocket,
    format_report,
)
from dlc_catalog import DlcCatalog, DlcEntry, fetch_dlc_plain  # noqa: E402
from rule_catalog import (  # noqa: E402
    AI_PROTECTED_EXACT,
    AI_PROTECTED_SUFFIXES,
    AMAZON_CN_DIRECT,
    ANTHROPIC_EXACT_DOMAINS,
    ANTHROPIC_KEYWORDS,
    ANTHROPIC_SUFFIXES,
    APPLE_CIDRS_V4,
    APPLE_CIDRS_V6,
    APPLE_COMMON_SUFFIXES,
    APPLE_SAFEBROWSING_OHTTP_SUFFIXES,
    APPLE_SR_DIRECT_EXTRA_SUFFIXES,
    APPLE_SR_DIRECT_KEYWORDS,
    APPLE_SR_US_ONLY_SUFFIXES,
    BUILTIN_MIHOMO_ACTIONS,
    BYTEDANCE_CN_DELTA_SUFFIXES,
    CHECKER_DELTA_DOMAINS,
    CN_DOMESTIC_AI_DELTA_SUFFIXES,
    CN_DOMESTIC_DELTA_SUFFIXES,
    CN_DOMESTIC_DEV_EXTRA,
    CORE_AD_SUFFIXES,
    DLC_CN_EXCLUDED_DOMAINS,
    FLCLASH_DEFAULT_NAMESERVER,
    FLCLASH_DNS_AD_REJECT_EXACT,
    FLCLASH_DNS_AD_REJECT_SUFFIXES,
    FLCLASH_DNS_ARPA_SUFFIXES,
    FLCLASH_DOMESTIC_DOH,
    FLCLASH_FAKE_IP_FILTER_BASE,
    FLCLASH_NCSI_DIRECT_SUFFIXES,
    FLCLASH_NCSI_IPV6_REJECT,
    FLCLASH_OVERSEAS_DOH_BASES,
    FLCLASH_PROXY_SERVER_NAMESERVER,
    FLCLASH_SNIFFER_SKIP,
    FLCLASH_TENCENT_UDP_PROCESSES,
    GOOGLE_AI_AND_PARENT_SUFFIXES,
    GOOGLE_AI_KEYWORDS,
    GOOGLE_CN_AD_VARIANTS,
    LAN_EXACT_DOMAINS,
    LAN_IPV4_CIDRS,
    LAN_IPV6_CIDRS,
    LAN_SUFFIXES,
    LAYER3_AD_EXEMPT_DOMAINS,
    LAYER3_EXACT_REJECT_DOMAINS,
    LAYER3_TELEMETRY_REJECT_DOMAINS,
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
    OVERSEAS_PROXY_DELTA_DOMAINS,
    PLATFORM_44_LOG_VERIFIED_DELTAS,
    SCHEME_B_EXEMPT_DOMAINS,
    SCHEME_B_GOOGLE_REJECT_DOMAINS,
    SR_GENERAL_LINES,
    SR_PCDN_NOISE_EXACT,
    SR_PCDN_NOISE_KEYWORDS,
    SR_PCDN_NOISE_SUFFIXES,
    SR_TENCENT_UDP_REJECT_SUFFIXES,
    SR_TENCENT_UDP_SUFFIXES,
    XAI_SUFFIXES,
    domain_in_suffix_set,
)

IP_NO_RESOLVE_TYPES = {"IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"}

_DLC_AD_VENDOR_LISTS = (
    "google",
    "bytedance",
    "tencent",
    "xiaomi",
    "apple",
    "baidu",
    "alibaba",
    "meta",
    "microsoft",
    "netease",
    "jd",
    "iqiyi",
    "kuaishou",
    "bilibili",
    "qihoo360",
)


def _normalize_cidr(value: str) -> tuple[str, str] | None:
    """Return canonical (IP-CIDR|IP-CIDR6, network_str) with host bits masked off."""
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None
    return ("IP-CIDR6" if net.version == 6 else "IP-CIDR", str(net))


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
        if "\\" in rule_text or '"' in rule_text:
            escaped = rule_text.replace("'", "''")
            return f"  - '{escaped}'"
        return f'  - "{rule_text}"'

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
        if t in {"IP-CIDR", "IP-CIDR6"}:
            norm = _normalize_cidr(v)
            if not norm:
                return False
            t, v = norm

        v_low = v if t == "DOMAIN-REGEX" else v.lower()
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


def is_ai_protected_reject_candidate(typ: str, val: str) -> bool:
    """Guardrail 2: strict DNS label-boundary protection for L2 AI & companion domains."""
    v = val.lower()
    if typ == "DOMAIN-KEYWORD":
        return v in set(OPENAI_KEYWORDS) | set(ANTHROPIC_KEYWORDS) | set(GOOGLE_AI_KEYWORDS)
    if typ == "DOMAIN-REGEX":
        return False
    if v in AI_PROTECTED_EXACT:
        return True
    return domain_in_suffix_set(v, AI_PROTECTED_SUFFIXES)


def is_apple_direct_for_sr_a(typ: str, val: str) -> bool:
    """Strict label-boundary check for generic Apple CDN entries filtered from L7 under Apple A."""
    apple_roots = {
        "apple",
        *APPLE_COMMON_SUFFIXES,
        *APPLE_SR_DIRECT_EXTRA_SUFFIXES,
        "apple.com.akadns.net",
        "apple.com.edgekey.net",
        "icloud.com.akadns.net",
    }
    v = val.lower()
    if typ == "DOMAIN-KEYWORD":
        return v in set(APPLE_SR_DIRECT_KEYWORDS)
    if typ == "DOMAIN-REGEX":
        return False
    if domain_in_suffix_set(v, set(APPLE_SR_US_ONLY_SUFFIXES)):
        return False
    return domain_in_suffix_set(v, apple_roots)


def _prepare_dlc_bundles(dlc: DlcCatalog, apple_mode: str) -> dict[str, object]:
    """Extract cleaned, conflict-free per-layer DLC sets with automatic exclusions."""
    httpdns_vals = {e.value for e in dlc.get("category-httpdns-cn") if e.typ in {"domain", "full"}}
    ad_exempt = set(LAYER3_AD_EXEMPT_DOMAINS) | httpdns_vals
    pcdn_blocked = set(SR_PCDN_NOISE_EXACT) | set(SR_PCDN_NOISE_SUFFIXES)

    # 1) Google Scheme B extensions from DLC/google@ads + @telemetry (exempt video-stats)
    scheme_b_exempt = set(SCHEME_B_EXEMPT_DOMAINS)
    google_parent_roots = set(GOOGLE_AI_AND_PARENT_SUFFIXES)
    scheme_b_extra: list[tuple[str, str]] = []
    seen_sb = set(SCHEME_B_GOOGLE_REJECT_DOMAINS)
    for e in dlc.get("google"):
        if "ads" not in e.attrs and "telemetry" not in e.attrs:
            continue
        if e.typ not in {"domain", "full"} or e.value in scheme_b_exempt or e.value in seen_sb:
            continue
        if domain_in_suffix_set(e.value, google_parent_roots):
            typ, val = dlc.rule_type_and_value(e)
            scheme_b_extra.append((typ, val))
            seen_sb.add(e.value)

    # 2) Private LAN entries
    private_entries = dlc.get("private")
    private_domain_payload: list[str] = []
    private_regex_entries: list[DlcEntry] = []
    for e in private_entries:
        if e.typ == "domain":
            private_domain_payload.append(f"+.{e.value}")
        elif e.typ == "full":
            private_domain_payload.append(e.value)
        elif e.typ == "regexp":
            private_regex_entries.append(e)

    # 3) AI lists (exclude @ads/@telemetry -> handled in L3; keep kimi.ai/moonshot.ai/minimax.io)
    ai_openai = dlc.filter_entries(dlc.get("openai"), ban_attrs=("ads", "telemetry"))
    ai_anthropic = dlc.filter_entries(dlc.get("anthropic"), ban_attrs=("ads", "telemetry"))
    ai_deepmind = dlc.filter_entries(dlc.get("google-deepmind"), ban_attrs=("ads", "telemetry"))
    ai_category = dlc.filter_entries(dlc.get("category-ai-!cn"), ban_attrs=("ads", "telemetry"))

    # 4) Lightweight high-precision Layer 3 ads from category-ads-all + major vendors @ads
    raw_ad_entries: list[DlcEntry] = list(dlc.get("category-ads-all"))
    for vname in _DLC_AD_VENDOR_LISTS:
        raw_ad_entries.extend(dlc.filter_entries(dlc.get(vname), must_attrs=("ads",)))
    dlc_ad_entries: list[DlcEntry] = []
    seen_ad_plain: set[str] = set()
    for e in raw_ad_entries:
        if e.plain in seen_ad_plain:
            continue
        seen_ad_plain.add(e.plain)
        if e.typ in {"domain", "full"} and domain_in_suffix_set(e.value, ad_exempt):
            continue
        if e.typ in {"domain", "full"} and e.value in seen_sb:
            continue
        typ, val = dlc.rule_type_and_value(e)
        if is_ai_protected_reject_candidate(typ, val):
            continue
        dlc_ad_entries.append(e)

    # 5) Microsoft split sets (github -> L4; bing -> L6.1; generic microsoft -> L8 DIRECT, kept out of L7)
    github_entries = dlc.filter_entries(dlc.get("github"), ban_attrs=("ads", "telemetry"))
    github_vals = {e.value for e in github_entries if e.typ in {"domain", "full"}}
    bing_entries = dlc.get("bing")
    bing_cn_entries = dlc.filter_entries(bing_entries, must_attrs=("cn",), ban_attrs=("ads", "telemetry"))
    bing_all_vals = {e.value for e in bing_entries if e.typ in {"domain", "full"}}

    ms_proxy_reserved = (
        set(MICROSOFT_AI_SUFFIXES)
        | set(MS_61_PROXY_8)
        | set(OPENAI_EXACT_DOMAINS)
        | set(OPENAI_SUFFIXES)
    )
    ms_direct_entries: list[DlcEntry] = []
    for e in dlc.filter_entries(dlc.get("microsoft"), ban_attrs=("ads", "telemetry")):
        if e.typ in {"domain", "full"}:
            if e.value in github_vals or e.value in bing_all_vals or e.value in ms_proxy_reserved:
                continue
        ms_direct_entries.append(e)
    ms_direct_roots = {e.value for e in ms_direct_entries if e.typ in {"domain", "full"}}

    # 6) Apple sets
    apple_intel = dlc.get("apple-intelligence")
    apple_tvplus = dlc.get("apple-tvplus")
    apple_us_reserved = (
        set(APPLE_SR_US_ONLY_SUFFIXES)
        | {e.value for e in apple_intel}
        | {e.value for e in apple_tvplus}
    )
    apple_all_clean = dlc.filter_entries(dlc.get("apple"), ban_attrs=("ads", "telemetry"))
    icloud_all_clean = dlc.filter_entries(dlc.get("icloud"), ban_attrs=("ads", "telemetry"))

    apple_direct_entries: list[DlcEntry] = []
    for e in (*apple_all_clean, *icloud_all_clean):
        if e.typ in {"domain", "full"} and e.value in apple_us_reserved:
            continue
        apple_direct_entries.append(e)
    apple_direct_roots = {e.value for e in apple_direct_entries if e.typ in {"domain", "full"}}

    # 7) Diagnostic IP/DNS checkers (non-@cn, non-ads)
    checker_entries = dlc.filter_entries(
        dlc.get("category-ip-geo-detect"),
        ban_attrs=("cn", "ads", "telemetry"),
    )

    # 8) Overseas backbone (geolocation-!cn minus @cn, @ads, @telemetry, microsoft_direct, and apple_direct if A)
    overseas_entries: list[DlcEntry] = []
    gnotcn_domain_roots: set[str] = set()
    ad_reject_roots = (
        set(CORE_AD_SUFFIXES)
        | set(GOOGLE_CN_AD_VARIANTS)
        | set(LAYER3_TELEMETRY_REJECT_DOMAINS)
    )
    for e in dlc.filter_entries(dlc.get("geolocation-!cn"), ban_attrs=("cn", "ads", "telemetry")):
        if e.typ == "keyword" and e.value in LAYER7_REMOVED_KEYWORDS:
            continue
        if e.typ in {"domain", "full"}:
            if domain_in_suffix_set(e.value, ms_direct_roots):
                continue
            if domain_in_suffix_set(e.value, ad_reject_roots):
                continue
            if apple_mode == "a" and (
                domain_in_suffix_set(e.value, apple_direct_roots)
                or is_apple_direct_for_sr_a("DOMAIN" if e.typ == "full" else "DOMAIN-SUFFIX", e.value)
            ):
                continue
            if e.typ == "domain":
                gnotcn_domain_roots.add(e.value)
        overseas_entries.append(e)

    gnotcn_full_vals = {e.value for e in overseas_entries if e.typ == "full"}
    overseas_delta = [
        d
        for d in OVERSEAS_PROXY_DELTA_DOMAINS
        if d.lower() not in gnotcn_full_vals and not domain_in_suffix_set(d, gnotcn_domain_roots)
    ]

    # 9) Domestic backbone (DLC/cn clean + category-ai-cn + auto-subtracted Delta)
    cn_ad_suffix_blocked = (
        pcdn_blocked
        | ad_reject_roots
        | {e.value for e in dlc_ad_entries if e.typ == "domain"}
    )
    cn_ad_exact_blocked = (
        set(LAYER3_EXACT_REJECT_DOMAINS)
        | {e.value for e in dlc_ad_entries if e.typ == "full"}
    )
    cn_clean_entries: list[DlcEntry] = []
    cn_domain_roots: set[str] = set()
    cn_full_vals: set[str] = set()
    cn_regex_entries: list[DlcEntry] = []
    for e in dlc.filter_entries(dlc.get("cn"), ban_attrs=("ads", "telemetry")):
        if e.typ in {"domain", "full"}:
            if (
                domain_in_suffix_set(e.value, DLC_CN_EXCLUDED_DOMAINS)
                or e.value in cn_ad_exact_blocked
                or domain_in_suffix_set(e.value, cn_ad_suffix_blocked)
            ):
                continue
            if e.typ == "domain":
                cn_domain_roots.add(e.value)
            else:
                cn_full_vals.add(e.value)
            cn_clean_entries.append(e)
        elif e.typ == "regexp":
            cn_regex_entries.append(e)

    # Supplement domestic AI (category-ai-cn) and Delta not yet covered by DLC/cn
    ai_cn_entries = dlc.filter_entries(dlc.get("category-ai-cn"), ban_attrs=("ads", "telemetry"))
    extra_cn_domains: list[tuple[str, str]] = []
    seen_extra_cn: set[str] = set()

    def _maybe_add_cn_delta(typ: str, val: str) -> None:
        v = val.lower()
        if (
            domain_in_suffix_set(v, DLC_CN_EXCLUDED_DOMAINS)
            or v in cn_ad_exact_blocked
            or domain_in_suffix_set(v, cn_ad_suffix_blocked)
            or v in seen_extra_cn
        ):
            return
        if v in cn_full_vals or domain_in_suffix_set(v, cn_domain_roots):
            return
        seen_extra_cn.add(v)
        extra_cn_domains.append((typ, v))

    for e in ai_cn_entries:
        if e.typ in {"domain", "full"}:
            _maybe_add_cn_delta("DOMAIN-SUFFIX" if e.typ == "domain" else "DOMAIN", e.value)
    for dom in (
        *CN_DOMESTIC_DEV_EXTRA,
        *CN_DOMESTIC_AI_DELTA_SUFFIXES,
        *CN_DOMESTIC_DELTA_SUFFIXES,
        *BYTEDANCE_CN_DELTA_SUFFIXES,
    ):
        _maybe_add_cn_delta("DOMAIN-SUFFIX", dom)

    cn_inline_payload: list[str] = []
    for e in cn_clean_entries:
        cn_inline_payload.append(f"+.{e.value}" if e.typ == "domain" else e.value)
    for typ, val in extra_cn_domains:
        cn_inline_payload.append(f"+.{val}" if typ == "DOMAIN-SUFFIX" else val)

    return {
        "scheme_b_extra": scheme_b_extra,
        "private_entries": private_entries,
        "private_domain_payload": private_domain_payload,
        "private_regex_entries": private_regex_entries,
        "ai_openai": ai_openai,
        "ai_anthropic": ai_anthropic,
        "ai_deepmind": ai_deepmind,
        "ai_category": ai_category,
        "dlc_ad_entries": dlc_ad_entries,
        "ad_exempt": ad_exempt,
        "github_entries": github_entries,
        "bing_cn_entries": bing_cn_entries,
        "ms_direct_entries": ms_direct_entries,
        "apple_intel": apple_intel,
        "apple_tvplus": apple_tvplus,
        "apple_all_clean": apple_all_clean,
        "icloud_all_clean": icloud_all_clean,
        "apple_direct_entries": apple_direct_entries,
        "checker_entries": checker_entries,
        "overseas_entries": overseas_entries,
        "overseas_delta": overseas_delta,
        "cn_clean_entries": cn_clean_entries,
        "cn_regex_entries": cn_regex_entries,
        "extra_cn_domains": extra_cn_domains,
        "cn_inline_payload": cn_inline_payload,
        "cn_domain_roots": cn_domain_roots,
        "bing_cn_roots": {e.value for e in bing_cn_entries if e.typ in {"domain", "full"}},
    }


def _emit_all_layers(
    emitter: RuleEmitter,
    proxy_target: str,
    platform: str,
    dlc: DlcCatalog,
    bundles: dict[str, object],
    *,
    apple_mode: str,
    strict_auth0: bool = True,
    drop_geoip_cn: bool = False,
    direct_cidrs: tuple[str, ...] = (),
    custom_user_rules: list[str] | None = None,
) -> dict[str, int]:
    """Emit Layers 1 through 9 cleanly from DLC + curated Delta/Guardrails."""
    counts = {"ad": 0, "overseas": 0, "cn_delta": len(bundles["extra_cn_domains"])}

    # --- Layer 1: LAN / Private ---
    emitter.comment("===== 1. 局域网 / 私有地址（最高优先级直连） =====")
    for cidr in direct_cidrs:
        emitter.add("IP-CIDR", cidr, "DIRECT", "L1-DirectCIDR", no_resolve=True)
    for d in LAN_EXACT_DOMAINS:
        emitter.add("DOMAIN", d, "DIRECT", "L1")
    for suf in LAN_SUFFIXES:
        emitter.add("DOMAIN-SUFFIX", suf, "DIRECT", "L1")
    for ip4 in LAN_IPV4_CIDRS:
        emitter.add("IP-CIDR", ip4, "DIRECT", "L1", no_resolve=True)
    for ip6 in LAN_IPV6_CIDRS:
        emitter.add("IP-CIDR6", ip6, "DIRECT", "L1", no_resolve=True)
    if platform == "flclash":
        emitter.add_raw("RULE-SET,private,DIRECT")
        for e in bundles["private_regex_entries"]:
            typ, val = dlc.rule_type_and_value(e, csv_safe_regex=False)
            emitter.add(typ, val, "DIRECT", "L1")
    else:
        for e in bundles["private_entries"]:
            typ, val = dlc.rule_type_and_value(e, csv_safe_regex=True)
            emitter.add(typ, val, "DIRECT", "L1")

    # --- Layer 1.5: QUIC Blocking + QQ/WeChat UDP Whitelist ---
    emitter.blank()
    if platform == "sr":
        emitter.comment("===== 1.5 腾讯广告 UDP 前置拦截 + QQ/微信 UDP 白名单、非腾讯 QUIC (UDP 443) 与 PCDN (:8567) 拦截 =====")
        for suf in SR_TENCENT_UDP_REJECT_SUFFIXES:
            emitter.add_raw(f"AND,((PROTOCOL,UDP),(DOMAIN-SUFFIX,{suf})),REJECT-NO-DROP")
        for suf in SR_TENCENT_UDP_SUFFIXES:
            emitter.add_raw(f"AND,((PROTOCOL,UDP),(DOMAIN-SUFFIX,{suf})),DIRECT")
        emitter.add_raw("AND,((PROTOCOL,UDP),(DEST-PORT,443)),REJECT-NO-DROP")
        emitter.add_raw("AND,((PROTOCOL,UDP),(DEST-PORT,8567)),REJECT-NO-DROP")
    else:
        emitter.comment("===== 1.5 腾讯广告 QUIC 前置拦截 + QQ/微信 UDP 443 白名单（含裸 IP 进程兜底）、其余 QUIC 与 PCDN (:8567) 拦截 =====")
        for suf in SR_TENCENT_UDP_REJECT_SUFFIXES:
            emitter.add_raw(f"AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,{suf})),REJECT")
        for suf in SR_TENCENT_UDP_SUFFIXES:
            emitter.add_raw(f"AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,{suf})),DIRECT")
        proc_clauses = ",".join(f"(PROCESS-NAME,{proc})" for proc in FLCLASH_TENCENT_UDP_PROCESSES)
        emitter.add_raw(
            f"AND,((NETWORK,UDP),(DST-PORT,443),(OR,({proc_clauses})),(GEOIP,CN,no-resolve)),DIRECT"
        )
        emitter.add_raw("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT")
        emitter.add_raw("AND,((NETWORK,UDP),(OR,((SRC-PORT,8567),(DST-PORT,8567)))),REJECT")

    # --- Layer 2: AI Platforms & Group-1 Companions (with Scheme B Google REJECT) ---
    emitter.blank()
    emitter.comment("===== 2. 主流 AI 全平台与必要鉴权/特性开关置顶代理（第 2 层保护，免疫第 3 层误杀） =====")
    emitter.comment("--- 2.1 OpenAI (DLC/openai + ① 必要组件，剔除遥测与问卷域) ---")
    # Pinpoint telemetry exceptions that match Layer 2.1 keywords (e.g. 'openai' in openai.qualtrics.com)
    emitter.add("DOMAIN", "openai.qualtrics.com", "REJECT", "L2.1-TelemetryPin")
    for suf in OPENAI_SUFFIXES:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L2.1")
    for kw in OPENAI_KEYWORDS:
        emitter.add("DOMAIN-KEYWORD", kw, proxy_target, "L2.1")
    for dom in OPENAI_EXACT_DOMAINS:
        emitter.add("DOMAIN", dom, proxy_target, "L2.1")
    for e in bundles["ai_openai"]:
        typ, val = dlc.rule_type_and_value(e, csv_safe_regex=(platform == "sr"))
        emitter.add(typ, val, proxy_target, "L2.1")
    for suf in OPENAI_COMPANION_SUFFIXES:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L2.1")
    if not strict_auth0:
        for suf in OPENAI_BROAD_AUTH0:
            emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L2.1")
    for ip4 in OPENAI_IPV4_CIDRS:
        emitter.add("IP-CIDR", ip4, proxy_target, "L2.1", no_resolve=True)
    for asn in OPENAI_ASNS:
        emitter.add("IP-ASN", asn, proxy_target, "L2.1", no_resolve=True)

    emitter.comment("--- 2.2 Anthropic (DLC/anthropic，剔除遥测域) ---")
    for suf in ANTHROPIC_SUFFIXES:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L2.2")
    for kw in ANTHROPIC_KEYWORDS:
        emitter.add("DOMAIN-KEYWORD", kw, proxy_target, "L2.2")
    for dom in ANTHROPIC_EXACT_DOMAINS:
        emitter.add("DOMAIN", dom, proxy_target, "L2.2")
    for e in bundles["ai_anthropic"]:
        typ, val = dlc.rule_type_and_value(e, csv_safe_regex=(platform == "sr"))
        emitter.add(typ, val, proxy_target, "L2.2")

    emitter.comment("--- 2.3 Google AI 及 Google 母域（方案 B：顶部精确拦截谷歌自家广告，豁免 video-stats） ---")
    for g_rej in SCHEME_B_GOOGLE_REJECT_DOMAINS:
        emitter.add("DOMAIN-SUFFIX", g_rej, "REJECT", "L2.3-SchemeB")
    for typ, val in bundles["scheme_b_extra"]:
        emitter.add(typ, val, "REJECT", "L2.3-SchemeB-DLC")
    for suf in GOOGLE_AI_AND_PARENT_SUFFIXES:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L2.3")
    for kw in GOOGLE_AI_KEYWORDS:
        emitter.add("DOMAIN-KEYWORD", kw, proxy_target, "L2.3")
    for e in bundles["ai_deepmind"]:
        typ, val = dlc.rule_type_and_value(e, csv_safe_regex=(platform == "sr"))
        emitter.add(typ, val, proxy_target, "L2.3")

    emitter.comment("--- 2.4 Meta AI / Copilot / xAI / DLC category-ai-!cn (含 kimi.ai/moonshot.ai/minimax.io) ---")
    for suf in META_COPILOT_SUFFIXES:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L2.4")
    for asn in META_ASNS:
        emitter.add("IP-ASN", asn, proxy_target, "L2.4", no_resolve=True)
    for suf in XAI_SUFFIXES:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L2.4.1")
    for suf in OTHER_AI_SUFFIXES:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L2.4.2")
    for e in bundles["ai_category"]:
        typ, val = dlc.rule_type_and_value(e, csv_safe_regex=(platform == "sr"))
        emitter.add(typ, val, proxy_target, "L2.4-DLC")

    emitter.comment("--- 2.5 AI 特性开关防误杀 & 流媒体短链保护 ---")
    for suf in LAYER25_PROTECTION_SUFFIXES:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L2.5")

    # --- Layer 3: Lightweight High-Precision Adblock + Group 3 Telemetry + PCDN ---
    emitter.blank()
    emitter.comment("===== 3. 轻量高精准广告与客户端遥测拦截（DLC category-ads-all + 大厂 @ads + ③ 遥测 + 核心联盟，已排除 httpdns-cn） =====")
    for dom in LAYER3_TELEMETRY_REJECT_DOMAINS:
        if emitter.add("DOMAIN", dom, "REJECT", "L3-Telemetry"):
            counts["ad"] += 1
    for suf in CORE_AD_SUFFIXES:
        if emitter.add("DOMAIN-SUFFIX", suf, "REJECT", "L3-Core"):
            counts["ad"] += 1
    for dom in LAYER3_EXACT_REJECT_DOMAINS:
        if emitter.add("DOMAIN", dom, "REJECT", "L3-Exact"):
            counts["ad"] += 1
    for e in bundles["dlc_ad_entries"]:
        typ, val = dlc.rule_type_and_value(e, csv_safe_regex=(platform == "sr"))
        if emitter.add(typ, val, "REJECT", "L3-DLC"):
            counts["ad"] += 1

    emitter.comment("--- 3.1 P2P/STUN 刷屏降噪（精准屏蔽 B 站与多云 PCDN/STUN/Tracker，不误伤弹幕与 HTTPDNS） ---")
    for dom in SR_PCDN_NOISE_EXACT:
        if emitter.add("DOMAIN", dom, "REJECT", "L3-PCDN"):
            counts["ad"] += 1
    for suf in SR_PCDN_NOISE_SUFFIXES:
        if emitter.add("DOMAIN-SUFFIX", suf, "REJECT", "L3-PCDN"):
            counts["ad"] += 1
    for kw in SR_PCDN_NOISE_KEYWORDS:
        if emitter.add("DOMAIN-KEYWORD", kw, "REJECT", "L3-PCDN"):
            counts["ad"] += 1

    # --- Layer 4: Overseas Specials & Exceptions Above L6/L8 ---
    emitter.blank()
    emitter.comment("===== 4. 海外专题例外代理（GitHub 防微软截胡 + Apple 分支 + 缺失日志域补全） =====")
    for dom in PLATFORM_44_LOG_VERIFIED_DELTAS:
        emitter.add("DOMAIN-SUFFIX", dom, proxy_target, "L4-Delta")
    for e in bundles["github_entries"]:
        typ, val = dlc.rule_type_and_value(e, csv_safe_regex=(platform == "sr"))
        emitter.add(typ, val, proxy_target, "L4-GitHub")
    for e in bundles["apple_intel"]:
        typ, val = dlc.rule_type_and_value(e, csv_safe_regex=(platform == "sr"))
        emitter.add(typ, val, proxy_target, "L4-AppleIntel")
    for suf in APPLE_SAFEBROWSING_OHTTP_SUFFIXES:
        emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L4-AppleOHTTP")

    if apple_mode == "a":
        emitter.comment("--- 4.7 美区 Apple 专属代理（Situation A：Apple Intelligence / TV+ / News / Siri） ---")
        for e in bundles["apple_tvplus"]:
            typ, val = dlc.rule_type_and_value(e, csv_safe_regex=(platform == "sr"))
            emitter.add(typ, val, proxy_target, "L4.7-TVPlus")
        for suf in APPLE_SR_US_ONLY_SUFFIXES:
            emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L4.7-USOnly")
    else:
        emitter.comment("--- 4.7 Apple 全生态代理（Situation B：Win/Android） ---")
        for suf in APPLE_COMMON_SUFFIXES:
            emitter.add("DOMAIN-SUFFIX", suf, proxy_target, "L4.7")
        for e in (*bundles["apple_all_clean"], *bundles["icloud_all_clean"]):
            typ, val = dlc.rule_type_and_value(e, csv_safe_regex=(platform == "sr"))
            emitter.add(typ, val, proxy_target, "L4.7-DLC")

    # --- Layer 5: Diagnostic Checkers ---
    emitter.blank()
    emitter.comment("===== 5. IP / DNS / WebRTC 检测站（1ms.dog + DLC category-ip-geo-detect@-cn，强制走代理） =====")
    for dom in CHECKER_DELTA_DOMAINS:
        emitter.add("DOMAIN-SUFFIX", dom, proxy_target, "L5-Delta")
    for e in bundles["checker_entries"]:
        typ, val = dlc.rule_type_and_value(e, csv_safe_regex=(platform == "sr"))
        emitter.add(typ, val, proxy_target, "L5-DLC")

    # --- Layer 6: Minimal Direct Exceptions & Microsoft Split ---
    emitter.blank()
    if apple_mode == "a":
        emitter.comment("===== 6. Apple 美区 App Store/iCloud 直连（Situation A）+ 微软/Amazon.cn 边界 =====")
        for suf in (*APPLE_COMMON_SUFFIXES, *APPLE_SR_DIRECT_EXTRA_SUFFIXES):
            emitter.add("DOMAIN-SUFFIX", suf, "DIRECT", "L6.0")
        for e in bundles["apple_direct_entries"]:
            typ, val = dlc.rule_type_and_value(e, csv_safe_regex=(platform == "sr"))
            emitter.add(typ, val, "DIRECT", "L6.0-DLC")
        for kw in APPLE_SR_DIRECT_KEYWORDS:
            emitter.add("DOMAIN-KEYWORD", kw, "DIRECT", "L6.0")
        for ip4 in APPLE_CIDRS_V4:
            emitter.add("IP-CIDR", ip4, "DIRECT", "L6.0", no_resolve=True)
        for ip6 in APPLE_CIDRS_V6:
            emitter.add("IP-CIDR6", ip6, "DIRECT", "L6.0", no_resolve=True)
    else:
        emitter.comment("===== 6. 微软特例与 Amazon.cn 边界（已清除 Top500 海外白名单，zoom.us 随 L7 走代理） =====")

    emitter.comment("--- 6.1 微软特定分流 + Windows NCSI + amazon.cn（须排在 L7/L8 之前） ---")
    for dom in AMAZON_CN_DIRECT:
        emitter.add("DOMAIN-SUFFIX", dom, "DIRECT", "L6.1")
    for dom in MS_61_DIRECT:
        emitter.add("DOMAIN-SUFFIX", dom, "DIRECT", "L6.1")
    for e in bundles["bing_cn_entries"]:
        typ, val = dlc.rule_type_and_value(e, csv_safe_regex=(platform == "sr"))
        emitter.add(typ, val, "DIRECT", "L6.1-BingCN")
    for dom in MS_61_PROXY_8:
        emitter.add("DOMAIN-SUFFIX", dom, proxy_target, "L6.1")
    for dom in FLCLASH_NCSI_IPV6_REJECT:
        emitter.add("DOMAIN", dom, "REJECT", "L6.1-NCSI")
    for suf in FLCLASH_NCSI_DIRECT_SUFFIXES:
        emitter.add("DOMAIN-SUFFIX", suf, "DIRECT", "L6.1-NCSI")
    # Pin Microsoft-specific Akamai/Akadns CDN hostnames from DLC/microsoft above L7 akamaized.net/akadns.net
    for e in bundles["ms_direct_entries"]:
        if e.typ in {"domain", "full"} and e.value.endswith(
            (".akamaized.net", ".akadns.net", ".edgekey.net", ".edgesuite.net")
        ):
            typ, val = dlc.rule_type_and_value(e, csv_safe_regex=(platform == "sr"))
            emitter.add(typ, val, "DIRECT", "L6.1-MS-CDN")

    # --- Layer 7: Overseas Backbone (DLC/geolocation-!cn cleaned + Overseas Delta) ---
    emitter.blank()
    emitter.comment("===== 7. 海外网站主干（清洗版 DLC geolocation-!cn + 海外 Delta，已剔除 @cn/广告/微软更新域） =====")
    emitter.add("DOMAIN-SUFFIX", "cloudflare.com", proxy_target, "L7")
    for dom in bundles["overseas_delta"]:
        if emitter.add("DOMAIN-SUFFIX", dom, proxy_target, "L7-Delta"):
            counts["overseas"] += 1
    for e in bundles["overseas_entries"]:
        typ, val = dlc.rule_type_and_value(e, csv_safe_regex=(platform == "sr"))
        if emitter.add(typ, val, proxy_target, "L7-DLC"):
            counts["overseas"] += 1

    if custom_user_rules:
        emitter.blank()
        emitter.comment("--- Preserved custom user rules ---")
        allowed_sr_actions = frozenset({"PROXY", "DIRECT", "REJECT", "REJECT-DROP", "REJECT-NO-DROP", "REJECT-TINYGIF"})
        ms_protected_roots = set(MICROSOFT_COMMON_SUFFIXES) | {
            e.value for e in bundles["ms_direct_entries"] if e.typ == "domain"
        }
        ms_protected_exact = {
            e.value for e in bundles["ms_direct_entries"] if e.typ == "full"
        }
        ad_exempt_set: set[str] = set(bundles["ad_exempt"])
        cn_protected_roots = set(bundles["cn_domain_roots"])
        for cr in custom_user_rules:
            parts = [p.strip() for p in cr.split(",")]
            if len(parts) < 3:
                continue
            typ = parts[0].upper()
            if typ not in {"DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "IP-CIDR6"}:
                continue
            has_nr = parts[-1].lower() == "no-resolve"
            if has_nr and len(parts) < 4:
                continue
            val = parts[1]
            val_low = val.lower()
            act = parts[-2] if has_nr else parts[-1]
            act_up = act.upper()
            if act_up not in allowed_sr_actions:
                emitter.notes.append(
                    f"[UserConf] skipped unsupported/airport policy action '{typ},{val},{act}' "
                    "(only built-in PROXY/DIRECT/REJECT* actions are allowed in --user-conf)"
                )
                continue
            if act_up.startswith("REJECT"):
                if is_ai_protected_reject_candidate(typ, val) or val_low in ad_exempt_set or domain_in_suffix_set(val_low, ad_exempt_set):
                    emitter.notes.append(
                        f"[UserConf] skipped protected/exempt REJECT rule '{typ},{val},{act}'"
                    )
                    continue
            if act_up != "DIRECT" and typ in {"DOMAIN", "DOMAIN-SUFFIX"}:
                if (
                    val_low in ms_protected_exact
                    or domain_in_suffix_set(val_low, ms_protected_roots)
                    or domain_in_suffix_set(val_low, cn_protected_roots)
                ):
                    emitter.notes.append(
                        f"[UserConf] skipped L8 domestic/Microsoft override '{typ},{val},{act}' "
                        "(do not pass raw airport .conf files to --user-conf)"
                    )
                    continue
            emitter.add(typ, val, act_up, "UserConf", no_resolve=(has_nr or typ in {"IP-CIDR", "IP-CIDR6"}))

    # --- Layer 8: Domestic Backbone + Clean Microsoft Direct + CN IP ---
    emitter.blank()
    emitter.comment("===== 8. 国内总集与微软直连（DLC/microsoft + DLC/cn + 自动差集 Delta） =====")
    for e in bundles["ms_direct_entries"]:
        typ, val = dlc.rule_type_and_value(e, csv_safe_regex=(platform == "sr"))
        emitter.add(typ, val, "DIRECT", "L8.0-MS")

    if platform == "flclash":
        emitter.add_raw("RULE-SET,cn-domain,DIRECT")
        for e in bundles["cn_regex_entries"]:
            typ, val = dlc.rule_type_and_value(e, csv_safe_regex=False)
            emitter.add(typ, val, "DIRECT", "L8.1-Regex")
    else:
        for typ, val in bundles["extra_cn_domains"]:
            emitter.add(typ, val, "DIRECT", "L8.1-Delta")
        for e in bundles["cn_clean_entries"]:
            typ, val = dlc.rule_type_and_value(e, csv_safe_regex=True)
            emitter.add(typ, val, "DIRECT", "L8.1-DLC")
        for e in bundles["cn_regex_entries"]:
            typ, val = dlc.rule_type_and_value(e, csv_safe_regex=True)
            emitter.add(typ, val, "DIRECT", "L8.1-Regex")

    emitter.comment("--- 8.2 国内 IP 兜底与防泄露（全带 ,no-resolve） ---")
    if not drop_geoip_cn:
        emitter.add_raw("GEOIP,CN,DIRECT,no-resolve")

    # --- Layer 9: Final Terminator ---
    emitter.blank()
    emitter.comment("===== 9. 终极兜底规则（其余未知海外流量一律走代理） =====")
    emitter.add_raw(f"FINAL,{proxy_target}" if platform == "sr" else f"MATCH,{proxy_target}")
    return counts


def _extract_sr_custom_user_rules(user_conf: pathlib.Path | None) -> list[str]:
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
        if not in_rule or not s or s.startswith(("#", ";", "//")):
            continue
        s = re.sub(r"\s+(?://|#).*$", "", s).strip()
        if not s or s.upper().startswith(("FINAL,", "GEOIP,CN", "AND,((PROTOCOL,UDP)")):
            continue
        out.append(s)
    return out


def build_shadowrocket(
    out_path: pathlib.Path,
    dlc_source: pathlib.Path,
    apple_mode: str = "a",
    strict_auth0: bool = True,
    user_conf: pathlib.Path | None = None,
    direct_cidrs: tuple[str, ...] = (),
    name: str = "Hardened-iOS-Shadowrocket",
    desc: str = "",
) -> int:
    """Build a pure-DLC, zero-airport-dependency Shadowrocket .conf (Full profile, pure LF)."""
    dlc = DlcCatalog.from_source(dlc_source)
    bundles = _prepare_dlc_bundles(dlc, apple_mode=apple_mode)

    emitter = RuleEmitter("sr")
    custom_rules = _extract_sr_custom_user_rules(user_conf)
    if custom_rules:
        print(f"[INFO]  Parsed {len(custom_rules)} rule(s) from --user-conf; merging non-conflicting rules above Layer 8")

    c = _emit_all_layers(
        emitter,
        proxy_target="PROXY",
        platform="sr",
        dlc=dlc,
        bundles=bundles,
        apple_mode=apple_mode,
        strict_auth0=strict_auth0,
        direct_cidrs=direct_cidrs,
        custom_user_rules=custom_rules,
    )

    header_desc = desc or f"DLC主干 + 轻量高精准去广告 + 遥测拦截 + Apple情况{apple_mode.upper()}"
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
        f"[BUILD] Shadowrocket (DLC Full, Apple={apple_mode.upper()}) -> {out_path} "
        f"(ads={c['ad']}, overseas={c['overseas']}, cn_delta={c['cn_delta']}, rules={emitter.rule_count})"
    )
    for note in emitter.notes[:20]:
        print(f"[NOTE]  {note}")
    if len(emitter.notes) > 20:
        print(f"[NOTE]  ... and {len(emitter.notes) - 20} additional dedup/shadow notes")

    report = audit_shadowrocket(out_path, strict=True, profile="full", apple_mode=apple_mode)
    print(format_report(report))
    return 1 if (report.errors or report.warnings) else 0


def _is_action_container(proxies: list[str] | None) -> bool:
    if not proxies:
        return False
    return all(p.upper() in BUILTIN_MIHOMO_ACTIONS for p in proxies)


_PRIMARY_GROUP_POSITIVE_HINTS = (
    "节点选择",
    "手动切换",
    "手动选择",
    "总代理",
    "代理选择",
    "proxy",
    "select",
    "main",
    "global",
)
_PRIMARY_GROUP_NEGATIVE_HINTS = (
    "直连",
    "国内",
    "广告",
    "拦截",
    "屏蔽",
    "净化",
    "漏网",
    "苹果",
    "apple",
    "微软",
    "microsoft",
    "netflix",
    "disney",
    "spotify",
    "youtube",
    "tiktok",
    "bilibili",
    "telegram",
    "openai",
    "chatgpt",
    "claude",
    "ai服务",
    "emby",
    "steam",
    "游戏",
    "game",
    "流媒体",
    "media",
    "direct",
    "reject",
)


def _detect_primary_select_group(group_lines: list[tuple[int, str]]) -> str | None:
    entries = _parse_proxy_group_entries(group_lines)
    select_candidates = [e for e in entries if e["type"] == "select" and not _is_action_container(e["proxies"])]
    if select_candidates:
        def _score(idx_entry: tuple[int, dict]) -> tuple[int, int]:
            idx, e = idx_entry
            name_low = (e["name"] or "").lower()
            score = 0
            if any(h in name_low for h in _PRIMARY_GROUP_POSITIVE_HINTS):
                score += 40
            if any(h in name_low for h in _PRIMARY_GROUP_NEGATIVE_HINTS):
                score -= 50
            pxs = e.get("proxies") or []
            if pxs:
                first_up = pxs[0].upper()
                if first_up in {"DIRECT", "REJECT", "REJECT-DROP"}:
                    score -= 60
                else:
                    score += 10
            if e.get("has_use") or e.get("has_include_all"):
                score += 10
            return (-score, idx)

        ranked = sorted(enumerate(select_candidates), key=_score)
        chosen = ranked[0][1]["name"]
        if len(select_candidates) > 1:
            print(
                f"[INFO]  Auto-selected primary proxy-group '{chosen}' from {len(select_candidates)} select groups "
                "(pass --proxy-group to override)"
            )
        return chosen
    for entry in entries:
        if entry["type"] == "select":
            return entry["name"]
    names = sorted(_extract_proxy_group_names(group_lines))
    return names[0] if names else None


def _dedup_proxy_members(
    decoded_list: list[str],
    raw_list: list[str],
    replacements: dict[str, tuple[str, str]],
) -> tuple[list[str], list[str], bool]:
    new_dec: list[str] = []
    new_raw: list[str] = []
    seen: set[str] = set()
    changed = False
    for dec, raw in zip(decoded_list, raw_list):
        cur_dec, cur_raw = dec, raw
        for _ in range(16):
            nxt = replacements.get(cur_dec)
            if not nxt or nxt[0] == cur_dec:
                break
            cur_dec, cur_raw = nxt
            changed = True
        if cur_dec in seen:
            changed = True
            continue
        seen.add(cur_dec)
        new_dec.append(cur_dec)
        new_raw.append(cur_raw)
    return new_dec, new_raw, changed


def _render_hardened_group_lines(
    entry: dict,
    min_interval: int,
    proxies_changed: bool,
) -> list[str]:
    force_select = bool(entry.get("force_select"))
    is_auto = (entry["type"] in AUTO_TEST_GROUP_TYPES) and not force_select

    def _upgrade_line(text: str) -> str:
        code, comment = _split_inline_comment(text)
        code = re.sub(
            r"""((?:^|\s|[,{])url\s*:\s*['"]?)http://([^\s'"#},]+)""",
            r"\1https://\2",
            code,
        )
        code = re.sub(
            r"((?:^|\s|[,{])interval\s*:\s*)(\d+)",
            lambda m: f"{m.group(1)}{max(int(m.group(2)), min_interval)}",
            code,
        )
        return f"{code}{comment}"

    if entry["is_flow"]:
        line = _upgrade_line(entry["lines"][0])
        if force_select:
            code, comment = _split_inline_comment(line)
            code = re.sub(
                r"""((?:^|\s|[,{])type\s*:\s*)(?:"[^"]*"|'[^']*'|[^,}\s]+)""",
                r"\1select",
                code,
                count=1,
                flags=re.I,
            )
            line = f"{code}{comment}"
        if proxies_changed and entry["proxy_raws"] is not None:
            joined = ", ".join(entry["proxy_raws"])
            line = _replace_flow_bracket_list(line, "proxies", f"[{joined}]")
        if is_auto:
            code, comment = _split_inline_comment(line)
            if re.search(r"(?:^|\s|[,{])lazy\s*:", code):
                code = re.sub(r"((?:^|\s|[,{])lazy\s*:\s*)(?:true|false)", r"\1true", code, flags=re.I)
            else:
                idx = code.rfind("}")
                if idx != -1:
                    before = code[:idx].rstrip()
                    sep = "" if before.endswith("{") else ", "
                    code = f"{before}{sep}lazy: true{code[idx:]}"
            line = f"{code}{comment}"
        return [line]

    raw_lines = list(entry["lines"])
    trailing_blanks: list[str] = []
    while raw_lines and not raw_lines[-1].strip():
        trailing_blanks.insert(0, raw_lines.pop())

    first_clean = _strip_inline_comment(raw_lines[0])
    head_indent = len(first_clean) - len(first_clean.lstrip())
    key_indent = head_indent + 2
    for rl in raw_lines[1:]:
        cl = _strip_inline_comment(rl)
        st = cl.strip()
        if st and not st.startswith("-") and ":" in st:
            key_indent = len(cl) - len(cl.lstrip())
            break

    rendered: list[str] = []
    seen_lazy = False
    lazy_insert_idx = -1
    skipping_proxies_items = False
    skipping_multiline_flow = False
    proxies_indent: int | None = None

    for line_idx, rl in enumerate(raw_lines):
        cl = _strip_inline_comment(rl)
        st = cl.strip()
        ind = len(cl) - len(cl.lstrip()) if st else 0

        if skipping_multiline_flow:
            if "]" in cl:
                skipping_multiline_flow = False
            continue

        if skipping_proxies_items:
            if not st or st.startswith("#"):
                continue
            if proxies_indent is not None and ind >= proxies_indent and st.startswith("-"):
                continue
            skipping_proxies_items = False
            proxies_indent = None

        if proxies_changed and entry["proxy_raws"] is not None:
            m_px = re.match(r"^(\s*(?:-\s+)?)proxies\s*:\s*(.*)$", cl)
            if m_px:
                tail = m_px.group(2).strip()
                item_ind = key_indent + 2
                for nxt in raw_lines[line_idx + 1 :]:
                    ncl = _strip_inline_comment(nxt)
                    nst = ncl.strip()
                    if nst.startswith("-"):
                        item_ind = len(ncl) - len(ncl.lstrip())
                        break
                if tail.startswith("["):
                    joined = ", ".join(entry["proxy_raws"])
                    if "]" in tail:
                        rendered.append(_replace_flow_bracket_list(rl, None, f"[{joined}]"))
                    else:
                        code, comment = _split_inline_comment(rl)
                        bpos = code.find("[")
                        rendered.append(f"{code[:bpos]}[{joined}]{comment}")
                        skipping_multiline_flow = True
                else:
                    rendered.append(rl)
                    for rtok in entry["proxy_raws"]:
                        rendered.append(f"{' ' * item_ind}- {rtok}")
                    skipping_proxies_items = True
                    proxies_indent = ind
                continue

        up = _upgrade_line(rl)
        if force_select and re.match(r"^\s*(?:-\s+)?type\s*:", cl):
            code, comment = _split_inline_comment(up)
            code = re.sub(r"^(\s*(?:-\s+)?type\s*:\s*).*$", r"\1select", code, flags=re.I)
            up = f"{code}{comment}"
        if is_auto and re.match(r"^\s*lazy\s*:", cl):
            code, comment = _split_inline_comment(up)
            code = re.sub(r"^(\s*lazy\s*:\s*).*$", r"\1true", code, flags=re.I)
            up = f"{code}{comment}"
            seen_lazy = True
        elif is_auto and re.match(r"^\s*interval\s*:", cl):
            lazy_insert_idx = len(rendered) + 1
        rendered.append(up)

    if is_auto and not seen_lazy:
        lazy_line = f"{' ' * key_indent}lazy: true"
        if 0 <= lazy_insert_idx <= len(rendered):
            rendered.insert(lazy_insert_idx, lazy_line)
        else:
            rendered.append(lazy_line)

    return rendered + trailing_blanks


def _harden_flclash_proxy_groups(
    group_lines: list[tuple[int, str]],
    min_interval: int = 300,
    protected_groups: set[str] | None = None,
) -> list[str]:
    if not group_lines:
        return []
    entries = _parse_proxy_group_entries(group_lines)
    if not entries:
        return [
            re.sub(
                r"((?:^|\s|[,{])interval\s*:\s*)(\d+)",
                lambda m: f"{m.group(1)}{max(int(m.group(2)), min_interval)}",
                re.sub(
                    r"""((?:^|\s|[,{])url\s*:\s*['"]?)http://([^\s'"#},]+)""",
                    r"\1https://\2",
                    raw,
                ),
            )
            for _, raw in group_lines
        ]

    protected = set(protected_groups or ())

    # Pass 1: Flatten singleton auto-test groups (fallback/url-test/load-balance with 1 member)
    candidate_replacements: dict[str, tuple[str, str]] = {}
    for e in entries:
        if (
            e["type"] in AUTO_TEST_GROUP_TYPES
            and not e["has_use"]
            and not e["has_include_all"]
            and e["name"] not in protected
            and e["proxies"] is not None
            and len(e["proxies"]) == 1
            and e["proxies"][0] != e["name"]
        ):
            candidate_replacements[e["name"]] = (e["proxies"][0], e["proxy_raws"][0])

    # Break any replacement cycle (e.g. G1 -> G2 -> G1) so cyclic groups are never deleted leaving dangling refs
    replacements: dict[str, tuple[str, str]] = {}
    for gname, target in candidate_replacements.items():
        seen_chain = {gname}
        cur_t = target[0]
        cyclic = False
        while cur_t in candidate_replacements:
            if cur_t in seen_chain:
                cyclic = True
                break
            seen_chain.add(cur_t)
            cur_t = candidate_replacements[cur_t][0]
        if not cyclic:
            replacements[gname] = target

    kept = [e for e in entries if e["name"] not in replacements]
    changed_map: dict[str, bool] = {}
    for e in kept:
        if e["proxies"] is not None and e["proxy_raws"] is not None and replacements:
            nd, nr, chg = _dedup_proxy_members(e["proxies"], e["proxy_raws"], replacements)
            e["proxies"], e["proxy_raws"] = nd, nr
            changed_map[e["name"]] = chg
        else:
            changed_map[e["name"]] = False

    # Pass 2: Prune unreachable orphan auto-test groups when root select/relay/protected groups exist
    by_name = {e["name"]: e for e in kept}
    roots = protected | {e["name"] for e in kept if e["type"] in {"select", "relay"}}
    if roots:
        reachable: set[str] = set()
        queue = list(roots)
        while queue:
            cur_name = queue.pop(0)
            if cur_name in reachable:
                continue
            reachable.add(cur_name)
            grp = by_name.get(cur_name)
            if grp and grp["proxies"]:
                for child in grp["proxies"]:
                    if child in by_name and child not in reachable:
                        queue.append(child)
        pruned_orphans = [
            e["name"]
            for e in kept
            if e["type"] in AUTO_TEST_GROUP_TYPES
            and not e["has_use"]
            and not e["has_include_all"]
            and e["name"] not in reachable
            and e["name"] not in protected
        ]
        if pruned_orphans:
            orphan_set = set(pruned_orphans)
            kept = [e for e in kept if e["name"] not in orphan_set]
    else:
        pruned_orphans = []

    # Pass 3: Convert protected/remaining singleton auto-test groups (e.g. 1-node self-hosted VPS) to select
    for e in kept:
        if (
            e["type"] in AUTO_TEST_GROUP_TYPES
            and not e["has_use"]
            and not e["has_include_all"]
            and e["proxies"] is not None
            and len(e["proxies"]) <= 1
        ):
            e["force_select"] = True
            print(
                f"[INFO]  Converted single-member '{e['type']}' group '{e['name']}' to 'select' "
                "(avoids redundant health checks on <=1 node)"
            )

    removed_count = len(replacements) + len(pruned_orphans)
    if removed_count:
        print(
            f"[INFO]  Streamlined {removed_count} redundant/orphan health-check proxy-group(s) "
            f"(inlined_singleton={len(replacements)}, pruned_orphan={len(pruned_orphans)}, lazy=true, interval>={min_interval}s)"
        )

    out: list[str] = [group_lines[0][1]]
    for _, raw in group_lines[1:]:
        st = raw.strip()
        if not st or st.startswith("#"):
            out.append(raw)
        else:
            break
    for e in kept:
        out.extend(_render_hardened_group_lines(e, min_interval, changed_map.get(e["name"], False)))
    return out


def _harden_flclash_proxy_providers(
    provider_lines: list[tuple[int, str]],
    min_interval: int = 300,
) -> list[str]:
    """Harden optional proxy-providers health-check blocks (HTTPS URL, interval >= 300s, lazy: true)."""
    if not provider_lines:
        return []

    def _upgrade_hc_flow(flow_text: str) -> str:
        t = re.sub(
            r"""((?:^|\s|[,{])url\s*:\s*['"]?)http://([^\s'"#},]+)""",
            r"\1https://\2",
            flow_text,
        )
        t = re.sub(
            r"((?:^|\s|[,{])interval\s*:\s*)(\d+)",
            lambda m: f"{m.group(1)}{max(int(m.group(2)), min_interval)}",
            t,
        )
        if not re.search(r"(?:^|\s|[,{])enable\s*:\s*false\b", t, flags=re.I):
            if re.search(r"(?:^|\s|[,{])lazy\s*:", t):
                t = re.sub(r"((?:^|\s|[,{])lazy\s*:\s*)(?:true|false)", r"\1true", t, flags=re.I)
            else:
                idx = t.rfind("}")
                if idx != -1:
                    before = t[:idx].rstrip()
                    sep = "" if before.endswith("{") else ", "
                    t = f"{before}{sep}lazy: true{t[idx:]}"
        return t

    out: list[str] = [provider_lines[0][1]]
    in_hc = False
    hc_indent = -1
    hc_child_indent = -1
    hc_seen_lazy = False
    hc_disabled = False

    def _flush_hc() -> None:
        nonlocal in_hc, hc_indent, hc_child_indent, hc_seen_lazy, hc_disabled
        if in_hc and not hc_disabled and not hc_seen_lazy:
            ind = hc_child_indent if hc_child_indent > hc_indent else (hc_indent + 2)
            out.append(f"{' ' * ind}lazy: true")
        in_hc = False
        hc_indent = -1
        hc_child_indent = -1
        hc_seen_lazy = False
        hc_disabled = False

    for _, raw in provider_lines[1:]:
        code, comment = _split_inline_comment(raw)
        s = code.strip()
        if not s:
            out.append(raw)
            continue
        indent = len(code) - len(code.lstrip())
        if in_hc and indent <= hc_indent:
            _flush_hc()

        if not in_hc:
            m_hc_inline = re.search(r"\bhealth-check\s*:\s*(\{.*\})", code)
            if m_hc_inline:
                upgraded = _upgrade_hc_flow(m_hc_inline.group(1))
                code = code[: m_hc_inline.start(1)] + upgraded + code[m_hc_inline.end(1) :]
                out.append(f"{code}{comment}")
                continue
            if re.match(r"^health-check\s*:\s*$", s):
                in_hc = True
                hc_indent = indent
                hc_child_indent = -1
                hc_seen_lazy = False
                hc_disabled = False
                out.append(raw)
                continue
            out.append(raw)
            continue

        # Inside block-style health-check:
        if hc_child_indent == -1:
            hc_child_indent = indent
        if re.match(r"^enable\s*:\s*false\b", s, flags=re.I):
            hc_disabled = True
        elif re.match(r"^url\s*:", s, flags=re.I):
            code = re.sub(
                r"""(url\s*:\s*['"]?)http://([^\s'"#},]+)""",
                r"\1https://\2",
                code,
                flags=re.I,
            )
        elif re.match(r"^interval\s*:", s, flags=re.I):
            code = re.sub(
                r"(interval\s*:\s*)(\d+)",
                lambda m: f"{m.group(1)}{max(int(m.group(2)), min_interval)}",
                code,
                flags=re.I,
            )
        elif re.match(r"^lazy\s*:", s, flags=re.I):
            hc_seen_lazy = True
            if not hc_disabled:
                code = re.sub(r"^(\s*lazy\s*:\s*).*$", r"\1true", code, flags=re.I)
        out.append(f"{code}{comment}")

    _flush_hc()
    return out


def _harden_flclash_proxies(proxy_lines: list[tuple[int, str]]) -> list[str]:
    """Ensure VLESS nodes explicitly enable packet-encoding: xudp while preserving comments and order."""
    if not proxy_lines:
        return []
    entries = _extract_proxy_entries(proxy_lines)
    if not entries:
        return [raw for _, raw in proxy_lines]

    out: list[str] = [proxy_lines[0][1]]
    for _, raw in proxy_lines[1:]:
        st = raw.strip()
        if not st or st.startswith("#"):
            out.append(raw)
        else:
            break

    updated = 0
    for e in entries:
        lines = list(e["lines"])
        if e["type"] == "vless" and e["packet_encoding"] != "xudp":
            if e["is_flow"]:
                code, comment = _split_inline_comment(lines[0])
                if e["packet_encoding"]:
                    code = re.sub(
                        r"""(\bpacket-encoding\s*:\s*)(?:"[^"]*"|'[^']*'|[^,}\s]+)""",
                        r"\1xudp",
                        code,
                        count=1,
                        flags=re.I,
                    )
                    lines[0] = f"{code}{comment}"
                    updated += 1
                else:
                    idx = code.rfind("}")
                    if idx != -1:
                        before = code[:idx].rstrip()
                        sep = "" if before.endswith("{") else ", "
                        lines[0] = f"{before}{sep}packet-encoding: xudp{code[idx:]}{comment}"
                        updated += 1
            elif e["packet_encoding_line_idx"] is not None:
                pidx = e["packet_encoding_line_idx"]
                code, comment = _split_inline_comment(lines[pidx])
                code = re.sub(
                    r"^(\s*(?:-\s+)?packet-encoding\s*:\s*).*$",
                    r"\1xudp",
                    code,
                    count=1,
                    flags=re.I,
                )
                lines[pidx] = f"{code}{comment}"
                updated += 1
            elif e["type_line_idx"] is not None:
                xudp_line = f"{' ' * e['key_indent']}packet-encoding: xudp"
                lines.insert(e["type_line_idx"] + 1, xudp_line)
                updated += 1
        out.extend(lines)

    if updated:
        print(f"[INFO]  Normalized 'packet-encoding: xudp' on {updated} VLESS proxy node(s)")
    return out


def _build_hardened_yaml_dns_and_sniffer(
    proxy_group: str,
    bundles: dict[str, object],
    apple_mode: str = "b",
) -> tuple[list[str], list[str]]:
    proxy_ns = list(FLCLASH_PROXY_SERVER_NAMESERVER)

    dns_lines = [
        "dns:",
        "    enable: true",
        "    ipv6: false",
        "    enhanced-mode: fake-ip",
        "    fake-ip-range: 198.18.0.1/16",
        "    fake-ip-filter:",
    ]
    for item in FLCLASH_FAKE_IP_FILTER_BASE:
        dns_lines.append(f"        - {item}")

    dns_lines.append("    default-nameserver:")
    for ns in FLCLASH_DEFAULT_NAMESERVER:
        dns_lines.append(f"        - {ns}")

    overseas_doh = tuple(f'"{base}#{proxy_group}"' for base in FLCLASH_OVERSEAS_DOH_BASES)
    dns_lines.append("    nameserver:")
    for srv in overseas_doh:
        dns_lines.append(f"        - {srv}")

    policy_entries: list[tuple[str, tuple[str, ...]]] = []
    seen_policy_keys: set[str] = set()

    def _add_ns_policy(key: str, servers: tuple[str, ...]) -> None:
        if key not in seen_policy_keys:
            seen_policy_keys.add(key)
            policy_entries.append((key, servers))

    for dom in FLCLASH_DNS_AD_REJECT_EXACT:
        _add_ns_policy(dom, ("rcode://name_error",))
    for dom in FLCLASH_DNS_AD_REJECT_SUFFIXES:
        _add_ns_policy(f"+.{dom}", ("rcode://name_error",))
    for dom in MS_61_DIRECT:
        _add_ns_policy(f"+.{dom}", FLCLASH_DOMESTIC_DOH)
    for dom in sorted(bundles["bing_cn_roots"]):
        _add_ns_policy(f"+.{dom}", FLCLASH_DOMESTIC_DOH)
    for dom in (*MICROSOFT_AI_SUFFIXES, *MS_61_PROXY_8):
        _add_ns_policy(f"+.{dom}", overseas_doh)
    if apple_mode == "b":
        for dom in (*APPLE_COMMON_SUFFIXES, *APPLE_SAFEBROWSING_OHTTP_SUFFIXES):
            _add_ns_policy(f"+.{dom}", overseas_doh)
    else:
        for dom in APPLE_SR_US_ONLY_SUFFIXES:
            _add_ns_policy(f"+.{dom}", overseas_doh)
        for dom in APPLE_COMMON_SUFFIXES:
            _add_ns_policy(f"+.{dom}", FLCLASH_DOMESTIC_DOH)
    for dom in MICROSOFT_COMMON_SUFFIXES:
        _add_ns_policy(f"+.{dom}", FLCLASH_DOMESTIC_DOH)
    for arpa in FLCLASH_DNS_ARPA_SUFFIXES:
        _add_ns_policy(f"+.{arpa}", ("rcode://name_error",))
    for rs in ("cn-domain", "private"):
        _add_ns_policy(f"rule-set:{rs}", FLCLASH_DOMESTIC_DOH)

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
        "    force-dns-mapping: true",
        "    parse-pure-ip: true",
        "    sniff:",
        "        HTTP:",
        '            ports: ["80", "8080"]',
        "        QUIC:",
        '            ports: ["443", "8443"]',
        "        TLS:",
        '            ports: ["443", "8443"]',
        "    skip-domain:",
    ]
    for sk in FLCLASH_SNIFFER_SKIP:
        sniffer_lines.append(f"        - {sk}")

    return dns_lines, sniffer_lines


def _build_inline_rule_providers_yaml(bundles: dict[str, object]) -> list[str]:
    """Emit local inline `behavior: domain` providers so FlClash needs zero airport/remote URLs."""
    lines = ["rule-providers:"]
    for pname, payload in (
        ("private", bundles["private_domain_payload"]),
        ("cn-domain", bundles["cn_inline_payload"]),
    ):
        lines.extend(
            [
                f"    {pname}:",
                "        type: inline",
                "        behavior: domain",
                "        payload:",
            ]
        )
        for dom in payload:
            lines.append(f"            - '{dom}'")
    return lines


def build_flclash(
    out_path: pathlib.Path,
    base_yaml: pathlib.Path,
    dlc_source: pathlib.Path,
    proxy_group: str | None = None,
    apple_mode: str = "b",
    strict_auth0: bool = True,
    drop_geoip_cn: bool = False,
    direct_cidrs: tuple[str, ...] = (),
) -> int:
    """Build a pure-DLC single-file FlClash/Mihomo .yaml keeping ONLY proxies, optional proxy-providers, and proxy-groups from --base."""
    raw_lines = base_yaml.read_text(encoding="utf-8", errors="replace").splitlines()
    blocks = _extract_yaml_top_blocks(raw_lines)
    defined_groups = _extract_proxy_group_names(blocks.get("proxy-groups", []))
    if not defined_groups:
        raise ValueError("Base YAML must declare at least one group in 'proxy-groups:'")
    target_group = proxy_group or _detect_primary_select_group(blocks.get("proxy-groups", []))
    if not target_group:
        raise ValueError("Could not auto-detect primary select proxy-group; pass --proxy-group explicitly")
    if target_group not in defined_groups:
        raise ValueError(f"Proxy group '{target_group}' not found in base YAML proxy-groups: {sorted(defined_groups)}")

    dlc = DlcCatalog.from_source(dlc_source)
    bundles = _prepare_dlc_bundles(dlc, apple_mode=apple_mode)

    top_scalars = [
        "mixed-port: 7890",
        "mode: rule",
        "log-level: info",
        "ipv6: false",
        "unified-delay: true",
        "tcp-concurrent: true",
        "keep-alive-interval: 15",
        "keep-alive-idle: 600",
    ]
    profile_lines = [
        "profile:",
        "    store-selected: true",
        "    store-fake-ip: true",
    ]
    dns_lines, sniffer_lines = _build_hardened_yaml_dns_and_sniffer(
        proxy_group=target_group,
        bundles=bundles,
        apple_mode=apple_mode,
    )
    raw_proxy_entries = _extract_proxy_entries(blocks.get("proxies", []))
    raw_provider_entries = _parse_proxy_provider_entries(blocks.get("proxy-providers", []))
    referenced_relay_groups = {
        e["dialer_proxy"] for e in raw_proxy_entries if e.get("dialer_proxy")
    } | {
        info["proxy"] for info in raw_provider_entries.values() if info.get("proxy")
    }
    proxy_lines = _harden_flclash_proxies(blocks.get("proxies", []))
    proxy_provider_lines = _harden_flclash_proxy_providers(blocks.get("proxy-providers", []))
    group_lines = _harden_flclash_proxy_groups(
        blocks.get("proxy-groups", []),
        protected_groups={target_group, *referenced_relay_groups},
    )
    prov_lines = _build_inline_rule_providers_yaml(bundles)

    emitter = RuleEmitter("flclash")
    c = _emit_all_layers(
        emitter,
        proxy_target=target_group,
        platform="flclash",
        dlc=dlc,
        bundles=bundles,
        apple_mode=apple_mode,
        strict_auth0=strict_auth0,
        drop_geoip_cn=drop_geoip_cn,
        direct_cidrs=direct_cidrs,
    )

    head_lines: list[str] = [*top_scalars, "", *profile_lines, ""]
    head_lines.extend(dns_lines)
    head_lines.append("")
    head_lines.extend(sniffer_lines)
    head_lines.append("")

    if proxy_lines:
        head_lines.extend(proxy_lines)
        if proxy_lines[-1].strip():
            head_lines.append("")

    if proxy_provider_lines:
        head_lines.extend(proxy_provider_lines)
        if proxy_provider_lines[-1].strip():
            head_lines.append("")

    if group_lines:
        head_lines.extend(group_lines)
        if group_lines[-1].strip():
            head_lines.append("")

    head_lines.extend(prov_lines)
    head_lines.append("")
    head_lines.append("rules:")

    content = "\n".join(head_lines + emitter.lines) + "\n"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(content.encode("utf-8"))

    print(
        f"[BUILD] FlClash (DLC inline, group={target_group}, Apple={apple_mode.upper()}) -> {out_path} "
        f"(ads={c['ad']}, overseas={c['overseas']}, cn_delta={c['cn_delta']}, "
        f"inline_cn={len(bundles['cn_inline_payload'])}, rules={emitter.rule_count})"
    )
    for note in emitter.notes[:20]:
        print(f"[NOTE]  {note}")
    if len(emitter.notes) > 20:
        print(f"[NOTE]  ... and {len(emitter.notes) - 20} additional dedup/shadow notes")

    report = audit_flclash(out_path, strict=True, apple_mode=apple_mode)
    print(format_report(report))
    return 1 if (report.errors or report.warnings) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Deterministically build pure-DLC Shadowrocket (.conf) or FlClash/Mihomo (.yaml) configs."
    )
    parser.add_argument("--mode", choices=["sr", "flclash"], required=True, help="Target platform config format")
    parser.add_argument(
        "--dlc-source",
        type=pathlib.Path,
        required=True,
        help="Path to dlc.dat_plain.yml or a local domain-list-community/data directory",
    )
    parser.add_argument(
        "--fetch-dlc",
        action="store_true",
        help="Download official dlc.dat_plain.yml (+ SHA-256 verify) to --dlc-source before building",
    )
    parser.add_argument(
        "--user-conf",
        type=pathlib.Path,
        help="Optional personal SR .conf for small built-in PROXY/DIRECT/REJECT overrides (never pass raw airport .conf)",
    )
    parser.add_argument(
        "--base",
        type=pathlib.Path,
        help="Required for --mode flclash: base .yaml supplying proxies, proxy-groups, and optional proxy-providers only (all original dns/rules/rule-providers are ignored)",
    )
    parser.add_argument("--proxy-group", help="Override FlClash main select proxy group name")
    parser.add_argument(
        "--apple",
        choices=["auto", "a", "b"],
        default="auto",
        help="Apple split strategy (auto: 'a' for SR iOS, 'b' for FlClash Win/Android)",
    )
    parser.add_argument(
        "--broad-auth0",
        action="store_true",
        help="Opt-in: allow broad auth0.com in Layer 2.1 (default keeps strict auth0.openai.com via openai.com)",
    )
    parser.add_argument(
        "--drop-geoip-cn",
        action="store_true",
        help="Omit fallback GEOIP,CN in FlClash (low-memory option)",
    )
    parser.add_argument(
        "--direct-cidr",
        action="append",
        default=[],
        help="Optional IPv4/IPv6 IP or CIDR to pin DIRECT at Layer 1 (anti-loopback for self-hosted VPS IP)",
    )
    parser.add_argument("--name", default="Hardened-iOS-Shadowrocket", help="Shadowrocket #!name header")
    parser.add_argument("--desc", default="", help="Shadowrocket #!desc header")
    parser.add_argument("-o", "--out", type=pathlib.Path, required=True, help="Output file path")
    args = parser.parse_args(argv)

    if args.fetch_dlc:
        if args.dlc_source.is_dir():
            print("[ERROR] --fetch-dlc requires --dlc-source to be a file path (e.g. dlc.dat_plain.yml)", file=sys.stderr)
            return 2
        fetch_dlc_plain(args.dlc_source)

    if not args.dlc_source.exists():
        print(f"[ERROR] --dlc-source not found: {args.dlc_source}", file=sys.stderr)
        return 2

    apple = args.apple
    if apple == "auto":
        apple = "a" if args.mode == "sr" else "b"

    strict_auth0 = not args.broad_auth0
    validated_direct_cidrs: list[str] = []
    for raw_cidr in args.direct_cidr:
        c = raw_cidr.strip()
        if not c:
            continue
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            print(
                f"[ERROR] Invalid --direct-cidr value '{c}': must be an IPv4/IPv6 address or CIDR (not a hostname)",
                file=sys.stderr,
            )
            return 2
        validated_direct_cidrs.append(str(net))
    direct_cidrs = tuple(validated_direct_cidrs)

    if args.mode == "sr":
        return build_shadowrocket(
            out_path=args.out,
            dlc_source=args.dlc_source,
            apple_mode=apple,
            strict_auth0=strict_auth0,
            user_conf=args.user_conf,
            direct_cidrs=direct_cidrs,
            name=args.name,
            desc=args.desc,
        )

    if not args.base or not args.base.is_file():
        print("[ERROR] --base <base.yaml> is required for --mode flclash", file=sys.stderr)
        return 2
    return build_flclash(
        out_path=args.out,
        base_yaml=args.base,
        dlc_source=args.dlc_source,
        proxy_group=args.proxy_group,
        apple_mode=apple,
        strict_auth0=strict_auth0,
        drop_geoip_cn=args.drop_geoip_cn,
        direct_cidrs=direct_cidrs,
    )


if __name__ == "__main__":
    raise SystemExit(main())
