#!/usr/bin/env python3
"""Static auditor for hardened Shadowrocket (.conf) and FlClash/Mihomo (.yaml) configs.

Uses only the Python standard library so it runs anywhere without extra packages
(runs optional yaml.safe_load check in FlClash mode when PyYAML is available;
otherwise full YAML syntax is validated via mihomo -t).
Checks BOM/CRLF, empty rules, YAML proxy-groups validity, IP no-resolve flags, IPv6
syntax, Scheme B pinpoint Google REJECT + AI priority over adblocking, first-match
shadowing, Google -cn ad variants, QUIC handling, DNS/Sniffer sanity, and provider behavior.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from dataclasses import dataclass, field

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from rule_catalog import (  # noqa: E402
    APPLE_SR_US_ONLY_SUFFIXES,
    BUILTIN_MIHOMO_ACTIONS,
    CHECKER_DOMAINS_36,
    CORE_AD_SUFFIXES,
    EXPECTED_AMAZON_CN_DIRECT,
    EXPECTED_CN_DOMESTIC_AI_AUDIT,
    EXPECTED_SR_DOMESTIC_NON_CN,
    GOOGLE_CN_AD_VARIANTS,
    LAYER7_REMOVED_KEYWORD_REASONS,
    LAYER7_REMOVED_KEYWORDS,
    PROVIDER_EXPECTED_BEHAVIOR,
    REQUIRED_AI_PROXY_DOMAINS,
    SCHEME_B_GOOGLE_REJECT_DOMAINS,
    domain_matches,
)

IP_RULE_TYPES = {"IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"}
_YAML_UNICODE_RE = re.compile(r"\\U([0-9a-fA-F]{8})|\\u([0-9a-fA-F]{4})")
_GENERIC_RULESET_STEMS = {
    "shadowrocket",
    "surge",
    "clash",
    "mihomo",
    "loon",
    "quantumult",
    "rules",
    "rule",
    "list",
}


def _ruleset_canonical_name(val: str) -> str:
    """Normalize a Clash provider name or Shadowrocket URL into a canonical set name."""
    low = val.strip().lower().split("?", 1)[0].split("#", 1)[0]
    if "/" not in low and not low.startswith(("http://", "https://")):
        return low
    segs = [s for s in low.split("/") if s]
    if not segs:
        return low
    stem = re.sub(r"\.(list|ya?ml|txt|conf|mrs)$", "", segs[-1])
    if stem in _GENERIC_RULESET_STEMS and len(segs) >= 2:
        return re.sub(r"\.(list|ya?ml|txt|conf|mrs)$", "", segs[-2])
    return stem


@dataclass
class AuditReport:
    """Collects categorized findings for a single configuration audit."""

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    infos: list[str] = field(default_factory=list)

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def info(self, msg: str) -> None:
        self.infos.append(msg)

    def gate(self, msg: str, strict: bool) -> None:
        if strict:
            self.error(msg)
        else:
            self.warn(msg)


def _unescape_yaml_double_quoted(text: str) -> str:
    return _YAML_UNICODE_RE.sub(
        lambda m: chr(int(m.group(1) or m.group(2), 16)),
        text,
    )


def _strip_yaml_quotes(text: str) -> str:
    s = text.strip()
    if len(s) >= 2:
        if s[0] == '"' and s[-1] == '"':
            return _unescape_yaml_double_quoted(s[1:-1])
        if s[0] == "'" and s[-1] == "'":
            return s[1:-1].replace("''", "'")
    return s


def _strip_inline_comment(text: str) -> str:
    in_single = False
    in_double = False
    for idx, ch in enumerate(text):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return text[:idx].rstrip()
    return text.rstrip()


def _parse_rule_line(raw: str) -> tuple[str, str, str, bool] | None:
    """Parse a Clash/Shadowrocket rule string into (type, value, action, no_resolve)."""
    s = raw.strip()
    if not s or s.startswith("#"):
        return None
    upper = s.upper()
    if upper.startswith(("AND,", "OR,", "NOT,")):
        idx = s.rfind(",")
        if idx == -1:
            return None
        return s.split(",", 1)[0].upper(), s[:idx], _strip_yaml_quotes(s[idx + 1 :]), False

    parts = [p.strip() for p in s.split(",")]
    if len(parts) == 2 and parts[0].upper() in {"FINAL", "MATCH"}:
        return parts[0].upper(), "", _strip_yaml_quotes(parts[1]), False
    if len(parts) < 3:
        return None

    typ = parts[0].upper()
    no_resolve = False
    if parts[-1].lower() == "no-resolve":
        no_resolve = True
        parts = parts[:-1]
    if len(parts) < 3:
        return None
    action = _strip_yaml_quotes(parts[-1])
    value = ",".join(parts[1:-1])
    return typ, value, action, no_resolve


def _is_proxy_action(action: str) -> bool:
    u = action.upper()
    return u not in {"DIRECT", "REJECT", "REJECT-DROP", "REJECT-NO-DROP", "REJECT-TINYGIF", "PASS"}


def _is_reject_action(action: str) -> bool:
    return action.upper().startswith("REJECT")


def _first_inline_match(
    domain: str,
    parsed_entries: list[tuple[int, int, str, str, str]],
    stop_at_ads_ruleset: bool = False,
) -> tuple[int, int, str, str] | None:
    """Simulate first-match routing across parsed domain rules.

    Returns (pos, line_no, action, rule_desc) or None if no rule matches before terminator.
    """
    dom = domain.lower()
    for pos, ln, typ, val_low, act in parsed_entries:
        if stop_at_ads_ruleset and typ in {"RULE-SET", "DOMAIN-SET"} and _ruleset_canonical_name(val_low) == "ads":
            return (pos, ln, act, f"{typ},{val_low}")
        if typ == "DOMAIN" and dom == val_low:
            return (pos, ln, act, f"DOMAIN,{val_low}")
        if typ == "DOMAIN-SUFFIX" and domain_matches(dom, val_low):
            return (pos, ln, act, f"DOMAIN-SUFFIX,{val_low}")
        if typ == "DOMAIN-KEYWORD" and val_low in dom:
            return (pos, ln, act, f"DOMAIN-KEYWORD,{val_low}")
    return None


def _check_reject_shadowing(
    parsed_entries: list[tuple[int, int, str, str, str]],
    report: AuditReport,
) -> None:
    """Detect inline REJECT rules shadowed by an earlier non-REJECT DOMAIN/DOMAIN-SUFFIX."""
    earlier_exact: dict[str, tuple[int, str, str]] = {}
    earlier_suffix: dict[str, tuple[int, str]] = {}
    for _, ln, typ, val_low, act in parsed_entries:
        if typ not in {"DOMAIN", "DOMAIN-SUFFIX"}:
            continue
        if _is_reject_action(act):
            candidates: list[tuple[int, str, str, str]] = []
            if typ == "DOMAIN" and val_low in earlier_exact:
                e_ln, e_typ, e_act = earlier_exact[val_low]
                candidates.append((e_ln, e_typ, val_low, e_act))
            parts = val_low.strip(".").split(".")
            for i in range(len(parts)):
                parent = ".".join(parts[i:])
                if parent in earlier_suffix:
                    e_ln, e_act = earlier_suffix[parent]
                    candidates.append((e_ln, "DOMAIN-SUFFIX", parent, e_act))
            if candidates:
                e_ln, e_typ, e_val, e_act = min(candidates, key=lambda item: item[0])
                report.error(
                    f"Line {ln}: REJECT rule '{typ},{val_low},{act}' is shadowed by earlier "
                    f"line {e_ln} '{e_typ},{e_val},{e_act}'"
                )
        elif act.upper() != "PASS":
            if typ == "DOMAIN" and val_low not in earlier_exact:
                earlier_exact[val_low] = (ln, typ, act)
            elif typ == "DOMAIN-SUFFIX" and val_low not in earlier_suffix:
                earlier_suffix[val_low] = (ln, act)


def _check_pair_precedence(
    parsed_entries: list[tuple[int, int, str, str, str]],
    child: str,
    child_expect_proxy: bool,
    parent: str,
    report: AuditReport,
    desc: str,
) -> None:
    """Verify specific child rule appears before its broader parent when both exist."""
    child_hit = None
    parent_hit = None
    for pos, ln, typ, val_low, act in parsed_entries:
        if typ not in {"DOMAIN", "DOMAIN-SUFFIX"}:
            continue
        if val_low == child and child_hit is None:
            child_hit = (pos, ln, act)
        if val_low == parent and parent_hit is None:
            parent_hit = (pos, ln, act)
    if child_hit and parent_hit and child_hit[0] > parent_hit[0]:
        report.error(
            f"Precedence inversion ({desc}): '{child}' at line {child_hit[1]} appears AFTER "
            f"broader '{parent}' at line {parent_hit[1]}"
        )
    if child_hit and (_is_proxy_action(child_hit[2]) != child_expect_proxy):
        expected = "proxy" if child_expect_proxy else "DIRECT"
        report.error(
            f"Line {child_hit[1]}: '{child}' routes to '{child_hit[2]}', expected {expected}"
        )


def _check_common_rules(
    indexed_rules: list[tuple[int, str]],
    report: AuditReport,
    mode: str,
    strict: bool = False,
    apple_mode: str = "auto",
    provider_behaviors: dict[str, str] | None = None,
) -> dict[str, int]:
    """Validate duplicates, IP no-resolve, IPv6 type, AI priority, Scheme B, and terminators."""
    seen_exact: dict[str, int] = {}
    seen_key: dict[tuple[str, str], tuple[int, str]] = {}
    dup_count = 0
    bad_ip_count = 0
    non_scheme_b_rejects = 0
    first_reject_idx: int | None = None
    ai_positions: dict[str, tuple[int, str]] = {}
    microsoft_ruleset_idx: int | None = None
    openai_ruleset_idx: int | None = None
    cf_actions: list[tuple[int, str]] = []
    checker_set = {d.lower() for d in CHECKER_DOMAINS_36}
    checkers_found: set[str] = set()
    parsed_entries: list[tuple[int, int, str, str, str]] = []
    apple_actions: list[tuple[int, int, str]] = []

    for pos, (line_no, raw_rule) in enumerate(indexed_rules):
        parsed = _parse_rule_line(raw_rule)
        if not parsed:
            continue
        typ, val, action, no_resolve = parsed
        val_low = val.lower()
        parsed_entries.append((pos, line_no, typ, val_low, action))

        exact_norm = f"{typ},{val_low},{action.lower()}"
        if exact_norm in seen_exact:
            dup_count += 1
        else:
            seen_exact[exact_norm] = line_no

        if typ not in {"AND", "OR", "NOT", "FINAL", "MATCH"}:
            key = (typ, val_low)
            if key in seen_key and seen_key[key][1].lower() != action.lower():
                prev_ln, prev_act = seen_key[key]
                report.gate(
                    f"Conflicting action for {typ},{val}: line {prev_ln} ({prev_act}) vs line {line_no} ({action})",
                    strict,
                )
            elif key not in seen_key:
                seen_key[key] = (line_no, action)

        # Ban overly broad keywords (e.g. DOMAIN-KEYWORD,aws or amazon)
        if typ == "DOMAIN-KEYWORD" and val_low in LAYER7_REMOVED_KEYWORDS and not _is_reject_action(action):
            reason = LAYER7_REMOVED_KEYWORD_REASONS.get(val_low, "causes routing false positives")
            report.error(
                f"Line {line_no}: overly broad rule 'DOMAIN-KEYWORD,{val},{action}' {reason}"
            )

        # IP / GEOIP / cn-ip no-resolve & IPv6 syntax
        rs_name = _ruleset_canonical_name(val_low) if typ in {"RULE-SET", "DOMAIN-SET"} else ""
        if typ in IP_RULE_TYPES:
            if not no_resolve:
                bad_ip_count += 1
                report.error(f"Line {line_no}: {typ},{val} is missing ',no-resolve' (DNS leak/latency risk)")
            if typ == "IP-CIDR" and ":" in val:
                report.error(f"Line {line_no}: IPv6 range '{val}' uses IP-CIDR instead of IP-CIDR6")
        if typ == "RULE-SET" and rs_name in {"cn-ip", "geoip-cn"} and not no_resolve:
            bad_ip_count += 1
            report.error(f"Line {line_no}: RULE-SET,{val} is missing ',no-resolve'")
        if typ == "RULE-SET" and mode == "flclash":
            beh = (provider_behaviors or {}).get(rs_name) or PROVIDER_EXPECTED_BEHAVIOR.get(rs_name, "")
            if beh in {"classical", "ipcidr"} and rs_name not in {"cn-ip", "geoip-cn"} and not no_resolve:
                bad_ip_count += 1
                report.gate(
                    f"Line {line_no}: RULE-SET,{val} (behavior: {beh}) is missing ',no-resolve' "
                    "(triggers unneeded DoH resolution on Fake-IP traffic)",
                    strict,
                )
        if typ == "DOMAIN-SET" and rs_name in {"cn-ip", "geoip-cn"}:
            bad_ip_count += 1
            report.error(f"Line {line_no}: DOMAIN-SET cannot match IP/CIDR ruleset '{rs_name}' (use RULE-SET with ',no-resolve')")

        if mode == "sr" and typ == "PROCESS-NAME":
            report.warn(f"Line {line_no}: iOS Shadowrocket does not support PROCESS-NAME ({raw_rule})")

        if typ in {"RULE-SET", "DOMAIN-SET"} and rs_name == "ads":
            if _is_proxy_action(action):
                report.error(f"Line {line_no}: {typ},{val} points to '{action}' instead of REJECT")
            elif first_reject_idx is None:
                first_reject_idx = pos
        elif _is_reject_action(action) and typ != "AND" and val_low not in SCHEME_B_GOOGLE_REJECT_DOMAINS:
            non_scheme_b_rejects += 1
            if first_reject_idx is None:
                # Track Layer 3 adblock boundary; Scheme B pinpoint rejects sit cleanly at Layer 2.3
                first_reject_idx = pos

        if typ == "DOMAIN-SET" and PROVIDER_EXPECTED_BEHAVIOR.get(rs_name) == "classical":
            report.gate(
                f"Line {line_no}: DOMAIN-SET used for classical ruleset '{rs_name}' "
                "(may silently drop typed/non-domain entries; prefer RULE-SET)",
                strict,
            )

        if typ in {"RULE-SET", "DOMAIN-SET"}:
            if rs_name == "microsoft" and microsoft_ruleset_idx is None:
                microsoft_ruleset_idx = pos
            elif rs_name == "openai" and openai_ruleset_idx is None:
                openai_ruleset_idx = pos

        if typ in {"DOMAIN-SUFFIX", "DOMAIN"}:
            for ai_dom in REQUIRED_AI_PROXY_DOMAINS:
                if val_low == ai_dom and ai_dom not in ai_positions:
                    ai_positions[ai_dom] = (pos, action)
            if val_low == "cloudflare.com":
                cf_actions.append((line_no, action))
            if val_low in checker_set and _is_proxy_action(action):
                checkers_found.add(val_low)
            if val_low == "apple.com":
                apple_actions.append((pos, line_no, action))

    if dup_count > 0:
        report.warn(f"Found {dup_count} duplicate rule(s)")

    # Verify AI priority over Layer 3 Adblock
    for ai_dom in REQUIRED_AI_PROXY_DOMAINS:
        if ai_dom not in ai_positions:
            report.gate(
                f"Recommended hardening baseline anchor '{ai_dom}' missing "
                "(expected diagnostic gap on unhardened raw subscriptions)",
                strict,
            )
            continue
        ai_pos, ai_act = ai_positions[ai_dom]
        if not _is_proxy_action(ai_act):
            report.error(f"AI domain '{ai_dom}' routes to '{ai_act}' instead of proxy")
        elif first_reject_idx is not None and ai_pos > first_reject_idx:
            report.error(
                f"AI domain '{ai_dom}' appears AFTER Layer 3 adblock REJECT rule (risk of false block)"
            )

    # Scheme B audit: verify pinpoint Google ad domains resolve to REJECT (not swallowed by google.com/googleapis.com)
    has_google_parent = any(
        typ == "DOMAIN-SUFFIX" and val_low in {"google.com", "googleapis.com"}
        for _, _, typ, val_low, _ in parsed_entries
    )
    for g_rej in SCHEME_B_GOOGLE_REJECT_DOMAINS:
        hit = _first_inline_match(g_rej, parsed_entries, stop_at_ads_ruleset=True)
        if hit is None:
            if has_google_parent:
                report.gate(
                    f"Scheme B pinpoint rule missing for '{g_rej}' while Google parent domain is in proxy layer",
                    strict,
                )
        else:
            _, hit_ln, hit_act, hit_desc = hit
            if not _is_reject_action(hit_act):
                report.error(
                    f"Scheme B violation: '{g_rej}' first matches line {hit_ln} '{hit_desc},{hit_act}' "
                    f"instead of REJECT (place '{g_rej},REJECT' above '{hit_desc}')"
                )

    # Reject shadowing, Google -cn variants, CORE_AD_SUFFIXES, Amazon .cn, and domestic AI checks
    _check_reject_shadowing(parsed_entries, report)
    use_ads_stop = mode == "flclash"
    for cn_ad in GOOGLE_CN_AD_VARIANTS:
        hit = _first_inline_match(cn_ad, parsed_entries, stop_at_ads_ruleset=use_ads_stop)
        if hit is not None and not _is_reject_action(hit[2]):
            report.gate(
                f"Google ad variant '{cn_ad}' routes to '{hit[2]}' via line {hit[1]} '{hit[3]}' instead of REJECT",
                strict,
            )

    missing_core_ads: list[str] = []
    misrouted_core_ads: list[str] = []
    for ad_suf in CORE_AD_SUFFIXES:
        hit = _first_inline_match(ad_suf, parsed_entries, stop_at_ads_ruleset=use_ads_stop)
        if hit is None:
            missing_core_ads.append(ad_suf)
        elif not _is_reject_action(hit[2]):
            misrouted_core_ads.append(f"{ad_suf}->{hit[2]}@L{hit[1]}({hit[3]})")
    if misrouted_core_ads:
        preview = ", ".join(misrouted_core_ads[:10])
        suffix = f" (+{len(misrouted_core_ads) - 10} more)" if len(misrouted_core_ads) > 10 else ""
        report.gate(f"Layer 3 CORE_AD_SUFFIXES shadowed before REJECT: {preview}{suffix}", strict)
    if missing_core_ads:
        preview = ", ".join(missing_core_ads[:10])
        suffix = f" (+{len(missing_core_ads) - 10} more)" if len(missing_core_ads) > 10 else ""
        report.gate(
            f"Layer 3 CORE_AD_SUFFIXES missing {len(missing_core_ads)} rule(s): {preview}{suffix}",
            strict,
        )

    for cn_dom in EXPECTED_AMAZON_CN_DIRECT:
        hit = _first_inline_match(cn_dom, parsed_entries, stop_at_ads_ruleset=False)
        if hit is None:
            report.gate(
                f"Domestic .cn domain '{cn_dom}' has no explicit/cn DIRECT rule before terminator",
                strict,
            )
        elif _is_proxy_action(hit[2]) or _is_reject_action(hit[2]):
            report.error(
                f"Line {hit[1]}: domestic domain '{cn_dom}' routes to '{hit[2]}' via '{hit[3]}', expected DIRECT"
            )

    for ai_cn in EXPECTED_CN_DOMESTIC_AI_AUDIT:
        hit = _first_inline_match(ai_cn, parsed_entries, stop_at_ads_ruleset=False)
        if hit is None:
            report.gate(
                f"Domestic AI domain '{ai_cn}' is not pinned DIRECT before fallback",
                strict,
            )
        elif _is_proxy_action(hit[2]) or _is_reject_action(hit[2]):
            report.error(
                f"Line {hit[1]}: domestic AI domain '{ai_cn}' routes to '{hit[2]}' via '{hit[3]}', expected DIRECT"
            )

    # Critical precedence invariants
    _check_pair_precedence(parsed_entries, "cn.bing.com", False, "bing.com", report, "Bing CN")
    _check_pair_precedence(
        parsed_entries,
        "github-avatars.oss-cn-hongkong.aliyuncs.com",
        True,
        "aliyuncs.com",
        report,
        "GitHub HK avatar",
    )
    _check_pair_precedence(parsed_entries, "amazon.cn", False, "amazon.com", report, "Amazon CN")

    # Platform-aware Apple precedence check
    effective_apple = apple_mode
    if effective_apple == "auto":
        effective_apple = "a" if mode == "sr" else "b"
    if effective_apple == "a":
        if apple_actions:
            _, a_ln, a_act = apple_actions[0]
            if _is_proxy_action(a_act):
                report.error(
                    f"Line {a_ln}: Apple Situation A expects apple.com -> DIRECT (found '{a_act}')"
                )
        for us_dom in ("tv.apple.com", "apple.news", APPLE_SR_US_ONLY_SUFFIXES[0]):
            _check_pair_precedence(parsed_entries, us_dom, True, "apple.com", report, "Apple Situation A US-only")

    if (
        microsoft_ruleset_idx is not None
        and openai_ruleset_idx is not None
        and microsoft_ruleset_idx < openai_ruleset_idx
    ):
        report.error("RULE-SET,microsoft appears before RULE-SET,openai (Azure endpoints will be hijacked direct)")

    if cf_actions:
        first_cf_ln, first_cf_act = cf_actions[0]
        if not _is_proxy_action(first_cf_act):
            report.error(
                f"Line {first_cf_ln}: cloudflare.com routes to '{first_cf_act}' (breaks WebRTC/Turnstile IP match)"
            )
    else:
        report.gate("cloudflare.com is not explicitly pinned to proxy (relies on fallback)", strict)

    for chk in ("1ms.dog", "ipqs.com"):
        if chk not in checkers_found:
            report.gate(
                f"Recommended Layer 5 diagnostic domain '{chk}' missing "
                "(expected diagnostic gap on unhardened raw subscriptions)",
                strict,
            )
    if len(checkers_found) < 30:
        report.gate(
            f"Layer 5 IP/DNS checker coverage too low ({len(checkers_found)}/{len(CHECKER_DOMAINS_36)} found)",
            strict,
        )

    # Terminator check
    if indexed_rules:
        last_ln, last_rule = indexed_rules[-1]
        parsed_last = _parse_rule_line(last_rule)
        expected_end = "FINAL" if mode == "sr" else "MATCH"
        if not parsed_last or parsed_last[0] != expected_end:
            report.warn(f"Last rule at line {last_ln} is '{last_rule}', expected '{expected_end},...'")

    return {
        "total_rules": len(indexed_rules),
        "duplicates": dup_count,
        "bad_ip": bad_ip_count,
        "checkers": len(checkers_found),
        "non_scheme_b_rejects": non_scheme_b_rejects,
    }


def audit_shadowrocket(
    path: pathlib.Path,
    strict: bool = False,
    profile: str = "generic",
    apple_mode: str = "auto",
) -> AuditReport:
    """Audit a Shadowrocket .conf configuration file."""
    report = AuditReport()
    raw_bytes = path.read_bytes()
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        report.error("File contains UTF-8 BOM (save as UTF-8 without BOM for iOS)")
    if b"\r\n" in raw_bytes:
        report.error("File uses CRLF (\\r\\n) line endings; iOS Shadowrocket configs must use pure LF (\\n)")

    lines = raw_bytes.decode("utf-8", errors="replace").splitlines()
    section = ""
    has_rule_section = False
    general: dict[str, str] = {}
    indexed_rules: list[tuple[int, str]] = []
    has_rewrite = False
    has_mitm = False

    for idx, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith("#") or s.startswith(";"):
            continue
        if s.startswith("[") and s.endswith("]"):
            section = s
            if section == "[Rule]":
                has_rule_section = True
            elif section == "[URL Rewrite]":
                has_rewrite = True
            elif section == "[MITM]":
                has_mitm = True
            continue
        if section == "[General]" and "=" in s:
            k, v = s.split("=", 1)
            general[k.strip().lower()] = v.strip()
        elif section == "[Rule]":
            indexed_rules.append((idx, s))

    if not has_rule_section:
        report.error("[Rule] section is missing")
    elif not indexed_rules:
        report.error("[Rule] section contains 0 rules")

    if general.get("ipv6", "").lower() != "false":
        report.gate("[General] 'ipv6 = false' is recommended to prevent carrier IPv6 leaks", strict)
    if general.get("hijack-dns") != "*:53":
        report.gate("[General] 'hijack-dns = *:53' is missing or customized", strict)

    block_quic = general.get("block-quic", "").lower()
    rule_texts = [r for _, r in indexed_rules]
    has_qq_udp_whitelist = any("PROTOCOL,UDP" in r and "qq.com" in r and r.endswith("DIRECT") for r in rule_texts)
    has_udp443_reject = any("PROTOCOL,UDP" in r and "DEST-PORT,443" in r and "REJECT" in r for r in rule_texts)

    if not block_quic and not has_udp443_reject:
        report.gate("No QUIC (UDP 443) blocking configured (TCP-over-TCP nodes like anytls may stall)", strict)
    elif block_quic == "all":
        report.gate(
            "[General] 'block-quic = all' overrides [Rule] DIRECT and blocks QQ/WeChat custom UDP (:8000/:80); "
            "prefer 'block-quic = all-proxy' + Layer 1.5 UDP whitelist + UDP 443 REJECT-NO-DROP",
            strict,
        )
    elif block_quic == "all-proxy":
        if not has_qq_udp_whitelist:
            report.info("block-quic = all-proxy set without explicit QQ/WeChat UDP whitelist")
        if not has_udp443_reject:
            report.gate("block-quic = all-proxy set, add Layer 1.5 UDP 443 REJECT-NO-DROP for direct HTTP/3", strict)
        report.info("Verify HTTP/3->TCP fallback on device when using block-quic = all-proxy")

    eff_strict = strict or profile in {"lite", "full"}
    stats = _check_common_rules(
        indexed_rules,
        report,
        mode="sr",
        strict=eff_strict,
        apple_mode=apple_mode,
    )

    if stats["non_scheme_b_rejects"] < len(CORE_AD_SUFFIXES):
        report.gate(
            f"Layer 3 adblock REJECT count too low ({stats['non_scheme_b_rejects']} < {len(CORE_AD_SUFFIXES)})",
            eff_strict,
        )
    if profile == "full" and stats["non_scheme_b_rejects"] < 10000:
        report.gate(
            f"Full profile expected >=10,000 Layer 3 REJECT rules, found {stats['non_scheme_b_rejects']}",
            eff_strict,
        )
    if profile == "lite" and len(indexed_rules) > 10000:
        report.warn(f"Lite profile has {len(indexed_rules)} rules (expected compact <10,000 rules)")
    if len(indexed_rules) > 60000:
        report.warn(
            f"Rule count ({len(indexed_rules)}) exceeds 60,000; beware iOS Packet Tunnel Jetsam memory constraints"
        )

    rule_domains = set()
    for _, r in indexed_rules:
        parsed = _parse_rule_line(r)
        if parsed and parsed[0] in {"DOMAIN-SUFFIX", "DOMAIN"}:
            rule_domains.add(parsed[1].lower())

    missing_dom = [d for d in EXPECTED_SR_DOMESTIC_NON_CN if d not in rule_domains]
    if missing_dom:
        report.gate(
            "Layer 8.1 non-.cn domestic baseline missing recommended domain(s) "
            "(expected diagnostic gap on unhardened raw subscriptions): " + ", ".join(missing_dom),
            eff_strict,
        )

    if not has_rewrite or not has_mitm:
        report.info("[URL Rewrite] / [MITM] section for *.google.cn not present")

    report.info(
        f"SR summary: {len(lines)} lines, {stats['total_rules']} rules, ads={stats['non_scheme_b_rejects']}, "
        f"checkers={stats['checkers']}/{len(CHECKER_DOMAINS_36)}, dups={stats['duplicates']}, bad_ip={stats['bad_ip']}"
    )
    return report


def _extract_yaml_top_blocks(lines: list[str]) -> dict[str, list[tuple[int, str]]]:
    """Group top-level YAML sections without external dependencies."""
    blocks: dict[str, list[tuple[int, str]]] = {}
    current_key = ""
    for idx, line in enumerate(lines, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            if current_key:
                blocks[current_key].append((idx, line))
            continue
        if not line[0].isspace() and ":" in line:
            key = line.split(":", 1)[0].strip()
            current_key = key
            blocks.setdefault(key, []).append((idx, line))
        elif current_key:
            blocks[current_key].append((idx, line))
    return blocks


def _extract_proxy_group_names(group_lines: list[tuple[int, str]]) -> set[str]:
    """Extract declared proxy-group names from YAML block (supporting quotes and Unicode escapes)."""
    names: set[str] = set()
    for _, raw in group_lines[1:]:
        clean = _strip_inline_comment(raw).strip()
        if not clean or clean.startswith("#"):
            continue
        # Match `- name: Foo` or `name: Foo`
        m = re.match(r"^(?:-\s+)?name\s*:\s*(.+)$", clean)
        if m:
            val = _strip_yaml_quotes(m.group(1).strip())
            if val:
                names.add(val)
            continue
        # Match inline flow map `- { name: "Foo", type: select }`
        fm = re.search(r"(?:^|[{\s,])name\s*:\s*(\"[^\"]+\"|'[^']+'|[^,}]+)", clean)
        if fm and clean.startswith("-") and "{" in clean:
            val = _strip_yaml_quotes(fm.group(1).strip())
            if val:
                names.add(val)
    return names


def audit_flclash(
    path: pathlib.Path,
    strict: bool = False,
    apple_mode: str = "auto",
) -> AuditReport:
    """Audit a FlClash / Mihomo .yaml configuration file."""
    report = AuditReport()
    raw_bytes = path.read_bytes()
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        report.error("File contains UTF-8 BOM")
    text = raw_bytes.decode("utf-8", errors="replace")
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        report.info(
            "PyYAML not installed; checked top-level YAML block structure only "
            "(run verify_runtime.py / mihomo -t for full YAML syntax validation)"
        )
    else:
        try:
            parsed_yaml = yaml.safe_load(text)
            if parsed_yaml is not None and not isinstance(parsed_yaml, dict):
                report.error("YAML root document must be a mapping")
        except yaml.YAMLError as exc:
            report.error(f"YAML syntax error: {exc}")

    lines = text.splitlines()
    blocks = _extract_yaml_top_blocks(lines)

    # Top-level scalars
    top_scalars: dict[str, str] = {}
    for _, raw in [b[0] for b in blocks.values() if b]:
        if not raw[0].isspace() and ":" in raw:
            k, v = raw.split(":", 1)
            val = _strip_inline_comment(v).strip()
            if val:
                top_scalars[k.strip()] = val

    if top_scalars.get("ipv6", "").lower() != "false":
        report.gate("Top-level 'ipv6: false' is recommended to prevent IPv6 leaks", strict)

    # DNS block checks
    dns_lines = blocks.get("dns", [])
    dns_text = "\n".join(l for _, l in dns_lines)
    if not dns_lines or not re.search(r"^\s+enable:\s*true\b", dns_text, re.M):
        report.error("dns.enable is missing or not set to true")
    if not re.search(r"^\s+ipv6:\s*false\b", dns_text, re.M):
        report.gate("dns.ipv6 is not set to false", strict)
    if "enhanced-mode: fake-ip" not in dns_text:
        report.warn("dns.enhanced-mode is not fake-ip")

    # Check DoH nameserver proxy binding
    in_nameserver = False
    for ln, raw in dns_lines:
        stripped = raw.strip()
        if stripped.startswith("nameserver:"):
            in_nameserver = True
            continue
        if in_nameserver:
            if stripped and not stripped.startswith("-") and ":" in stripped:
                in_nameserver = False
            elif stripped.startswith("-") and "https://" in stripped and "#" not in stripped:
                report.warn(f"Line {ln}: dns.nameserver DoH entry '{stripped}' has no '#<PROXY_GROUP>' suffix")

    # Sniffer checks
    sniffer_lines = blocks.get("sniffer", [])
    sniffer_text = "\n".join(l for _, l in sniffer_lines)
    if not sniffer_lines or not re.search(r"^\s+enable:\s*true\b", sniffer_text, re.M):
        report.error("sniffer.enable is missing or not set to true")
    if "parse-pure-ip: true" not in sniffer_text:
        report.warn("sniffer.parse-pure-ip: true is missing")
    for ln, raw in sniffer_lines:
        if "Mijia Cloud" in raw:
            report.error(f"Line {ln}: invalid sniffer.skip-domain 'Mijia Cloud'; use '+.mijia.cloud'")

    # Parse rule-providers -> behavior
    providers: dict[str, str] = {}
    current_prov = ""
    prov_indent = -1
    for _, raw in blocks.get("rule-providers", [])[1:]:
        clean = _strip_inline_comment(raw)
        if not clean.strip():
            continue
        indent = len(clean) - len(clean.lstrip())
        s = clean.strip()
        if s.endswith(":") and (prov_indent == -1 or indent <= prov_indent):
            prov_indent = indent
            current_prov = s[:-1].strip()
        elif current_prov and s.startswith("behavior:"):
            providers[current_prov] = s.split(":", 1)[1].strip().strip("\"'")

    # Parse nameserver-policy entries to verify Microsoft/Copilot split ordering safety
    ns_policy: dict[str, list[str]] = {}
    in_ns_policy = False
    ns_policy_indent = -1
    current_ns_key = ""
    for _, raw in dns_lines:
        clean = _strip_inline_comment(raw)
        stripped = clean.strip()
        if not stripped:
            continue
        indent = len(clean) - len(clean.lstrip())
        if stripped.startswith("nameserver-policy:"):
            in_ns_policy = True
            ns_policy_indent = indent
            current_ns_key = ""
            continue
        if in_ns_policy:
            if indent <= ns_policy_indent:
                in_ns_policy = False
                current_ns_key = ""
                continue
            if stripped.startswith("-"):
                if current_ns_key:
                    ns_policy.setdefault(current_ns_key, []).append(
                        _strip_yaml_quotes(stripped[1:].strip())
                    )
            else:
                m_pol = re.match(r"""^(['"]?)(.+?)\1\s*:\s*(.*)$""", stripped)
                if m_pol:
                    current_ns_key = m_pol.group(2).strip()
                    rhs = m_pol.group(3).strip()
                    vals = ns_policy.setdefault(current_ns_key, [])
                    if rhs:
                        vals.append(_strip_yaml_quotes(rhs))

    ms_vals = ns_policy.get("+.microsoft.com") or ns_policy.get("microsoft.com")
    if ms_vals and all("#" not in v for v in ms_vals):
        copilot_vals = ns_policy.get("+.copilot.microsoft.com") or ns_policy.get("copilot.microsoft.com")
        if not copilot_vals or not any("#" in v for v in copilot_vals):
            report.error(
                "dns.nameserver-policy aligns '+.microsoft.com' to domestic DoH without an overseas '#<PROXY>' "
                "override for '+.copilot.microsoft.com'"
            )

    effective_apple = "b" if apple_mode == "auto" else apple_mode
    if effective_apple == "b" and ns_policy and (
        "rule-set:cn-domain" in ns_policy or "cn-domain" in providers
    ):
        apple_ns_vals = ns_policy.get("+.apple.com") or ns_policy.get("apple.com")
        if not apple_ns_vals or not any("#" in v for v in apple_ns_vals):
            report.gate(
                "dns.nameserver-policy lacks overseas '#<PROXY>' override for '+.apple.com' "
                "while cn-domain is present (--apple b)",
                strict,
            )

    # Verify DNS rule-set references ONLY use behavior: domain
    for ln, raw in dns_lines:
        for m in re.finditer(r"rule-set:([A-Za-z0-9_.-]+)", raw):
            rname = m.group(1)
            beh = providers.get(rname)
            if beh is None:
                report.warn(f"Line {ln}: DNS references unknown rule-set '{rname}'")
            elif beh != "domain":
                report.error(
                    f"Line {ln}: DNS references rule-set '{rname}' with behavior '{beh}'; "
                    "Mihomo requires 'behavior: domain' in fake-ip-filter / nameserver-policy"
                )

    if providers.get("private") and providers["private"] != "domain":
        report.error(f"rule-providers.private has behavior '{providers['private']}', usually must be 'domain'")

    # Extract declared proxy-groups
    defined_groups = _extract_proxy_group_names(blocks.get("proxy-groups", []))
    if not defined_groups:
        report.warn("proxy-groups section is missing or declares 0 groups")

    # Extract rules list
    rules_block = blocks.get("rules", [])
    indexed_rules: list[tuple[int, str]] = []
    for ln, raw in rules_block[1:]:
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("-"):
            item = _strip_yaml_quotes(_strip_inline_comment(s[1:].strip()))
            if item:
                indexed_rules.append((ln, item))

    if not rules_block:
        report.error("rules section is missing")
    elif not indexed_rules:
        report.error("rules section contains 0 rules")

    # Check every rule's target group exists in proxy-groups or built-in actions
    if defined_groups:
        valid_targets = defined_groups | BUILTIN_MIHOMO_ACTIONS
        for ln, item in indexed_rules:
            parsed = _parse_rule_line(item)
            if not parsed:
                continue
            _, _, act, _ = parsed
            if act not in valid_targets:
                report.error(
                    f"Line {ln}: rule target '{act}' not found in proxy-groups or built-in Mihomo actions"
                )

    has_quic_reject = any("NETWORK,UDP" in r and "DST-PORT,443" in r and "REJECT" in r for _, r in indexed_rules)
    if not has_quic_reject:
        if any("PROTOCOL,UDP" in r or "DEST-PORT,443" in r for _, r in indexed_rules):
            report.error("Detected Shadowrocket rule syntax (PROTOCOL/DEST-PORT) in Mihomo YAML; use NETWORK/DST-PORT")
        else:
            report.gate("Layer 1.5 QUIC block 'AND,((NETWORK,UDP),(DST-PORT,443)),REJECT' not found", strict)

    stats = _check_common_rules(
        indexed_rules,
        report,
        mode="flclash",
        strict=strict,
        apple_mode=apple_mode,
        provider_behaviors=providers,
    )
    report.info(
        f"FlClash summary: {len(lines)} lines, {stats['total_rules']} inline rules, "
        f"{len(defined_groups)} proxy-groups, {len(providers)} rule-providers, "
        f"checkers={stats['checkers']}/{len(CHECKER_DOMAINS_36)}, dups={stats['duplicates']}, bad_ip={stats['bad_ip']}"
    )
    return report


def format_report(report: AuditReport) -> str:
    """Render an AuditReport as readable lines."""
    out: list[str] = []
    for line in report.infos:
        out.append(f"[INFO]  {line}")
    for line in report.warnings:
        out.append(f"[WARN]  {line}")
    for line in report.errors:
        out.append(f"[ERROR] {line}")
    if report.errors:
        out.append(f"\nAudit FAILED: {len(report.errors)} error(s), {len(report.warnings)} warning(s).")
    else:
        out.append(f"\nAudit PASSED: 0 errors, {len(report.warnings)} warning(s).")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Static auditor for Shadowrocket (.conf) and FlClash/Mihomo (.yaml) configs."
    )
    parser.add_argument("--mode", choices=["sr", "flclash"], required=True, help="Target config format")
    parser.add_argument(
        "--profile",
        choices=["generic", "lite", "full"],
        default="generic",
        help="SR output profile (enables stricter curated rule checks for lite/full)",
    )
    parser.add_argument(
        "--apple",
        choices=["auto", "a", "b"],
        default="auto",
        help="Expected Apple routing strategy (auto defaults to 'a' for SR iOS, 'b' for FlClash)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Promote missing curated rules, -cn ad leaks, and Layer 0 hardening warnings to errors",
    )
    parser.add_argument("config", type=pathlib.Path, help="Path to the .conf or .yaml config file")
    args = parser.parse_args(argv)

    if not args.config.is_file():
        print(f"[ERROR] File not found: {args.config}", file=sys.stderr)
        return 2

    if args.mode == "sr":
        report = audit_shadowrocket(
            args.config,
            strict=args.strict,
            profile=args.profile,
            apple_mode=args.apple,
        )
    else:
        report = audit_flclash(
            args.config,
            strict=args.strict,
            apple_mode=args.apple,
        )

    print(format_report(report))
    return 1 if report.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
