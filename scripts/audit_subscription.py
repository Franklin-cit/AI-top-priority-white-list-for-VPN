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
import ipaddress
import pathlib
import re
import sys
from dataclasses import dataclass, field

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from rule_catalog import (  # noqa: E402
    APPLE_SAFEBROWSING_OHTTP_SUFFIXES,
    APPLE_SR_US_ONLY_SUFFIXES,
    BUILTIN_MIHOMO_ACTIONS,
    CHECKER_DOMAINS,
    CORE_AD_SUFFIXES,
    EXPECTED_AMAZON_CN_DIRECT,
    EXPECTED_CN_DOMESTIC_AI_AUDIT,
    EXPECTED_CRYPTO_PROXY_AUDIT,
    EXPECTED_RELOCATED_PROXY_AUDIT,
    EXPECTED_SR_DOMESTIC_NON_CN,
    EXPECTED_TELEMETRY_REJECT_AUDIT,
    FLCLASH_DNS_AD_REJECT_EXACT,
    FLCLASH_DNS_AD_REJECT_SUFFIXES,
    FLCLASH_NCSI_DIRECT_SUFFIXES,
    FLCLASH_NCSI_IPV6_REJECT,
    GOOGLE_AI_AND_PARENT_SUFFIXES,
    GOOGLE_CN_AD_VARIANTS,
    LAYER3_AD_EXEMPT_DOMAINS,
    LAYER3_EXACT_REJECT_DOMAINS,
    LAYER7_REMOVED_KEYWORD_REASONS,
    LAYER7_REMOVED_KEYWORDS,
    PROVIDER_EXPECTED_BEHAVIOR,
    REQUIRED_AI_PROXY_DOMAINS,
    SCHEME_B_EXEMPT_DOMAINS,
    SCHEME_B_GOOGLE_REJECT_DOMAINS,
    SR_PCDN_NOISE_EXACT,
    SR_PCDN_NOISE_KEYWORDS,
    SR_PCDN_NOISE_SUFFIXES,
    SR_TENCENT_UDP_REJECT_SUFFIXES,
    domain_in_suffix_set,
    domain_matches,
)

IP_RULE_TYPES = {"IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"}
AUTO_TEST_GROUP_TYPES = {"url-test", "fallback", "load-balance"}
_BAD_PROXY_NS_HOSTS = frozenset(
    {
        "1.1.1.1",
        "1.0.0.1",
        "8.8.8.8",
        "8.8.4.4",
        "9.9.9.9",
        "149.112.112.112",
        "1.12.12.12",
        "120.53.53.53",
        "dns.google",
        "doh.pub",
        "dot.pub",
        "dns.alidns.com",
    }
)
_YAML_UNICODE_RE = re.compile(r"\\U([0-9a-fA-F]{8})|\\u([0-9a-fA-F]{4})")
_FLOW_GROUP_RE = re.compile(r"^-\s*(?:&[A-Za-z0-9_.-]+\s+)?\{(?P<body>.*)\}\s*$")
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


def _split_inline_comment(text: str) -> tuple[str, str]:
    """Split a YAML line into (code_without_trailing_ws, comment_suffix) respecting quotes and escapes."""
    in_single = False
    in_double = False
    escaped = False
    for idx, ch in enumerate(text):
        if escaped:
            escaped = False
            continue
        if in_double and ch == "\\":
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double and (idx == 0 or text[idx - 1].isspace()):
            code = text[:idx].rstrip()
            return code, text[len(code) :]
    return text.rstrip(), ""


def _strip_inline_comment(text: str) -> str:
    return _split_inline_comment(text)[0]


def _iter_flow_kvs(body: str) -> list[tuple[str, str]]:
    """Parse top-level `key: value` pairs inside a YAML flow mapping `{...}` respecting quotes and brackets."""
    pairs: list[tuple[str, str]] = []
    n = len(body)
    i = 0
    while i < n:
        while i < n and body[i] in " \t,":
            i += 1
        if i >= n:
            break
        # Read key (optionally quoted)
        k_start = i
        if body[i] in "'\"":
            q = body[i]
            i += 1
            esc = False
            while i < n:
                ch = body[i]
                i += 1
                if esc:
                    esc = False
                elif q == '"' and ch == "\\":
                    esc = True
                elif ch == q:
                    break
            key = _strip_yaml_quotes(body[k_start:i])
            while i < n and body[i] in " \t":
                i += 1
            if i >= n or body[i] != ":":
                while i < n and body[i] != ",":
                    i += 1
                continue
        else:
            colon = body.find(":", i)
            if colon == -1:
                break
            key = body[i:colon].strip()
            i = colon
        i += 1  # skip ':'
        while i < n and body[i] in " \t":
            i += 1
        v_start = i
        in_single = False
        in_double = False
        esc = False
        bracket_depth = 0
        brace_depth = 0
        while i < n:
            ch = body[i]
            if esc:
                esc = False
                i += 1
                continue
            if in_double and ch == "\\":
                esc = True
                i += 1
                continue
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            elif not in_single and not in_double:
                if ch == "[":
                    bracket_depth += 1
                elif ch == "]" and bracket_depth > 0:
                    bracket_depth -= 1
                elif ch == "{":
                    brace_depth += 1
                elif ch == "}" and brace_depth > 0:
                    brace_depth -= 1
                elif ch == "," and bracket_depth == 0 and brace_depth == 0:
                    break
            i += 1
        val = body[v_start:i].strip()
        if key:
            pairs.append((key, val))
        if i < n and body[i] == ",":
            i += 1
    return pairs


def _find_bracket_span(text: str, start_pos: int) -> tuple[int, int] | None:
    """Find matching `[...]` span starting at or after start_pos, respecting quotes and escapes."""
    open_idx = text.find("[", start_pos)
    if open_idx == -1:
        return None
    in_single = False
    in_double = False
    esc = False
    depth = 0
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        if esc:
            esc = False
            continue
        if in_double and ch == "\\":
            esc = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    return open_idx, idx + 1
    return None


def _replace_flow_bracket_list(text: str, key: str | None, new_list_literal: str) -> str:
    """Replace the `[...]` list literal (for `key:` if given) without re.sub escape bugs or quote truncation."""
    code, comment = _split_inline_comment(text)
    search_from = 0
    if key is not None:
        m = re.search(rf"(?:^|[\s,{{]){re.escape(key)}\s*:\s*", code)
        if not m:
            return text
        search_from = m.end()
    span = _find_bracket_span(code, search_from)
    if span is None:
        return text
    s, e = span
    return f"{code[:s]}{new_list_literal}{code[e:]}{comment}"


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
    inline_provider_matchers: dict[str, tuple[set[str], set[str]]] | None = None,
) -> tuple[int, int, str, str] | None:
    """Simulate first-match routing across parsed domain rules and inline domain rule-providers.

    Returns (pos, line_no, action, rule_desc) or None if no rule matches before terminator.
    """
    dom = domain.lower()
    parts = dom.split(".")
    suffix_candidates = [".".join(parts[i:]) for i in range(len(parts))]
    for pos, ln, typ, val_low, act in parsed_entries:
        if stop_at_ads_ruleset and typ in {"RULE-SET", "DOMAIN-SET"} and _ruleset_canonical_name(val_low) == "ads":
            return (pos, ln, act, f"{typ},{val_low}")
        if typ == "RULE-SET" and inline_provider_matchers and val_low in inline_provider_matchers:
            exact_set, suf_set = inline_provider_matchers[val_low]
            if dom in exact_set or any(cand in suf_set for cand in suffix_candidates):
                return (pos, ln, act, f"RULE-SET,{val_low}")
        if typ == "DOMAIN" and dom == val_low:
            return (pos, ln, act, f"DOMAIN,{val_low}")
        if typ == "DOMAIN-SUFFIX" and domain_matches(dom, val_low):
            return (pos, ln, act, f"DOMAIN-SUFFIX,{val_low}")
        if typ == "DOMAIN-KEYWORD" and val_low in dom:
            return (pos, ln, act, f"DOMAIN-KEYWORD,{val_low}")
        if typ == "DOMAIN-REGEX":
            try:
                if re.search(val_low, dom, re.IGNORECASE):
                    return (pos, ln, act, f"DOMAIN-REGEX,{val_low}")
            except re.error:
                pass
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
    inline_provider_matchers: dict[str, tuple[set[str], set[str]]] | None = None,
) -> None:
    """Verify specific child rule appears before its broader parent when both exist."""
    child_hit = None
    parent_hit = None
    for pos, ln, typ, val_low, act in parsed_entries:
        if typ == "RULE-SET" and inline_provider_matchers and val_low in inline_provider_matchers:
            exact_set, suf_set = inline_provider_matchers[val_low]
            if child_hit is None and (child in exact_set or child in suf_set):
                child_hit = (pos, ln, act)
            if parent_hit is None and (parent in exact_set or parent in suf_set):
                parent_hit = (pos, ln, act)
            continue
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


def _check_tencent_udp_precedence(
    rule_texts: list[str],
    udp_token: str,
    report: AuditReport,
    strict: bool,
    quic_reject_idx: int | None = None,
) -> None:
    """Verify Tencent ad UDP pre-reject sits above QQ/WeChat whitelist, and whitelist sits above UDP 443 reject."""
    qq_udp_idx = next(
        (
            i
            for i, r in enumerate(rule_texts)
            if udp_token in r and "(DOMAIN-SUFFIX,qq.com)" in r and r.upper().endswith(",DIRECT")
        ),
        None,
    )
    if qq_udp_idx is None:
        return
    if quic_reject_idx is not None and qq_udp_idx > quic_reject_idx:
        report.error(
            "Layer 1.5 precedence inversion: qq.com UDP 443 whitelist appears AFTER catch-all UDP 443 REJECT"
        )
    for ad_suf in SR_TENCENT_UDP_REJECT_SUFFIXES:
        ad_idx = next(
            (
                i
                for i, r in enumerate(rule_texts)
                if udp_token in r and f"(DOMAIN-SUFFIX,{ad_suf})" in r and ",REJECT" in r.upper()
            ),
            None,
        )
        if ad_idx is None:
            report.gate(
                f"Layer 1.5 lacks UDP pre-reject for '{ad_suf}' above qq.com UDP whitelist (ad QUIC bypass risk)",
                strict,
            )
        elif ad_idx > qq_udp_idx:
            report.error(
                f"Layer 1.5 precedence inversion: UDP REJECT for '{ad_suf}' appears AFTER qq.com UDP whitelist"
            )
    if udp_token == "NETWORK,UDP":
        proc_udp_idx = next(
            (
                i
                for i, r in enumerate(rule_texts)
                if udp_token in r and "PROCESS-NAME,WEIXIN.EXE" in r.upper() and r.upper().endswith(",DIRECT")
            ),
            None,
        )
        if proc_udp_idx is None:
            report.gate(
                "Layer 1.5 lacks Tencent process bare-IP UDP 443 whitelist above catch-all UDP 443 REJECT",
                strict,
            )
        else:
            proc_rule = rule_texts[proc_udp_idx].lower()
            if quic_reject_idx is not None and proc_udp_idx > quic_reject_idx:
                report.error(
                    "Layer 1.5 precedence inversion: Tencent process UDP 443 whitelist appears AFTER catch-all REJECT"
                )
            if "no-resolve" not in proc_rule:
                report.error(
                    "Layer 1.5 Tencent process UDP 443 CN-IP guard is missing ',no-resolve'"
                )
            for ad_suf in SR_TENCENT_UDP_REJECT_SUFFIXES:
                ad_idx = next(
                    (
                        i
                        for i, r in enumerate(rule_texts)
                        if udp_token in r and f"(DOMAIN-SUFFIX,{ad_suf})" in r and ",REJECT" in r.upper()
                    ),
                    None,
                )
                if ad_idx is not None and ad_idx > proc_udp_idx:
                    report.error(
                        f"Layer 1.5 precedence inversion: UDP REJECT for '{ad_suf}' appears AFTER Tencent process whitelist"
                    )


def _check_common_rules(
    indexed_rules: list[tuple[int, str]],
    report: AuditReport,
    mode: str,
    strict: bool = False,
    apple_mode: str = "auto",
    provider_behaviors: dict[str, str] | None = None,
    inline_provider_matchers: dict[str, tuple[set[str], set[str]]] | None = None,
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
    checker_set = {d.lower() for d in CHECKER_DOMAINS}
    checkers_found: set[str] = set()
    parsed_entries: list[tuple[int, int, str, str, str]] = []
    apple_actions: list[tuple[int, int, str]] = []
    tiktok_ruleset_idx: int | None = None

    for pos, (line_no, raw_rule) in enumerate(indexed_rules):
        parsed = _parse_rule_line(raw_rule)
        if not parsed:
            continue
        typ, val, action, no_resolve = parsed
        val_low = val.lower()
        match_val = val if typ == "DOMAIN-REGEX" else val_low
        parsed_entries.append((pos, line_no, typ, match_val, action))

        exact_norm = f"{typ},{match_val},{action.lower()}"
        if exact_norm in seen_exact:
            dup_count += 1
        else:
            seen_exact[exact_norm] = line_no

        if typ not in {"AND", "OR", "NOT", "FINAL", "MATCH"}:
            key = (typ, match_val)
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
            if typ in {"IP-CIDR", "IP-CIDR6"}:
                try:
                    net = ipaddress.ip_network(val, strict=True)
                    if (typ == "IP-CIDR6" and net.version != 6) or (typ == "IP-CIDR" and net.version != 4):
                        bad_ip_count += 1
                        report.error(f"Line {line_no}: address family mismatch for {typ},{val}")
                except ValueError:
                    try:
                        canonical = str(ipaddress.ip_network(val, strict=False))
                    except ValueError:
                        bad_ip_count += 1
                        report.error(f"Line {line_no}: invalid CIDR '{val}' in {typ}")
                    else:
                        bad_ip_count += 1
                        report.gate(
                            f"Line {line_no}: non-canonical CIDR '{val}' has non-zero host bits (use '{canonical}')",
                            strict,
                        )
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
            report.gate(f"Line {line_no}: iOS Shadowrocket does not support PROCESS-NAME ({raw_rule})", strict)

        if typ in {"RULE-SET", "DOMAIN-SET"} and rs_name == "ads":
            has_provider = (
                mode != "flclash"
                or provider_behaviors is None
                or val in provider_behaviors
                or val_low in provider_behaviors
                or rs_name in provider_behaviors
            )
            if _is_proxy_action(action) and has_provider:
                report.error(f"Line {line_no}: {typ},{val} points to '{action}' instead of REJECT")
            elif not _is_proxy_action(action) and first_reject_idx is None:
                first_reject_idx = pos
        elif _is_reject_action(action) and typ != "AND":
            is_pre_l3_pin = (
                val_low in SCHEME_B_GOOGLE_REJECT_DOMAINS
                or val_low in FLCLASH_NCSI_IPV6_REJECT
                or val_low == "openai.qualtrics.com"
                or domain_in_suffix_set(val_low, GOOGLE_AI_AND_PARENT_SUFFIXES)
            )
            if not is_pre_l3_pin:
                non_scheme_b_rejects += 1
                if first_reject_idx is None:
                    # Track Layer 3 adblock boundary; Scheme B / pinpoint guards sit cleanly inside L1.7/L2
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
            elif rs_name == "tiktok" and tiktok_ruleset_idx is None:
                tiktok_ruleset_idx = pos

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
        report.gate(f"Found {dup_count} duplicate rule(s)", strict)

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
        hit = _first_inline_match(
            g_rej,
            parsed_entries,
            stop_at_ads_ruleset=True,
            inline_provider_matchers=inline_provider_matchers,
        )
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

    for ex_dom in SCHEME_B_EXEMPT_DOMAINS:
        hit = _first_inline_match(
            ex_dom,
            parsed_entries,
            stop_at_ads_ruleset=False,
            inline_provider_matchers=inline_provider_matchers,
        )
        if hit is not None and _is_reject_action(hit[2]):
            report.error(
                f"Line {hit[1]}: exempt analytics domain '{ex_dom}' is REJECTed by '{hit[3]}' (must stay PROXY)"
            )
        elif hit is None or not _is_proxy_action(hit[2]):
            report.gate(
                f"Exempt analytics domain '{ex_dom}' does not resolve to PROXY",
                strict,
            )

    # Reject shadowing, Google -cn variants, CORE_AD_SUFFIXES, Group-3 telemetry, exemptions, Amazon .cn, and AI checks
    _check_reject_shadowing(parsed_entries, report)
    use_ads_stop = mode == "flclash"
    for cn_ad in GOOGLE_CN_AD_VARIANTS:
        hit = _first_inline_match(
            cn_ad,
            parsed_entries,
            stop_at_ads_ruleset=use_ads_stop,
            inline_provider_matchers=inline_provider_matchers,
        )
        if hit is not None and not _is_reject_action(hit[2]):
            report.gate(
                f"Google ad variant '{cn_ad}' routes to '{hit[2]}' via line {hit[1]} '{hit[3]}' instead of REJECT",
                strict,
            )

    missing_core_ads: list[str] = []
    misrouted_core_ads: list[str] = []
    for ad_suf in CORE_AD_SUFFIXES:
        hit = _first_inline_match(
            ad_suf,
            parsed_entries,
            stop_at_ads_ruleset=use_ads_stop,
            inline_provider_matchers=inline_provider_matchers,
        )
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

    for tel_dom in EXPECTED_TELEMETRY_REJECT_AUDIT:
        hit = _first_inline_match(
            tel_dom,
            parsed_entries,
            stop_at_ads_ruleset=use_ads_stop,
            inline_provider_matchers=inline_provider_matchers,
        )
        if hit is None:
            report.gate(
                f"Group-3 telemetry/tracker domain '{tel_dom}' missing Layer 3 REJECT rule",
                strict,
            )
        elif not _is_reject_action(hit[2]):
            report.error(
                f"Line {hit[1]}: Group-3 telemetry domain '{tel_dom}' routes to '{hit[2]}' via '{hit[3]}', expected REJECT"
            )

    for keep_dom in (*LAYER3_AD_EXEMPT_DOMAINS, "httpdns.bilivideo.com", "dns.weixin.qq.com.cn"):
        hit = _first_inline_match(
            keep_dom,
            parsed_entries,
            stop_at_ads_ruleset=use_ads_stop,
            inline_provider_matchers=inline_provider_matchers,
        )
        if hit is not None and _is_reject_action(hit[2]):
            report.error(
                f"Line {hit[1]}: functional API/push/HTTPDNS domain '{keep_dom}' is REJECTed by '{hit[3]}'"
            )

    for px_rel in EXPECTED_RELOCATED_PROXY_AUDIT:
        hit = _first_inline_match(
            px_rel,
            parsed_entries,
            stop_at_ads_ruleset=False,
            inline_provider_matchers=inline_provider_matchers,
        )
        if hit is not None and not _is_proxy_action(hit[2]):
            report.error(
                f"Line {hit[1]}: relocated proxy domain '{px_rel}' routes to '{hit[2]}' via '{hit[3]}', expected PROXY"
            )

    for ms_dom in (
        "windowsupdate.com",
        "update.microsoft.com",
        "microsoft.com",
        "windows.com",
        "office.com",
        "msedge.net",
    ):
        hit = _first_inline_match(
            ms_dom,
            parsed_entries,
            stop_at_ads_ruleset=False,
            inline_provider_matchers=inline_provider_matchers,
        )
        if hit is None:
            report.gate(
                f"Microsoft domestic-boundary domain '{ms_dom}' lacks explicit DIRECT rule before terminator",
                strict,
            )
        elif _is_proxy_action(hit[2]) or _is_reject_action(hit[2]):
            report.error(
                f"Line {hit[1]}: Microsoft direct domain '{ms_dom}' routes to '{hit[2]}' via '{hit[3]}', expected DIRECT"
            )

    for cn_dom in EXPECTED_AMAZON_CN_DIRECT:
        hit = _first_inline_match(
            cn_dom,
            parsed_entries,
            stop_at_ads_ruleset=False,
            inline_provider_matchers=inline_provider_matchers,
        )
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
        hit = _first_inline_match(
            ai_cn,
            parsed_entries,
            stop_at_ads_ruleset=False,
            inline_provider_matchers=inline_provider_matchers,
        )
        if hit is None:
            report.gate(
                f"Domestic AI domain '{ai_cn}' is not pinned DIRECT before fallback",
                strict,
            )
        elif _is_proxy_action(hit[2]) or _is_reject_action(hit[2]):
            report.error(
                f"Line {hit[1]}: domestic AI domain '{ai_cn}' routes to '{hit[2]}' via '{hit[3]}', expected DIRECT"
            )

    for dom_cn_host in EXPECTED_SR_DOMESTIC_NON_CN:
        hit = _first_inline_match(
            dom_cn_host,
            parsed_entries,
            stop_at_ads_ruleset=False,
            inline_provider_matchers=inline_provider_matchers,
        )
        if hit is None:
            report.gate(
                f"Domestic non-.cn baseline '{dom_cn_host}' has no explicit/provider DIRECT rule",
                strict,
            )
        elif _is_proxy_action(hit[2]) or _is_reject_action(hit[2]):
            report.error(
                f"Line {hit[1]}: domestic non-.cn domain '{dom_cn_host}' routes to '{hit[2]}' via '{hit[3]}', expected DIRECT"
            )

    # Critical precedence invariants
    _check_pair_precedence(
        parsed_entries,
        "cn.bing.com",
        False,
        "bing.com",
        report,
        "Bing CN",
        inline_provider_matchers=inline_provider_matchers,
    )
    _check_pair_precedence(
        parsed_entries,
        "github-avatars.oss-cn-hongkong.aliyuncs.com",
        True,
        "aliyuncs.com",
        report,
        "GitHub HK avatar",
        inline_provider_matchers=inline_provider_matchers,
    )

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
            _check_pair_precedence(
                parsed_entries,
                us_dom,
                True,
                "apple.com",
                report,
                "Apple Situation A US-only",
                inline_provider_matchers=inline_provider_matchers,
            )
        _check_pair_precedence(
            parsed_entries,
            "safebrowsing.apple",
            True,
            "apple",
            report,
            "Apple SafeBrowsing vs .apple TLD",
            inline_provider_matchers=inline_provider_matchers,
        )

    for px_dom in (*APPLE_SAFEBROWSING_OHTTP_SUFFIXES, "ibyteimg.com", *EXPECTED_CRYPTO_PROXY_AUDIT):
        hit = _first_inline_match(
            px_dom,
            parsed_entries,
            stop_at_ads_ruleset=False,
            inline_provider_matchers=inline_provider_matchers,
        )
        if hit is None:
            report.gate(
                f"Log-verified proxy domain '{px_dom}' has no explicit PROXY rule before fallback",
                strict,
            )
        elif not _is_proxy_action(hit[2]):
            report.error(
                f"Line {hit[1]}: '{px_dom}' routes to '{hit[2]}' via '{hit[3]}', expected proxy"
            )

    for ncsi_v6 in FLCLASH_NCSI_IPV6_REJECT:
        hit_v6 = _first_inline_match(
            ncsi_v6,
            parsed_entries,
            stop_at_ads_ruleset=False,
            inline_provider_matchers=inline_provider_matchers,
        )
        if hit_v6 is None:
            report.gate(f"IPv6 NCSI probe '{ncsi_v6}' is not explicitly REJECTed (causes empty-A cache errors)", strict)
        elif not _is_reject_action(hit_v6[2]):
            report.error(f"Line {hit_v6[1]}: IPv6 NCSI probe '{ncsi_v6}' routes to '{hit_v6[2]}' instead of REJECT")

    for ncsi_dom in FLCLASH_NCSI_DIRECT_SUFFIXES:
        hit_ncsi = _first_inline_match(
            ncsi_dom,
            parsed_entries,
            stop_at_ads_ruleset=False,
            inline_provider_matchers=inline_provider_matchers,
        )
        if hit_ncsi is None:
            report.gate(
                f"Windows NCSI domain '{ncsi_dom}' lacks explicit DIRECT rule before RULE-SET,microsoft",
                strict,
            )
        elif _is_proxy_action(hit_ncsi[2]) or _is_reject_action(hit_ncsi[2]):
            report.error(
                f"Line {hit_ncsi[1]}: Windows NCSI domain '{ncsi_dom}' routes to '{hit_ncsi[2]}' via '{hit_ncsi[3]}', expected DIRECT"
            )
        elif microsoft_ruleset_idx is not None and hit_ncsi[0] > microsoft_ruleset_idx:
            report.gate(
                f"Windows NCSI domain '{ncsi_dom}' appears AFTER RULE-SET,microsoft (may fall through to MATCH)",
                strict,
            )

    sns_hit = _first_inline_match(
        "aweme.snssdk.com",
        parsed_entries,
        stop_at_ads_ruleset=False,
        inline_provider_matchers=inline_provider_matchers,
    )
    if sns_hit is not None and _is_proxy_action(sns_hit[2]):
        report.error(
            f"Line {sns_hit[1]}: domestic 'aweme.snssdk.com' hijacked to '{sns_hit[2]}' via '{sns_hit[3]}' instead of DIRECT"
        )
    elif mode == "flclash" and tiktok_ruleset_idx is not None:
        if sns_hit is None or sns_hit[0] > tiktok_ruleset_idx:
            report.gate(
                "Domestic 'snssdk.com' lacks DIRECT guard above RULE-SET,tiktok (upstream tiktok.yaml may hijack it)",
                strict,
            )

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

    for chk in ("1ms.dog", "ipqs.com", "ipquery.io"):
        if chk not in checkers_found:
            report.gate(
                f"Recommended Layer 5 diagnostic domain '{chk}' missing "
                "(expected diagnostic gap on unhardened raw subscriptions)",
                strict,
            )
    if len(checkers_found) < 30:
        report.gate(
            f"Layer 5 IP/DNS checker coverage too low ({len(checkers_found)}/{len(CHECKER_DOMAINS)} found)",
            strict,
        )

    # Terminator check
    if indexed_rules:
        last_ln, last_rule = indexed_rules[-1]
        parsed_last = _parse_rule_line(last_rule)
        expected_end = "FINAL" if mode == "sr" else "MATCH"
        if not parsed_last or parsed_last[0] != expected_end:
            report.gate(f"Last rule at line {last_ln} is '{last_rule}', expected '{expected_end},...'", strict)

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
        if not s or s.startswith(("#", ";", "//")):
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
            rule_clean = re.sub(r"\s+(?://|#).*$", "", s).strip()
            if rule_clean:
                indexed_rules.append((idx, rule_clean))

    if not has_rule_section:
        report.error("[Rule] section is missing")
    elif not indexed_rules:
        report.error("[Rule] section contains 0 rules")

    eff_strict = strict or profile in {"lite", "full"}
    if general.get("ipv6", "").lower() != "false":
        report.gate("[General] 'ipv6 = false' is recommended to prevent carrier IPv6 leaks", eff_strict)
    if general.get("prefer-ipv6", "").lower() != "false":
        report.gate("[General] 'prefer-ipv6 = false' is recommended to suppress redundant AAAA node lookups", eff_strict)
    if general.get("hijack-dns") != "*:53":
        report.gate("[General] 'hijack-dns = *:53' is missing or customized", eff_strict)
    fb_dns = general.get("fallback-dns-server", "").lower()
    if "1.1.1.1" in fb_dns or "dns.google" in fb_dns:
        report.gate(
            "[General] 'fallback-dns-server' uses overseas DoH (times out on direct links); prefer literal-IP domestic DoH",
            eff_strict,
        )
    if "1.12.12.12" in fb_dns or "120.53.53.53" in fb_dns:
        report.gate(
            "[General] 'fallback-dns-server' uses unreliable/deprecated DNSPod IP (1.12.12.12 times out on mobile networks); "
            "prefer https://223.6.6.6/dns-query#no-h3",
            eff_strict,
        )
    if "system" in fb_dns:
        report.gate(
            "[General] 'fallback-dns-server' includes plaintext 'system' fallback (UDP:53 leak risk); prefer encrypted pure-IP DoH",
            eff_strict,
        )
    if "https://" in fb_dns and "#no-h3" not in fb_dns:
        report.gate(
            "[General] 'fallback-dns-server' DoH without '#no-h3' may hit HTTP/3 QUIC handshake timeouts",
            eff_strict,
        )
    if general.get("dns-direct-fallback-proxy", "").lower() != "false":
        report.gate(
            "[General] 'dns-direct-fallback-proxy = false' is recommended to avoid flipping failed/AAAA-only DIRECT queries into proxy",
            eff_strict,
        )
    dns_srv = general.get("dns-server", "").lower()
    if "https://" in dns_srv and "#no-h3" not in dns_srv:
        report.gate(
            "[General] 'dns-server' DoH without '#no-h3' may hit HTTP/3 QUIC handshake timeouts on restricted networks",
            eff_strict,
        )
    if "doh.pub" in dns_srv:
        report.gate(
            "[General] 'dns-server' uses hostname 'doh.pub' (frequent remote disconnects & UDP:53 bootstrap); prefer literal-IP AliDoH 223.5.5.5 / 223.6.6.6",
            eff_strict,
        )
    bypass_entries = {c.strip().lower() for c in general.get("bypass-tun", "").split(",") if c.strip()}
    bad_bypass = sorted(bypass_entries & {"127.0.0.0/8", "198.18.0.0/15", "::1/128"})
    if bad_bypass:
        report.gate(
            f"[General] 'bypass-tun' contains invalid/self-conflicting route(s): {', '.join(bad_bypass)}",
            eff_strict,
        )

    block_quic = general.get("block-quic", "").lower()
    rule_texts = [r for _, r in indexed_rules]
    has_qq_udp_whitelist = any(
        "PROTOCOL,UDP" in r and "(DOMAIN-SUFFIX,qq.com)" in r and r.upper().endswith(",DIRECT")
        for r in rule_texts
    )
    has_udp443_reject = any("PROTOCOL,UDP" in r and "DEST-PORT,443" in r and "REJECT" in r for r in rule_texts)

    if not block_quic and not has_udp443_reject:
        report.gate("No QUIC (UDP 443) blocking configured (TCP-over-TCP nodes such as VLESS/AnyTLS may stall)", eff_strict)
    elif block_quic == "all":
        report.gate(
            "[General] 'block-quic = all' overrides [Rule] DIRECT and blocks QQ/WeChat custom UDP (:8000/:80); "
            "prefer 'block-quic = all-proxy' + Layer 1.5 UDP whitelist + UDP 443 REJECT-NO-DROP",
            eff_strict,
        )
    elif block_quic == "all-proxy":
        if not has_qq_udp_whitelist:
            report.info("block-quic = all-proxy set without explicit QQ/WeChat UDP whitelist")
        if not has_udp443_reject:
            report.gate("block-quic = all-proxy set, add Layer 1.5 UDP 443 REJECT-NO-DROP for direct HTTP/3", eff_strict)
        report.info("Verify HTTP/3->TCP fallback on device when using block-quic = all-proxy")

    _check_tencent_udp_precedence(rule_texts, "PROTOCOL,UDP", report, eff_strict)
    if not any("PROTOCOL,UDP" in r and "DEST-PORT,8567" in r and "REJECT" in r for r in rule_texts):
        report.gate("Layer 1.5 lacks PCDN port 8567 UDP REJECT-NO-DROP guard", eff_strict)

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
    if profile == "lite" and len(indexed_rules) > 10000:
        report.gate(f"Lite profile has {len(indexed_rules)} rules (expected compact <10,000 rules)", eff_strict)
    if len(indexed_rules) > 60000:
        report.gate(
            f"Rule count ({len(indexed_rules)}) exceeds 60,000; beware iOS Packet Tunnel Jetsam memory constraints",
            eff_strict,
        )

    rule_domains = set()
    rule_keywords = set()
    for _, r in indexed_rules:
        parsed = _parse_rule_line(r)
        if parsed:
            if parsed[0] in {"DOMAIN-SUFFIX", "DOMAIN"}:
                rule_domains.add(parsed[1].lower())
            elif parsed[0] == "DOMAIN-KEYWORD":
                rule_keywords.add(parsed[1].lower())

    _check_layer3_exact_and_pcdn(rule_domains, rule_keywords, report, eff_strict)

    if not has_rewrite or not has_mitm:
        report.info("[URL Rewrite] / [MITM] section for *.google.cn not present")

    report.info(
        f"SR summary: {len(lines)} lines, {stats['total_rules']} rules, ads={stats['non_scheme_b_rejects']}, "
        f"checkers={stats['checkers']}/{len(CHECKER_DOMAINS)}, dups={stats['duplicates']}, bad_ip={stats['bad_ip']}"
    )
    return report


def _check_layer3_exact_and_pcdn(
    rule_domains: set[str],
    rule_keywords: set[str],
    report: AuditReport,
    strict: bool,
) -> None:
    """Verify Layer 3 exact probe/malformed REJECT rules and Layer 3.1 PCDN/STUN noise guards."""
    missing_exact = [d for d in LAYER3_EXACT_REJECT_DOMAINS if d.lower() not in rule_domains]
    if missing_exact:
        report.gate(
            "Layer 3 exact REJECT baseline missing rule(s): " + ", ".join(missing_exact),
            strict,
        )
    missing_pcdn = [d for d in (*SR_PCDN_NOISE_EXACT, *SR_PCDN_NOISE_SUFFIXES) if d.lower() not in rule_domains]
    missing_pcdn.extend(k for k in SR_PCDN_NOISE_KEYWORDS if k.lower() not in rule_keywords)
    if missing_pcdn:
        report.gate(
            "Layer 3.1 P2P/STUN noise reject missing rule(s): " + ", ".join(missing_pcdn),
            strict,
        )


def _extract_yaml_top_blocks(lines: list[str]) -> dict[str, list[tuple[int, str]]]:
    """Group top-level YAML sections without external dependencies."""
    blocks: dict[str, list[tuple[int, str]]] = {}
    current_key = ""
    for idx, line in enumerate(lines, 1):
        if idx == 1 and line.startswith("\ufeff"):
            line = line.lstrip("\ufeff")
        stripped = line.strip()
        if not stripped or line.lstrip().startswith("#"):
            if current_key:
                blocks[current_key].append((idx, line))
            continue
        if not line[0].isspace() and stripped in {"---", "..."}:
            current_key = ""
            continue
        if not line[0].isspace() and ":" in line:
            key = _strip_yaml_quotes(line.split(":", 1)[0].strip())
            current_key = key
            blocks.setdefault(key, []).append((idx, line))
        elif current_key:
            blocks[current_key].append((idx, line))
    return blocks


def _split_inline_group_raw_items(tail: str) -> list[str]:
    """Split a YAML flow sequence '[a, b, ...]' into raw scalar tokens respecting quotes."""
    inner = tail.strip()
    if inner.startswith("[") and inner.endswith("]"):
        inner = inner[1:-1]
    tokens: list[str] = []
    cur: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    for ch in inner:
        if escaped:
            cur.append(ch)
            escaped = False
            continue
        if in_double and ch == "\\":
            cur.append(ch)
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "," and not in_single and not in_double:
            tok = "".join(cur).strip()
            if tok:
                tokens.append(tok)
            cur = []
            continue
        cur.append(ch)
    tok = "".join(cur).strip()
    if tok:
        tokens.append(tok)
    return tokens


def _split_inline_group_list(tail: str) -> list[str]:
    return [_strip_yaml_quotes(tok) for tok in _split_inline_group_raw_items(tail)]


def _parse_proxy_group_entries(group_lines: list[tuple[int, str]]) -> list[dict]:
    """Parse YAML proxy-groups entries (both block and flow style) with structural metadata."""
    entries: list[dict] = []
    cur: dict | None = None
    group_item_indent: int | None = None
    proxies_indent: int | None = None
    use_indent: int | None = None
    multiline_flow_field: str | None = None
    multiline_flow_buf: list[str] = []

    def _finish_multiline_flow() -> None:
        nonlocal multiline_flow_field, multiline_flow_buf
        if cur is not None and multiline_flow_field is not None:
            joined = " ".join(multiline_flow_buf)
            raw_items = _split_inline_group_raw_items(joined)
            if multiline_flow_field == "proxies":
                cur["proxy_raws"] = raw_items
                cur["proxies"] = [_strip_yaml_quotes(t) for t in raw_items]
            elif multiline_flow_field == "use":
                cur["use_providers"] = [_strip_yaml_quotes(t) for t in raw_items]
        multiline_flow_field = None
        multiline_flow_buf = []

    def _apply_kv(entry: dict, key: str, val: str) -> None:
        k = key.lower()
        if k == "name":
            entry["name"] = _strip_yaml_quotes(val)
        elif k == "type":
            entry["type"] = _strip_yaml_quotes(val).lower()
        elif k == "url":
            entry["url"] = _strip_yaml_quotes(val)
        elif k == "interval":
            m_int = re.match(r"^\d+", _strip_yaml_quotes(val))
            if m_int:
                entry["interval"] = int(m_int.group(0))
        elif k == "lazy":
            vlow = _strip_yaml_quotes(val).lower()
            if vlow in {"true", "false"}:
                entry["lazy"] = vlow == "true"
        elif k in {"include-all", "include-all-proxies", "include-all-providers"}:
            if _strip_yaml_quotes(val).lower() == "true":
                entry["has_include_all"] = True
        elif k == "use":
            entry["has_use"] = True
            if val.startswith("[") and _find_bracket_span(val, 0) is not None:
                entry["use_providers"] = _split_inline_group_list(val)
            elif val and not val.startswith("["):
                entry["use_providers"] = [_strip_yaml_quotes(val)]

    for ln, raw in group_lines[1:]:
        clean = _strip_inline_comment(raw)
        s = clean.strip()
        if not s:
            if cur is not None:
                cur["lines"].append(raw)
            continue
        indent = len(clean) - len(clean.lstrip())

        if multiline_flow_field is not None and cur is not None:
            cur["lines"].append(raw)
            multiline_flow_buf.append(s)
            if _find_bracket_span(" ".join(multiline_flow_buf), 0) is not None:
                _finish_multiline_flow()
            continue

        m_flow = _FLOW_GROUP_RE.match(s)
        if m_flow and (group_item_indent is None or indent <= group_item_indent):
            _finish_multiline_flow()
            if group_item_indent is None:
                group_item_indent = indent
            entry: dict = {
                "name": None,
                "type": None,
                "proxies": None,
                "proxy_raws": None,
                "url": None,
                "interval": None,
                "lazy": None,
                "has_use": False,
                "has_include_all": False,
                "use_providers": [],
                "is_flow": True,
                "line": ln,
                "lines": [raw],
            }
            for key, val in _iter_flow_kvs(m_flow.group("body")):
                if key.lower() == "proxies" and val.startswith("["):
                    raw_items = _split_inline_group_raw_items(val)
                    entry["proxy_raws"] = raw_items
                    entry["proxies"] = [_strip_yaml_quotes(t) for t in raw_items]
                else:
                    _apply_kv(entry, key, val)
            if entry["name"]:
                entries.append(entry)
            cur, proxies_indent, use_indent = None, None, None
            continue

        m_bare_dash = re.match(r"^-(?:\s+&[A-Za-z0-9_.-]+)?\s*$", s)
        m_new = re.match(r"^-\s+(?:&[A-Za-z0-9_.-]+\s+)?([A-Za-z0-9_.-]+)\s*:\s*(.*)$", s)
        if (m_bare_dash or m_new) and (group_item_indent is None or indent <= group_item_indent):
            _finish_multiline_flow()
            if group_item_indent is None:
                group_item_indent = indent
            cur = {
                "name": None,
                "type": None,
                "proxies": None,
                "proxy_raws": None,
                "url": None,
                "interval": None,
                "lazy": None,
                "has_use": False,
                "has_include_all": False,
                "use_providers": [],
                "is_flow": False,
                "line": ln,
                "lines": [raw],
            }
            entries.append(cur)
            proxies_indent = None
            use_indent = None
            if m_new:
                k0, v0 = m_new.group(1), m_new.group(2).strip()
                if k0.lower() == "proxies":
                    if v0.startswith("["):
                        if _find_bracket_span(v0, 0) is not None:
                            raw_items = _split_inline_group_raw_items(v0)
                            cur["proxy_raws"] = raw_items
                            cur["proxies"] = [_strip_yaml_quotes(t) for t in raw_items]
                        else:
                            multiline_flow_field = "proxies"
                            multiline_flow_buf = [v0]
                    else:
                        cur["proxy_raws"] = []
                        cur["proxies"] = []
                        proxies_indent = indent
                elif k0.lower() == "use":
                    cur["has_use"] = True
                    if v0.startswith("["):
                        if _find_bracket_span(v0, 0) is not None:
                            cur["use_providers"] = _split_inline_group_list(v0)
                        else:
                            multiline_flow_field = "use"
                            multiline_flow_buf = [v0]
                    elif v0:
                        cur["use_providers"] = [_strip_yaml_quotes(v0)]
                    else:
                        use_indent = indent
                else:
                    _apply_kv(cur, k0, v0)
            continue

        if cur is None:
            continue
        cur["lines"].append(raw)

        if proxies_indent is not None and indent >= proxies_indent and s.startswith("-"):
            raw_tok = s[1:].strip()
            cur["proxy_raws"].append(raw_tok)
            cur["proxies"].append(_strip_yaml_quotes(raw_tok))
            continue

        if use_indent is not None and indent >= use_indent and s.startswith("-"):
            tok = _strip_yaml_quotes(s[1:].strip())
            if tok:
                cur["use_providers"].append(tok)
            continue

        m_kv = re.match(r"^([A-Za-z0-9_.-]+)\s*:\s*(.*)$", s)
        if m_kv:
            key = m_kv.group(1).strip()
            val = m_kv.group(2).strip()
            proxies_indent = None
            use_indent = None
            if key.lower() == "proxies":
                if val.startswith("["):
                    if _find_bracket_span(val, 0) is not None:
                        raw_items = _split_inline_group_raw_items(val)
                        cur["proxy_raws"] = raw_items
                        cur["proxies"] = [_strip_yaml_quotes(t) for t in raw_items]
                    else:
                        multiline_flow_field = "proxies"
                        multiline_flow_buf = [val]
                else:
                    cur["proxy_raws"] = []
                    cur["proxies"] = []
                    proxies_indent = indent
            elif key.lower() == "use":
                cur["has_use"] = True
                if val.startswith("["):
                    if _find_bracket_span(val, 0) is not None:
                        cur["use_providers"] = _split_inline_group_list(val)
                    else:
                        multiline_flow_field = "use"
                        multiline_flow_buf = [val]
                elif val:
                    cur["use_providers"] = [_strip_yaml_quotes(val)]
                else:
                    use_indent = indent
            else:
                _apply_kv(cur, key, val)

    _finish_multiline_flow()
    return [e for e in entries if e["name"]]


def _parse_proxy_provider_entries(provider_lines: list[tuple[int, str]]) -> dict[str, dict]:
    """Parse declared entries inside a YAML `proxy-providers:` block including health-check metadata."""
    providers_map: dict[str, dict] = {}
    prov_indent = -1
    cur_name = ""
    in_hc = False
    hc_indent = -1
    for ln, raw in provider_lines[1:]:
        clean = _strip_inline_comment(raw)
        s = clean.strip()
        if not s:
            continue
        indent = len(clean) - len(clean.lstrip())
        if prov_indent == -1:
            prov_indent = indent
        if indent <= prov_indent:
            in_hc = False
            cur_name = ""
            m_flow = re.match(r"""^(['"]?)([^:'"]+)\1\s*:\s*(?:&[A-Za-z0-9_.-]+\s+)?\{(.*)\}\s*$""", s)
            if m_flow:
                pname = m_flow.group(2).strip()
                info = {
                    "name": pname,
                    "line": ln,
                    "proxy": None,
                    "hc_enable": None,
                    "hc_url": None,
                    "hc_interval": None,
                    "hc_lazy": None,
                }
                for k, v in _iter_flow_kvs(m_flow.group(3)):
                    kl = k.lower()
                    if kl == "proxy":
                        info["proxy"] = _strip_yaml_quotes(v)
                    elif kl == "health-check" and v.startswith("{") and v.endswith("}"):
                        for hk, hv in _iter_flow_kvs(v[1:-1]):
                            hkl = hk.lower()
                            hvv = _strip_yaml_quotes(hv)
                            if hkl == "enable":
                                info["hc_enable"] = hvv.lower() == "true"
                            elif hkl == "url":
                                info["hc_url"] = hvv
                            elif hkl == "interval":
                                m_i = re.match(r"^\d+", hvv)
                                if m_i:
                                    info["hc_interval"] = int(m_i.group(0))
                            elif hkl == "lazy":
                                info["hc_lazy"] = hvv.lower() == "true"
                providers_map[pname] = info
                continue
            m_head = re.match(r"""^(['"]?)([^:'"]+)\1\s*:\s*(?:&[A-Za-z0-9_.-]+)?\s*$""", s)
            if m_head:
                pname = m_head.group(2).strip()
                cur_name = pname
                providers_map[pname] = {
                    "name": pname,
                    "line": ln,
                    "proxy": None,
                    "hc_enable": None,
                    "hc_url": None,
                    "hc_interval": None,
                    "hc_lazy": None,
                }
            continue
        if not cur_name:
            continue
        info = providers_map[cur_name]
        if in_hc and indent <= hc_indent:
            in_hc = False
        m_kv = re.match(r"^([A-Za-z0-9_.-]+)\s*:\s*(.*)$", s)
        if not m_kv:
            continue
        k = m_kv.group(1).lower()
        v = m_kv.group(2).strip()
        if not in_hc:
            if k == "proxy" and v:
                info["proxy"] = _strip_yaml_quotes(v)
            elif k == "health-check":
                if v.startswith("{") and v.endswith("}"):
                    for hk, hv in _iter_flow_kvs(v[1:-1]):
                        hkl = hk.lower()
                        hvv = _strip_yaml_quotes(hv)
                        if hkl == "enable":
                            info["hc_enable"] = hvv.lower() == "true"
                        elif hkl == "url":
                            info["hc_url"] = hvv
                        elif hkl == "interval":
                            m_i = re.match(r"^\d+", hvv)
                            if m_i:
                                info["hc_interval"] = int(m_i.group(0))
                        elif hkl == "lazy":
                            info["hc_lazy"] = hvv.lower() == "true"
                else:
                    in_hc = True
                    hc_indent = indent
        else:
            vv = _strip_yaml_quotes(v)
            if k == "enable":
                info["hc_enable"] = vv.lower() == "true"
            elif k == "url":
                info["hc_url"] = vv
            elif k == "interval":
                m_i = re.match(r"^\d+", vv)
                if m_i:
                    info["hc_interval"] = int(m_i.group(0))
            elif k == "lazy":
                info["hc_lazy"] = vv.lower() == "true"
    return providers_map


def _extract_proxy_provider_names(provider_lines: list[tuple[int, str]]) -> set[str]:
    """Extract declared top-level provider names inside a YAML `proxy-providers:` block."""
    return set(_parse_proxy_provider_entries(provider_lines).keys())


def _extract_proxy_entries(proxy_lines: list[tuple[int, str]]) -> list[dict]:
    """Parse YAML proxies entries (both block and flow style) with metadata for audit and hardening."""
    entries: list[dict] = []
    cur: dict | None = None
    item_indent: int | None = None

    for ln, raw in proxy_lines[1:]:
        clean = _strip_inline_comment(raw)
        s = clean.strip()
        if not s:
            if cur is not None:
                cur["lines"].append(raw)
            continue
        indent = len(clean) - len(clean.lstrip())

        m_flow = _FLOW_GROUP_RE.match(s)
        if m_flow and (item_indent is None or indent <= item_indent):
            if item_indent is None:
                item_indent = indent
            entry: dict = {
                "name": None,
                "type": None,
                "packet_encoding": None,
                "dialer_proxy": None,
                "is_flow": True,
                "line": ln,
                "item_indent": indent,
                "key_indent": indent + 2,
                "type_line_idx": None,
                "packet_encoding_line_idx": None,
                "lines": [raw],
            }
            for k_raw, v_raw in _iter_flow_kvs(m_flow.group("body")):
                k = k_raw.strip().lower()
                v = _strip_yaml_quotes(v_raw.strip())
                if k == "name":
                    entry["name"] = v
                elif k == "type":
                    entry["type"] = v.lower()
                elif k == "packet-encoding":
                    entry["packet_encoding"] = v.lower()
                elif k == "dialer-proxy":
                    entry["dialer_proxy"] = v
            entries.append(entry)
            cur = None
            continue

        m_bare_dash = re.match(r"^-(?:\s+&[A-Za-z0-9_.-]+)?\s*$", s)
        m_new = re.match(r"^-\s+(?:&[A-Za-z0-9_.-]+\s+)?([A-Za-z0-9_.-]+)\s*:\s*(.*)$", s)
        if (m_bare_dash or m_new) and (item_indent is None or indent <= item_indent):
            if item_indent is None:
                item_indent = indent
            cur = {
                "name": None,
                "type": None,
                "packet_encoding": None,
                "dialer_proxy": None,
                "is_flow": False,
                "line": ln,
                "item_indent": indent,
                "key_indent": None,
                "type_line_idx": None,
                "packet_encoding_line_idx": None,
                "lines": [raw],
            }
            entries.append(cur)
            if m_new:
                k0, v0 = m_new.group(1).lower(), _strip_yaml_quotes(m_new.group(2).strip())
                if k0 == "name":
                    cur["name"] = v0
                elif k0 == "type":
                    cur["type"] = v0.lower()
                    cur["type_line_idx"] = 0
                elif k0 == "packet-encoding":
                    cur["packet_encoding"] = v0.lower()
                    cur["packet_encoding_line_idx"] = 0
                elif k0 == "dialer-proxy":
                    cur["dialer_proxy"] = v0
            continue

        if cur is None:
            continue
        cur["lines"].append(raw)
        if indent > cur["item_indent"]:
            # Only top-level fields inside the proxy item matter; track shallowest child indent
            if cur["key_indent"] is None or indent < cur["key_indent"]:
                if re.match(r"^[A-Za-z0-9_.-]+\s*:", s):
                    cur["key_indent"] = indent
            if indent == cur["key_indent"]:
                m_kv = re.match(r"^([A-Za-z0-9_.-]+)\s*:\s*(.*)$", s)
                if m_kv:
                    k, v = m_kv.group(1).lower(), _strip_yaml_quotes(m_kv.group(2).strip())
                    if k == "name":
                        cur["name"] = v
                    elif k == "type":
                        cur["type"] = v.lower()
                        cur["type_line_idx"] = len(cur["lines"]) - 1
                    elif k == "packet-encoding":
                        cur["packet_encoding"] = v.lower()
                        cur["packet_encoding_line_idx"] = len(cur["lines"]) - 1
                    elif k == "dialer-proxy":
                        cur["dialer_proxy"] = v

    for e in entries:
        if e["key_indent"] is None:
            e["key_indent"] = e["item_indent"] + 2
    return entries


def _extract_proxy_group_names(group_lines: list[tuple[int, str]]) -> set[str]:
    """Extract declared proxy-group names from YAML block (supporting quotes and Unicode escapes)."""
    return {e["name"] for e in _parse_proxy_group_entries(group_lines) if e["name"]}


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
    if b"\r\n" in raw_bytes:
        report.gate("File uses CRLF (\\r\\n) line endings; use pure LF (\\n)", strict)
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

    # Detect unresolved YAML aliases (*alias whose &alias anchor was stripped or never defined)
    defined_anchors: set[str] = set()
    used_aliases: list[tuple[int, str]] = []
    for ln_idx, raw_line in enumerate(lines, 1):
        code_part = _strip_inline_comment(raw_line)
        if not code_part.strip():
            continue
        for m_anc in re.finditer(r"(?:^|[\s:,\[\{])&([A-Za-z0-9_.-]+)", code_part):
            defined_anchors.add(m_anc.group(1))
        for m_ali in re.finditer(r"(?:^|[\s:,\[\{])\*([A-Za-z0-9_.-]+)", code_part):
            # Ignore wildcard domain patterns like *.google.cn or +.stun.*.*
            alias_name = m_ali.group(1)
            if not alias_name.startswith(".") and "." not in alias_name:
                used_aliases.append((ln_idx, alias_name))
    for ln_idx, alias_name in used_aliases:
        if alias_name not in defined_anchors:
            report.error(
                f"Line {ln_idx}: unresolved YAML alias '*{alias_name}' "
                f"(original anchor '&{alias_name}' is missing; inline values before hardening)"
            )

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
    if top_scalars.get("tcp-concurrent", "").lower() != "true":
        report.gate("Top-level 'tcp-concurrent: true' is recommended to speed up multi-IP handshakes", strict)
    if not top_scalars.get("keep-alive-interval"):
        report.gate("Top-level 'keep-alive-interval: 15' is recommended to sustain long-lived connections", strict)
    if not top_scalars.get("keep-alive-idle"):
        report.gate("Top-level 'keep-alive-idle: 600' is recommended to reduce reconnect handshakes", strict)

    profile_lines = blocks.get("profile", [])
    profile_text = "\n".join(_strip_inline_comment(l) for _, l in profile_lines)
    if not profile_lines or not re.search(r"(?:^|\s|,)store-selected\s*:\s*true\b", profile_text, re.M):
        report.gate(
            "Top-level 'profile.store-selected: true' is missing (selected group/node state is lost on restart)",
            strict,
        )
    if not profile_lines or not re.search(r"(?:^|\s|,)store-fake-ip\s*:\s*true\b", profile_text, re.M):
        report.gate(
            "Top-level 'profile.store-fake-ip: true' is missing (Fake-IP mappings are lost on restart)",
            strict,
        )

    # DNS block checks
    dns_lines = blocks.get("dns", [])
    dns_text = "\n".join(_strip_inline_comment(l) for _, l in dns_lines)
    if not dns_lines or not re.search(r"^\s+enable:\s*true\b", dns_text, re.M):
        report.error("dns.enable is missing or not set to true")
    if not re.search(r"^\s+ipv6:\s*false\b", dns_text, re.M):
        report.gate("dns.ipv6 is not set to false", strict)
    if not re.search(r"^\s+enhanced-mode:\s*fake-ip\b", dns_text, re.M):
        report.gate("dns.enhanced-mode is not fake-ip", strict)

    # Parse dns.fake-ip-filter entries
    in_fif = False
    fif_indent = -1
    fake_ip_filter_entries: set[str] = set()
    for _, raw in dns_lines:
        clean = _strip_inline_comment(raw)
        stripped = clean.strip()
        if not stripped:
            continue
        indent = len(clean) - len(clean.lstrip())
        if stripped.startswith("fake-ip-filter:"):
            rhs = stripped.split(":", 1)[1].strip()
            if rhs.startswith("[") and rhs.endswith("]"):
                for item in _split_inline_group_list(rhs):
                    fake_ip_filter_entries.add(item.lower())
                in_fif = False
            else:
                in_fif = True
                fif_indent = indent
            continue
        if in_fif:
            if indent <= fif_indent:
                in_fif = False
            elif stripped.startswith("-"):
                val = _strip_yaml_quotes(stripped[1:].strip()).lower()
                if val:
                    fake_ip_filter_entries.add(val)

    for req_fif in ("rule-set:cn-domain", "rule-set:private"):
        if req_fif not in fake_ip_filter_entries:
            report.gate(
                f"dns.fake-ip-filter lacks '{req_fif}' (domestic/private domains may get Fake-IP mapped)",
                strict,
            )

    # Check DoH nameserver proxy binding & literal-IP DoH (supports block and inline flow lists)
    in_nameserver = False
    ns_indent = -1
    ns_entries: list[tuple[int, str]] = []
    for ln, raw in dns_lines:
        clean = _strip_inline_comment(raw)
        stripped = clean.strip()
        if not stripped:
            continue
        indent = len(clean) - len(clean.lstrip())
        if stripped.startswith("nameserver:"):
            rhs = stripped.split(":", 1)[1].strip()
            if rhs.startswith("[") and rhs.endswith("]"):
                for item in _split_inline_group_list(rhs):
                    ns_entries.append((ln, item))
                in_nameserver = False
            else:
                in_nameserver = True
                ns_indent = indent
            continue
        if in_nameserver:
            if indent <= ns_indent:
                in_nameserver = False
            elif stripped.startswith("-"):
                val = _strip_yaml_quotes(stripped[1:].strip())
                if val:
                    ns_entries.append((ln, val))
    if not ns_entries:
        report.gate("dns.nameserver is missing (overseas queries require encrypted DoH via proxy)", strict)
    for ln, val in ns_entries:
        val_low = val.lower()
        if not val_low.startswith(("https://", "tls://", "quic://")):
            report.gate(
                f"Line {ln}: dns.nameserver '{val}' uses plaintext/unencrypted DNS; use encrypted literal-IP DoH (e.g. https://1.1.1.1/dns-query#<GROUP>)",
                strict,
            )
        elif "#" not in val:
            report.gate(f"Line {ln}: dns.nameserver DoH entry '{val}' has no '#<PROXY_GROUP>' suffix", strict)
        if "dns.google" in val_low:
            report.gate(
                f"Line {ln}: dns.nameserver '{val}' uses hostname 'dns.google' "
                "(triggers plaintext domestic DNS lookup; use literal IP https://1.1.1.1/dns-query or https://8.8.8.8/dns-query)",
                strict,
            )

    # Sniffer checks
    sniffer_lines = blocks.get("sniffer", [])
    sniffer_text = "\n".join(_strip_inline_comment(l) for _, l in sniffer_lines)
    if not sniffer_lines or not re.search(r"^\s+enable:\s*true\b", sniffer_text, re.M):
        report.error("sniffer.enable is missing or not set to true")
    if not re.search(r"^\s+force-dns-mapping:\s*true\b", sniffer_text, re.M):
        report.gate("sniffer.force-dns-mapping: true is recommended for reliable domain classification", strict)
    if not re.search(r"^\s+parse-pure-ip:\s*true\b", sniffer_text, re.M):
        report.gate("sniffer.parse-pure-ip: true is missing", strict)
    for ln, raw in sniffer_lines:
        if "Mijia Cloud" in _strip_inline_comment(raw):
            report.error(f"Line {ln}: invalid sniffer.skip-domain 'Mijia Cloud'; use '+.mijia.cloud'")
    for required_skip, reason in (
        ("data.bilibili.com", "risk of SNI rewrite to dataflow.biliapi.com"),
        ("www.workbuddy.cn", "risk of SNI rewrite on WorkBuddy/copilot.tencent.com endpoints"),
        ("long.weixin.qq.com", "risk of MMTLS port-80 sniffing failure on WeChat long connections"),
    ):
        if required_skip not in sniffer_text:
            report.gate(f"sniffer.skip-domain lacks '{required_skip}' ({reason})", strict)

    # Check dns.default-nameserver (must be literal domestic IPv4s, no domain names or overseas/deprecated DNS)
    in_default_ns = False
    dns_def_indent = -1
    default_ns_entries: list[tuple[int, str]] = []
    for ln, raw in dns_lines:
        clean = _strip_inline_comment(raw)
        stripped = clean.strip()
        if not stripped:
            continue
        indent = len(clean) - len(clean.lstrip())
        if stripped.startswith("default-nameserver:"):
            rhs = stripped.split(":", 1)[1].strip()
            if rhs.startswith("[") and rhs.endswith("]"):
                for item in _split_inline_group_list(rhs):
                    default_ns_entries.append((ln, item))
                in_default_ns = False
            else:
                in_default_ns = True
                dns_def_indent = indent
            continue
        if in_default_ns:
            if indent <= dns_def_indent:
                in_default_ns = False
            elif stripped.startswith("-"):
                val = _strip_yaml_quotes(stripped[1:].strip())
                if val:
                    default_ns_entries.append((ln, val))

    if not default_ns_entries:
        report.gate("dns.default-nameserver is missing (must specify domestic literal IPv4 bootstrap resolvers)", strict)
    for ln, val in default_ns_entries:
        val_low = val.lower().strip()
        m_host = re.match(r"^(?:(?:https|tls|udp|tcp|quic)://)?\[?([^/\]:?#]+)\]?", val_low)
        host = m_host.group(1) if m_host else val_low
        is_ipv4 = False
        try:
            ipaddress.IPv4Address(host)
            is_ipv4 = True
        except ipaddress.AddressValueError:
            is_ipv4 = False
        if not is_ipv4:
            report.gate(
                f"Line {ln}: dns.default-nameserver '{val}' is not a literal IPv4 address "
                "(hostnames or IPv6 are invalid here when ipv6: false; use domestic literal IPv4 such as 223.5.5.5 / 119.29.29.29)",
                strict,
            )
        elif host in _BAD_PROXY_NS_HOSTS:
            report.gate(
                f"Line {ln}: dns.default-nameserver '{val}' uses overseas or deprecated DNS IP; "
                "use domestic literal IPv4 resolvers (e.g. 223.5.5.5 / 119.29.29.29)",
                strict,
            )

    in_pns = False
    pns_indent = -1
    pns_entries: list[tuple[int, str]] = []
    for ln, raw in dns_lines:
        clean = _strip_inline_comment(raw)
        stripped = clean.strip()
        if not stripped:
            continue
        indent = len(clean) - len(clean.lstrip())
        if stripped.startswith("proxy-server-nameserver:"):
            rhs = stripped.split(":", 1)[1].strip()
            if rhs.startswith("[") and rhs.endswith("]"):
                for item in _split_inline_group_list(rhs):
                    pns_entries.append((ln, item.lower()))
                in_pns = False
            else:
                in_pns = True
                pns_indent = indent
            continue
        if in_pns:
            if indent <= pns_indent:
                in_pns = False
            elif stripped.startswith("-"):
                val = _strip_yaml_quotes(stripped[1:].strip()).lower()
                if val:
                    pns_entries.append((ln, val))

    if not pns_entries:
        report.gate("dns.proxy-server-nameserver is missing (node resolution lacks domestic direct DoH/DoT)", strict)
    elif len(pns_entries) < 2:
        report.gate("dns.proxy-server-nameserver has only 1 entry; recommend >= 2 redundant domestic IP DoH/DoT resolvers", strict)
    for ln, val in pns_entries:
        m_host = re.match(r"^(?:https|tls|quic)://\[?([^/\]:?#]+)\]?", val)
        if not m_host:
            report.gate(
                f"Line {ln}: dns.proxy-server-nameserver '{val}' is not an encrypted DoH/DoT/DoQ URL; "
                "use domestic literal-IP DoH/DoT (223.5.5.5 / 223.6.6.6 / tls://223.5.5.5:853)",
                strict,
            )
            continue
        host = m_host.group(1)
        is_ipv4 = False
        try:
            ipaddress.IPv4Address(host)
            is_ipv4 = True
        except ipaddress.AddressValueError:
            is_ipv4 = False
        if not is_ipv4 or host in _BAD_PROXY_NS_HOSTS:
            report.gate(
                f"Line {ln}: dns.proxy-server-nameserver '{val}' uses overseas, hostname, or deprecated pure-IP DNS; "
                "prefer domestic literal-IP DoH/DoT (223.5.5.5 / 223.6.6.6 / tls://223.5.5.5:853)",
                strict,
            )

    # Parse rule-providers -> behavior/type/inline payload (supports block style and inline flow maps)
    providers: dict[str, str] = {}
    provider_types: dict[str, str] = {}
    provider_payloads: dict[str, list[str]] = {}
    current_prov = ""
    prov_indent = -1
    in_payload = False
    payload_indent = -1
    for ln, raw in blocks.get("rule-providers", [])[1:]:
        clean = _strip_inline_comment(raw)
        if not clean.strip():
            continue
        indent = len(clean) - len(clean.lstrip())
        s = clean.strip()
        m_flow = re.match(r"""^(['"]?)([^:'"]+)\1\s*:\s*\{(.*)\}\s*$""", s)
        if m_flow and (prov_indent == -1 or indent <= prov_indent):
            prov_indent = indent
            current_prov = ""
            in_payload = False
            pname = m_flow.group(2).strip()
            body = m_flow.group(3)
            m_beh = re.search(r"""\bbehavior\s*:\s*['"]?([A-Za-z0-9_-]+)['"]?""", body)
            m_typ = re.search(r"""\btype\s*:\s*['"]?([A-Za-z0-9_-]+)['"]?""", body)
            providers[pname] = m_beh.group(1).lower() if m_beh else ""
            if m_typ:
                provider_types[pname] = m_typ.group(1).lower()
            continue
        if s.endswith(":") and not s.startswith(("behavior:", "type:", "payload:", "format:", "interval:", "url:", "path:")) and (prov_indent == -1 or indent <= prov_indent):
            prov_indent = indent
            current_prov = _strip_yaml_quotes(s[:-1].strip())
            providers.setdefault(current_prov, "")
            in_payload = False
        elif current_prov:
            if in_payload and indent <= payload_indent:
                in_payload = False
            if s.startswith("behavior:"):
                providers[current_prov] = s.split(":", 1)[1].strip().strip("\"'").lower()
            elif s.startswith("type:"):
                provider_types[current_prov] = s.split(":", 1)[1].strip().strip("\"'").lower()
            elif s.startswith("payload:"):
                rhs = s.split(":", 1)[1].strip()
                items = provider_payloads.setdefault(current_prov, [])
                if rhs.startswith("[") and rhs.endswith("]"):
                    for tok in rhs[1:-1].split(","):
                        tok_clean = _strip_yaml_quotes(tok.strip()).lower()
                        if tok_clean:
                            items.append(tok_clean)
                else:
                    in_payload = True
                    payload_indent = indent
            elif in_payload and s.startswith("-"):
                item = _strip_yaml_quotes(s[1:].strip()).lower()
                if item:
                    provider_payloads.setdefault(current_prov, []).append(item)

    allowed_inline_rule_providers = frozenset({"private", "cn-domain"})
    for pname in providers:
        ptype = provider_types.get(pname, "")
        if ptype != "inline":
            report.gate(
                f"rule-providers.{pname} uses 'type: {ptype or '<missing>'}' instead of local 'type: inline' DLC payload",
                strict,
            )
        if pname not in allowed_inline_rule_providers:
            report.gate(
                f"rule-providers.{pname} is outside pure-DLC inline allowlist {sorted(allowed_inline_rule_providers)} "
                "(remove external or custom rule-providers)",
                strict,
            )

    for pname in allowed_inline_rule_providers:
        if pname not in providers:
            report.gate(f"Required inline rule-provider '{pname}' is missing from rule-providers", strict)
        elif not provider_payloads.get(pname):
            report.gate(f"Inline rule-provider '{pname}' has an empty payload", strict)

    inline_provider_matchers: dict[str, tuple[set[str], set[str]]] = {}
    for pname, entries in provider_payloads.items():
        if providers.get(pname) != "domain":
            continue
        exact_set: set[str] = set()
        suf_set: set[str] = set()
        for entry in entries:
            if any(ch in entry for ch in "^$\\[]()"):
                report.error(
                    f"rule-providers.{pname} (behavior: domain) contains regex-like entry '{entry}' "
                    "(Mihomo inline domain payloads do not support regexes; move to rules as DOMAIN-REGEX)"
                )
            if entry.startswith("+."):
                suf_set.add(entry[2:])
            elif entry.startswith("."):
                suf_set.add(entry[1:])
            else:
                exact_set.add(entry)
        inline_provider_matchers[pname.lower()] = (exact_set, suf_set)

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
                        if rhs.startswith("[") and rhs.endswith("]"):
                            vals.extend(_split_inline_group_list(rhs))
                        else:
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
    if ns_policy and (
        "rule-set:cn-domain" in ns_policy or "cn-domain" in providers
    ):
        apple_ns_vals = ns_policy.get("+.apple.com") or ns_policy.get("apple.com")
        if effective_apple == "b":
            if not apple_ns_vals or not any("#" in v for v in apple_ns_vals):
                report.gate(
                    "dns.nameserver-policy lacks overseas '#<PROXY>' override for '+.apple.com' "
                    "while cn-domain is present (--apple b)",
                    strict,
                )
        else:
            if not apple_ns_vals or any("#" in v for v in apple_ns_vals):
                report.gate(
                    "dns.nameserver-policy lacks domestic DoH mapping for '+.apple.com' under Situation A (--apple a)",
                    strict,
                )
            us_apple_vals = ns_policy.get("+.tv.apple.com") or ns_policy.get("+.safebrowsing.apple")
            if not us_apple_vals or not any("#" in v for v in us_apple_vals):
                report.gate(
                    "dns.nameserver-policy lacks overseas '#<PROXY>' override for US-only Apple services (--apple a)",
                    strict,
                )

    if not ns_policy:
        report.gate("dns.nameserver-policy is missing (domestic/private/ad split DNS is required)", strict)
    else:
        for req_rs_pol in ("rule-set:cn-domain", "rule-set:private"):
            if req_rs_pol not in ns_policy:
                report.gate(
                    f"dns.nameserver-policy lacks domestic DoH mapping for '{req_rs_pol}'",
                    strict,
                )
        for ncsi_dom in ("+.msftconnecttest.com", "+.msftncsi.com"):
            ncsi_vals = ns_policy.get(ncsi_dom)
            if not ncsi_vals or any("#" in v for v in ncsi_vals):
                report.gate(
                    f"dns.nameserver-policy lacks domestic DoH mapping for '{ncsi_dom}' (NCSI may bypass to overseas DNS)",
                    strict,
                )
        for arpa_dom in ("+.in-addr.arpa", "+.ip6.arpa"):
            if arpa_dom not in ns_policy:
                report.gate(
                    f"dns.nameserver-policy lacks '{arpa_dom}' guard (PTR reverse lookups may leak to overseas DNS)",
                    strict,
                )
        if any("doh.pub" in v.lower() for vals in ns_policy.values() for v in vals):
            report.gate(
                "dns.nameserver-policy uses hostname 'doh.pub' (risk of HTTP 429 rate-limit and UDP bootstrap fallback; prefer IP DoH 223.5.5.5 / 223.6.6.6)",
                strict,
            )
        if any(ip in v.lower() for vals in ns_policy.values() for v in vals for ip in ("1.12.12.12", "120.53.53.53")):
            report.gate(
                "dns.nameserver-policy uses deprecated pure-IP DNSPod endpoint (1.12.12.12 / 120.53.53.53); prefer AliDoH 223.5.5.5 / 223.6.6.6",
                strict,
            )
        if any("dns.google" in v.lower() for vals in ns_policy.values() for v in vals):
            report.gate(
                "dns.nameserver-policy uses hostname 'dns.google' (triggers plaintext domestic DNS lookup; prefer literal IP 1.1.1.1 / 8.8.8.8)",
                strict,
            )
        missing_dns_ad_rejects = [
            dom
            for dom in FLCLASH_DNS_AD_REJECT_EXACT
            if "rcode://name_error" not in [v.lower() for v in ns_policy.get(dom, [])]
        ] + [
            f"+.{dom}"
            for dom in FLCLASH_DNS_AD_REJECT_SUFFIXES
            if "rcode://name_error" not in [v.lower() for v in ns_policy.get(f"+.{dom}", [])]
        ]
        if missing_dns_ad_rejects:
            preview = ", ".join(missing_dns_ad_rejects[:5])
            suffix = f" (+{len(missing_dns_ad_rejects) - 5} more)" if len(missing_dns_ad_rejects) > 5 else ""
            report.gate(
                f"dns.nameserver-policy lacks rcode://name_error short-circuit for high-freq ad domain(s): {preview}{suffix}",
                strict,
            )

    for px in _extract_proxy_entries(blocks.get("proxies", [])):
        if px["type"] == "vless" and px["packet_encoding"] != "xudp":
            report.gate(
                f"Line {px['line']}: VLESS proxy '{px['name'] or 'unnamed'}' lacks 'packet-encoding: xudp'",
                strict,
            )

    # Verify DNS rule-set references ONLY use behavior: domain
    for ln, raw in dns_lines:
        clean_dns = _strip_inline_comment(raw)
        for m in re.finditer(r"rule-set:([A-Za-z0-9_.-]+)", clean_dns):
            rname = m.group(1)
            beh = providers.get(rname)
            if beh is None:
                report.gate(f"Line {ln}: DNS references unknown rule-set '{rname}'", strict)
            elif beh and beh != "domain":
                report.error(
                    f"Line {ln}: DNS references rule-set '{rname}' with behavior '{beh}'; "
                    "Mihomo requires 'behavior: domain' in fake-ip-filter / nameserver-policy"
                )

    if providers.get("private") and providers["private"] != "domain":
        report.error(f"rule-providers.private has behavior '{providers['private']}', usually must be 'domain'")

    # Extract declared proxy-groups & proxy-providers and verify hardening + references
    group_block = blocks.get("proxy-groups", [])
    group_entries = _parse_proxy_group_entries(group_block)
    defined_groups = {g["name"] for g in group_entries}
    proxy_provider_entries = _parse_proxy_provider_entries(blocks.get("proxy-providers", []))
    defined_proxy_providers = set(proxy_provider_entries.keys())
    if not defined_groups:
        report.gate("proxy-groups section is missing or declares 0 groups", strict)

    # Validate dns.nameserver '#<group>' targets exist in proxy-groups
    if defined_groups:
        for ln, val in ns_entries:
            if "#" in val:
                ns_grp = val.split("#", 1)[1].strip()
                if ns_grp and ns_grp not in defined_groups and ns_grp not in BUILTIN_MIHOMO_ACTIONS:
                    report.error(
                        f"Line {ln}: dns.nameserver '{val}' references undefined proxy-group '{ns_grp}'"
                    )

    # Validate optional proxy-providers health-check hardening & proxy: group references
    for pname, pinfo in proxy_provider_entries.items():
        if pinfo["proxy"] and defined_groups:
            if pinfo["proxy"] not in defined_groups and pinfo["proxy"] not in BUILTIN_MIHOMO_ACTIONS:
                report.error(
                    f"Line {pinfo['line']}: proxy-providers.{pname} 'proxy: {pinfo['proxy']}' references undefined proxy-group"
                )
        if pinfo["hc_url"] and pinfo["hc_url"].lower().startswith("http://"):
            report.gate(
                f"Line {pinfo['line']}: proxy-providers.{pname} health-check url uses plaintext HTTP ({pinfo['hc_url']}); use HTTPS",
                strict,
            )
        if pinfo["hc_enable"] is not False and (pinfo["hc_enable"] is True or pinfo["hc_url"] or pinfo["hc_interval"] is not None):
            if pinfo["hc_interval"] is not None and pinfo["hc_interval"] < 300:
                report.gate(
                    f"Line {pinfo['line']}: proxy-providers.{pname} health-check interval {pinfo['hc_interval']}s is below 300s",
                    strict,
                )
            if pinfo["hc_lazy"] is not True:
                report.gate(
                    f"Line {pinfo['line']}: proxy-providers.{pname} health-check lacks 'lazy: true'",
                    strict,
                )

    for g in group_entries:
        if g["has_use"]:
            if not g["use_providers"]:
                report.error(
                    f"Line {g['line']}: proxy-group '{g['name']}' declares 'use:' with no proxy-provider names"
                )
            else:
                for up in g["use_providers"]:
                    if up not in defined_proxy_providers:
                        report.error(
                            f"Line {g['line']}: proxy-group '{g['name']}' references undefined proxy-provider '{up}' "
                            "in 'use:' (missing from top-level proxy-providers)"
                        )
        if g["url"] and g["url"].lower().startswith("http://"):
            report.gate(
                f"Line {g['line']}: proxy-group '{g['name']}' health-check url uses plaintext HTTP ({g['url']}); use HTTPS for reliability",
                strict,
            )
        if g["type"] in AUTO_TEST_GROUP_TYPES:
            if g["interval"] is not None and g["interval"] < 300:
                report.gate(
                    f"Line {g['line']}: proxy-group '{g['name']}' ({g['type']}) interval {g['interval']}s is below 300s",
                    strict,
                )
            if g["lazy"] is not True:
                report.gate(
                    f"Line {g['line']}: proxy-group '{g['name']}' ({g['type']}) lacks 'lazy: true' "
                    "(risk of cold-start concurrent health-check storm)",
                    strict,
                )
            if (
                not g["has_use"]
                and not g["has_include_all"]
                and g["proxies"] is not None
                and len(g["proxies"]) <= 1
            ):
                report.gate(
                    f"Line {g['line']}: proxy-group '{g['name']}' ({g['type']}) wraps <=1 proxy "
                    "(redundant health-check group)",
                    strict,
                )

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

    # Check every rule's target group and referenced RULE-SET providers exist
    valid_targets = (defined_groups | BUILTIN_MIHOMO_ACTIONS) if defined_groups else set()
    for ln, item in indexed_rules:
        parsed = _parse_rule_line(item)
        if not parsed:
            continue
        typ, val, act, _ = parsed
        if typ == "RULE-SET":
            prov_key = val.strip()
            if prov_key not in providers:
                report.error(
                    f"Line {ln}: RULE-SET,{prov_key} references undefined rule-provider '{prov_key}' "
                    "(mihomo -t will fail)"
                )
        if valid_targets and act not in valid_targets:
            report.error(
                f"Line {ln}: rule target '{act}' not found in proxy-groups or built-in actions"
            )

    rule_texts = [r for _, r in indexed_rules]
    quic_reject_idx = next(
        (
            i
            for i, r in enumerate(rule_texts)
            if r.upper().startswith("AND,") and "NETWORK,UDP" in r.upper() and "DST-PORT,443" in r.upper()
            and "DOMAIN-SUFFIX" not in r.upper() and ",REJECT" in r.upper()
        ),
        None,
    )
    if quic_reject_idx is None:
        if any("PROTOCOL,UDP" in r or "DEST-PORT,443" in r for r in rule_texts):
            report.error("Detected Shadowrocket rule syntax (PROTOCOL/DEST-PORT) in Mihomo YAML; use NETWORK/DST-PORT")
        else:
            report.gate("Layer 1.5 QUIC block 'AND,((NETWORK,UDP),(DST-PORT,443)),REJECT' not found", strict)
    _check_tencent_udp_precedence(
        rule_texts,
        "NETWORK,UDP",
        report,
        strict,
        quic_reject_idx=quic_reject_idx,
    )
    if not any(
        "NETWORK,UDP" in r.upper() and "SRC-PORT,8567" in r.upper() and "DST-PORT,8567" in r.upper() and ",REJECT" in r.upper()
        for r in rule_texts
    ):
        report.gate("Layer 1.5 lacks PCDN port 8567 UDP REJECT guard (SRC-PORT/DST-PORT)", strict)

    stats = _check_common_rules(
        indexed_rules,
        report,
        mode="flclash",
        strict=strict,
        apple_mode=apple_mode,
        provider_behaviors=providers,
        inline_provider_matchers=inline_provider_matchers or None,
    )
    fc_domains = set()
    fc_keywords = set()
    for _, r in indexed_rules:
        p = _parse_rule_line(r)
        if p:
            if p[0] in {"DOMAIN", "DOMAIN-SUFFIX"}:
                fc_domains.add(p[1].lower())
            elif p[0] == "DOMAIN-KEYWORD":
                fc_keywords.add(p[1].lower())
    _check_layer3_exact_and_pcdn(fc_domains, fc_keywords, report, strict)
    report.info(
        f"FlClash summary: {len(lines)} lines, {stats['total_rules']} inline rules, "
        f"{len(defined_groups)} proxy-groups, {len(providers)} rule-providers, "
        f"checkers={stats['checkers']}/{len(CHECKER_DOMAINS)}, dups={stats['duplicates']}, bad_ip={stats['bad_ip']}"
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
    if args.strict:
        return 1 if (report.errors or report.warnings) else 0
    return 1 if report.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
