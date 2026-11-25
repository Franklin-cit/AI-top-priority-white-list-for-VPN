#!/usr/bin/env python3
"""Loader, SHA-256 fetcher, and layer extractor for v2fly/domain-list-community.

Uses only the Python standard library and supports both:
1. Official Release `dlc.dat_plain.yml` (verified against `dlc.dat_plain.yml.sha256sum`), and
2. A local `domain-list-community/data` directory (resolved and pruned identically to `main.go`).
"""

from __future__ import annotations

import hashlib
import pathlib
import re
import urllib.request
from dataclasses import dataclass

DLC_PLAIN_YML_URL = (
    "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat_plain.yml"
)
DLC_PLAIN_SHA256_URL = (
    "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat_plain.yml.sha256sum"
)

_QUANTIFIER_COMMA_RE = re.compile(
    r"(\\.|\[[^\]]+\]|\([^()]+\)|[A-Za-z0-9_.\-])\{(\d+),(\d*)\}"
)
_YAML_DQ_ESCAPE_RE = re.compile(
    r'\\(["\\/bfnrt]|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})'
)
_YAML_SIMPLE_ESCAPES = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}


def _unescape_yaml_double_quoted(raw_inner: str) -> str:
    """Decode YAML double-quoted escape sequences (critical for regexps in dlc.dat_plain.yml)."""

    def _sub(m: re.Match[str]) -> str:
        esc = m.group(1)
        if esc in _YAML_SIMPLE_ESCAPES:
            return _YAML_SIMPLE_ESCAPES[esc]
        return chr(int(esc[1:], 16))

    return _YAML_DQ_ESCAPE_RE.sub(_sub, raw_inner)


@dataclass(frozen=True)
class DlcEntry:
    """Single domain rule entry from domain-list-community."""

    typ: str
    value: str
    attrs: tuple[str, ...] = ()

    @property
    def plain(self) -> str:
        if not self.attrs:
            return f"{self.typ}:{self.value}"
        attr_str = ",".join(f"@{a}" for a in self.attrs)
        return f"{self.typ}:{self.value}:{attr_str}"


def rewrite_regex_without_commas(pattern: str) -> str:
    """Expand `{m,n}` and `{m,}` regex quantifiers so comma-delimited rule parsers never split patterns."""
    if "," not in pattern:
        return pattern

    def _replace(match: re.Match[str]) -> str:
        atom = match.group(1)
        lo = int(match.group(2))
        hi_str = match.group(3)
        if not hi_str:
            return (atom * lo) + f"{atom}*"
        hi = int(hi_str)
        if hi < lo:
            return match.group(0)
        if hi > 8:
            return (atom * lo) + f"{atom}*"
        return (atom * lo) + (f"(?:{atom})?" * (hi - lo))

    out = pattern
    for _ in range(4):
        nxt = _QUANTIFIER_COMMA_RE.sub(_replace, out)
        if nxt == out or "," not in nxt:
            out = nxt
            break
        out = nxt
    return out


def fetch_dlc_plain(
    dest: pathlib.Path,
    url: str = DLC_PLAIN_YML_URL,
    sha_url: str = DLC_PLAIN_SHA256_URL,
) -> pathlib.Path:
    """Download official `dlc.dat_plain.yml` and verify its SHA-256 checksum."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "subscription-hardener/2.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()
    if len(data) < 100_000 or b"lists:\n" not in data[:128]:
        raise ValueError(f"Downloaded dlc.dat_plain.yml looks invalid ({len(data)} bytes)")

    if sha_url:
        sha_req = urllib.request.Request(sha_url, headers={"User-Agent": "subscription-hardener/2.0"})
        with urllib.request.urlopen(sha_req, timeout=30) as resp:
            sha_text = resp.read().decode("utf-8", errors="replace").strip()
        expected_hex = sha_text.split()[0].lower() if sha_text else ""
        actual_hex = hashlib.sha256(data).hexdigest().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_hex) or actual_hex != expected_hex:
            raise ValueError(
                f"SHA-256 mismatch for dlc.dat_plain.yml: expected {expected_hex}, got {actual_hex}"
            )
        dest.with_name(dest.name + ".sha256sum").write_text(f"{actual_hex}  {dest.name}\n", encoding="utf-8")

    dest.write_bytes(data)
    return dest


def _parse_plain_rule_token(token: str) -> DlcEntry | None:
    if ":" not in token:
        return None
    typ_raw, rest = token.split(":", 1)
    typ = typ_raw.strip().lower()
    if typ not in {"domain", "full", "keyword", "regexp"} or not rest.strip():
        return None
    m_attr = re.match(r"^(.*?):(@[^:]+)$", rest)
    if m_attr:
        val = m_attr.group(1).strip()
        attr_part = m_attr.group(2)
    else:
        val = rest.strip()
        attr_part = ""
    if not val:
        return None
    if typ != "regexp":
        val = val.lower()
    attrs: tuple[str, ...] = ()
    if attr_part:
        attrs = tuple(sorted({a.strip().lstrip("@").lower() for a in attr_part.split(",") if a.strip()}))
    return DlcEntry(typ=typ, value=val, attrs=attrs)


def _load_plain_yml(path: pathlib.Path) -> dict[str, list[DlcEntry]]:
    lists: dict[str, list[DlcEntry]] = {}
    cur_name: str | None = None
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if raw.startswith("  - name: "):
            cur_name = raw.split('"', 2)[1].strip().lower()
            lists[cur_name] = []
        elif raw.startswith("      - ") and cur_name is not None:
            token = raw[8:].strip()
            if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
                token = _unescape_yaml_double_quoted(token[1:-1])
            elif len(token) >= 2 and token[0] == "'" and token[-1] == "'":
                token = token[1:-1].replace("''", "'")
            entry = _parse_plain_rule_token(token)
            if entry is not None:
                lists[cur_name].append(entry)
    if not lists or "cn" not in lists or "geolocation-!cn" not in lists:
        raise ValueError(f"Invalid dlc.dat_plain.yml structure in {path}")
    return lists


def _polish_entries(rough: dict[str, DlcEntry]) -> list[DlcEntry]:
    """Prune redundant subdomains exactly matching DLC `polishList` in `main.go`."""
    parents: set[str] = set()
    queuing: list[DlcEntry] = []
    final: list[DlcEntry] = []
    for entry in rough.values():
        if entry.typ in {"regexp", "keyword"}:
            final.append(entry)
        elif entry.typ == "domain":
            parents.add(entry.value)
            if entry.attrs:
                _, domain_and_attrs = entry.plain.split(":", 1)
                parents.add(domain_and_attrs)
            queuing.append(entry)
        elif entry.typ == "full":
            queuing.append(entry)

    for qentry in queuing:
        pd = qentry.value if not qentry.attrs else qentry.plain.split(":", 1)[1]
        if qentry.typ == "full":
            pd = "." + pd
        redundant = False
        while "." in pd:
            _, pd = pd.split(".", 1)
            if pd in parents:
                redundant = True
                break
        if not redundant:
            final.append(qentry)

    return sorted(final, key=lambda e: e.plain)


def _load_raw_data_dir(data_dir: pathlib.Path) -> dict[str, list[DlcEntry]]:
    if (data_dir / "data").is_dir():
        data_dir = data_dir / "data"

    raw_lists: dict[str, dict[str, list]] = {}
    for file_path in sorted(data_dir.iterdir()):
        if not file_path.is_file():
            continue
        name = file_path.name.lower()
        cur = raw_lists.setdefault(name, {"incs": [], "entries": []})
        for raw_line in file_path.read_text(encoding="utf-8", errors="replace").splitlines():
            clean = raw_line.split("#", 1)[0].strip()
            if not clean:
                continue
            if ":" in clean:
                typ, rest = clean.split(":", 1)
                typ = typ.strip().lower()
            else:
                typ, rest = "domain", clean
            parts = rest.split()
            if not parts:
                continue
            val = parts[0].strip()
            if typ == "include":
                must = [p[1:].lower() for p in parts[1:] if p.startswith("@") and not p.startswith("@-")]
                ban = [p[2:].lower() for p in parts[1:] if p.startswith("@-")]
                cur["incs"].append((val.lower(), must, ban))
            elif typ in {"domain", "full", "keyword", "regexp"}:
                val_norm = val if typ == "regexp" else val.lower()
                attrs = tuple(sorted({p[1:].lower() for p in parts[1:] if p.startswith("@")}))
                affs = [p[1:].lower() for p in parts[1:] if p.startswith("&")]
                entry = DlcEntry(typ=typ, value=val_norm, attrs=attrs)
                cur["entries"].append(entry)
                for aff in affs:
                    raw_lists.setdefault(aff, {"incs": [], "entries": []})["entries"].append(entry)

    resolved_rough: dict[str, dict[str, DlcEntry]] = {}
    resolving: set[str] = set()

    def _resolve(name: str) -> dict[str, DlcEntry]:
        if name in resolved_rough:
            return resolved_rough[name]
        if name in resolving:
            raise ValueError(f"Circular inclusion in DLC data: {name}")
        resolving.add(name)
        rough = {e.plain: e for e in raw_lists[name]["entries"]}
        for src, must, ban in raw_lists[name]["incs"]:
            src_rough = _resolve(src)
            is_full = not must and not ban
            for plain, entry in src_rough.items():
                if is_full:
                    rough[plain] = entry
                    continue
                if not entry.attrs:
                    ok = len(must) == 0
                else:
                    ok = all(m in entry.attrs for m in must) and all(b not in entry.attrs for b in ban)
                if ok:
                    rough[plain] = entry
        resolving.remove(name)
        resolved_rough[name] = rough
        return rough

    out: dict[str, list[DlcEntry]] = {}
    for list_name in raw_lists:
        rough = _resolve(list_name)
        if rough:
            out[list_name] = _polish_entries(rough)
    if "cn" not in out or "geolocation-!cn" not in out:
        raise ValueError(f"Invalid DLC data directory: {data_dir}")
    return out


class DlcCatalog:
    """In-memory query interface over v2fly/domain-list-community lists."""

    def __init__(self, lists: dict[str, list[DlcEntry]]) -> None:
        self.lists = lists

    @classmethod
    def from_source(cls, source: pathlib.Path) -> DlcCatalog:
        if source.is_dir():
            return cls(_load_raw_data_dir(source))
        if source.is_file():
            return cls(_load_plain_yml(source))
        raise FileNotFoundError(f"DLC source not found: {source}")

    def get(self, name: str) -> list[DlcEntry]:
        return list(self.lists.get(name.lower(), ()))

    @staticmethod
    def filter_entries(
        entries: list[DlcEntry],
        *,
        must_attrs: tuple[str, ...] = (),
        ban_attrs: tuple[str, ...] = (),
    ) -> list[DlcEntry]:
        out: list[DlcEntry] = []
        for e in entries:
            if must_attrs and not all(m in e.attrs for m in must_attrs):
                continue
            if ban_attrs and any(b in e.attrs for b in ban_attrs):
                continue
            out.append(e)
        return out

    def rule_type_and_value(self, entry: DlcEntry, csv_safe_regex: bool = True) -> tuple[str, str]:
        if entry.typ == "domain":
            return "DOMAIN-SUFFIX", entry.value
        if entry.typ == "full":
            return "DOMAIN", entry.value
        if entry.typ == "keyword":
            return "DOMAIN-KEYWORD", entry.value
        pat = rewrite_regex_without_commas(entry.value) if csv_safe_regex else entry.value
        return "DOMAIN-REGEX", pat
