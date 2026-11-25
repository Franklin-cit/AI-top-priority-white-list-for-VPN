#!/usr/bin/env python3
"""Optional headless Mihomo runtime 3-way routing verifier for FlClash (.yaml) configs.

Applies lessons from earlier runtime testing safely:
1. Checks that no active local proxy/FlClash TUN is hijacking traffic before testing.
2. Can pre-download geoip.metadb and remote rule-providers WHILE proxy is active (--prepare-env).
3. Disables ONLY tun.enable inside the 'tun:' block (never touches dns.enable or sniffer.enable).
4. Waits for all rule-providers to finish parsing (ruleCount > 0), then runs CONNECT probes
   for --expect-proxy, --expect-direct, and --expect-reject targets (Scheme B defaults included).

Requires a Mihomo binary (mihomo / mihomo.exe) and is specifically for FlClash/Mihomo YAML.
Shadowrocket iOS configs are verified via audit_subscription.py + on-device SR testing.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

DEFAULT_PROXY_PROBES = (
    "chatgpt.com",
    "api.openai.com",
    "claude.ai",
    "gemini.google.com",
    "antigravity.google",
    "aistudio.google.com",
    "generativelanguage.googleapis.com",
    "www.google.com",
    "www.gstatic.com",
    "lh3.googleusercontent.com",
    "muse.ai",
    "www.meta.ai",
    "grok.com",
    "copilot.microsoft.com",
    "perplexity.ai",
    "groq.com",
    "midjourney.com",
    "cursor.com",
    "hatch.metaaivm.com",
    "kimi.ai",
    "moonshot.ai",
    "minimax.io",
    "zoom.us",
    "www.ieee.org",
    "www.alibabacloud.com",
    "api.binance.com",
    "www.okx.com",
    "www.oklink.com",
    "1ms.dog",
    "ipqs.com",
    "api.ipquery.io",
    "ipinfo.io",
    "iplocate.io",
    "p19-oec-general.ttcdn-us.com",
    "tv.apple.com",
    "video-stats.video.google.com",
    "graph.instagram.com",
)
DEFAULT_DIRECT_PROBES = (
    "baidu.com",
    "www.taobao.com",
    "cn.bing.com",
    "www.microsoft.com",
    "ctldl.windowsupdate.com",
    "update.microsoft.com",
    "www.office.com",
    "login.live.com",
    "www.msftconnecttest.com",
    "www.msftncsi.com",
    "aweme.snssdk.com",
    "data.bilibili.com",
    "httpdns.bilivideo.com",
    "dns.weixin.qq.com.cn",
    "www.amazon.cn",
    "amazonaws.cn",
    "yuque.com",
    "www.coolapk.com",
    "www.bbdc.cn",
    "bubei.com.cn",
    "deepseek.com",
    "doubao.com",
    "kimi.com",
    "moonshot.cn",
    "www.minimaxi.com",
    "qwen.ai",
    "yiyan.baidu.com",
    "api.mijia.tech",
    "fp-it.fengkongcloud.com",
    "api-verify.dutils.com",
    "api.open.weshineapp.com",
)
DEFAULT_REJECT_PROBES = (
    "doubleclick.net",
    "doubleclick.com",
    "admob.com",
    "miaozhen.com",
    "googlesyndication.com",
    "adservice.google.com",
    "analytics.google.com",
    "crashlyticsreports-pa.googleapis.com",
    "clientmetrics-pa.googleapis.com",
    "imasdk.googleapis.com",
    "pagead.l.google.com",
    "googlesyndication-cn.com",
    "ipv6.msftconnecttest.com",
    "app-analytics-services.com",
    "app-ads-services.com",
    "sdk.e.qq.com",
    "ios.bugly.qq.com",
    "stun.chat.bilibili.com",
    "oslogs.umeng.com",
    "vc-brain-lf.ndcpp.com",
    "status-ipv6.jpush.cn",
    "api-c.dutils.com",
    "cnlogs.umengcloud.com",
    "dvzqy5r8qco96.v1d.pkoplink.com",
    "browser-intake-datadoghq.com",
    "browser-intake-us5-datadoghq.com",
    "http-intake.logs.us5.datadoghq.com",
    "o33249.ingest.sentry.io",
    "o33249.ingest.us.sentry.io",
    "o1158394.ingest.us.sentry.io",
    "copilot-telemetry-service.githubusercontent.com",
    "copilot-telemetry.githubusercontent.com",
    "openai.qualtrics.com",
    "api.segment.io",
    "cdn.segment.com",
    "api-access.pangolin-sdk-toutiao.com",
    "csjplatform.com",
    "tjdl02.ankltoken.com",
    "orzonera.yingt.fun",
    "applog.zijieapi.com",
    "log.snssdk.com",
    "apmplus.volces.com",
    "unitelogreport.reader.qq.com",
    "dw-online.ksosoft.com",
    "shuc-android.ksord.com",
    "pre-api.miui.security.xiaomi.com",
    "tracking.crazyegg.com",
    "media.ethicalads.io",
    "track.hsadspixel.net",
    "js.hs-analytics.net",
    "collect.wpsmail.net",
)

_LOG_MATCH_RE = re.compile(r"\[TCP\] .+ --> ([^ ]+)(?: \([^)]+\))? match (.+?) using ([^\r\n\"]+)")
_GEOIP_DB_URL = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb"
_ASN_DB_URL = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb"


def _strip_comments_and_quotes(val: str) -> str:
    s = val.split("#", 1)[0].strip()
    return s.strip("\"'")


def extract_provider_urls(yaml_text: str) -> dict[str, tuple[str, str]]:
    """Extract {provider_name: (url, local_rel_path)} from rule-providers block."""
    out: dict[str, tuple[str, str]] = {}
    in_prov = False
    cur_name = ""
    cur_url = ""
    cur_path = ""
    base_indent = -1

    for raw in yaml_text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[0].isspace():
            if in_prov and cur_name and cur_url:
                out[cur_name] = (cur_url, cur_path or f"./ruleset/{cur_name}.yaml")
            in_prov = raw.split(":", 1)[0].strip() == "rule-providers"
            cur_name = ""
            cur_url = ""
            cur_path = ""
            base_indent = -1
            continue
        if not in_prov:
            continue
        indent = len(raw) - len(raw.lstrip())
        s = raw.strip()
        if s.endswith(":") and (base_indent == -1 or indent <= base_indent):
            if cur_name and cur_url:
                out[cur_name] = (cur_url, cur_path or f"./ruleset/{cur_name}.yaml")
            base_indent = indent
            cur_name = s[:-1].strip()
            cur_url = ""
            cur_path = ""
        elif cur_name and s.startswith("url:"):
            cur_url = _strip_comments_and_quotes(s.split(":", 1)[1])
        elif cur_name and s.startswith("path:"):
            cur_path = _strip_comments_and_quotes(s.split(":", 1)[1])

    if in_prov and cur_name and cur_url:
        out[cur_name] = (cur_url, cur_path or f"./ruleset/{cur_name}.yaml")
    return out


def prepare_env(yaml_path: pathlib.Path, env_dir: pathlib.Path, proxy_url: str | None = None) -> int:
    """Pre-download geoip.metadb and all rule-providers while proxy is online."""
    env_dir.mkdir(parents=True, exist_ok=True)
    handlers = []
    if proxy_url:
        handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    opener = urllib.request.build_opener(*handlers)

    def _download(url: str, dest: pathlib.Path) -> None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": "mihomo-verifier/1.0"})
        with opener.open(req, timeout=60) as resp:
            data = resp.read()
        if not data:
            raise ValueError(f"Empty response from {url}")
        dest.write_bytes(data)

    geoip_dest = env_dir / "geoip.metadb"
    print(f"[PREP] Downloading geoip.metadb -> {geoip_dest}")
    _download(_GEOIP_DB_URL, geoip_dest)

    asn_dest = env_dir / "ASN.mmdb"
    print(f"[PREP] Downloading ASN.mmdb -> {asn_dest}")
    try:
        _download(_ASN_DB_URL, asn_dest)
    except Exception as exc:
        print(f"[WARN] Failed to download ASN.mmdb ({exc}); IP-ASN rules may require manual ASN.mmdb placement")

    providers = extract_provider_urls(yaml_path.read_text(encoding="utf-8", errors="replace"))
    print(f"[PREP] Found {len(providers)} remote rule-providers")
    for name, (url, rel_path) in providers.items():
        clean_rel = rel_path.lstrip("./\\")
        dest = env_dir / clean_rel
        print(f"[PREP] {name} -> {dest}")
        _download(url, dest)

    print("[PREP] Environment ready. You may now disconnect active system proxy/TUN before running live verification.")
    return 0


def check_no_active_proxy() -> list[str]:
    """Warn if active local FlClash/Clash processes or system proxy settings could skew tests."""
    warnings: list[str] = []
    if os.name == "nt":
        low = ""
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-Command", "Get-Process flclash* -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName"],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=5,
            )
            low = (proc.stdout or "").lower()
        except (OSError, subprocess.TimeoutExpired):
            try:
                proc = subprocess.run(
                    ["tasklist", "/NH"],
                    capture_output=True,
                    text=True,
                    errors="replace",
                    timeout=3,
                )
                low = (proc.stdout or "").lower()
            except (OSError, subprocess.TimeoutExpired):
                pass
        if "flclash" in low:
            warnings.append("Detected running FlClash.exe / FlClashCore.exe process")
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            )
            enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
            if enable == 1:
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
                warnings.append(f"Windows system proxy is active ({server})")
        except OSError:
            pass
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        if os.environ.get(var):
            warnings.append(
                f"Environment variable {var}={os.environ[var]} is set "
                "(may come from a terminal/sandbox proxy rather than FlClash; unset it in this shell or pass --allow-active-proxy)"
            )
    return warnings


def build_safe_runtime_yaml(src_text: str, test_port: int, ctrl_addr: str, secret: str) -> str:
    """Create minimal-diff headless YAML disabling ONLY tun.enable without touching dns/sniffer."""
    lines = src_text.splitlines()
    out: list[str] = []
    in_tun = False
    tun_found = False
    tun_enable_set = False
    tun_header_idx = -1

    seen_mixed = False
    seen_ctrl = False
    seen_secret = False
    seen_log = False

    for raw in lines:
        stripped = raw.strip()
        if stripped and not raw[0].isspace() and ":" in raw:
            top_key = raw.split(":", 1)[0].strip()
            top_val = _strip_comments_and_quotes(raw.split(":", 1)[1])
            if in_tun and not tun_enable_set and tun_header_idx >= 0:
                out.insert(tun_header_idx + 1, "    enable: false")
                tun_enable_set = True
            in_tun = top_key == "tun"
            if top_key == "tun":
                tun_found = True
                if top_val.startswith("{"):
                    if re.search(r"(?:^|[\s,{])enable\s*:", raw):
                        patched = re.sub(
                            r"((?:^|[\s,{])enable\s*:\s*)(?:true|false)",
                            r"\1false",
                            raw,
                            count=1,
                            flags=re.I,
                        )
                    else:
                        idx = raw.rfind("}")
                        if idx != -1:
                            before = raw[:idx].rstrip()
                            sep = "" if before.endswith("{") else ", "
                            patched = f"{before}{sep}enable: false{raw[idx:]}"
                        else:
                            patched = raw
                    out.append(patched)
                    in_tun = False
                    tun_enable_set = True
                    continue
                out.append(raw)
                tun_header_idx = len(out) - 1
                continue
            if top_key == "mixed-port":
                seen_mixed = True
                out.append(f"mixed-port: {test_port}")
                continue
            if top_key == "external-controller":
                seen_ctrl = True
                out.append(f"external-controller: {ctrl_addr}")
                continue
            if top_key == "secret":
                seen_secret = True
                out.append(f'secret: "{secret}"')
                continue
            if top_key in {"port", "socks-port"} and top_val:
                out.append(f"{top_key}: 0")
                continue
            if top_key == "log-level":
                seen_log = True
                if top_val.lower() in {"info", "debug"}:
                    out.append(raw)
                else:
                    out.append("log-level: info")
                continue
        if in_tun and re.match(r"^\s+enable\s*:", raw):
            indent = raw[: len(raw) - len(raw.lstrip())]
            out.append(f"{indent}enable: false")
            tun_enable_set = True
            continue
        out.append(raw)

    if in_tun and not tun_enable_set and tun_header_idx >= 0:
        out.insert(tun_header_idx + 1, "    enable: false")
        tun_enable_set = True

    tail: list[str] = []
    if not seen_mixed:
        tail.append(f"mixed-port: {test_port}")
    if not seen_log:
        tail.append("log-level: info")
    if not seen_ctrl:
        tail.append(f"external-controller: {ctrl_addr}")
    if not seen_secret:
        tail.append(f'secret: "{secret}"')
    if not tun_found:
        tail.extend(["tun:", "    enable: false"])

    return "\n".join(out + tail) + "\n"


def _http_json(url: str, secret: str, timeout: float = 5.0) -> dict:
    req = urllib.request.Request(url)
    if secret:
        req.add_header("Authorization", f"Bearer {secret}")
    # Never route local loopback Mihomo controller traffic through HTTP_PROXY/HTTPS_PROXY
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _connect_probe(host: str, port: int, timeout: float = 8.0) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
            sock.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
            data = sock.recv(512)
            return data.startswith((b"HTTP/1.1 200", b"HTTP/1.0 200"))
    except OSError:
        return False


def _collect_log_hits(log_path: pathlib.Path) -> dict[str, tuple[str, str]]:
    """Parse Mihomo stdout/stderr log lines for matched TCP routing decisions."""
    hits: dict[str, tuple[str, str]] = {}
    if not log_path.is_file():
        return hits
    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    for m in _LOG_MATCH_RE.finditer(log_text):
        target, rule, outbound = m.groups()
        host = target.rsplit(":", 1)[0].lower()
        hits[host] = (rule.strip(), outbound.strip())
    return hits


def _wait_for_listener_and_hits(
    port: int,
    proc: subprocess.Popen,
    timeout: float = 10.0,
) -> None:
    """Wait until the temporary mixed-port listener accepts TCP connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("Mihomo exited prematurely before proxy port opened")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"Timed out waiting for Mihomo listener on 127.0.0.1:{port}")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _yaml_section_has_enable_true(yaml_text: str, section: str) -> bool:
    """Return True if the specified top-level YAML block contains `enable: true`."""
    in_section = False
    for raw in yaml_text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if not raw[0].isspace() and ":" in raw:
            in_section = raw.split(":", 1)[0].strip() == section
            continue
        if in_section and re.match(r"^\s+enable\s*:\s*true\b", raw):
            return True
    return False


def verify_runtime(
    config_path: pathlib.Path,
    mihomo_bin: str,
    env_dir: pathlib.Path | None = None,
    expect_proxy: list[str] | None = None,
    expect_direct: list[str] | None = None,
    expect_reject: list[str] | None = None,
    allow_active_proxy: bool = False,
) -> int:
    """Run Mihomo -t and live 3-way routing probes."""
    if not shutil.which(mihomo_bin) and not pathlib.Path(mihomo_bin).is_file():
        print(f"[ERROR] Mihomo binary not found: {mihomo_bin}", file=sys.stderr)
        return 2

    if not allow_active_proxy:
        warns = check_no_active_proxy()
        if warns:
            for w in warns:
                print(f"[ERROR] {w}", file=sys.stderr)
            print("[ERROR] Disable active proxy/FlClash or pass --allow-active-proxy to proceed.", file=sys.stderr)
            return 2

    workdir = pathlib.Path(tempfile.mkdtemp(prefix="mihomo_verify_"))
    try:
        if env_dir and env_dir.is_dir():
            for name in ("geoip.metadb", "GeoIP.dat", "geosite.dat", "ASN.mmdb", "ruleset", "rules"):
                src_item = env_dir / name
                if src_item.is_dir():
                    shutil.copytree(src_item, workdir / name, dirs_exist_ok=True)
                elif src_item.is_file():
                    shutil.copy2(src_item, workdir / name)

        src_text = config_path.read_text(encoding="utf-8", errors="replace")
        test_port = _free_port()
        ctrl_port = _free_port()
        ctrl_addr = f"127.0.0.1:{ctrl_port}"
        secret = "verify-runtime-secret"
        runtime_yaml = build_safe_runtime_yaml(src_text, test_port, ctrl_addr, secret)

        # Sanity assert dns.enable and sniffer.enable were NOT accidentally flipped off
        if _yaml_section_has_enable_true(src_text, "dns") and not _yaml_section_has_enable_true(runtime_yaml, "dns"):
            raise RuntimeError("Safety guard tripped: dns.enable: true missing in runtime YAML")
        if _yaml_section_has_enable_true(src_text, "sniffer") and not _yaml_section_has_enable_true(runtime_yaml, "sniffer"):
            raise RuntimeError("Safety guard tripped: sniffer.enable: true missing in runtime YAML")

        runtime_file = workdir / "runtime.yaml"
        runtime_file.write_text(runtime_yaml, encoding="utf-8")

        syntax = subprocess.run(
            [mihomo_bin, "-t", "-f", str(runtime_file), "-d", str(workdir)],
            capture_output=True,
            text=True,
            errors="replace",
        )
        if syntax.returncode != 0:
            print(syntax.stdout)
            print(syntax.stderr, file=sys.stderr)
            raise RuntimeError(f"mihomo -t failed with exit {syntax.returncode}")

        log_path = workdir / "run.log"
        log_fh = log_path.open("w", encoding="utf-8", errors="replace")
        child_env = {
            k: v
            for k, v in os.environ.items()
            if k.lower() not in {"http_proxy", "https_proxy", "all_proxy"}
        }
        proc = subprocess.Popen(
            [mihomo_bin, "-f", str(runtime_file), "-d", str(workdir)],
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            env=child_env,
        )
        try:
            deadline = time.time() + 60.0
            while time.time() < deadline:
                try:
                    provs = _http_json(f"http://{ctrl_addr}/providers/rules", secret)
                    providers = provs.get("providers", {})
                    if not providers or all(v.get("ruleCount", 0) > 0 for v in providers.values()):
                        break
                except Exception:
                    pass
                if proc.poll() is not None:
                    raise RuntimeError("Mihomo exited prematurely during startup")
                time.sleep(0.5)
            else:
                raise RuntimeError("Timed out waiting for rule-providers ruleCount > 0")

            proxies = expect_proxy or list(DEFAULT_PROXY_PROBES)
            directs = expect_direct or list(DEFAULT_DIRECT_PROBES)
            rejects = expect_reject or list(DEFAULT_REJECT_PROBES)
            all_targets = [*proxies, *directs, *rejects]

            _wait_for_listener_and_hits(test_port, proc)
            # Warm up dialer/DNS/selector state before first measured pass
            _connect_probe("www.gstatic.com", test_port, timeout=5.0)
            time.sleep(0.5)

            for host in all_targets:
                _connect_probe(host, test_port)

            def _poll_until_settled(targets: list[str], wait_secs: float = 3.0) -> dict[str, tuple[str, str]]:
                stop_at = time.time() + wait_secs
                latest = _collect_log_hits(log_path)
                while time.time() < stop_at:
                    if all(h.lower() in latest for h in targets):
                        return latest
                    time.sleep(0.25)
                    latest = _collect_log_hits(log_path)
                return latest

            hits = _poll_until_settled(all_targets, wait_secs=3.0)
            retried_ok: set[str] = set()
            for _ in range(2):
                missing = [h for h in all_targets if h.lower() not in hits]
                if not missing:
                    break
                time.sleep(1.5)
                for h in missing:
                    _connect_probe(h, test_port)
                hits = _poll_until_settled(all_targets, wait_secs=3.0)
                for h in missing:
                    if h.lower() in hits:
                        retried_ok.add(h.lower())
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            log_fh.close()

        hits.update(_collect_log_hits(log_path))

        failures = 0
        print(f"{'Category':<8} {'Domain':<42} {'Matched Rule':<34} {'Outbound':<18} Status")
        print("-" * 116)
        for cat, hosts, pred in (
            ("PROXY", proxies, lambda ob: ob not in {"DIRECT", "REJECT", "REJECT-DROP"}),
            ("DIRECT", directs, lambda ob: ob == "DIRECT"),
            ("REJECT", rejects, lambda ob: ob.startswith("REJECT")),
        ):
            for h in hosts:
                hl = h.lower()
                rule, ob = hits.get(hl, ("<not seen>", "<none>"))
                ok = hl in hits and pred(ob)
                if not ok:
                    failures += 1
                    status = "FAIL"
                elif hl in retried_ok:
                    status = "RETRY-OK"
                else:
                    status = "PASS"
                print(f"{cat:<8} {h:<42} {rule[:33]:<34} {ob:<18} {status}")

        if failures:
            fail_dir = pathlib.Path(tempfile.gettempdir()) / "subscription_hardener_last_failed"
            shutil.rmtree(fail_dir, ignore_errors=True)
            shutil.copytree(workdir, fail_dir)
            print(f"\n[FAIL] {failures} probe(s) failed. Preserved artifacts in: {fail_dir}")
            return 1
        print("\n[PASS] All runtime probes matched expected routing.")
        return 0
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    default_env_dir = pathlib.Path(tempfile.gettempdir()) / "flclash_test_env"
    parser = argparse.ArgumentParser(description="Optional Mihomo headless runtime verifier for FlClash YAML.")
    parser.add_argument("--config", type=pathlib.Path, required=True, help="Path to FlClash YAML config")
    parser.add_argument("--prepare-env", action="store_true", help="Pre-download geoip/rule-providers to --env-dir")
    parser.add_argument("--proxy-url", help="Optional proxy URL (e.g. http://127.0.0.1:7890) for --prepare-env")
    parser.add_argument(
        "--env-dir",
        type=pathlib.Path,
        help=f"Cache dir containing geoip.metadb & ruleset/ (defaults to {default_env_dir} if present)",
    )
    parser.add_argument("--mihomo", default="mihomo", help="Path to mihomo binary (default: mihomo on PATH)")
    parser.add_argument("--allow-active-proxy", action="store_true", help="Skip active proxy guard check")
    parser.add_argument("--expect-proxy", nargs="*", help="Override expected PROXY domains")
    parser.add_argument("--expect-direct", nargs="*", help="Override expected DIRECT domains")
    parser.add_argument("--expect-reject", nargs="*", help="Override expected REJECT domains")
    args = parser.parse_args(argv)

    if not args.config.is_file():
        print(f"[ERROR] Config not found: {args.config}", file=sys.stderr)
        return 2

    if args.prepare_env:
        target_dir = args.env_dir or default_env_dir
        return prepare_env(args.config, target_dir, proxy_url=args.proxy_url)

    effective_env_dir = args.env_dir or (default_env_dir if default_env_dir.is_dir() else None)
    return verify_runtime(
        config_path=args.config,
        mihomo_bin=args.mihomo,
        env_dir=effective_env_dir,
        expect_proxy=args.expect_proxy,
        expect_direct=args.expect_direct,
        expect_reject=args.expect_reject,
        allow_active_proxy=args.allow_active_proxy,
    )


if __name__ == "__main__":
    raise SystemExit(main())
