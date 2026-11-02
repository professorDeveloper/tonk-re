"""Audit report generator: render a decompiled app's analysis as a Markdown report.

Pure w.r.t. tonk-re's other modules — the caller (server.py) gathers the structured
analysis (manifest info, secrets, URLs, crypto/security findings, signing cert) and
passes it in; this module only formats. That keeps it unit-testable and free of any
import cycle with the facade (same rule as native.py / patches.py).

Entry point: build_markdown(data) -> str, where `data` is the dict produced by
server.build_report_data(). Hit lists are capped here (not in the scanners) so the
report stays readable; the scanners keep their own, larger caps for interactive use.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

# Permissions worth calling out in the risk summary. Mirrors the UI's DANGER list
# (ui.html) — the report is a different surface (Markdown, offline) so it owns its own
# copy rather than reaching into the front-end.
_DANGEROUS_PERM = re.compile(
    r"(?:READ|WRITE)_(?:SMS|CONTACTS|CALL_LOG|EXTERNAL_STORAGE)|RECORD_AUDIO|CAMERA|"
    r"ACCESS_(?:FINE|BACKGROUND)_LOCATION|SYSTEM_ALERT_WINDOW|BIND_ACCESSIBILITY|"
    r"REQUEST_INSTALL|QUERY_ALL_PACKAGES|MANAGE_EXTERNAL"
)

# How many evidence lines to print per finding group in the report.
_MAX_HITS = 12
_MAX_URLS = 60

# Human labels + whether a hit in this crypto/security group is inherently a concern.
_SECURITY_LABELS = {
    "cipher_usage": "Cipher.getInstance usage",
    "ecb_or_des": "Weak cipher mode (ECB / DES)",
    "insecure_trust": "TLS trust / hostname override",
    "ssl_pinning": "Certificate pinning",
    "webview_js": "WebView JavaScript bridge",
    "dynamic_loading": "Dynamic code / native loading",
    "reflection": "Reflection",
    "root_detection": "Root detection",
    "anti_debug_frida": "Anti-debug / Frida / Xposed detection",
    "exec": "Runtime.exec / ProcessBuilder",
    "raw_sql": "Raw SQL",
    "shared_prefs_world": "World-readable/writable prefs",
}


def _dangerous_perms(perms: list[str]) -> list[str]:
    return [p for p in perms if _DANGEROUS_PERM.search(p or "")]


def _unguarded_exports(info: dict) -> list[dict]:
    """Exported components callable by any app (no permission guard)."""
    return [c for c in info.get("exported_components", []) if not c.get("permission")]


def _risk_rows(data: dict) -> list[tuple[str, bool, str]]:
    """(label, is_risk, detail) rows for the summary table, in priority order."""
    info = data.get("info", {}) or {}
    app = info.get("application", {}) or {}
    secrets, security = data.get("secrets", {}), data.get("security", {})
    unguarded = _unguarded_exports(info)
    danger = _dangerous_perms(info.get("permissions", []))
    weak_crypto = [k for k in ("ecb_or_des", "insecure_trust", "shared_prefs_world") if security.get(k)]
    return [
        ("Debuggable", app.get("debuggable") == "true", "android:debuggable=\"true\""),
        ("Cleartext traffic allowed", app.get("usesCleartextTraffic") == "true",
         "android:usesCleartextTraffic=\"true\""),
        ("Backup allowed", app.get("allowBackup") == "true", "android:allowBackup=\"true\""),
        ("Hard-coded secrets", bool(secrets), f"{sum(len(v) for v in secrets.values())} hit(s) across "
         f"{len(secrets)} pattern(s)"),
        ("Unguarded exported components", bool(unguarded),
         f"{len(unguarded)} component(s) callable by any app"),
        ("Dangerous permissions", bool(danger), ", ".join(p.rsplit('.', 1)[-1] for p in danger) or "-"),
        ("Weak crypto / insecure config", bool(weak_crypto),
         ", ".join(_SECURITY_LABELS[k] for k in weak_crypto) or "-"),
    ]


def _hits(lines: list[str], limit: int = _MAX_HITS) -> str:
    """Render capped 'path:line:text' evidence as a fenced block, noting any overflow."""
    shown = lines[:limit]
    body = "\n".join(shown)
    out = f"```\n{body}\n```"
    if len(lines) > limit:
        out += f"\n_… {len(lines) - limit} more; see the SCAN tab or `search_code`._"
    return out


def build_markdown(data: dict) -> str:
    """Render the full Markdown audit report from gathered analysis data."""
    info = data.get("info", {}) or {}
    app = info.get("application", {}) or {}
    generated = data.get("generated") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out: list[str] = []
    w = out.append

    # ---- header ----
    w(f"# Security audit — {info.get('package', data.get('project', '?'))}")
    w("")
    w(f"- **Project:** `{data.get('project', '?')}`")
    if data.get("apk"):
        w(f"- **APK:** `{data['apk']}`")
    if data.get("sha256"):
        w(f"- **SHA-256:** `{data['sha256']}`")
    w(f"- **Package:** `{info.get('package', '?')}`  **Version:** "
      f"{info.get('versionName', '?')} ({info.get('versionCode', '?')})")
    w(f"- **SDK min/target:** {info.get('minSdkVersion', '?')} / {info.get('targetSdkVersion', '?')}")
    if info.get("frameworks"):
        w(f"- **Frameworks:** {', '.join(info['frameworks'])}")
    w(f"- **Generated:** {generated} by tonk-re")
    w("")

    # ---- risk summary ----
    w("## Risk summary")
    w("")
    w("| Check | Status | Detail |")
    w("|---|---|---|")
    for label, is_risk, detail in _risk_rows(data):
        w(f"| {label} | {'⚠️ RISK' if is_risk else '✅ ok'} | {detail} |")
    w("")

    # ---- manifest / attack surface ----
    w("## Manifest & attack surface")
    w("")
    for key, flag, bad in (("Debuggable", app.get("debuggable"), "true"),
                           ("Allow backup", app.get("allowBackup"), "true"),
                           ("Cleartext traffic", app.get("usesCleartextTraffic"), "true")):
        mark = " ⚠️" if (flag == bad) else ""
        w(f"- **{key}:** `{flag if flag is not None else '-'}`{mark}")
    w(f"- **Network security config:** `{app.get('networkSecurityConfig') or '-'}`")
    w(f"- **Application class:** `{app.get('name') or '-'}`")
    w("")

    exported = info.get("exported_components", [])
    w(f"### Exported components ({len(exported)})")
    w("")
    if exported:
        w("| Type | Component | Guard | Deep-link schemes |")
        w("|---|---|---|---|")
        for c in exported:
            guard = f"`{c['permission']}`" if c.get("permission") else "**none (any app)**"
            schemes = ", ".join(c.get("schemes") or []) or "-"
            w(f"| {c.get('type', '?')} | `{c.get('name', '?')}` | {guard} | {schemes} |")
    else:
        w("_None._")
    w("")

    perms = info.get("permissions", [])
    danger = set(_dangerous_perms(perms))
    w(f"### Permissions ({len(perms)})")
    w("")
    if perms:
        for p in perms:
            w(f"- {'⚠️ ' if p in danger else ''}`{p}`")
    else:
        w("_None._")
    w("")

    libs = info.get("native_libs", [])
    w(f"### Native libraries ({len(libs)})")
    w("")
    if libs:
        for lib in libs:
            w(f"- `{lib}`")
        w("")
        w("_Analyze each with `analyze_native` (arch, JNI entry points, mitigations, strings)._")
    else:
        w("_None._")
    w("")

    # ---- secrets ----
    secrets = data.get("secrets", {})
    total = sum(len(v) for v in secrets.values())
    w(f"## Hard-coded secrets ({total})")
    w("")
    if secrets:
        w("> Regex hits are leads, not confirmed findings — verify each in context before reporting.")
        w("")
        for name, hits in secrets.items():
            w(f"### {name} ({len(hits)})")
            w(_hits(hits))
            w("")
    else:
        w("_No secret patterns matched._")
        w("")

    # ---- urls ----
    urls = data.get("urls", {})
    w(f"## Endpoints / URLs ({len(urls)})")
    w("")
    if urls:
        shown = sorted(urls.items())[:_MAX_URLS]
        for u, src in shown:
            w(f"- `{u}`  — {src}")
        if len(urls) > _MAX_URLS:
            w(f"- _… {len(urls) - _MAX_URLS} more; see `find_urls`._")
    else:
        w("_None found._")
    w("")

    # ---- crypto / security ----
    security = data.get("security", {})
    w(f"## Crypto & security findings ({len(security)} group(s))")
    w("")
    if security:
        for key, hits in security.items():
            w(f"### {_SECURITY_LABELS.get(key, key)} ({len(hits)})")
            w(_hits(hits))
            w("")
    else:
        w("_No matches._")
        w("")

    # ---- signing ----
    w("## Signing certificate")
    w("")
    signing = data.get("signing")
    if signing and signing.strip():
        w("```")
        w(signing.strip())
        w("```")
    else:
        w("_Not available (keytool missing, or the APK is unsigned)._")
    w("")

    # ---- footer ----
    w("---")
    w("")
    w("_Generated by [tonk-re](https://github.com/xaldarof/tonk-re). For authorized analysis only — "
      "audit apps you own or are permitted to test._")
    w("")
    return "\n".join(out)
