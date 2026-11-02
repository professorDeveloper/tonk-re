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

import html
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


# Severity -> (emoji, label) for the Markdown report.
_SEV_MD = {"critical": "🟥 CRITICAL", "high": "🟧 HIGH", "medium": "🟨 MEDIUM",
           "low": "🟦 LOW", "info": "⬜ INFO"}


def build_markdown(data: dict, audit: dict | None = None) -> str:
    """Render the full Markdown audit report from gathered analysis data.
    If `audit` (from audit.evaluate) is given, prepend the score, grade and triaged findings."""
    info = data.get("info", {}) or {}
    app = info.get("application", {}) or {}
    generated = data.get("generated") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out: list[str] = []
    w = out.append

    # ---- header ----
    w(f"# Security audit — {info.get('package', data.get('project', '?'))}")
    w("")
    if audit:
        c = audit["counts"]
        w(f"> **Security score: {audit['score']}/100 — grade {audit['grade']}**  ·  "
          f"{c['critical']} critical · {c['high']} high · {c['medium']} medium · "
          f"{c['low']} low · {c['info']} info")
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

    # ---- triaged findings (when an audit was run) ----
    if audit:
        w(f"## Findings ({len(audit['findings'])})")
        w("")
        if audit["findings"]:
            w("| # | Severity | Finding | MASVS |")
            w("|---|---|---|---|")
            for n, f in enumerate(audit["findings"], 1):
                w(f"| {n} | {_SEV_MD[f['severity']]} | {f['title']} | {f['category']} |")
            w("")
            for n, f in enumerate(audit["findings"], 1):
                w(f"### {n}. {f['title']}  — {_SEV_MD[f['severity']]}")
                w("")
                w(f"- **Category:** {f['category']}")
                w(f"- **What:** {f['detail']}")
                w(f"- **Fix:** {f['remediation']}")
                if f.get("evidence"):
                    w("- **Evidence:**")
                    w(_hits(f["evidence"]))
                w("")
        else:
            w("_No rule-based findings._")
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

    # ---- trackers (from the audit) ----
    if audit is not None:
        trackers = audit.get("trackers", [])
        w(f"## Third-party trackers / SDKs ({len(trackers)})")
        w("")
        if trackers:
            w("| SDK | Category | Package |")
            w("|---|---|---|")
            for t in trackers:
                w(f"| {t['name']} | {t['category']} | `{t['package']}` |")
        else:
            w("_None detected (signature-based; absence isn't proof)._")
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


# --------------------------------------------------------------------------- #
# HTML dashboard                                                              #
# --------------------------------------------------------------------------- #

_SEV_COLOR = {"critical": "#ff3b30", "high": "#ff7a18", "medium": "#ffcc00",
              "low": "#2f9bff", "info": "#8a8f98"}

_HTML_CSS = """
:root{--bg:#0b0f0c;--panel:#111713;--line:#20301f;--fg:#8affa0;--hi:#d6ffe0;
  --dim:#5f7a63;--amber:#ffb000}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--hi);
  font:14px/1.55 'IBM Plex Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
a{color:var(--fg)}
.wrap{max-width:980px;margin:0 auto;padding:28px 20px 64px}
.head{display:flex;gap:24px;align-items:center;flex-wrap:wrap;border-bottom:1px solid var(--line);
  padding-bottom:20px;margin-bottom:24px}
.score{position:relative;width:132px;height:132px;flex:0 0 auto}
.score svg{transform:rotate(-90deg)}
.score .num{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;
  justify-content:center}
.score .num b{font-size:30px;color:var(--hi);line-height:1}
.score .num .grade{font-size:15px;color:var(--amber);margin-top:2px}
.score .num small{font-size:11px;color:var(--dim)}
.meta h1{font-size:21px;margin:0 0 6px;color:var(--fg);word-break:break-all}
.meta .kv{color:var(--dim);font-size:12.5px}
.meta .kv b{color:var(--hi);font-weight:600}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0 28px}
.chip{border:1px solid var(--line);border-radius:999px;padding:3px 12px;font-size:12px;color:var(--dim)}
.chip b{color:var(--hi)}
h2{font-size:13px;letter-spacing:.12em;text-transform:uppercase;color:var(--amber);
  border-bottom:1px solid var(--line);padding-bottom:6px;margin:34px 0 14px}
details{background:var(--panel);border:1px solid var(--line);border-left-width:4px;border-radius:6px;
  margin:9px 0;overflow:hidden}
details>summary{cursor:pointer;padding:10px 14px;list-style:none;display:flex;align-items:center;gap:12px}
details>summary::-webkit-details-marker{display:none}
summary .sev{font-size:10.5px;font-weight:700;letter-spacing:.06em;padding:2px 8px;border-radius:4px;
  color:#000;flex:0 0 auto}
summary .t{color:var(--hi);font-weight:600}
summary .cat{margin-left:auto;color:var(--dim);font-size:11.5px;flex:0 0 auto}
.body{padding:2px 16px 14px 16px;border-top:1px solid var(--line)}
.body p{margin:10px 0}
.body .lbl{color:var(--amber);font-size:11px;letter-spacing:.08em;text-transform:uppercase}
pre{background:#0a140c;border:1px solid var(--line);border-radius:5px;padding:9px 11px;overflow:auto;
  font-size:12px;color:var(--fg);margin:6px 0 0;white-space:pre-wrap;word-break:break-word}
table{width:100%;border-collapse:collapse;font-size:12.5px;margin:4px 0}
th,td{border:1px solid var(--line);padding:5px 9px;text-align:left;vertical-align:top;word-break:break-word}
th{background:var(--panel);color:var(--amber);font-weight:600}
tr:hover td{background:#0e1810}
.pill{display:inline-block;font-size:10.5px;padding:1px 7px;border-radius:4px;color:#000;font-weight:700}
.muted{color:var(--dim)}
.flag-bad{color:#ff7a18;font-weight:600}
.flag-ok{color:var(--fg)}
footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);color:var(--dim);font-size:11.5px}
"""


def _e(s) -> str:
    return html.escape("" if s is None else str(s))


def _pre(lines) -> str:
    return "<pre>" + _e("\n".join(lines)) + "</pre>" if lines else ""


def _dash_score_svg(score: int, color: str) -> str:
    # circumference of r=58 circle; dash shows the score fraction.
    c = 2 * 3.14159 * 58
    filled = c * max(0, min(100, score)) / 100
    return (f'<svg width="132" height="132" viewBox="0 0 132 132">'
            f'<circle cx="66" cy="66" r="58" fill="none" stroke="#20301f" stroke-width="10"/>'
            f'<circle cx="66" cy="66" r="58" fill="none" stroke="{color}" stroke-width="10" '
            f'stroke-linecap="round" stroke-dasharray="{filled:.1f} {c:.1f}"/></svg>')


def build_html(data: dict, audit: dict) -> str:
    """Render a self-contained, styled HTML audit dashboard (no external assets)."""
    info = data.get("info", {}) or {}
    app = info.get("application", {}) or {}
    generated = data.get("generated") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    grade = audit.get("grade", "?")
    score = audit.get("score", 0)
    gcolor = {"A": "#2fd36b", "B": "#8affa0", "C": "#ffcc00", "D": "#ff7a18", "F": "#ff3b30"}.get(grade, "#8a8f98")
    o: list[str] = []
    w = o.append

    w("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
    w('<meta name="viewport" content="width=device-width, initial-scale=1">')
    w(f"<title>tonk-re audit — {_e(info.get('package', data.get('project', '')))}</title>")
    w(f"<style>{_HTML_CSS}</style></head><body><div class=\"wrap\">")

    # header: score dial + metadata
    w('<div class="head"><div class="score">')
    w(_dash_score_svg(score, gcolor))
    w(f'<div class="num"><b>{score}</b><span class="grade">GRADE {_e(grade)}</span><small>/ 100</small></div>')
    w('</div><div class="meta">')
    w(f"<h1>{_e(info.get('package', data.get('project', '?')))}</h1>")
    w('<div class="kv">')
    w(f"Version <b>{_e(info.get('versionName', '?'))}</b> ({_e(info.get('versionCode', '?'))}) · "
      f"SDK <b>{_e(info.get('minSdkVersion', '?'))}</b>→<b>{_e(info.get('targetSdkVersion', '?'))}</b>")
    if info.get("frameworks"):
        w(f" · {_e(', '.join(info['frameworks']))}")
    w(f"<br>SHA-256 <b>{_e(data.get('sha256', '?'))}</b>")
    w(f"<br>Generated {_e(generated)} by tonk-re</div></div></div>")

    # severity chips
    c = audit.get("counts", {})
    w('<div class="chips">')
    for sev in ("critical", "high", "medium", "low", "info"):
        w(f'<span class="chip"><span class="pill" style="background:{_SEV_COLOR[sev]}">'
          f'{c.get(sev, 0)}</span> {sev}</span>')
    w(f'<span class="chip"><b>{len(audit.get("trackers", []))}</b> trackers</span></div>')

    # findings
    w(f"<h2>Findings ({len(audit.get('findings', []))})</h2>")
    if audit.get("findings"):
        for f in audit["findings"]:
            col = _SEV_COLOR[f["severity"]]
            w(f'<details style="border-left-color:{col}">')
            w(f'<summary><span class="sev" style="background:{col}">{_e(f["severity"].upper())}</span>'
              f'<span class="t">{_e(f["title"])}</span><span class="cat">{_e(f["category"])}</span></summary>')
            w('<div class="body">')
            w(f'<p><span class="lbl">What</span><br>{_e(f["detail"])}</p>')
            w(f'<p><span class="lbl">Fix</span><br>{_e(f["remediation"])}</p>')
            if f.get("evidence"):
                w(f'<p><span class="lbl">Evidence</span>{_pre(f["evidence"])}</p>')
            w("</div></details>")
    else:
        w('<p class="muted">No rule-based findings.</p>')

    # manifest flags
    w("<h2>Manifest flags</h2><table><tr><th>Flag</th><th>Value</th></tr>")
    for label, val, bad in (("debuggable", app.get("debuggable"), "true"),
                            ("allowBackup", app.get("allowBackup"), "true"),
                            ("usesCleartextTraffic", app.get("usesCleartextTraffic"), "true"),
                            ("networkSecurityConfig", app.get("networkSecurityConfig"), None),
                            ("application", app.get("name"), None)):
        cls = "flag-bad" if (bad and val == bad) else "flag-ok"
        w(f'<tr><td>{_e(label)}</td><td class="{cls}">{_e(val) if val is not None else "-"}</td></tr>')
    w("</table>")

    # exported components
    exported = info.get("exported_components", [])
    w(f"<h2>Exported components ({len(exported)})</h2>")
    if exported:
        w("<table><tr><th>Type</th><th>Component</th><th>Guard</th><th>Schemes</th></tr>")
        for cc in exported:
            guard = (f'<span class="flag-ok">{_e(cc["permission"])}</span>' if cc.get("permission")
                     else '<span class="flag-bad">none (any app)</span>')
            w(f"<tr><td>{_e(cc.get('type'))}</td><td>{_e(cc.get('name'))}</td><td>{guard}</td>"
              f"<td>{_e(', '.join(cc.get('schemes') or []) or '-')}</td></tr>")
        w("</table>")
    else:
        w('<p class="muted">None.</p>')

    # trackers
    trackers = audit.get("trackers", [])
    w(f"<h2>Third-party trackers / SDKs ({len(trackers)})</h2>")
    if trackers:
        w("<table><tr><th>SDK</th><th>Category</th><th>Package</th></tr>")
        for t in trackers:
            w(f"<tr><td>{_e(t['name'])}</td><td>{_e(t['category'])}</td><td>{_e(t['package'])}</td></tr>")
        w("</table>")
    else:
        w('<p class="muted">None detected (signature-based; absence isn\'t proof).</p>')

    # endpoints
    urls = data.get("urls", {}) or {}
    w(f"<h2>Endpoints / URLs ({len(urls)})</h2>")
    if urls:
        shown = sorted(urls.items())[:_MAX_URLS]
        w("<table><tr><th>URL</th><th>Source</th></tr>")
        for u, src in shown:
            w(f"<tr><td>{_e(u)}</td><td class=\"muted\">{_e(src)}</td></tr>")
        w("</table>")
        if len(urls) > _MAX_URLS:
            w(f'<p class="muted">… {len(urls) - _MAX_URLS} more.</p>')
    else:
        w('<p class="muted">None found.</p>')

    # signing
    w("<h2>Signing certificate</h2>")
    signing = data.get("signing")
    w(_pre(signing.strip().splitlines()) if signing and signing.strip()
      else '<p class="muted">Not available (keytool missing, or the APK is unsigned).</p>')

    w('<footer>Generated by <a href="https://github.com/xaldarof/tonk-re">tonk-re</a>. '
      "Heuristic findings — verify each in context. For authorized analysis only.</footer>")
    w("</div></body></html>")
    return "\n".join(o)
