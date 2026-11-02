"""Security audit engine: turn tonk-re's raw analysis into scored, triaged findings.

Pure leaf module (stdlib only, no server/gui import, same rule as native.py /
patches.py / report.py). The caller (server.py) gathers the data — the manifest
`info`, the secret / URL / crypto-security scan dicts and the class list — and passes
it in; this module evaluates a fixed rule set and returns findings tagged with a
severity, an OWASP MASVS category and a remediation hint, plus an overall score/grade
and the detected trackers. report.py renders the result (Markdown + HTML); nothing
here formats or does I/O.

Findings are heuristic: a regex/manifest signal, not a proven exploit. Severities rank
the *lead*, and every finding points back to the evidence so a human can confirm it.
"""
from __future__ import annotations

import re

# Severity order (worst first) and the score penalty each point costs.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Permissions worth flagging as privacy-sensitive (kept in sync with report.py / the UI).
_DANGEROUS_PERM = re.compile(
    r"(?:READ|WRITE)_(?:SMS|CONTACTS|CALL_LOG|EXTERNAL_STORAGE)|RECORD_AUDIO|CAMERA|"
    r"ACCESS_(?:FINE|BACKGROUND)_LOCATION|SYSTEM_ALERT_WINDOW|BIND_ACCESSIBILITY|"
    r"REQUEST_INSTALL|QUERY_ALL_PACKAGES|MANAGE_EXTERNAL|READ_PHONE_STATE"
)

# Third-party SDK / tracker signatures, matched against the app's class package paths.
# {display name: (category, [package prefixes])}. Exodus-style; extend freely.
TRACKER_SIGNATURES: dict[str, tuple[str, list[str]]] = {
    "Google AdMob": ("ads", ["com.google.android.gms.ads"]),
    "Google Firebase Analytics": ("analytics", ["com.google.firebase.analytics",
                                                 "com.google.android.gms.measurement"]),
    "Google Crashlytics": ("crash", ["com.google.firebase.crashlytics", "com.crashlytics"]),
    "Google Tag Manager": ("analytics", ["com.google.android.gms.tagmanager"]),
    "Facebook (Meta) SDK": ("analytics", ["com.facebook.appevents", "com.facebook.internal",
                                          "com.facebook.login"]),
    "Facebook Audience Network": ("ads", ["com.facebook.ads"]),
    "AppsFlyer": ("attribution", ["com.appsflyer"]),
    "Adjust": ("attribution", ["com.adjust.sdk"]),
    "Branch": ("attribution", ["io.branch"]),
    "Kochava": ("attribution", ["com.kochava"]),
    "Singular": ("attribution", ["com.singular.sdk"]),
    "Flurry": ("analytics", ["com.flurry"]),
    "Mixpanel": ("analytics", ["com.mixpanel"]),
    "Amplitude": ("analytics", ["com.amplitude"]),
    "Segment": ("analytics", ["com.segment.analytics"]),
    "Yandex Metrica": ("analytics", ["com.yandex.metrica", "io.appmetrica"]),
    "Umeng": ("analytics", ["com.umeng"]),
    "Localytics": ("analytics", ["com.localytics"]),
    "Leanplum": ("analytics", ["com.leanplum"]),
    "Sentry": ("crash", ["io.sentry"]),
    "Bugsnag": ("crash", ["com.bugsnag"]),
    "Microsoft App Center": ("crash", ["com.microsoft.appcenter"]),
    "OneSignal": ("push", ["com.onesignal"]),
    "Braze (Appboy)": ("push", ["com.appboy", "com.braze"]),
    "Unity Ads": ("ads", ["com.unity3d.ads", "com.unity3d.services"]),
    "AppLovin": ("ads", ["com.applovin"]),
    "ironSource": ("ads", ["com.ironsource"]),
    "Vungle": ("ads", ["com.vungle"]),
    "Chartboost": ("ads", ["com.chartboost"]),
    "InMobi": ("ads", ["com.inmobi"]),
    "MoPub": ("ads", ["com.mopub"]),
    "Pangle / ByteDance": ("ads", ["com.bytedance.sdk", "com.bykv.vk", "com.pangle"]),
    "Tapjoy": ("ads", ["com.tapjoy"]),
    "Smaato": ("ads", ["com.smaato"]),
    "Fyber": ("ads", ["com.fyber"]),
    "Huawei HMS": ("analytics", ["com.huawei.hms"]),
}


def detect_trackers(classes: list[str]) -> list[dict]:
    """Match tracker/SDK signatures against decompiled class package paths.
    `classes` is a list of fully-qualified class names (e.g. com.foo.Bar)."""
    found = []
    for name, (category, prefixes) in TRACKER_SIGNATURES.items():
        hit = next((c for c in classes if any(c == p or c.startswith(p + ".") for p in prefixes)), None)
        if hit:
            matched = next(p for p in prefixes if hit == p or hit.startswith(p + "."))
            found.append({"name": name, "category": category, "package": matched})
    return sorted(found, key=lambda t: (t["category"], t["name"]))


def _finding(fid, title, severity, category, detail, remediation, evidence=None):
    return {"id": fid, "title": title, "severity": severity, "category": category,
            "detail": detail, "remediation": remediation, "evidence": evidence or []}


# Per-severity score penalty (summed, then clamped). Tuned so one critical ≈ fail.
_PENALTY = {"critical": 40, "high": 15, "medium": 8, "low": 3, "info": 0}


def evaluate(data: dict, trackers: list[dict] | None = None) -> dict:
    """Run the rule set over gathered analysis. Returns findings (worst-first), the
    detected trackers, a 0–100 score and a letter grade."""
    info = data.get("info", {}) or {}
    app = info.get("application", {}) or {}
    secrets = data.get("secrets", {}) or {}
    security = data.get("security", {}) or {}
    trackers = trackers if trackers is not None else []
    findings: list[dict] = []

    # --- MASVS-CODE / RESILIENCE: build & platform config ---
    if app.get("debuggable") == "true":
        findings.append(_finding(
            "debuggable", "App is debuggable", "high", "MASVS-RESILIENCE",
            "android:debuggable=\"true\" ships a debuggable build — any user can attach a debugger "
            "and read/modify runtime state.",
            "Remove android:debuggable or set it to false for release builds.",
            ["AndroidManifest.xml: <application android:debuggable=\"true\">"]))

    # --- MASVS-NETWORK: transport security ---
    if app.get("usesCleartextTraffic") == "true":
        findings.append(_finding(
            "cleartext", "Cleartext (HTTP) traffic allowed", "medium", "MASVS-NETWORK",
            "android:usesCleartextTraffic=\"true\" permits unencrypted HTTP, exposing traffic to "
            "interception and tampering on hostile networks.",
            "Disable cleartext and use HTTPS; restrict exceptions in a network-security-config.",
            ["AndroidManifest.xml: usesCleartextTraffic=\"true\""]))
    if security.get("insecure_trust"):
        findings.append(_finding(
            "trust_override", "Custom TLS trust / hostname verification", "high", "MASVS-NETWORK",
            "Custom X509TrustManager / hostname verifier code can disable certificate validation, "
            "enabling trivial MITM.",
            "Remove permissive trust managers; pin or rely on the platform trust store.",
            security["insecure_trust"][:6]))

    # --- MASVS-CRYPTO ---
    if security.get("ecb_or_des"):
        findings.append(_finding(
            "weak_crypto", "Weak cipher mode / algorithm (ECB / DES)", "high", "MASVS-CRYPTO",
            "ECB mode leaks plaintext structure; DES/DESede are broken. ",
            "Use AES-GCM (or AES-CBC with HMAC) and a random IV per message.",
            security["ecb_or_des"][:6]))

    # --- MASVS-STORAGE ---
    if secrets:
        total = sum(len(v) for v in secrets.values())
        ev = [h for hits in secrets.values() for h in hits][:6]
        findings.append(_finding(
            "secrets", f"Hard-coded secrets ({total} hit{'s' if total != 1 else ''})", "high",
            "MASVS-STORAGE",
            f"Potential credentials embedded in the app across {len(secrets)} pattern(s) "
            f"({', '.join(secrets)}). Anyone can extract them from the APK.",
            "Move secrets server-side; rotate anything exposed; never ship API keys in the binary.",
            ev))
    if app.get("allowBackup") == "true":
        findings.append(_finding(
            "allow_backup", "Backups allowed (allowBackup)", "low", "MASVS-STORAGE",
            "android:allowBackup=\"true\" lets `adb backup` pull the app's private data off a device.",
            "Set android:allowBackup=\"false\" or define a strict backup rules set.",
            ["AndroidManifest.xml: allowBackup=\"true\""]))
    if security.get("shared_prefs_world"):
        findings.append(_finding(
            "world_prefs", "World-readable/writable storage", "medium", "MASVS-STORAGE",
            "MODE_WORLD_READABLE/WRITEABLE exposes files to other apps.",
            "Use MODE_PRIVATE; share via a guarded ContentProvider or FileProvider.",
            security["shared_prefs_world"][:6]))

    # --- MASVS-PLATFORM: exported attack surface ---
    unguarded = [c for c in info.get("exported_components", []) if not c.get("permission")]
    if unguarded:
        ev = [f"{c.get('type')}: {c.get('name')}" for c in unguarded][:8]
        sev = "high" if len(unguarded) >= 5 else "medium"
        findings.append(_finding(
            "exported", f"Unguarded exported components ({len(unguarded)})", sev, "MASVS-PLATFORM",
            "Exported activities/services/receivers/providers with no permission are callable by any "
            "installed app — a common entry point for intent-based attacks.",
            "Add android:exported=\"false\" where external access isn't needed, or guard with a "
            "signature-level permission; validate all incoming intent data.",
            ev))
    if security.get("webview_js"):
        findings.append(_finding(
            "webview_js", "WebView JavaScript bridge", "medium", "MASVS-PLATFORM",
            "addJavascriptInterface / JS enabled can expose native methods to loaded web content "
            "(RCE risk if content isn't fully trusted).",
            "Avoid addJavascriptInterface with untrusted content; restrict file access; use "
            "@JavascriptInterface narrowly on API 17+.",
            security["webview_js"][:6]))

    # --- MASVS-CODE: dynamic loading ---
    if security.get("dynamic_loading"):
        findings.append(_finding(
            "dynamic_loading", "Dynamic code loading", "low", "MASVS-CODE",
            "DexClassLoader / loadLibrary can run code fetched at runtime; verify its integrity and "
            "origin.",
            "Load only bundled, integrity-checked code; avoid loading from external storage.",
            security["dynamic_loading"][:4]))

    # --- MASVS-PRIVACY: trackers & dangerous permissions ---
    if trackers:
        cats = sorted({t["category"] for t in trackers})
        findings.append(_finding(
            "trackers", f"Third-party trackers / SDKs ({len(trackers)})", "info", "MASVS-PRIVACY",
            f"Bundled SDKs across: {', '.join(cats)}. Relevant to a privacy review and data-sharing "
            "disclosures.",
            "Confirm each SDK is needed and disclosed in your privacy policy / data-safety form.",
            [f"{t['name']} ({t['category']}) — {t['package']}" for t in trackers][:12]))
    danger = [p for p in info.get("permissions", []) if _DANGEROUS_PERM.search(p or "")]
    if danger:
        findings.append(_finding(
            "dangerous_perms", f"Privacy-sensitive permissions ({len(danger)})", "info",
            "MASVS-PRIVACY",
            "The app requests permissions that access personal data or powerful device capabilities.",
            "Request only what's required; prefer scoped/one-time access; justify each at review.",
            [p.rsplit(".", 1)[-1] for p in danger]))

    findings.sort(key=lambda f: (_RANK[f["severity"]], f["id"]))

    # Score: start at 100, subtract penalties, clamp to [0, 100].
    score = max(0, 100 - sum(_PENALTY[f["severity"]] for f in findings))
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 \
        else "D" if score >= 60 else "F"
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
    return {"score": score, "grade": grade, "counts": counts,
            "findings": findings, "trackers": trackers}
