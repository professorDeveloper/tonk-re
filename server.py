#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["mcp>=1.2,<2","defusedxml>=0.7"]
# ///
"""tonk-re: APK decompilation + analysis MCP server for Claude Code.

Wraps jadx (Java/Kotlin source) and apktool (resources, manifest, smali),
caches results per APK hash, and exposes analysis tools over MCP.

Run as MCP server:   uv run --script server.py
Run as CLI:          uv run --script server.py cli <command> [args]
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import defusedxml.ElementTree as ET
from mcp.server.fastmcp import FastMCP

sys.path.insert(0, str(Path(__file__).parent))
import tools  # noqa: E402
import native  # noqa: E402  (pure-stdlib ELF/.so analysis)
import patches  # noqa: E402  (manifest + smali patch engine)
import report  # noqa: E402  (Markdown audit-report renderer)

tools.activate()  # managed ~/.tonkre/tools (jadx, apktool, JDK, SDK) onto PATH for every subprocess

WORKSPACE = Path(os.environ.get("TONKRE_HOME", Path.home() / ".tonkre")) / "projects"
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
MAX_OUT = 60_000  # chars returned per tool call, keeps Claude's context sane

mcp = FastMCP("tonk-re")


# ---------- helpers ----------

def _truncate(text: str, limit: int = MAX_OUT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n\n[... truncated {len(text) - limit} chars; narrow your query ...]"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _project_dir(project: str) -> Path:
    """Resolve a project name (as returned by decompile_apk) to its directory."""
    p = (WORKSPACE / project).resolve()
    if WORKSPACE.resolve() not in p.parents or not p.is_dir():
        raise ValueError(f"Unknown project '{project}'. Use list_projects or decompile_apk first.")
    return p


def _safe_join(root: Path, rel: str) -> Path:
    p = (root / rel).resolve()
    if root.resolve() != p and root.resolve() not in p.parents:
        raise ValueError("Path escapes project directory")
    return p


def _run(cmd: list[str], timeout: int = 1800) -> tuple[int, str]:
    cmd = [shutil.which(cmd[0]) or cmd[0], *cmd[1:]]  # Windows needs jadx.bat / apktool.bat resolved
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace")
    return r.returncode, (r.stdout + r.stderr)[-4000:]


def _manifest_root(proj: Path):
    m = proj / "apktool" / "AndroidManifest.xml"
    if not m.exists():
        raise ValueError("Manifest not decoded (apktool output missing)")
    return ET.parse(str(m)).getroot()


def _a(el, name: str):
    return el.get(ANDROID_NS + name)


# ---------- core ----------

def decompile(apk_path: str, force: bool = False, deobf: bool = False) -> dict:
    apk = Path(apk_path).expanduser().resolve()
    if not apk.is_file():
        raise FileNotFoundError(apk)
    digest = _sha256(apk)
    name = f"{re.sub(r'[^A-Za-z0-9_.-]', '_', apk.stem)}-{digest[:10]}"
    proj = WORKSPACE / name
    meta_file = proj / "meta.json"
    if meta_file.exists() and not force:
        return json.loads(meta_file.read_text(encoding="utf-8")) | {"cached": True}

    if proj.exists():
        shutil.rmtree(proj)
    proj.mkdir(parents=True)
    log = {}

    # Handle split bundles (.xapk/.apks/.apkm): extract and decompile base.apk
    target = apk
    if apk.suffix.lower() in {".xapk", ".apks", ".apkm"}:
        with zipfile.ZipFile(apk) as z:
            apks = [n for n in z.namelist() if n.endswith(".apk") and "/" not in n.strip("/")]
            base = next((n for n in apks if n in ("base.apk",) or "base" in n), apks[0] if apks else None)
            if not base:
                raise ValueError("No base APK found inside bundle")
            (proj / "splits").mkdir()
            for n in apks:
                (proj / "splits" / n).write_bytes(z.read(n))
            target = proj / "splits" / base

    jadx_cmd = ["jadx", "-d", str(proj / "jadx"), "--show-bad-code", "-j", str(os.cpu_count() or 4)]
    if deobf:
        jadx_cmd.append("--deobf")
    rc, out = _run(jadx_cmd + [str(target)])
    log["jadx"] = {"rc": rc, "tail": out[-1500:]}

    rc, out = _run(["apktool", "d", "-f", "-o", str(proj / "apktool"), str(target)])
    log["apktool"] = {"rc": rc, "tail": out[-1500:]}

    meta = {
        "project": name,
        "apk": str(apk),
        "sha256": digest,
        "dirs": {"java": str(proj / "jadx" / "sources"), "resources": str(proj / "apktool"),
                 "smali": str(proj / "apktool")},
        "log": log,
    }
    try:
        meta["info"] = info(name, _meta_override=meta)
    except Exception as e:  # manifest decode failures shouldn't kill the run
        meta["info_error"] = str(e)
    meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta | {"cached": False}


def info(project: str, _meta_override: dict | None = None) -> dict:
    proj = WORKSPACE / project if _meta_override else _project_dir(project)
    root = _manifest_root(proj)
    yml = proj / "apktool" / "apktool.yml"
    sdk = {}
    if yml.exists():
        for key in ("minSdkVersion", "targetSdkVersion", "versionCode", "versionName"):
            m = re.search(rf"{key}:\s*'?([^'\n]+)'?", yml.read_text(encoding="utf-8", errors="ignore"))
            if m:
                sdk[key] = m.group(1).strip()

    app = root.find("application")
    comps = {}
    exported = []
    for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
        items = []
        for el in (app.findall(kind) if app is not None else []):
            n = _a(el, "name")
            has_filter = el.find("intent-filter") is not None
            exp = _a(el, "exported")
            is_exp = exp == "true" or (exp is None and has_filter)
            items.append(n)
            if is_exp:
                exported.append({"type": kind, "name": n, "permission": _a(el, "permission"),
                                 "actions": [_a(a, "name") for a in el.iter("action")],
                                 "schemes": sorted({_a(d, "scheme") for d in el.iter("data") if _a(d, "scheme")})})
        comps[kind] = items

    native = sorted({p.relative_to(proj / "apktool").as_posix() for p in (proj / "apktool" / "lib").rglob("*.so")}) \
        if (proj / "apktool" / "lib").exists() else []

    flags = {}
    if app is not None:
        for f in ("debuggable", "allowBackup", "usesCleartextTraffic", "networkSecurityConfig", "name"):
            flags[f] = _a(app, f)

    return {
        "package": root.get("package"),
        **sdk,
        "application": flags,
        "permissions": sorted({_a(p, "name") for p in root.iter("uses-permission")}),
        "custom_permissions": [{"name": _a(p, "name"), "protectionLevel": _a(p, "protectionLevel")}
                               for p in root.findall("permission")],
        "component_counts": {k: len(v) for k, v in comps.items()},
        "exported_components": exported,
        "native_libs": native,
        "frameworks": _detect_frameworks(proj),
    }


def _detect_frameworks(proj: Path) -> list[str]:
    a = proj / "apktool"
    hits = []
    checks = {
        "Flutter": [a / "lib" / "arm64-v8a" / "libflutter.so", a / "assets" / "flutter_assets"],
        "React Native": [a / "assets" / "index.android.bundle"],
        "Xamarin/.NET": [a / "assemblies", a / "lib" / "arm64-v8a" / "libmonodroid.so"],
        "Unity": [a / "lib" / "arm64-v8a" / "libunity.so", a / "assets" / "bin" / "Data"],
        "Cordova/Capacitor": [a / "assets" / "www", a / "assets" / "public"],
        "Kotlin": [a / "kotlin"],
    }
    for fw, paths in checks.items():
        if any(p.exists() for p in paths):
            hits.append(fw)
    return hits


SECRET_PATTERNS = {
    "google_api_key": r"AIza[0-9A-Za-z_\-]{35}",
    "firebase_db": r"https://[a-z0-9\-]+\.firebaseio\.com",
    "aws_access_key": r"(?:AKIA|ASIA)[0-9A-Z]{16}",
    "private_key": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
    "jwt": r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    "slack_token": r"xox[baprs]-[0-9A-Za-z\-]{10,}",
    "stripe_key": r"(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{16,}",
    "github_token": r"gh[pousr]_[A-Za-z0-9]{36,}",
    "generic_secret": r"(?i)(?:api[_-]?key|secret|token|passw(?:or)?d)[\"']?\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']",
}
URL_RE = r"https?://[A-Za-z0-9.\-_~:/?#\[\]@!$&'()*+,;=%]{4,}"


def _grep(root: Path, pattern: str, globs: list[str], max_hits: int, ignore_case: bool = False) -> list[str]:
    rg = shutil.which("rg")
    if rg:
        cmd = [rg, "-n", "--no-heading", "-M", "300", "--max-columns-preview", "-e", pattern]
        if ignore_case:
            cmd.insert(1, "-i")
        for g in globs:
            cmd += ["-g", g]
        cmd.append(str(root))
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300, encoding="utf-8", errors="replace")
        lines = r.stdout.splitlines()
    else:
        rx = re.compile(pattern, re.I if ignore_case else 0)
        lines = []
        inc = [g for g in globs if not g.startswith("!")]
        exc = [g[1:] for g in globs if g.startswith("!")]
        for p in root.rglob("*"):
            if not p.is_file() or (inc and not any(p.match(g) for g in inc)) or any(p.match(g) for g in exc):
                continue
            try:
                for i, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                    if rx.search(line):
                        lines.append(f"{p}:{i}:{line[:300]}")
                        if len(lines) >= max_hits:
                            break
            except OSError:
                continue
    return [_relhit(root, l) for l in lines[:max_hits]]


def _relhit(root: Path, line: str) -> str:
    """'<abs path>:<n>:<text>' -> '<posix rel path>:<n>:<text>' on every OS."""
    prefix = str(root) + os.sep
    if line.startswith(prefix):
        line = line[len(prefix):]
    path, sep, rest = line.partition(":")
    return path.replace("\\", "/") + sep + rest


# ---------- MCP tools ----------

@mcp.tool()
def decompile_apk(apk_path: str, force: bool = False, deobfuscate: bool = False) -> str:
    """Decompile an APK/XAPK/APKS with jadx (Java source) and apktool (manifest, resources, smali).
    Results are cached by SHA-256; returns the project name used by all other tools plus a
    manifest summary (package, SDKs, permissions, exported components, native libs, frameworks).
    Set deobfuscate=true to have jadx rename obfuscated (a.b.c) identifiers."""
    return _truncate(json.dumps(decompile(apk_path, force, deobfuscate), indent=2))


@mcp.tool()
def list_projects() -> str:
    """List previously decompiled APK projects."""
    if not WORKSPACE.exists():
        return "[]"
    out = []
    for m in sorted(WORKSPACE.glob("*/meta.json")):
        d = json.loads(m.read_text(encoding="utf-8"))
        out.append({"project": d["project"], "apk": d["apk"], "package": d.get("info", {}).get("package")})
    return json.dumps(out, indent=2)


@mcp.tool()
def apk_info(project: str) -> str:
    """Manifest-level attack surface summary: permissions, exported components with intent
    actions/deep-link schemes, debuggable/allowBackup/cleartext flags, native libs, frameworks."""
    return _truncate(json.dumps(info(project), indent=2))


@mcp.tool()
def read_manifest(project: str) -> str:
    """Return the decoded AndroidManifest.xml."""
    return _truncate((_project_dir(project) / "apktool" / "AndroidManifest.xml").read_text(encoding="utf-8", errors="ignore"))


@mcp.tool()
def list_classes(project: str, package_prefix: str = "", limit: int = 500) -> str:
    """List decompiled Java classes, optionally filtered by package prefix (e.g. 'com.example.net')."""
    src = _project_dir(project) / "jadx" / "sources"
    prefix = package_prefix.replace(".", "/")
    classes = []
    for p in src.rglob("*.java"):
        rel = p.relative_to(src).as_posix()
        if rel.startswith(prefix):
            classes.append(rel[:-5].replace("/", "."))
    classes.sort()
    head = f"{len(classes)} classes" + (f" (showing {limit})" if len(classes) > limit else "") + "\n"
    return head + "\n".join(classes[:limit])


@mcp.tool()
def package_tree(project: str, depth: int = 3) -> str:
    """Show the package hierarchy with class counts, to orient in a large app."""
    src = _project_dir(project) / "jadx" / "sources"
    counts: dict[str, int] = {}
    for p in src.rglob("*.java"):
        parts = p.relative_to(src).parts[:-1][:depth]
        key = ".".join(parts) or "(default)"
        counts[key] = counts.get(key, 0) + 1
    return "\n".join(f"{n:6d}  {k}" for k, n in sorted(counts.items(), key=lambda x: -x[1]))


@mcp.tool()
def read_class(project: str, class_name: str, start_line: int = 1, max_lines: int = 800) -> str:
    """Read decompiled Java source for a class (fully-qualified, e.g. com.example.MainActivity).
    Inner classes resolve to their outer file."""
    src = _project_dir(project) / "jadx" / "sources"
    rel = class_name.split("$")[0].replace(".", "/") + ".java"
    f = _safe_join(src, rel)
    if not f.exists():
        return f"Not found: {rel}. Try search_code or list_classes."
    lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
    chunk = lines[start_line - 1:start_line - 1 + max_lines]
    footer = f"\n[lines {start_line}-{start_line + len(chunk) - 1} of {len(lines)}]"
    return _truncate("\n".join(f"{i:5d}  {l}" for i, l in enumerate(chunk, start_line)) + footer)


@mcp.tool()
def read_file(project: str, path: str, start_line: int = 1, max_lines: int = 800) -> str:
    """Read any file in the project by relative path, e.g. 'apktool/res/values/strings.xml',
    'apktool/smali/com/x/Y.smali', 'jadx/sources/com/x/Y.java'."""
    f = _safe_join(_project_dir(project), path)
    if not f.is_file():
        return f"Not a file: {path}"
    data = f.read_bytes()
    if b"\x00" in data[:4096]:
        return f"Binary file ({len(data)} bytes). Use REA/native tools for .so/.dex binaries."
    lines = data.decode(errors="ignore").splitlines()
    chunk = lines[start_line - 1:start_line - 1 + max_lines]
    return _truncate("\n".join(chunk) + f"\n[lines {start_line}-{start_line + len(chunk) - 1} of {len(lines)}]")


@mcp.tool()
def search_code(project: str, pattern: str, scope: str = "java", ignore_case: bool = False,
                max_hits: int = 200) -> str:
    """Regex search across the decompiled app. scope: 'java' (jadx sources), 'smali',
    'resources' (res/ + assets/ + manifest), or 'all'."""
    proj = _project_dir(project)
    scopes = {
        "java": (proj / "jadx" / "sources", ["*.java"]),
        "smali": (proj / "apktool", ["*.smali"]),
        "resources": (proj / "apktool", ["!*.smali", "!*.so"]),
        "all": (proj, ["!*.so", "!*.dex"]),
    }
    if scope not in scopes:
        return f"scope must be one of {list(scopes)}"
    root, globs = scopes[scope]
    hits = _grep(root, pattern, globs, max_hits, ignore_case)
    return _truncate(f"{len(hits)} hits\n" + "\n".join(hits)) if hits else "No matches."


# Security-relevant API patterns, shared by the scanner and the report (DRY).
SECURITY_CHECKS = {
    "cipher_usage": r"Cipher\.getInstance\(",
    "ecb_or_des": r"\"(?:AES|DES|DESede)(?:/ECB[^\"]*)?\"",
    "insecure_trust": r"X509TrustManager|checkServerTrusted|ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier",
    "ssl_pinning": r"CertificatePinner|network-security-config|TrustKit|pin-set",
    "webview_js": r"addJavascriptInterface|setJavaScriptEnabled\(true\)|setAllowFileAccess",
    "dynamic_loading": r"DexClassLoader|PathClassLoader|InMemoryDexClassLoader|System\.loadLibrary",
    "reflection": r"Class\.forName\(|getDeclaredMethod\(",
    "root_detection": r"(?i)/system/xbin/su|Superuser\.apk|RootBeer|isRooted|magisk",
    "anti_debug_frida": r"(?i)frida|isDebuggerConnected|TracerPid|xposed",
    "exec": r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder\(",
    "raw_sql": r"rawQuery\(|execSQL\(",
    "shared_prefs_world": r"MODE_WORLD_(?:READABLE|WRITEABLE)",
}
_URL_NOISE = ("schemas.android.com", "www.w3.org", "apache.org/licenses", "xmlpull.org", "ns.adobe.com")


# Data producers — return structured dicts so both the MCP/CLI scanners and the audit
# report build on one implementation (the scanners add their own JSON/text formatting).

def _secrets_data(proj: Path, max_per_type: int = 30) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name, pat in SECRET_PATTERNS.items():
        hits = _grep(proj, pat, ["!*.so", "!*.dex", "!*.png", "!*.jpg", "!*.webp"], max_per_type)
        if hits:
            out[name] = hits
    return out


def _urls_data(proj: Path) -> dict[str, str]:
    """Unique endpoint -> first source file (project-relative), schema/namespace noise filtered."""
    urls: dict[str, str] = {}
    for h in _grep(proj, URL_RE, ["!*.so", "!*.dex", "!*.smali"], 5000):
        for u in re.findall(URL_RE, h):
            u = u.rstrip("\"');,.)")
            if not any(n in u for n in _URL_NOISE) and u not in urls:
                urls[u] = h.split(":", 1)[0]
    return urls


def _security_data(proj: Path) -> dict[str, list[str]]:
    src = proj / "jadx" / "sources"
    out: dict[str, list[str]] = {}
    for k, pat in SECURITY_CHECKS.items():
        # pinning is often declared in res/xml/network_security_config.xml, not code
        root = proj if k == "ssl_pinning" else src
        hits = _grep(root, pat, ["*.java", "*.xml"], 40)
        if hits:
            out[k] = hits
    return out


@mcp.tool()
def find_secrets(project: str, max_per_type: int = 30) -> str:
    """Scan sources, resources and assets for hard-coded credentials (Google/AWS/Stripe/GitHub/
    Slack keys, JWTs, private keys, generic api_key/secret/password assignments)."""
    out = _secrets_data(_project_dir(project), max_per_type)
    return _truncate(json.dumps(out, indent=2)) if out else "No secret patterns matched."


@mcp.tool()
def find_urls(project: str, max_hits: int = 400) -> str:
    """Extract unique URLs/endpoints from code and resources (filters common schema/namespace noise)."""
    urls = _urls_data(_project_dir(project))
    lines = [f"{u}    <- {src}" for u, src in sorted(urls.items())][:max_hits]
    return _truncate(f"{len(urls)} unique URLs\n" + "\n".join(lines))


@mcp.tool()
def find_crypto_and_security(project: str) -> str:
    """Locate security-relevant API usage: crypto (Cipher/ECB/static IVs), TLS trust overrides,
    WebView JS bridges, dynamic code loading, root/emulator/Frida detection, SSL pinning, SQL."""
    out = _security_data(_project_dir(project))
    return _truncate(json.dumps(out, indent=2)) if out else "No matches."


@mcp.tool()
def xrefs(project: str, symbol: str, max_hits: int = 150) -> str:
    """Find references to a class/method/field name in Java sources (word-boundary match)."""
    hits = _grep(_project_dir(project) / "jadx" / "sources", rf"\b{re.escape(symbol)}\b", ["*.java"], max_hits)
    return _truncate(f"{len(hits)} refs\n" + "\n".join(hits)) if hits else "No references."


@mcp.tool()
def signing_info(project: str) -> str:
    """Show the APK signing certificate (subject, issuer, validity, fingerprints) via keytool."""
    apk = json.loads((_project_dir(project) / "meta.json").read_text(encoding="utf-8"))["apk"]
    if not shutil.which("keytool"):
        return "keytool not found (ships with the JDK)."
    _, out = _run(["keytool", "-printcert", "-jarfile", apk], timeout=60)
    return out


# ---------- intent / deep-link tester ----------

def _fqcn(package: str, name: str) -> str:
    """Resolve a manifest component name ('.Foo' / 'Foo' / 'com.x.Foo') to fully-qualified."""
    if not name:
        return name
    if name.startswith("."):
        return package + name
    return name if "." in name else f"{package}.{name}"


def intents(project: str) -> dict:
    """Enumerate launchable adb intents for every exported component and deep link."""
    proj = _project_dir(project)
    root = _manifest_root(proj)
    pkg = root.get("package")
    app = root.find("application")
    am = {"activity": "start", "activity-alias": "start", "service": "start-foreground-service",
          "receiver": "broadcast"}
    comps = []
    for kind in ("activity", "activity-alias", "service", "receiver"):
        for el in (app.findall(kind) if app is not None else []):
            name = _a(el, "name")
            has_filter = el.find("intent-filter") is not None
            exp = _a(el, "exported")
            if not (exp == "true" or (exp is None and has_filter)):
                continue
            comp = f"{pkg}/{name}"  # adb accepts pkg/.Rel directly
            actions = [_a(a, "name") for a in el.iter("action")
                       if _a(a, "name") != "android.intent.action.MAIN"]
            cats = [_a(c, "name") for c in el.iter("category")
                    if _a(c, "name") not in ("android.intent.category.LAUNCHER",
                                             "android.intent.category.DEFAULT")]
            # build deep-link URIs from <data> elements
            links = []
            for d in el.iter("data"):
                scheme, host = _a(d, "scheme"), _a(d, "host")
                path = _a(d, "path") or _a(d, "pathPrefix") or ""
                if scheme:
                    uri = f"{scheme}://{host or 'HOST'}{path}"
                    if uri not in links:
                        links.append(uri)
            comps.append({
                "type": kind, "am_cmd": am[kind], "component": comp,
                "fqcn": _fqcn(pkg, name), "permission": _a(el, "permission"),
                "actions": actions, "categories": cats, "deep_links": links,
                "exploitable_note": ("no-permission; callable by any app" if not _a(el, "permission")
                                     else f"guarded by {_a(el, 'permission')}"),
            })
    return {"package": pkg, "components": comps}


def build_am(kind: str, component: str, action: str = "", data: str = "", categories: list | None = None,
             mime: str = "", extras: list | None = None, flags: list | None = None) -> list[str]:
    """Build the `adb shell am ...` argv for an intent. extras: [{type,key,value}]."""
    sub = {"activity": "start", "activity-alias": "start", "service": "start-foreground-service",
           "receiver": "broadcast"}.get(kind, "start")
    cmd = ["shell", "am", sub, "-n", component]
    if sub == "start":
        cmd += ["-W"]  # wait + print result
    if action:
        cmd += ["-a", action]
    if data:
        cmd += ["-d", data]
    for c in (categories or []):
        cmd += ["-c", c]
    if mime:
        cmd += ["-t", mime]
    opt = {"s": "--es", "string": "--es", "i": "--ei", "int": "--ei", "l": "--el", "long": "--el",
           "z": "--ez", "bool": "--ez", "f": "--ef", "float": "--ef", "uri": "--eu"}
    for e in (extras or []):
        flag = opt.get(str(e.get("type", "s")).lower(), "--es")
        cmd += [flag, str(e["key"]), str(e["value"])]
    cmd += (flags or [])
    return cmd


# ---------- version diff ----------

def _class_set(proj: Path) -> set[str]:
    src = proj / "jadx" / "sources"
    return {p.relative_to(src).as_posix()[:-5].replace("/", ".") for p in src.rglob("*.java")} \
        if src.exists() else set()


def diff_versions(project_a: str, project_b: str, max_items: int = 400) -> dict:
    """Compare two decompiled projects: manifest, permissions, components, classes, URLs."""
    pa, pb = _project_dir(project_a), _project_dir(project_b)
    ia, ib = info(project_a), info(project_b)

    def addrm(a: set, b: set):
        return {"added": sorted(b - a)[:max_items], "removed": sorted(a - b)[:max_items]}

    # changed classes: present in both, different source hash
    ca, cb = _class_set(pa), _class_set(pb)
    changed = []
    srca, srcb = pa / "jadx" / "sources", pb / "jadx" / "sources"
    for cls in sorted(ca & cb):
        rel = cls.replace(".", "/") + ".java"
        fa, fb = srca / rel, srcb / rel
        try:
            if fa.read_bytes() != fb.read_bytes():
                changed.append(cls)
        except OSError:
            pass
        if len(changed) >= max_items:
            break

    exp = lambda i: {f"{c['type']}:{c['name']}" for c in i["exported_components"]}
    urls = lambda p, proj: set(re.findall(URL_RE, "\n".join(_grep(p, URL_RE, ["!*.so", "!*.dex", "!*.smali"], 4000))))
    ua, ub = urls(pa, project_a), urls(pb, project_b)

    return {
        "a": {"project": project_a, "version": f"{ia.get('versionName')} ({ia.get('versionCode')})"},
        "b": {"project": project_b, "version": f"{ib.get('versionName')} ({ib.get('versionCode')})"},
        "sdk": {"a": f"{ia.get('minSdkVersion')}/{ia.get('targetSdkVersion')}",
                "b": f"{ib.get('minSdkVersion')}/{ib.get('targetSdkVersion')}"},
        "permissions": addrm(set(ia["permissions"]), set(ib["permissions"])),
        "exported_components": addrm(exp(ia), exp(ib)),
        "frameworks": addrm(set(ia.get("frameworks", [])), set(ib.get("frameworks", []))),
        "classes": addrm(ca, cb) | {"changed": changed, "changed_count": len(changed)},
        "urls": addrm(ua, ub),
        "flag_changes": {k: [ia["application"].get(k), ib["application"].get(k)]
                         for k in ("debuggable", "allowBackup", "usesCleartextTraffic", "networkSecurityConfig")
                         if ia["application"].get(k) != ib["application"].get(k)},
    }


# ---------- Frida script generator ----------

FRIDA_PRELUDE = """// Generated by tonk-re. Run:  frida -U -f %PKG% -l %FILE% --no-pause
// (attach to a running app instead:  frida -U %PKG% -l %FILE%)
function stringify(v) {
  try { if (v === null || v === undefined) return "" + v;
    if (typeof v === "object") return Java.use("java.util.Objects").toString(v); return "" + v;
  } catch (e) { return "<?>"; }
}
"""


def frida_script(project: str, class_name: str = "", method: str = "", template: str = "trace") -> dict:
    pkg = info(project).get("package", "com.example.app")
    cls = class_name.strip()
    short = cls.rsplit(".", 1)[-1] if cls else "target"

    if template == "ssl_bypass":
        body = _FRIDA_SSL
    elif template == "root_bypass":
        body = _FRIDA_ROOT
    elif not cls:
        body = '  console.log("[!] set a class name for this template");'
    elif template == "trace_class" or not method:
        body = f'''  var C = Java.use("{cls}");
  C.class.getDeclaredMethods().forEach(function (m) {{
    var name = m.getName();
    try {{
      C[name].overloads.forEach(function (ov) {{
        ov.implementation = function () {{
          var a = [].slice.call(arguments);
          console.log("[>] {short}." + name + "(" + a.map(stringify).join(", ") + ")");
          var r = ov.apply(this, arguments);
          console.log("[<] {short}." + name + " => " + stringify(r));
          return r;
        }};
      }});
    }} catch (e) {{}}
  }});
  console.log("[*] hooked all methods of {cls}");'''
    elif template == "return":
        body = f'''  var C = Java.use("{cls}");
  C.{method}.overloads.forEach(function (ov) {{
    ov.implementation = function () {{
      console.log("[!] {short}.{method} forced return (edit the value below)");
      return ov.apply(this, arguments);   // <-- replace with e.g. true / 0 / "str"
    }};
  }});'''
    else:  # trace a single method
        body = f'''  var C = Java.use("{cls}");
  C.{method}.overloads.forEach(function (ov) {{
    ov.implementation = function () {{
      var a = [].slice.call(arguments);
      console.log("[>] {short}.{method}(" + a.map(stringify).join(", ") + ")");
      if ({str(template == 'stacktrace').lower()})
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
      var r = ov.apply(this, arguments);
      console.log("[<] {short}.{method} => " + stringify(r));
      return r;
    }};
  }});'''

    script = FRIDA_PRELUDE + "\nJava.perform(function () {\n" + body + "\n});\n"
    fdir = _project_dir(project) / "frida"
    fdir.mkdir(exist_ok=True)
    fname = f"{template}_{short}.js" if cls else f"{template}.js"
    fpath = fdir / re.sub(r"[^A-Za-z0-9_.]", "_", fname)
    fpath.write_text(script, encoding="utf-8")
    rel = fpath.relative_to(_project_dir(project)).as_posix()
    return {"path": rel, "package": pkg, "script": script,
            "spawn_cmd": f"frida -U -f {pkg} -l {fpath} --no-pause",
            "attach_cmd": f"frida -U {pkg} -l {fpath}"}


_FRIDA_SSL = '''  // Universal-ish SSL pinning bypass (TrustManager + OkHttp CertificatePinner)
  try {
    var TMF = Java.use("javax.net.ssl.TrustManagerFactory");
    var TM = Java.registerClass({name: "com.tonkre.TrustAll",
      implements: [Java.use("javax.net.ssl.X509TrustManager")],
      methods: {checkClientTrusted: function () {}, checkServerTrusted: function () {},
        getAcceptedIssuers: function () { return []; }}});
    var ctx = Java.use("javax.net.ssl.SSLContext");
    ctx.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;",
      "java.security.SecureRandom").implementation = function (k, t, r) {
      this.init(k, [TM.$new()], r); console.log("[*] SSLContext.init bypassed");
    };
  } catch (e) { console.log("[!] TM hook: " + e); }
  try {
    var CP = Java.use("okhttp3.CertificatePinner");
    CP.check.overload("java.lang.String", "java.util.List").implementation = function () {
      console.log("[*] OkHttp CertificatePinner.check bypassed"); };
  } catch (e) {}
  console.log("[*] SSL pinning bypass installed");'''

_FRIDA_ROOT = '''  // Common root-detection bypass
  try {
    var F = Java.use("java.io.File");
    F.exists.implementation = function () {
      var p = this.getAbsolutePath();
      if (/su|magisk|supersu|busybox/i.test(p)) { console.log("[*] hid " + p); return false; }
      return this.exists();
    };
  } catch (e) {}
  try {
    var RT = Java.use("java.lang.Runtime");
    RT.exec.overload("java.lang.String").implementation = function (c) {
      if (/\\bsu\\b|which su/.test(c)) { console.log("[*] blocked exec: " + c);
        return this.exec("echo"); }
      return this.exec(c);
    };
  } catch (e) {}
  console.log("[*] root-detection bypass installed");'''


# ---------- Java <-> smali linking ----------

def smali_paths(project: str, class_name: str) -> list[str]:
    """smali file(s) for a Java class (multidex + inner classes), as project-relative posix paths."""
    proj = _project_dir(project)
    base = class_name.split("$")[0].replace(".", "/")
    found = []
    for d in sorted(proj.glob("apktool/smali*")):
        main = d / (base + ".smali")
        if main.is_file():
            found.append(main)
            found += sorted((d / base).parent.glob(Path(base).name + "$*.smali"))
    return [p.relative_to(proj).as_posix() for p in found]


def counterpart(project: str, path: str) -> dict:
    """Map a java file <-> its smali file(s). Returns the other side's project-relative path(s)."""
    proj = _project_dir(project)
    if path.endswith(".java") and "jadx/sources/" in path:
        cls = path.split("jadx/sources/", 1)[1][:-5].replace("/", ".")
        return {"kind": "smali", "paths": smali_paths(project, cls), "class": cls}
    if path.endswith(".smali"):
        rel = re.sub(r"^apktool/smali[^/]*/", "", path)[:-6]  # strip dir + .smali
        cls = rel.split("$")[0].replace("/", ".")
        jf = proj / "jadx" / "sources" / (rel.split("$")[0] + ".java")
        return {"kind": "java", "paths": [jf.relative_to(proj).as_posix()] if jf.is_file() else [], "class": cls}
    return {"kind": None, "paths": []}


# ---------- MCP tools (extensions) ----------

@mcp.tool()
def list_intents(project: str) -> str:
    """List exported components and deep links as ready-to-run `adb shell am` intents. Use for
    attack-surface testing of activities/services/receivers and scheme://host deep links."""
    return _truncate(json.dumps(intents(project), indent=2))


@mcp.tool()
def diff_apks(project_a: str, project_b: str) -> str:
    """Diff two decompiled versions: version, permissions, exported components, classes (added/
    removed/changed), URLs, frameworks and security-flag changes. Pass two project names."""
    return _truncate(json.dumps(diff_versions(project_a, project_b), indent=2))


@mcp.tool()
def generate_frida_hook(project: str, class_name: str = "", method: str = "", template: str = "trace") -> str:
    """Generate a Frida hook script and save it under the project. templates: 'trace' (log one
    method's args/return), 'trace_class' (all methods of a class), 'stacktrace', 'return' (stub to
    override a return value), 'ssl_bypass', 'root_bypass'. Returns the script and run commands."""
    return _truncate(json.dumps(frida_script(project, class_name, method, template), indent=2))


@mcp.tool()
def smali_for_class(project: str, class_name: str) -> str:
    """Return the smali file path(s) for a Java class (multidex + inner classes). Edit smali, then
    BUILD, to patch app behavior (jadx Java is read-only; apktool rebuilds from smali)."""
    paths = smali_paths(project, class_name)
    return "\n".join(paths) if paths else f"No smali found for {class_name}."


# ---------- native (.so / ELF) analysis ----------

def native_report(project: str, path: str) -> dict:
    """Static ELF analysis of a native lib, extended with a secret scan over its strings."""
    f = _safe_join(_project_dir(project), path)
    if not f.is_file():
        raise ValueError(f"not a file: {path}")
    a = native.analyze_so(f)
    joined = "\n".join(a.get("strings", []) + a.get("urls", []))  # reuse SECRET_PATTERNS (DRY)
    found = {name: sorted(set(re.findall(pat, joined)))[:20]
             for name, pat in SECRET_PATTERNS.items() if re.search(pat, joined)}
    if found:
        a["secrets"] = found
    return a


@mcp.tool()
def analyze_native(project: str, path: str) -> str:
    """Static analysis of a native .so/ELF library: architecture, JNI entry points (Java_*/
    JNI_OnLoad), exported & imported functions, NEEDED libraries, exploit mitigations (NX/RELRO/
    canary/FORTIFY), and URLs/strings. `path` is project-relative, e.g.
    'apktool/lib/arm64-v8a/libfoo.so' (see native_libs from apk_info)."""
    return _truncate(native.format_report(native_report(project, path)))


@mcp.tool()
def decompile_native(project: str, path: str, symbol: str = "") -> str:
    """Pseudo-decompile/disassemble a function in a native .so with radare2 (if installed).
    `symbol` defaults to the entry point; pass a JNI name like 'Java_com_x_A_foo'. If radare2 is
    not installed, returns an install hint instead."""
    f = _safe_join(_project_dir(project), path)
    return _truncate(json.dumps(native.decompile_native(f, symbol), indent=2))


# ---------- one-click / guided patches ----------

@mcp.tool()
def make_interceptable(project: str) -> str:
    """One-click MITM prep: set the app debuggable, add a network-security-config that trusts
    user CA certs, and allow cleartext, so Burp/mitmproxy can intercept TLS. Edits the manifest
    and resources, so rebuild with a FULL apktool BUILD (not the code-only fallback), then SIGN."""
    return _truncate(json.dumps(patches.make_interceptable(_project_dir(project) / "apktool"), indent=2))


@mcp.tool()
def patch_method(project: str, class_name: str, method: str, action: str = "force_true") -> str:
    """Guided smali patch: rewrite every overload of a method to immediately return a constant.
    actions: 'force_true', 'force_false', 'return_zero', 'return_null', 'noop' (void methods).
    Ideal for root/premium/license gates. Then BUILD+SIGN. Static counterpart to a Frida hook."""
    files = [_project_dir(project) / p for p in smali_paths(project, class_name)]
    if not files:
        return f"No smali found for {class_name}."
    return _truncate(json.dumps(patches.patch_method_return(files, method, action), indent=2))


# ---------- audit report ----------

def build_report_data(project: str) -> dict:
    """Gather every analysis the report needs into one structured dict (reuses the scanners)."""
    proj = _project_dir(project)
    meta = json.loads((proj / "meta.json").read_text(encoding="utf-8"))
    data = {
        "project": project,
        "apk": meta.get("apk"),
        "sha256": meta.get("sha256"),
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "info": info(project),
        "secrets": _secrets_data(proj),
        "urls": _urls_data(proj),
        "security": _security_data(proj),
    }
    try:
        data["signing"] = signing_info(project)
    except Exception:  # keytool/APK issues shouldn't sink the whole report
        data["signing"] = None
    return data


def write_report(project: str) -> dict:
    """Render AUDIT.md into the project directory. Returns a summary of what it contains."""
    data = build_report_data(project)
    md = report.build_markdown(data)
    out = _project_dir(project) / "AUDIT.md"
    out.write_text(md, encoding="utf-8")
    return {"path": "AUDIT.md", "bytes": len(md.encode("utf-8")),
            "secret_types": len(data["secrets"]), "urls": len(data["urls"]),
            "security_groups": len(data["security"])}


@mcp.tool()
def export_report(project: str) -> str:
    """Write a Markdown security-audit report (AUDIT.md) into the project, consolidating the
    manifest attack surface, hard-coded secrets, endpoints, crypto/security findings and the
    signing certificate with file:line evidence. Returns the path and a summary. Regex hits are
    leads — verify each in context before relying on them."""
    return _truncate(json.dumps(write_report(project), indent=2))


# ---------- CLI ----------

def cli(argv: list[str]) -> None:
    usage = ("usage: tonkre <decompile APK [--force] [--deobf] | info PROJECT | projects | "
             "search PROJECT REGEX [scope] | secrets PROJECT | urls PROJECT | security PROJECT | "
             "intents PROJECT | diff PROJECT_A PROJECT_B | frida PROJECT [CLASS] [METHOD] [TEMPLATE] | "
             "smali PROJECT CLASS | native PROJECT SO_PATH | mitm PROJECT | "
             "patch PROJECT CLASS METHOD [force_true|force_false|return_zero|return_null|noop] | "
             "report PROJECT | "
             "setup [status|all|COMPONENT...] [--accept-android-license]>")
    if not argv:
        sys.exit(usage)
    cmd, *rest = argv
    if cmd == "setup":
        tools.cli(rest)
    elif cmd == "decompile" and rest:
        r = decompile(rest[0], force="--force" in rest, deobf="--deobf" in rest)
        print(json.dumps(r, indent=2))
    elif cmd == "info" and rest:
        print(apk_info(rest[0]))
    elif cmd == "projects":
        print(list_projects())
    elif cmd == "search" and len(rest) >= 2:
        print(search_code(rest[0], rest[1], rest[2] if len(rest) > 2 else "java"))
    elif cmd == "secrets" and rest:
        print(find_secrets(rest[0]))
    elif cmd == "urls" and rest:
        print(find_urls(rest[0]))
    elif cmd == "security" and rest:
        print(find_crypto_and_security(rest[0]))
    elif cmd == "intents" and rest:
        print(list_intents(rest[0]))
    elif cmd == "diff" and len(rest) >= 2:
        print(diff_apks(rest[0], rest[1]))
    elif cmd == "frida" and rest:
        print(frida_script(rest[0], rest[1] if len(rest) > 1 else "",
                           rest[2] if len(rest) > 2 else "",
                           rest[3] if len(rest) > 3 else "trace")["script"])
    elif cmd == "smali" and len(rest) >= 2:
        print(smali_for_class(rest[0], rest[1]))
    elif cmd == "native" and len(rest) >= 2:
        print(analyze_native(rest[0], rest[1]))
    elif cmd == "mitm" and rest:
        print(make_interceptable(rest[0]))
    elif cmd == "patch" and len(rest) >= 3:
        print(patch_method(rest[0], rest[1], rest[2], rest[3] if len(rest) > 3 else "force_true"))
    elif cmd == "report" and rest:
        print(export_report(rest[0]))
    else:
        sys.exit(usage)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "cli":
        cli(sys.argv[2:])
    else:
        mcp.run()
