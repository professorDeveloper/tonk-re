"""Static patch engine: manifest + smali rewrites applied to a decompiled apktool tree.

Two families, both of which land as on-disk edits the user then rebuilds with BUILD+SIGN:

  * make_interceptable()  -- the standard Burp/mitmproxy prep: debuggable + a
    network_security_config that trusts user CAs + cleartext allowed.
  * guided_patch()        -- method-level smali rewrites: force a method to return
    true / false / 0 / null, or no-op a void method. The static counterpart to the
    Frida generator (good for root/premium/license checks that gate on a boolean).

These functions are pure w.r.t. tonk-re's other modules: callers pass in the paths
(the apktool dir, or the resolved smali files), so the engine stays unit-testable and
has no import cycle with server.py. Edits to the manifest/resources need a FULL apktool
rebuild — the code-only dex-swap fallback keeps the original resources, so it will NOT
include a MITM patch. guided_patch (smali only) works with either build path.
"""
from __future__ import annotations

import re
from pathlib import Path

NSC_XML = """<?xml version="1.0" encoding="utf-8"?>
<!-- Added by tonk-re "make interceptable": trust user-installed CAs (Burp / mitmproxy). -->
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
"""

GUIDED_ACTIONS = ("force_true", "force_false", "return_zero", "return_null", "noop")

# return descriptor from a .method signature, e.g. "...isRooted()Z" -> "Z", "...get()Ljava/lang/String;" -> "L..;"
_RET_RE = re.compile(r"\([^)]*\)(\[*(?:[VZBSCIJFD]|L[^;]+;))\s*$")


# ---------- manifest: make interceptable (MITM) ----------

def _upsert_attr(tag_attrs: str, attr: str, value: str) -> str:
    """Set android:<attr>="value" inside an opening-tag attribute string (replace or append)."""
    pat = re.compile(rf'\s{re.escape(attr)}="[^"]*"')
    repl = f' {attr}="{value}"'
    return pat.sub(repl, tag_attrs) if pat.search(tag_attrs) else tag_attrs + repl


def make_interceptable(apktool_dir: Path) -> dict:
    """Edit the manifest + add a network-security-config so the app trusts user CA certs.
    Returns a summary of what changed. Needs a full apktool rebuild to take effect."""
    manifest = apktool_dir / "AndroidManifest.xml"
    if not manifest.is_file():
        raise ValueError("AndroidManifest.xml not found (decode with apktool first)")
    text = manifest.read_text(encoding="utf-8", errors="ignore")

    m = re.search(r"(<application\b)(.*?)(/?>)", text, re.DOTALL)
    if not m:
        raise ValueError("no <application> element in the manifest")
    head, attrs, close = m.groups()
    changes, before = [], attrs
    existing = re.search(r'networkSecurityConfig="([^"]*)"', attrs)
    if existing and existing.group(1) != "@xml/network_security_config":
        changes.append(f"replaced existing networkSecurityConfig ({existing.group(1)})")
    attrs = _upsert_attr(attrs, "android:debuggable", "true")
    attrs = _upsert_attr(attrs, "android:usesCleartextTraffic", "true")
    attrs = _upsert_attr(attrs, "android:networkSecurityConfig", "@xml/network_security_config")
    if attrs != before:
        text = text[:m.start()] + head + attrs + close + text[m.end():]
        manifest.write_text(text, encoding="utf-8", newline="")
        changes = ["android:debuggable=true", "android:usesCleartextTraffic=true",
                   "android:networkSecurityConfig=@xml/network_security_config"] + changes

    nsc = apktool_dir / "res" / "xml" / "network_security_config.xml"
    nsc.parent.mkdir(parents=True, exist_ok=True)
    nsc.write_text(NSC_XML, encoding="utf-8", newline="")

    return {
        "op": "make_interceptable",
        "changes": changes,
        "files_written": ["AndroidManifest.xml", "res/xml/network_security_config.xml"],
        "requires_full_build": True,
        "next": "BUILD+SIGN with apktool 3.x (the code-only build keeps the ORIGINAL manifest/resources, "
                "so it will NOT include this patch), install, then point your device proxy at Burp/mitmproxy.",
    }


# ---------- smali: guided method-return patches ----------

def _return_body(ret: str, value) -> tuple[int, list[str]]:
    """(.locals count, body instruction lines) for forcing a method's return value."""
    if ret == "V":
        return 0, ["return-void"]
    if ret == "J":  # long (wide)
        n = int(value) if str(value).lstrip("-").isdigit() else 0
        return 2, [f"const-wide v0, {hex(n & 0xFFFFFFFFFFFFFFFF)}", "return-wide v0"]
    if ret == "D":  # double
        return 2, ["const-wide v0, 0x0", "return-wide v0"]
    if ret == "F":  # float
        return 1, ["const v0, 0x0", "return v0"]
    if ret.startswith("L") or ret.startswith("["):  # object / array -> null only
        return 1, ["const/4 v0, 0x0", "return-object v0"]
    # int family: Z B S C I
    if str(value).lower() in ("true", "1"):
        n = 1
    elif str(value).lower() in ("false", "0", "null", ""):
        n = 0
    else:
        n = int(value)
    if n in (0, 1):
        return 1, [f"const/4 v0, {hex(n)}", "return v0"]
    return 1, [f"const v0, {hex(n & 0xFFFFFFFF)}", "return v0"]


def _value_for(action: str, ret: str):
    if action == "force_true":
        return "true"
    if action == "force_false":
        return "false"
    if action == "return_zero":
        return 0
    return 0  # return_null / noop -> 0 (null for objects, 0 for primitives, return-void for V)


def patch_method_return(smali_files: list[Path], method: str, action: str = "force_true") -> dict:
    """Rewrite every overload of `method` in the given smali files to immediately return a
    constant (per `action`). Skips native/abstract methods (no body to replace)."""
    if action not in GUIDED_ACTIONS:
        raise ValueError(f"action must be one of {GUIDED_ACTIONS}")
    patched, skipped = [], []
    for sf in smali_files:
        sf = Path(sf)
        if not sf.is_file():
            continue
        lines = sf.read_text(encoding="utf-8", errors="ignore").splitlines()
        out, i, changed = [], 0, False
        start_re = re.compile(rf"^\s*\.method\b.*\b{re.escape(method)}\s*\(")
        while i < len(lines):
            line = lines[i]
            if start_re.search(line):
                # find the end of this method
                j = i + 1
                while j < len(lines) and not lines[j].strip().startswith(".end method"):
                    j += 1
                mod = line
                rm = _RET_RE.search(line.strip())
                if (" native " in f" {mod} ") or (" abstract " in f" {mod} ") or not rm:
                    skipped.append(f"{sf.name}:{method} (native/abstract or unparsable return)")
                    out.extend(lines[i:j + 1])
                else:
                    ret = rm.group(1)
                    if action == "noop" and ret != "V":
                        # "neutralize" a non-void method == return a default
                        locals_n, body = _return_body(ret, _value_for("return_zero", ret))
                    else:
                        locals_n, body = _return_body(ret, _value_for(action, ret))
                    out.append(line)
                    out.append(f"    .locals {locals_n}")
                    out += [f"    {b}" for b in body]
                    out.append(".end method")
                    patched.append(f"{sf.name}::{method}(){ret}  ->  {' '.join(body)}")
                    changed = True
                i = j + 1
                continue
            out.append(line)
            i += 1
        if changed:
            sf.write_text("\n".join(out) + "\n", encoding="utf-8", newline="")
    return {
        "op": "guided_patch",
        "action": action,
        "method": method,
        "patched": patched,
        "skipped": skipped,
        "count": len(patched),
        "next": "BUILD+SIGN, then install. (Smali-only patch: works with the full or code-only build.)"
                if patched else "no matching method found — check the class/method name.",
    }
