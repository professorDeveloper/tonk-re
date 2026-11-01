---
name: tonk-re
description: Decompile and reverse engineer Android APK/XAPK/APKS files with the tonk-re MCP tools (jadx + apktool). Use when the user gives an .apk or asks to analyze, audit, or understand an Android app.
---

# APK reverse engineering workflow

Tools come from the `tonk-re` MCP server (`mcp__tonk-re__*`).

1. **Decompile**: `decompile_apk(apk_path)` (cached by SHA-256). Keep the returned `project` name.
   Use `deobfuscate=true` if class names look like `a.b.c`.
2. **Orient**: review the manifest summary, then `package_tree` to separate app code from libraries
   (androidx, kotlin, okhttp, com.google are usually noise).
3. **Attack surface**: `apk_info` → exported components, deep-link schemes, debuggable/allowBackup/
   cleartext flags. Read handlers for every exported component with `read_class`.
4. **Sweeps**: `find_secrets`, `find_urls`, `find_crypto_and_security`. Confirm every hit by reading
   the surrounding code; regex hits are leads, not findings.
5. **Dig in**: `search_code` (scopes: java/smali/resources/all), `xrefs`, `read_class`, `read_file`.
   When jadx output is broken (`/* JADX WARNING */`), read the smali at `apktool/smali*/...`.
6. **Test the surface**: `list_intents` turns exported components and deep links into `adb am`
   commands; for a risky handler, `generate_frida_hook(project, class, method)` makes a runtime trace.
7. **Patch**: `smali_for_class` maps a Java class to its smali for manual edits. For common gates use
   `patch_method(project, class, method, action)` — `force_true` / `force_false` / `return_zero` /
   `return_null` / `noop` rewrites the method to return a constant (root/premium/license checks).
   For MITM, `make_interceptable(project)` sets debuggable + a user-CA network-security-config.
   Both land as on-disk edits; the user then BUILDs + SIGNs (manifest/resource edits need a full
   apktool build, not the code-only fallback).
8. **Compare versions**: `diff_apks(project_a, project_b)` for permission/component/class/URL deltas.
9. **Native / non-Java**: for `.so` libraries use `analyze_native(project, so_path)` (arch, JNI
   entry points, exports/imports, NEEDED libs, exploit mitigations, URLs/strings) and
   `decompile_native(project, so_path, symbol)` for radare2 pseudo-code when installed. React Native
   (`assets/index.android.bundle`) and Flutter Dart snapshots still need `read_file` / other tools.
10. **Report**: package, SDKs, frameworks, attack surface, confirmed findings with
   `file:line` evidence and severity, and open questions.

Analyze only apps the user owns or is authorized to test.
