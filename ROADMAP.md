# TONK-RE Roadmap

Planned and proposed features, grouped by impact. Not committed to dates — a backlog to pull from.
Contributions welcome; open an issue to claim one.

## Shipped

- Decompile `.apk/.xapk/.apks/.apkm` (jadx + apktool)
- Manifest attack-surface summary (exported components, deep links, permissions, flags, native libs, framework detection)
- Secret / URL / crypto-security scanners, regex search (java/smali/resources)
- Syntax-highlighted editor, Java ⇄ smali bridge
- Rebuild & sign (apktool / zipalign / apksigner), with code-only build fallback when resource re-linking fails
- `RESIGN APK`, `INSTALL ▸ ADB`
- Deep-link / intent tester (exported components + deep links as `adb am` commands)
- Version diff (permissions / components / classes / URLs / flags)
- Frida hook generator (trace / stacktrace / return-override / SSL & root bypass)
- **Native `.so` analysis** — pure-stdlib ELF parser: arch, JNI entry points, exports/imports, NEEDED libs, exploit mitigations (NX/RELRO/canary/FORTIFY), URLs/strings + secret scan; shown read-only in the editor. Optional radare2 pseudo-code backend (`decompile_native`).
- **One-click "Make interceptable" (MITM) patch** — debuggable + a `network_security_config` trusting user CA certs + cleartext, via the `[ PATCH ▾ ]` menu (`make_interceptable`).
- **Guided smali patches** — right-click a method → force return true/false, return null/0, no-op → smali rewrite, then BUILD (`patch_method`). Static counterpart to the Frida generator.
- **Editor method menu** — right-click a Java/smali method for Frida (trace / override return), "ask Claude for a Frida hook", and the guided smali patches above.
- **Scored security audit** — `security_audit` (MCP) / `tonkre audit` evaluates the manifest, secrets, crypto/security scans and detected trackers into triaged findings (severity + OWASP MASVS category + remediation) with a 0–100 score and letter grade (engine: `audit.py`).
- **Tracker / SDK detection** — signature table (`audit.TRACKER_SIGNATURES`, ~35 ad/analytics/crash/attribution/push SDKs) matched against class package paths; surfaced in the audit + report.
- **Report export** — one-click `[ AUDIT ↯ ]` (and `export_report` / `tonkre report`) writes `AUDIT.md` **and** a styled, self-contained `AUDIT.html` dashboard (score dial, severity chips, collapsible findings) into the project, shown in an in-app iframe. Consolidates the scored findings, manifest attack surface, secrets, endpoints, trackers, crypto/security and the signing cert with file:line evidence.
- **Resource viewer** — click a drawable/icon (`png/jpg/webp/gif/bmp/ico`) to render it instead of raw bytes; `[ TABLE ▦ ]` renders a `res/values*` XML (strings, arrays, colors…) as a filterable name/value table.
- Built-in Claude assistant (conversation memory, editable pre-prompt, orange tree-flash on file reads)
- Missing-tool handling + setup banner, apktool version warning + updater
- Cross-platform (macOS/Windows/Linux), native macOS Dock app, MCP server for Claude Code

## Biggest capability gaps (next)

- [ ] **Native pseudo-code in the GUI** — surface `decompile_native` (radare2) in the editor with a function picker; bundle/offer a Ghidra-headless backend for richer output. (ELF structural analysis already ships.)
- [ ] **More guided patches** — "neutralize a specific call" (remove an `invoke-*` + its `move-result`), signature/integrity-check bypass, and overload-specific targeting (by descriptor, not just name).
- [ ] **Patch review/undo** — show a diff of what a one-click patch changed, and a one-click revert (re-decompile or keep a backup of edited smali/manifest).

## Dynamic analysis (uses adb / maestro)

- [ ] **Device panel** — list devices, screenshot, pull/push files.
- [ ] **Live logcat viewer** — stream logcat filtered to the package; pairs with the intent tester.
- [ ] **Run + observe** — launch via adb and capture logcat around a triggered action.

## Quick wins

- [ ] **Claude "full audit" button** — one click runs a structured Claude pass over the static report and writes `AUDIT-claude.md` (narrative findings, confirmed-in-context), complementing the static `export_report` (`AUDIT.md`).
- [ ] **Per-project bookmarks / notes** — mark interesting classes / lines while exploring.

## Polish

- [ ] **CI** — `py_compile` + a headless smoke test on push.
- [ ] **Demo GIF** in the README.
- [ ] **Method-level diff** in the version-diff view (not just changed-class list).
- [ ] **Native window** on Windows/Linux (currently a Chromium app window), matching the macOS app.

---

Only analyze apps you own or are authorized to test.
