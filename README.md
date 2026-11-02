<div align="center">

# TONK-RE

**A retro-terminal GUI for decompiling, inspecting, patching, rebuilding and signing Android APKs — with an AI assistant built in.**

Drop in an `.apk`, read the Java, grep the smali, scan for secrets and insecure crypto, edit, rebuild, and re-sign — all from one green-phosphor CRT interface. Also ships as an MCP server so [Claude Code](https://claude.com/claude-code) can drive the same analysis from your terminal.

Runs on **macOS**, **Windows** and **Linux**.

![TONK-RE overview](docs/screenshots/overview.png)

</div>

---

> [!WARNING]
> **For authorized use only.** Decompile, patch and re-sign only apps you own or have explicit permission to test. You are responsible for complying with the app's license and your local laws.

## Features

- **Decompile** `.apk` / `.xapk` / `.apks` / `.apkm` with [jadx](https://github.com/skylot/jadx) (Java/Kotlin source) and [apktool](https://apktool.org) (manifest, resources, smali) in one click.
- **Manifest attack-surface summary** — package, SDKs, `debuggable` / `allowBackup` / cleartext flags, exported components with their intent actions and deep-link schemes, dangerous permissions (highlighted), native libs, and detected frameworks (Flutter, React Native, Unity, Xamarin, Cordova).
- **Code editor** with syntax highlighting for Java, smali, XML, JSON, JS and YAML. Tabs, find (`⌘F`), go-to-line (`⌥G`), and editable smali/resources.
- **Security sweeps** — one click each for hard-coded secrets (Google/AWS/Stripe/GitHub/Slack keys, JWTs, private keys), URLs/endpoints, and risky API usage (weak crypto, TLS trust overrides, WebView JS bridges, dynamic code loading, root/Frida detection, raw SQL…).
- **Regex search** across Java, smali or resources — click any hit to jump to the exact line.
- **Deep-link / intent tester** — every exported activity/service/receiver and `scheme://host` deep link rendered as a ready-to-fire `adb am` intent, with editable data URI and extras; run it on a connected device or copy the command. No-permission (callable-by-any-app) components are flagged in red.
- **Version diff** — pick two decompiled versions and see added/removed permissions and exported components, added/removed/**changed** classes, added/removed endpoints, framework changes and security-flag flips.
- **Frida hook generator** — generate a hook script for a method or whole class (trace args/return, stacktrace, override a return value) or a universal SSL-pinning / root-detection bypass; saved into the project with ready `frida` spawn/attach commands.
- **Native `.so` analysis** — click any native library to open a read-only report: architecture/bitness, SONAME and NEEDED libs, **JNI entry points** (`Java_*` / `JNI_OnLoad`), exported & imported functions, exploit mitigations (exec-stack / RELRO / stack-canary / FORTIFY), and URLs/strings with a secret scan. Pure-stdlib ELF parser (no external tool); optional radare2 pseudo-code when installed. Unblocks Flutter / NDK / game apps where the logic lives in native code.
- **One-click & guided patches** — the `[ PATCH ▾ ]` menu's **Make interceptable (MITM)** sets `debuggable`, allows cleartext and injects a `network_security_config` trusting user CA certs (the standard Burp / mitmproxy prep). **Right-click any method** in Java or smali for Frida (trace / override return), "ask Claude for a Frida hook", or a **guided smali patch** — force return true/false, return null/0, or no-op — then BUILD+SIGN. The static counterpart to the Frida generator, ideal for root/premium/license gates.
- **Java ⇄ smali bridge** — read a class in clean decompiled Java, then jump straight to its smali (multidex- and inner-class-aware) to patch it and rebuild.
- **Audit report export** — one click (`[ REPORT ↯ ]`, or `export_report` / `tonkre report`) writes a Markdown **`AUDIT.md`** into the project: a risk summary, the manifest attack surface, hard-coded secrets, endpoints, crypto/security findings and the signing certificate, each with `file:line` evidence. One shareable artifact that reuses every scanner.
- **Resource viewer** — click a drawable or icon (`png/jpg/webp/gif/bmp/ico`) to render it in place of raw bytes, and hit `[ TABLE ▦ ]` on any `res/values*` XML to read it as a filterable name/value table (strings, arrays, colors, dimens…) instead of raw XML.
- **Rebuild & sign** — `BUILD` (apktool), `SIGN` (zipalign + apksigner v1–v3), `BUILD+SIGN`, `INSTALL ▸ ADB`, and `RESIGN APK` for any existing APK. A debug keystore is generated automatically. If apktool's resource re-linking fails (common with heavily-optimized or obfuscated apps), BUILD automatically **falls back to a code-only build** — it patches the freshly-compiled dex into a copy of the original APK, so smali/code patches still produce a working signed APK (original resources kept).
- **Ask Claude** — a built-in chat panel runs the `claude` CLI inside the project (read-only, or tick **WRITE** to let it create/edit files in the project folder and `~/Downloads` only), with your editor selection as context, and links file:line references straight into the editor. The conversation has memory (**+ NEW SESSION** starts fresh), and an editable **pre-prompt** template (saved per machine) wraps every question so you can pin a role/output format (e.g. an OWASP MASVS audit).
- **MCP server** — the same engine is exposed to Claude Code as the `tonk-re` tool set, so you can decompile and audit from any `claude` session.
- **Retro CRT UI** — scanlines, glow, boot sequence, and a green/amber phosphor toggle. Resizable panels.

## Screenshots

| Decompiled source + manifest attack surface | Secret scan on smali |
|---|---|
| ![overview](docs/screenshots/overview.png) | ![secrets](docs/screenshots/smali-secrets.png) |

| Crypto / security scan | Rebuild + sign (apksigner verified) |
|---|---|
| ![security](docs/screenshots/security-scan.png) | ![build and sign](docs/screenshots/build-sign.png) |

| Deep-link / intent tester | Version diff |
|---|---|
| ![intent tester](docs/screenshots/intent.png) | ![version diff](docs/screenshots/diff.png) |

| Frida hook generator | Amber phosphor mode |
|---|---|
| ![frida](docs/screenshots/frida.png) | ![amber](docs/screenshots/amber.png) |

## Requirements

**You only need [uv](https://docs.astral.sh/uv/)**, and the setup script installs that too. Everything else is installed with one click from the app's **SETUP ⚙** panel (or `tonkre setup all`) into `~/.tonkre/tools`: per-user, no admin/sudo, no package manager, no PATH changes. To uninstall, delete that folder. Every download is checksum-verified before it is unpacked.

| Component | What for | Installed from | |
|---|---|---|---|
| JDK 21 (Temurin) | runs jadx/apktool/apksigner; `keytool` for signing | [Adoptium](https://adoptium.net) (sha256) | required |
| [jadx](https://github.com/skylot/jadx) | Java/Kotlin decompiler | GitHub release (sha256) | required |
| [apktool](https://apktool.org) 3.x | manifest, resources, smali, rebuild | GitHub release (sha256) | required |
| Android build-tools | `apksigner`, `zipalign` (v2/v3 signing) | Google SDK repository (sha1), needs the Android SDK License accepted | required to sign |
| Android platform-tools | `adb`: INSTALL to device, intents | Google SDK repository (sha1), needs the Android SDK License accepted | optional |
| [frida-tools](https://frida.re) | *running* generated hooks (generating them needs nothing) | `uv tool install frida-tools` | optional |
| Chrome / Edge / Brave / Chromium | app-window mode | your system | optional |
| zenity *or* kdialog (Linux) | the `BROWSE` file dialog | `sudo apt install zenity` | optional |

Tools you already have (on `PATH`, or in an Android SDK at `ANDROID_HOME` / the Android Studio default) are detected and used as-is; SETUP only fills the gaps. The panel opens on its own when a required tool is missing, and if you try an action whose tool is missing (e.g. DECOMPILE without jadx) the console tells you which SETUP button to press.

> **macOS note:** only macOS gets the native Dock app (`.app`). Windows and Linux run in an app window of your Chromium-family browser, or a normal browser tab.

## Install

**New users: double-click the setup file.** Download the repo (git clone or *Code ▸ Download ZIP*), then:

| OS | Double-click | or from a terminal |
|---|---|---|
| Windows | `Setup-TONK-RE.cmd` | `Setup-TONK-RE.cmd` |
| macOS | `Setup-TONK-RE.command` | `./setup.sh` |
| Linux | n/a | `./setup.sh` |

It installs uv if needed, runs the installer below, and opens TONK-RE. In the **SETUP ⚙** panel, tick *I accept the Android SDK License* and press **INSTALL ALL**. That's it.

```sh
git clone https://github.com/xaldarof/tonk-re.git
cd tonk-re
```

**Installer only** (if you already have uv): `./install.sh` (macOS / Linux) or `powershell -ExecutionPolicy Bypass -File install.ps1` (Windows). It:

- creates the `tonkre-gui` (GUI) and `tonkre` (CLI) launchers in `~/.local/bin`,
- installs the Claude Code skill,
- registers the `tonk-re` MCP server with Claude Code (if the `claude` CLI is present), and
- prints the toolchain status (`tonkre setup status`).

On Windows it also adds a **TONK-RE** desktop shortcut.

**Toolchain from the CLI** (headless / CI):

```sh
tonkre setup                                   # status of every component
tonkre setup all --accept-android-license      # install everything missing
tonkre setup jadx apktool                      # or just some (the JDK is added automatically if needed)
```

### Updating apktool

Older apktool (< 3.x) frequently fails to recompile resources for optimized/obfuscated apps. TONK-RE warns at startup if yours is old and still produces a working **code-only** build, but for full resource rebuilds update apktool:

```sh
./macos/update-apktool.sh           # macOS / Linux; downloads, verifies, installs apktool 3.x
```

Then re-decompile the affected app with **FORCE** checked.

### macOS: Dock app

To get a real Dock app with its own icon:

```sh
./macos/build_app.sh --dock
```

This builds `~/Applications/TONK-RE.app` and pins it to your Dock. Launch it from the Dock, Launchpad or Spotlight; the window is native (not a browser tab) and quitting it (`⌘Q`) stops the background server. Omit `--dock` to build the app without pinning.

## Usage

### GUI

```sh
tonkre-gui             # opens an app window
tonkre-gui --browser   # opens in a normal browser tab instead
```

Or launch **TONK-RE** from the Dock (macOS).

1. **Load an APK** — drag an `.apk` onto the window, or click `BROWSE`, or paste a path and hit `DECOMPILE`. Results are cached by file hash, so re-opening the same APK is instant. Already-decompiled apps appear in the **PROJECTS** dropdown.
2. **Explore** — use the file tree (left) to read decompiled Java under `jadx/sources/` or smali/resources under `apktool/`. The **INFO** panel (right) summarizes the manifest and attack surface — click an exported component to jump to its handler.
3. **Scan** — the **SCAN** tab runs secret / URL / crypto-security sweeps; the **SEARCH** tab is a regex grep over Java, smali or resources. Click any result to open it at that line.
4. **Patch** — edit smali or resources in the editor and `⌘S` to save.
5. **Rebuild** — `BUILD` recompiles with apktool, `SIGN` signs it, `BUILD+SIGN` does both, `OPEN DIST` shows the output (`<project>/dist/signed.apk`), and `INSTALL ▸ ADB` pushes it to a connected device.
6. **Ask Claude** — the **CLAUDE** tab answers questions about the app and cites file:line; select code in the editor first to send it as context. Use **+ NEW SESSION** to reset the conversation, and **PRE-PROMPT** to edit the saved template (with `{question}` / `{context}` placeholders) that wraps every question.

> Only smali and resource edits are recompiled into the APK. Edits to the decompiled **Java** are for reading/reference — the app reminds you when you save one.

### CLI

The `tonkre` command exposes the core engine headlessly:

```sh
tonkre decompile /path/to/app.apk      # -> prints the project name + manifest summary
tonkre projects                        # list decompiled projects
tonkre info     <project>              # manifest attack-surface summary
tonkre secrets  <project>              # hard-coded secrets
tonkre urls     <project>              # endpoints
tonkre security <project>              # crypto / security findings
tonkre search   <project> <regex> [java|smali|resources|all]
tonkre intents  <project>              # exported components + deep links as adb am intents
tonkre diff      <project_a> <project_b>   # diff two decompiled versions
tonkre frida    <project> [class] [method] [template]   # print a Frida hook script
tonkre smali    <project> <class>      # smali path(s) for a Java class
tonkre native   <project> <so_path>    # analyze a native .so (arch, JNI, exports, mitigations)
tonkre mitm     <project>              # make interceptable (debuggable + user-CA network config)
tonkre patch    <project> <class> <method> [force_true|force_false|return_zero|return_null|noop]
tonkre report   <project>              # write a Markdown audit report (AUDIT.md) into the project
```

### With Claude Code

After install, the `tonk-re` MCP server is registered. In any `claude` session you can simply ask:

```
decompile ~/Downloads/app.apk and audit it for hard-coded secrets and insecure crypto
```

Claude will call the `tonk-re` tools (`decompile_apk`, `apk_info`, `find_secrets`, `find_crypto_and_security`, `search_code`, `read_class`, `xrefs`, `analyze_native`, `decompile_native`, `make_interceptable`, `patch_method`, `export_report`, …) and report back with file:line evidence. A bundled skill guides the workflow.

## Configuration

Set these environment variables before launching:

| Variable | Default | Purpose |
|---|---|---|
| `TONKRE_PORT` | `7777` | port for the GUI server (GUI mode only; the Dock app picks a random free port) |
| `TONKRE_HOME` | `~/.tonkre` | where projects, uploads and the debug keystore live |
| `ANDROID_HOME` / `ANDROID_SDK_ROOT` | OS default | Android SDK location (for apksigner/zipalign/adb) |

Decompiled projects live in `$TONKRE_HOME/projects/`; the auto-generated signing key is `$TONKRE_HOME/debug.keystore`.

## How it works

```
         ┌──────────────┐        ┌──────────────┐
  APK ──▶ │   gui.py     │  HTTP  │   ui.html    │  ← retro CRT front-end
         │ (127.0.0.1,  │◀──────▶│ (CodeMirror) │
         │  token-auth) │        └──────────────┘
         └──────┬───────┘
                │ imports
         ┌──────▼───────┐
         │  server.py   │  ← core engine + MCP server
         └──────┬───────┘
     ┌──────────┼───────────┬───────────┐
   jadx      apktool    apksigner /    claude CLI
 (sources)  (smali/res)  zipalign       (read-only)
```

- **`server.py`** — the decompile/scan/search engine, usable three ways: imported by the GUI, run as a CLI (`cli` subcommand), or run as an MCP server (default).
- **`gui.py`** — a stdlib HTTP server bound to `127.0.0.1` with a per-launch random token; it streams long-running jobs (decompile/build/sign/claude) line-by-line to the console. Also handles OS integration (file dialog, "reveal in folder", app window, native macOS window).
- **`ui.html`** — a single-file front-end (CodeMirror + vanilla JS), no build step.

### Security model

The server listens only on `127.0.0.1` and every API call requires a secret token generated fresh at launch (printed in the URL). Other websites in your browser can't reach it without the token. Nothing is uploaded anywhere — all analysis is local. The `claude` panel runs the CLI with `--allowedTools Read,Grep,Glob` (read-only) in the project directory. Ticking **WRITE** adds `Edit(./**)` and `Edit(~/Downloads/**)`, so it can create/edit files only in the project folder and Downloads; writes anywhere else are still denied.

## Project layout

```
tonk-re/
├── server.py          core engine + MCP server + CLI
├── gui.py             local web server + OS integration
├── ui.html            retro-terminal front-end
├── install.sh         macOS / Linux installer
├── install.ps1        Windows installer
├── setup.sh, Setup-TONK-RE.cmd/.command   one-click bootstrap (uv + installer + open app)
├── tools.py           toolchain manager: SETUP panel / `tonkre setup` installs into ~/.tonkre/tools
├── macos/
│   ├── build_app.sh   builds TONK-RE.app (+ --dock)
│   └── make_icon.py   renders the CRT app icon
├── skill/SKILL.md     Claude Code skill
└── docs/screenshots/
```

## License

[MIT](LICENSE) © Temur ([@xaldarof](https://github.com/xaldarof))
