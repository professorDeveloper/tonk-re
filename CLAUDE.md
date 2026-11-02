# CLAUDE.md — working rules for TONK-RE

Guidance for Claude Code (and humans) contributing to this repo. Read this before editing.

## What this project is

An Android APK reverse-engineering workbench: decompile (jadx + apktool), inspect, scan,
**patch**, rebuild and re-sign — exposed three ways over **one engine**:

- a retro-CRT **GUI** (`gui.py` + `ui.html`),
- a headless **CLI** (`tonkre …`), and
- an **MCP server** for Claude Code (`tonk-re` tools).

> For **authorized** analysis only (apps you own or are permitted to test). Keep that framing in
> docs and prompts. Do not add features whose only purpose is evading detection for abuse.

## Architecture (facade + engines)

```
ui.html ──HTTP──▶ gui.py ──imports──▶ server.py ──imports──▶ engine modules
(front-end)      (HTTP + OS           (MCP + CLI facade)      ├─ tools.py    toolchain install/activate
                  integration)                                ├─ native.py   ELF/.so static analysis
                                                              ├─ patches.py  manifest + smali patch engine
                                                              ├─ audit.py    scored MASVS findings + trackers
                                                              └─ report.py   Markdown/HTML audit report render
                                           │ shells out to:  jadx · apktool · apksigner/zipalign · adb · radare2 · claude
```

**Dependency direction is one-way and must stay that way:**

- `server.py` is the **facade**: it owns `@mcp.tool()` definitions, the CLI dispatch, project
  resolution (`_project_dir`, `_safe_join`) and the scanners. It imports the engine modules.
- `gui.py` imports `server as core` and adds **only** HTTP routing and OS integration
  (file dialogs, app window, streaming build/sign). It must not re-implement engine logic —
  call `core.*`.
- **Engine modules** (`native.py`, `patches.py`, `tools.py`, `audit.py`, `report.py`) are **leaves**: pure, dependency-light,
  and they **never import `server` or `gui`**. If an engine needs a project path or a resolved file
  list, the **caller passes it in** (dependency injection) — e.g. `patch_method_return()` takes the
  smali paths, it does not look them up. This keeps engines unit-testable and avoids import cycles.

New analysis capability → new engine module (or extend an existing one) + a thin facade wrapper.

## Design principles (enforced in review)

- **SOLID** — one module/function, one responsibility. A new feature is an engine function plus
  thin facade wrappers, not logic smeared across `gui.py` and `ui.html`. Depend on arguments, not
  on reaching back into the facade.
- **DRY** — reuse don't duplicate: regexes/patterns live once (e.g. `SECRET_PATTERNS` in
  `server.py`; the native scanner reuses them). Shared path/safety helpers live in `server.py`.
- **KISS** — prefer the stdlib and a small, obvious implementation. `native.py` parses ELF by hand
  rather than pulling a dependency. Don't add a framework where a function will do.
- **YAGNI** — build what the roadmap item needs now; leave hooks, not speculative abstractions.
- **Fail soft for user input** — analysis of an untrusted artifact must never crash the server.
  Return `{"error": …}` and show what was parsed (see `native.analyze_so`). Patches validate their
  inputs and report what they changed/skipped.
- **Security model is a feature, not a suggestion** — see below. Do not weaken it for convenience.

## Hard constraints — do not break these

1. **Single-file, zero-build runtime.** `server.py` and `gui.py` are `uv run --script` scripts with
   PEP 723 inline dependencies in the header. New third-party deps go in **that header**, and only
   when truly necessary (prefer stdlib). Sibling modules (`native.py`, …) are imported via the
   existing `sys.path.insert(…parent)` — they must run under the entry script's declared deps and
   **must not** carry their own PEP 723 block or import packages not declared by the entry script.
2. **Localhost + token auth.** `gui.py` binds `127.0.0.1` only and every `/api/*` call requires the
   per-launch `X-Token`. New endpoints go **after** `self._authed()` and must use `_safe_join` for
   any path from the client. Never serve a path outside the project dir.
3. **Claude panel stays sandboxed.** Read-only by default (`Read,Grep,Glob`); WRITE adds only
   `Edit(./**)` and `Edit(~/Downloads/**)`. Do not broaden the allowlist.
4. **`ui.html` is a single file, no build step.** Vanilla JS + CodeMirror from cdnjs. No bundler, no
   npm. Keep the phosphor theme tokens (`--fg`, `--amber`, …); don't hard-code colors.
5. **Cross-platform.** macOS / Windows / Linux. Resolve `.bat` launchers via `shutil.which`
   (see `_run` / `stream_cmd`), use `pathlib`, emit project-relative **posix** paths to the UI.
6. **Patches land on disk, rebuild is explicit.** Patch functions edit the decompiled tree and
   return a summary; the user then runs BUILD/SIGN. Manifest/resource edits need a **full** apktool
   build — say so (the code-only dex-swap fallback keeps the original resources).

## How to add things

- **A new MCP tool / CLI command:** implement the logic in an engine module (or a plain function in
  `server.py`), wrap it with `@mcp.tool()` (concise docstring — it's the model's API), add a `cli()`
  branch and extend the `usage` string. Keep output under `MAX_OUT` via `_truncate`.
- **A new GUI action:** add the endpoint in `gui.py` (`do_GET`/`do_POST`, after auth, via `core.*`),
  then wire the UI in `ui.html`. Long jobs stream via `_stream`/`ACTIONS`; quick ops return JSON.
- **A new one-click / guided patch:** add a function to `patches.py` (pure, takes paths), expose it
  through `/api/patch` (op switch) and the `@mcp.tool()` facade, and surface it in the UI (the
  `[ PATCH ▾ ]` menu for whole-app patches, the editor right-click menu for method-level ones).

## Verify before you finish

- `python -c "import py_compile; py_compile.compile('<file>.py', doraise=True)"` for each changed
  module (deps aren't needed to compile).
- Full import through uv: `uv run --script server.py cli` (prints usage; forces all imports).
- `ui.html`: confirm the inline `<script>` still parses (e.g. `new Function(...)` on its contents).
- Update `ROADMAP.md` (move the item to **Shipped**) and `skill/SKILL.md` when you add a tool.

## Conventions

- Commit/PR only when asked; branch off `main` first. Keep diffs focused.
- Match the existing terse, comment-above-the-tricky-bit style. Comments explain **why**, not what.
- Do not reformat untouched code or churn unrelated lines.
