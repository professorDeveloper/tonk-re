"""Native shared-object (.so / ELF) static analysis — pure stdlib, no external tools.

Parses an ELF file directly (32/64-bit, little/big-endian) to surface the things that
matter when the real logic lives in native code (Flutter / NDK / Unity / game apps):

  * architecture, bitness, type, SONAME, NEEDED libraries, RUNPATH
  * exported functions (esp. JNI `Java_*` / `JNI_OnLoad`) and imported symbols
  * exploit-mitigation posture (exec-stack, RELRO, stack canary, FORTIFY)
  * whether the lib is stripped
  * printable strings and the URLs among them

This is deliberately dependency-free (matches tonk-re's stdlib ethos). Pseudo-code
decompilation (Ghidra/radare2) is a separate, optional backend — see `decompile_native`.
"""
from __future__ import annotations

import re
import shutil
import struct
import subprocess
from pathlib import Path

# ELF constants -----------------------------------------------------------------
_MACHINE = {
    0x03: "x86", 0x08: "MIPS", 0x28: "ARM (32-bit)", 0x3E: "x86-64",
    0xB7: "AArch64 (arm64-v8a)", 0xF3: "RISC-V", 0x14: "PowerPC", 0x15: "PowerPC64",
}
_ETYPE = {1: "REL (object)", 2: "EXEC (executable)", 3: "DYN (shared/PIE)", 4: "CORE"}

SHT_SYMTAB, SHT_DYNSYM, SHT_DYNAMIC = 2, 11, 6
STB_GLOBAL, STB_WEAK = 1, 2
STT_FUNC = 2
PT_GNU_STACK, PT_GNU_RELRO = 0x6474E551, 0x6474E552
DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH, DT_FLAGS, DT_BIND_NOW, DT_FLAGS_1 = 1, 14, 15, 29, 30, 24, 0x6FFFFFFB
DF_BIND_NOW, DF_1_NOW = 0x8, 0x1

URL_RE = re.compile(rb"[a-z][a-z0-9+.\-]*://[A-Za-z0-9.\-_~:/?#\[\]@!$&'()*+,;=%]{3,}")
_STRING_RE = re.compile(rb"[\x20-\x7e]{5,}")
_MAX_FILE = 256 * 1024 * 1024  # don't try to parse absurdly large blobs into memory


def is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def _cstr(buf: bytes, off: int) -> str:
    end = buf.find(b"\x00", off)
    return buf[off:end if end >= 0 else None].decode("utf-8", "replace")


def analyze_so(path: str | Path, max_strings: int = 300, max_syms: int = 800) -> dict:
    """Static ELF analysis of a .so file. Never raises for a malformed file: returns
    {"error": ...} (plus whatever was parsed) so the caller can always show something."""
    p = Path(path)
    size = p.stat().st_size
    if size > _MAX_FILE:
        return {"error": f"file too large to parse in-memory ({size} bytes)", "size": size}
    data = p.read_bytes()
    out: dict = {"file": p.name, "size": size}
    try:
        _parse_elf(data, out, max_syms)
    except Exception as e:  # malformed / truncated ELF — keep going with strings
        out["error"] = f"ELF parse error: {e}"
    _extract_strings(data, out, max_strings)
    return out


def _parse_elf(data: bytes, out: dict, max_syms: int) -> None:
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    ei_class, ei_data = data[4], data[5]
    is64 = ei_class == 2
    en = "<" if ei_data == 1 else ">"
    out["bits"] = 64 if is64 else 32
    out["endian"] = "little" if ei_data == 1 else "big"

    if is64:
        (e_type, e_machine, _ev, _entry, e_phoff, e_shoff, _flags, _eh, e_phentsize,
         e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(en + "HHIQQQIHHHHHH", data, 16)
        sh_fmt, ph_fmt, sym_fmt, dyn_fmt = en + "IIQQQQIIQQ", en + "IIQQQQQQ", en + "IBBHQQ", en + "QQ"
    else:
        (e_type, e_machine, _ev, _entry, e_phoff, e_shoff, _flags, _eh, e_phentsize,
         e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(en + "HHIIIIIHHHHHH", data, 16)
        sh_fmt, ph_fmt, sym_fmt, dyn_fmt = en + "IIIIIIIIII", en + "IIIIIIII", en + "IIIBBH", en + "II"

    out["arch"] = _MACHINE.get(e_machine, f"machine 0x{e_machine:x}")
    out["type"] = _ETYPE.get(e_type, str(e_type))

    # --- section headers ---
    secs = []
    for i in range(e_shnum):
        f = struct.unpack_from(sh_fmt, data, e_shoff + i * e_shentsize)
        if is64:
            name, typ, flags, addr, offset, ssize, link, info, _al, entsize = f
        else:
            name, typ, flags, addr, offset, ssize, link, info, _al, entsize = f
        secs.append({"name_off": name, "type": typ, "offset": offset, "size": ssize,
                     "link": link, "entsize": entsize})
    if e_shstrndx < len(secs):
        shstr = data[secs[e_shstrndx]["offset"]:secs[e_shstrndx]["offset"] + secs[e_shstrndx]["size"]]
        for s in secs:
            s["name"] = _cstr(shstr, s["name_off"])

    by_type = lambda t: [s for s in secs if s["type"] == t]
    out["stripped"] = not by_type(SHT_SYMTAB)

    # --- dynamic symbols (exports / imports) ---
    exports, imports = [], []
    for sym_sec in by_type(SHT_DYNSYM):
        strtab_sec = secs[sym_sec["link"]] if sym_sec["link"] < len(secs) else None
        strtab = data[strtab_sec["offset"]:strtab_sec["offset"] + strtab_sec["size"]] if strtab_sec else b""
        entsize = sym_sec["entsize"] or (24 if is64 else 16)
        n = sym_sec["size"] // entsize
        for i in range(1, n):  # index 0 is the null symbol
            try:
                vals = struct.unpack_from(sym_fmt, data, sym_sec["offset"] + i * entsize)
            except struct.error:
                break
            if is64:
                st_name, st_info, _oth, st_shndx, _val, _sz = vals
            else:
                st_name, _val, _sz, st_info, _oth, st_shndx = vals
            name = _cstr(strtab, st_name)
            if not name:
                continue
            bind, typ = st_info >> 4, st_info & 0xF
            if st_shndx == 0:  # SHN_UNDEF -> imported
                imports.append(name)
            elif bind in (STB_GLOBAL, STB_WEAK) and typ == STT_FUNC:
                exports.append(name)
    exports, imports = sorted(set(exports)), sorted(set(imports))

    jni = [e for e in exports if e.startswith("Java_") or e in ("JNI_OnLoad", "JNI_OnUnload")]
    out["jni"] = {
        "symbols": jni[:max_syms],
        "count": len(jni),
        "dynamic_registration": "JNI_OnLoad" in exports and not any(e.startswith("Java_") for e in exports),
    }
    out["exports"] = {"count": len(exports), "functions": exports[:max_syms]}
    out["imports"] = {"count": len(imports), "functions": imports[:max_syms]}

    # --- program headers: exec-stack / RELRO ---
    exec_stack, has_relro = None, False
    for i in range(e_phnum):
        f = struct.unpack_from(ph_fmt, data, e_phoff + i * e_phentsize)
        if is64:
            p_type, p_flags = f[0], f[1]
        else:
            p_type, p_flags = f[0], f[6]
        if p_type == PT_GNU_STACK:
            exec_stack = bool(p_flags & 0x1)
        elif p_type == PT_GNU_RELRO:
            has_relro = True

    # --- dynamic section: NEEDED / SONAME / RUNPATH / FLAGS ---
    needed, soname, runpath, dflags, bind_now = [], None, None, 0, False
    for dyn_sec in by_type(SHT_DYNAMIC):
        strtab_sec = secs[dyn_sec["link"]] if dyn_sec["link"] < len(secs) else None
        strtab = data[strtab_sec["offset"]:strtab_sec["offset"] + strtab_sec["size"]] if strtab_sec else b""
        off, step = dyn_sec["offset"], (16 if is64 else 8)
        for i in range(dyn_sec["size"] // step):
            try:
                tag, val = struct.unpack_from(dyn_fmt, data, off + i * step)
            except struct.error:
                break
            if tag == 0:  # DT_NULL
                break
            if tag == DT_NEEDED:
                needed.append(_cstr(strtab, val))
            elif tag == DT_SONAME:
                soname = _cstr(strtab, val)
            elif tag in (DT_RPATH, DT_RUNPATH):
                runpath = _cstr(strtab, val)
            elif tag == DT_FLAGS:
                dflags = val
            elif tag == DT_FLAGS_1:
                bind_now = bind_now or bool(val & DF_1_NOW)
            elif tag == DT_BIND_NOW:
                bind_now = True
    bind_now = bind_now or bool(dflags & DF_BIND_NOW)

    out["soname"] = soname
    out["needed"] = needed
    out["runpath"] = runpath
    out["security"] = {
        "nx_exec_stack": "executable stack (RWX) — risky" if exec_stack else "non-exec stack" if exec_stack is False else "no GNU_STACK header",
        "relro": "full" if (has_relro and bind_now) else "partial" if has_relro else "none",
        "stack_canary": "__stack_chk_fail" in imports,
        "fortify_source": any(s.endswith("_chk") for s in imports),
    }


def _extract_strings(data: bytes, out: dict, max_strings: int) -> None:
    strings, urls, seen = [], [], set()
    for m in _STRING_RE.finditer(data):
        s = m.group()
        for u in URL_RE.findall(s):
            u = u.decode("utf-8", "replace")
            if u not in seen:
                seen.add(u)
                urls.append(u)
        if len(strings) < max_strings * 6:  # keep a wider pool than we display, for scanning
            strings.append(s.decode("utf-8", "replace"))
        if len(strings) >= max_strings * 6 and len(urls) >= 500:
            break
    out["urls"] = urls[:500]
    # the ones worth eyeballing: paths, keys, format strings, class refs
    interesting = [s for s in strings
                   if ("/" in s or s.lower().startswith(("http", "key", "secret", "token", "password", "api"))
                       or s.startswith(("L", "(", "lib")) or "." in s) and len(s) <= 200]
    out["strings"] = (interesting or strings)[:max_strings]
    out["strings_total"] = len(strings)


# --- optional pseudo-code backend (radare2); degrades gracefully if absent ----

def decompile_native(path: str | Path, symbol: str = "", max_out: int = 40_000) -> dict:
    """Disassemble/pseudo-decompile a function with radare2 if it is installed. Returns
    {"available": False, ...} when no backend is present, so the UI can suggest installing one."""
    r2 = shutil.which("r2") or shutil.which("radare2")
    if not r2:
        return {"available": False, "reason": "radare2 not found",
                "hint": "install radare2 (https://rada.re) for native pseudo-code; `brew install radare2` / `apt install radare2`"}
    p = Path(path)
    target = symbol or "entry0"
    # pdc = pseudo-decompile (built in); fall back to pdf (disassembly) if pdc unavailable
    cmds = f"aa; s sym.{target} 2>/dev/null || s {target}; pdc"
    try:
        r = subprocess.run([r2, "-2", "-q", "-c", cmds, str(p)],
                           capture_output=True, text=True, timeout=180, encoding="utf-8", errors="replace")
        text = (r.stdout or r.stderr)[:max_out]
        return {"available": True, "backend": "radare2", "symbol": target, "text": text or "(no output)"}
    except Exception as e:
        return {"available": True, "backend": "radare2", "error": str(e)}


def format_report(a: dict) -> str:
    """Render analyze_so() output as a readable fixed-width report for the editor pane."""
    L = [f"// NATIVE LIBRARY: {a.get('file', '?')}    ({a.get('size', 0):,} bytes)", "=" * 64]
    if a.get("error") and "arch" not in a:
        L.append(f"[-] {a['error']}")
        if a.get("strings"):
            L += ["", "// STRINGS", *a["strings"][:200]]
        return "\n".join(L)
    sec = a.get("security", {})
    L += [
        f"arch          {a.get('arch', '?')}   ({a.get('bits', '?')}-bit, {a.get('endian', '?')}-endian)",
        f"type          {a.get('type', '?')}",
        f"soname        {a.get('soname') or '-'}",
        f"stripped      {a.get('stripped')}",
        "",
        "// EXPLOIT MITIGATIONS",
        f"  exec-stack    {sec.get('nx_exec_stack', '?')}",
        f"  RELRO         {sec.get('relro', '?')}",
        f"  stack canary  {sec.get('stack_canary', '?')}",
        f"  FORTIFY       {sec.get('fortify_source', '?')}",
    ]
    needed = a.get("needed") or []
    L += ["", f"// NEEDED LIBRARIES ({len(needed)})", *(f"  {n}" for n in needed)]
    if a.get("runpath"):
        L += [f"  RUNPATH: {a['runpath']}"]
    jni = a.get("jni", {})
    L += ["", f"// JNI ENTRY POINTS ({jni.get('count', 0)})"]
    if jni.get("dynamic_registration"):
        L.append("  [!] JNI_OnLoad present and no Java_* exports — natives are registered")
        L.append("      dynamically via RegisterNatives; inspect JNI_OnLoad to map them.")
    L += [f"  {s}" for s in jni.get("symbols", [])] or ["  (none)"]
    exp = a.get("exports", {})
    L += ["", f"// EXPORTED FUNCTIONS ({exp.get('count', 0)})", *(f"  {s}" for s in exp.get("functions", [])[:200])]
    imp = a.get("imports", {})
    L += ["", f"// IMPORTED FUNCTIONS ({imp.get('count', 0)})", *(f"  {s}" for s in imp.get("functions", [])[:200])]
    if a.get("urls"):
        L += ["", f"// URLs IN BINARY ({len(a['urls'])})", *(f"  {u}" for u in a["urls"])]
    if a.get("strings"):
        L += ["", f"// STRINGS (showing {len(a['strings'])} of ~{a.get('strings_total', 0)})", *a["strings"]]
    return "\n".join(L)
