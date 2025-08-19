# callmap/translator.py
from __future__ import annotations
import os
import json
from typing import Dict, Any, List, Optional

# --- Regole iniziali di mapping (estendibili) ---
# Ogni regola indica: modulo!funzione -> {target, headers, notes, map_args, map_ret}
MAPPING_RULES: Dict[str, Dict[str, Any]] = { # TODO are all of this correct and is anything missing?
    # --- LoadLibrary / GetProcAddress: concettualmente -> dlopen/dlsym ---
    "KERNEL32!LoadLibraryA": {
        "target": "dlopen",
        "headers": ["<dlfcn.h>"],
        "notes": "Sostituisce caricamento dinamico; usare RTLD_NOW/RTLD_LOCAL. Gestire .dll vs .dylib path.",
        "map_args": ["const char* filename -> lpLibFileName", "int flags -> RTLD_NOW"],
        "map_ret": "void* handle (NULL on error)",
    },
    "KERNEL32!LoadLibraryW": {
        "target": "dlopen",
        "headers": ["<dlfcn.h>"],
        "notes": "Wide string -> UTF-8 via CFStringCreateWithCharacters + CFStringGetCString.",
        "map_args": ["const char* filename (UTF-8) -> lpLibFileName", "int flags -> RTLD_NOW"],
        "map_ret": "void* handle",
    },
    "KERNEL32!GetProcAddress": {
        "target": "dlsym",
        "headers": ["<dlfcn.h>"],
        "notes": "Gestire ordinali: non c'è equivalente diretto; serve mappa simboli.",
        "map_args": ["void* handle -> hModule", "const char* symbol -> lpProcName"],
        "map_ret": "void* sym",
    },

    # --- File I/O (CreateFile/ReadFile/WriteFile/CloseHandle) -> open/read/write/close ---
    "KERNEL32!CreateFileA": {
        "target": "open",
        "headers": ["<fcntl.h>", "<unistd.h>", "<sys/stat.h>"],
        "notes": "Tradurre dwDesiredAccess, dwCreationDisposition in flag POSIX; path A=ANSI.",
        "map_args": ["const char* path", "int oflag", "mode_t mode (opzionale)"],
        "map_ret": "int fd (-1 on error)",
    },
    "KERNEL32!CreateFileW": {
        "target": "open",
        "headers": ["<fcntl.h>", "<unistd.h>", "<sys/stat.h>", "<CoreFoundation/CoreFoundation.h>"],
        "notes": "Wide path -> UTF-8. Attenzione a condivisione/locking stile Win32 (non nativo).",
        "map_args": ["const char* path (UTF-8)", "int oflag", "mode_t mode"],
        "map_ret": "int fd",
    },
    "KERNEL32!ReadFile": {
        "target": "read",
        "headers": ["<unistd.h>"],
        "notes": "lpNumberOfBytesRead -> ssize_t; gestire overlapped I/O separatamente.",
        "map_args": ["int fd", "void* buf", "size_t count"],
        "map_ret": "ssize_t read_bytes",
    },
    "KERNEL32!WriteFile": {
        "target": "write",
        "headers": ["<unistd.h>"],
        "notes": "lpNumberOfBytesWritten -> ssize_t.",
        "map_args": ["int fd", "const void* buf", "size_t count"],
        "map_ret": "ssize_t written",
    },
    "KERNEL32!CloseHandle": {
        "target": "close",
        "headers": ["<unistd.h>"],
        "notes": "Su POSIX handle diversi dai fd non chiudibili con close(). Disambiguare.",
        "map_args": ["int fd"],
        "map_ret": "int rc",
    },

    # Puoi aggiungere USER32/GDI32 se miri a Cocoa/Metal più avanti
}

STUB_TEMPLATE = r"""// Auto-generated stub for {win_key} -> {target}
{includes}

#ifdef __APPLE__
#include <TargetConditionals.h>
#if !TARGET_OS_MAC
#error "This stub targets macOS."
#endif
#endif

// Notes: {notes}

int stub_{safe_name}(void) {{
    // TODO: Map arguments from Windows signature to POSIX/macos
    // Mapped args: {map_args}
    // Return mapping: {map_ret}
    // Place your translation logic here.
    return 0;
}}
"""

def make_safe_name(win_key: str) -> str:
    return win_key.replace("!", "_").replace("@", "_").replace("#", "_")

def plan_from_compact(compact_path: str) -> Dict[str, Any]:
    with open(compact_path, "r") as f:
        data = json.load(f)

    seen: Dict[str, int] = {}
    for th in data.get("threads", []):
        for c in th.get("calls", []):
            key = f"{c['module'].upper()}!{c['function']}"
            seen[key] = seen.get(key, 0) + 1

    plan: List[Dict[str, Any]] = []
    for key, count in sorted(seen.items(), key=lambda kv: kv[1], reverse=True):
        rule = MAPPING_RULES.get(key)
        plan.append({
            "win_api": key,
            "count": count,
            "mapped": bool(rule),
            "target": rule.get("target") if rule else None,
            "headers": rule.get("headers") if rule else None,
            "notes": rule.get("notes") if rule else "No rule yet.",
            "map_args": rule.get("map_args") if rule else [],
            "map_ret": rule.get("map_ret") if rule else None,
        })
    return {
        "metadata": data.get("metadata", {}),
        "plan": plan
    }

def write_stubs(plan: Dict[str, Any], out_dir: str):
    os.makedirs(out_dir, exist_ok=True)
    for item in plan["plan"]:
        if not item["mapped"]:
            continue
        win_key = item["win_api"]
        safe = make_safe_name(win_key)
        includes = "\n".join([f"#include {h}" for h in (item["headers"] or [])])
        src = STUB_TEMPLATE.format(
            win_key=win_key,
            target=item["target"],
            includes=includes,
            notes=item["notes"],
            map_args=", ".join(item["map_args"] or []),
            map_ret=item["map_ret"] or "N/A",
            safe_name=safe
        )
        path = os.path.join(out_dir, f"{safe}.c")
        with open(path, "w") as f:
            f.write(src)

def save_plan(plan: Dict[str, Any], out_path: str):
    with open(out_path, "w") as f:
        json.dump(plan, f, indent=2)

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Traduce una compact trace in un piano di traduzione e genera stub macOS")
    ap.add_argument("compact_trace", help="compact_trace.json")
    ap.add_argument("--plan-out", default="reports/callmaps/translation_plan.json")
    ap.add_argument("--stubs-out", default="out/stubs")
    args = ap.parse_args()

    plan = plan_from_compact(args.compact_trace)
    os.makedirs(os.path.dirname(args.plan_out), exist_ok=True)
    save_plan(plan, args.plan_out)
    write_stubs(plan, args.stubs_out)

    print(f"[+] Piano di traduzione salvato in {args.plan_out}")
    print(f"[+] Stub generati in {args.stubs_out}")
