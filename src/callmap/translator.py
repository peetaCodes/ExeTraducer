# backend_translator.py
# Minimal backend translator: convert callmap entries -> target-specific IR / simple shim.
import json, os, shlex
from typing import List, Dict, Any, Optional

from src.mapping.winapi_to_ir import map_winapi_to_ir_with_dll
from src.mapping.ir_to_macosaarch64 import map_ir_to_macos

from src.tools.universal_translation_utils import WIN_ACCESS_TO_POSIX, WIN_CREATION_TO_POSIX

# --------------------------------------------------------------------
# Helper: normalize target names
TARGET_ALIASES = {
    "macos-apple_silicon": "macos-aarch64",
    "macos-intel_64bit": "macos-x86_64",
    "macos-intel_32bit": "macos-x86",  # warning: macOS 32-bit obsolete
    "linux-ARM64": "linux-arm64",
    "linux-ARM": "linux-armv7",
    "linux-x86": "linux-x86",
    "linux-x86_64": "linux-x86_64",
    "IR": "ir"
}


def normalize_target(t: str) -> str:
    return TARGET_ALIASES.get(t, t)


def map_createfile_args(raw_args: List[Any]) -> Dict[str, Any]:
    # raw_args heuristics: [path, access, flags, ...]
    path = raw_args[0] if len(raw_args) > 0 else None
    access = raw_args[1] if len(raw_args) > 1 else None
    disposition = raw_args[2] if len(raw_args) > 2 else None

    # normalize access
    posix_flags = []
    access_s = ""
    if access:
        a = str(access).upper()
        # heuristic convert numeric constants to strings if coded
        if "GENERIC" in a:
            if "WRITE" in a and "READ" in a:
                access_s = "GENERIC_READ_WRITE"
            elif "WRITE" in a:
                access_s = "GENERIC_WRITE"
            else:
                access_s = "GENERIC_READ"
    if access_s and access_s in WIN_ACCESS_TO_POSIX:
        posix_flags.append(WIN_ACCESS_TO_POSIX[access_s])

    # creation disposition
    if disposition:
        d = str(disposition).upper()
        for k, v in WIN_CREATION_TO_POSIX.items():
            if k in d:
                posix_flags.extend(v)

    if not posix_flags:
        posix_flags.append("O_RDONLY")

    return {
        "path": path,
        "posix_flags": posix_flags,
        "mode": "0644"  # default file mode
    }


# --------------------------------------------------------------------
# Map MessageBox -> platform action
def map_messagebox_to_target(raw_args: List[Any], target: str) -> Dict[str, Any]:
    # heuristics: MessageBoxW(hwnd, text, caption, type)
    text = raw_args[1] if len(raw_args) > 1 else (raw_args[0] if raw_args else "")
    title = raw_args[2] if len(raw_args) > 2 else ""
    if target.startswith("macos"):
        # use osascript display dialog
        cmd = f"osascript -e {shlex.quote('display dialog ' + shlex.quote(str(text)) + ' with title ' + shlex.quote(str(title)))}"
        return {"type": "osascript", "cmd": cmd}
    elif target.startswith("linux"):
        # prefer zenity if available
        cmd = f"zenity --info --text={shlex.quote(str(text))} --title={shlex.quote(str(title))}"
        return {"type": "zenity", "cmd": cmd}
    else:
        return {"type": "fallback", "cmd": f"echo {shlex.quote(str(title + ': ' + text))}"}


# --------------------------------------------------------------------
# BackendTranslator: main class
class BackendTranslator:
    def __init__(self, target: str):
        self.target: str = normalize_target(target)

    def translate_entry(self, call_entry: Dict[str, Any]) -> Dict[str, Any]:
        match self.target:
            case "ir":
                dll = (call_entry.get("dll") or "").lower()
                func = (call_entry.get("func") or "").lower()
                call_name = f"{dll}!{func}"
                translated = map_winapi_to_ir_with_dll(func, dll)
            case "macos-aarch64":
                call_name = call_entry.get("ir")
                translated = map_ir_to_macos(call_entry)

        params = map_createfile_args(call_entry.get("args", []))
        print(f"Translated {call_name} into {self.target} with {translated['confidence'].upper()} confidence")
        return {f"{self.target}": translated["ir"], "params": params, "meta": call_entry}

    def translate_callmap(self, callmap: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out = []
        for c in callmap:
            out.append(self.translate_entry(c))
        return out

    def emit_json(self, callmap_translated: List[Dict[str, Any]], out_path: str):
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(callmap_translated, f, indent=2, ensure_ascii=False)

    def emit_c_shim_for_fileops(self, translated_map: List[Dict[str, Any]], out_c_path: str):
        """
        Example: generate a tiny C file that implements wrappers for file.create calls.
        This is a minimal stub to show how to produce target-native code (compile with target toolchain).
        """
        lines = []
        lines.append('#include <stdio.h>')
        lines.append('#include <fcntl.h>')
        lines.append('#include <unistd.h>')
        lines.append('')
        lines.append('// Auto-generated shim (minimal) - adapt semantics to your needs')
        for i, e in enumerate(translated_map):
            if e.get("ir") == "sys.file.create":
                p = e["params"]
                path = p.get("path") or "/tmp/unknown"
                flags = "|".join(p.get("posix_flags", [])) or "O_RDONLY"
                mode = p.get("mode", "0644")
                func_name = f"shim_createfile_{i}"
                lines.append(f'int {func_name}(void) ' + '{')
                lines.append(f'  int fd = open("{path}", {flags}, {mode});')
                lines.append('  if (fd < 0) { perror("open"); return -1; }')
                lines.append('  // TODO: use fd as needed')
                lines.append('  close(fd);')
                lines.append('  return 0;')
                lines.append('}')
                lines.append('')
        with open(out_c_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

# --------------------------------------------------------------------
# Example usage:
# bt = BackendTranslator("macos-aarch64")
# translated = bt.translate_callmap(callmap_json)
# bt.emit_json(translated, "out/ir_macos.json")
# bt.emit_c_shim_for_fileops(translated, "out/shims/file_shim.c")
