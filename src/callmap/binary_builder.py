#!/usr/bin/env python3
"""
Create a runnable macOS (Apple Silicon) executable from a translated callmap JSON.
This script is multi-target ready but currently implements only macOS (macos-aarch64).

Design and behaviour (conservative):
 - Input: JSON file produced by your translator backend. Expected to be a LIST of call entries:
     [ { "ir": "...", "action_type": "...", "json_repr": {...}, "code_c": "...", "code_objc": "...", "confidence": "...", "meta": {...} }, ... ]
 - For each entry the script generates a C function stub `call_N()` that either embeds `code_c` if present,
   or generates a safe stub that prints the json_repr. If `code_objc` exists it will be placed into an Objective-C .m file
   compiled and linked with -framework Cocoa.
 - The script produces a `main.c` that invokes each `call_N()` sequentially. It then compiles with clang for arm64.
 - Output: a single executable (default ./out/app_macos_aarch64).

Security notes / warnings:
 - The script will embed and compile the `code_c` and `code_objc` snippets taken from the JSON.
   You MUST review or run this only on trusted data. Generated code may call system(), open files, kill processes, etc.
 - The script does not sandbox produced binaries. Use VMs or test machines for execution.

Requirements (to build locally on macOS):
 - Xcode toolchain / clang available in PATH
 - For GUI/ObjC snippets, compilation uses -framework Cocoa and .m files

Usage:
    python build_binary.py --callmap translated_calls.json --out ./out/app_macos_aarch64 --target macos-aarch64 --workdir ./build_artifacts

"""

from __future__ import annotations
import argparse
import json
import shutil
import subprocess
import sys
from os.path import abspath
from pathlib import Path
from typing import Any, Dict, List

from src.tools.universal_translation_utils import MAIN_HEADER, C_STUB_WRAPPER, clean_dictionary


# Utility
def safe_ident(n: str) -> str:
    # Create a safe C identifier from an index or name
    s = "".join(c if c.isalnum() or c == '_' else '_' for c in str(n))
    if s and s[0].isdigit():
        s = "_" + s
    return s


# Default compile/link flags for macOS Apple Silicon
MACOS_CFLAGS = ["-std=c11", "-arch", "arm64", "-O2", "-fPIC"]
MACOS_LDFLAGS = ["-arch", "arm64"]


def render_c_safe_snippet(code_c: str, indent: int = 4) -> str:
    if not code_c:
        return " " * indent + '// (no C snippet provided)\\n' + " " * indent + 'printf("call stub (no-op)\\n");\\n'
    # ensure code ends with newline
    if not code_c.endswith("\n"):
        code_c = code_c + "\n"
    # indent each line properly
    ind = " " * indent
    safe_lines = []
    for line in code_c.splitlines():
        safe_lines.append(ind + line)
    return "\n".join(safe_lines) + "\n"


def ensure_tool_exists(tool: str) -> bool:
    return shutil.which(tool) is not None


def compile_macos(output_path: Path, sources: List[Path], extra_objc: List[Path], cflags: List[str] = None,
                  ldflags: List[str] = None) -> tuple[int, str]:
    # Build the clang command for macOS arm64
    clang = shutil.which("clang") or shutil.which("clang++")
    if clang is None:
        return 2, ''
    cflags = cflags or []
    ldflags = ldflags or []

    # compile each source to object
    objs = []
    for src in sources:
        obj = src.with_suffix(".o")
        cmd = [clang, "-c", str(src), "-o", str(obj)] + cflags
        print("CC:", " ".join(cmd))
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            return 3, f"Compilation failed for '{src}'. stderr: {proc.stderr}"
        objs.append(obj)
    # compile ObjC sources if present (clang compiles .m too)
    for objc in extra_objc:
        obj = objc.with_suffix(".o")
        cmd = [clang, "-c", str(objc), "-o", str(obj)] + cflags + ["-ObjC", "-fobjc-arc"]
        print("CC (ObjC):", " ".join(cmd))
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            return 4, f"ObjC compilation failed for '{objc}'. stderr: proc.stderr"
        objs.append(obj)
    # link
    out = str(output_path / "compiled")
    link_cmd = [clang] + [str(o) for o in objs] + ["-o", out] + ldflags + ["-framework", "Cocoa"]
    print("LD:", " ".join(link_cmd))
    proc = subprocess.run(link_cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return 5, f"Link failed stderr: {proc.stderr}"
    return 0, ''


def generate_sources_from_callmap(callmap: List[Dict[str, Any]], workdir: Path) -> Dict[str, Any]:
    """
    Create C & ObjC source files in workdir based on callmap entries.
    Returns a dict with lists of generated source paths and the list of function names.
    """
    workdir.mkdir(parents=True, exist_ok=True)
    objc_file = workdir / "generated_calls.m"
    header_file = workdir / "generated_calls.h"

    func_calls = []  # In the main
    c_bodies = []  # In the generated_calls.c
    objc_decls = []
    objc_bodies = []

    # We will produce a simple header forward declarations for both C and ObjC functions
    for idx, entry in enumerate(callmap):  # will end up in the header file
        fn = f"call_{idx}"
        func_calls.append(f"    {fn}();")
        # prefer C snippet if available
        code_c = entry.get("code_c")
        code_objc = entry.get("code_objc")

        if code_c and isinstance(code_c, str) and code_c.strip():
            body = render_c_safe_snippet(code_c, indent=4)
            c_bodies.append(C_STUB_WRAPPER.format(fn_name=fn, body=body))

        elif code_objc and isinstance(code_objc, str) and code_objc.strip():
            # create a tiny C wrapper that calls an ObjC function implemented in .m
            objc_fn = f"{fn}_objc_impl"

            # Forward-declare the ObjC bridge function in C and declare wrapper
            c_body = f'    // Bridge to ObjC implementation\n    extern void {objc_fn}(void);\n    {objc_fn}();\n'
            c_bodies.append(C_STUB_WRAPPER.format(fn_name=fn, body=c_body))

            # Add Objective-C implementation
            objc_impl = '\n'.join([line for line in (code_objc.splitlines())])
            objc_body = f'void {objc_fn}(void) {{\n{objc_impl}\n}}\n'
            objc_bodies.append(objc_body)
            objc_decls.append(f"void {objc_fn}(void)" + "{};")

        else:
            # fallback: print the json_repr; safe stub
            ir_label = str(entry.get("ir", "(no-ir)"))
            dll_label = str(entry.get("dll", "(no-dll)"))
            func_label = str(entry.get("func", "(no-func)"))
            conf_label = str(entry.get("confidence", "unknown"))
            jr = entry.get("json_repr") or entry.get("params") or entry.get("action_type") or {}
            jr_s = json.dumps(jr, ensure_ascii=False)

            body = (
                f'    printf("CALL {idx}: IR={ir_label} DLL={dll_label} FUNC={func_label} CONF={conf_label}\\n");\n'
                f'    printf("  json: {clean_dictionary(jr_s)}\\n");\n'
            )
            c_bodies.append(C_STUB_WRAPPER.format(fn_name=fn, body=body))

    # Write ObjC file if needed
    if objc_bodies:
        with open(objc_file, "w", encoding="utf-8") as of:
            # Objective-C file header
            of.write('#import <Foundation/Foundation.h>\n#import <Cocoa/Cocoa.h>\n')
            for b in objc_bodies:
                of.write(b + "\n")
    else:
        objc_file = None

    return {
        'c_bodies': c_bodies,
        'objc_file': objc_file,
        'header_file': header_file,
        'func_calls': func_calls,
        'count': len(callmap)
    }


def build_main_and_compile(sources_info: Dict[str, Any], out_path: Path, workdir: Path) -> tuple[int, str]:
    # create main.c using decls and calls
    calls = "\n".join(sources_info['func_calls'])
    bodies = "\n".join(sources_info['c_bodies'])
    main_c = workdir / 'main.c'
    with open(main_c, 'w', encoding='utf-8') as mf:
        mf.write(MAIN_HEADER.format(funcs=bodies, calls=calls))
    # prepare compile lists
    objc_sources = []
    if sources_info.get('objc_file'):
        objc_sources.append(sources_info['objc_file'])
    # compile
    code, message = compile_macos(out_path, [main_c], objc_sources, cflags=MACOS_CFLAGS, ldflags=MACOS_LDFLAGS)
    return code, message


def load_callmap(path: Path) -> List[Dict[str, Any]]:
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    # Expecting list; if dict with 'callmap' key, support it
    if isinstance(data, dict) and 'callmap' in data:
        return data['callmap']
    if isinstance(data, list):
        return data
    raise RuntimeError('Unexpected JSON layout: expected list of call entries or {callmap: [...] }')


def generate_code(callmap: str, workdir: str):
    callmap_path = Path(callmap)
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    # Load callmap
    try:
        callmap = load_callmap(callmap_path)
    except Exception as e:
        print('Failed to load callmap:', e, file=sys.stderr);
        return 10

    # Generate sources
    print(f'Generating C/ObjC sources in {workdir} for {len(callmap)} entries...')
    src_info = generate_sources_from_callmap(callmap, workdir)
    print('Generated:', src_info)
    return src_info


def build_exec(output_path: str, workdir: str, src_info, target: str, clang: str) -> tuple[int, str]:
    out_path = Path(output_path)

    # Build for macOS arm64
    if target == 'macos-aarch64':
        # check clang exists
        if not ensure_tool_exists(clang):
            return 20, f"Clang not found at '{clang}' or in PATH. Please install Xcode command line tools."
        rc, message = build_main_and_compile(src_info, out_path, workdir)
        if rc != 0:
            print('Build failed with code', rc, file=sys.stderr)
            return rc, message
        print('Build succeeded. Executable at:', out_path)
        return 0, ''
    else:
        return 30, f"Target not implemented yet: {target}"


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Build an executable from translated callmap JSON (macOS arm64 implementation)')
    parser.add_argument('--callmap', '-c', required=True, help='Path to translated callmap JSON (list of entries)')
    parser.add_argument('--out', '-o', default='./out/app_macos_aarch64', help='Output executable path')
    parser.add_argument('--workdir', '-w', default='./build_artifacts',
                        help='Temporary working folder (will be created)')
    parser.add_argument('--target', '-t', default='macos-aarch64', choices=['macos-aarch64'],
                        help='Target platform (currently only macos-aarch64 implemented)')
    parser.add_argument('--clang', default='clang', help='Path to clang if not in PATH')
    args = parser.parse_args(sys.argv[1:])

    sys.exit(generate_code(args.callmap, args.out, args.workdir, args.target, args.clang))
