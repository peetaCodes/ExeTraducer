#!/usr/bin/env python3
"""
Global frontend CLI for ExeTraducer.

Place this file at: src/cli.py

This script calls your existing CLIs by running them as subprocesses:
 - src/disassembler CLI (expected as a Python script under src/disassembler/)
 - src/IR CLI (expected as a Python script under src/IR/)

It will try several likely locations for each CLI (cli.py, __main__.py,
__init__.py) and fall back to invoking via -m if appropriate.

Usage examples:

# Disassemble a PE (re-uses your disassembler CLI)
python src/cli.py disassemble --pe path/to/file.exe --outdir work/output_dir

# Convert an assembly text file to IR (re-uses your IR CLI)
python src/cli.py asm2ir --in work/output_dir/MyExe_native.asm --out work/MyExe.ir.json --db translation_tables.db

# Full pipeline: disassemble and convert to IR
python src/cli.py translate-pe --pe file.exe --outdir work/out --db /path/translation_tables_x86_64.db --arch x86_64
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

PY = sys.executable or "python3"


def _invoke_script(script_path: Path, args: List[str], cwd: Optional[Path] = None, verbose: bool = True) -> int:
    """
    Run `sys.executable script_path args...` with optional cwd.
    Prints stdout/stderr and returns exit code.
    """
    cmd = [PY, str(script_path)] + args
    if verbose:
        print(f"> running: {' '.join(cmd)}  (cwd={cwd or Path.cwd()})")
    proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True)
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    return proc.returncode


def _invoke_module(module_name: str, args: List[str], cwd: Optional[Path] = None, verbose: bool = True) -> int:
    """
    Run `python -m module_name args...` with optional cwd.
    """
    cmd = [PY, "-m", module_name] + args
    if verbose:
        print(f"> running: {' '.join(cmd)}  (cwd={cwd or Path.cwd()})")
    proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True)
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    return proc.returncode


def _locate_and_run(package: str, subargs: List[str], cwd: Optional[Path], verbose: bool = True) -> int:
    """
    Try to find the package CLI script and run it. Fallback to -m <package> if not found.
    """
    script = Path('src') / package / "cli.py"
    if script:
        return _invoke_script(script, subargs, cwd=cwd, verbose=verbose)
    # fallback to python -m src.<package> or python -m <package>
    # we try 'src.<package>' first (package under src/), then package itself.
    mod_try = f"src.{package}"
    rc = _invoke_module(mod_try, subargs, cwd=cwd, verbose=verbose)
    if rc == 0:
        return rc
    # try plain package
    return _invoke_module(package, subargs, cwd=cwd, verbose=verbose)


def cmd_disassemble(args) -> int:
    """
    Reuse the disassembler CLI to disassemble a PE.
    Because your disassembler writes into the current working directory (it
    expects an 'output' folder by default), we run it with cwd set to the
    requested outdir so its outputs appear there.
    """
    pe = Path(args.pe)
    if not pe.exists():
        print("PE file not found:", pe, file=sys.stderr)
        return 2
    outdir = Path(args.outdir or ".").resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    # run the disassembler package (expected under src/disassembler)
    # the disassembler CLI in your project expects: disassembler <path_to_pe>
    disassembler_pkg = "disassembler"  # corresponds to src/disassembler
    subargs = [str(pe)]

    rc = _locate_and_run(disassembler_pkg, subargs, cwd=outdir, verbose=not args.quiet)
    if rc != 0:
        print("Disassembler failed with exit code", rc, file=sys.stderr)
        return rc

    print("Disassembly finished. Outputs are in:", outdir)
    return 0


def cmd_asm2ir(args) -> int:
    """
    Reuse the IR CLI to convert an assembly file to IR JSON.
    Calls the IR CLI's asm2ir command and forwards DB/tables/arch arguments.
    """
    asm_in = Path(args.infile)
    if not asm_in.exists():
        print("Assembly file not found:", asm_in, file=sys.stderr)
        return 2
    outjson = Path(args.outfile)
    outjson.parent.mkdir(parents=True, exist_ok=True)

    ir_pkg = "IR"  # corresponds to src/IR (module name in your repo)
    subargs = ["asm2ir", "--in", str(asm_in), "--out", str(outjson)]
    if args.arch:
        subargs += ["--arch", args.arch]
    if args.db:
        subargs += ["--db", args.db]
    if args.tables:
        subargs += ["--tables", args.tables]
    if args.func:
        subargs += ["--func", args.func]
    if args.no_validate:
        subargs += ["--no-validate"]

    rc = _locate_and_run(ir_pkg, subargs, cwd=None, verbose=not args.quiet)
    if rc != 0:
        print("asm2ir failed with exit code", rc, file=sys.stderr)
        return rc

    print("Assembly translated to IR JSON:", outjson)
    return 0


def cmd_translate_pe(args) -> int:
    """
    Full pipeline: disassemble PE (into outdir) then run asm2ir on the produced asm.
    - We run the disassembler with cwd=outdir so it writes outputs there.
    - The disassembler produces <base>_native.asm; we then call asm2ir on that file.
    """
    pe = Path(args.pe)
    if not pe.exists():
        print("PE file not found:", pe, file=sys.stderr)
        return 2
    outdir = Path(args.outdir or tempfile.mkdtemp(prefix="etr_")).resolve()
    if outdir.exists() and any(outdir.iterdir()) and not args.force:
        print(f"Output directory {outdir} exists and is not empty (use --force to overwrite).", file=sys.stderr)
        return 3
    outdir.mkdir(parents=True, exist_ok=True)

    # 1) run disassembler with cwd=outdir
    disassembler_pkg = "disassembler"
    subargs = [str(pe)]
    rc = _locate_and_run(disassembler_pkg, subargs, cwd=Path(os.getcwd()), verbose=not args.quiet)
    if rc != 0:
        print("Disassembler failed; aborting pipeline.", file=sys.stderr)
        return rc

    # derive base filename and expected asm output
    base = pe.stem
    asm_fname = outdir / f"{base}_native.asm"
    if not asm_fname.exists():
        # the disassembler may use a different naming scheme (or nested 'output' dir).
        # try outdir/output/<base>_native.asm or outdir/<base>_native.asm
        alt = outdir / "output" / f"{base}_native.asm"
        if alt.exists():
            asm_fname = alt
        else:
            # try to find any *_native.asm in outdir subtree
            found = list(outdir.glob("**/*_native.asm"))
            if found:
                asm_fname = found[0]
            else:
                print("Could not find the generated assembly file in", outdir, file=sys.stderr)
                return 4

    # 2) run asm2ir on the found asm
    ir_out = outdir / f"{base}.ir.json"

    # build command-line args for asm2ir
    asm2ir_args = ["asm2ir", "--in", str(asm_fname), "--out", str(ir_out)]
    if args.arch:
        asm2ir_args += ["--arch", args.arch]
    if args.db:
        asm2ir_args += ["--db", args.db]
    if args.tables:
        asm2ir_args += ["--tables", args.tables]
    if not args.validate:
        asm2ir_args += ["--no-validate"]

    rc = _locate_and_run("IR", asm2ir_args, cwd=None, verbose=not args.quiet)
    if rc != 0:
        print("asm2ir failed; pipeline incomplete.", file=sys.stderr)
        return rc

    print("Pipeline completed. IR file:", ir_out)
    if args.open:
        try:
            # attempt to open the IR JSON with system default app (best-effort)
            if sys.platform == "darwin":
                subprocess.run(["open", str(ir_out)])
            elif sys.platform == "win32":
                os.startfile(str(ir_out))  # type: ignore
            else:
                subprocess.run(["xdg-open", str(ir_out)])
        except Exception:
            pass
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="etr", description="ExeTraducer global CLI (disassembler + IR)")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_dis = sub.add_parser("disassemble", help="Run the disassembler CLI on a PE")
    p_dis.add_argument("--pe", required=True, help="Path to PE file")
    p_dis.add_argument("--outdir", required=False, help="Directory to write disassembly outputs (cwd for disassembler)")
    p_dis.add_argument("--quiet", action="store_true", help="Suppress verbose subprocess prints")
    p_dis.set_defaults(func=cmd_disassemble)

    p_a2i = sub.add_parser("asm2ir", help="Run the IR CLI's asm2ir command")
    p_a2i.add_argument("--in", dest="infile", required=True, help="Assembly text file (one instruction per line)")
    p_a2i.add_argument("--out", dest="outfile", required=True, help="Output IR JSON file")
    p_a2i.add_argument("--arch", required=False, help="Source architecture (default x86_64)")
    p_a2i.add_argument("--db", required=False, help="Path to translation_tables.db (SQLite)")
    p_a2i.add_argument("--tables", required=False, help="Path to directory with per-arch JSON tables (fallback)")
    p_a2i.add_argument("--func", required=False, help="Function name to use in IR (default @translated)")
    p_a2i.add_argument("--no-validate", dest="no_validate", action="store_true",
                       help="Do not validate final JSON against schema")
    p_a2i.add_argument("--quiet", action="store_true", help="Suppress verbose subprocess prints")
    p_a2i.set_defaults(func=cmd_asm2ir)

    p_tr = sub.add_parser("translate-pe",
                          help="Full pipeline: disassemble a PE and translate the generated asm into IR")
    p_tr.add_argument("--pe", required=True, help="Path to PE file")
    p_tr.add_argument("--outdir", required=False, help="Directory to place outputs (defaults to temporary dir)")
    p_tr.add_argument("--arch", required=False, help="Source architecture for asm2ir (default x86_64)")
    p_tr.add_argument("--db", required=False, help="Path to translation_tables.db (SQLite)")
    p_tr.add_argument("--tables", required=False, help="Path to directory with per-arch JSON tables (fallback)")
    p_tr.add_argument("--no-validate", dest="validate", action="store_false",
                      help="Do not validate final JSON against schema")
    p_tr.add_argument("--force", action="store_true", help="Allow non-empty outdir to be overwritten")
    p_tr.add_argument("--open", action="store_true", help="Open resulting IR file with default app (best-effort)")
    p_tr.add_argument("--quiet", action="store_true", help="Suppress verbose subprocess prints")
    p_tr.set_defaults(func=cmd_translate_pe, validate=True, quiet=False)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
