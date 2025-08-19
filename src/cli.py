#!/usr/bin/env python3
"""
CLI orchestrator per la pipeline:
.exe -> wine log -> full AST (calls.json) -> compact_trace.json -> callmap -> translation_plan -> out/project (translated_replayer)

Esempi:
  python src/cli.py sample.exe
  python src/cli.py sample.exe --build              # prova a compilare automaticamente (se cmake/make presenti)
  python src/cli.py sample.exe --force --no-build  # rigenera tutto ma non compila
"""
import argparse
import sys
import os
from pathlib import Path

# wine parser/runner
from analyzer_dynamic.wine_runner import WineRunner
from analyzer_dynamic.wine_parser import WineParser

# trace compactor helper
import analyzer_dynamic.trace_compactor as trace_compactor

# pipeline helpers (assumo che i moduli siano presenti come prima)
import callmap.builder as callmap_builder
import callmap.translator as callmap_translator
import callmap.binary_builder as binary_builder

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def run_pipeline(
    exe_path: str,
    *,
    wine_debug: str = "relay",
    output_dir: str = "reports",
    stubs_out: str = "out/stubs",
    project_out: str = "out/project",
    force: bool = False,
    build: bool = False
):
    # prepare dirs & paths
    out_dir = Path(output_dir)
    ensure_dir(out_dir)
    wine_logs_dir = out_dir / "wine_logs"
    callmaps_dir = out_dir / "callmaps"
    ensure_dir(wine_logs_dir)
    ensure_dir(callmaps_dir)
    ensure_dir(Path(stubs_out))
    ensure_dir(Path(project_out))

    # filenames
    full_ast_path = callmaps_dir / "calls.json"               # full AST
    compact_path  = callmaps_dir / "compact_trace.json"       # compact
    callmap_path  = callmaps_dir / "callmap.json"             # callmap
    plan_path     = callmaps_dir / "translation_plan.json"    # translator plan

    # 1) run wine and produce log
    runner = WineRunner(output_dir=str(wine_logs_dir))
    print(f"[1/7] Running {exe_path} under Wine (debug={wine_debug})...")
    log_file = runner.run_with_debug(exe_path, args=None, debug_channel=wine_debug)
    print(f"    -> log: {log_file}")

    # 2) parse with WineParser -> ExecutionTrace, save full AST
    print("[2/7] Parsing wine log to ExecutionTrace (full AST)...")
    wp = WineParser(log_file)
    exec_trace = wp.parse()
    if full_ast_path.exists() and not force:
        print(f"    - full AST already exists at {full_ast_path} (use --force to overwrite). Skipping save.")
    else:
        wp.save_as_json(str(full_ast_path), exec_trace)
        print(f"    -> saved full AST to {full_ast_path}")

    # 3) compact trace
    print("[3/7] Producing compact trace (smaller, filtered) ...")
    if compact_path.exists() and not force:
        print(f"    - compact trace already exists at {compact_path} (use --force to overwrite). Skipping compaction.")
    else:
        trace_compactor.save_compact_json(exec_trace, str(compact_path))
        print(f"    -> saved compact trace to {compact_path}")

    # 4) build callmap from compact trace
    print("[4/7] Building callmap from compact trace ...")
    cm = callmap_builder.build_callmap_from_compact(str(compact_path))
    callmap_builder.save_callmap(cm, str(callmap_path))
    print(f"    -> callmap written to {callmap_path}")

    # 5) translation plan & stub generation
    print("[5/7] Generating translation plan and C stubs ...")
    plan = callmap_translator.plan_from_compact(str(compact_path))
    # save plan
    os.makedirs(os.path.dirname(str(plan_path)), exist_ok=True)
    callmap_translator.save_plan(plan, str(plan_path))
    # write stubs (only for mapped apis)
    callmap_translator.write_stubs(plan, stubs_out)
    print(f"    -> translation plan: {plan_path}")
    print(f"    -> stubs written to: {stubs_out}")

    # 6) generate binary replayer project (trace.script + sources + CMake)
    print("[6/7] Generating replayer project (C sources + CMake) ...")
    # binary_builder.build_project will also report mismatches
    binary_builder.build_project(str(compact_path), str(plan_path), project_out, auto_build=build)
    print(f"    -> project generated in {project_out}")

    # 7) post-checks & final message
    replayer_bin = Path(project_out) / "translated_replayer"
    if build and replayer_bin.exists():
        print(f"[7/7] Build requested and binary seems present: {replayer_bin}")
    else:
        print("[7/7] Pipeline finished. To compile the replayer on macOS (arm64):")
        print(f"    cd {project_out} && cmake -DCMAKE_OSX_ARCHITECTURES=arm64 . && make")
        print(f"    then run: ./translated_replayer trace.script")

    print("\nNota: alcune API (es. USER32/GDI) spesso non sono mappate automaticamente.")
    print("Se vedi messaggi '[replayer] unmapped api ...' implementa le funzioni corrispondenti in " + stubs_out)

def main(argv):
    ap = argparse.ArgumentParser(description="Orchestrator: .exe -> translated_replayer")
    ap.add_argument("exe", help="Percorso al file .exe Windows da analizzare")
    ap.add_argument("--debug", default="relay", help="WINEDEBUG channel (default: relay)")
    ap.add_argument("--out", default="reports", help="Directory base per i report (default: reports/)")
    ap.add_argument("--stubs-out", default="out/stubs", help="Directory dove scrivere gli stub C")
    ap.add_argument("--project-out", default="out/project", help="Directory progetto replayer")
    ap.add_argument("--build", action="store_true", help="Se passato prova a lanciare cmake && make alla fine (solo su macOS)")
    ap.add_argument("--force", action="store_true", help="Forza sovrascrittura dei file intermedi")
    args = ap.parse_args(argv)

    if not Path(args.exe).exists():
        print(f"[ERROR] exe file not found: {args.exe}", file=sys.stderr)
        return 2

    try:
        run_pipeline(
            args.exe,
            wine_debug=args.debug,
            output_dir=args.out,
            stubs_out=args.stubs_out,
            project_out=args.project_out,
            force=args.force,
            build=args.build
        )
    except Exception as e:
        print("[ERROR] Pipeline failed:", e, file=sys.stderr)
        raise

if __name__ == "__main__":
    main(sys.argv[1:])
