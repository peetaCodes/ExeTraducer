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
from pathlib import Path
from types import TracebackType as Traceback
from traceback import print_exception

from analyzer_static.callmap_builder import PEAnalyzer

# Custom exception handling (doesn't show the Traceback if a custom exception was raised)
def ExeTraducerExceptionHandler(e_type:Exception, value, actual_traceback:Traceback):
    traceback = None if e_type.__name__ == 'ExeTraducerError' else actual_traceback
    print_exception(e_type, value, traceback, file=sys.stderr, colorize=True)

# Custom exception
class ExeTraducerError(Exception):
    def __init__(self, message, error_code):
        super().__init__(message)
        self.error_code = error_code
        self.message = message

    def __str__(self):
        return f"{self.message} (Error Code: {self.error_code})"

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def run_pipeline(
    exe_path: str,
    *,
    junk_out: str = "reports",
    project_out: str = "out/project",
    verbose: bool = False,
    min_wide: int = 4,
    min_ascii: int = 4,
    allow_emulation: bool = False,
    force: bool = False,
    build: bool = False
):
    # prepare dirs & paths
    out_dir = Path(junk_out)
    ensure_dir(out_dir)
    pe_callmap_logs_dir = out_dir / "pe_analyzer_logs"
    callmaps_dir = out_dir / "callmaps"
    ensure_dir(callmaps_dir)
    ensure_dir(Path(project_out))

    # filenames (paths)
    callmap_path  = callmaps_dir / "callmap.json" # callmap

    # Utility dicts
    FILE_ERROR_CODES: dict = {
        1701: ("callmap.json",pe_callmap_logs_dir),
        1702: ("callmap_ascii_strings.json", pe_callmap_logs_dir),
        1703: ("callmap_wide_strings.json", pe_callmap_logs_dir),
    }

    # 1) Build the callmap by analyzing the PE
    pe_analyzer = PEAnalyzer(verbose=verbose, log=verbose, log_dir=pe_callmap_logs_dir)
    status = pe_analyzer.analyze_pe(exe_path, out_json=callmap_path, min_wide=min_wide, min_ascii=min_ascii, allow_emulation=allow_emulation, force=force)
    if status == 0: print(f"    -> log: {pe_analyzer.LOG_FILE}")
    else:
        raise ExeTraducerError(f"File '{FILE_ERROR_CODES[status][0]}' already exists at '{FILE_ERROR_CODES[status][1]}'. Use --force to overwrite the file in the next execution",status)


def main(argv):
    parser = argparse.ArgumentParser(description=".exe File Translator ffrom Linux and macOS")
    parser.add_argument("exe", help="Path to the .exe file")
    parser.add_argument("--junk-out", help="Intermediate JSON archives AND logs path. ANy of the files in this folder can be deleted after execution", default="../reports/")
    parser.add_argument("--project-out", default="out/project", help="Converted .exe path")
    parser.add_argument("--min-wide", type=int, default=4, help="Minimum UTF-16 wide string length")
    parser.add_argument("--min-ascii", type=int, default=4, help="Minimum ASCII string length")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--allow-emulation", action="store_true", help="""If passed it will allow the program to emulate part of the PE if the confidence is low.
    Emulating may create un-trusty results, but it's likely that it will actually improve the final result;
    as it will (try to) re-create parts of the PE that couldn't be understood.
    The program will still prefer to not emulate when possible, even if --allow-emulation is passed.""")
    parser.add_argument("--log", action="store_true",help="If passed the script will create a log inf the --log-dir directory")
    parser.add_argument("--build", action="store_true",help="If passed the script will try to run cmake && make at the end automatically (currently macOS only)")
    parser.add_argument("--force", action="store_true", help="If passed the program will continue even if it already found files from previous executions")
    args = parser.parse_args(argv)

    sys.excepthook = ExeTraducerExceptionHandler

    if not Path(args.exe).exists():
        raise ExeTraducerError(f".exe file not found: '{args.exe}'.", 2)

    try:
        run_pipeline(
            args.exe,
            junk_out=args.junk_out,
            project_out=args.project_out,
            verbose=args.verbose,
            min_wide=args.min_wide,
            min_ascii=args.min_ascii,
            allow_emulation=args.allow_emulation,
            force=args.force,
            build=args.build
        )
    except Exception as e:
        print("[ERROR] Pipeline failed:", e, file=sys.stderr)
        raise

if __name__ == "__main__":
    main(sys.argv[1:])
