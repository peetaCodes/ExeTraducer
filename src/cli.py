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
from traceback import print_tb, print_exception

from json import loads

from analyzer.callmap_builder import PEAnalyzer
from callmap.translator import BackendTranslator
from callmap.binary_builder import generate_code, build_exec


# Custom exception handler (doesn't show the Traceback if a *custom* exception was raised)
def ExeTraducerExceptionHandler(e_type: Exception, value, traceback: Traceback):
    is_custom: bool = e_type.__name__ == 'ExeTraducerError'

    if is_custom:
        print_exception(e_type, value, None, file=sys.stderr, colorize=True)
    else:
        sys.excepthook(e_type, value, traceback)

# Custom exception
class ExeTraducerError(Exception):
    def __init__(self, message, error_code):
        super().__init__(message, error_code)
        self.__error_code__: int = error_code
        self.__message__ = message

    def __str__(self):
        return f"{self.__message__} (Error Code: {self.__error_code__})"

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def run_pipeline(
    exe_path: str,
    *,
        system: str,
    junk_out: str = "reports",
    project_out: str = "out/project",
        clang_path: str,
    verbose: bool = False,
        log: bool = False,
    min_wide: int = 4,
    min_ascii: int = 4,
    allow_emulation: bool = False,
    force: bool = False,
    build: bool = False
):
    # prepare dirs & paths
    out_dir: Path = Path(junk_out)
    pe_callmap_logs_dir: Path = out_dir / "pe_analyzer_logs"
    callmaps_dir: Path = out_dir / "callmaps"
    code_dir: Path = out_dir / "c_code"
    ensure_dir(out_dir)
    ensure_dir(code_dir)
    ensure_dir(callmaps_dir)
    ensure_dir(Path(project_out))

    # filenames (paths)
    callmap_path  = callmaps_dir / "callmap.json" # callmap
    IR_callmap_path = callmaps_dir / "IR_callmap.json"  # partially translated callmap (intermediate language)
    target_system_callmap_path = callmaps_dir / "target_system_callmap.json"  # completely translated callmap

    # Utility dicts
    FILE_ERROR_CODES: dict[int, tuple[str, Path]] = {
        1701: ("callmap.json",pe_callmap_logs_dir),
        1702: ("callmap_ascii_strings.json", pe_callmap_logs_dir),
        1703: ("callmap_wide_strings.json", pe_callmap_logs_dir),
    }

    total_ops: int = int(build) + 4

    # 1) Build the callmap by analyzing the PE
    # """
    print(f"[1/{total_ops}] Creating callmap")
    pe_analyzer = PEAnalyzer(verbose=verbose, log=log, log_dir=pe_callmap_logs_dir)
    status = pe_analyzer.analyze_pe(exe_path, out_json=callmap_path, min_wide=min_wide, min_ascii=min_ascii, allow_emulation=allow_emulation, force=force)
    if status == 0:
        print(f"    -> file: {callmap_path}");print(f"    -> log: {pe_analyzer.LOG_FILE}")
    else:
        raise ExeTraducerError(f"File '{FILE_ERROR_CODES[status][0]}' already exists at '{FILE_ERROR_CODES[status][1]}'. Use --force to overwrite the file in the next execution",status)
    # """

    # 2) Translate callmap file into IR (intermediate language)
    print(f"[2/{total_ops}] Translating the callmap into IR (intermediate language)")
    translator = BackendTranslator("IR")
    translated = translator.translate_callmap(callmap=loads(callmap_path.read_text('utf-8')))
    translator.emit_json(translated, IR_callmap_path)

    print(f"    -> file: {IR_callmap_path}")

    # 3) Translate the IR callmap into the target system
    print(f"[3/{total_ops}] Translating the callmap into the target system")
    translator = BackendTranslator(system)
    translated = translator.translate_callmap(callmap=translated)
    translator.emit_json(translated, target_system_callmap_path)

    print(f"    -> file: {target_system_callmap_path}")

    # 4) Making source code to simulate the obtained callmap
    print(f"[4/{total_ops}] Writing source code that replicates the translated callmap")
    src_info = generate_code(target_system_callmap_path, workdir=code_dir)

    # 5) Building the binary
    if build:
        print(f"[5/{total_ops}] Compiling the executable")
        status, message = build_exec(output_path=project_out, workdir=code_dir, src_info=src_info, target=system,
                                     clang=clang_path)
        if status != 0: raise ExeTraducerError(message, status)


def main(argv):
    parser = argparse.ArgumentParser(description=".exe File Translator ffrom Linux and macOS")
    parser.add_argument("exe", help="""Path to the .exe file""")
    parser.add_argument("system", choices=[
        "macos-aarch64", "macos-intel_64bit", "macos-intel_32bit", "linux-ARM64", "linux-armv7", "linux-x86",
        "linux-x86_64"],
                        help="""The target system for the translated executable. If you're unsure, there's a table located in help/systems.txt """)
    parser.add_argument("-junk-out", help="""
    Intermediate JSON archives AND logs path. Any of the files in this folder can be deleted after execution", default="/reports/""")
    parser.add_argument("-project-out", default="../out/project", help="""Converted .exe path""")
    parser.add_argument('--clang', default='clang', help="""Path to clang if not in PATH""")
    parser.add_argument("-min-wide", type=int, default=4, help="""Minimum UTF-16 wide string length""")
    parser.add_argument("-min-ascii", type=int, default=4, help="""Minimum ASCII string length""")
    parser.add_argument("--verbose", action="store_true", help="""Enable consol output""")
    parser.add_argument("--allow-emulation", action="store_true", help="""If passed it will allow the program to emulate part of the PE if the confidence is low.
    Emulating may create un-trusty results, but it's likely that it will actually improve the final result;
    as it will (try to) re-create parts of the PE that couldn't be understood.
    The program will still prefer to not emulate when possible, even if --allow-emulation is passed.""")
    parser.add_argument("--log", action="store_true",
                        help="""If passed the script will create a log inf the --log-dir directory""")
    parser.add_argument("--build", action="store_true",
                        help="""If passed the script will try to run cmake && make at the end automatically (currently macOS only)""")
    parser.add_argument("--force", action="store_true",
                        help="""If passed the program will continue even if it already found files from previous executions""")
    args = parser.parse_args(argv)

    sys.excepthook = ExeTraducerExceptionHandler

    if not Path(args.exe).exists():
        raise ExeTraducerError(f".exe file not found: '{args.exe}'.", 2)

    try:
        run_pipeline(
            args.exe,
            system=args.system,
            junk_out=args.junk_out,
            project_out=args.project_out,
            verbose=args.verbose,
            log=args.log,
            min_wide=args.min_wide,
            min_ascii=args.min_ascii,
            allow_emulation=args.allow_emulation,
            force=args.force,
            build=args.build,
            clang_path=args.clang
        )
    except Exception as e:
        if type(e).__name__ == 'ExeTraducerError':
            raise
        else:
            print("[ERROR] Pipeline failed:", type(e).__name__, e.args[0], print_tb(e.__traceback__), file=sys.stderr)

if __name__ == "__main__":
    main(sys.argv[1:])
