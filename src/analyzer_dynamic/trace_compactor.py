# callmap/trace_compactor.py
import json
from dataclasses import asdict
from typing import Dict, Any
from src.analyzer_dynamic.wine_parser import ExecutionTrace, CallNode

# --- Lista funzioni interessanti (estendibile) ---
INTERESTING_FUNCTIONS = {
    "KERNEL32!LoadLibraryA",
    "KERNEL32!LoadLibraryW",
    "KERNEL32!LoadLibraryExA",
    "KERNEL32!LoadLibraryExW",
    "KERNEL32!GetProcAddress",
    "KERNEL32!CreateFileA",
    "KERNEL32!CreateFileW",
    "KERNEL32!ReadFile",
    "KERNEL32!WriteFile",
    "KERNEL32!CloseHandle",
    "USER32!CreateWindowExA",
    "USER32!CreateWindowExW",
    "USER32!DispatchMessageA",
    "USER32!DispatchMessageW",
    "GDI32!BitBlt",
    "GDI32!StretchBlt",
    # TODO: did i include every important windows API function?
}


def is_interesting(call: CallNode) -> bool:
    """Verifica se la funzione è da mantenere."""
    key = f"{call.module.upper()}!{call.function}"
    return key in INTERESTING_FUNCTIONS


def compact_execution_trace(exec_trace: ExecutionTrace) -> Dict[str, Any]:
    """
    Crea una versione ridotta dell'ExecutionTrace
    mantenendo solo le chiamate "interessanti".
    """
    compact_threads = []

    for thread in exec_trace.threads:
        compact_calls = []

        def collect(c: CallNode):
            if is_interesting(c):
                compact_calls.append({
                    "id": c.id,
                    "module": c.module,
                    "function": c.function,
                    "args": [
                        {
                            "name": a.name,
                            "value": a.value.value if a.value else None,
                            "kind": a.value.kind if a.value else None,
                        }
                        for a in c.args
                    ],
                    "retval": c.retval.value if c.retval else None,
                    "last_error": c.last_error,
                    "ts_start": c.ts_start,
                    "ts_end": c.ts_end,
                })
            # continua nei figli
            for ch in c.children:
                collect(ch)

        for root in thread.root_calls:
            collect(root)

        if compact_calls:
            compact_threads.append({
                "tid": thread.tid_hex,
                "calls": compact_calls
            })

    return {
        "metadata": exec_trace.metadata,
        "threads": compact_threads,
        "dynamic_modules": exec_trace.dynamic_modules,
        "dynamic_symbols": exec_trace.dynamic_symbols,
    }


def save_compact_json(exec_trace: ExecutionTrace, out_file: str):
    """Salva la versione compatta su file JSON."""
    compact = compact_execution_trace(exec_trace)
    with open(out_file, "w") as f:
        json.dump(compact, f, indent=2)


# --- Uso standalone ---
if __name__ == "__main__":
    import argparse
    from wine_parser import WineParser

    parser = argparse.ArgumentParser(description="Compatta un ExecutionTrace in versione ridotta")
    parser.add_argument("logfile", help="File di log generato da Wine")
    parser.add_argument("--out", default="compact_trace.json", help="File JSON compatto di output")
    args = parser.parse_args()

    wp = WineParser(args.logfile)
    trace = wp.parse()
    save_compact_json(trace, args.out)
    print(f"[+] Traccia compatta salvata in {args.out}")
