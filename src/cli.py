#!/usr/bin/env python3
import argparse
import os
from analyzer_dynamic.wine_runner import WineRunner
from analyzer_dynamic.wine_parser import WineParser

def main():
    parser = argparse.ArgumentParser(
        description="CLI per eseguire programmi Windows con Wine e parsare le chiamate API"
    )
    parser.add_argument("exe", help="Percorso al programma Windows (exe)")
    parser.add_argument("--args", nargs=argparse.REMAINDER, help="Argomenti da passare all'exe")
    parser.add_argument("--debug", default="relay", help="Canale WINEDEBUG (default: relay)")
    parser.add_argument("--json-out", default="wine_calls.json", help="File JSON di output")

    args = parser.parse_args()

    # 1. Avvia WineRunner
    runner = WineRunner()
    print(f"[+] Eseguo {args.exe} con Wine (debug={args.debug})...")
    log_file = runner.run_with_debug(args.exe, args=args.args, debug_channel=args.debug)
    print(f"[+] Log generato: {log_file}")

    # 2. Parser log con WineParser
    parser = WineParser(log_file)
    parser.parse()
    parser.save_as_json(args.json_out)

    print(f"[+] Chiamate salvate in {args.json_out}")

if __name__ == "__main__":
    main()
