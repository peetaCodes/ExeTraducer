import os
from pe_analyzer import PEAnalyzer
from dynamic_loader import DynamicLoaderAnalyzer



def analyze_pe_recursive(pe_path, analyzed_files=None, depth=0):
    """
    Analizza un PE (exe o dll) e stampa le dipendenze ad albero.
    """
    if analyzed_files is None:
        analyzed_files = set()

    abs_path = os.path.abspath(pe_path)
    if abs_path in analyzed_files:
        return

    indent = "  " * depth
    print(f"{indent}- {os.path.basename(abs_path)}")
    analyzed_files.add(abs_path)

    try:
        # Static imports
        pe_analyzer = PEAnalyzer(pe_path)
        imported = pe_analyzer.get_imported_apis()
        if imported:
            print(f"{indent}  [Import statici]:")
            for dll, func in imported:
                print(f"{indent}    {dll} -> {func}")

        # Dynamic analysis
        dyn_loader = DynamicLoaderAnalyzer(pe_analyzer.pe)
        all_calls = dyn_loader.find_calls_to_functions()
        if all_calls:
            print(f"{indent}  [Chiamate dirette/indirette]:")
            for addr, func in all_calls:
                print(f"{indent}    0x{addr:X} -> {func}")

        # LoadLibrary / GetProcAddress
        dynamic_calls = dyn_loader.find_loadlibrary_getprocaddress_strings()
        dlls = [func for _, func in dynamic_calls if func.lower().startswith("loadlibrary")]
        funcs = [func for _, func in dynamic_calls if func.lower().startswith("getprocaddress")]

        if dlls:
            print(f"{indent}  [Possibili DLL caricate dinamicamente]:")
            for d in dlls:
                print(f"{indent}    {d}")
        if funcs:
            print(f"{indent}  [Possibili funzioni risolte dinamicamente]:")
            for f in funcs:
                print(f"{indent}    {f}")

        # Ricorsione sulle DLL individuate
        base_dir = os.path.dirname(abs_path)
        for dll_name in dlls:
            dll_path = os.path.join(base_dir, dll_name)
            if os.path.isfile(dll_path):
                analyze_pe_recursive(dll_path, analyzed_files, depth + 1)
            else:
                print(f"{indent}    [!] DLL non trovata localmente: {dll_name}")

    except Exception as e:
        print(f"{indent}  [ERRORE analisi: {e}]")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python main.py <file.exe>")
        sys.exit(1)

    analyze_pe_recursive(sys.argv[1])
