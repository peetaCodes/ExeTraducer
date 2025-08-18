import os
from pe_analyzer import PEAnalyzer
from dynamic_loader import DynamicLoaderAnalyzer



def analyze_pe_recursive(pe_path, analyzed_files=None):
    if analyzed_files is None:
        analyzed_files = set()

    abs_path = os.path.abspath(pe_path)
    if abs_path in analyzed_files:
        return
    analyzed_files.add(abs_path)

    print(f"\nAnalizzando: {abs_path}")
    pe_an = PEAnalyzer(pe_path)
    imported = pe_an.get_imported_apis()
    print("API importate staticamente:")
    for dll, func in imported:
        print(f"  {dll} -> {func}")

    dyn = DynamicLoaderAnalyzer(pe_an.pe)

    # 1) Chiamate LL/LLEx/GPA con argomenti
    dyn_calls = dyn.find_loadlibrary_getprocaddress_strings()
    print("\nChiamate dinamiche (con argomenti se trovati):")
    for name, arg in dyn_calls:
        print(f"  {name} -> {arg}")

    # 2) Indirizzi chiamate a funzioni interessanti (debug + copertura indirette)
    interesting = ['LoadLibraryA','LoadLibraryW','LoadLibraryExA','LoadLibraryExW','GetProcAddress']
    calls = dyn.find_calls_to_functions(interesting)
    print("\nMappa call a funzioni interessanti:")
    for addr, label in calls:
        print(f"  0x{addr:X} -> {label}")

    # Ricorsione: DLL passate a LoadLibrary*
    base_dir = os.path.dirname(abs_path)
    dlls = set(arg for (fn, arg) in dyn_calls if fn.startswith('LoadLibrary') and arg and arg != "<non trovata>")
    for dll_name in dlls:
        dll_path = os.path.join(base_dir, dll_name)
        if os.path.isfile(dll_path):
            analyze_pe_recursive(dll_path, analyzed_files)
        else:
            print(f"DLL non trovata localmente: {dll_name}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python main.py <file.exe>")
        sys.exit(1)

    analyze_pe_recursive(sys.argv[1])
