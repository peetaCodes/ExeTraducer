from __future__ import annotations
import sys
import os
import json
import pefile

from pathlib import Path

from src.disassembler import (
    extract_imports,
    extract_resources,
    extract_tls,
    disasm_sections,

    is_dotnet,
    dump_dotnet_info,
    dump_pe_header,
)


def _is_empty_dir(path: Path) -> bool:
    return (not any(path.iterdir())) if path.is_dir() else True


def main():
    OUT_DIR = Path("output")
    if not _is_empty_dir(OUT_DIR): print(f"Output directory {os.getcwd() / OUT_DIR} exists and is not empty.",
                                         file=sys.stderr); sys.exit(0)
    OUT_DIR.mkdir(exist_ok=True)

    if len(sys.argv) != 2:
        print("Usage: disassembler <path_to_pe>")
        return
    path = sys.argv[1]
    if not os.path.exists(path):
        print("File not found:", path)
        return
    base = os.path.splitext(os.path.basename(path))[0]
    asm_out = OUT_DIR / f"{base}_native.asm"
    meta_out = OUT_DIR / f"{base}_imports.json"
    dotnet_out = OUT_DIR / f"{base}_dotnet.txt"

    # pefile load
    pe = pefile.PE(path, fast_load=False)
    # save header + sections -> metadata object
    metadata = {}
    try:
        metadata["header"] = dump_pe_header(pe)
    except Exception as e:
        metadata["header"] = {"error": str(e)}
    try:
        metadata.update(extract_imports(pe))
    except Exception as e:
        metadata["imports_error"] = str(e)
    try:
        metadata["resources"] = extract_resources(pe)
    except Exception as e:
        metadata["resources_error"] = str(e)
    try:
        metadata["tls"] = extract_tls(pe)
    except Exception as e:
        metadata["tls_error"] = str(e)
    try:
        # write metadata json
        with open(meta_out, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
        print("Metadata written to", meta_out)
    except Exception as e:
        print("Failed to write metadata:", e)

    # disassemble native code
    try:
        disasm_sections(pe, asm_out)
    except Exception as e:
        print("Error disassembling:", e)

    # dotnet detection + dump
    if is_dotnet(pe):
        print("CLR directory present; extracting .NET method summaries and producing IL-stub IR.")
        from src.IR import extract_dotnet_methods_to_ir, save_ir_json_file
        try:
            dotnet_ir = extract_dotnet_methods_to_ir(path)
            save_ir_json_file(dotnet_ir, OUT_DIR / f"{base}_dotnet.ir.json")
            print("Wrote managed IR to", OUT_DIR / f"{base}_dotnet.ir.json")
        except Exception as e:
            print("Failed to produce managed IR; falling back to dnfile dump:", e)
            dump_dotnet_info(path, dotnet_out)
    else:
        print("Not a .NET assembly (no CLR directory)")

    print("Done.")


if __name__ == '__main__':
    main()
