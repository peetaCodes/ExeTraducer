#!/usr/bin/env python3
"""
disassembler module of ExeTraducer
Single-module tool to:
 - parse PE headers/sections/imports/exports/resources
 - disassemble native executable sections with capstone
 - detect .NET CLR header and dump .NET metadata using dnfile
Outputs:
 - <base>_native.asm
 - <base>_imports.json
 - <base>_dotnet.txt (if managed)
"""
from __future__ import annotations
from datetime import datetime
from pathlib import Path

# try optional libs
try:
    import pefile
except Exception as e:
    print("Missing dependency: pefile (pip install pefile)")
    raise

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
except Exception as e:
    print("Missing dependency: capstone (pip install capstone)")
    raise

# optional enhanced parsers
try:
    import dnfile
except Exception:
    dnfile = None

try:
    import lief
except Exception:
    lief = None


def detect_arch(pe: pefile.PE):
    """Return (capstone_mode, arch_str)"""
    machine = pe.FILE_HEADER.Machine
    # pefile constants: IMAGE_FILE_MACHINE_I386 = 0x14c, AMD64 = 0x8664
    if machine == 0x14c:
        return CS_MODE_32, "x86 (32-bit)"
    elif machine == 0x8664:
        return CS_MODE_64, "x64 (64-bit)"
    else:
        return None, f"unknown: 0x{machine:04x}"


def extract_imports(pe: pefile.PE):
    out = {"imports": [], "delay_imports": [], "exports": None, "iat": []}
    # Normal imports
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="ignore") if entry.dll else ""
            funcs = []
            for imp in entry.imports:
                name = imp.name.decode(errors="ignore") if imp.name else None
                funcs.append({"name": name, "address": hex(imp.address) if hasattr(imp, "address") else None,
                              "hint": getattr(imp, "hint", None)})
            out["imports"].append({"dll": dll, "functions": funcs})
    # Delay imports
    if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            dll = entry.dll.decode(errors="ignore") if entry.dll else ""
            funcs = []
            for imp in entry.imports:
                name = imp.name.decode(errors="ignore") if imp.name else None
                funcs.append(
                    {"name": name, "iat_address": hex(imp.iat_address) if hasattr(imp, "iat_address") else None})
            out["delay_imports"].append({"dll": dll, "functions": funcs})
    # Exports
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        ex = []
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            ex.append({"name": exp.name.decode(errors="ignore") if exp.name else None, "ordinal": exp.ordinal,
                       "address": hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)})
        out["exports"] = ex
    # IAT heuristic
    try:
        for sect in pe.sections:
            name = sect.Name.decode(errors="ignore").strip("\x00")
            if name.lower().startswith(".idata") or name.lower().startswith(".idata"):
                out["iat"].append(
                    {"section": name, "virtual_address": hex(sect.VirtualAddress), "size": hex(sect.Misc_VirtualSize)})
    except Exception:
        pass
    return out


def extract_resources(pe: pefile.PE):
    out = []
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        def recurse_resources(directory, path=""):
            for entry in directory.entries:
                name = None
                if entry.name:
                    try:
                        name = str(entry.name)
                    except Exception:
                        name = None
                id = entry.id
                typ = None
                if entry.struct:
                    typ = entry.struct.Id
                if hasattr(entry, "directory"):
                    recurse_resources(entry.directory, path + f"/{name or id}")
                elif hasattr(entry, "data"):
                    data_rva = entry.data.struct.OffsetToData
                    size = entry.data.struct.Size
                    out.append({"path": path + f"/{name or id}", "rva": hex(data_rva), "size": size})

        try:
            recurse_resources(pe.DIRECTORY_ENTRY_RESOURCE)
        except Exception:
            pass
    return out


def extract_tls(pe: pefile.PE):
    out = {}
    if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS:
        tls = pe.DIRECTORY_ENTRY_TLS.struct
        out["start_address_of_raw_data"] = hex(getattr(tls, "StartAddressOfRawData", 0))
        out["end_address_of_raw_data"] = hex(getattr(tls, "EndAddressOfRawData", 0))
        callbacks = []
        try:
            # pefile usually exposes callbacks array in DIRECTORY_ENTRY_TLS
            callbacks_raw = pe.DIRECTORY_ENTRY_TLS.callbacks
            for cb in callbacks_raw:
                callbacks.append(hex(cb))
        except Exception:
            pass
        out["callbacks"] = callbacks
    return out


def dump_pe_header(pe: pefile.PE):
    h = {}
    h["filename"] = getattr(pe, "name", None)
    h["timestamp"] = datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat() if hasattr(pe.FILE_HEADER,
                                                                                                    "TimeDateStamp") else None
    h["entry_point_rva"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint) if hasattr(pe.OPTIONAL_HEADER,
                                                                                  "AddressOfEntryPoint") else None
    h["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase) if hasattr(pe.OPTIONAL_HEADER, "ImageBase") else None
    h["sections"] = []
    for s in pe.sections:
        name = s.Name.decode(errors="ignore").strip('\x00')
        h["sections"].append({
            "name": name,
            "vaddr": hex(s.VirtualAddress),
            "vsize": hex(s.Misc_VirtualSize),
            "raw_size": hex(s.SizeOfRawData),
            "characteristics": hex(s.Characteristics)
        })
    return h


def disasm_sections(pe: pefile.PE, out_asm_path: Path):
    mode, arch = detect_arch(pe)
    if mode is None:
        print("Unsupported architecture for capstone disasm.")
        return False

    md = Cs(CS_ARCH_X86, mode)
    md.detail = True
    written = 0

    with open(out_asm_path, 'w', encoding='utf-8') as f:
        # Write file information
        f.write(f"; File: {out_asm_path.name.rstrip('_native.asm') + '.exe'}\n")
        f.write(f"; Architecture: {arch}\n")
        f.write(f"; Entry point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08x}\n")
        f.write(f"; ImageBase: 0x{pe.OPTIONAL_HEADER.ImageBase:08x}\n\n")

        # Iterate through each section
        for section in pe.sections:
            if section.IMAGE_SCN_MEM_EXECUTE:  # Check if the section is executable
                section_name = section.Name.decode().strip('\x00')
                f.write(f"\n;{'=' * 50}\n")
                f.write(f";Section: {section_name}\n")
                f.write(f";Virtual Address: 0x{section.VirtualAddress:08x}\n")
                f.write(f";Size: 0x{section.Misc_VirtualSize:08x}\n")
                f.write(f";{'=' * 50}\n\n")

                # Get the section data
                code = section.get_data()

                # Get the virtual address of the section
                address = section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase

                # Disassemble the code
                for insn in md.disasm(code, address):
                    # Format and write the instructions
                    bytes_str = ' '.join([f'{b:02x}' for b in insn.bytes])
                    f.write(f"0x{insn.address:08x}: {bytes_str:24} {insn.mnemonic:8} {insn.op_str}\n")

                    written += 1

    print(f"Disassembled {written} instructions into {out_asm_path}")
    return True


def is_dotnet(pe: pefile.PE):
    # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14 (index), but simplest: check CLR directory
    try:
        # pe.OPTIONAL_HEADER.DATA_DIRECTORY[14] exists for CLR
        dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        return dd.VirtualAddress != 0 and dd.Size != 0
    except Exception:
        return False


def dump_dotnet_info(path: str, out_txt: Path):
    print(out_txt)
    if not dnfile:
        with open(out_txt, "w", encoding="utf-8") as f:
            f.write("dnfile not installed; cannot parse .NET metadata.\n")
            f.write("Install it with: pip install dnfile\n")
        return
    try:
        dpe = dnfile.dnPE(path)
        # dnfile exposes a print_info helper — capture it
        with open(out_txt, "w", encoding="utf-8") as f:
            f.write("=== dnfile metadata print_info() ===\n")
            try:
                # many dnfile objects provide print_info()
                dpe.print_info(file=f)  # noqa
            except TypeError:
                # fallback: write a summary
                f.write(repr(dpe) + "\n")
            # attempt to list method defs (if present)
            try:
                md = getattr(dpe.net, "mdtables", getattr(dpe.net, "mdtables", None))
                if md and hasattr(md, "MethodDef"):
                    f.write("\n=== MethodDef entries ===\n")
                    for m in md.MethodDef.rows:
                        f.write(str(m) + "\n")
                else:
                    # try the common property name used by dnfile
                    if hasattr(dpe.net, "mdtables") and hasattr(dpe.net.mdtables, "MethodDef"):
                        for m in dpe.net.mdtables.MethodDef:
                            f.write(str(m) + "\n")
            except Exception:
                pass
        print(f".NET metadata dumped to {out_txt}")
    except Exception:
        with open(out_txt, "w", encoding="utf-8") as f:
            f.write("Error while using dnfile: " + str(e) + "\n")
