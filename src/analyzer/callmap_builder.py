#!/usr/bin/env python3
# pe_callmap_static_v2.py
# TODO: re-make all of this as it is unreliable and just SUCKS
"""
Enhanced prototyping tool for static PE callmap extraction (x86/x64).
Features added compared to earlier prototype:
 - automatic UTF-16 (wide) string extraction across the image
 - improved ASCII string extraction
 - detection of GetProcAddress uses and best-effort static resolution
 - attempts to associate GetProcAddress with preceding LoadLibrary/GetModuleHandle calls
 - better handling of CALL reg where register was loaded from memory pointing at an IAT entry
 - richer callmap entries with confidence levels and evidence (string resolution, linked dll)
 - CLI options for output file and verbosity

Limitations:
 - Static-only heuristics: cannot resolve runtime-generated strings or JIT code
 - Packers/obfuscation/anti-analysis can break heuristics
 - No emulation / symbolic execution implemented here (Unicorn/angr are future steps)
 - Designed as a basis for further improvements and integration into the full pipeline.

Dependencies:
  pip install pefile capstone

Usage:
  python pe_callmap_static_v2.py <path-to-pe> [--out callmap.json] [--min-wide 4] [--min-ascii 4]

Author: prototype mostly by chatGPT; final version (mostly patches) by me
"""

from src.analyzer.snippet_emulator import emulate_snippet

import os, json, argparse, struct
import pefile
from capstone import *
from capstone.x86 import *

from datetime import datetime
from os.path import join as merge
from os import system

# ---------- Utility helpers ----------
def rva_to_offset(pe, rva):
    try:
        return pe.get_offset_from_rva(rva)
    except Exception:
        return None

def offset_to_rva(pe, offset):
    """
    Map a file offset to RVA by scanning sections manually.
    Returns RVA (int) or None if not mappable (overlay / bad offset).
    """
    for sec in pe.sections:
        start = sec.PointerToRawData
        size = sec.SizeOfRawData
        if start <= offset < start + size:
            # RVA = VirtualAddress + (offset - PointerToRawData)
            return sec.VirtualAddress + (offset - start)
    return None

def va_to_rva(pe, va):
    """
    Convert VA -> RVA in modo robusto.
    - se `va` è None o non convertibile, ritorna None.
    - se `va` è una stringa del tipo "file_offset:0x..." tenterà di convertire
      l'offset in RVA tramite offset_to_rva(pe, offset).
    - se `va` è una stringa esadecimale '0x...' la converte in int prima.
    - se il calcolo produce un RVA negativo o non plausibile, ritorna None.
    """
    if va is None:
        return None

    # Gestisci valori stringa generati come fallback (es. "file_offset:0x1234")
    if isinstance(va, str):
        va = va.strip()
        if va.startswith("file_offset:"):
            # non è una VA reale ma un file offset; mappalo in RVA con offset_to_rva
            try:
                off_s = va.split(":", 1)[1]
                offset = int(off_s, 16) if off_s.lower().startswith("0x") else int(off_s, 10)
            except Exception:
                return None
            return offset_to_rva(pe, offset)
        # se è una stringa hex '0x...' la converto a int (suppongo sia una VA)
        if va.lower().startswith("0x"):
            try:
                va = int(va, 16)
            except Exception:
                return None
        else:
            # stringa non riconosciuta: non convertibile
            return None

    # ora va dovrebbe essere un int
    if not isinstance(va, int):
        return None

    # calcola RVA
    try:
        image_base = pe.OPTIONAL_HEADER.ImageBase
    except Exception:
        return None

    rva = va - image_base
    # sanity check: non-negative e non troppo grande
    if rva < 0:
        return None
    # opzionale: controlla che si trovi in qualche sezione o nel file data length
    # if offset_to_rva(pe, ???) not usable here; ma ritornare rva comunque è ok.
    return rva


def read_cstring_at_va(pe, va, maxlen=4096):
    try:
        rva = va - pe.OPTIONAL_HEADER.ImageBase
        data = pe.get_memory_mapped_image()[rva:rva + maxlen]
        s = []
        for b in data:
            if b == 0:
                break
            if 32 <= b < 127:
                s.append(chr(b))
            else:
                break
        return "".join(s)
    except Exception as e:
        print(f"read_cstring_at_va failed for {va:x}: {e}")
        return None

def read_wstring_at_va(pe, va, maxlen=4096):
    rva = va_to_rva(pe, va)
    off = rva_to_offset(pe, rva)
    if off is None:
        return None
    data = pe.__data__[off: off + maxlen]
    # look for two consecutive zero bytes marking end of UTF-16LE string
    for i in range(0, len(data)-1, 2):
        if data[i] == 0x00 and data[i+1] == 0x00:
            # terminate at i (but ensure even length)
            try:
                s = data[:i].decode('utf-16le', errors='replace')
                return s
            except Exception:
                return None
    # fallback: try to decode partial
    try:
        return data.decode('utf-16le', errors='replace').split('\x00',1)[0]
    except Exception:
        return None

def read_cstring_at_offset(pe, offset, maxlen=4096):
    """
    Read a NUL-terminated ASCII/UTF-8 string starting at a file offset.
    Works even for overlay (offset beyond section data), by reading pe.__data__.
    Returns decoded string or None.
    """
    data = pe.__data__
    if offset < 0 or offset >= len(data):
        return None
    chunk = data[offset: offset + maxlen]
    idx = chunk.find(b'\x00')
    if idx == -1:
        return None
    try:
        return chunk[:idx].decode('utf-8', errors='replace')
    except:
        try:
            return chunk[:idx].decode('ascii', errors='replace')
        except:
            return None

def read_wstring_at_offset(pe, offset, maxlen=4096):
    """
    Read UTF-16LE string at file offset (overlay-friendly).
    """
    data = pe.__data__
    if offset < 0 or offset+1 >= len(data):
        return None
    # ensure even start - if offset is odd, it's probably wrong, but we still attempt
    chunk = data[offset: offset + maxlen]
    for i in range(0, len(chunk)-1, 2):
        if chunk[i] == 0x00 and chunk[i+1] == 0x00:
            try:
                return chunk[:i].decode('utf-16le', errors='replace')
            except:
                return None
    try:
        return chunk.decode('utf-16le', errors='replace').split('\x00',1)[0]
    except:
        return None


def format_va(va):
    """
    Normalizza/formatta 'va' per output JSON:
      - se è int -> '0x...' (hex string)
      - se è str e comincia con 'file_offset:' -> restituisce così com'è
      - se è str che sembra '0x...' -> normalizza a hex lower-case (es. '0x401000')
      - se è str vuota o None -> restituisce None (si serializza come null)
      - altrimenti -> restituisce la stringa così com'è (fallback)
    """
    if va is None:
        return None
    # intero
    if isinstance(va, int):
        return hex(va)
    # bytes? converti
    if isinstance(va, bytes):
        try:
            ival = int.from_bytes(va, 'little')
            return hex(ival)
        except Exception:
            try:
                return va.decode('utf-8', errors='ignore')
            except:
                return None
    # stringa
    if isinstance(va, str):
        s = va.strip()
        if s == "":
            return None
        if s.startswith("file_offset:"):
            return s  # keep overlay marker as-is
        if s.lower().startswith("0x"):
            # normalizza (es: '0x001234' -> '0x1234')
            try:
                return hex(int(s, 16))
            except Exception:
                return s
        # otherwise return string as-is (could be a symbol name or other tag)
        return s
    # fallback: try cast
    try:
        return str(va)
    except:
        return None

def byte_to_int(b):
    """
    Normalize a byte-like value to an integer 0-255.
    Compatible with Python3 (iterating bytes yields ints) and edge-cases
    where iterating returns single-byte bytes objects.
    """
    if isinstance(b, int):
        return b
    if isinstance(b, bytes) or isinstance(b, bytearray):
        # single-byte bytes indexing gives int; if b happens to be length>1, take first
        return b[0]
    try:
        return ord(b)
    except Exception:
        return 0

def try_emulate_arg(pe, call_entry, idx):
    """
    Prova a emulare lo snippet relativo a una call sospetta
    e a ricostruire l'argomento idx-esimo (es. stringa passata a GetProcAddress).
    """
    start_va = call_entry.get("addr")
    if not start_va:
        return None

    try:
        result = emulate_snippet(pe, int(start_va, 16), max_insns=500)
    except Exception as e:
        return None

    if not result.get("success"):
        return None

    strings = result.get("strings", [])
    if not strings:
        return None

    # euristica semplice: prendi la stringa più lunga
    best = max(strings, key=lambda s: len(s["s"]))
    return best["s"]

def safe_save(force:bool, filepath:str, content:dict|list[dict]):
    """
    Saves the given data into the given file.
    Keep track of whether it's in force mode
    """
    mode = 'x' if not force else 'w'
    try:
        with open(filepath, mode, encoding='utf-8') as f:
            json.dump(content, f, indent=2, ensure_ascii=False)
        return 0
    except FileExistsError:
        return 1



# ---------- String extraction ----------
def extract_ascii_strings(pe, min_len=4):
    out = []
    data = pe.__data__
    cur = []
    cur_off = None
    for i, b in enumerate(data):
        val = byte_to_int(b)
        if 32 <= val < 127:
            if not cur:
                cur_off = i
            cur.append(chr(val))
        else:
            if cur and len(cur) >= min_len:
                rva = pe.get_rva_from_offset(cur_off)
                if rva is None:
                    rva = offset_to_rva(pe, cur_off)
                if rva is not None:
                    va = pe.OPTIONAL_HEADER.ImageBase + rva
                else:
                    va = f"file_offset:0x{cur_off:x}"
                out.append((va, "".join(cur)))
            cur = []
    # tail
    if cur and len(cur) >= min_len:
        # prova il mapping tramite get_rva_from_offset, ma gestisci fallback
        rva = pe.get_rva_from_offset(cur_off)
        if rva is None:
            # prova mapping manuale dalle sezioni
            rva = offset_to_rva(pe, cur_off)
        if rva is not None:
            va = pe.OPTIONAL_HEADER.ImageBase + rva
            out.append((va, cur.decode('ascii', errors='replace')))
        else:
            # overlay o offset non mappabile: registra come file offset e salva la stringa
            out.append((f"file_offset:0x{cur_off:x}", cur.decode('ascii', errors='replace')))
    return out

def extract_utf16_strings(pe, min_len=4):
    # scan raw bytes for UTF-16LE sequences where high bytes are zero for ASCII-range chars
    out = []
    data = pe.__data__
    i = 0
    while i < len(data) - 1:
        if data[i] >= 32 and data[i + 1] == 0:
            seq_start = i
            j = i + 2
            while j < len(data) - 1 and data[j] >= 32 and data[j + 1] == 0:
                j += 2
            if seq_start is not None and (j - seq_start) // 2 >= min_len:
                rva = pe.get_rva_from_offset(seq_start)
                if rva is None:
                    rva = offset_to_rva(pe, seq_start)
                if rva is not None:
                    va = pe.OPTIONAL_HEADER.ImageBase + rva
                else:
                    va = f"file_offset:0x{seq_start:x}"
                raw = data[seq_start:j]
                try:
                    s = raw.decode('utf-16le', errors='replace')
                except:
                    s = None
                out.append((va, s))
                i = j
            else:
                i += 1
        else:
            i += 1
    return out

# ---------- Import Map ----------
def build_import_map(pe):
    imap = {}
    imports = {}
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return imap, imports
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode('utf-8', errors='ignore').lower()
        for imp in entry.imports:
            if imp.address is None:
                continue
            name = None
            if imp.name:
                name = imp.name.decode('utf-8', errors='ignore')
            else:
                name = f"ordinal_{imp.ordinal}"
            imap[imp.address] = (dll, name)
            imports.setdefault(dll, []).append((imp.address, name))
    return imap, imports

# ---------- Capstone setup ----------
def get_cs(pe):
    if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        arch = 'x64'
    elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        arch = 'x86'
    else:
        raise RuntimeError("Unsupported machine: 0x%x" % pe.FILE_HEADER.Machine)
    md.detail = True
    return md, arch

def mem_operand_target(instr, op, pe, arch):
    # Compute absolute VA of memory operand when possible
    if op.type == X86_OP_MEM:
        base = op.mem.base
        disp = op.mem.disp
        if arch == 'x64' and base == X86_REG_RIP:
            return instr.address + instr.size + disp
        elif arch == 'x86' and base == 0:
            # direct absolute memory
            return disp
    return None

# ---------- Argument recovery (improved) ----------
def recover_args_simple(insns, idx, arch, pe):
    # Returns list of resolved args (strings or hex) in call-site logical order
    args = []
    N = 40
    start = max(0, idx - N)
    if arch == 'x86':
        # push-based
        pushes = []
        for i in range(idx-1, start-1, -1):
            ins = insns[i]
            if ins.mnemonic.startswith('push'):
                # examine operand
                for op in ins.operands:
                    if op.type == X86_OP_IMM:
                        pushes.append(('imm', op.imm))
                    elif op.type == X86_OP_MEM:
                        tgt = mem_operand_target(ins, op, pe, arch)
                        pushes.append(('mem', tgt))
                    elif op.type == X86_OP_REG:
                        pushes.append(('reg', ins.reg_name(op.reg)))
                    else:
                        pushes.append((ins.op_str, None))
            if ins.mnemonic.startswith('call') or ins.mnemonic.startswith('jmp'):
                break
        pushes.reverse()
        # try to resolve mem/imm to strings
        for kind, val in pushes:
            if kind == 'mem' and val:
                s = read_cstring_at_va(pe, val)
                if s:
                    args.append(s)
                    continue
                ws = read_wstring_at_va(pe, val)
                if ws:
                    args.append(ws)
                    continue
                args.append(hex(val))
            elif kind == 'imm':
                if isinstance(val, int) and val > 0x1000:
                    s = read_cstring_at_va(pe, val)
                    if s:
                        args.append(s)
                        continue
                    ws = read_wstring_at_va(pe, val)
                    if ws:
                        args.append(ws)
                        continue
                    args.append(hex(val))
                else:
                    args.append(hex(val))
            else:
                args.append(str(kind))
    else:
        # x64: RCX, RDX, R8, R9
        regs_order = ['rcx','rdx','r8','r9']
        found = {r: None for r in regs_order}
        for i in range(idx-1, start-1, -1):
            ins = insns[i]
            if ins.mnemonic in ('mov','lea'):
                if len(ins.operands) >= 2:
                    dst = ins.operands[0]
                    src = ins.operands[1]
                    if dst.type == X86_OP_REG:
                        regname = ins.reg_name(dst.reg)
                        if regname in regs_order:
                            if src.type == X86_OP_IMM:
                                found[regname] = ('imm', src.imm)
                            elif src.type == X86_OP_MEM:
                                tgt = mem_operand_target(ins, src, pe, arch)
                                found[regname] = ('mem', tgt)
            if ins.mnemonic == 'xor' and len(ins.operands)==2:
                dst = ins.operands[0]; src = ins.operands[1]
                if dst.type == X86_OP_REG and src.type == X86_OP_REG and ins.reg_name(dst.reg)==ins.reg_name(src.reg):
                    regname = ins.reg_name(dst.reg)
                    if regname in regs_order:
                        found[regname] = ('imm', 0)
            if ins.mnemonic.startswith('call') or ins.mnemonic.startswith('jmp'):
                break
        for r in regs_order:
            v = found[r]
            if v is None:
                continue
            kind, val = v
            if kind == 'mem' and val:
                s = read_cstring_at_va(pe, val)
                if s:
                    args.append(s)
                    continue
                ws = read_wstring_at_va(pe, val)
                if ws:
                    args.append(ws)
                    continue
                args.append(hex(val))
            elif kind == 'imm':
                if isinstance(val, int) and val > 0x1000:
                    s = read_cstring_at_va(pe, val)
                    if s:
                        args.append(s); continue
                    ws = read_wstring_at_va(pe, val)
                    if ws:
                        args.append(ws); continue
                    args.append(hex(val))
                else:
                    args.append(hex(val))
            else:
                args.append(str(v))
    return args

# ---------- Heuristic: try to resolve register-based CALL targets ----------
def resolve_call_register(insns, idx, pe, arch, imap):
    # If instruction is 'call rax' or similar, try to find mov rax, [absaddr] previously
    if idx < 0:
        return None
    ins = insns[idx]
    if len(ins.operands)==0:
        return None
    op = ins.operands[0]
    if op.type == X86_OP_REG:
        regname = ins.reg_name(op.reg)
        # scan backwards for mov <reg>, [abs]
        N = 40
        start = max(0, idx - N)
        for i in range(idx-1, start-1, -1):
            prev = insns[i]
            if prev.mnemonic == 'mov' and len(prev.operands)>=2:
                dst = prev.operands[0]; src = prev.operands[1]
                if dst.type==X86_OP_REG and ins.reg_name(dst.reg)==regname and src.type==X86_OP_MEM:
                    tgt = mem_operand_target(prev, src, pe, arch)
                    if tgt and tgt in imap:
                        return imap[tgt]
                    # dereference pointer at tgt to see if it contains IAT pointer
                    off = rva_to_offset(pe, va_to_rva(pe, tgt)) if pe else None
                    if off:
                        try:
                            if arch=='x64':
                                ptr = struct.unpack_from('<Q', pe.__data__, off)[0]
                            else:
                                ptr = struct.unpack_from('<I', pe.__data__, off)[0]
                            if ptr in imap:
                                return imap[ptr]
                        except Exception:
                            pass
    return None

# ---------- GetProcAddress detection & static resolution ----------
def find_getproc_and_resolve(insns, pe, arch, imap, ascii_strings, wide_strings):
    # Find IAT addresses for GetProcAddress / GetProcAddressA / W
    getproc_iats = set()
    for va, (dll, name) in imap.items():
        nl = name.lower()
        if 'getproc' in nl:  # covers GetProcAddressA/W
            getproc_iats.add(va)
    results = []  # list of dicts with resolution info
    addr2idx = {ins.address: idx for idx, ins in enumerate(insns)}
    for idx, ins in enumerate(insns):
        if not ins.mnemonic.startswith('call'):
            continue
        # check memory op targets referencing imap entries
        resolved = None
        for op in ins.operands:
            if op.type==X86_OP_MEM:
                tgt = mem_operand_target(ins, op, pe, arch)
                if tgt and tgt in getproc_iats:
                    resolved = True
                    break
            elif op.type==X86_OP_IMM:
                if op.imm in getproc_iats:
                    resolved = True
                    break
            elif op.type==X86_OP_REG:
                # try resolve register-based call
                r = resolve_call_register(insns, idx, pe, arch, imap)
                if r and (pe.OPTIONAL_HEADER.ImageBase + r[0] if False else True):  # just detect
                    # if register call resolves to getproc IAT, mark resolved
                    # Note: resolve_call_register returns (dll,name) or None, adjust checking
                    pass
        if not resolved:
            # maybe call target is register that we can resolve to IAT; try resolution
            r = resolve_call_register(insns, idx, pe, arch, imap)
            if r and 'getproc' in r[1].lower():
                resolved = True

        if not resolved:
            continue

        # We have a call to GetProcAddress; attempt to recover args
        args = recover_args_simple(insns, idx, arch, pe)
        # For x86 pushes: arg[0] = name, arg[1] = hModule (since pushes are reversed)
        # For x64: args order rcx, rdx,... so args[1] is name (rdx)
        func_name = None
        dll_name = None
        confidence = 'low'
        evidence = []

        # heuristics to get function name
        if arch == 'x86':
            if len(args) >= 1:
                func_name = args[0]
            if len(args) >= 2:
                mod_arg = args[1]
                # if mod_arg is a string VA that points to module name (unlikely), use it
                if isinstance(mod_arg, str) and mod_arg.startswith('0x'):
                    # try reading as string
                    try:
                        va = int(mod_arg, 16)
                        s = read_cstring_at_va(pe, va)
                        ws = read_wstring_at_va(pe, va)
                        if s:
                            dll_name = s.lower()
                        elif ws:
                            dll_name = ws.lower()
                    except Exception:
                        pass
        else:
            if len(args) >= 2:
                func_name = args[1]
            if len(args) >= 1:
                mod_arg = args[0]
                if isinstance(mod_arg, str) and mod_arg.startswith('0x'):
                    try:
                        va = int(mod_arg, 16)
                        s = read_cstring_at_va(pe, va)
                        ws = read_wstring_at_va(pe, va)
                        if s:
                            dll_name = s.lower()
                        elif ws:
                            dll_name = ws.lower()
                    except Exception:
                        pass

        evidence.append({"call_instr": f"{ins.mnemonic} {ins.op_str}", "offset": hex(ins.address)})

        # If func_name is still a hex pointer, attempt to dereference pointer in data to string
        if isinstance(func_name, str) and func_name.startswith('0x'):
            try:
                va = int(func_name, 16)
                s = read_cstring_at_va(pe, va)
                ws = read_wstring_at_va(pe, va)
                if s:
                    func_name = s
                    confidence = 'medium'
                    evidence.append({"resolved_via": "read_cstring", "va": hex(va)})
                elif ws:
                    func_name = ws
                    confidence = 'medium'
                    evidence.append({"resolved_via": "read_wstring", "va": hex(va)})
            except Exception:
                pass

        # If still unresolved, attempt to find nearby LoadLibrary/GetModuleHandle that used const string
        if not dll_name:
            # search backwards for LoadLibrary/GetModuleHandle calls in previous 40 instructions
            N = 40
            start = max(0, idx - N)
            for i in range(idx-1, start-1, -1):
                p = insns[i]
                if p.mnemonic.startswith('call'):
                    # check if this call targets LoadLibrary or GetModuleHandle in imap
                    for op in p.operands:
                        tgt = None
                        if op.type==X86_OP_MEM:
                            tgt = mem_operand_target(p, op, pe, arch)
                            if tgt and tgt in imap:
                                dlln = imap[tgt][1].lower()
                                if 'loadlibrary' in dlln or 'getmodulehandle' in dlln:
                                    # try to recover args of that call (first arg)
                                    mod_args = recover_args_simple(insns, i, arch, pe)
                                    if mod_args:
                                        candidate = mod_args[0]
                                        if isinstance(candidate, str) and not candidate.startswith('0x'):
                                            dll_name = candidate.lower()
                                            evidence.append({"linked_load_call": dll_name, "offset": hex(p.address)})
                                            confidence = 'medium'
                                            break
                        elif op.type==X86_OP_IMM:
                            if op.imm in imap:
                                dlln = imap[op.imm][1].lower()
                                if 'loadlibrary' in dlln or 'getmodulehandle' in dlln:
                                    mod_args = recover_args_simple(insns, i, arch, pe)
                                    if mod_args:
                                        candidate = mod_args[0]
                                        if isinstance(candidate, str) and not candidate.startswith('0x'):
                                            dll_name = candidate.lower()
                                            evidence.append({"linked_load_call": dll_name, "offset": hex(p.address)})
                                            confidence = 'medium'
                                            break
                if dll_name:
                    break

        # If func_name appears in ascii or wide string lists as substring, prefer it
        if func_name and isinstance(func_name, str):
            # strip trailing nulls
            func_name = func_name.split('\x00',1)[0]
            # improve confidence when exact match exists
            for va, s in ascii_strings:
                if s and s == func_name:
                    confidence = 'high'
                    evidence.append({"found_in_ascii_strings_va": hex(va)})
                    break
            for va, s in wide_strings:
                if s and s == func_name:
                    confidence = 'high'
                    evidence.append({"found_in_wide_strings_va": hex(va)})
                    break

        results.append({
            "call_va": hex(ins.address),
            "func_name": func_name,
            "dll_name": dll_name,
            "args": args,
            "confidence": confidence,
            "evidence": evidence
        })

    return results

class PEAnalyzer:
    def __init__(self, verbose: bool = False, log: bool = False, log_dir: bool = "/reports/pe_analyzer_logs/"):
        self.DEBUG_MODE = verbose
        self.LOG_FILE = merge(log_dir, f'pe_callmap_{datetime.now().strftime("%Y%m%d-%H%M%S")}.log') if log else None

    # ---------- Main analysis flow ----------
    def analyze_pe(
            self,
            path:str,
            out_json:str="callmap.json",
            min_wide:int=4,
            min_ascii:int=4,
            allow_emulation: bool = False,
            force:bool=False) -> int:

        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        imap, imports = build_import_map(pe)

        md, arch = get_cs(pe)

        # find .text section
        self.dbp("Searching for .txt section...",end="")
        text_sec = None
        for sec in pe.sections:
            name = sec.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            if name == '.text':
                text_sec = sec
                break
        if not text_sec:
            print("No .text section found")
            return
        self.dbp(f"DONE!\ntext_sec:\n{text_sec}\n")

        text_rva = text_sec.VirtualAddress
        text_va = pe.OPTIONAL_HEADER.ImageBase + text_rva
        text_data = text_sec.get_data()
        #text_size = len(text_data)


        self.dbp("Disassebling text...",end="")
        # disassemble .text
        insns = []
        for i in md.disasm(text_data, text_va):
            insns.append(i)
        self.dbp("DONE!")
        self.dbp(f"insns has: {len(insns)} elements\n")

        #addr2idx = {ins.address: idx for idx, ins in enumerate(insns)}

        # extract strings
        self.dbp("Extracting ASCII strings...",end="")
        ascii_strings = extract_ascii_strings(pe, min_len=min_ascii)
        self.dbp("DONE!")
        self.dbp("Extracting UTF-16 (wide) strings...", end="")
        wide_strings = extract_utf16_strings(pe, min_len=min_wide)
        self.dbp("DONE!")
        self.dbp(f"Found {len(ascii_strings)} ascii strings, {len(wide_strings)} utf-16 strings.\n")

        callmap = []

        self.dbp("\n\n----- Building callmap ------\n\n")
        # detect normal calls to IAT imports and attempt arg recovery
        self.dbp("Analyzing insns...")
        for idx, ins in enumerate(insns):
            if not ins.mnemonic.startswith('call'):
                continue
            target = None
            resolved = None
            # check memory operand mem imm (calls to [rip+disp] or [addr])
            for op in ins.operands:
                if op.type == X86_OP_MEM:
                    self.dbp("  Handling x86_OP_MEM operand...",end="")
                    tgt = mem_operand_target(ins, op, pe, arch)
                    if tgt:
                        # direct IAT entry
                        if tgt in imap:
                            resolved = imap[tgt]
                            target = tgt
                            break
                        # deref pointer value
                        off = rva_to_offset(pe, va_to_rva(pe, tgt))
                        if off is not None:
                            try:
                                if arch == 'x64':
                                    ptr = struct.unpack_from('<Q', pe.__data__, off)[0]
                                else:
                                    ptr = struct.unpack_from('<I', pe.__data__, off)[0]
                                if ptr in imap:
                                    resolved = imap[ptr]
                                    target = ptr
                                    break
                            except Exception:
                                pass
                elif op.type == X86_OP_IMM:
                    self.dbp("  Handling x86_OP_IMM operand...",end="")
                    if op.imm in imap:
                        resolved = imap[op.imm]
                        target = op.imm
                        break
                elif op.type == X86_OP_REG:
                    self.dbp("  Handling x86_OP_REG operand...",end="")
                    # try register-based resolution
                    r = resolve_call_register(insns, idx, pe, arch, imap)
                    if r:
                        resolved = r
                        target = None
                        break

            if resolved:
                self.dbp("RESOLVED!")
                dll, func = resolved
                args = recover_args_simple(insns, idx, arch, pe)
                confidence = 'high' if args else 'medium'
                evidence = [{"instr": f"{ins.mnemonic} {ins.op_str}", "offset": hex(ins.address)}]


                entry = {
                    "origin": "static",
                    "dll": dll,
                    "func": func,
                    "args": args,
                    "ret": "unknown",
                    "addr": hex(ins.address),
                    "confidence": confidence,
                    "evidence": evidence
                }

                if allow_emulation:
                    self.dbp("MAY EMULATE")
                    # If we're not much confident and/or suspicious about GetProcAddress' sh..tuff; emulate it
                    if entry["func"].lower() == "getprocaddress" and entry["args"]:
                        target_arg = entry["args"][1] if len(entry["args"]) > 1 else None
                        if isinstance(target_arg, str) and target_arg.startswith("0x"):
                            self.dbp("Trying to emulate because of un-resolved GetProcAddress arguments")
                            s = try_emulate_arg(pe, entry, 1)
                            if s:
                                entry["args"][1] = s
                                entry["confidence"] = "emulated"

                    for i, arg in enumerate(entry["args"]):
                        if isinstance(arg, str) and arg.startswith("0x") and entry["confidence"] == "low":
                            self.dbp("Trying to emulate because of low confidence when resolving GetProcAddress calls")
                            s = try_emulate_arg(pe, entry, i)
                            if s:
                                entry["args"][i] = s
                                entry["confidence"] = "emulated"

        self.dbp("Done with insns!\n")

        # Add import table entries not hit in code
        self.dbp("Analyzing imap...",end="")
        for va, (dll, func) in imap.items():
            if not any(c['dll']==dll and c['func']==func for c in callmap):
                callmap.append({
                    "origin": "import_table",
                    "dll": dll,
                    "func": func,
                    "args": [],
                    "ret": "unknown",
                    "addr": hex(va),
                    "confidence": "low",
                    "evidence": [{"note": "import_table"}]
                })
        self.dbp("DONE")

        # Detect GetProcAddress usage and attempt static resolution
        self.dbp("Detecting GetProcAddress usage and trying to adapt a static resolution...",end="")
        gp_results = find_getproc_and_resolve(insns, pe, arch, imap, ascii_strings, wide_strings)
        self.dbp("DONE\n")

        # Translate getproc results into synthetic callmap entries where resolvable
        for r in gp_results:
            func_name = r.get('func_name')
            dll_name = r.get('dll_name') or 'unknown'
            confidence = r.get('confidence','low')
            entry = {
                "origin": "getproc_static",
                "dll": dll_name,
                "func": func_name if func_name else 'unknown',
                "args": r.get('args',[]),
                "ret": "unknown",
                "addr": r.get('call_va'),
                "confidence": confidence,
                "evidence": r.get('evidence',[])
            }
            callmap.append(entry)

        # Output summary JSON
        if safe_save(force, out_json, callmap) != 0: return 1701

        if not self.DEBUG_MODE: print(f"Wrote {len(callmap)} entries to {out_json}")
        self.dbp(f"Wrote {len(callmap)} entries to {out_json}")


        # Also write extracted strings to files for debugging
        base = os.path.splitext(out_json)[0]
        if safe_save(force, f"{base}_ascii_strings.json", [{ "va": format_va(va), "s": s } for va, s in ascii_strings]) != 0: return 1702
        if safe_save(force, f"{base}_wide_strings.json",  [{ "va": format_va(va), "s": s } for va, s in wide_strings])  != 0: return 1703


        if not self.DEBUG_MODE: print(f"Wrote ascii/wide string extracts to {base}_ascii_strings.json and {base}_wide_strings.json")
        self.dbp(f"Wrote ascii/wide string extracts to {base}_ascii_strings.json and {base}_wide_strings.json")

        return 0

    def dbp(self,*args, end="\n") -> None:  # Debug printer. Only prints if in DEBUG mode
        if self.DEBUG_MODE:
            print(*args, end=end)
        if self.LOG_FILE:
            system(f"touch {self.LOG_FILE}")
            with open(self.LOG_FILE, "at") as f:
                content: str = "".join(*args) + end
                f.write(content)

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="Static PE callmap extractor (x86/x64)")
    parser.add_argument("pe", help="Path to PE (exe/dll)")
    parser.add_argument("--out", help="Output JSON path", default="callmap.json")
    parser.add_argument("--log-dir", help="The folder in which to store the logs", default="/reports/pe_analyzer_logs/")
    parser.add_argument("--min-wide", type=int, default=4, help="Minimum UTF-16 wide string length")
    parser.add_argument("--min-ascii", type=int, default=4, help="Minimum ASCII string length")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--allow-emulation", action="store_true", help="""If passed it will allow the program to emulate part of the PE if the confidence is low.
    Emulating may create un-trusty results, but it's likely that it will actually improve the final result;
    as it will (try to) re-create parts of the PE that couldn't be understood.
    The program will still prefer to not emulate when possible, even if --allow-emulation is passed.""")
    parser.add_argument("--log", action="store_true", help="If passed the script will create a log inf the --log-dir directory")
    args = parser.parse_args()

    pe_analyzer = PEAnalyzer(verbose=args.verbose, log=args.log, log_dir=args.log_dir)
    pe_analyzer.analyze_pe(args.pe, out_json=args.out, min_wide=args.min_wide, min_ascii=args.min_ascii,
                           allow_emulation=args.allow_emulation)

    if __name__ == "__main__":
        main()
