#!/usr/bin/env python3
"""
Risoluzione (quanto più esaustiva) di chiamate WinAPI da eseguibili PE:
- analisi statica completa di import/IAT + disassembly
- ricostruzione argomenti con slicing euristico (x86/x64)
- opzionale analisi dinamica mirata con Qiling (LoadLibrary/GetProcAddress hooks)
- output strutturato con provenienza, confidenza, evidenze e argomenti decodificati

Dipendenze:
  pip install pefile capstone
  # opzionale:
  pip install qiling unicorn

Uso (programmatico):
  from winapi_call_resolver import PECallResolver
  res = PECallResolver(pe_path, enable_dynamic=True, max_dyn_ms=120000)
  calls = res.run()
  for c in calls: print(c)

Nota: non scrive file. Restituisce una lista di dict.
"""

from __future__ import annotations
import struct
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any

# --- hard deps ---
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_OPT_SYNTAX_INTEL
from capstone.x86_const import *

# --- soft deps (dyn) ---
try:
    import qiling
    from qiling.const import QL_VERBOSE

    HAVE_QL = True
except ImportError:
    qiling = None
    QL_VERBOSE = None
    HAVE_QL = False

try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64

    HAVE_UC = True
except ImportError:
    HAVE_UC = False

from src.tools.universal_translation_utils import normalize_windows_path_to_posix


# -------------------- Aggressive arg recovery helpers --------------------

def _is_likely_windows_path(s: str) -> bool:
    if not isinstance(s, str) or len(s) < 3:
        return False
    # semplici euristiche: backslash, drive letter, common names
    if "\\" in s or ":" in s and s[1:2] == ":":
        return True
    if s.lower().startswith(("c:\\", "d:\\", "e:\\")) or s.lower().startswith("\\\\"):
        return True
    return False


def backward_resolve_register(insns: List, start_idx: int, target_reg: str, max_back: int = 200):
    """
    Scansiona 'insns' all'indietro partendo da start_idx-1 per trovare
    l'ultimo assegnamento utile al register `target_reg`.
    Restituisce:
      - ('imm', imm_val)
      - ('mem_rip', va)  -> mem via RIP-relative (x64)
      - ('mem_abs', va)  -> absolute memory
      - ('reg', other_regname)
      - None se non risolvibile
    """
    target_reg = target_reg.lower()
    cnt = 0
    for i in range(start_idx - 1, -1, -1):
        ins = insns[i]
        cnt += 1
        if cnt > max_back:
            break
        # consideriamo mov/lea/xor patterns
        mnem = ins.mnemonic.lower()
        # mov/lea with two operands
        if (mnem.startswith("mov") or mnem.startswith("lea")) and len(ins.operands) >= 2:
            dst = ins.operands[0]
            src = ins.operands[1]
            if dst.type == X86_OP_REG and ins.reg_name(dst.reg).lower() == target_reg:
                # imm
                if src.type == X86_OP_IMM:
                    return 'imm', src.imm
                # direct reg copy
                if src.type == X86_OP_REG:
                    return 'reg', ins.reg_name(src.reg).lower()
                # mem: rip+disp (x64) or abs (x86)
                if src.type == X86_OP_MEM:
                    mem = src.value.mem
                    # RIP-rel
                    if mem.base == X86_REG_RIP:
                        va = ins.address + ins.size + mem.disp
                        return 'mem_rip', va
                    # absolute (base==0)
                    if mem.base == 0 and mem.index == 0:
                        # disp might be RVA or VA — caller normalizzerà
                        return 'mem_abs', mem.disp
                    # mem referencing another reg — fallback
                    if mem.base != 0:
                        return 'mem_reg', ins.reg_name(mem.base).lower()
        # xor reg, reg -> zeroing register
        if mnem.startswith("xor") and len(ins.operands) >= 2:
            dst = ins.operands[0];
            src = ins.operands[1]
            if dst.type == X86_OP_REG and src.type == X86_OP_REG:
                if ins.reg_name(dst.reg).lower() == target_reg and ins.reg_name(dst.reg) == ins.reg_name(src.reg):
                    return 'imm', 0
        # push imm followed by pop reg pattern (rare) - skip for brevity
    return None


def _resolve_mem_value_to_string(pe, kind, val):
    """
    kind: 'mem_rip' -> val is VA, 'mem_abs' -> val is maybe RVA/VA
    restituisce stringa se trovata, altrimenti None. Normalizza path se necessario.
    """
    if kind == 'mem_rip':
        s = decode_possible_string(pe, val)
        if s:
            if _is_likely_windows_path(s):
                try:
                    return normalize_windows_path_to_posix(s)
                except Exception:
                    return s
            return s
        # maybe pointer to pointer: read ptr at that offset
        try:
            off = rva_to_offset(pe, va_to_rva(pe, val))
            if off is not None:
                # try read pointer sized (qword/dword)
                if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
                    ptr = struct.unpack_from('<Q', pe.__data__, off)[0]
                else:
                    ptr = struct.unpack_from('<I', pe.__data__, off)[0]
                return decode_possible_string(pe, ptr)
        except Exception:
            pass
    elif kind == 'mem_abs':
        # val might be RVA or VA; try both conversions
        try:
            va = to_va(pe, val)
            s = decode_possible_string(pe, va)
            if s:
                if _is_likely_windows_path(s):
                    try:
                        return normalize_windows_path_to_posix(s)
                    except:
                        return s
                return s
            # as above, deref pointer stored at that offset
            off = rva_to_offset(pe, va_to_rva(pe, va))
            if off is not None:
                if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
                    ptr = struct.unpack_from('<Q', pe.__data__, off)[0]
                else:
                    ptr = struct.unpack_from('<I', pe.__data__, off)[0]
                return decode_possible_string(pe, ptr)
        except Exception:
            pass
    return None


def resolve_call_register_improved_at_idx(insns, idx, pe, arch, imap, max_back=400):
    """
    Try to resolve register-based call at insns[idx], scanning backwards and following
    memory chains & thunk stubs.
    Ritorna (dll, func, evidence) o None.
    """
    if idx < 0:
        return None
    ins = insns[idx]
    # get the target reg if call uses reg
    if len(ins.operands) == 0:
        return None
    op = ins.operands[0]
    if op.type != X86_OP_REG:
        return None
    regname = ins.reg_name(op.reg).lower()
    # scan backwards up to max_back instrs, track reg moves/transfers
    # reg_map maps reg -> last assignment description (('imm',val), ('mem',va), ('reg',other))
    reg_map = {}
    for i in range(idx - 1, max(-1, idx - max_back) - 1, -1):
        prev = insns[i]
        mnem = prev.mnemonic.lower()
        # handle mov dst, src or lea dst, src
        if mnem.startswith('mov') or mnem.startswith('lea'):
            if len(prev.operands) >= 2:
                dst = prev.operands[0];
                src = prev.operands[1]
                if dst.type == X86_OP_REG:
                    dst_name = prev.reg_name(dst.reg).lower()
                    # if this writes to our reg, record src
                    if dst_name == regname:
                        # imm
                        if src.type == X86_OP_IMM:
                            val = src.imm
                            # immediate may be VA or RVA; normalize
                            if isinstance(val, int) and not looks_like_ptr(pe, val):
                                val = to_va(pe, val)
                            return _check_immediate_or_ptr(val, imap, prev, pe)
                        # mem: compute mem target (rip or abs)
                        if src.type == X86_OP_MEM:
                            # compute VA of memory operand
                            tgt = mem_operand_target(prev, src, pe, arch)
                            if tgt:
                                # try resolve mem chain to import
                                matched_va, matched_sym, chain = resolve_mem_chain_to_import(pe, tgt, imap, max_deref=2)
                                if matched_sym:
                                    dll, func = matched_sym
                                    ev = [{"pattern": "mov reg,[mem] before call", "reg": regname, "mem": hex(tgt),
                                           "chain": [hex(x) for x in chain]}]
                                    return dll, func, ev
                                # else maybe the mem points directly to function VA (not IAT): try follow_thunk
                                # read pointer at tgt, if value is a code address, try to follow thunk
                                ptr = read_ptr_at_va(pe, tgt)
                                if ptr:
                                    ptr_va = to_va(pe, ptr)
                                    thunk_follow = follow_thunk(pe, ptr_va, max_depth=4)
                                    if thunk_follow and thunk_follow in imap:
                                        dll, func = imap[thunk_follow]
                                        ev = [{"pattern": "mov reg,[mem] -> ptr -> thunk", "reg": regname,
                                               "mem": hex(tgt), "ptr": hex(ptr_va), "thunk": hex(thunk_follow)}]
                                        return dll, func, ev
                                # not resolved, but continue scanning (maybe earlier mov)
                        # reg copy
                        if src.type == X86_OP_REG:
                            srcname = prev.reg_name(src.reg).lower()
                            # Now chase srcname further backwards by updating regname = srcname and continue
                            regname = srcname
                            continue
        # handle xor reg, reg (zero)
        if mnem.startswith('xor') and len(prev.operands) >= 2:
            d = prev.operands[0];
            s = prev.operands[1]
            if d.type == X86_OP_REG and s.type == X86_OP_REG:
                if prev.reg_name(d.reg).lower() == regname and prev.reg_name(d.reg) == prev.reg_name(s.reg):
                    # register zeroed: stop
                    return None
        # handle call/jump boundaries: if we reach function boundary consider stopping
        if prev.mnemonic.startswith('call') or prev.mnemonic.startswith('ret'):
            # conservative: stop scanning
            break
    # final fallbacks: could not resolve
    return None


def resolve_call_register_improved(insns, pe, arch, imap, max_back=400):
    """
    Try to resolve register-based call at insns[idx], scanning backwards and following
    memory chains & thunk stubs.
    Ritorna (dll, func, evidence) o None.
    """
    for idx, ins in enumerate(insns):
        # get the target reg if call uses reg
        if len(ins.operands) == 0:
            return None
        op = ins.operands[0]
        if op.type != X86_OP_REG:
            return None
        regname = ins.reg_name(op.reg).lower()
        # scan backwards up to max_back instrs, track reg moves/transfers
        # reg_map maps reg -> last assignment description (('imm',val), ('mem',va), ('reg',other))
        reg_map = {}
        for i in range(idx - 1, max(-1, idx - max_back) - 1, -1):
            prev = insns[i]
            mnem = prev.mnemonic.lower()
            # handle mov dst, src or lea dst, src
            if mnem.startswith('mov') or mnem.startswith('lea'):
                if len(prev.operands) >= 2:
                    dst = prev.operands[0];
                    src = prev.operands[1]
                    if dst.type == X86_OP_REG:
                        dst_name = prev.reg_name(dst.reg).lower()
                        # if this writes to our reg, record src
                        if dst_name == regname:
                            # imm
                            if src.type == X86_OP_IMM:
                                val = src.imm
                                # immediate may be VA or RVA; normalize
                                if isinstance(val, int) and not looks_like_ptr(pe, val):
                                    val = to_va(pe, val)
                                return _check_immediate_or_ptr(val, imap, prev, pe)
                            # mem: compute mem target (rip or abs)
                            if src.type == X86_OP_MEM:
                                # compute VA of memory operand
                                tgt = mem_operand_target(prev, src, pe, arch)
                                if tgt:
                                    # try resolve mem chain to import
                                    matched_va, matched_sym, chain = resolve_mem_chain_to_import(pe, tgt, imap,
                                                                                                 max_deref=2)
                                    if matched_sym:
                                        dll, func = matched_sym
                                        ev = [{"pattern": "mov reg,[mem] before call", "reg": regname, "mem": hex(tgt),
                                               "chain": [hex(x) for x in chain]}]
                                        return dll, func, ev
                                    # else maybe the mem points directly to function VA (not IAT): try follow_thunk
                                    # read pointer at tgt, if value is a code address, try to follow thunk
                                    ptr = read_ptr_at_va(pe, tgt)
                                    if ptr:
                                        ptr_va = to_va(pe, ptr)
                                        thunk_follow = follow_thunk(pe, ptr_va, max_depth=4)
                                        if thunk_follow and thunk_follow in imap:
                                            dll, func = imap[thunk_follow]
                                            ev = [{"pattern": "mov reg,[mem] -> ptr -> thunk", "reg": regname,
                                                   "mem": hex(tgt), "ptr": hex(ptr_va), "thunk": hex(thunk_follow)}]
                                            return dll, func, ev
                                    # not resolved, but continue scanning (maybe earlier mov)
                            # reg copy
                            if src.type == X86_OP_REG:
                                srcname = prev.reg_name(src.reg).lower()
                                # Now chase srcname further backwards by updating regname = srcname and continue
                                regname = srcname
                                continue
            # handle xor reg, reg (zero)
            if mnem.startswith('xor') and len(prev.operands) >= 2:
                d = prev.operands[0];
                s = prev.operands[1]
                if d.type == X86_OP_REG and s.type == X86_OP_REG:
                    if prev.reg_name(d.reg).lower() == regname and prev.reg_name(d.reg) == prev.reg_name(s.reg):
                        # register zeroed: stop
                        return None
            # handle call/jump boundaries: if we reach function boundary consider stopping
            if prev.mnemonic.startswith('call') or prev.mnemonic.startswith('ret'):
                # conservative: stop scanning
                break
        # final fallbacks: could not resolve
        return None


def _check_immediate_or_ptr(val, imap, prev_ins, pe):
    """
    if val points (or equals) to an IAT slot, return (dll, func, evidence)
    else if val is a code address, follow thunk and check imap
    """
    try:
        if val is None:
            return None
        # normalize va
        va = to_va(pe, val) if isinstance(val, int) else None
        if va and va in imap:
            dll, func = imap[va]
            return dll, func, [{"pattern": "mov reg, imm pointing to IAT", "va": format_va(va)}]
        # if va is code, try following common thunk patterns
        thunk_follow = follow_thunk(pe, va, max_depth=4) if va else None
        if thunk_follow and thunk_follow in imap:
            dll, func = imap[thunk_follow]
            return dll, func, [
                {"pattern": "mov reg, imm -> thunk", "va": format_va(va), "thunk": format_va(thunk_follow)}]
        return None
    except Exception:
        return None


# ----------------------------- helpers low-level -----------------------------

IMAGE_SCN_MEM_EXECUTE = 0x20000000

# ------- Return-type inference helpers -------
# Known explicit returns for common WinAPI (lower-case keys).
# Questa lista è estensibile; copre molte API comuni per alta confidenza.
KNOWN_RETURNS = {
    # kernel32
    "kernel32.dll!createfilew": "handle",
    "kernel32.dll!createfilea": "handle",
    "kernel32.dll!openfile": "handle",
    "kernel32.dll!createprocessw": "handle",
    "kernel32.dll!createprocessa": "handle",
    "kernel32.dll!createthread": "handle",
    "kernel32.dll!getmodulehandlea": "handle",
    "kernel32.dll!getmodulehandlew": "handle",
    "kernel32.dll!getprocaddress": "ptr",
    "kernel32.dll!loadlibrarya": "handle",
    "kernel32.dll!loadlibraryw": "handle",
    "kernel32.dll!loadlibraryexa": "handle",
    "kernel32.dll!virtualalloc": "ptr",
    "kernel32.dll!virtualallocex": "ptr",
    "kernel32.dll!virtualfree": "bool",
    "kernel32.dll!readfile": "bool",
    "kernel32.dll!writefile": "bool",
    "kernel32.dll!closehandle": "bool",
    "kernel32.dll!getlasterror": "dword",
    "kernel32.dll!getcurrentprocessid": "dword",
    "kernel32.dll!getcurrentthreadid": "dword",
    "kernel32.dll!getmodulefilenamea": "size_t",
    "kernel32.dll!getmodulefilenamew": "size_t",
    "kernel32.dll!setstdhandle": "bool",
    "kernel32.dll!getstdhandle": "handle",
    "kernel32.dll!openprocess": "handle",
    "kernel32.dll!openthread": "handle",
    "kernel32.dll!createfilemappingw": "handle",
    # user32
    "user32.dll!messageboxw": "int",
    "user32.dll!messageboxa": "int",
    # ws2_32 / winsock
    "ws2_32.dll!socket": "socket",
    "ws2_32.dll!connect": "int",
    "ws2_32.dll!send": "int",
    "ws2_32.dll!recv": "int",
    # advapi32 / registry
    "advapi32.dll!regopenkeyexw": "dword",  # returns LSTATUS
    "advapi32.dll!regopenkeyexa": "dword",
    "advapi32.dll!regsetvalueexa": "dword",
    "advapi32.dll!regqueryvalueexa": "dword",
    # comdlg / file dialogs
    "comdlg32.dll!getopenfilenamew": "bool",
    "comdlg32.dll!getsavefilenamew": "bool",
    # gdi32 examples (resources)
    "gdi32.dll!createcompatiblebitmap": "handle",
    "gdi32.dll!createbitmap": "handle",
}

# mapping by verb/suffix patterns (lower-cased func name -> return-type guess)
VERB_PATTERNS = [
    (["create", "open", "load", "alloc", "map", "getmodule", "getproc"], "handle_or_ptr"),
    (["get", "query", "enum", "find"], "dword_or_size"),
    (["read", "write", "flush", "set", "close", "remove", "delete", "flush", "free"], "bool"),
    (["is", "has", "check"], "bool"),
    (["socket", "accept"], "socket_or_handle"),
    (["send", "recv", "recvfrom", "sendto"], "int"),
    (["messagebox", "msgbox", "dialog"], "int"),
    (["getcurrent", "getlast", "getmodulefilename"], "dword"),
    (["getmodulefilename", "getprocaddress"], "size_t_or_ptr"),
]


def _norm_funcname(funcname: Optional[str]) -> str:
    if not funcname:
        return ""
    f = funcname.lower()
    # strip trailing 'a'/'w' forms and 'ex' etc for heuristics
    if f.endswith("w") or f.endswith("a"):
        # sometimes NameA/NameW; if so strip only last char if previous isn't a letter?
        if len(f) > 1 and f[-2].isalpha():
            f = f[:-1]
    if f.endswith("ex"):
        f = f[:-2]
    return f


def infer_return_type(entry: Dict[str, Any]) -> Tuple[str, str]:
    """
    Prova a risolvere il tipo di ritorno per una callmap entry.
    Ritorna (ret_type_string, confidence_level).
    ret_type_string: e.g. 'handle','bool','ptr','int','dword','size_t','unknown'
    confidence: 'high'|'medium'|'low'
    """
    dll = (entry.get("dll") or "").lower() if entry.get("dll") else ""
    func = entry.get("func") or ""
    func_l = func.lower() if isinstance(func, str) else ""
    key_full = f"{dll}!{func_l}" if dll else func_l

    # 1) exact known map
    if key_full in KNOWN_RETURNS:
        return KNOWN_RETURNS[key_full], "high"
    if func_l in KNOWN_RETURNS:
        return KNOWN_RETURNS[func_l], "high"

    # 2) try normalized func name exact
    nf = _norm_funcname(func_l)
    if nf in KNOWN_RETURNS:
        return KNOWN_RETURNS[nf], "high"

    # 3) pattern based on verb
    for verbs, typ in VERB_PATTERNS:
        for v in verbs:
            if func_l.startswith(v) or func_l.find(v) != -1:
                # map pattern types to concrete return strings
                if typ == "handle_or_ptr":
                    # distinguish: if name contains 'file' or 'module' -> handle
                    if "file" in func_l or "module" in func_l or "process" in func_l or "thread" in func_l:
                        return "handle", "medium"
                    return "ptr", "medium"
                if typ == "dword_or_size":
                    return "dword", "medium"
                if typ == "bool":
                    return "bool", "medium"
                if typ == "socket_or_handle":
                    return "socket", "medium"
                if typ == "int":
                    return "int", "medium"
                if typ == "size_t_or_ptr":
                    return "size_t", "medium"
                # fallback
                return "unknown", "low"

    # 4) heuristics by args: if first argument looks like a path/string and verb includes create/open -> handle
    args = entry.get("args") or []
    if args and isinstance(args[0], str):
        a0 = args[0]
        if isinstance(a0, str) and (("\\" in a0) or (a0.startswith("/") or ":" in a0)):
            # some heuristics
            if func_l.startswith("create") or func_l.startswith("open") or func_l.startswith("load"):
                return "handle", "medium"
            if func_l.startswith("read") or func_l.startswith("write"):
                return "bool", "medium"

    # 5) fallback: unknown
    return "unknown", "low"


def byte_to_int(b) -> int:
    if isinstance(b, int): return b
    if isinstance(b, (bytes, bytearray)): return b[0]
    try:
        return ord(b)
    except:
        return 0


def rva_to_offset(pe: pefile.PE, rva: int) -> Optional[int]:
    try:
        return pe.get_offset_from_rva(rva)
    except Exception:
        return None


def offset_to_rva(pe: pefile.PE, offset: int) -> Optional[int]:
    for sec in pe.sections:
        start = sec.PointerToRawData
        size = sec.SizeOfRawData
        if start <= offset < start + size:
            return sec.VirtualAddress + (offset - start)
    return None


def va_to_rva(pe: pefile.PE, va: int | str | None) -> Optional[int]:
    if va is None: return None
    if isinstance(va, str):
        s = va.strip().lower()
        if s.startswith("file_offset:"):
            try:
                off = int(s.split(":", 1)[1], 16)
            except Exception:
                return None
            return offset_to_rva(pe, off)
        if s.startswith("0x"):
            try:
                va = int(s, 16)
            except Exception:
                return None
        else:
            return None
    if not isinstance(va, int): return None
    try:
        return va - pe.OPTIONAL_HEADER.ImageBase
    except Exception:
        return None


def to_va(pe: pefile.PE, maybe_rva_or_va: int | None) -> Optional[int]:
    """
    Normalizza un valore che può essere RVA o VA in una VA intera.
    Restituisce None se non è possibile normalizzare.
    """
    if maybe_rva_or_va is None:
        return None
    try:
        ib = int(pe.OPTIONAL_HEADER.ImageBase)
        size = int(pe.OPTIONAL_HEADER.SizeOfImage)
        v = int(maybe_rva_or_va)

        # Se è già in [ImageBase, ImageBase+SizeOfImage) → è VA
        if ib <= v < (ib + size):
            return v
        # Se sembra essere un RVA plausibile (piccolo rispetto a SizeOfImage) → converto
        if 0 <= v < size:
            return ib + v
        # fallback: se supera imagebase+size ma non rientra, lascio com'è (best-effort)
        return v
    except Exception:
        return None


def format_va(va: Any) -> Optional[str]:
    if va is None: return None
    if isinstance(va, int): return hex(va)
    if isinstance(va, str):
        s = va.strip()
        if s == "": return None
        if s.lower().startswith("0x"):
            try:
                return hex(int(s, 16))
            except:
                return s
        return s
    return str(va)


def iter_exec_sections(pe: pefile.PE):
    for sec in pe.sections:
        if sec.Characteristics & IMAGE_SCN_MEM_EXECUTE:
            data = sec.get_data()
            sec_va = pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress
            yield sec, data, sec_va


def read_cstring_at_va(pe: pefile.PE, va: int, maxlen=4096) -> Optional[str]:
    try:
        rva = va - pe.OPTIONAL_HEADER.ImageBase
        mm = pe.get_memory_mapped_image()
        data = mm[rva:rva + maxlen]
        out = []
        for b in data:
            if b == 0: break
            if 32 <= b < 127:
                out.append(chr(b))
            else:
                break
        return "".join(out) if out else None
    except Exception:
        return None


def read_wstring_at_va(pe: pefile.PE, va: int, maxlen=4096) -> Optional[str]:
    rva = va_to_rva(pe, va)
    off = rva_to_offset(pe, rva) if rva is not None else None
    if off is None: return None
    data = pe.__data__[off: off + maxlen]
    # find NUL NUL
    for i in range(0, len(data)-1, 2):
        if data[i] == 0 and data[i + 1] == 0:
            try:
                return data[:i].decode("utf-16le", errors="replace")
            except:
                return None
    try:
        return data.decode("utf-16le", errors="replace").split("\x00", 1)[0]
    except:
        return None


def read_ptr_at_va(pe, va):
    """
    Legge un valore pointer-sized alla VA `va` leggendo dal file (non memoria runtime).
    Restituisce intero o None.
    """
    try:
        rva = va_to_rva(pe, va)
        if rva is None:
            return None
        off = rva_to_offset(pe, rva)
        if off is None:
            return None
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            if off + 8 > len(pe.__data__): return None
            return struct.unpack_from('<Q', pe.__data__, off)[0]
        else:
            if off + 4 > len(pe.__data__): return None
            return struct.unpack_from('<I', pe.__data__, off)[0]
    except Exception:
        return None


def looks_like_ptr(pe: pefile.PE, value: int) -> bool:
    ib = pe.OPTIONAL_HEADER.ImageBase
    size = pe.OPTIONAL_HEADER.SizeOfImage
    return ib <= value < ib + size


def decode_possible_string(pe: pefile.PE, value: int) -> Optional[str]:
    if not isinstance(value, int): return None
    if not looks_like_ptr(pe, value): return None
    s = read_cstring_at_va(pe, value)
    if s: return s
    s = read_wstring_at_va(pe, value)
    return s


def resolve_mem_chain_to_import(pe, start_va, imap, max_deref=2):
    """
    Given a VA that points to a memory cell, try up to max_deref times to follow pointer(s)
    and check if the resulting value is an IAT slot in imap. Ritorna the (matched_va, (dll,func), chain_list)
    chain_list is list of intermediate pointer VAs.
    """
    chain = []
    cur = start_va
    try:
        for i in range(max_deref):
            if cur is None:
                break
            # If cur explicitly equals an IAT slot:
            if cur in imap:
                return cur, imap[cur], chain
            # read pointer at VA cur (if cur points to a pointer-sized field)
            ptr = read_ptr_at_va(pe, cur)
            if ptr is None:
                break
            # normalize ptr to VA (it may be RVA)
            ptr_va = to_va(pe, ptr)
            chain.append(ptr_va)
            # If this pointer is an IAT slot key
            if ptr_va in imap:
                return ptr_va, imap[ptr_va], chain
            # else continue
            cur = ptr_va
        return None, None, chain
    except Exception:
        return None, None, chain


def get_cs(pe):
    """
    Return a configured Capstone disassembler (md) and a short arch string ('x86'|'x64')
    based on the given pefile.PE instance.

    - md.detail = True so we can inspect operands.
    - md.skipdata = True to avoid trying to disassemble large non-code data chunks.
    - Intel syntax is selected (CS_OPT_SYNTAX_INTEL).

    Raises RuntimeError if the PE machine is not supported or Capstone is missing.
    """
    try:
        # detect machine type from pe header
        machine = getattr(pe, "FILE_HEADER", None)
        if machine is None:
            raise RuntimeError("PE object does not have FILE_HEADER")

        m = pe.FILE_HEADER.Machine
    except Exception as e:
        raise RuntimeError(f"Unable to read PE machine type: {e}")

    try:
        # x64
        if m == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            arch = 'x64'
        # x86
        elif m == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            arch = 'x86'
        else:
            raise RuntimeError(f"Unsupported machine type: 0x{m:x}")
    except NameError as e:
        # Capstone not imported / not available
        raise RuntimeError("Capstone library not available or not imported") from e

    # configure disassembler
    md.detail = True
    # skipdata is available on Cs object (useful to ignore data inside code)
    try:
        md.skipdata = True
    except Exception:
        # some capstone bindings may not expose skipdata attribute; ignore if absent
        pass

    # set Intel syntax (preferred)
    try:
        md.syntax = CS_OPT_SYNTAX_INTEL
    except Exception:
        # older bindings use set_syntax
        try:
            md.set_syntax(CS_OPT_SYNTAX_INTEL)
        except Exception:
            pass

    return md, arch


# ----------------------------- import map builder -----------------------------

def build_import_map(pe: pefile.PE) -> Dict[int, Tuple[str, str]]:
    """
    Ritorna { IAT_slot_VA : (dll, func) } per Import e Delay-Import.
    """
    imap: Dict[int, Tuple[str, str]] = {}

    def _normdll(b) -> str:
        s = b.decode("ascii", "ignore") if isinstance(b, bytes) else str(b)
        return (s or "").lower()

    def _name(imp) -> str:
        if getattr(imp, "name", None):
            n = imp.name.decode("ascii", "ignore") if isinstance(imp.name, bytes) else str(imp.name)
            return (n or "unknown").lower()
        if getattr(imp, "ordinal", None) is not None:
            return f"ordinal_{imp.ordinal}"
        return "unknown"

    # imports
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for desc in pe.DIRECTORY_ENTRY_IMPORT:
            dll = _normdll(desc.dll)
            for imp in desc.imports:
                addr = to_va(pe, imp.address) if getattr(imp, 'address', None) else None
                if addr:
                    imap[addr] = (dll, _name(imp))

    # delay imports
    if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for desc in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            dll = _normdll(desc.dll)
            for imp in desc.imports:
                addr = to_va(pe, imp.address) if getattr(imp, 'address', None) else None
                if addr:
                    imap[addr] = (dll, _name(imp))

    return imap


# ----------------------------- disassembly & call scan -----------------------------

@dataclass
class ArgEvidence:
    kind: str  # 'push', 'mov', 'imm', 'mem'
    value: Any
    note: str = ""


@dataclass
class CallEntry:
    origin: str  # 'static' | 'dynamic' | 'import_table' | ...
    dll: Optional[str]
    func: Optional[str]
    args: List[Any] = field(default_factory=list)
    ret: str = "unknown"
    addr: Optional[str] = None
    confidence: str = "low"
    evidence: List[Dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "origin": self.origin,
            "dll": self.dll,
            "func": self.func,
            "args": self.args,
            "ret": self.ret,
            "addr": self.addr,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


def capstone_for(pe: pefile.PE) -> Tuple[Cs, str]:
    m = pe.FILE_HEADER.Machine
    if m == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
        md = Cs(CS_ARCH_X86, CS_MODE_64);
        arch = "x64"
    elif m == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
        md = Cs(CS_ARCH_X86, CS_MODE_32);
        arch = "x86"
    else:
        raise RuntimeError(f"Unsupported Machine 0x{m:x}")
    md.detail = True
    md.skipdata = True
    return md, arch


def _mem_target_x64(ins) -> Optional[int]:
    # call [rip+disp]
    for op in ins.operands:
        if op.type == X86_OP_MEM and op.value.mem.base == X86_REG_RIP:
            return ins.address + ins.size + op.value.mem.disp
    return None


def _mem_target_x86(ins) -> Optional[int]:
    # call [abs] (m.base==0, m.index==0)
    for op in ins.operands:
        if op.type == X86_OP_MEM:
            m = op.value.mem
            if m.base == 0 and m.index == 0:
                return m.disp
    return None


def mem_operand_target(ins, arch):
    """
    Ritorna il VA target se la CALL ha un operando memoria.
    - x64: [RIP+disp] -> VA calcolato
    - x86: [disp32]   -> disp (assunto VA già rebased nel file)
    In altri casi (es. base!=0) ritorna None (si risolverà via altre euristiche).
    """
    for op in ins.operands:
        if op.type == X86_OP_MEM:
            m = op.value.mem
            # x64: RIP-relative
            if arch == "x64" and m.base == X86_REG_RIP:
                return ins.address + ins.size + m.disp
            # x86: memoria assoluta [disp32]
            if arch == "x86" and m.base == 0 and m.index == 0:
                return m.disp
    return None


def _resolve_iat_use_from_mov(ins, imap: Dict[int, Tuple[str, str]], pe: pefile.PE) -> Optional[Tuple[str, str]]:
    # pattern: mov reg, [IAT]; ...; call reg
    for op in ins.operands:
        if op.type == X86_OP_MEM:
            m = op.value.mem
            if m.base == X86_REG_RIP:
                tgt = ins.address + ins.size + m.disp
            elif m.base == 0 and m.index == 0:
                tgt = to_va(pe, m.disp)
            else:
                continue
            if tgt in imap:
                return imap[tgt]
    return None


# ---------- Helpers per risolvere stub interni / thunk ----------
def _read_exec_bytes(pe, va, maxlen=16):
    """Legge pochi byte da VA (se mappabile) per disassemblare lo stub."""
    try:
        rva = va - pe.OPTIONAL_HEADER.ImageBase
        blob = pe.get_memory_mapped_image()
        if rva < 0 or rva >= len(blob):
            return None
        return blob[rva:rva + maxlen]
    except Exception:
        return None


def _disasm_one(pe, va, arch):
    """Disassembla 1-2 istruzioni allo start di `va` per riconoscere un thunk."""
    code = _read_exec_bytes(pe, va, maxlen=16)
    if not code:
        return []
    md = Cs(CS_ARCH_X86, CS_MODE_64 if arch == "x64" else CS_MODE_32)
    md.detail = True
    md.skipdata = True
    return list(md.disasm(code, va))[:2]


def _extract_mem_target_from_op(ins, arch):
    """
    Se l'istruzione ha un operando memoria, ritorna il VA effective:
      - x64: [RIP+disp] -> ins.address + ins.size + disp
      - x86: [disp32]   -> disp (assunto come VA già rebased nel file)
    """
    for op in ins.operands:
        if op.type == X86_OP_MEM:
            m = op.value.mem
            # x64 rip-relative
            if arch == "x64" and m.base == X86_REG_RIP:
                return ins.address + ins.size + m.disp
            # x86 abs [disp32]
            if arch == "x86" and m.base == 0 and m.index == 0:
                return m.disp
    return None


def resolve_import_thunk(pe, thunk_va, imap, arch):
    """
    Se `thunk_va` punta a uno stub tipo 'jmp [IAT]' ritorna (dll, func) risolti, altrimenti None.
    """
    insns = _disasm_one(pe, thunk_va, arch)
    if not insns:
        return None

    # Caso tipico: prima istruzione è un jmp indiretto tramite memoria
    ins0 = insns[0]
    if ins0.mnemonic == "jmp":
        tgt = _extract_mem_target_from_op(ins0, arch)
        if tgt and tgt in imap:
            return imap[tgt]  # (dll, func)

    # Pattern alternativi: mov reg,[IAT]; jmp reg
    if len(insns) >= 2 and insns[0].mnemonic == "mov" and insns[1].mnemonic == "jmp":
        # mov reg, [mem]
        mem_va = _extract_mem_target_from_op(insns[0], arch)
        if mem_va and mem_va in imap:
            return imap[mem_va]

    # (opz.) push imm; jmp [IAT] – molto raro, ma si può gestire a estensione
    return None


def is_va_in_executable_section(pe, va) -> bool:
    """Return True se `va` appartiene a una sezione eseguibile (.text)."""
    try:
        rva = va_to_rva(pe, va)
        if rva is None:
            return False
        for sec in pe.sections:
            start = sec.VirtualAddress
            size = sec.Misc_VirtualSize or sec.SizeOfRawData
            if start <= rva < start + size:
                # Characteristic bit 0x20000000 è IMAGE_SCN_MEM_EXECUTE
                if (getattr(sec, 'Characteristics', 0) & 0x20000000) != 0:
                    return True
        return False
    except Exception:
        return False


def disasm_instructions_at(pe, va, max_ins=12):
    """
    Disassembla fino a `max_ins` istruzioni a partire da VA e ritorna la lista.
    """
    try:
        md, arch = get_cs(pe)
        rva = va_to_rva(pe, va)
        if rva is None:
            return []
        off = rva_to_offset(pe, rva)
        if off is None:
            return []
        code = pe.__data__[off: off + 256]  # ioctl chunk
        out = []
        for i, ins in enumerate(md.disasm(code, va)):
            out.append(ins)
            if len(out) >= max_ins:
                break
        return out
    except Exception:
        return []


def resolve_internal_target(pe, start_va, imap, max_ins=12, max_deref=2):
    """
    Data una VA interna (target di una call), prova a risalire al reale target
    (IAT) seguendo thunk/stub patterns all'inizio della funzione.
    Restituisce (dll, func, evidence) o None.
    """
    try:
        insns = disasm_instructions_at(pe, start_va, max_ins=max_ins)
        if not insns:
            return None

        # Scorri le istruzioni cercando pattern:
        # pattern A: jmp [rip+disp]  => operand mem -> mem_va -> check imap / mem_chain
        # pattern B: jmp rel32 -> follow_thunk on target
        # pattern C: mov reg, [rip+disp]; jmp reg  (o mov reg, imm; jmp reg) -> resolve mem/imm
        # pattern D: sequences: (mov reg, [mem]; mov reg, [reg]; jmp reg)
        for idx, ins in enumerate(insns):
            mnem = ins.mnemonic.lower()
            # A: jmp mem
            if mnem == 'jmp' and ins.operands:
                op = ins.operands[0]
                if op.type == X86_OP_MEM:
                    mem_va = mem_operand_target(ins, op, pe,
                                                arch='x64' if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE[
                                                    'IMAGE_FILE_MACHINE_AMD64'] else 'x86')
                    if mem_va:
                        # direct IAT?
                        norm_mem_va = to_va(pe, mem_va)
                        if norm_mem_va in imap:
                            dll, func = imap[norm_mem_va]
                            ev = [{"pattern": "jmp [mem] at stub", "stub": format_va(start_va),
                                   "mem": format_va(norm_mem_va)}]
                            return dll, func, ev
                        # try deref chain
                        matched_va, matched_sym, chain = resolve_mem_chain_to_import(pe, mem_va, imap,
                                                                                     max_deref=max_deref)
                        if matched_sym:
                            dll, func = matched_sym
                            ev = [{"pattern": "jmp [mem] -> deref chain", "stub": format_va(start_va),
                                   "mem": format_va(mem_va), "chain": [format_va(x) for x in chain]}]
                            return dll, func, ev

                elif op.type == X86_OP_IMM:
                    # jmp rel/abs immediate
                    target = to_va(pe, op.imm)
                    # direct mapping if target in imap
                    if target in imap:
                        dll, func = imap[target]
                        ev = [{"pattern": "jmp imm in stub", "stub": format_va(start_va), "target": format_va(target)}]
                        return dll, func, ev
                    # follow further thunk at the new target
                    thunk_follow = follow_thunk(pe, target, max_depth=4)
                    if thunk_follow and thunk_follow in imap:
                        dll, func = imap[thunk_follow]
                        ev = [{"pattern": "jmp imm -> thunk_follow", "stub": format_va(start_va),
                               "intermediate": format_va(target), "thunk": format_va(thunk_follow)}]
                        return dll, func, ev

                elif op.type == X86_OP_REG:
                    # jmp reg — look backward inside insns (we have a small window)
                    # find previous mov to this reg within the small window
                    regname = ins.reg_name(op.reg).lower()
                    # scan backwards in our disasm window
                    for back in range(idx - 1, -1, -1):
                        prev = insns[back]
                        pm = prev.mnemonic.lower()
                        if pm.startswith('mov') and len(prev.operands) >= 2:
                            dst = prev.operands[0];
                            src = prev.operands[1]
                            if dst.type == X86_OP_REG and prev.reg_name(dst.reg).lower() == regname:
                                # mov reg, [mem]
                                if src.type == X86_OP_MEM:
                                    mem_va = mem_operand_target(prev, src, pe, arch='x64' if pe.FILE_HEADER.Machine ==
                                                                                             pefile.MACHINE_TYPE[
                                                                                                 'IMAGE_FILE_MACHINE_AMD64'] else 'x86')
                                    if mem_va:
                                        matched_va, matched_sym, chain = resolve_mem_chain_to_import(pe, mem_va, imap,
                                                                                                     max_deref=max_deref)
                                        if matched_sym:
                                            dll, func = matched_sym
                                            ev = [{"pattern": "mov reg,[mem]; jmp reg in stub",
                                                   "stub": format_va(start_va), "mem": format_va(mem_va),
                                                   "chain": [format_va(x) for x in chain]}]
                                            return dll, func, ev
                                    # try ptr -> follow_thunk
                                    ptr = read_ptr_at_va(pe, mem_va)
                                    if ptr:
                                        ptr_va = to_va(pe, ptr)
                                        thunk_follow = follow_thunk(pe, ptr_va, max_depth=4)
                                        if thunk_follow and thunk_follow in imap:
                                            dll, func = imap[thunk_follow]
                                            ev = [{"pattern": "mov reg,[mem] -> ptr -> thunk -> imap",
                                                   "stub": format_va(start_va), "mem": format_va(mem_va),
                                                   "ptr": format_va(ptr_va), "thunk": format_va(thunk_follow)}]
                                            return dll, func, ev

                                # mov reg, imm
                                if src.type == X86_OP_IMM:
                                    va_candidate = to_va(pe, src.imm)
                                    if va_candidate in imap:
                                        dll, func = imap[va_candidate]
                                        ev = [{"pattern": "mov reg,imm; jmp reg in stub", "stub": format_va(start_va),
                                               "imm": format_va(va_candidate)}]
                                        return dll, func, ev
                                    tf = follow_thunk(pe, va_candidate, max_depth=4)
                                    if tf and tf in imap:
                                        dll, func = imap[tf]
                                        ev = [{"pattern": "mov reg,imm -> thunk; jmp reg", "stub": format_va(start_va),
                                               "imm": format_va(va_candidate), "thunk": format_va(tf)}]
                                        return dll, func, ev
                        # stop if we cross a call/ret (too far)
                        if pm.startswith('call') or pm.startswith('ret'):
                            break

            # B: jmp rel32 at top-level already handled by op.type==IMM above

            # C: might also be patterns like "push imm; ret" returning address
            if mnem == 'push' and len(ins.operands) >= 1:
                op0 = ins.operands[0]
                if op0.type == X86_OP_IMM:
                    imm = op0.imm
                    # push imm; ret is a common import thunk on x86
                    # if the imm normalized points to an IAT entry or thunk -> resolve
                    va_candidate = to_va(pe, imm)
                    if va_candidate in imap:
                        dll, func = imap[va_candidate]
                        ev = [{"pattern": "push imm; ret thunk", "stub": format_va(start_va),
                               "imm": format_va(va_candidate)}]
                        return dll, func, ev
                    tf = follow_thunk(pe, va_candidate, max_depth=4)
                    if tf and tf in imap:
                        dll, func = imap[tf]
                        ev = [{"pattern": "push imm; ret -> thunk", "stub": format_va(start_va),
                               "imm": format_va(va_candidate), "thunk": format_va(tf)}]
                        return dll, func, ev

        # not resolved
        return None
    except Exception:
        return None


def follow_thunk(pe, va, max_depth=4):
    """
    Segue fino a `max_depth` trampolini: se `va` è dentro .text e inizia con un
    jmp [rip+disp] / jmp qword ptr [abs] / jmp <rel> -> ritorna la destinazione finale (VA)
    Se non trova thunk, ritorna None.
    """
    try:
        depth = 0
        cur = va
        while depth < max_depth and cur:
            rva = va_to_rva(pe, cur)
            off = rva_to_offset(pe, rva)
            if off is None: break
            # leggi primo paio di bytes per riconoscere opcode jmp
            code = pe.__data__[off: off + 16]
            # x86-64: 0xFF 0x25 -> jmp qword ptr [rip+disp32]
            if len(code) >= 6 and code[0] == 0xFF and code[1] == 0x25:
                # disp32 little endian
                disp = struct.unpack_from('<i', code, 2)[0]
                jmp_target_va = cur + 6 + disp
                # read pointer at that address
                ptr = read_ptr_at_va(pe, jmp_target_va)
                if ptr:
                    # ptr might be VA or RVA; normalize
                    ptr_va = to_va(pe, ptr)
                    # if ptr_va in imap -> resolved; else continue following
                    cur = ptr_va
                    depth += 1
                    continue
                else:
                    cur = jmp_target_va
                    depth += 1
                    continue
            # x86: FF 25 (absolute dword)
            # x86 direct relative jmp: 0xE9 disp32 (jmp rel32)
            if len(code) >= 5 and code[0] == 0xE9:
                rel = struct.unpack_from('<i', code, 1)[0]
                cur = cur + 5 + rel
                depth += 1
                continue
            # else: not a jump thunk pattern we care about
            break
        return cur if depth > 0 else None
    except Exception:
        return None


# ----------------------------- argument recovery -----------------------------

def track_regs_pre_call(insns_window: List) -> Dict[str, Any]:
    """
    Traccia semplicemente assegnazioni a RCX,RDX,R8,R9 (x64) nelle ultime N istruzioni prima della call.
    """
    regs = {}
    interesting = {"rcx", "rdx", "r8", "r9"}
    for ins in insns_window:
        if ins.mnemonic.startswith("mov") and len(ins.operands) == 2 and ins.operands[0].type == X86_OP_REG:
            dst = ins.reg_name(ins.operands[0].reg).lower()
            if dst in interesting:
                src = ins.operands[1]
                if src.type == X86_OP_IMM:
                    regs[dst] = src.imm
                elif src.type == X86_OP_REG:
                    regs[dst] = f"reg:{ins.reg_name(src.reg)}"
                elif src.type == X86_OP_MEM:
                    regs[dst] = "memref"
    return regs


# -------------------- Aggressive x64 arg recovery --------------------

def recover_args_x64(insns_window: List, pe: pefile.PE, call_ins_idx: int = None, max_args=4):
    """
    insns_window: lista di istruzioni (in ordine) che termina con la CALL.
    call_ins_idx: indice nella lista globale di istruzioni (opzionale) per backward slicing.
    Return: (args_list, evidence_list)
    """
    # prefer backward resolve per ogni register arg (rcx, rdx, r8, r9)
    regs_order = ['rcx', 'rdx', 'r8', 'r9']
    args = []
    evid = []
    if call_ins_idx is None:
        # fallback: simple track_regs_pre_call
        regs = track_regs_pre_call(insns_window)
        return recover_args_x64_from_regdict(regs, pe)
    # call_ins_idx riferito alla lista globale (richiede che il caller passi il vero indice)
    for r in regs_order:
        resolved = backward_resolve_register(insns_window, len(insns_window), r, max_back=200)
        if resolved is None:
            break
        kind, val = resolved
        if kind == 'imm':
            s = decode_possible_string(pe, val)
            if s:
                args.append(s);
                evid.append(ArgEvidence('mov', val, f'{r}<-imm/decoded'))
            else:
                args.append(hex(val));
                evid.append(ArgEvidence('mov', val, f'{r}<-imm'))
        elif kind == 'reg':
            args.append(f'reg:{val}');
            evid.append(ArgEvidence('mov', val, f'{r}<-reg'))
        elif kind in ('mem_rip', 'mem_abs'):
            s = _resolve_mem_value_to_string(pe, kind, val)
            if s:
                args.append(s);
                evid.append(ArgEvidence('mem', val, f'{r}<-mem->str'))
            else:
                # if cannot decode string, present VA hex
                va = val if kind == 'mem_rip' else to_va(pe, val)
                args.append(hex(va) if isinstance(va, int) else str(va))
                evid.append(ArgEvidence('mem', val, f'{r}<-mem'))
        else:
            args.append(f'unknown:{kind}')
            evid.append(ArgEvidence('mov', val, f'{r}<-unknown'))
        if len(args) >= max_args:
            break
    return args, evid


def recover_args_x64_from_regdict(regs, pe):
    # fallback se backward_resolve_register non usabile
    order = ['rcx', 'rdx', 'r8', 'r9']
    args = [];
    evid = []
    for r in order:
        v = regs.get(r)
        if v is None:
            break
        if isinstance(v, int):
            s = decode_possible_string(pe, v)
            if s:
                args.append(s);
                evid.append(ArgEvidence('mov', v, f'{r}<-imm/decoded'))
            else:
                args.append(hex(v));
                evid.append(ArgEvidence('mov', v, 'imm'))
        else:
            args.append(str(v));
            evid.append(ArgEvidence('mov', v, 'reg/mem'))
    return args, evid


# -------------------- Aggressive x86 arg recovery --------------------

def recover_args_x86(insns_window: List, pe: pefile.PE, max_args: int = 8, max_back=200):
    """
    Migliorata: prima cerchiamo push imm / push [rip+disp], poi se troviamo push reg
    facciamo backward_resolve_register per quel reg; se push memref cerchiamo stringhe.
    """
    args = [];
    evid = []
    # collect pushes from the end backward until we hit the call or run out
    pushes = []
    for ins in reversed(insns_window):
        if ins.mnemonic.startswith('call'):
            break
        if ins.mnemonic.startswith('push'):
            if len(ins.operands) >= 1:
                op = ins.operands[0]
                pushes.append(op)
        # stop if too long
        if len(pushes) >= max_args:
            break
    # pushes are in reverse order, we need logical order as passed to callee
    pushes.reverse()
    # process pushes
    for op in pushes:
        if op.type == X86_OP_IMM:
            v = op.imm
            s = decode_possible_string(pe, v)
            if s:
                args.append(s);
                evid.append(ArgEvidence('push', v, 'imm_str'))
            else:
                args.append(hex(v));
                evid.append(ArgEvidence('push', v, 'imm'))
        elif op.type == X86_OP_MEM:
            # mem: could be rip-rel or abs
            m = op.value.mem
            if m.base == X86_REG_RIP:
                va = op.address + op.size + m.disp if hasattr(op, 'address') else None
                # we don't have ins here, so fallback: try to compute via context not available
                # but often push [rip+disp] appears as operand in an instruction object; we instead expect the op to be inside an instruction
                # For safety, attempt to decode by searching nearest instruction in insns_window that contains this op
                # Simpler approach: use op.value.mem.disp as if rip disp target from the call ins address (best-effort)
                try:
                    ins = insns_window[-1]  # the call instr; use its address
                    va = ins.address + ins.size + m.disp
                except:
                    ins = insns_window[-1]
                    va = None
                if va:
                    s = decode_possible_string(pe, va)
                    if s:
                        args.append(s);
                        evid.append(ArgEvidence('push', va, 'mem_rip_str'))
                        continue
                    # else try deref pointer at va
                    off = rva_to_offset(pe, va_to_rva(pe, va))
                    if off is not None:
                        try:
                            if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
                                ptr = struct.unpack_from('<Q', pe.__data__, off)[0]
                            else:
                                ptr = struct.unpack_from('<I', pe.__data__, off)[0]
                            s2 = decode_possible_string(pe, ptr)
                            if s2:
                                args.append(s2);
                                evid.append(ArgEvidence('push', ptr, 'mem_rip_ptr->str'));
                                continue
                        except Exception:
                            pass
                    # fallback to hex
                    args.append(hex(va) if va else 'mem')
                    evid.append(ArgEvidence('push', va, 'mem_rip'))
                    continue
            elif m.base == 0 and m.index == 0:
                # absolute disp
                va = to_va(pe, m.disp)
                s = decode_possible_string(pe, va)
                if s:
                    args.append(s);
                    evid.append(ArgEvidence('push', va, 'mem_abs_str'));
                    continue
                off = rva_to_offset(pe, va_to_rva(pe, va))
                if off is not None:
                    try:
                        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
                            ptr = struct.unpack_from('<Q', pe.__data__, off)[0]
                        else:
                            ptr = struct.unpack_from('<I', pe.__data__, off)[0]
                        s2 = decode_possible_string(pe, ptr)
                        if s2:
                            args.append(s2);
                            evid.append(ArgEvidence('push', ptr, 'mem_abs_ptr->str'));
                            continue
                    except Exception:
                        pass
                args.append(hex(va));
                evid.append(ArgEvidence('push', va, 'mem_abs'))
                continue
            else:
                # mem with register base (push [reg+disp]) => try to resolve reg
                # Use the CALL instruction (last element in insns_window) as reference
                call_ins = insns_window[-1] if insns_window else None

                # choose a candidate register: prefer base, fallback to index (capstone uses 0 for 'no reg')
                base_reg = None
                try:
                    # capstone may provide X86_REG_INVALID constant; import from capstone.x86_const if necessario
                    if getattr(m, "base", 0) and m.base not in (0, X86_REG_INVALID):
                        base_reg = (call_ins.reg_name(m.base).lower() if call_ins is not None else None)
                    elif getattr(m, "index", 0) and m.index not in (0, X86_REG_INVALID):
                        base_reg = (call_ins.reg_name(m.index).lower() if call_ins is not None else None)
                except Exception:
                    base_reg = None

                if base_reg:
                    # try backward resolve of base_reg
                    resolved = backward_resolve_register(insns_window, len(insns_window), base_reg, max_back=max_back)
                    if resolved and resolved[0] in ('mem_rip', 'mem_abs', 'imm'):
                        s = _resolve_mem_value_to_string(pe, resolved[0], resolved[1])
                        if s:
                            args.append(s)
                            evid.append(ArgEvidence('push', resolved[1], f'base_reg({base_reg})->str'))
                            continue
                # fallback if we couldn't resolve the base/index register
                args.append('memref')
                evid.append(ArgEvidence('push', None, 'memreg'))
        elif op.type == X86_OP_REG:
            regname = op.reg
            # op.reg is id, convert
            try:
                rname = op.reg_name(op.reg).lower()
            except Exception:
                rname = str(op.reg)
            # backward resolve the register
            resolved = backward_resolve_register(insns_window, len(insns_window), rname, max_back=max_back)
            if resolved:
                kind, val = resolved
                if kind == 'imm':
                    s = decode_possible_string(pe, val)
                    if s:
                        args.append(s);
                        evid.append(ArgEvidence('push', val, 'reg<-imm_str'))
                    else:
                        args.append(hex(val));
                        evid.append(ArgEvidence('push', val, 'reg<-imm'))
                elif kind in ('mem_rip', 'mem_abs'):
                    s = _resolve_mem_value_to_string(pe, kind, val)
                    if s:
                        args.append(s);
                        evid.append(ArgEvidence('push', val, 'reg<-mem_str'))
                    else:
                        args.append(hex(to_va(pe, val) if kind == 'mem_abs' else val));
                        evid.append(ArgEvidence('push', val, 'reg<-mem'))
                elif kind == 'reg':
                    args.append(f"reg:{val}");
                    evid.append(ArgEvidence('push', val, 'reg<-reg'))
                else:
                    args.append(f"unknown:{kind}");
                    evid.append(ArgEvidence('push', None, 'reg<-unknown'))
            else:
                args.append(f"reg:{rname}");
                evid.append(ArgEvidence('push', None, 'reg_unresolved'))
        else:
            args.append('unknown')
            evid.append(ArgEvidence('push', None, 'unknown'))
        if len(args) >= max_args:
            break

    # reverse to logical order (first arg first)
    return args, evid


# ----------------------------- core resolver -----------------------------

class PECallResolver:
    def __init__(self,
                 pe_path: str,
                 enable_dynamic: bool = True,
                 dyn_strategy: str = "qiling-then-unicorn",
                 max_dyn_ms: int = 120_000,
                 verbose: bool = False):
        self.pe_path = pe_path
        self.enable_dynamic = enable_dynamic
        self.dyn_strategy = dyn_strategy
        self.max_dyn_ms = max_dyn_ms
        self.verbose = verbose

        self.pe = pefile.PE(pe_path, fast_load=False)
        self.imap = build_import_map(self.pe)
        self.md, self.arch = capstone_for(self.pe)

    # ---- static imports as baseline ----
    def imports_baseline(self) -> List[CallEntry]:
        """
        Build baseline entries from Import Table and Delay-Import Table.
        For each import we set:
          - origin: 'import_table' or 'delay_import_table'
          - dll, func
          - addr: VA of the IAT slot (if computable)
          - evidence: note + iat_slot and iat_value (if can be deref'd from file)
        """
        out: List[CallEntry] = []
        seen = set()
        pe = self.pe

        def _norm_name(imp):
            if getattr(imp, "name", None):
                n = imp.name.decode("ascii", "ignore") if isinstance(imp.name, bytes) else str(imp.name)
                return (n or f"ordinal_{getattr(imp, 'ordinal', 0)}").lower()
            if getattr(imp, "ordinal", None) is not None:
                return f"ordinal_{imp.ordinal}"
            return "unknown"

        # --- Normal imports ---
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for desc in pe.DIRECTORY_ENTRY_IMPORT:
                dll = (
                    desc.dll.decode("ascii", "ignore") if isinstance(desc.dll, bytes) else str(desc.dll) or "").lower()
                for imp in desc.imports:
                    func_name = _norm_name(imp)
                    key = (dll, func_name, "import_table")
                    if key in seen:
                        continue
                    seen.add(key)

                    # compute VA for the IAT slot if possible
                    addr_va = None
                    if getattr(imp, "address", None):
                        try:
                            addr_va = to_va(pe, imp.address)
                        except Exception:
                            addr_va = None

                    evidence = [{"note": "import_table"}]
                    if addr_va:
                        evidence.append({"iat_slot": format_va(addr_va)})

                        # try to read the pointer value stored in the slot (best-effort)
                        try:
                            rva = va_to_rva(pe, addr_va)
                            off = rva_to_offset(pe, rva)
                            if off is not None:
                                if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
                                    ptr = struct.unpack_from("<Q", pe.__data__, off)[0]
                                else:
                                    ptr = struct.unpack_from("<I", pe.__data__, off)[0]
                                evidence.append({"iat_value": format_va(ptr)})
                        except Exception:
                            # non-critical: just don't include iat_value
                            pass

                    ce = CallEntry(
                        origin="import_table",
                        dll=dll,
                        func=func_name,
                        args=[],
                        ret="unknown",
                        addr=format_va(addr_va) if addr_va else None,
                        confidence="medium",
                        evidence=evidence
                    )
                    out.append(ce)

        # --- Delay imports ---
        if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
            for desc in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                dll = (
                    desc.dll.decode("ascii", "ignore") if isinstance(desc.dll, bytes) else str(desc.dll) or "").lower()
                for imp in desc.imports:
                    func_name = _norm_name(imp)
                    key = (dll, func_name, "delay_import_table")
                    if key in seen:
                        continue
                    seen.add(key)

                    addr_va = None
                    if getattr(imp, "address", None):
                        try:
                            addr_va = to_va(pe, imp.address)
                        except Exception:
                            addr_va = None

                    evidence = [{"note": "delay_import_table"}]
                    if addr_va:
                        evidence.append({"iat_slot": format_va(addr_va)})
                        try:
                            rva = va_to_rva(pe, addr_va)
                            off = rva_to_offset(pe, rva)
                            if off is not None:
                                if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
                                    ptr = struct.unpack_from("<Q", pe.__data__, off)[0]
                                else:
                                    ptr = struct.unpack_from("<I", pe.__data__, off)[0]
                                evidence.append({"iat_value": format_va(ptr)})
                        except Exception:
                            pass

                    ce = CallEntry(
                        origin="delay_import_table",
                        dll=dll,
                        func=func_name,
                        args=[],
                        ret="unknown",
                        addr=format_va(addr_va) if addr_va else None,
                        confidence="medium",
                        evidence=evidence
                    )
                    out.append(ce)

        return out

    # ---- static disassembly scan ----
    def static_calls(self) -> List[CallEntry]:
        entries: List[CallEntry] = []
        ib = self.pe.OPTIONAL_HEADER.ImageBase
        imap = self.imap  # { IAT_slot_VA : (dll, func) }

        for sec, data, sec_va in iter_exec_sections(self.pe):
            window: List = []
            for ins in self.md.disasm(data, sec_va):
                window.append(ins)
                if len(window) > 24:
                    window.pop(0)

                if ins.mnemonic != "call":
                    continue

                dll = func = None
                confidence = "low"
                ev: List[Dict[str, Any]] = [{"instr": f"{ins.mnemonic} {ins.op_str}", "offset": hex(ins.address)}]

                # A) call [IAT] diretto
                tgt_va = mem_operand_target(ins, self.arch)
                if tgt_va and tgt_va in imap:
                    dll, func = imap[tgt_va]
                    ev.append({"iat_slot": hex(tgt_va)})
                    confidence = "high"

                # B) call reg, dove prima: mov reg, [IAT]
                if dll is None and len(window) >= 2:
                    prev = window[-2]
                    r = _resolve_iat_use_from_mov(prev, imap, self.pe)
                    if r:
                        dll, func = r
                        ev.append({"pattern": "mov reg,[IAT]; call reg"})
                        confidence = "high"

                # C) call thunk (stub nel .text/.plt-like) → risolviamo al volo
                if dll is None:
                    # call imm: intra-module; call [abs]/[rip+disp]: potenziale thunk
                    for op in ins.operands:
                        if op.type == X86_OP_IMM:
                            # call imm => non un IAT; potrebbe essere un wrapper nostro,
                            # ma tipicamente NON è thunk d’import. Segnala solo intra.
                            ev.append({"direct_call": hex(op.imm)})
                            break
                    else:
                        # non è call imm → potrebbe essere memoria/reg indiretto verso thunk
                        # prova prima mem
                        if tgt_va and tgt_va not in imap:
                            # se l'indirizzo cade in una sezione eseguibile, prova a trattarlo da thunk
                            if is_va_in_executable_section(self.pe, tgt_va):
                                r = resolve_import_thunk(self.pe, tgt_va, imap, self.arch)
                                if r:
                                    dll, func = r
                                    ev.append({"thunk": hex(tgt_va)})
                                    confidence = "high"

                        # poi il caso call reg con reg caricato da thunk prima
                        if dll is None and len(window) >= 2:
                            r = resolve_call_register_improved(window, self.pe, self.arch, imap)
                            if r:
                                dll, func, extra_ev = r
                                ev.extend(extra_ev)
                                confidence = "high"

                # Recupero argomenti (come già facevi)
                pre_win = window[:-1][-16:]
                if self.arch == "x86":
                    args, arg_evs = recover_args_x86(pre_win, self.pe)
                else:
                    args, arg_evs = recover_args_x64(pre_win, self.pe)
                if arg_evs:
                    ev.append({"arg_evidence": [e.__dict__ for e in arg_evs]})

                ce = CallEntry(
                    origin="static",
                    dll=dll,
                    func=func,
                    args=args,
                    addr=hex(ins.address),
                    confidence=confidence,
                    evidence=ev
                )
                entries.append(ce)
        return entries

    # ---- dynamic pass (optional) ----
    def dynamic_pass(self) -> List[CallEntry]:
        """
        Best-effort:
         - prefer Qiling (se disponibile)
         - altrimenti fallback nullo (non forziamo Unicorn here: richiede setup OS)
        """
        if not self.enable_dynamic:
            return []
        if self.dyn_strategy.startswith("qiling") and HAVE_QL:
            try:
                return self._dyn_qiling()
            except Exception as e:
                if self.verbose:
                    print("[dyn] Qiling failed:", e)
                # fallback: none
                return []
        # No dynamic available
        return []

    def _dyn_qiling(self) -> List[CallEntry]:
        """
        Avvia Qiling con hooks per LoadLibrary*/GetProcAddress.
        Registra:
         - (dll, func) risolti dinamicamente
         - call indirette a tali puntatori (quando possibile)
        """
        calls: List[CallEntry] = []
        resolved_ptrs: Dict[int, Tuple[str, str]] = {}

        def _mk(name):
            return name.lower() if isinstance(name, str) else name

        def hook_LoadLibrary(ql: qiling.Qiling, address: int, params):
            try:
                # Windows loader prototype: LPCSTR lpLibFileName
                lib_ptr = params["lpLibFileName"]
            except Exception:
                lib_ptr = params[0] if params else 0
            s = decode_possible_string(self.pe, lib_ptr) or f"0x{lib_ptr:x}"
            ce = CallEntry(
                origin="dynamic",
                dll="kernel32.dll",
                func="loadlibrary*",
                args=[s],
                addr=hex(address),
                confidence="high",
                evidence=[{"hook": "LoadLibrary*", "arg0": s}],
            )
            calls.append(ce)

        def hook_GetProcAddress(ql: qiling.Qiling, address: int, params):
            try:
                hmod = params["hModule"];
                namep = params["lpProcName"]
            except Exception:
                hmod = params[0] if len(params) > 0 else 0
                namep = params[1] if len(params) > 1 else 0

            # Qiling spesso fornisce già stringa; se è ptr prova a decodificare
            if isinstance(namep, int):
                sym = decode_possible_string(self.pe, namep) or f"0x{namep:x}"
            else:
                sym = str(namep)

            # best-effort: infer DLL dal handle (Qiling non sempre dà mapping)
            dll = "unknown"
            ce = CallEntry(
                origin="dynamic",
                dll=dll,
                func="getprocaddress",
                args=[hex(hmod), sym],
                addr=hex(address),
                confidence="high",
                evidence=[{"hook": "GetProcAddress", "hModule": hex(hmod), "name": sym}],
            )
            calls.append(ce)

            # se Qiling restituisce un "return value" (indirizzo funzione), lo registriamo
            try:
                ret = ql.arch.regs.read("rax") if self.arch == "x64" else ql.arch.regs.read("eax")
                if isinstance(ret, int) and ret:
                    # mappalo come simbolo dinamico se possibile
                    if isinstance(sym, str) and sym and not sym.startswith("0x"):
                        resolved_ptrs[ret] = (dll, _mk(sym))
            except Exception:
                pass

        # setup Qiling
        ql = qiling.Qiling([self.pe_path], rootfs="qiling/examples/rootfs/x86_windows" if self.arch == "x86"
        else "qiling/examples/rootfs/x8664_windows",
                           console=False, verbose=QL_VERBOSE.OFF)
        # Hook su API note
        for api in ("kernel32.LoadLibraryA", "kernel32.LoadLibraryW",
                    "kernel32.LoadLibraryExA", "kernel32.LoadLibraryExW"):
            try:
                ql.set_api(api, hook_LoadLibrary)
            except:
                pass
        for api in ("kernel32.GetProcAddress",):
            try:
                ql.set_api(api, hook_GetProcAddress)
            except:
                pass

        # timeout hard
        ql.run(timeout=self.max_dyn_ms)

        # (opzionale) potresti camminare la memoria di Qiling per trovare thunk eseguiti

        # Arricchisci le call indirette risolte
        for ptr, (dl, fn) in resolved_ptrs.items():
            calls.append(CallEntry(
                origin="dynamic",
                dll=dl,
                func=fn,
                args=[],
                confidence="medium",
                evidence=[{"resolved_ptr": hex(ptr), "source": "GetProcAddress"}]
            ))

        return calls

    # ---- orchestration ----
    def run(self) -> List[Dict[str, Any]]:
        out: List[CallEntry] = []

        # 1) baseline da import/delay-import (evita la tua situazione "solo LOW")
        out.extend(self.imports_baseline())

        # 2) static scan (& arg recovery)
        out.extend(self.static_calls())

        # 3) dynamic enrichment (optional)
        out.extend(self.dynamic_pass())

        # 4) post-process: normalize, deduplicate keeping richer entry
        norm = []
        seen = {}

        def key(call: CallEntry):
            return call.origin, call.dll or "", call.func or "", call.addr or ""

        def rank(conf: str) -> int:
            return {"low": 0, "medium": 1, "high": 2}.get(conf, 0)

        for c in out:
            k = key(c)
            if k not in seen:
                seen[k] = c
            else:
                # keep the one with more args or higher confidence
                old = seen[k]
                if (rank(c.confidence) > rank(old.confidence)) or (len(c.args) > len(old.args)):
                    seen[k] = c
        for c in seen.values():
            norm.append(c.as_dict())

        # 5) infer return types for each normalized entry
        for ent in norm:
            ret, conf = infer_return_type(ent)
            ent['ret'] = ret
            # upgrade confidence if inference is high
            if conf == "high" and ent.get('confidence', 'low') != 'high':
                ent['confidence'] = 'high'
            # optionally attach evidence
            ent.setdefault('evidence', [])
            ent['evidence'].append({"inferred_ret": ret, "inferred_ret_conf": conf})

        return norm
