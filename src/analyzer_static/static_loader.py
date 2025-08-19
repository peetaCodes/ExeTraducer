# dynamic_loader_enhanced.py
# Versione estesa: gestione disp+ImageBase, follow thunk chains, vtable sensibile, diagnostics.

import pefile
import capstone
from typing import Optional, Tuple, List, Dict, Iterable, Set

CS_OP_MEM = capstone.CS_OP_MEM
CS_OP_IMM = capstone.CS_OP_IMM
CS_OP_REG = capstone.CS_OP_REG

class DynamicLoaderAnalyzer:
    def __init__(self, pe: pefile.PE, debug: bool = False):
        self.pe = pe
        self.debug = debug

        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.md.detail = True

        self._last_instructions: Optional[List[capstone.CsInsn]] = None
        self._addr_to_index: Optional[Dict[int,int]] = None

        self.iat_slot_to_name: Dict[int, str] = {}
        self.thunk_to_name: Dict[int, str] = {}
        self.func_addr_map: Dict[int, str] = {}

        self.vtables: Dict[int, List[int]] = {}

        self.stats = {
            'total_calls': 0,
            'resolved_iat': 0,
            'resolved_thunk': 0,
            'resolved_internal_direct': 0,
            'resolved_internal_indirect': 0,
            'resolved_vtable': 0,
            'unresolved_mem': 0,
            'unresolved_other': 0
        }

    # ------------------------
    # Disassembly
    # ------------------------
    def ensure_disassembled(self):
        if self._last_instructions is not None and self._addr_to_index is not None:
            return
        text_sec = None
        for s in self.pe.sections:
            name = s.Name.decode(errors='ignore').rstrip('\x00')
            if name == '.text':
                text_sec = s
                break
        if not text_sec:
            self._last_instructions = []
            self._addr_to_index = {}
            return
        code = text_sec.get_data()
        base = self.pe.OPTIONAL_HEADER.ImageBase + text_sec.VirtualAddress
        insns = list(self.md.disasm(code, base))
        self._last_instructions = insns
        self._addr_to_index = {ins.address: i for i, ins in enumerate(insns)}

    # ------------------------
    # Memory reads
    # ------------------------
    def read_memory_bytes(self, absolute_address: int, size: int) -> Optional[bytes]:
        data = self.pe.__data__
        img_base = self.pe.OPTIONAL_HEADER.ImageBase
        for sec in self.pe.sections:
            start = img_base + sec.VirtualAddress
            end = start + max(sec.Misc_VirtualSize, sec.SizeOfRawData)
            if start <= absolute_address < end:
                off_in_sec = absolute_address - start
                raw_off = sec.PointerToRawData + off_in_sec
                if raw_off + size > len(data):
                    return None
                return data[raw_off: raw_off + size]
        return None

    def read_memory_dword(self, absolute_address: int) -> Optional[int]:
        chunk = self.read_memory_bytes(absolute_address, 4)
        if not chunk or len(chunk) < 4:
            return None
        return int.from_bytes(chunk, 'little')

    def read_best_string_at(self, absolute_address: int) -> Optional[str]:
        # try utf16le
        chunk = self.read_memory_bytes(absolute_address, 2048)
        if not chunk:
            return None
        try:
            s = chunk.decode('utf-16le', errors='strict').split('\x00',1)[0]
            if s:
                return s
        except Exception:
            pass
        # ascii fallback
        out = []
        for b in chunk:
            if b == 0:
                break
            if 32 <= b <= 126:
                out.append(chr(b))
            else:
                return None
        return ''.join(out) if out else None

    # ------------------------
    # Section helpers
    # ------------------------
    def _is_in_section(self, va: int, section_name: str) -> bool:
        img = self.pe.OPTIONAL_HEADER.ImageBase
        for sec in self.pe.sections:
            name = sec.Name.decode(errors='ignore').rstrip('\x00')
            if name != section_name:
                continue
            start = img + sec.VirtualAddress
            end = start + max(sec.Misc_VirtualSize, sec.SizeOfRawData)
            if start <= va < end:
                return True
        return False

    def _classify_pointer(self, va: int) -> Optional[str]:
        img = self.pe.OPTIONAL_HEADER.ImageBase
        for sec in self.pe.sections:
            name = sec.Name.decode(errors='ignore').rstrip('\x00')
            start = img + sec.VirtualAddress
            end = start + max(sec.Misc_VirtualSize, sec.SizeOfRawData)
            if start <= va < end:
                return name
        return None

    # ------------------------
    # Vtable scanner (min_entries=2)
    # ------------------------
    def scan_vtables(self, min_entries: int = 2):
        img_base = self.pe.OPTIONAL_HEADER.ImageBase
        sections_to_scan = ['.rdata', '.data', '.rodata']
        for sec in self.pe.sections:
            name = sec.Name.decode(errors='ignore').rstrip('\x00')
            if name not in sections_to_scan:
                continue
            start = img_base + sec.VirtualAddress
            size = max(sec.Misc_VirtualSize, sec.SizeOfRawData)
            for offset in range(0, max(0, size - 4), 4):
                base_va = start + offset
                # sample min_entries
                good = True
                entries = []
                for k in range(min_entries):
                    ptr = self.read_memory_dword(base_va + 4*k)
                    if not ptr or not self._is_in_section(ptr, '.text'):
                        good = False
                        break
                    entries.append(ptr)
                if good:
                    # extend until broken
                    i = 0
                    funcs = []
                    while True:
                        p = self.read_memory_dword(base_va + 4*i)
                        if p and self._is_in_section(p, '.text'):
                            funcs.append(p)
                            i += 1
                        else:
                            break
                    if funcs:
                        if base_va not in self.vtables:
                            self.vtables[base_va] = funcs

    def _is_likely_vtable(self, va: int) -> Optional[Tuple[int, List[int]]]:
        for base, funcs in self.vtables.items():
            if base <= va < base + 4*len(funcs):
                return base, funcs
        return None

    # ------------------------
    # Build imports + delay + thunks + vtables
    # ------------------------
    def build_full_import_maps(self):
        self.iat_slot_to_name = {}
        self.thunk_to_name = {}
        self.func_addr_map = {}
        self.vtables = {}

        # normal imports
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT') and self.pe.DIRECTORY_ENTRY_IMPORT:
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode('utf-8', errors='ignore') if entry.dll else ''
                for imp in entry.imports:
                    if not imp or not getattr(imp, 'address', None):
                        continue
                    name = None
                    if getattr(imp, 'name', None):
                        try:
                            name = imp.name.decode('utf-8', errors='ignore')
                        except Exception:
                            name = None
                    if not name:
                        name = f"ordinal#{getattr(imp, 'ordinal', '?')}"
                    label = f"{dll}!{name}"
                    self.iat_slot_to_name[imp.address] = label
                    self.func_addr_map[imp.address] = label

        # delay imports
        if hasattr(self.pe, 'DIRECTORY_ENTRY_DELAY_IMPORT') and getattr(self.pe, 'DIRECTORY_ENTRY_DELAY_IMPORT') is not None:
            try:
                for entry in self.pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                    dll = entry.dll.decode('utf-8', errors='ignore') if getattr(entry, 'dll', None) else ''
                    for imp in getattr(entry, 'imports', []) or []:
                        if not getattr(imp, 'address', None):
                            continue
                        name = None
                        if getattr(imp, 'name', None):
                            try:
                                name = imp.name.decode('utf-8', errors='ignore')
                            except Exception:
                                name = None
                        if not name:
                            name = f"ordinal#{getattr(imp, 'ordinal', '?')}"
                        label = f"{dll}!{name}"
                        self.iat_slot_to_name[imp.address] = label
                        self.func_addr_map[imp.address] = label
            except Exception:
                pass

        # vtables
        self.scan_vtables(min_entries=2)

        # thunks detection: jmp dword ptr [disp] ; try disp and disp+ImageBase
        self.ensure_disassembled()
        if not self._last_instructions:
            return
        img_base = self.pe.OPTIONAL_HEADER.ImageBase
        for ins in self._last_instructions:
            if ins.mnemonic == 'jmp' and len(ins.operands) == 1:
                op = ins.operands[0]
                if op.type == CS_OP_MEM:
                    mem = op.mem
                    if mem.base == 0 and mem.index == 0:
                        for candidate in (mem.disp, mem.disp + img_base):
                            if candidate in self.iat_slot_to_name:
                                self.thunk_to_name[ins.address] = self.iat_slot_to_name[candidate]
                                break

    # ------------------------
    # small static reg-state updater
    # ------------------------
    def _reg_name(self, reg_id: int) -> str:
        return self.md.reg_name(reg_id)

    def _update_reg_state_for_instruction(self, ins: capstone.CsInsn, reg_state: dict):
        try:
            m = ins.mnemonic
            ops = ins.operands
            if m == 'mov' and len(ops) >= 2:
                dst, src = ops[0], ops[1]
                if dst.type == CS_OP_REG and src.type == CS_OP_IMM:
                    reg_state[self._reg_name(dst.reg)] = src.imm
                elif dst.type == CS_OP_REG and src.type == CS_OP_REG:
                    reg_state[self._reg_name(dst.reg)] = reg_state.get(self._reg_name(src.reg), 0)
                elif dst.type == CS_OP_REG and src.type == CS_OP_MEM:
                    mem = src.mem
                    # support mem.base==0,index==0 with disp or disp+ImageBase
                    if mem.base == 0 and mem.index == 0:
                        for candidate in (mem.disp, mem.disp + self.pe.OPTIONAL_HEADER.ImageBase):
                            ptr = self.read_memory_dword(candidate)
                            if ptr:
                                reg_state[self._reg_name(dst.reg)] = ptr
                                break
            elif m == 'xor' and len(ops) >= 2:
                dst, src = ops[0], ops[1]
                if dst.type == CS_OP_REG and src.type == CS_OP_REG and dst.reg == src.reg:
                    reg_state[self._reg_name(dst.reg)] = 0
            elif m == 'lea' and len(ops) >= 2:
                dst, src = ops[0], ops[1]
                if dst.type == CS_OP_REG and src.type == CS_OP_MEM:
                    mem = src.mem
                    if mem.base == 0 and mem.index == 0:
                        reg_state[self._reg_name(dst.reg)] = mem.disp
            elif m in ('add', 'sub') and len(ops) >= 2:
                dst, src = ops[0], ops[1]
                if dst.type == CS_OP_REG and src.type == CS_OP_IMM:
                    cur = reg_state.get(self._reg_name(dst.reg), 0)
                    if m == 'add':
                        reg_state[self._reg_name(dst.reg)] = cur + src.imm
                    else:
                        reg_state[self._reg_name(dst.reg)] = cur - src.imm
        except Exception:
            pass

    # ------------------------
    # mem operand abs address (try both disp and disp+ImageBase)
    # ------------------------
    def get_mem_operand_abs_address(self, op: capstone.CS_OP, reg_state: Optional[dict] = None) -> Optional[int]:
        if op.type != CS_OP_MEM:
            return None
        mem = op.mem
        # simple case
        if mem.base == 0 and mem.index == 0:
            # try disp as VA or disp+ImageBase
            candidates = [mem.disp, mem.disp + self.pe.OPTIONAL_HEADER.ImageBase]
            for cand in candidates:
                # quick check if inside any known section
                if self._classify_pointer(cand) is not None:
                    return cand
            # if none matched, return first candidate (best effort)
            return mem.disp
        # general case: need reg_state
        base_val = 0
        index_val = 0
        if mem.base != 0:
            if reg_state is None:
                return None
            base_val = reg_state.get(self._reg_name(mem.base), 0)
        if mem.index != 0:
            if reg_state is None:
                return None
            index_val = reg_state.get(self._reg_name(mem.index), 0) * mem.scale
        return base_val + index_val + mem.disp

    # ------------------------
    # follow chained jmps (thunks) up to hops
    # ------------------------
    def _follow_jmp_chain(self, addr: int, max_hops: int = 6) -> Optional[int]:
        """Se addr è dentro .text e l'istr. lì è jmp imm/reg/mem, segue la catena fino ad arrivare a IAT/thunk/.text"""
        self.ensure_disassembled()
        for hop in range(max_hops):
            idx = self._addr_to_index.get(addr)
            if idx is None:
                return addr
            ins = self._last_instructions[idx]
            if ins.mnemonic == 'jmp' and len(ins.operands) == 1:
                op = ins.operands[0]
                if op.type == CS_OP_IMM:
                    addr = op.imm
                    continue
                if op.type == CS_OP_MEM:
                    # try to deref mem: absolute or absolute+ImageBase
                    mem = op.mem
                    if mem.base == 0 and mem.index == 0:
                        for cand in (mem.disp, mem.disp + self.pe.OPTIONAL_HEADER.ImageBase):
                            ptr = self.read_memory_dword(cand)
                            if ptr:
                                addr = ptr
                                break
                        else:
                            # can't deref; break
                            return addr
                        continue
                    # other patterns: can't follow
                    return addr
                # other operand types: can't follow
                return addr
            else:
                # not a jmp, stop
                return addr
        return addr

    # ------------------------
    # resolve direct target with follow chain
    # ------------------------
    def resolve_direct_target(self, target_abs: int) -> str:
        # follow jmp chain first (to unroll thunks)
        final = self._follow_jmp_chain(target_abs)
        if final in self.thunk_to_name:
            self.stats['resolved_thunk'] += 1
            return self.thunk_to_name[final]
        if final in self.iat_slot_to_name:
            self.stats['resolved_iat'] += 1
            return self.iat_slot_to_name[final]
        sec = self._classify_pointer(final)
        if sec == '.text':
            self.stats['resolved_internal_direct'] += 1
            return f"internal_0x{final:X}"
        return f"unknown_0x{final:X}"

    # ------------------------
    # try_resolve_indirect_call (with disp+ImageBase attempts and vtable)
    # ------------------------
    def try_resolve_indirect_call(self, call_ins: capstone.CsInsn, depth: int = 80) -> str:
        self.ensure_disassembled()
        if not self._last_instructions or self._addr_to_index is None:
            self.stats['unresolved_other'] += 1
            return "call_indiretta_non_risolta"
        op = call_ins.operands[0]
        idx = self._addr_to_index.get(call_ins.address)
        if idx is None:
            self.stats['unresolved_other'] += 1
            return "call_indiretta_non_risolta"

        # call [mem]
        if op.type == CS_OP_MEM:
            mem = op.mem
            # case base==0,index==0: try disp, disp+ImageBase
            if mem.base == 0 and mem.index == 0:
                for candidate in (mem.disp, mem.disp + self.pe.OPTIONAL_HEADER.ImageBase):
                    if candidate in self.iat_slot_to_name:
                        self.stats['resolved_iat'] += 1
                        return self.iat_slot_to_name[candidate]
                    ptr = self.read_memory_dword(candidate)
                    if ptr:
                        if self._is_in_section(ptr, '.text'):
                            self.stats['resolved_internal_indirect'] += 1
                            return f"internal_0x{ptr:X}"
                        if ptr in self.thunk_to_name:
                            self.stats['resolved_thunk'] += 1
                            return self.thunk_to_name[ptr]
                        if ptr in self.iat_slot_to_name:
                            self.stats['resolved_iat'] += 1
                            return self.iat_slot_to_name[ptr]
                        # vtable heuristic: if candidate is vtable base or ptr in .rdata, check vtables
                        sec = self._classify_pointer(candidate)
                        if sec in ('.rdata', '.data', '.rodata'):
                            maybe_v = self._is_likely_vtable(candidate) or self._is_likely_vtable(ptr)
                            if maybe_v:
                                base, funcs = maybe_v
                                self.stats['resolved_vtable'] += 1
                                idx_v = (candidate - base) // 4 if maybe_v else 0
                                if 0 <= idx_v < len(funcs):
                                    return f"vtable_{base:X}_entry{idx_v}->0x{funcs[idx_v]:X}"
                        # fallback label
                        self.stats['unresolved_mem'] += 1
                        return f"call_mem_indiretta_0x{ptr:X}_non_mappata"
                # nothing found
                self.stats['unresolved_mem'] += 1
                return "call_mem_indiretta_non_mappata"

            # general: reconstruct reg state and try
            reg_state = {r: 0 for r in ['eax','ebx','ecx','edx','esi','edi','esp','ebp']}
            for i in range(idx-1, max(idx-depth-1, -1), -1):
                self._update_reg_state_for_instruction(self._last_instructions[i], reg_state)
            abs_mem = self.get_mem_operand_abs_address(op, reg_state)
            if abs_mem is None:
                self.stats['unresolved_mem'] += 1
                return "call_indiretta_non_risolta"
            # try deref
            ptr = self.read_memory_dword(abs_mem)
            if ptr:
                if self._is_in_section(ptr, '.text'):
                    self.stats['resolved_internal_indirect'] += 1
                    return f"internal_0x{ptr:X}"
                if ptr in self.iat_slot_to_name:
                    self.stats['resolved_iat'] += 1
                    return self.iat_slot_to_name[ptr]
                maybe_v = self._is_likely_vtable(abs_mem)
                if maybe_v:
                    base, funcs = maybe_v
                    self.stats['resolved_vtable'] += 1
                    idx_v = (abs_mem - base) // 4
                    if 0 <= idx_v < len(funcs):
                        return f"vtable_{base:X}_entry{idx_v}->0x{funcs[idx_v]:X}"
                self.stats['unresolved_mem'] += 1
                return f"call_mem_indiretta_0x{ptr:X}_non_mappata"
            self.stats['unresolved_mem'] += 1
            return "call_mem_indiretta_non_mappata"

        # call reg
        if op.type == CS_OP_REG:
            reg_name = self._reg_name(op.reg)
            reg_state = {r: 0 for r in ['eax','ebx','ecx','edx','esi','edi','esp','ebp']}
            for i in range(idx-1, max(idx-depth-1, -1), -1):
                prev = self._last_instructions[i]
                self._update_reg_state_for_instruction(prev, reg_state)
                # mov reg, imm
                if prev.mnemonic == 'mov' and len(prev.operands) >= 2:
                    dst, src = prev.operands[0], prev.operands[1]
                    if dst.type == CS_OP_REG and self._reg_name(dst.reg) == reg_name:
                        if src.type == CS_OP_IMM:
                            imm = src.imm
                            for candidate in (imm, imm + self.pe.OPTIONAL_HEADER.ImageBase):
                                if candidate in self.thunk_to_name:
                                    self.stats['resolved_thunk'] += 1
                                    return self.thunk_to_name[candidate]
                                if candidate in self.iat_slot_to_name:
                                    self.stats['resolved_iat'] += 1
                                    return self.iat_slot_to_name[candidate]
                                val = self.read_memory_dword(candidate)
                                if val:
                                    if self._is_in_section(val, '.text'):
                                        self.stats['resolved_internal_indirect'] += 1
                                        return f"internal_0x{val:X}"
                                    if val in self.iat_slot_to_name:
                                        self.stats['resolved_iat'] += 1
                                        return self.iat_slot_to_name[val]
                                    self.stats['unresolved_mem'] += 1
                                    return f"call_indiretta_0x{val:X}_non_mappata"
                        elif src.type == CS_OP_MEM:
                            try:
                                abs_mem = self.get_mem_operand_abs_address(src, reg_state)
                            except Exception:
                                abs_mem = None
                            if abs_mem:
                                if abs_mem in self.iat_slot_to_name:
                                    self.stats['resolved_iat'] += 1
                                    return self.iat_slot_to_name[abs_mem]
                                val = self.read_memory_dword(abs_mem)
                                if val:
                                    if self._is_in_section(val, '.text'):
                                        self.stats['resolved_internal_indirect'] += 1
                                        return f"internal_0x{val:X}"
                                    if val in self.iat_slot_to_name:
                                        self.stats['resolved_iat'] += 1
                                        return self.iat_slot_to_name[val]
                                    self.stats['unresolved_mem'] += 1
                                    return f"call_mem_indiretta_0x{val:X}_non_mappata"
                # lea reg, [disp]
                if prev.mnemonic == 'lea' and len(prev.operands) >= 2:
                    dst, src = prev.operands[0], prev.operands[1]
                    if dst.type == CS_OP_REG and self._reg_name(dst.reg) == reg_name and src.type == CS_OP_MEM:
                        mem = src.mem
                        if mem.base == 0 and mem.index == 0:
                            addr = mem.disp
                            for candidate in (addr, addr + self.pe.OPTIONAL_HEADER.ImageBase):
                                if candidate in self.thunk_to_name:
                                    self.stats['resolved_thunk'] += 1
                                    return self.thunk_to_name[candidate]
                                if candidate in self.iat_slot_to_name:
                                    self.stats['resolved_iat'] += 1
                                    return self.iat_slot_to_name[candidate]
                                val = self.read_memory_dword(candidate)
                                if val:
                                    if self._is_in_section(val, '.text'):
                                        self.stats['resolved_internal_indirect'] += 1
                                        return f"internal_0x{val:X}"
                                    self.stats['unresolved_mem'] += 1
                                    return f"call_mem_indiretta_0x{val:X}_non_mappata"
            return "call_indiretta_non_risolta"

        self.stats['unresolved_other'] += 1
        return "call_indiretta_non_risolta"

    # ------------------------
    # Public scanning
    # ------------------------
    def find_calls_to_functions(self, func_names: Optional[Iterable[str]] = None) -> List[Tuple[int,str]]:
        self.ensure_disassembled()
        self.build_full_import_maps()
        out: List[Tuple[int,str]] = []
        for ins in self._last_instructions:
            if ins.mnemonic != 'call' or len(ins.operands) == 0:
                continue
            self.stats['total_calls'] += 1
            op = ins.operands[0]
            if op.type == CS_OP_IMM:
                target = op.imm
                # try imm and imm+ImageBase for direct calls
                label = self.resolve_direct_target(target)
                if label.startswith('unknown_'):
                    alt = target + self.pe.OPTIONAL_HEADER.ImageBase
                    label2 = self.resolve_direct_target(alt)
                    if not label2.startswith('unknown_'):
                        label = label2
                out_label = label
            else:
                out_label = self.try_resolve_indirect_call(ins)
            if func_names is None:
                out.append((ins.address, out_label))
            else:
                for patt in func_names:
                    if patt and isinstance(out_label, str) and patt.lower() in out_label.lower():
                        out.append((ins.address, out_label))
                        break
        return out

    # ------------------------
    # Find LoadLibrary/GetProcAddress strings
    # ------------------------
    def find_loadlibrary_getprocaddress_strings(self) -> List[Tuple[str,str]]:
        calls = self.find_calls_to_functions()
        self.ensure_disassembled()
        results: List[Tuple[str,str]] = []
        for call_va, resolved in calls:
            if not isinstance(resolved, str):
                continue
            low = resolved.lower()
            if 'loadlibrary' not in low and 'getprocaddress' not in low:
                continue
            idx = self._addr_to_index.get(call_va)
            arg_str = None
            if idx is None:
                results.append((resolved, "<non trovata>"))
                continue
            reg_state = {r:0 for r in ['eax','ebx','ecx','edx','esi','edi','esp','ebp']}
            start = max(0, idx-40)
            for i in range(start, idx):
                self._update_reg_state_for_instruction(self._last_instructions[i], reg_state)
            for j in range(idx-1, max(idx-20,-1), -1):
                ins = self._last_instructions[j]
                if ins.mnemonic == 'push' and len(ins.operands) >= 1:
                    op = ins.operands[0]
                    if op.type == CS_OP_IMM:
                        for candidate in (op.imm, op.imm + self.pe.OPTIONAL_HEADER.ImageBase):
                            s = self.read_best_string_at(candidate)
                            if s:
                                arg_str = s
                                break
                        if arg_str:
                            break
                    elif op.type == CS_OP_MEM:
                        try:
                            mem_abs = self.get_mem_operand_abs_address(op, reg_state)
                        except Exception:
                            mem_abs = None
                        if mem_abs:
                            ptr = self.read_memory_dword(mem_abs)
                            if ptr:
                                s = self.read_best_string_at(ptr)
                                if s:
                                    arg_str = s
                                    break
                if ins.mnemonic == 'mov' and len(ins.operands) >= 2:
                    dst, src = ins.operands[0], ins.operands[1]
                    if dst.type == CS_OP_REG and src.type == CS_OP_IMM:
                        for candidate in (src.imm, src.imm + self.pe.OPTIONAL_HEADER.ImageBase):
                            s = self.read_best_string_at(candidate)
                            if s:
                                arg_str = s
                                break
                        if arg_str:
                            break
            if not arg_str:
                arg_str = "<non trovata>"
            results.append((resolved, arg_str))
        return results

    # ------------------------
    # Diagnostics
    # ------------------------
    def dump_unresolved_calls(self, limit: Optional[int] = None) -> List[Tuple[int,str]]:
        """Ritorna e stampa le call non risolte (o call mem indiretta non mappate)."""
        self.ensure_disassembled()
        calls = self.find_calls_to_functions()
        unresolved = []
        for addr, label in calls:
            if isinstance(label, str) and ('non_mappata' in label or 'non_risolta' in label or label.startswith('unknown_')):
                unresolved.append((addr, label))
        if limit:
            unresolved = unresolved[:limit]
        # print details for each
        for addr, label in unresolved:
            print(f"UNRESOLVED 0x{addr:X} -> {label}")
            idx = self._addr_to_index.get(addr)
            if idx is None:
                continue
            # print window -3..+2
            for i in range(max(0, idx-3), min(len(self._last_instructions), idx+3)):
                ins = self._last_instructions[i]
                marker = "=> " if ins.address == addr else "   "
                print(f"{marker}0x{ins.address:X}: {ins.mnemonic} {ins.op_str}")
        return unresolved

    def compare_with_other_callset(self, other_addrs: Iterable[int]) -> Dict[str, Set[int]]:
        """Confronta gli indirizzi di call (attualmente trovati) con 'other_addrs' dal vecchio script.
           Restituisce dict con 'only_new', 'only_old', 'both' sets."""
        current = {addr for addr, _ in self.find_calls_to_functions()}
        other = set(other_addrs)
        return {
            'only_new': current - other,
            'only_old': other - current,
            'both': current & other
        }

    # ------------------------
    # Stats helpers
    # ------------------------
    def get_stats(self) -> Dict[str, float]:
        total = max(1, self.stats.get('total_calls', 0))
        return {k: (v / total * 100.0) for k, v in self.stats.items()}

    def dump_stats(self):
        stats = self.get_stats()
        print("=== Dynamic stats (%) ===")
        for k,v in stats.items():
            print(f"{k}: {v:.4f}%")
        return stats
