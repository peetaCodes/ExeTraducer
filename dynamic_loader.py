import pefile
import capstone

class DynamicLoaderAnalyzer:
    def __init__(self, pe):
        self.pe = pe
        # Capstone (x86 32-bit)
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.md.detail = True

        # Stato per l’analisi
        self.registers_current_values = {r: 0 for r in ['eax','ebx','ecx','edx','esi','edi','esp','ebp']}
        self._last_instructions = None
        self._addr_to_index = None

        # Mappa indirizzo_import → nome_funzione (riempita on-demand)
        self.func_addr_map = {}

    # ----------------- Setup/Disassemblaggio -----------------

    def ensure_disassembled(self):
        if self._last_instructions is not None and self._addr_to_index is not None:
            return
        text = None
        for s in self.pe.sections:
            name = s.Name.decode(errors='ignore').rstrip('\x00')
            if name == '.text':
                text = s
                break
        if not text:
            self._last_instructions, self._addr_to_index = [], {}
            return
        code = text.get_data()
        base = self.pe.OPTIONAL_HEADER.ImageBase + text.VirtualAddress
        insns = list(self.md.disasm(code, base))
        self._last_instructions = insns
        self._addr_to_index = {ins.address: i for i, ins in enumerate(insns)}

    def build_full_import_maps(self):
        """
        Costruisce:
          - self.iat_slot_to_name: { IAT_slot_abs_VA -> "Kernel32.dll!LoadLibraryA" }
          - self.thunk_to_name:    { stub_addr_in_text -> "Kernel32.dll!LoadLibraryA" }
        """
        self.iat_slot_to_name = {}
        self.thunk_to_name = {}

        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return

        img_base = self.pe.OPTIONAL_HEADER.ImageBase

        # 1) Mappa IAT slot -> nome funzione
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('utf-8', errors='ignore') if entry.dll else ''
            for imp in entry.imports:
                if not imp or not imp.address:
                    continue
                fname = imp.name.decode('utf-8', errors='ignore') if imp.name else None
                if not fname:
                    # import by ordinal; usa "ordinal#NNN"
                    fname = f"ordinal#{imp.ordinal}" if imp.ordinal else "unknown"
                self.iat_slot_to_name[imp.address] = f"{dll}!{fname}"

        # 2) Cerca thunk nel .text: pattern "jmp dword ptr [abs]"
        self.ensure_disassembled()
        for ins in self._last_instructions:
            if ins.mnemonic == 'jmp' and len(ins.operands) == 1:
                op = ins.operands[0]
                if op.type == capstone.x86.X86_OP_MEM:
                    try:
                        abs_mem = self.get_mem_operand_abs_address(op)
                    except Exception:
                        continue
                    # se l'operand punta ad uno slot IAT, questo indirizzo "ins.address" è uno stub
                    if abs_mem in self.iat_slot_to_name:
                        self.thunk_to_name[ins.address] = self.iat_slot_to_name[abs_mem]

    # ----------------- Letture memoria/registri -----------------

    def read_memory_dword(self, absolute_address, size=4):
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
                chunk = data[raw_off:raw_off+size]
                return int.from_bytes(chunk, 'little')
        return None

    def read_ascii_string_at(self, absolute_address, max_len=2048):
        data = self.pe.__data__
        img = self.pe.OPTIONAL_HEADER.ImageBase
        for sec in self.pe.sections:
            start = img + sec.VirtualAddress
            end = start + max(sec.Misc_VirtualSize, sec.SizeOfRawData)
            if start <= absolute_address < end:
                off = sec.PointerToRawData + (absolute_address - start)
                out = []
                for i in range(max_len):
                    if off + i >= len(data):
                        break
                    b = data[off + i]
                    if b == 0:
                        break
                    if 32 <= b <= 126:
                        out.append(chr(b))
                    else:
                        return None
                return ''.join(out) if out else None
        return None

    def read_utf16le_string_at(self, absolute_address, max_len=2048):
        data = self.pe.__data__
        img = self.pe.OPTIONAL_HEADER.ImageBase
        for sec in self.pe.sections:
            start = img + sec.VirtualAddress
            end = start + max(sec.Misc_VirtualSize, sec.SizeOfRawData)
            if start <= absolute_address < end:
                off = sec.PointerToRawData + (absolute_address - start)
                out = []
                for i in range(0, max_len, 2):
                    if off + i + 1 >= len(data):
                        break
                    lo = data[off + i]
                    hi = data[off + i + 1]
                    ch = lo | (hi << 8)
                    if ch == 0:
                        break
                    # range unicode basilare stampabile
                    if 32 <= ch <= 0xFFFF:
                        out.append(chr(ch))
                    else:
                        return None
                return ''.join(out) if out else None
        return None

    def read_best_string_at(self, absolute_address):
        s = self.read_ascii_string_at(absolute_address)
        if s:
            return s
        s = self.read_utf16le_string_at(absolute_address)
        return s

    def get_mem_operand_abs_address(self, op):
        """op: ins.operands[n] (Capstone). type deve essere MEM."""
        if op.type != capstone.x86.X86_OP_MEM:
            raise ValueError("Operando non di tipo memoria (CS_OP_MEM).")
        mem = op.mem
        base_val = 0
        idx_val = 0
        if mem.base != 0:
            base_val = self.registers_current_values.get(self.md.reg_name(mem.base), 0)
        if mem.index != 0:
            idx_val = self.registers_current_values.get(self.md.reg_name(mem.index), 0) * mem.scale
        return base_val + idx_val + mem.disp

    def update_registers_from_instruction(self, ins):
        try:
            if ins.mnemonic == 'mov' and len(ins.operands) >= 2:
                dst, src = ins.operands[0], ins.operands[1]
                if dst.type == capstone.x86.X86_OP_REG and src.type == capstone.x86.X86_OP_IMM:
                    self.registers_current_values[self.md.reg_name(dst.reg)] = src.imm
                elif dst.type == capstone.x86.X86_OP_REG and src.type == capstone.x86.X86_OP_REG:
                    self.registers_current_values[self.md.reg_name(dst.reg)] = \
                        self.registers_current_values.get(self.md.reg_name(src.reg), 0)
            elif ins.mnemonic == 'xor' and len(ins.operands) >= 2:
                dst, src = ins.operands[0], ins.operands[1]
                if dst.type == capstone.x86.X86_OP_REG and src.type == capstone.x86.X86_OP_REG and dst.reg == src.reg:
                    self.registers_current_values[self.md.reg_name(dst.reg)] = 0
            elif ins.mnemonic == 'lea' and len(ins.operands) >= 2:
                dst, src = ins.operands[0], ins.operands[1]
                if dst.type == capstone.x86.X86_OP_REG and src.type == capstone.x86.X86_OP_MEM:
                    mem = src.mem
                    if mem.base == 0 and mem.index == 0:
                        self.registers_current_values[self.md.reg_name(dst.reg)] = mem.disp
        except Exception:
            pass

    # ----------------- Risoluzione call -----------------

    def resolve_direct_target(self, target_abs):
        """
        Prova a risolvere una CALL diretta:
        - se target è in thunk_to_name => ritorna quel nome (API)
        - se target è in iat_slot_to_name => improbabile per call diretta, ma gestiamo comunque
        - se target cade in .text e non è thunk => presumibilmente funzione interna
        """
        if hasattr(self, 'thunk_to_name') and target_abs in self.thunk_to_name:
            return self.thunk_to_name[target_abs]

        if hasattr(self, 'iat_slot_to_name') and target_abs in self.iat_slot_to_name:
            return self.iat_slot_to_name[target_abs]

        # Heuristica: se sta nel .text e non è stub → scrivi "internal"
        img_base = self.pe.OPTIONAL_HEADER.ImageBase
        for sec in self.pe.sections:
            name = sec.Name.decode(errors='ignore').rstrip('\x00')
            start = img_base + sec.VirtualAddress
            end = start + max(sec.Misc_VirtualSize, sec.SizeOfRawData)
            if start <= target_abs < end:
                if name == '.text':
                    return f"internal_0x{target_abs:X}"
        return f"unknown_0x{target_abs:X}"

    def try_resolve_indirect_call(self, call_ins, depth=80):
        """
        Esteso:
        - call [abs] -> se abs è IAT slot -> nome import
        - call [reg+disp] -> se disp solo (base=0,index=0) usiamo disp come abs; altrimenti prova data-flow semplice
        - call reg -> data-flow (mov/lea) e prova deref -> IAT
        """
        self.ensure_disassembled()
        op = call_ins.operands[0]
        idx = self._addr_to_index.get(call_ins.address, None)
        if idx is None:
            return "call_indiretta_non_risolta"

        # MEM: call [something]
        if op.type == capstone.x86.X86_OP_MEM:
            try:
                abs_mem_addr = self.get_mem_operand_abs_address(op)
            except Exception:
                return "call_indiretta_non_risolta"

            # caso semplice: [abs] è proprio uno slot IAT
            if hasattr(self, 'iat_slot_to_name') and abs_mem_addr in self.iat_slot_to_name:
                return self.iat_slot_to_name[abs_mem_addr]

            # caso: dereferenzia [abs] -> ptr; a volte in file punta a thunk/IAT
            ptr = self.read_memory_dword(abs_mem_addr, 4)
            if ptr:
                # se ptr è thunk
                if hasattr(self, 'thunk_to_name') and ptr in self.thunk_to_name:
                    return self.thunk_to_name[ptr]
                # se ptr è IAT slot (meno comune qui)
                if hasattr(self, 'iat_slot_to_name') and ptr in self.iat_slot_to_name:
                    return self.iat_slot_to_name[ptr]
                # fallback: non mappata ma stampo dove punta
                return f"call_mem_indiretta_0x{ptr:X}_non_mappata"

            return "call_indiretta_non_risolta"

        # REG: call eax (data-flow retro)
        if op.type == capstone.x86.X86_OP_REG:
            reg_name = self.md.reg_name(op.reg)
            for i in range(idx - 1, max(idx - depth - 1, -1), -1):
                prev = self._last_instructions[i]
                # aggiorna uno stato minimo dei registri
                self.update_registers_from_instruction(prev)

                # Prova pattern chiave
                if prev.mnemonic == 'mov' and len(prev.operands) == 2:
                    dst, src = prev.operands[0], prev.operands[1]
                    if dst.type == capstone.x86.X86_OP_REG and self.md.reg_name(dst.reg) == reg_name:
                        # mov reg, imm
                        if src.type == capstone.x86.X86_OP_IMM:
                            imm = src.imm
                            # imm può essere indirizzo di thunk
                            if hasattr(self, 'thunk_to_name') and imm in self.thunk_to_name:
                                return self.thunk_to_name[imm]
                            # imm può essere slot IAT (raro in mov reg, imm)
                            if hasattr(self, 'iat_slot_to_name') and imm in self.iat_slot_to_name:
                                return self.iat_slot_to_name[imm]
                            # dereferenzia imm (es. puntatore a thunk/IAT)
                            val = self.read_memory_dword(imm, 4)
                            if val:
                                if hasattr(self, 'thunk_to_name') and val in self.thunk_to_name:
                                    return self.thunk_to_name[val]
                                if hasattr(self, 'iat_slot_to_name') and val in self.iat_slot_to_name:
                                    return self.iat_slot_to_name[val]
                                return f"call_indiretta_0x{val:X}_non_mappata"
                        # mov reg, [mem]
                        elif src.type == capstone.x86.X86_OP_MEM:
                            try:
                                mem_addr = self.get_mem_operand_abs_address(src)
                            except Exception:
                                continue
                            # [mem] è slot IAT?
                            if hasattr(self, 'iat_slot_to_name') and mem_addr in self.iat_slot_to_name:
                                return self.iat_slot_to_name[mem_addr]
                            # altrimenti dereferenzia
                            val = self.read_memory_dword(mem_addr, 4)
                            if val:
                                if hasattr(self, 'thunk_to_name') and val in self.thunk_to_name:
                                    return self.thunk_to_name[val]
                                if hasattr(self, 'iat_slot_to_name') and val in self.iat_slot_to_name:
                                    return self.iat_slot_to_name[val]
                                return f"call_mem_indiretta_0x{val:X}_non_mappata"

                # lea reg, [disp] → a volte puntatore a thunk
                if prev.mnemonic == 'lea' and len(prev.operands) == 2:
                    dst, src = prev.operands[0], prev.operands[1]
                    if dst.type == capstone.x86.X86_OP_REG and self.md.reg_name(
                            dst.reg) == reg_name and src.type == capstone.x86.X86_OP_MEM:
                        mem = src.mem
                        if mem.base == 0 and mem.index == 0:
                            addr = mem.disp
                            if hasattr(self, 'thunk_to_name') and addr in self.thunk_to_name:
                                return self.thunk_to_name[addr]
                            if hasattr(self, 'iat_slot_to_name') and addr in self.iat_slot_to_name:
                                return self.iat_slot_to_name[addr]
                            val = self.read_memory_dword(addr, 4)
                            if val:
                                if hasattr(self, 'thunk_to_name') and val in self.thunk_to_name:
                                    return self.thunk_to_name[val]
                                if hasattr(self, 'iat_slot_to_name') and val in self.iat_slot_to_name:
                                    return self.iat_slot_to_name[val]
            return "call_indiretta_non_risolta"

        return "call_indiretta_non_risolta"

    # ----------------- API pubbliche richieste -----------------

    def find_calls_to_functions(self, func_names):
        """Ritorna [(indirizzo_call, nome_funzione | descrizione)]"""
        self.ensure_disassembled()
        self.build_full_import_maps()

        out = []
        for ins in self._last_instructions:
            self.update_registers_from_instruction(ins)

            if ins.mnemonic != 'call' or len(ins.operands) == 0:
                continue

            op = ins.operands[0]

            # CALL diretta (IMM)
            if op.type == capstone.x86.X86_OP_IMM:
                target = op.imm
                label = self.resolve_direct_target(target)
                out.append((ins.address, label))
                continue

            # CALL indiretta
            label = self.try_resolve_indirect_call(ins)
            out.append((ins.address, label))

        return out

    def find_loadlibrary_getprocaddress_strings(self):
        """Ritorna [(nome_funzione_chiamata, arg_stringa_o_<non trovata>)]"""
        func_names = ['LoadLibraryA','LoadLibraryW','LoadLibraryExA','LoadLibraryExW','GetProcAddress']
        calls = self.find_calls_to_functions(func_names)
        self.ensure_disassembled()
        results = []

        # mappa indirizzo call -> index istruzione per risalire ai push
        for call_addr, func_or_desc in calls:
            idx = self._addr_to_index.get(call_addr, None)
            if idx is None:
                results.append((func_or_desc, "<non trovata>"))
                continue

            # cerchiamo un push immediato poco prima (euristica)
            arg_str = None
            for j in range(idx-1, max(idx-30, -1), -1):
                prev = self._last_instructions[j]
                self.update_registers_from_instruction(prev)
                if prev.mnemonic == 'push' and len(prev.operands) == 1:
                    op = prev.operands[0]
                    if op.type == capstone.x86.X86_OP_IMM:
                        imm = op.imm
                        s = self.read_ascii_string_at(imm)
                        if s:
                            arg_str = s
                            break
                        # prova come RVA: imm - ImageBase
                        maybe_abs = imm
                        if not s:
                            s = self.read_ascii_string_at(maybe_abs)
                            if s:
                                arg_str = s
                                break
                    elif op.type == capstone.x86.X86_OP_MEM:
                        try:
                            abs_addr = self.get_mem_operand_abs_address(op)
                            ptr = self.read_memory_dword(abs_addr, 4)
                            if ptr:
                                s = self.read_ascii_string_at(ptr)
                                if s:
                                    arg_str = s
                                    break
                        except Exception:
                            pass

            results.append((func_or_desc, arg_str if arg_str else "<non trovata>"))
        return results
