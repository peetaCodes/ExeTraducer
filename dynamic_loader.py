# dynamic_loader.py
#TODO map and resolve each call
import pefile
import capstone

# Costanti capstone per comodità
CS_OP_MEM = capstone.CS_OP_MEM
CS_OP_IMM = capstone.CS_OP_IMM
CS_OP_REG = capstone.CS_OP_REG

class DynamicLoaderAnalyzer:
    def __init__(self, pe: pefile.PE):
        self.pe = pe

        # Capstone disasm (x86 32-bit)
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.md.detail = True

        # Disassembly cache
        self._last_instructions = None
        self._addr_to_index = None

        # Mappe di import / thunk (popolate da build_full_import_maps)
        self.iat_slot_to_name = {}
        self.thunk_to_name = {}

        # Mappa indirizzo_import -> nome funzione (semplificata)
        self.func_addr_map = {}

    # -----------------------------
    # Disassemblaggio e caching
    # -----------------------------
    def ensure_disassembled(self):
        """Disassembla la sezione .text se non è già presente in cache."""
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

    # -----------------------------
    # Letture memoria dal PE
    # -----------------------------
    def read_memory_bytes(self, absolute_address, size):
        """Legge 'size' byte dall'immagine mappata del PE dato un indirizzo assoluto (VA)."""
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

    def read_memory_dword(self, absolute_address):
        """Legge 4 byte little-endian dall'indirizzo assoluto (ritorna int)"""
        chunk = self.read_memory_bytes(absolute_address, 4)
        if not chunk or len(chunk) < 4:
            return None
        return int.from_bytes(chunk, 'little')

    def read_ascii_string_at(self, absolute_address, max_len=2048):
        """Prova a leggere una stringa ASCII stampabile da absolute_address."""
        chunk = self.read_memory_bytes(absolute_address, max_len)
        if not chunk:
            return None
        out = []
        for b in chunk:
            if b == 0:
                break
            if 32 <= b <= 126:
                out.append(chr(b))
            else:
                return None
        return ''.join(out) if out else None

    def read_utf16le_string_at(self, absolute_address, max_len=2048):
        """Prova a leggere una stringa UTF-16LE da absolute_address."""
        # max_len in byte (multiplo di 2 preferibile)
        chunk = self.read_memory_bytes(absolute_address, max_len)
        if not chunk:
            return None
        # Tentativo semplice: decodifica e prendi fino al primo \x00\x00
        try:
            s = chunk.decode('utf-16le', errors='strict')
            return s.split('\x00', 1)[0]
        except Exception:
            return None

    def read_best_string_at(self, absolute_address):
        """Prova UTF-16LE prima, poi ASCII."""
        s = self.read_utf16le_string_at(absolute_address)
        if s:
            return s
        return self.read_ascii_string_at(absolute_address)

    # -----------------------------
    # Build import maps (IAT + thunk)
    # -----------------------------
    def build_full_import_maps(self):
        """
        Costruisce:
          - self.iat_slot_to_name: VA_slot -> "DLL!Func"
          - self.thunk_to_name: stub_va_in_.text -> "DLL!Func"  (se trovi stubs jmp [slot])
        """
        self.iat_slot_to_name = {}
        self.thunk_to_name = {}
        self.func_addr_map = {}

        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return

        # IAT slots
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('utf-8', errors='ignore') if entry.dll else ''
            for imp in entry.imports:
                if not imp or not getattr(imp, 'address', None):
                    continue
                name = None
                if imp.name:
                    try:
                        name = imp.name.decode('utf-8', errors='ignore')
                    except Exception:
                        name = None
                if not name:
                    name = f"ordinal#{getattr(imp, 'ordinal', '?')}"
                self.iat_slot_to_name[imp.address] = f"{dll}!{name}"
                # anche func_addr_map per lookup semplice
                self.func_addr_map[imp.address] = f"{dll}!{name}"

        # Detect thunk stubs nel .text: pattern "jmp dword ptr [abs]"
        self.ensure_disassembled()
        if not self._last_instructions:
            return

        for ins in self._last_instructions:
            if ins.mnemonic == 'jmp' and len(ins.operands) == 1:
                op = ins.operands[0]
                if op.type == CS_OP_MEM:
                    # ricaviamo l'indirizzo assoluto dell'operand se possibile (caso base/index == 0)
                    addr = self._try_get_mem_operand_simple_abs(op)
                    if addr and addr in self.iat_slot_to_name:
                        self.thunk_to_name[ins.address] = self.iat_slot_to_name[addr]

    def _try_get_mem_operand_simple_abs(self, op):
        """
        Calcolo semplice dell'indirizzo quando op.mem.base==0 and index==0.
        Restituisce VA (abs) o None.
        """
        if op.type != CS_OP_MEM:
            return None
        mem = op.mem
        if mem.base == 0 and mem.index == 0:
            # mem.disp è tipicamente un valore assoluto (o relativo al linker); proviamo come VA
            return mem.disp
        return None

    # -----------------------------
    # Helpers: register-state simulation (locale)
    # -----------------------------
    def _reg_name(self, reg_id):
        return self.md.reg_name(reg_id)

    def _update_reg_state_for_instruction(self, ins, reg_state):
        """
        Aggiorna reg_state (dict) con pattern semplici per MOV/XOR/LEA.
        Non altera lo stato esterno della classe.
        """
        try:
            if ins.mnemonic == 'mov' and len(ins.operands) >= 2:
                dst, src = ins.operands[0], ins.operands[1]
                if dst.type == CS_OP_REG and src.type == CS_OP_IMM:
                    reg_state[self._reg_name(dst.reg)] = src.imm
                elif dst.type == CS_OP_REG and src.type == CS_OP_REG:
                    reg_state[self._reg_name(dst.reg)] = reg_state.get(self._reg_name(src.reg), 0)
            elif ins.mnemonic == 'xor' and len(ins.operands) >= 2:
                dst, src = ins.operands[0], ins.operands[1]
                if dst.type == CS_OP_REG and src.type == CS_OP_REG and dst.reg == src.reg:
                    reg_state[self._reg_name(dst.reg)] = 0
            elif ins.mnemonic == 'lea' and len(ins.operands) >= 2:
                dst, src = ins.operands[0], ins.operands[1]
                if dst.type == CS_OP_REG and src.type == CS_OP_MEM:
                    mem = src.mem
                    # gestione semplice: se base==0,index==0 -> disp è indirizzo
                    if mem.base == 0 and mem.index == 0:
                        reg_state[self._reg_name(dst.reg)] = mem.disp
        except Exception:
            pass

    # -----------------------------
    # Calcolo indirizzo per operando MEM (usando reg_state)
    # -----------------------------
    def get_mem_operand_abs_address(self, op, reg_state=None):
        """
        Calcola indirizzo assoluto per op (operand di Capstone) se possibile.
        reg_state è dict con valori di registro se disponibili; se None assume 0.
        """
        if op.type != CS_OP_MEM:
            return None
        mem = op.mem
        base_val = 0
        index_val = 0
        if mem.base != 0:
            if reg_state is None:
                return None
            base_reg = self._reg_name(mem.base)
            base_val = reg_state.get(base_reg, 0)
        if mem.index != 0:
            if reg_state is None:
                return None
            index_reg = self._reg_name(mem.index)
            index_val = reg_state.get(index_reg, 0) * mem.scale
        return base_val + index_val + mem.disp

    # -----------------------------
    # Risoluzione target diretto/indiretto
    # -----------------------------
    def resolve_direct_target(self, target_abs):
        """Risolvi target di call diretta (IMM) usando thunk/IAT heuristics."""
        # thunk first
        if target_abs in self.thunk_to_name:
            return self.thunk_to_name[target_abs]
        if target_abs in self.iat_slot_to_name:
            return self.iat_slot_to_name[target_abs]
        # se è all'interno del .text -> funzione interna
        img_base = self.pe.OPTIONAL_HEADER.ImageBase
        for sec in self.pe.sections:
            start = img_base + sec.VirtualAddress
            end = start + max(sec.Misc_VirtualSize, sec.SizeOfRawData)
            if start <= target_abs < end:
                name = sec.Name.decode(errors='ignore').rstrip('\x00')
                if name == '.text':
                    return f"internal_0x{target_abs:X}"
        return f"unknown_0x{target_abs:X}"

    def try_resolve_indirect_call(self, call_ins, depth=80):
        """
        Tenta di risolvere una call indiretta (call reg / call [mem]) con euristiche:
        - Scansione a ritroso fino a depth istruzioni per trovare mov/lea che impostano il registro coinvolto
        - Dereferenziazione mem se possibile (read_memory_dword)
        Ritorna stringa descrittiva (es. "KERNEL32.dll!LoadLibraryA") o etichette tipo "call_indiretta_non_risolta".
        """
        self.ensure_disassembled()
        if not self._last_instructions or self._addr_to_index is None:
            return "call_indiretta_non_risolta"

        op = call_ins.operands[0]
        idx = self._addr_to_index.get(call_ins.address, None)
        if idx is None:
            return "call_indiretta_non_risolta"

        # Caso call [mem]
        if op.type == CS_OP_MEM:
            # tentativo semplice: se mem.base/index == 0 -> mem.disp potrebbe essere VA (IAT slot)
            mem = op.mem
            if mem.base == 0 and mem.index == 0:
                abs_mem = mem.disp
                # se è uno slot IAT
                if abs_mem in self.iat_slot_to_name:
                    return self.iat_slot_to_name[abs_mem]
                # dereferenzia [abs] -> ptr
                ptr = self.read_memory_dword(abs_mem)
                if ptr:
                    if ptr in self.thunk_to_name:
                        return self.thunk_to_name[ptr]
                    if ptr in self.iat_slot_to_name:
                        return self.iat_slot_to_name[ptr]
                    return f"call_mem_indiretta_0x{ptr:X}_non_mappata"
                return "call_indiretta_non_risolta"
            # caso più generale: abbiamo bisogno di valori di registro -> ricostruisco reg_state locale
            reg_state = {r: 0 for r in ['eax','ebx','ecx','edx','esi','edi','esp','ebp']}
            for i in range(idx-1, max(idx-depth-1, -1), -1):
                prev = self._last_instructions[i]
                self._update_reg_state_for_instruction(prev, reg_state)
            try:
                abs_mem = self.get_mem_operand_abs_address(op, reg_state)
            except Exception:
                abs_mem = None
            if abs_mem is None:
                return "call_indiretta_non_risolta"
            # dereferenzia
            ptr = self.read_memory_dword(abs_mem)
            if ptr:
                if ptr in self.thunk_to_name:
                    return self.thunk_to_name[ptr]
                if ptr in self.iat_slot_to_name:
                    return self.iat_slot_to_name[ptr]
                return f"call_mem_indiretta_0x{ptr:X}_non_mappata"
            return "call_indiretta_non_risolta"

        # Caso call reg  (es. call eax)
        if op.type == CS_OP_REG:
            reg_name = self._reg_name(op.reg)
            # scanning backward con stato locale dei registri
            reg_state = {r: 0 for r in ['eax','ebx','ecx','edx','esi','edi','esp','ebp']}
            for i in range(idx-1, max(idx-depth-1, -1), -1):
                prev = self._last_instructions[i]
                # aggiorna reg_state (non globale)
                self._update_reg_state_for_instruction(prev, reg_state)

                # se trovi mov reg, imm
                if prev.mnemonic == 'mov' and len(prev.operands) >= 2:
                    dst, src = prev.operands[0], prev.operands[1]
                    if dst.type == CS_OP_REG and self._reg_name(dst.reg) == reg_name:
                        # mov reg, imm
                        if src.type == CS_OP_IMM:
                            imm = src.imm
                            # imm può essere indirizzo di thunk o IAT
                            if imm in self.thunk_to_name:
                                return self.thunk_to_name[imm]
                            if imm in self.iat_slot_to_name:
                                return self.iat_slot_to_name[imm]
                            # prova dereferenzia imm (imm potrebbe essere VA puntatore)
                            val = self.read_memory_dword(imm)
                            if val:
                                if val in self.thunk_to_name:
                                    return self.thunk_to_name[val]
                                if val in self.iat_slot_to_name:
                                    return self.iat_slot_to_name[val]
                                return f"call_indiretta_0x{val:X}_non_mappata"
                        # mov reg, [mem]
                        if src.type == CS_OP_MEM:
                            try:
                                abs_mem = self.get_mem_operand_abs_address(src, reg_state)
                            except Exception:
                                abs_mem = None
                            if abs_mem:
                                # se abs_mem è slot IAT
                                if abs_mem in self.iat_slot_to_name:
                                    return self.iat_slot_to_name[abs_mem]
                                val = self.read_memory_dword(abs_mem)
                                if val:
                                    if val in self.thunk_to_name:
                                        return self.thunk_to_name[val]
                                    if val in self.iat_slot_to_name:
                                        return self.iat_slot_to_name[val]
                                    return f"call_mem_indiretta_0x{val:X}_non_mappata"

                # lea reg, [disp] pattern
                if prev.mnemonic == 'lea' and len(prev.operands) >= 2:
                    dst, src = prev.operands[0], prev.operands[1]
                    if dst.type == CS_OP_REG and self._reg_name(dst.reg) == reg_name and src.type == CS_OP_MEM:
                        mem = src.mem
                        if mem.base == 0 and mem.index == 0:
                            addr = mem.disp
                            if addr in self.thunk_to_name:
                                return self.thunk_to_name[addr]
                            if addr in self.iat_slot_to_name:
                                return self.iat_slot_to_name[addr]
                            val = self.read_memory_dword(addr)
                            if val:
                                if val in self.thunk_to_name:
                                    return self.thunk_to_name[val]
                                if val in self.iat_slot_to_name:
                                    return self.iat_slot_to_name[val]
                                return f"call_mem_indiretta_0x{val:X}_non_mappata"
            return "call_indiretta_non_risolta"

        return "call_indiretta_non_risolta"

    # -----------------------------
    # Interfaccia pubblica
    # -----------------------------
    def find_calls_to_functions(self, func_names=None):
        """
        Scansiona tutte le CALL nella sezione .text e prova a risolverle.
        - func_names: None (tutte) oppure iterable di nomi da filtrare (sottostringhe cercate)
        Ritorna lista di tuple (call_va, resolved_label).
        """
        self.ensure_disassembled()
        self.build_full_import_maps()

        out = []
        for ins in self._last_instructions:
            # aggiorna run-time-sim (opzionale) non necessario qui
            if ins.mnemonic != 'call' or len(ins.operands) == 0:
                continue

            op = ins.operands[0]
            resolved = None

            # call immediata
            if op.type == CS_OP_IMM:
                target = op.imm
                resolved = self.resolve_direct_target(target)
            else:
                resolved = self.try_resolve_indirect_call(ins)

            # filtraggio
            if func_names is None:
                out.append((ins.address, resolved))
            else:
                # func_names può essere list/set di nomi o sottostringhe
                match = False
                for pattern in func_names:
                    if pattern is None:
                        continue
                    if isinstance(resolved, str) and pattern.lower() in resolved.lower():
                        match = True
                        break
                if match:
                    out.append((ins.address, resolved))
        return out

    def find_loadlibrary_getprocaddress_strings(self):
        """
        Cerca chiamate LoadLibrary*/GetProcAddress e tenta di risalire al parametro stringa
        Ritorna lista di tuple: (resolved_function_label, argument_string_or_<non trovata>)
        """
        # Chiamiamo find_calls_to_functions senza filtro per ottenere tutti i call risolti
        calls = self.find_calls_to_functions()
        results = []

        # per poter fare ricerca a ritroso, assicuriamoci del disassembly in cache
        self.ensure_disassembled()

        for call_va, resolved in calls:
            # interessano solo LoadLibrary* e GetProcAddress
            lowered = resolved.lower() if isinstance(resolved, str) else ''
            if 'loadlibrary' not in lowered and 'getprocaddress' not in lowered:
                continue

            idx = self._addr_to_index.get(call_va)
            arg_str = None

            # scan a ritroso alla ricerca di push immediati / push [mem] / mov in registri
            reg_state = {r: 0 for r in ['eax','ebx','ecx','edx','esi','edi','esp','ebp']}
            # ricostruiamo lo stato su finestra ridotta per avere reg_state sensato
            # (scandagliamo fino a 40 istruzioni indietro)
            start = max(0, idx - 40)
            for i in range(start, idx):
                ins = self._last_instructions[i]
                self._update_reg_state_for_instruction(ins, reg_state)

            # ora cerchiamo PUSH subito prima della call (fino a 20 istruzioni)
            for j in range(idx-1, max(idx-20, -1), -1):
                ins = self._last_instructions[j]
                # aggiornamento locale (utile se troviamo mov/pop)
                # non modifichiamo reg_state qui per non cambiare il contesto precedente
                if ins.mnemonic == 'push' and len(ins.operands) >= 1:
                    op = ins.operands[0]
                    if op.type == CS_OP_IMM:
                        imm = op.imm
                        s = self.read_best_string_at(imm)
                        if s:
                            arg_str = s
                            break
                        # fallback: se imm sembra essere una RVA senza ImageBase, prova ad aggiungere ImageBase
                        maybe_abs = imm
                        s2 = self.read_best_string_at(maybe_abs)
                        if s2:
                            arg_str = s2
                            break
                    elif op.type == CS_OP_MEM:
                        # prova a calcolare abs con reg_state
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
                # alcuni programmi passano l'argomento in registri (es. stdcall con push mancante) -> cerca mov reg, imm pattern
                if ins.mnemonic == 'mov' and len(ins.operands) >= 2:
                    dst, src = ins.operands[0], ins.operands[1]
                    # mov reg, imm e poi call reg (es. loadlibrary via register)
                    if dst.type == CS_OP_REG and src.type == CS_OP_IMM:
                        imm = src.imm
                        s = self.read_best_string_at(imm)
                        if s:
                            arg_str = s
                            break

            if not arg_str:
                arg_str = "<non trovata>"

            results.append((resolved, arg_str))

        return results
