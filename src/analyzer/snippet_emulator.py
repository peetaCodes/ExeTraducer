# improved Unicorn-based snippet emulator for PE analysis
# Dependencies: unicorn, capstone, pefile
# Provides emulate_snippet(pe, start_va, max_insns=2000, stack_size=0x20000, arch_hint=None, init_regs=None)
#
# Output includes:
#  - success, reason
#  - regs, instr_executed
#  - mem_writes: list of {address, size, data, ptr(if pointer-sized int)}
#  - strings: detected strings from mem_writes (ascii/utf16le)
#  - calls: list of intercepted calls: { call_va, import_name, dll, args, ret_ptr }
#
# Notes:
#  - this emulator *intercepts* calls to imported functions (IAT slots) and does NOT execute them.
#    Instead it records args and returns a synthetic pointer in RAX/EAX (or the appropriate register).
#  - it tries to decode string arguments and returns them in call entries.
#  - faithful full-emulation of every Windows API is out of scope, but this is very useful to
#    recover the names passed to GetProcAddress / LoadLibrary and the pointer values written into tables.
#
import struct
import math
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
from capstone.x86 import *
import pefile
try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64, UC_PROT_ALL, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    import unicorn.x86_const as ux
except Exception as e:
    raise RuntimeError("Unicorn is required. Install with `pip install unicorn`") from e

PAGE_SIZE = 0x1000

def align_down(addr, a=PAGE_SIZE):
    return addr & ~(a-1)
def align_up(addr, a=PAGE_SIZE):
    return (addr + a - 1) & ~(a-1)

def map_pe_to_uc(uc, pe):
    # Map sections (text, rdata, data, etc.) into unicorn memory and write their content.
    for sec in pe.sections:
        va = pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress
        size = max(len(sec.get_data()), getattr(sec, "Misc_VirtualSize", 0) or 0)
        if size == 0:
            continue
        mstart = align_down(va)
        mend = align_up(va + size)
        msize = mend - mstart
        try:
            uc.mem_map(mstart, msize, UC_PROT_ALL)
        except Exception:
            pass
        # write section content at section VA (not at page aligned start necessarily)
        try:
            uc.mem_write(va, sec.get_data()[:size])
        except Exception:
            pass


# helper: build imap from PE imports (VA -> (dll,name))
def build_imap_va(pe):
    imap = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for desc in pe.DIRECTORY_ENTRY_IMPORT:
            dll = (desc.dll.decode('ascii', 'ignore') if isinstance(desc.dll, bytes) else str(desc.dll) or "").lower()
            for imp in desc.imports:
                addr = getattr(imp, 'address', None)
                if addr:
                    # normalize to VA
                    ib = pe.OPTIONAL_HEADER.ImageBase
                    va = addr if addr > ib else (ib + addr if addr < ib + pe.OPTIONAL_HEADER.SizeOfImage else addr)
                    name = (imp.name.decode('ascii', 'ignore') if getattr(imp, 'name', None) else None) or (
                        f"ordinal_{getattr(imp, 'ordinal', 0)}")
                    imap[va] = (dll, name.lower())
    if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
        for desc in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            dll = (desc.dll.decode('ascii', 'ignore') if isinstance(desc.dll, bytes) else str(desc.dll) or "").lower()
            for imp in desc.imports:
                addr = getattr(imp, 'address', None)
                if addr:
                    ib = pe.OPTIONAL_HEADER.ImageBase
                    va = addr if addr > ib else (ib + addr if addr < ib + pe.OPTIONAL_HEADER.SizeOfImage else addr)
                    name = (imp.name.decode('ascii', 'ignore') if getattr(imp, 'name', None) else None) or (
                        f"ordinal_{getattr(imp, 'ordinal', 0)}")
                    imap[va] = (dll, name.lower())
    return imap


# helpers to read strings from PE mapped image or __data__
def rva_to_offset(pe, rva):
    try:
        return pe.get_offset_from_rva(rva)
    except Exception:
        return None


def va_to_rva(pe, va):
    try:
        ib = pe.OPTIONAL_HEADER.ImageBase
        return va - ib
    except Exception:
        return None


def read_cstring_at_va_from_pe(pe, va, maxlen=4096):
    try:
        rva = va_to_rva(pe, va)
        off = rva_to_offset(pe, rva)
        if off is None:
            return None
        data = pe.__data__[off: off + maxlen]
        idx = data.find(b'\x00')
        if idx == -1:
            return None
        return data[:idx].decode('ascii', errors='replace')
    except Exception:
        return None


def read_wstring_at_va_from_pe(pe, va, maxlen=4096):
    try:
        rva = va_to_rva(pe, va)
        off = rva_to_offset(pe, rva)
        if off is None:
            return None
        data = pe.__data__[off: off + maxlen]
        for i in range(0, len(data) - 1, 2):
            if data[i] == 0 and data[i + 1] == 0:
                return data[:i].decode('utf-16le', errors='replace')
        return data.decode('utf-16le', errors='replace').split('\x00', 1)[0]
    except Exception:
        return None


# decode possible string by trying ascii then utf-16le
def decode_possible_string(pe, val):
    if not isinstance(val, int):
        return None
    s = read_cstring_at_va_from_pe(pe, val)
    if s:
        return s
    s = read_wstring_at_va_from_pe(pe, val)
    return s


# Evaluate a memory operand target similar to eval_mem_target used elsewhere
def eval_mem_target_ins(ins):
    # ins is a Capstone insn with detailed operands
    for op in ins.operands:
        if op.type == X86_OP_MEM:
            m = op.value.mem
            # RIP-relative:
            if m.base == X86_REG_RIP:
                return ins.address + ins.size + m.disp
            # absolute [disp] with no base/index
            if m.base == 0 and m.index == 0:
                return m.disp
    return None


# --- helper: storiella delle istruzioni eseguite e stima arg count ---
def estimate_arg_count_from_history(executed_insns, ptr_size=4, lookback=64):
    """
    Semplice euristica:
     - conta 'push' istruzioni nell'ultimo lookback insns
     - se trovi 'sub esp, imm' e poi mov [esp+...], considera imm/ptr_size come arg_count
    Ritorna (estimated_count, evidence_dict)
    """
    pushes = 0
    sub_esp_bytes = None
    evidence = {'pushes_seen': [], 'sub_esp': None}

    # scan backwards
    for ins in reversed(executed_insns[-lookback:]):
        m = ins.mnemonic.lower()
        if m == 'push':
            pushes += 1
            evidence['pushes_seen'].append(hex(ins.address))
        elif m == 'sub' and ins.operands and ins.operands[0].type == X86_OP_REG:
            # check 'sub esp, imm'
            try:
                dst = ins.reg_name(ins.operands[0].reg).lower()
                if dst in ('esp', 'rsp') and len(ins.operands) >= 2 and ins.operands[1].type == X86_OP_IMM:
                    imm = ins.operands[1].imm
                    sub_esp_bytes = imm
                    evidence['sub_esp'] = {'addr': hex(ins.address), 'imm': imm}
                    break
            except Exception:
                pass
        # stop if we hit a boundary (call/ret/prologue)
        if m in ('call', 'ret', 'retn', 'pushf', 'popf'):
            break

    if sub_esp_bytes:
        # approx arg count = bytes / ptr_size
        est = max(0, int(sub_esp_bytes / ptr_size))
        return est, evidence
    return pushes, evidence


# The improved emulate_snippet
def emulate_snippet(pe, start_va, max_insns=2000, stack_size=0x20000, arch_hint=None, init_regs=None):
    """
    Emulate snippet starting at start_va. Returns a rich dictionary:
      {
        'success': True/False,
        'reason': str-or-None,
        'regs': {...},
        'instr_executed': N,
        'mem_writes': [ {'address':..., 'size':..., 'data': b'...', 'ptr': 0x... (if pointer-sized)} ],
        'strings': [ {'addr':..., 's':..., 'kind':'ascii'|'utf16le'} ],
        'calls': [ {'call_va': hex(addr), 'dll': dll, 'func': name, 'args': [...], 'ret_ptr': hex(...)}, ... ]
      }
    """
    # determine arch
    if arch_hint is None:
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            arch = 'x64'
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            arch = 'x86'
        else:
            return {'success': False, 'reason': 'unsupported_arch'}
    else:
        arch = arch_hint

    mode = UC_MODE_64 if arch=='x64' else UC_MODE_32
    ptr_size = 8 if arch == 'x64' else 4

    uc = Uc(UC_ARCH_X86, mode)

    # Map PE into memory
    map_pe_to_uc(uc, pe)

    # Map a writable scratch area for stubs and stack
    # stack placed at ImageBase + 0x200000 (heuristic)
    stack_top = pe.OPTIONAL_HEADER.ImageBase + 0x200000
    stack_base = stack_top - stack_size
    try:
        uc.mem_map(align_down(stack_base), align_up(stack_size), UC_PROT_ALL)
    except Exception:
        # ignore mapping errors
        pass

    # allocate small stub region for synthetic return pointers
    stub_base = stack_top + 0x1000
    try:
        uc.mem_map(align_down(stub_base), PAGE_SIZE, UC_PROT_ALL)
    except Exception:
        pass

    # write a single 'ret' byte at stub_base so a jump there returns immediately if needed
    try:
        uc.mem_write(stub_base, b'\xc3')  # ret
    except Exception:
        pass

    # set initial registers
    if arch == 'x64':
        uc.reg_write(ux.UC_X86_REG_RSP, stack_top)
        uc.reg_write(ux.UC_X86_REG_RBP, stack_top)
        uc.reg_write(ux.UC_X86_REG_RIP, start_va)
    else:
        uc.reg_write(ux.UC_X86_REG_ESP, stack_top)
        uc.reg_write(ux.UC_X86_REG_EBP, stack_top)
        uc.reg_write(ux.UC_X86_REG_EIP, start_va)

    if init_regs:
        for k,v in init_regs.items():
            try:
                reg_const = getattr(ux, 'UC_X86_REG_' + k.upper())
                uc.reg_write(reg_const, int(v))
            except Exception:
                pass

    # prepare capstone (detailed) for decoding in hooks
    MD = Cs(CS_ARCH_X86, CS_MODE_64 if arch == 'x64' else CS_MODE_32)
    MD.detail = True

    # build import map VA -> (dll,name)
    imap = build_imap_va(pe)

    # state collectors
    mem_writes = []
    calls = []
    instr_count = 0
    stopped = {'flag': False, 'reason': None}

    # synthetic pointer allocation counter
    synthetic_next = stub_base + 0x10
    synthetic_map = {}  # ptr_val -> (dll, func, info)

    # hook for memory writes: record bytes and pointer interpretation
    def hook_mem_write(uc_obj, access, address, size, value, user_data):
        nonlocal mem_writes
        try:
            data = uc_obj.mem_read(address, size)
        except Exception:
            data = b''
        entry = {'address': address, 'size': size, 'data': data}
        # if it's pointer-sized, decode as integer little-endian
        if size in (4, 8):
            try:
                if size == 8:
                    entry['ptr'] = struct.unpack_from('<Q', data)[0]
                else:
                    entry['ptr'] = struct.unpack_from('<I', data)[0]
            except Exception:
                entry['ptr'] = None
        mem_writes.append(entry)

    # --- versione modificata dell'intercettazione: estratto importante del hook_code ---
    # (inserire questo nel tuo hook_code all'interno di emulate_snippet)
    executed_insns = []  # append (capstone_insn) each executed instruction (trim to N)
    MAX_EXEC_HISTORY = 256

    def hook_code(uc_obj, address, size, user_data):
        nonlocal instr_count, stopped, synthetic_next, executed_insns
        instr_count += 1
        if instr_count > max_insns:
            stopped['flag'] = True;
            stopped['reason'] = 'max_insns';
            uc_obj.emu_stop();
            return

        # read bytes & disassemble
        try:
            code = uc_obj.mem_read(address, size)
        except Exception:
            stopped['flag'] = True;
            stopped['reason'] = 'mem_read_fail';
            uc_obj.emu_stop();
            return

        try:
            insns_here = list(MD.disasm(code, address))
        except Exception:
            stopped['flag'] = True;
            stopped['reason'] = 'decode_fail';
            uc_obj.emu_stop();
            return

        if not insns_here:
            return

        # we expect single instruction in most cases, but iterate
        for ins in insns_here:
            # record executed instruction in history
            executed_insns.append(ins)
            if len(executed_insns) > MAX_EXEC_HISTORY:
                executed_insns.pop(0)

            mnem = ins.mnemonic.lower()

            if mnem in ('ret', 'retn'):
                stopped['flag'] = True;
                stopped['reason'] = 'ret';
                uc_obj.emu_stop();
                return
            if mnem in ('int', 'syscall', 'sysenter'):
                stopped['flag'] = True;
                stopped['reason'] = 'syscall';
                uc_obj.emu_stop();
                return

            if mnem.startswith('call'):
                # compute next addr
                next_addr = ins.address + ins.size
                # compute possible target VA (imm/rip/mem/reg)
                target_va = None
                import_info = None
                op = ins.operands[0] if ins.operands else None
                if op is None:
                    continue

                # immediate direct call (relative e8) -> op.imm is often absolute target (capstone already resolves)
                if op.type == X86_OP_IMM:
                    tgt = op.imm
                    # capstone for relative call often already gives absolute; normalize small vs large
                    if tgt < pe.OPTIONAL_HEADER.ImageBase:
                        tgt_va = pe.OPTIONAL_HEADER.ImageBase + tgt
                    else:
                        tgt_va = tgt
                    target_va = tgt_va
                    import_info = imap.get(tgt_va)
                elif op.type == X86_OP_MEM:
                    # rip-relative or absolute disp
                    m = op.value.mem
                    if m.base == X86_REG_RIP:
                        tgt_va = ins.address + ins.size + m.disp
                    elif m.base == 0 and m.index == 0:
                        tgt_va = m.disp
                    else:
                        tgt_va = None
                    target_va = tgt_va
                    import_info = imap.get(tgt_va) if tgt_va else None
                elif op.type == X86_OP_REG:
                    # try read register value
                    try:
                        regname = ins.reg_name(op.reg).lower()
                        reg_const = getattr(ux, 'UC_X86_REG_' + regname.upper())
                        val = uc_obj.reg_read(reg_const)
                        if val in imap:
                            import_info = imap[val]
                            target_va = val
                        else:
                            # attempt deref of pointer stored at val
                            try:
                                ptr_bytes = uc_obj.mem_read(val, ptr_size)
                                if ptr_size == 8:
                                    p2 = struct.unpack_from('<Q', ptr_bytes)[0]
                                else:
                                    p2 = struct.unpack_from('<I', ptr_bytes)[0]
                                if p2 in imap:
                                    import_info = imap[p2]
                                    target_va = p2
                            except Exception:
                                pass
                    except Exception:
                        pass

                # If this is an imported function call -> intercept and emulate callee effects
                if import_info:
                    dll, name = import_info
                    # estimate arg count (only for x86 we need to clean stack)
                    est_args, evidence = estimate_arg_count_from_history(executed_insns, ptr_size=ptr_size)
                    # gather args for reporting (try to decode strings)
                    args = []
                    if arch == 'x64':
                        # RCX, RDX, R8, R9 then stack...
                        try:
                            regs_values = [uc_obj.reg_read(ux.UC_X86_REG_RCX),
                                           uc_obj.reg_read(ux.UC_X86_REG_RDX),
                                           uc_obj.reg_read(ux.UC_X86_REG_R8),
                                           uc_obj.reg_read(ux.UC_X86_REG_R9)]
                            for rv in regs_values:
                                s = decode_possible_string(pe, rv)
                                args.append(s if s else rv)
                            # read some stack slots too
                            try:
                                rsp = uc_obj.reg_read(ux.UC_X86_REG_RSP)
                                stk = uc_obj.mem_read(rsp, ptr_size * 4)
                                for i in range(0, ptr_size * 3, ptr_size):
                                    if ptr_size == 8:
                                        v = struct.unpack_from('<Q', stk, i)[0]
                                    else:
                                        v = struct.unpack_from('<I', stk, i)[0]
                                    s = decode_possible_string(pe, v)
                                    args.append(s if s else v)
                            except Exception:
                                pass
                        except Exception:
                            pass
                    else:
                        # x86: read top-of-stack args (caller pushed right-to-left, before call)
                        try:
                            esp = uc_obj.reg_read(ux.UC_X86_REG_ESP)
                            stack_bytes = uc_obj.mem_read(esp, ptr_size * 8)
                            for i in range(0, ptr_size * 6, ptr_size):
                                if ptr_size == 8:
                                    v = struct.unpack_from('<Q', stack_bytes, i)[0]
                                else:
                                    v = struct.unpack_from('<I', stack_bytes, i)[0]
                                s = decode_possible_string(pe, v)
                                args.append(s if s else v)
                        except Exception:
                            pass

                    # allocate synthetic return pointer far away (avoid PE area)
                    ib = pe.OPTIONAL_HEADER.ImageBase
                    peb_end = ib + getattr(pe.OPTIONAL_HEADER, 'SizeOfImage', 0)
                    high_stub_base = max(peb_end + 0x100000, 0x100000000)
                    # align
                    if synthetic_next < high_stub_base:
                        synthetic_next = high_stub_base + 0x10
                    ret_ptr = synthetic_next
                    synthetic_next += max(0x10, ptr_size)

                    # ensure page present
                    try:
                        uc_obj.mem_map(align_down(ret_ptr), PAGE_SIZE, UC_PROT_ALL)
                        uc_obj.mem_write(ret_ptr, b'\xc3')  # ret stub
                    except Exception:
                        pass

                    # Write return value into RAX/EAX
                    try:
                        if arch == 'x64':
                            uc_obj.reg_write(ux.UC_X86_REG_RAX, ret_ptr)
                        else:
                            uc_obj.reg_write(ux.UC_X86_REG_EAX, ret_ptr & 0xffffffff)
                    except Exception:
                        pass

                    # *** CRUCIAL: emulate post-call stack state for x86 stdcall functions ***
                    if arch == 'x86':
                        # assume __stdcall (callee cleaned). Increase ESP by estimated args
                        if est_args is None:
                            est_args = 0
                        try:
                            esp_val = uc_obj.reg_read(ux.UC_X86_REG_ESP)
                            new_esp = esp_val + (est_args * ptr_size)
                            uc_obj.reg_write(ux.UC_X86_REG_ESP, new_esp)
                        except Exception:
                            pass
                    # for x64 nothing to do (caller cleans, args were in registers)

                    # record call entry
                    calls.append({
                        'call_va': hex(ins.address),
                        'dll': dll,
                        'func': name,
                        'args': args,
                        'ret_ptr': hex(ret_ptr),
                        'estimated_args': est_args,
                        'evidence': evidence,
                        'target_iat_slot': hex(target_va) if target_va else None
                    })

                    # resume execution at next instruction (we do not push return addr)
                    try:
                        if arch == 'x64':
                            uc_obj.reg_write(ux.UC_X86_REG_RIP, next_addr)
                        else:
                            uc_obj.reg_write(ux.UC_X86_REG_EIP, next_addr)
                    except Exception:
                        stopped['flag'] = True;
                        stopped['reason'] = 'cannot_skip_call';
                        uc_obj.emu_stop();
                        return

                    return  # we intercepted call and already updated RIP/EIP

    # register hooks
    uc.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
    uc.hook_add(UC_HOOK_CODE, hook_code)

    # start emulation
    try:
        uc.emu_start(start_va, 0)
    except Exception as e:
        # unicorn errors or intentional stops may raise exceptions; capture reason
        stopped['flag'] = True
        stopped['reason'] = f'unicorn_error:{e}'

    # read registers at end
    regs = {}
    try:
        if arch == 'x64':
            for r in ('RAX','RBX','RCX','RDX','RSI','RDI','RSP','RBP','RIP'):
                try:
                    regs[r.lower()] = uc.reg_read(getattr(ux, 'UC_X86_REG_' + r))
                except Exception:
                    regs[r.lower()] = None
        else:
            for r in ('EAX','EBX','ECX','EDX','ESI','EDI','ESP','EBP','EIP'):
                try:
                    regs[r.lower()] = uc.reg_read(getattr(ux, 'UC_X86_REG_' + r))
                except Exception:
                    regs[r.lower()] = None
    except Exception:
        pass

    # collect strings from mem_writes (ascii/utf16le)
    strings = []
    for w in mem_writes:
        data = w.get('data') or b''
        try:
            s = data.split(b'\x00', 1)[0].decode('ascii', errors='ignore')
            if len(s) >= 3:
                strings.append({'addr': w['address'], 's': s, 'kind': 'ascii'})
        except Exception:
            pass
        try:
            if len(data) >= 4:
                ws = data.decode('utf-16le', errors='ignore').split('\x00', 1)[0]
                if len(ws) >= 2:
                    strings.append({'addr': w['address'], 's': ws, 'kind': 'utf16le'})
        except Exception:
            pass

    return {
        'success': True,
        'reason': stopped.get('reason'),
        'regs': regs,
        'instr_executed': instr_count,
        'mem_writes': mem_writes,
        'strings': strings,
        'calls': calls
    }
