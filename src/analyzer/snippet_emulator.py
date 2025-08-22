# snippet_emulator.py - lightweight Unicorn-based snippet emulator for PE analysis
# Dependencies: unicorn, capstone, pefile
# Provides emulate_snippet(pe, start_va, max_insns=2000, stack_size=0x20000, arch_hint=None, init_regs=None)

import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
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
    for sec in pe.sections:
        va = pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress
        size = max(len(sec.get_data()), sec.Misc_VirtualSize)
        if size == 0:
            continue
        mstart = align_down(va)
        mend = align_up(va + size)
        msize = mend - mstart
        try:
            uc.mem_map(mstart, msize, UC_PROT_ALL)
        except Exception:
            pass
        try:
            uc.mem_write(va, sec.get_data()[:size])
        except Exception:
            pass

def emulate_snippet(pe, start_va, max_insns=2000, stack_size=0x20000, arch_hint=None, init_regs=None):
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

    uc = Uc(UC_ARCH_X86, mode)

    # map PE and stack
    map_pe_to_uc(uc, pe)
    stack_top = pe.OPTIONAL_HEADER.ImageBase + 0x200000
    stack_base = stack_top - stack_size
    uc.mem_map(align_down(stack_base), align_up(stack_size), UC_PROT_ALL)
    if arch=='x64':
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

    mem_writes = []
    instr_count = 0
    stopped = {'flag': False, 'reason': None}

    MD = Cs(CS_ARCH_X86, CS_MODE_64 if arch=='x64' else CS_MODE_32)
    MD.detail = False

    def hook_mem_write(uc_obj, access, address, size, value, user_data):
        try:
            data = uc_obj.mem_read(address, size)
        except Exception:
            data = b''
        mem_writes.append({'address': address, 'size': size, 'data': data})

    def hook_code(uc_obj, address, size, user_data):
        nonlocal instr_count, stopped
        instr_count += 1
        if instr_count > max_insns:
            stopped['flag'] = True; stopped['reason'] = 'max_insns'; uc_obj.emu_stop(); return
        try:
            code = uc_obj.mem_read(address, size)
            for ins in MD.disasm(code, address):
                if ins.mnemonic.lower() in ('ret','retn'):
                    stopped['flag'] = True; stopped['reason'] = 'ret'; uc_obj.emu_stop(); return
                if ins.mnemonic.lower() in ('int','syscall','sysenter'):
                    stopped['flag'] = True; stopped['reason'] = 'syscall'; uc_obj.emu_stop(); return
        except Exception:
            stopped['flag'] = True; stopped['reason'] = 'disasm_fail'; uc_obj.emu_stop(); return

    uc.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
    uc.hook_add(UC_HOOK_CODE, hook_code)

    try:
        uc.emu_start(start_va, 0)
    except Exception as e:
        stopped['flag'] = True; stopped['reason'] = f'unicorn_error:{e}'

    regs = {}
    try:
        if arch=='x64':
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

    strings = []
    for w in mem_writes:
        data = w.get('data') or b''
        try:
            s = data.split(b'\\x00',1)[0].decode('ascii',errors='ignore')
            if len(s)>=3:
                strings.append({'addr': w['address'], 's': s, 'kind': 'ascii'})
        except Exception:
            pass
        try:
            if len(data)>=4:
                ws = data.decode('utf-16le', errors='ignore').split('\\x00',1)[0]
                if len(ws)>=2:
                    strings.append({'addr': w['address'], 's': ws, 'kind': 'utf16le'})
        except Exception:
            pass

    return {
        'success': True,
        'reason': stopped.get('reason'),
        'regs': regs,
        'instr_executed': instr_count,
        'mem_writes': mem_writes,
        'strings': strings
    }