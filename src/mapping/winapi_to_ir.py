# winapi_to_ir.py
"""
Algorithmic WinAPI -> IR mapper.
Given a WinAPI function name (optionally prefixed "dll!"), this module
tries to produce a canonical IR string algorithmically using tokenization,
domain heuristics and a small set of special-case overrides.

Output format: a dict with keys:
  - ir: the generated IR (string)
  - confidence: "high"|"medium"|"low"
  - reason: short explanation of how it was derived

Example:
  map_winapi_to_ir("kernel32.dll!CreateFileW") -> {"ir":"sys.file.create", ...}
"""

import re
from typing import List, Tuple, Dict, Optional

# aggiungi al top del file (GLOBAL)
DLL_DOMAIN = {
    "kernel32.dll": "sys",
    "advapi32.dll": "security",
    "user32.dll": "ui",
    "gdi32.dll": "gdi",
    "comctl32.dll": "ui",
    "comdlg32.dll": "dialog",
    "shell32.dll": "shell",
    "winmm.dll": "multimedia",
    "ws2_32.dll": "net",
    "iphlpapi.dll": "net",
    "ole32.dll": "com",
    "oleaut32.dll": "com",
    "ntdll.dll": "nt",
    "dbghelp.dll": "debug",
    "d3d11.dll": "graphics",
    "d3d9.dll": "graphics",
    "dxgi.dll": "graphics",
    "secur32.dll": "security",
    "bcrypt.dll": "crypto",
    "advapi32": "security"
    # TODO: do I need to extend this?
}

DOMAIN_MAP = {
    "file": "file", "filename": "file", "directory": "file", "path": "file",
    "volume": "storage", "disk": "storage",
    "process": "process", "thread": "thread", "handle": "handle", "token": "security",
    "module": "module", "library": "module", "dll": "module", "proc": "module",
    "reg": "registry", "registry": "registry", "key": "registry", "value": "registry",
    "socket": "net", "connect": "net", "send": "net", "recv": "net", "wsastartup": "net",
    "bind": "net", "listen": "net", "accept": "net", "http": "net", "dns": "net",
    "message": "ui", "messagebox": "ui", "window": "ui", "dialog": "ui", "menu": "ui",
    "cursor": "ui", "virtual": "memory", "virtualalloc": "memory", "map": "memory",
    "allocation": "memory", "alloc": "memory", "heap": "memory",
    "mutex": "sync", "semaphore": "sync", "event": "sync", "wait": "sync", "critical": "sync",
    "access": "security", "security": "security", "acl": "security",
    "shell": "shell", "clipboard": "ipc", "pipe": "ipc", "namedpipe": "ipc",
    "print": "printer", "printer": "printer", "audio": "audio", "device": "device",
    "service": "service", "time": "time", "sleep": "time", "console": "console",
    "crypt": "crypto", "crypto": "crypto", "compress": "compression",
}

VERB_MAP = {
    "create": "create", "open": "open", "close": "close", "read": "read", "write": "write",
    "get": "get", "set": "set", "start": "start", "stop": "stop", "delete": "delete",
    "remove": "delete", "load": "load", "unload": "unload", "connect": "connect",
    "send": "send", "recv": "recv", "receive": "recv", "listen": "listen", "accept": "accept",
    "map": "map", "alloc": "allocate", "virtualalloc": "allocate", "query": "query",
    "enum": "enumerate", "register": "register", "unregister": "unregister", "wait": "wait",
    "is": "query", "has": "query", "lookup": "get", "createfile": "create", "messagebox": "message"
}

SPECIAL_OVERRIDES = {
    "messagebox": ("ui.dialog.message", "special-case"),
    "messageboxa": ("ui.dialog.message", "special-case"),
    "messageboxw": ("ui.dialog.message", "special-case"),
    "getprocaddress": ("sys.module.get_symbol", "special-case"),
    "loadlibrary": ("sys.module.load", "special-case"),
    "loadlibrarya": ("sys.module.load", "special-case"),
    "loadlibraryw": ("sys.module.load", "special-case"),
    "createfile": ("sys.file.create", "special-case"),
    "createfilea": ("sys.file.create", "special-case"),
    "createfilew": ("sys.file.create", "special-case"),
    "readfile": ("sys.file.read", "special-case"),
    "writefile": ("sys.file.write", "special-case"),
    "closehandle": ("sys.handle.close", "special-case"),
    "createprocess": ("sys.process.create", "special-case"),
    "createthread": ("sys.thread.create", "special-case"),
    "wsastartup": ("net.init", "special-case"),
    "wsasocket": ("net.socket.create", "special-case"),
    "socket": ("net.socket.create", "special-case"),
    "connect": ("net.socket.connect", "special-case"),
    "send": ("net.socket.send", "special-case"),
    "recv": ("net.socket.recv", "special-case"),
    "virtualalloc": ("sys.memory.allocate", "special-case"),
    "virtualfree": ("sys.memory.free", "special-case"),
    "openfile": ("sys.file.open", "special-case"),
    "createfilemapping": ("sys.memory.file_mapping.create", "special-case"),
    "mapviewoffile": ("sys.memory.map_view", "special-case"),
    "regopenkeyex": ("sys.registry.open_key", "special-case"),
    "regsetvalueex": ("sys.registry.set_value", "special-case"),
    "regqueryvalueex": ("sys.registry.query_value", "special-case"),
    "regdeletekey": ("sys.registry.delete_key", "special-case"),
    "regclosekey": ("sys.registry.close_key", "special-case"),
    "getcurrentprocessid": ("sys.process.get_pid", "special-case"),
    "getcurrentthreadid": ("sys.thread.get_tid", "special-case"),
    "createmutex": ("sys.sync.mutex.create", "special-case"),
    "waitforsingleobject": ("sys.sync.wait", "special-case")
}

_SPLIT_RE = re.compile(r'[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+', re.UNICODE)


def normalize_name_tokens(s: str):
    # remove Ex suffix but keep marker
    if s.lower().endswith("ex"):
        s_core = s[:-2]
        variant = "ex"
    else:
        s_core = s
        variant = None
    # remove trailing A/W if >2 len
    if s_core.endswith('A') or s_core.endswith('W'):
        if len(s_core) > 2:
            s_core = s_core[:-1]
    # strip digits like 64,32 if trailing, keep as token
    s_core = re.sub(r'64$|32$', ' ', s_core)
    # then split with your regex
    tokens = _SPLIT_RE.findall(s_core)
    return [t.lower() for t in tokens if t], variant


def split_tokens(name: str):
    """
    Divides an API name in normalized tokens.
    - Handles suffixes Ex / A / W / 32 / 64 / Ptr
    - Returns: (tokens, variant), where variant can be either 'ex', 'a', 'w', ecc.
    """
    # Usa la tua funzione per rimuovere suffissi principali
    tokens, variant = normalize_name_tokens(name)

    # Gestione di Ptr come token separato
    final_tokens = []
    for t in tokens:
        if t.endswith("ptr") and t != "ptr":
            final_tokens.append(t[:-3])
            final_tokens.append("ptr")
        else:
            final_tokens.append(t)

    # Se è rimasto un suffisso particolare come variante, aggiungilo come metadato
    return final_tokens, variant


def infer_domain_from_tokens(tokens: list[str]):
    for t in tokens:
        if t in DOMAIN_MAP:
            return DOMAIN_MAP[t]
    for t in reversed(tokens):
        if t in DOMAIN_MAP:
            return DOMAIN_MAP[t]
    for t in tokens:
        for k in DOMAIN_MAP:
            if k in t:
                return DOMAIN_MAP[k]
    return None


def infer_verb_from_tokens(tokens):
    for t in tokens:
        if t in VERB_MAP:
            return VERB_MAP[t]
    if tokens:
        t0 = tokens[0]
        common_verbs = ['create', 'open', 'close', 'read', 'write', 'get', 'set', 'load', 'free', 'map', 'alloc',
                        'register', 'enum', 'query', 'start', 'stop', 'delete', 'remove', 'wait', 'is', 'has', 'lookup']
        for cv in common_verbs:
            if t0.startswith(cv) or t0 == cv:
                return cv
    return None


def build_ir(domain, verb, tokens, fullname):
    key = fullname.lower()
    key = re.sub(r'[\(\)]', '', key)
    if key in SPECIAL_OVERRIDES:
        return SPECIAL_OVERRIDES[key][0], f"override:{SPECIAL_OVERRIDES[key][1]}"
    if domain and verb:
        if domain == 'ui':
            if verb in ('message', 'messagebox', 'show', 'display'):
                return f"ui.dialog.{verb}", "ui-mapping"
            if any(tok in ('window', 'createwindow', 'showwindow') for tok in tokens):
                return f"ui.window.{verb}", "ui-window-mapping"
            return f"ui.{verb}", "ui-generic"
        if domain == 'memory':
            return f"sys.memory.{verb}", "memory-mapping"
        if domain == 'net':
            if verb in ('connect', 'send', 'recv', 'listen', 'accept'):
                return f"net.socket.{verb}", "net-socket"
            return f"net.{verb}", "net-generic"
        if domain == 'registry':
            if verb in ('open', 'query', 'set', 'delete', 'close'):
                return f"sys.registry.{verb}_key" if verb in (
                'open', 'close') else f"sys.registry.{verb}_value", "registry-specific"
            return f"sys.registry.{verb}", "registry-generic"
        if domain == 'sync':
            return f"sys.sync.{verb}", "sync-mapping"
        return f"sys.{domain}.{verb}", "default-mapping"
    if domain and not verb:
        if domain == 'net':
            return "net.socket.create", "domain-only-default"
        if domain == 'file':
            return "sys.file.operate", "domain-only-default"
        return f"sys.{domain}.call", "domain-only"
    if verb and not domain:
        if verb in ('get', 'get_symbol') and any('proc' in t or 'procaddress' in t or 'addr' in t for t in tokens):
            return "sys.module.get_symbol", "verb-only-getproc-heuristic"
        return f"sys.object.{verb}", "verb-only"
    return "foreign.call", "fallback"


def map_winapi_to_ir_with_dll(fullname: str, dll_hint: str = None):
    # fullname può essere "dll!func" oppure "func"
    base = fullname.split("!")[-1]
    result = map_winapi_to_ir(base)  # tua funzione esistente
    # if dll hint provided, try to use it
    if dll_hint:
        dkey = dll_hint.lower()
        if not dkey.endswith('.dll'):
            dkey += '.dll'
        ddomain = DLL_DOMAIN.get(dkey)
        if ddomain:
            # se risultato domain mismatch, prefer dll domain as override when confidence low
            cur_domain = None
            if result.get('reason') and result['reason'].startswith('default-mapping'):
                # default-mapping likely ok; otherwise set domain from dll
                pass
            # Boost confidence when dll domain matches token-inferred domain
            tokens = result.get('tokens', [])
            inferred_dom = infer_domain_from_tokens(tokens)
            if inferred_dom == ddomain:
                # increase confidence
                if result['confidence'] == 'low':
                    result['confidence'] = 'medium'
                elif result['confidence'] == 'medium':
                    result['confidence'] = 'high'
                result['reason'] += f";boosted-by-dll({dll_hint})"
            else:
                # If result is low and dll_domain exists, prefer sys.<dll_domain>.<verb>
                verb = infer_verb_from_tokens(tokens)
                if verb:
                    result['ir'] = f"sys.{ddomain}.{verb}"
                    result['reason'] = f"overridden-by-dll({dll_hint})"
                    result['confidence'] = 'medium'
                else:
                    # domain-only fallback
                    if result['confidence'] == 'low':
                        result['ir'] = f"sys.{ddomain}.call"
                        result['reason'] = f"domain-assigned-by-dll({dll_hint})"
                        result['confidence'] = 'low'
    return result


def map_winapi_to_ir(fullname: str) -> Dict[str, str]:
    name = fullname.split("!")[-1] if "!" in fullname else fullname
    name_clean = re.sub(r'[^A-Za-z0-9_]', '', name)
    toks, _ = split_tokens(name_clean)
    if not toks:
        return {"ir": "foreign.call", "confidence": "low", "reason": "no_tokens"}
    lname = name_clean.lower()
    if lname in SPECIAL_OVERRIDES:
        ir, r = SPECIAL_OVERRIDES[lname]
        return {"ir": ir, "confidence": "high", "reason": r, "tokens": toks}
    domain = infer_domain_from_tokens(toks)
    verb = infer_verb_from_tokens(toks)
    ir, reason = build_ir(domain, verb, toks, name_clean)
    if reason.startswith("override") or reason in (
    "special-case", "ui-mapping", "registry-specific", "memory-mapping", "net-socket", "default-mapping"):
        confidence = "high"
    elif domain and verb:
        confidence = "medium"
    elif domain or verb:
        confidence = "low"
    else:
        confidence = "low"
    return {"ir": ir, "confidence": confidence, "reason": reason, "tokens": toks}


# Demo
if __name__ == '__main__':
    examples = [
        "kernel32.dll!CreateFileW",
        "CreateProcessA",
        "ReadFile",
        "WriteFile",
        "MessageBoxW",
        "LoadLibraryA",
        "GetProcAddress",
        "RegOpenKeyExW",
        "RegSetValueExA",
        "WSASocketA",
        "connect",
        "VirtualAlloc",
        "CreateMutexA",
        "WaitForSingleObject",
        "MapViewOfFile",
        "CreateFileMappingA"
    ]
    for ex in examples:
        print(ex, "->", map_winapi_to_ir(ex))
