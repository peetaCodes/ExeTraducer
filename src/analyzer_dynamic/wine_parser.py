# analyzer_dynamic/wine_parser.py
from __future__ import annotations
import re
import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any, Iterable
from datetime import datetime

# ---------- AST dataclasses ----------

@dataclass
class ValueNode:
    kind: str            # "string", "wstring", "hex", "int", "pointer", "raw"
    raw: str
    value: Any = None

@dataclass
class ArgNode:
    name: Optional[str]  # se noto da plugin, altrimenti None
    value: ValueNode

@dataclass
class CallNode:
    id: str
    module: str
    function: str
    ordinal: Optional[int] = None
    callsite_retaddr: Optional[str] = None
    ts_start: Optional[str] = None
    ts_end: Optional[str] = None
    args: List[ArgNode] = field(default_factory=list)
    retval: Optional[ValueNode] = None
    last_error: Optional[int] = None
    children: List['CallNode'] = field(default_factory=list)

@dataclass
class ThreadTrace:
    tid_hex: str
    root_calls: List[CallNode] = field(default_factory=list)

@dataclass
class ExecutionTrace:
    metadata: Dict[str, Any]
    threads: List[ThreadTrace]
    indices: Dict[str, Dict[str, Any]] = field(default_factory=lambda: {"by_callsite": {}, "by_function": {}})
    dynamic_symbols: Dict[str, str] = field(default_factory=dict)
    dynamic_modules: Dict[str, str] = field(default_factory=dict)  # HMODULE ptr -> path

# ---------- Parser core ----------

class WineParser:
    CALL_RE = re.compile(r'^(?P<tid>[0-9A-Fa-f]{4}):\s*Call\s+(?P<mod>[A-Za-z0-9_.-]+)\.(?P<fn>[A-Za-z0-9_@?$]+)\((?P<args>.*)\)\s*(?P<trailer>.*)$')
    RET_RE  = re.compile(r'^(?P<tid>[0-9A-Fa-f]{4}):\s*Ret\s+(?P<mod>[A-Za-z0-9_.-]+)\.(?P<fn>[A-Za-z0-9_@?$]+)\((?P<retargs>.*)\)\s*(?P<trailer>.*)$')
    TS_RE   = re.compile(r'^\d{4}-\d{2}-\d{2}T')  # se abiliti WINEDEBUG_TIMESTAMP=1 (ISO-like)

    TRAIL_RETADDR = re.compile(r'\bret=([0-9A-Fa-fx]+)')
    TRAIL_RETVAL  = re.compile(r'\bretval=([0-9A-Fa-fx]+)')
    TRAIL_LASTERR = re.compile(r'\berr(?:or)?=([0-9A-Fa-fx]+)')

    def __init__(self, log_file: str, has_timestamps: bool = False):
        self.log_file = log_file
        self.has_timestamps = has_timestamps

        self.threads: Dict[str, ThreadTrace] = {}
        self.stacks: Dict[str, List[CallNode]] = {}
        self.call_seq: int = 0

        # per plugin
        self.dynamic_symbols: Dict[str, str] = {}
        self.dynamic_modules: Dict[str, str] = {}

        # indice veloce per funzione
        self.index_by_function: Dict[str, List[str]] = {}
        self.index_by_callsite: Dict[str, str] = {}

    # -------------- public API --------------

    def parse(self) -> ExecutionTrace:
        meta = {
            "log_file": self.log_file,
            "wine_debug": "+relay",
            "timestamp_start": None,
            "timestamp_end": None,
            "has_timestamps": self.has_timestamps
        }

        with open(self.log_file, "r", errors="ignore") as f:
            for raw_line in f:
                line = raw_line.rstrip("\n")
                ts = None
                # Se abbiamo timestamp all'inizio riga, estrailo per ts_start/ts_end
                if self.has_timestamps and self.TS_RE.match(line):
                    # formato tipico ISO-like → prendi token iniziale
                    first_sp = line.find(' ')
                    ts = line[:first_sp] if first_sp > 0 else None
                    # rimuovi timestamp per far combaciare le regex Call/Ret
                    line = line[first_sp+1:] if first_sp > 0 else line

                    if meta["timestamp_start"] is None:
                        meta["timestamp_start"] = ts
                    meta["timestamp_end"] = ts

                if not line:
                    continue

                m_call = self.CALL_RE.match(line)
                if m_call:
                    self._handle_call(m_call, ts)
                    continue

                m_ret = self.RET_RE.match(line)
                if m_ret:
                    self._handle_ret(m_ret, ts)
                    continue

                # ignora altri canali (trace: fix_me, warn, ecc.)
                continue

        exec_trace = ExecutionTrace(
            metadata=meta,
            threads=list(self.threads.values()),
            dynamic_symbols=self.dynamic_symbols,
            dynamic_modules=self.dynamic_modules,
            indices={
                "by_callsite": self.index_by_callsite,
                "by_function": self.index_by_function
            }
        )
        return exec_trace

    def save_as_json(self, out_file: str, exec_trace: ExecutionTrace):
        with open(out_file, "w") as f:
            json.dump(asdict(exec_trace), f, indent=2)

    # -------------- internals --------------

    def _new_call_id(self, tid: str) -> str:
        self.call_seq += 1
        return f"call-{tid}-{self.call_seq:06d}"

    def _get_thread(self, tid: str) -> ThreadTrace:
        if tid not in self.threads:
            self.threads[tid] = ThreadTrace(tid_hex=tid)
            self.stacks[tid] = []
        return self.threads[tid]

    def _handle_call(self, m: re.Match, ts: Optional[str]):
        tid = m.group("tid")
        module = m.group("mod")
        function = m.group("fn")
        args_raw = m.group("args")
        trailer = m.group("trailer") or ""

        retaddr = self._extract_retaddr(trailer)
        arg_tokens = self._split_args(args_raw)
        args_nodes = self._tokens_to_args(module, function, arg_tokens)

        call = CallNode(
            id=self._new_call_id(tid),
            module=module,
            function=function,
            callsite_retaddr=retaddr,
            ts_start=ts,
            args=args_nodes
        )

        # plugin pre-return (p.es. niente da fare qui in genere)
        self._plugin_on_call_enter(call)

        thr = self._get_thread(tid)
        stack = self.stacks[tid]
        if stack:
            stack[-1].children.append(call)
        else:
            thr.root_calls.append(call)
        stack.append(call)

        # indicizzazione
        fn_key = f"{module}!{function}"
        self.index_by_function.setdefault(fn_key, []).append(call.id)
        if retaddr:
            self.index_by_callsite[retaddr] = call.id

    def _handle_ret(self, m: re.Match, ts: Optional[str]):
        tid = m.group("tid")
        module = m.group("mod")
        function = m.group("fn")
        retargs = m.group("retargs") or ""
        trailer = m.group("trailer") or ""

        stack = self.stacks.get(tid, [])
        if not stack:
            return  # linea “Ret” orfana: ignora o logga warning

        # chiudi il frame più vicino che combacia
        idx = len(stack) - 1
        while idx >= 0 and not (stack[idx].module == module and stack[idx].function == function):
            idx -= 1
        if idx < 0:
            # mismatch estremo → chiudi l’ultimo comunque
            node = stack.pop()
        else:
            node = stack.pop(idx)
            # se abbiamo “saltato” frame, chiudili forzatamente
            while len(stack) > idx:
                stack.pop()

        node.ts_end = ts

        # retval + last_error dalla trailer/retargs
        retval = self._extract_retval(trailer) or self._extract_retval(retargs)
        lasterr = self._extract_lasterr(trailer) or self._extract_lasterr(retargs)
        if retval is not None:
            node.retval = self._infer_value_kind(retval)
        if lasterr is not None:
            try:
                node.last_error = int(lasterr, 16 if lasterr.startswith(("0x","0X")) else 10)
            except ValueError:
                node.last_error = None

        # plugin post-return (qui spesso c’è il succo: mapping HMODULE/fptr → nomi)
        self._plugin_on_call_exit(node)

    # ---------- helpers: trailer fields ----------

    def _extract_retaddr(self, trailer: str) -> Optional[str]:
        m = self.TRAIL_RETADDR.search(trailer)
        return self._norm_hex(m.group(1)) if m else None

    def _extract_retval(self, s: str) -> Optional[str]:
        m = self.TRAIL_RETVAL.search(s)
        return self._norm_hex(m.group(1)) if m else None

    def _extract_lasterr(self, s: str) -> Optional[str]:
        m = self.TRAIL_LASTERR.search(s)
        return self._norm_hex(m.group(1)) if m else None

    def _norm_hex(self, token: str) -> str:
        t = token.strip()
        if t.startswith(("0x","0X")):
            return f"0x{t[2:].upper()}"
        # es. "00401073" → normalizza a 0x401073
        try:
            val = int(t, 16)
            return f"0x{val:X}"
        except ValueError:
            return t

    # ---------- argument splitting & inference ----------

    def _split_args(self, args_raw: str) -> List[str]:
        out, cur = [], []
        in_q = False
        in_wq = False
        brace = 0
        i = 0
        while i < len(args_raw):
            ch = args_raw[i]
            if ch == '"' and not in_wq:
                # toggle quote (attento a \" escaped)
                bs = (i > 0 and args_raw[i-1] == '\\')
                if not bs:
                    in_q = not in_q
                cur.append(ch)
            elif ch == 'L' and (i+1) < len(args_raw) and args_raw[i+1] == '"' and not in_q:
                in_wq = not in_wq
                cur.append('L')
                cur.append('"')
                i += 1
            elif ch == '{' and not (in_q or in_wq):
                brace += 1
                cur.append(ch)
            elif ch == '}' and not (in_q or in_wq):
                brace = max(0, brace-1)
                cur.append(ch)
            elif ch == ',' and not (in_q or in_wq) and brace == 0:
                token = ''.join(cur).strip()
                if token:
                    out.append(token)
                cur = []
            else:
                cur.append(ch)
            i += 1
        token = ''.join(cur).strip()
        if token:
            out.append(token)
        return out

    def _tokens_to_args(self, module: str, function: str, tokens: List[str]) -> List[ArgNode]:
        # Descrittori noti per funzioni (plugin semplice)
        arg_names = self._api_arg_names(module, function)
        args: List[ArgNode] = []
        for idx, tok in enumerate(tokens):
            val = self._infer_value_kind(tok)
            name = arg_names[idx] if idx < len(arg_names) else None
            args.append(ArgNode(name=name, value=val))
        return args

    def _infer_value_kind(self, token: str) -> ValueNode:
        t = token.strip()
        # wide string L"..."
        if t.startswith('L"') and t.endswith('"'):
            content = self._unescape_cstring(t[2:-1])
            return ValueNode(kind="wstring", raw=token, value=content)
        # ascii string "..."
        if t.startswith('"') and t.endswith('"'):
            content = self._unescape_cstring(t[1:-1])
            return ValueNode(kind="string", raw=token, value=content)
        # hex (0x..) or pure-hex width
        if t.startswith(("0x","0X")):
            try: return ValueNode(kind="hex", raw=token, value=int(t, 16))
            except: return ValueNode(kind="hex", raw=token, value=None)
        if re.fullmatch(r'[0-9A-Fa-f]{8}', t):
            # spesso è un puntatore/indirizzo stampato in 8 hex
            try: return ValueNode(kind="pointer", raw=token, value=int(t, 16))
            except: return ValueNode(kind="pointer", raw=token, value=None)
        # integer decimal
        if re.fullmatch(r'[0-9]+', t):
            try: return ValueNode(kind="int", raw=token, value=int(t, 10))
            except: return ValueNode(kind="int", raw=token, value=None)
        # fallback
        return ValueNode(kind="raw", raw=token, value=None)

    def _unescape_cstring(self, s: str) -> str:
        # decodifica molto basilare di \n, \r, \t, \", \\  (sufficiente per i log)
        return (s
                .replace(r'\"','"')
                .replace(r'\\','\\')
                .replace(r'\n','\n')
                .replace(r'\r','\r')
                .replace(r'\t','\t'))

    # ---------- plugins ----------

    def _api_arg_names(self, module: str, function: str) -> List[str]:
        mod = module.upper()
        fn  = function
        # mapping minimo utile (estendibile)
        if mod == "KERNEL32" and fn in ("LoadLibraryW","LoadLibraryA"):
            return ["lpLibFileName"]
        if mod == "KERNEL32" and fn in ("LoadLibraryExW","LoadLibraryExA"):
            return ["lpLibFileName","hFile","dwFlags"]
        if mod == "KERNEL32" and fn == "GetProcAddress":
            return ["hModule","lpProcName"]
        return []

    def _plugin_on_call_enter(self, node: CallNode):
        # Hook chiamato all’ingresso: in genere non serve molto qui.
        pass

    def _plugin_on_call_exit(self, node: CallNode):
        # LoadLibrary* → mappa HMODULE → path dll (se noto)
        if node.module.upper() == "KERNEL32" and node.function.startswith("LoadLibrary"):
            # arg0 deve essere libreria
            if node.args and node.args[0].value.kind in ("string","wstring"):
                path = node.args[0].value.value
                if node.retval and node.retval.kind in ("hex","pointer"):
                    self.dynamic_modules[self._hexstr(node.retval)] = path

        # GetProcAddress → mappa fptr → "MODULE!Name/ordinal"
        if node.module.upper() == "KERNEL32" and node.function == "GetProcAddress":
            if len(node.args) >= 2 and node.retval:
                hmod = node.args[0].value
                proc = node.args[1].value
                fptr = self._hexstr(node.retval)
                mod_name = None
                if hmod.kind in ("hex","pointer"):
                    mod_name = self.dynamic_modules.get(self._hexstr(hmod))
                # nome proc
                if proc.kind in ("string",):
                    pname = proc.value
                elif proc.kind in ("int","hex"):
                    pname = f"ordinal#{proc.value}"
                else:
                    pname = "<unknown>"
                label = f"{(mod_name or 'HMODULE@' + (self._hexstr(hmod) if hmod.kind!='raw' else hmod.raw))}!{pname}"
                self.dynamic_symbols[fptr] = label

    def _hexstr(self, valnode: ValueNode) -> str:
        if isinstance(valnode, ValueNode):
            v = valnode.value
        else:
            v = valnode
        if v is None:
            return "0x0"
        try:
            return f"0x{int(v):X}"
        except:
            return str(v)
