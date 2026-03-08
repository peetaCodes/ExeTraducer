#!/usr/bin/env python3
"""
ExeTraducer IR - Python core module (parser/serializer/translator)

This version extends the single-file IR module with two features requested:
 1) dotted-placeholder resolution in Translator._render_placeholders
    (supports templates like "{0.name}" or "{1.address.disp}")
 2) a conservative, best-effort .NET/IL extraction pipeline using dnfile
    (functions: extract_dotnet_method_summaries, extract_dotnet_methods_to_ir)

Design/Integration notes:
 - The dotted-placeholder code is implemented inside Translator._render_placeholders
   (search for that function in this file). It is fully backwards compatible with
   existing templates that use simple {0} placeholders.
 - The .NET extraction utilities live as module-level helpers (extract_*).
   They use dnfile when available and fall back to producing method summaries
   (method token/name/RVA and a short hex preview of the method body read through pefile).

Limitations & notes:
 - Parsing full, correct IL into semantic IR requires a real IL parser such as
   dnlib (C#) or a proper dnfile method-body decoder. This code purposely keeps
   the extractor conservative and safe: it returns method summaries and a tiny
   proof-of-concept IL->IR "stub" mapping (ops like il_ldstr, il_call, il_ret)
   populated from raw bytes and metadata. This is adequate for inspection and
   building the real lifter incrementally.

Usage examples (integration):
 - In your disassembler CLI, after you detect a CLR directory (is_dotnet(pe) == True),
   replace the current call to dump_dotnet_info(path, dotnet_out) with:

     from src.IR import extract_dotnet_methods_to_ir, save_ir_json_file
     dotnet_ir = extract_dotnet_methods_to_ir(path)
     save_ir_json_file(dotnet_ir, OUT_DIR / f"{base}_dotnet.ir.json")

   This will create an IR JSON containing per-method stub instructions for the
   managed methods inside the assembly. The produced IR is intentionally small
   and uses opnames starting with `il_` so you can differentiate them from
   native -> IR translated instructions.

 - You can also call extract_dotnet_method_summaries(path) to get a list of
   method metadata (token, name, rva, size_estimate, hex_preview).

"""

from __future__ import annotations

import json
import re
import sqlite3
import binascii
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# optional libs
try:
    import dnfile
except Exception:
    dnfile = None

try:
    import pefile
except Exception:
    pefile = None

# jsonschema optional
try:
    import jsonschema
    from jsonschema import ValidationError
except Exception:
    jsonschema = None
    ValidationError = Exception

# ---------------------
# Embedded JSON Schema
# ---------------------
# (Same SCHEMA as previously embedded. Keep in sync with the spec.)
SCHEMA: Dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "ExeTraducer IR v0.1",
    "type": "object",
    "required": ["version", "arch", "endianness", "functions"],
    "additionalProperties": False,
    "properties": {
        "version": {"type": "string", "pattern": "^0\\.1$"},
        "arch": {"type": "string"},
        "endianness": {"type": "string", "enum": ["little", "big"]},
        "image_base": {"type": ["string", "null"]},
        "entry": {"type": ["string", "null"]},
        "imports": {"type": "array", "items": {"$ref": "#/definitions/import"}},
        "exports": {"type": "array", "items": {"$ref": "#/definitions/export"}},
        "functions": {"type": "array", "minItems": 1, "items": {"$ref": "#/definitions/function"}},
        "meta": {"type": "object"}
    },
    "definitions": {
        "function": {
            "type": "object",
            "required": ["name", "entry", "blocks"],
            "additionalProperties": False,
            "properties": {
                "name": {"type": "string"},
                "entry": {"type": "string"},
                "calling_convention": {"type": ["string", "null"]},
                "blocks": {"type": "array", "minItems": 1, "items": {"$ref": "#/definitions/block"}},
                "meta": {"type": "object"}
            }
        },
        "block": {
            "type": "object",
            "required": ["id", "instructions"],
            "additionalProperties": False,
            "properties": {
                "id": {"type": "string"},
                "instructions": {"type": "array", "items": {"$ref": "#/definitions/instruction"}},
                "successors": {"type": "array", "items": {"type": "string"}},
                "meta": {"type": "object"}
            }
        },
        "instruction": {
            "type": "object",
            "required": ["op"],
            "additionalProperties": False,
            "properties": {
                "op": {"type": "string"},
                "dst": {"$ref": "#/definitions/operand"},
                "src": {"$ref": "#/definitions/operand"},
                "args": {"type": "array", "items": {"$ref": "#/definitions/operand"}},
                "expr": {"$ref": "#/definitions/expression"},
                "cond": {"$ref": "#/definitions/operand"},
                "true": {"type": "string"},
                "false": {"type": "string"},
                "target": {"$ref": "#/definitions/operand"},
                "width": {"type": "integer", "minimum": 1},
                "set_flags": {"type": "boolean"},
                "memory_order": {"type": "string", "enum": ["relaxed", "acquire", "release", "acq_rel", "seq_cst"]},
                "meta": {"type": "object"}
            }
        },
        "operand": {
            "oneOf": [
                {"$ref": "#/definitions/imm"},
                {"$ref": "#/definitions/reg"},
                {"$ref": "#/definitions/temp"},
                {"$ref": "#/definitions/mem"},
                {"$ref": "#/definitions/label_ref"}
            ]
        },
        "imm": {
            "type": "object",
            "required": ["type", "value", "width"],
            "additionalProperties": False,
            "properties": {"type": {"const": "imm"}, "value": {"type": ["integer", "string"]},
                           "width": {"type": "integer", "minimum": 1}}
        },
        "reg": {
            "type": "object",
            "required": ["type", "name", "width"],
            "additionalProperties": False,
            "properties": {"type": {"const": "reg"}, "name": {"type": "string"},
                           "width": {"type": "integer", "minimum": 1}}
        },
        "temp": {
            "type": "object",
            "required": ["type", "id", "width"],
            "additionalProperties": False,
            "properties": {"type": {"const": "temp"}, "id": {"type": "string"},
                           "width": {"type": "integer", "minimum": 1}}
        },
        "mem": {
            "type": "object",
            "required": ["type", "address", "width"],
            "additionalProperties": False,
            "properties": {"type": {"const": "mem"}, "address": {"$ref": "#/definitions/address"},
                           "width": {"type": "integer", "minimum": 1}}
        },
        "label_ref": {"type": "object", "required": ["type", "name"], "additionalProperties": False,
                      "properties": {"type": {"const": "label"}, "name": {"type": "string"}}},
        "address": {"type": "object", "required": ["type"], "additionalProperties": False,
                    "properties": {"type": {"const": "addr"}, "base": {"$ref": "#/definitions/operand"},
                                   "index": {"$ref": "#/definitions/operand"}, "scale": {"type": "integer"},
                                   "disp": {"type": "integer"}}},
        "expression": {"type": "object", "required": ["op", "args"], "additionalProperties": False,
                       "properties": {"op": {"type": "string"}, "args": {"type": "array", "minItems": 1, "items": {
                           "$ref": "#/definitions/operand_or_expr"}}}},
        "operand_or_expr": {"oneOf": [{"$ref": "#/definitions/operand"}, {"$ref": "#/definitions/expression"}]},
        "import": {"type": "object", "required": ["name"], "additionalProperties": False,
                   "properties": {"name": {"type": "string"}, "library": {"type": "string"},
                                  "meta": {"type": "object"}}},
        "export": {"type": "object", "required": ["name"], "additionalProperties": False,
                   "properties": {"name": {"type": "string"}, "address": {"type": ["string", "null"]},
                                  "meta": {"type": "object"}}}
    }
}


# ---------------------
# Validation wrapper
# ---------------------
class IRValidationError(Exception):
    pass


def validate_ir_json(obj: Dict[str, Any]) -> None:
    if jsonschema is None:
        raise IRValidationError("jsonschema is required for validation. Install with: pip install jsonschema")
    try:
        jsonschema.validate(instance=obj, schema=SCHEMA)
    except ValidationError as e:
        path = "/".join(map(str, getattr(e, 'path', [])))
        raise IRValidationError(f"IR JSON validation error: {e.message} (at {path})") from e


# ---------------------
# Minimal textual parser (same as earlier)
# ---------------------
RE_HEADER = re.compile(r"^\s*(version|arch|endianness|image_base|entry)\s+(.+)$")
RE_FUNC = re.compile(r"^\s*\.func\s+@([A-Za-z0-9_.$@]+)\s*:\s*$")
RE_LABEL = re.compile(r"^\s*([A-Za-z0-9_.$:]+)\s*:\s*$")
RE_INSTR = re.compile(r"^\s*([^;#]+?)(?:[;#].*)?$")
RE_REG = re.compile(r"^([A-Za-z][A-Za-z0-9]*)$")
RE_IMM = re.compile(r"^(-?0x[0-9a-fA-F]+|-?\\d+)$")
RE_MEM_SIMPLE = re.compile(r"^\[(.*?)\]$")


def _parse_imm(token: str) -> Optional[Dict[str, Any]]:
    m = RE_IMM.match(token)
    if not m:
        return None
    s = token
    try:
        if s.startswith("0x") or s.startswith("-0x"):
            v = int(s, 16)
        else:
            v = int(s, 10)
    except Exception:
        return None
    return {"type": "imm", "value": v, "width": 64}


def _parse_reg(token: str) -> Optional[Dict[str, Any]]:
    m = RE_REG.match(token)
    if not m:
        return None
    name = m.group(1)
    return {"type": "reg", "name": name.upper(), "width": 64}


def _parse_operand(token: str) -> Dict[str, Any]:
    tok = token.strip()
    if tok.startswith("@"):
        return {"type": "label", "name": tok}
    m = RE_MEM_SIMPLE.match(tok)
    if m:
        inner = m.group(1).strip()
        parts = re.split(r"(\+|-)", inner)
        base = None
        index = None
        scale = None
        disp = 0
        i = 0
        sign = 1
        while i < len(parts):
            p = parts[i].strip()
            if p == '+' or p == '-':
                sign = 1 if p == '+' else -1
                i += 1
                continue
            if '*' in p:
                sub = p.split('*')
                left = sub[0].strip()
                right = sub[1].strip()
                rreg = _parse_reg(left)
                rscale = int(right, 0)
                index = rreg
                scale = rscale
            else:
                r = _parse_reg(p)
                if r:
                    if base is None:
                        base = r
                    else:
                        index = r
                        if scale is None:
                            scale = 1
                else:
                    im = _parse_imm(p)
                    if im:
                        disp += sign * im["value"]
                    else:
                        disp = p
            i += 1
        addr = {"type": "addr", "base": base, "index": index, "scale": scale or 1, "disp": disp}
        return {"type": "mem", "address": addr, "width": 64}
    im = _parse_imm(tok)
    if im:
        return im
    r = _parse_reg(tok)
    if r:
        return r
    return {"type": "label", "name": tok}


def parse_textual_ir(text: str) -> Dict[str, Any]:
    lines = text.splitlines()
    header: Dict[str, Any] = {"version": "0.1", "arch": "x86_64", "endianness": "little", "functions": []}
    cur_func: Optional[Dict[str, Any]] = None
    cur_block: Optional[Dict[str, Any]] = None

    def _finish_block():
        nonlocal cur_block, cur_func
        if cur_block is not None:
            assert cur_func is not None
            cur_func["blocks"].append(cur_block)
            cur_block = None

    def _finish_func():
        nonlocal cur_func
        if cur_func is not None:
            header["functions"].append(cur_func)
            cur_func = None

    lineno = 0
    for raw in lines:
        lineno += 1
        line = raw.strip()
        if line == "" or line.startswith(";") or line.startswith("#"):
            continue
        m = RE_HEADER.match(line)
        if m:
            k = m.group(1).strip()
            v = m.group(2).strip()
            if k == "version":
                header["version"] = v
            elif k == "arch":
                header["arch"] = v
            elif k == "endianness":
                header["endianness"] = v
            elif k == "image_base":
                header["image_base"] = v
            elif k == "entry":
                header["entry"] = v
            continue
        m = RE_FUNC.match(line)
        if m:
            _finish_block()
            _finish_func()
            fname = "@" + m.group(1)
            cur_func = {"name": fname, "entry": "b0", "blocks": [], "meta": {}}
            cur_block = {"id": "b0", "instructions": [], "meta": {}}
            continue
        m = RE_LABEL.match(line)
        if m:
            lbl = m.group(1).strip()
            if cur_func is None:
                raise ValueError(f"Label outside function at line {lineno}: {raw}")
            _finish_block()
            cur_block = {"id": lbl, "instructions": [], "meta": {}}
            continue
        m = RE_INSTR.match(line)
        if m:
            instr_text = m.group(1).strip()
            parts = instr_text.split(maxsplit=1)
            if len(parts) == 0:
                continue
            op = parts[0].lower()
            ops = parts[1] if len(parts) > 1 else ""
            instr_obj: Dict[str, Any] = {"op": op, "meta": {"asm": instr_text, "line": lineno}}
            try:
                if op in ("mov", "add", "sub", "and", "or", "xor", "lea"):
                    left_right = [p.strip() for p in ops.split(",", 1)] if ops else [""]
                    dst_tok = left_right[0] if len(left_right) > 0 else ""
                    src_tok = left_right[1] if len(left_right) > 1 else ""
                    if dst_tok:
                        instr_obj["dst"] = _parse_operand(dst_tok)
                    if src_tok:
                        instr_obj["src"] = _parse_operand(src_tok)
                elif op.startswith("load") or op.startswith("store"):
                    if "=" in instr_text:
                        lhs, rhs = instr_text.split("=", 1)
                        dst = lhs.strip()
                        rhs = rhs.strip()
                        m2 = re.match(r"load(\d+|)\s*\[(.*)\]", rhs)
                        if m2:
                            width = int(m2.group(1)) if m2.group(1) else 64
                            addr_str = m2.group(2)
                            instr_obj["dst"] = _parse_operand(dst)
                            addr_op = _parse_operand("[" + addr_str + "]")
                            if addr_op["type"] == "mem":
                                instr_obj["addr"] = addr_op["address"]
                                instr_obj["op"] = "load"
                                instr_obj["width"] = width
                        else:
                            instr_obj["expr"] = {"op": "load", "args": []}
                    else:
                        sub = ops.split(",", 1)
                        if len(sub) == 2:
                            dst_tok = sub[0].strip()
                            addr_tok = sub[1].strip()
                            instr_obj["dst"] = _parse_operand(dst_tok)
                            memop = _parse_operand(addr_tok)
                            if memop["type"] == "mem":
                                instr_obj["addr"] = memop["address"]
                                instr_obj["width"] = int(re.findall(r"\d+", op)[0]) if re.findall(r"\d+", op) else 64
                                instr_obj["op"] = "load"
                elif op == "cmp" or op.startswith("cmp"):
                    sub = ops.split(",", 1)
                    if len(sub) == 2:
                        a = _parse_operand(sub[0].strip())
                        b = _parse_operand(sub[1].strip())
                        instr_obj["op"] = "sub"
                        instr_obj["dst"] = a
                        instr_obj["src"] = b
                        instr_obj["set_flags"] = True
                elif op == "cjmp":
                    parts2 = [p.strip() for p in ops.split(",")]
                    if len(parts2) >= 2:
                        cond_tok = parts2[0]
                        true_lbl = parts2[1]
                        false_lbl = parts2[2] if len(parts2) > 2 else ""
                        instr_obj["cond"] = _parse_operand(cond_tok)
                        instr_obj["true"] = true_lbl
                        instr_obj["false"] = false_lbl
                elif op == "jmp":
                    instr_obj["op"] = "jmp"
                    instr_obj["target"] = {"type": "label", "name": ops.strip()}
                elif op == "ret":
                    instr_obj["op"] = "ret"
                elif op == "call":
                    target = ops.strip()
                    if target.startswith("@"):
                        instr_obj["target"] = {"type": "label", "name": target}
                    else:
                        instr_obj["target"] = _parse_operand(target)
                else:
                    if ops:
                        args = [a.strip() for a in ops.split(",")]
                        instr_obj["args"] = [_parse_operand(a) for a in args if a]
            except Exception as e:
                instr_obj.setdefault("meta", {})["parse_error"] = str(e)

            if cur_block is None:
                raise ValueError(f"Instruction outside function at line {lineno}: {raw}")
            cur_block["instructions"].append(instr_obj)  # noqa
            continue
        raise ValueError(f"Could not parse line {lineno}: {raw}")
    _finish_block()
    _finish_func()
    if "entry" not in header:
        header["entry"] = None
    return header


# ---------------------
# Serializer: JSON -> textual IR
# ---------------------

def serialize_ir_to_text(ir: Dict[str, Any]) -> str:
    out_lines: List[str] = [
        f"version {ir.get('version', '0.1')}",
        f"arch {ir.get('arch', 'x86_64')}",
        f"endianness {ir.get('endianness', 'little')}"
    ]
    if ir.get('image_base'):
        out_lines.append(f"image_base {ir.get('image_base')}")
    if ir.get('entry'):
        out_lines.append(f"entry {ir.get('entry')}")
    out_lines.append("")

    for func in ir.get('functions', []):
        name = func.get('name')
        out_lines.append(f".func {name}:")
        for block in func.get('blocks', []):
            out_lines.append(f"{block.get('id')}:")
            for instr in block.get('instructions', []):
                op = instr.get('op')
                meta = instr.get('meta', {})
                asm = meta.get('asm')
                if asm:
                    out_lines.append(f"  {asm}")
                    continue
                if op in ("mov", "add", "sub", "and", "or", "xor", "lea"):
                    dst = instr.get('dst')
                    src = instr.get('src')

                    def fmt_operand(o):
                        if o is None: return ""
                        _t = o.get('type')
                        if _t == 'reg': return o['name']
                        if _t == 'imm': return str(o['value'])
                        if _t == 'mem':
                            _addr = o['address']
                            parts = []
                            if _addr.get('base'): parts.append(_addr['base']['name'])
                            if _addr.get('index'):
                                parts.append(_addr['index']['name'] + '*' + str(_addr.get('scale', 1)))
                            if _addr.get('disp'):
                                parts.append(str(_addr['disp']))
                            return '[' + ' + '.join(parts) + ']'
                        return str(o)

                    out_lines.append(f"  {op} {fmt_operand(dst)}, {fmt_operand(src)}")
                elif op == 'load':
                    dst = instr.get('dst')
                    addr = instr.get('addr')

                    def fmt_addr(_a):
                        parts = []
                        if _a.get('base'): parts.append(_a['base']['name'])
                        if _a.get('index'): parts.append(_a['index']['name'] + '*' + str(_a.get('scale', 1)))
                        if _a.get('disp'): parts.append(str(_a['disp']))
                        return '[' + ' + '.join(parts) + ']'

                    out_lines.append(
                        f"  {dst.get('name') if dst and dst.get('type') == 'reg' else 't?'} = load{instr.get('width', 64)} {fmt_addr(addr)}")
                elif op == 'store':
                    out_lines.append(f"  store{instr.get('width', 64)} {instr.get('addr')}, {instr.get('src')}")
                elif op == 'cjmp':
                    cond = instr.get('cond')
                    t = instr.get('true')
                    f = instr.get('false')
                    cond_str = cond.get('name') if cond and cond.get('type') == 'reg' else str(cond)
                    out_lines.append(f"  cjmp {cond_str}, {t}, {f}")
                elif op == 'jmp':
                    tgt = instr.get('target')
                    if tgt and tgt.get('type') == 'label':
                        out_lines.append(f"  jmp {tgt.get('name')}")
                    else:
                        out_lines.append(f"  jmp {tgt}")
                elif op == 'ret':
                    out_lines.append("  ret")
                elif op == 'call':
                    tgt = instr.get('target')
                    if tgt and tgt.get('type') == 'label':
                        out_lines.append(f"  call {tgt.get('name')}")
                    else:
                        out_lines.append(f"  call {tgt}")
                else:
                    args = instr.get('args')
                    if args:
                        arg_strs = []
                        for a in args:
                            if a.get('type') == 'reg':
                                arg_strs.append(a['name'])
                            elif a.get('type') == 'imm':
                                arg_strs.append(str(a['value']))
                            else:
                                arg_strs.append(str(a))
                        out_lines.append(f"  {op} " + ", ".join(arg_strs))
                    else:
                        out_lines.append(f"  {op}")
        out_lines.append("")
    return "\n".join(out_lines)


# ---------------------
# JSON loader / writer
# ---------------------

def load_ir_json_file(path: Path, validate_schema: bool = True) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding='utf-8'))
    if validate_schema:
        validate_ir_json(data)
    return data


def save_ir_json_file(data: Dict[str, Any], path: Path, indent: int = 2, validate_schema: bool = True) -> None:
    if validate_schema:
        validate_ir_json(data)
    path.write_text(json.dumps(data, indent=indent), encoding='utf-8')


# ---------------------
# Translation table manager
# ---------------------
class TranslationTableManager:
    """Load translation templates from SQLite or JSON files.

    Template format (JSON object) example (conceptual):
    {
      "op": "mov",
      "dst": "{0}",
      "src": "{1}",
      "meta": { "note": "direct copy" }
    }

    The template fields use positional placeholders {0}, {1} corresponding to
    parsed operands. The translator will replace them with operand objects.
    """

    def __init__(self, db_path: Optional[Path] = None, json_dir: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else None
        self.json_dir = Path(json_dir) if json_dir else None
        self.conn: Optional[sqlite3.Connection] = None
        self._cache: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        if self.db_path and self.db_path.exists():
            self._open_db()

    def _open_db(self):
        if self.conn:
            return
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row

    def get_templates_for(self, arch: str, mnemonic: str) -> List[Dict[str, Any]]:
        key = (arch, mnemonic.lower())
        if key in self._cache:
            return self._cache[key]
        results: List[Dict[str, Any]] = []
        # Try SQLite
        if self.conn:
            cur = self.conn.cursor()
            cur.execute("SELECT pattern, template_json FROM translations WHERE arch=? AND mnemonic=? ORDER BY id",
                        (arch, mnemonic.lower()))
            for row in cur.fetchall():
                try:
                    tpl = json.loads(row["template_json"])
                    tpl["pattern"] = row["pattern"]
                    results.append(tpl)
                except Exception:
                    continue
        # Fallback: JSON files per-arch
        if not results and self.json_dir and self.json_dir.exists():
            jsf = self.json_dir / f"{arch}.json"
            if jsf.exists():
                try:
                    doc = json.loads(jsf.read_text(encoding='utf-8'))
                    # doc is expected to be { "mnemonic": [ {"pattern":"...","template":{...}}, ... ] }
                    entries = doc.get(mnemonic.lower(), [])
                    for e in entries:
                        tpl = e.get("template")
                        tpl["pattern"] = e.get("pattern")
                        results.append(tpl)
                except Exception:
                    pass
        self._cache[key] = results
        return results


# ---------------------
# Translator
# ---------------------
class Translator:
    """Translates textual assembly lines into IR instruction dicts using
    templates provided by TranslationTableManager.

    Behavior when no template found:
     - Try a best-effort heuristic for simple mnemonics (mov/add/sub/lea)
     - Otherwise return an instruction with op set to original mnemonic and
       meta.annotated to indicate missing translation
    """

    def __init__(self, table_mgr: TranslationTableManager):
        self.table_mgr = table_mgr

    @staticmethod
    def _tokenize_operands(op_str: str) -> List[str]:
        # naive split by commas (doesn't handle nested commas in complex exprs)
        if not op_str:
            return []
        parts = [p.strip() for p in op_str.split(',')]
        return [p for p in parts if p]

    def translate_line(self, asm_line: str, arch: str = 'x86_64') -> Dict[str, Any]:
        """Translate a single assembly mnemonic line into an IR instruction object.

        Handles Capstone-style lines, plain assembly lines, and data directives.

        Examples recognized:
          0x140002000: 48 8b 05 ...    mov    rax, qword ptr [rip + 0x...]
          0x401000:  C3                 ret
          mov rax, rbx
          db 0x90,0x90
        """
        raw = asm_line or ""
        line = raw.strip()
        if line == '':
            return {"op": "nop", "meta": {"asm": asm_line}}

        # Pattern for capstone-style output:
        #  - address:  bytes...  mnemonic  operands...
        # example: 0x401000: 48 8b 05 ...  mov    rax, [rip + 0x...]
        cap_re = re.compile(
            r'^\s*0x[0-9A-Fa-f]+[:]{1,2}\s*(?:[0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*\s+)?([A-Za-z0-9_.]+)(?:\s+(.*))?$')
        m = cap_re.match(line)
        if m:
            mnemonic = m.group(1).lower()
            operands_text = (m.group(2) or "").strip()
        else:
            # If the line begins with a bytes-only directive or assembler data directive,
            # treat as data (so it won't be fed to mnemonic templates)
            data_directive_re = re.compile(r'^\s*(db|byte|dq|dw|.byte|\.byte)\b', re.IGNORECASE)
            if data_directive_re.match(line):
                # create a data sentinel IR node (translator should skip templates for this)
                return {'op': 'data', 'meta': {'asm': asm_line}}
            # fallback: plain textual form like "mov rax, rbx" or "ret"
            parts = line.split(maxsplit=1)
            mnemonic = parts[0].lower()
            operands_text = parts[1] if len(parts) > 1 else ''

        # tokenize operands and continue as before
        operands = [_parse_operand(op) for op in self._tokenize_operands(operands_text)]

        # try templates
        templates = self.table_mgr.get_templates_for(arch, mnemonic)
        for tpl in templates:
            pat = tpl.get('pattern', 'any')
            if self._match_pattern(pat, operands):
                try:
                    instr = self.apply_template(tpl, operands, asm_line)
                    return instr
                except Exception:
                    # try next
                    continue
        # fallback heuristics for common ops
        instr = self._heuristic_translate(mnemonic, operands, asm_line)
        return instr

    @staticmethod
    def _match_pattern(pattern: str, operands: List[Dict[str, Any]]) -> bool:
        # patterns: "reg,reg", "reg,mem", "mem,reg", "any"
        if pattern == 'any':
            return True
        expected = [p.strip() for p in pattern.split(',') if p.strip()]
        if len(expected) != len(operands):
            return False
        for e, op in zip(expected, operands):
            if e == 'reg' and op.get('type') != 'reg':
                return False
            if e == 'mem' and op.get('type') != 'mem':
                return False
            if e == 'imm' and op.get('type') != 'imm':
                return False
            # 'any' matches any
        return True

    def apply_template(self, tpl: Dict[str, Any], operands: List[Dict[str, Any]], asm_line: str) -> Dict[str, Any]:
        # tpl is expected to be a dict with op/dst/src/args fields using placeholders
        # placeholder style: "{0}" refers to operands[0] object inserted directly
        # we support substitution for top-level dst/src and args
        op = tpl.get('op', None)
        instr: Dict[str, Any] = {}
        if not op and 'op' in tpl:
            op = tpl['op']
        if op:
            instr['op'] = op
        # dst
        if 'dst' in tpl:
            dst_tpl = tpl['dst']
            instr['dst'] = self._render_placeholders(dst_tpl, operands)
        if 'src' in tpl:
            src_tpl = tpl['src']
            instr['src'] = self._render_placeholders(src_tpl, operands)
        if 'args' in tpl:
            args_tpl = tpl['args']
            instr['args'] = [self._render_placeholders(a, operands) for a in args_tpl]
        # copy meta, record original asm
        meta = tpl.get('meta', {}) or {}
        meta = dict(meta)  # copy
        meta['asm'] = asm_line
        instr['meta'] = meta
        # width and set_flags if present
        if 'width' in tpl:
            instr['width'] = tpl['width']
        if 'set_flags' in tpl:
            instr['set_flags'] = bool(tpl['set_flags'])
        return instr

    @staticmethod
    def _get_nested_attr(obj: Any, attrs: List[str]) -> Any:
        """
        Safely traverse a nested dict/object using a list of attribute keys.
        For dicts, use keys. For objects, try getattr.
        Returns None if any step fails.
        """
        cur = obj
        for a in attrs:
            if cur is None:
                return None
            if isinstance(cur, dict):
                # support both 'name' and nested 'address.disp' etc.
                cur = cur.get(a)
            else:
                # fallback to getattr for objects (rare)
                cur = getattr(cur, a, None)
        return cur

    def _render_placeholders(self, template_value: Any, operands: List[Dict[str, Any]]) -> Any:
        """
        Extended placeholder resolver supporting dotted form {0.name} and {1.address.disp}.

        - If template_value is a string of the form "{N}" => returns operands[N]
        - If template_value is "{N.field.sub}"
            => returns nested attribute; if final value is a primitive returns it; if dict returns dict
        - If template_value is a simple register name like "RAX" => returns a reg operand dict
        - If string isn't a placeholder, the function attempts to parse it as imm/reg,
          otherwise returns the raw string.
        - If template_value is a dict, resolves nested strings recursively.
        """
        # string placeholders
        if isinstance(template_value, str):
            s = template_value.strip()
            # dotted placeholder: {0.name} or {1.address.disp}
            m = re.fullmatch(r"\{(\d+(?:\.[A-Za-z0-9_]+)*)\}", s)
            if m:
                body = m.group(1)
                parts = body.split('.')
                idx = int(parts[0])
                if idx < len(operands):
                    if len(parts) == 1:
                        return operands[idx]
                    # traverse attributes
                    val = self._get_nested_attr(operands[idx], parts[1:])
                    # if the nested value looks like an operand (dict with 'type'), return as-is
                    if isinstance(val, dict):
                        return val
                    # if it's a primitive, attempt to coerce to imm/reg if possible
                    if isinstance(val, (int, str)):
                        # attempt imm or reg
                        im = _parse_imm(str(val))
                        if im:
                            return im
                        r = _parse_reg(str(val))
                        if r:
                            return r
                        # otherwise return as string
                        return str(val)
                    return val
                else:
                    raise IndexError("Operand index out of range in template")
            # simple positional {N}
            m2 = re.fullmatch(r"\{(\d+)\}", s)
            if m2:
                idx = int(m2.group(1))
                if idx < len(operands):
                    return operands[idx]
                raise IndexError("Operand index out of range in template")
            # fallback: parse as reg or imm
            r = _parse_reg(s)
            if r:
                return r
            im = _parse_imm(s)
            if im:
                return im
            return s
        # dict: recursively resolve string values
        if isinstance(template_value, dict):
            out = {}
            for k, v in template_value.items():
                if isinstance(v, (str, dict)):
                    out[k] = self._render_placeholders(v, operands)
                else:
                    out[k] = v
            return out
        # lists: resolve each item
        if isinstance(template_value, list):
            return [self._render_placeholders(x, operands) for x in template_value]
        return template_value

    @staticmethod
    def _heuristic_translate(mnemonic: str, operands: List[Dict[str, Any]], asm_line: str) -> Dict[str, Any]:
        # Very small heuristics to cover common mnemonics when no table exists.
        if mnemonic in ('mov', 'add', 'sub', 'and', 'or', 'xor', 'lea'):
            instr: dict[str, Any] = {'op': mnemonic}
            if len(operands) >= 1:
                instr['dst'] = operands[0]
            if len(operands) >= 2:
                instr['src'] = operands[1]
            instr['meta'] = {'asm': asm_line, 'heuristic': True}
            return instr
        if mnemonic.startswith('jmp'):
            instr = {'op': 'jmp', 'target': operands[0] if operands else {'type': 'label', 'name': asm_line},
                     'meta': {'asm': asm_line, 'heuristic': True}}
            return instr
        if mnemonic == 'call':
            instr = {'op': 'call', 'target': operands[0] if operands else {'type': 'label', 'name': asm_line},
                     'meta': {'asm': asm_line, 'heuristic': True}}
            return instr
        if mnemonic == 'ret':
            return {'op': 'ret', 'meta': {'asm': asm_line}}
        # default unknown
        return {'op': mnemonic, 'args': operands, 'meta': {'asm': asm_line, 'missing_table': True}}


# ---------------------
# .NET / IL extraction helpers (best-effort)
# ---------------------

def _try_get_attr_any(obj, names: List[str]):
    for n in names:
        if hasattr(obj, n):
            return getattr(obj, n)
        if isinstance(obj, dict) and n in obj:
            return obj[n]
    return None


def extract_dotnet_method_summaries(pe_path: str) -> List[Dict[str, Any]]:
    """
    Best-effort method summary extractor using dnfile when available.

    Returns a list of dicts: { 'token': token, 'name': name, 'rva': rva, 'size_est': size_est, 'hex_preview': 'deadbeef' }

    Notes:
      - This function is intentionally conservative: it uses available metadata
        in dnfile to list methods. It does NOT attempt to fully decode method
        bodies; for that you should use dnlib or a dedicated IL parser.
      - When dnfile is not installed, this returns an empty list and raises
        an informative Exception.
    """
    if dnfile is None:
        raise RuntimeError(
            "dnfile not installed; cannot extract .NET method summaries. Install with: pip install dnfile")
    if pefile is None:
        raise RuntimeError("pefile is required to fetch raw bytes for RVA previews (pip install pefile)")

    dpe = dnfile.dnPE(pe_path)
    summaries: List[Dict[str, Any]] = []
    # The metadata tables are accessible as dpe.net.mdtables
    mdt = getattr(dpe.net, 'mdtables', None) or getattr(dpe.net, 'mdtables', None)
    if not mdt:
        # fallback: try scanning dnfile objects for MethodDef table
        tables = getattr(dpe.net, 'tables_list', [])
    # iterate methoddef table rows if present
    try:
        method_rows = list(getattr(dpe.net.mdtables, 'MethodDef', []))
    except Exception:
        # try attribute access alternative
        try:
            method_rows = list(getattr(dpe.net, 'MethodDef', []))
        except Exception:
            method_rows = []

    # helper to read bytes at RVA using pefile
    pe = pefile.PE(pe_path, fast_load=True)

    for row in method_rows:
        try:
            # token or row id
            token = getattr(row, 'row_id', None) or getattr(row, 'Token', None) or None
            # method name: dnfile provides many helpers; try common properties
            name = _try_get_attr_any(row, ['Name', 'name', 'get_name'])
            # RVA: row.RVA or row.rva or row.RelativeVirtualAddress
            rva = _try_get_attr_any(row, ['RVA', 'rva', 'RelativeVirtualAddress', 'rva_value'])
            if isinstance(rva, str):
                try:
                    rva = int(rva, 0)
                except Exception:
                    rva = None
            # if rva is zero-ish skip
            if not rva:
                size_est = 0
                hex_preview = ''
            else:
                # read a small preview (512 bytes) from the native image (file offset)
                try:
                    raw = pe.get_memory_mapped_image()[rva:rva + 512]
                except Exception:
                    try:
                        raw = pe.get_data(rva, 512)
                    except Exception:
                        raw = b''
                hex_preview = binascii.hexlify(raw[:256]).decode('ascii')
                size_est = len(raw)
            summaries.append(
                {'token': token, 'name': str(name), 'rva': rva, 'size_est': size_est, 'hex_preview': hex_preview})
        except Exception:
            continue
    return summaries


def _stub_map_il_bytes_to_ir(il_bytes: bytes, method_summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Very small, conservative IL->IR prototype mapper.

    It scans the raw IL bytes and emits lightweight 'il_' opnames with meta.
    This is NOT a full IL lifter; it's a scaffold so the rest of the pipeline can
    consume and be extended later.
    """
    ops: List[Dict[str, Any]] = []
    i = 0
    while i < len(il_bytes):
        b = il_bytes[i]
        # single-byte opcodes: ret=0x2A, ldstr=0x72, call=0x28, ldc.i4 = 0x20..0x26
        if b == 0x2A:
            ops.append({'op': 'il_ret', 'meta': {'offset': i}})
            i += 1
            continue
        if b == 0x28:  # call
            # call token 4 bytes little endian follows
            if i + 4 < len(il_bytes):
                token = int.from_bytes(il_bytes[i + 1:i + 5], 'little')
                ops.append({'op': 'il_call', 'meta': {'offset': i, 'token': token}})
                i += 5
                continue
        if b == 0x72:  # ldstr token
            if i + 4 < len(il_bytes):
                token = int.from_bytes(il_bytes[i + 1:i + 5], 'little')
                ops.append({'op': 'il_ldstr', 'meta': {'offset': i, 'token': token}})
                i += 5
                continue
        # short and small immediates: ldc.i4.s (0x1F) then 1 byte
        if b == 0x1F:
            if i + 1 < len(il_bytes):
                imm = int.from_bytes(il_bytes[i + 1:i + 2], 'little', signed=True)
                ops.append(
                    {'op': 'il_ldc.i4', 'dst': {'type': 'imm', 'value': imm, 'width': 32}, 'meta': {'offset': i}})
                i += 2
                continue
        # fallback: record unknown byte as 'il_raw'
        ops.append({'op': 'il_raw_byte', 'meta': {'offset': i, 'byte': b}})
        i += 1
    # attach method id in meta for convenience
    for o in ops:
        o.setdefault('meta', {})['method'] = method_summary.get('name')
    return ops


def extract_dotnet_methods_to_ir(pe_path: str) -> Dict[str, Any]:
    """
    Produce a compact IR JSON that contains one function per managed method.

    Each method gets a function named '@method_<token_or_name>' with a single
    block 'b0' containing a sequence of small 'il_' or 'il_raw' IR instructions
    produced by _stub_map_il_bytes_to_ir. This output is conservative and meant
    to be consumed by later lifter passes that will replace stub ops with
    semantically-rich IR nodes.

    The function returns a complete IR dict matching your schema's minimal
    requirements (version, arch, endianness, functions).
    """
    summaries = extract_dotnet_method_summaries(pe_path)
    # try to open the on-disk PE for reading full bytes
    if pefile is None:
        raise RuntimeError("pefile required to read IL bytes for preview; install pip install pefile")
    pe = pefile.PE(pe_path, fast_load=True)
    functions: List[Dict[str, Any]] = []
    for m in summaries:
        name = m.get('name') or f"method_{m.get('token')}"
        rva = m.get('rva')
        il_bytes = b''
        if rva and rva > 0:
            try:
                # read a small chunk; real size of IL body may be longer; this is a preview
                il_bytes = pe.get_data(rva, 4096) or b''
            except Exception:
                il_bytes = b''
        # map to IR stub ops
        ops = _stub_map_il_bytes_to_ir(il_bytes, m)
        instrs = []
        for o in ops:
            instr = {'op': o['op'], 'meta': o.get('meta', {})}
            # attach token where meaningful
            if 'token' in o.get('meta', {}):
                instr['meta']['token'] = o['meta']['token']
            instrs.append(instr)
        func = {
            'name': '@' + name,
            'entry': 'b0',
            'blocks': [{'id': 'b0', 'instructions': instrs, 'meta': {}}],
            'meta': {'dotnet_method_summary': m}
        }
        functions.append(func)
    ir = {
        'version': '0.1',
        'arch': 'msil',
        'endianness': 'little',
        'functions': functions
    }
    return ir


# ---------------------
# High-level helpers: assemble file -> IR JSON
# ---------------------

def assembly_lines_to_ir(asm_lines: List[str], arch: str, table_mgr: TranslationTableManager,
                         func_name: str = '@translated') -> Dict[str, Any]:
    trans = Translator(table_mgr)
    instrs = []
    for line in asm_lines:
        line = line.strip()
        if line == '' or line.startswith(';') or line.startswith('#'):
            continue
        instr = trans.translate_line(line, arch=arch)
        instrs.append(instr)
    func = {
        'name': func_name,
        'entry': 'b0',
        'blocks': [{'id': 'b0', 'instructions': instrs}],
        'meta': {'assembled_from': len(asm_lines)}
    }
    ir = {
        'version': '0.1',
        'arch': arch,
        'endianness': 'little' if '64' in arch or 'x86' in arch else 'little',
        'functions': [func]
    }
    return ir
