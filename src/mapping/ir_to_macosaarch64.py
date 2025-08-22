# macos_aarch64_translator.py
"""
Algorithmic IR -> macos-aarch64 translator.

Main functions:
 - translate_ir_call_algorithmic(ir_entry, target="macos-aarch64")
     -> returns dict with keys: target, action_type, params, code_c, code_objc, json_repr, confidence, notes

 - generate_static_handler_map(ir_list, out_json=None)
     -> produces a JSON file mapping IR -> chosen handler metadata (auto-generated).

Design:
 - No manual _HANDLER_MAP required: router inspects IR tokens and applies templates.
 - Extensible: add template entries to DOMAIN_TEMPLATES or CUSTOM_TEMPLATES.
"""

from typing import Optional, List, Tuple, Dict, Any
import json
from src.tools.macos_translation_utils import *


# ----------------------------
# Parser of IR string: sys.file.create -> domain=file, verb=create, extras path
def parse_ir(ir: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Parse IR like: sys.file.create -> returns (domain, verb, rest)
    Supports nested like: sys.memory.file_mapping.create => domain=memory.file_mapping verb=create
    """
    if not ir or not isinstance(ir, str):
        return None, None, None
    parts = ir.split(".")
    if len(parts) < 2:
        return None, None, None
    # expected forms:
    #   sys.<domain>.<verb>
    #   ui.dialog.message -> domain='ui', sub='dialog.message', verb='message'
    # heuristics:
    if parts[0] in ("sys", "ui", "net"):
        if len(parts) == 3:
            domain = parts[1]
            verb = parts[2]
            rest = None
            return domain, verb, rest
        elif len(parts) > 3:
            # treat everything between 1..-2 as domain path
            domain = ".".join(parts[1:-1])
            verb = parts[-1]
            return domain, verb, None
    else:
        # fallback: first token = domain, last = verb if many parts
        if len(parts) >= 2:
            return parts[0], parts[-1], None
    return None, None, None


# ----------------------------
# Confidence scoring helper
def score_confidence(base_confidence: str, adjustments: List[Tuple[str, int]]) -> str:
    """
    base_confidence in 'low'|'medium'|'high'
    adjustments: list of (reason, delta)
    Map to numeric and back.
    """
    mapping = {"low": 0, "medium": 5, "high": 10}
    score = mapping.get(base_confidence, 0)
    for _, d in adjustments:
        score += d
    if score >= 9:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


# ----------------------------
# Main algorithmic translator
def map_ir_to_macos(ir_entry: Dict[str, Any], target: str = "macos-aarch64") -> Dict[str, Any]:
    """
    ir_entry: {"ir":"sys.file.create", "params": {...}, "meta": {...}}
    returns: dict with keys target, action_type, params, code_c, code_objc, json_repr, confidence, notes
    """
    ir = ir_entry.get("ir") or ir_entry.get("name") or ""
    params = ir_entry.get("params", {}) or {}
    meta = ir_entry.get("meta", {}) or {}
    # parse IR string
    domain, verb, _ = parse_ir(ir)
    # try domain templates
    adjustments = []
    chosen_template = None
    chosen_action = None
    # prefer exact domain path (e.g., 'memory.file_mapping')
    if domain in DOMAIN_TEMPLATES:
        dom_map = DOMAIN_TEMPLATES[domain]
        if verb in dom_map:
            chosen_template = dom_map[verb]["template"]
            chosen_action = dom_map[verb]["action"]
        elif "default" in dom_map:
            chosen_template = dom_map["default"]["template"]
            chosen_action = dom_map["default"]["action"]
    else:
        # maybe composite domain: split on '.' and try leftmost/first token
        if domain and "." in domain:
            head = domain.split(".")[0]
            if head in DOMAIN_TEMPLATES:
                dom_map = DOMAIN_TEMPLATES[head]
                if verb in dom_map:
                    chosen_template = dom_map[verb]["template"]
                    chosen_action = dom_map[verb]["action"]
                else:
                    chosen_template = dom_map.get("default", {}).get("template")
                    chosen_action = dom_map.get("default", {}).get("action")
    # fallback by top-level tokens (e.g., ir='ui.dialog.message' domain parsed as 'dialog' earlier)
    if chosen_template is None:
        # try heuristics on ir string tokens
        parts = ir.split(".")
        # try sys.<something>.<verb> with something as domain
        if len(parts) >= 3 and parts[0] in ("sys", "ui", "net"):
            head = parts[1]
            if head in DOMAIN_TEMPLATES:
                dom_map = DOMAIN_TEMPLATES[head]
                chosen_template = dom_map.get(verb, dom_map.get("default", None))["template"] if dom_map.get(verb,
                                                                                                             None) else dom_map.get(
                    "default", {}).get("template")
                chosen_action = dom_map.get(verb, dom_map.get("default", {})).get("action") if dom_map.get(verb,
                                                                                                           None) else dom_map.get(
                    "default", {}).get("action")
        # last-ditch: map by verb (generic)
    if chosen_template is None:
        # Generic verb-based mapping
        if verb in ("create", "open", "read", "write", "delete"):
            chosen_template = DOMAIN_TEMPLATES["file"]["default"]["template"]
            chosen_action = DOMAIN_TEMPLATES["file"]["default"]["action"]
            adjustments.append(("verb_fallback", +2))
        elif verb in ("connect", "send", "recv"):
            chosen_template = DOMAIN_TEMPLATES["net"]["default"]["template"]
            chosen_action = DOMAIN_TEMPLATES["net"]["default"]["action"]
            adjustments.append(("verb_net_fallback", +2))
        elif verb in ("load", "get_symbol"):
            chosen_template = DOMAIN_TEMPLATES["module"]["default"]["template"]
            chosen_action = DOMAIN_TEMPLATES["module"]["default"]["action"]
            adjustments.append(("verb_module_fallback", +2))
        else:
            # final fallback generic foreign
            chosen_template = DOMAIN_TEMPLATES[None]["default"]["template"]
            chosen_action = DOMAIN_TEMPLATES[None]["default"]["action"]
            adjustments.append(("final_fallback", 0))

    # apply template generator
    templ_res = chosen_template(params) if callable(chosen_template) else translate_foreign_template(params)
    json_repr = templ_res.get("json_repr") or templ_res.get("json") or templ_res[
        "json_repr"] if "json_repr" in templ_res else templ_res.get("json_repr", {})
    code_c = templ_res.get("code_c")
    code_objc = templ_res.get("code_objc")
    base_conf = templ_res.get("confidence", "low")
    notes = templ_res.get("notes", "")
    # scoring adjustments: if meta indicates original confidence high, boost
    if meta.get("confidence") in ("high", "manual", "verified"):
        adjustments.append(("meta_confidence", +3))
    # if ir string explicitly special-case common functions (GetProcAddress etc) boost
    if ir.lower().endswith("getprocaddress") or "get_symbol" in ir.lower():
        adjustments.append(("getproc_boost", +3))
    # final compute confidence
    confidence = score_confidence(base_conf, adjustments)
    # action_type determined earlier
    result = {
        "target": target,
        "ir": ir,
        "action_type": chosen_action or templ_res.get("json_repr", {}).get("action", "foreign.call"),
        "params": json_repr,
        "code_c": code_c,
        "code_objc": code_objc,
        "json_repr": json_repr,
        "confidence": confidence,
        "notes": notes,
        "meta": meta
    }
    return result


# ----------------------------
# Helper: generate a static handler map for an IR list (auto-generate)
def generate_static_handler_map(ir_list: List[str], out_json: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """
    Given list of IR strings (or keys like 'sys.file.create'), produce mapping:
      ir -> { action_type, default_params, suggested_code_snippet, confidence_estimate, auto_generated:True }
    If out_json specified, write mapping to file.
    """
    mapping = {}
    for ir in ir_list:
        dummy_entry = {"ir": ir, "params": {}, "meta": {}}
        tr = map_ir_to_macos(dummy_entry)
        mapping[ir] = {
            "action_type": tr["action_type"],
            "json_repr": tr["json_repr"],
            "code_c": tr["code_c"],
            "code_objc": tr["code_objc"],
            "confidence": tr["confidence"],
            "notes": tr["notes"],
            "auto_generated": True
        }
    if out_json:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(mapping, f, indent=2, ensure_ascii=False)
    return mapping


# ----------------------------
# Example quick test
if __name__ == "__main__":
    examples = [
        {"ir": "sys.file.create", "params": {"path": "C:\\temp\\x.txt", "flags": ["CREATE_ALWAYS", "GENERIC_WRITE"]}},
        {"ir": "ui.dialog.message", "params": {"title": "Hi", "text": "hello"}},
        {"ir": "sys.module.get_symbol", "params": {"symbol_name": "init_plugin"}},
        {"ir": "net.socket.connect", "params": {"host": "127.0.0.1", "port": 80}},
        {"ir": "sys.thread.create", "params": {"start_routine": "worker"}},
        {"ir": "sys.registry.open_key", "params": {"key": "HKEY_CURRENT_USER\\Software\\Foo"}}
    ]
    for e in examples:
        out = map_ir_to_macos(e)
        print("IR:", e["ir"], "=> action:", out["action_type"], "conf:", out["confidence"])
        print("  json_repr:", out["json_repr"])
        if out.get("code_c"):
            print("  code_c snippet:", out["code_c"])
        print("----")
