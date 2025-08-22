from typing import Dict, Any
import shlex

from src.tools.universal_translation_utils import normalize_windows_path_to_posix

# ----------------------------
# Domain templates: algorithmic generation rules
# Each domain maps verbs to "action_types" and template generators that produce json_repr + code snippets.
# Use conservative default templates; they can be customized/extended.
DOMAIN_TEMPLATES = {
    # file operations map to open/read/write/close/lseek etc.
    "file": {
        "create": {
            "action": "posix_open",
            "template": lambda params: translate_file_open_template(params)
        },
        "open": {
            "action": "posix_open",
            "template": lambda params: translate_file_open_template(params)
        },
        "read": {
            "action": "posix_read",
            "template": lambda params: translate_file_read_template(params)
        },
        "write": {
            "action": "posix_write",
            "template": lambda params: translate_file_write_template(params)
        },
        "delete": {
            "action": "posix_unlink",
            "template": lambda params: translate_file_unlink_template(params)
        },
        "operate": {
            "action": "posix_open",
            "template": lambda params: translate_file_open_template(params)
        },
        "default": {
            "action": "posix_open",
            "template": lambda params: translate_file_open_template(params)
        }
    },
    # module loading / symbol lookup
    "module": {
        "load": {"action": "dlopen", "template": lambda p: translate_module_load_template(p)},
        "get_symbol": {"action": "dlsym", "template": lambda p: translate_module_get_symbol_template(p)},
        "default": {"action": "dlopen", "template": lambda p: translate_module_load_template(p)}
    },
    # processes
    "process": {
        "create": {"action": "posix_spawn", "template": lambda p: translate_process_create_template(p)},
        "terminate": {"action": "kill", "template": lambda p: translate_process_kill_template(p)},
        "get_pid": {"action": "getpid", "template": lambda p: translate_simple_action("getpid", p)}
    },
    # threads
    "thread": {
        "create": {"action": "pthread_create", "template": lambda p: translate_thread_create_template(p)},
        "get_tid": {"action": "pthread_self", "template": lambda p: translate_simple_action("pthread_self", p)}
    },
    # memory
    "memory": {
        "allocate": {"action": "mmap/posix", "template": lambda p: translate_memory_alloc_template(p)},
        "free": {"action": "munmap/posix", "template": lambda p: translate_memory_free_template(p)}
    },
    # networking
    "net": {
        "connect": {"action": "socket_connect", "template": lambda p: translate_net_connect_template(p)},
        "send": {"action": "socket_send", "template": lambda p: translate_net_send_template(p)},
        "recv": {"action": "socket_recv", "template": lambda p: translate_net_recv_template(p)},
        "default": {"action": "socket", "template": lambda p: translate_net_default_template(p)}
    },
    # UI
    "ui": {
        "message": {"action": "osascript_dialog", "template": lambda p: translate_ui_message_template(p)},
        "dialog": {"action": "osascript_dialog", "template": lambda p: translate_ui_message_template(p)},
        "window": {"action": "nswindow", "template": lambda p: translate_ui_window_template(p)},
        "default": {"action": "ui_generic", "template": lambda p: translate_ui_generic_template(p)}
    },
    # registry
    "registry": {
        "open_key": {"action": "cfpreferences_open", "template": lambda p: translate_registry_template(p)},
        "set_value": {"action": "cfpreferences_set", "template": lambda p: translate_registry_template(p)},
        "query_value": {"action": "cfpreferences_get", "template": lambda p: translate_registry_template(p)},
        "default": {"action": "cfpreferences", "template": lambda p: translate_registry_template(p)}
    },
    # sync
    "sync": {
        "create": {"action": "pthread_mutex", "template": lambda p: translate_sync_mutex_template(p)},
        "wait": {"action": "pthread_wait", "template": lambda p: translate_sync_wait_template(p)},
        "default": {"action": "sync_generic", "template": lambda p: translate_sync_generic_template(p)}
    },
    # fallback domain
    None: {
        "default": {"action": "foreign.call", "template": lambda p: translate_foreign_template(p)}
    }
}


# ----------------------------
# Translation utilities
def safe_quote(s):
    return shlex.quote(str(s)) if s is not None else "''"


# ----------------------------
# Low-level template implementations
# Each returns a dict: (json_repr, code_c (opt), code_objc (opt), confidence, notes)

def translate_file_open_template(params: Dict[str, Any]) -> Dict[str, Any]:
    # expects params: path, flags (symbolic list), mode
    path = params.get("path") or (params.get("orig_args", [None])[0] if params.get("orig_args") else None)
    path_posix = normalize_windows_path_to_posix(path)
    # flags may be symbolic from earlier pipeline
    flags = params.get("flags") or params.get("posix_flags") or []
    # best-effort mapping
    posix_flags = []
    for f in flags:
        if isinstance(f, str):
            # map GENERIC -> O_ heuristics
            if f.upper().startswith("GENERIC"):
                if "READ" in f.upper():
                    posix_flags.append("O_RDONLY")
                elif "WRITE" in f.upper():
                    posix_flags.append("O_WRONLY")
                else:
                    posix_flags.append("O_RDWR")
            elif f.upper().startswith("O_"):
                posix_flags.append(f.upper())
            else:
                # treat common creation names
                if f.upper() in ("CREATE_NEW", "CREATE_ALWAYS", "OPEN_ALWAYS"):
                    posix_flags.append("O_CREAT")
        # numeric fallback: include numeric expression
    if not posix_flags:
        posix_flags = ["O_RDONLY"]
    flags_expr = "|".join(posix_flags)
    mode = params.get("mode", "0644")
    try:
        mode_int = int(str(mode), 8) if isinstance(mode, (str, int)) else 0o644
    except Exception:
        mode_int = 0o644
    code_c = f'int fd = open("{path_posix or "/tmp/unknown"}", {flags_expr}, {oct(mode_int)});\n'
    json_repr = {"action": "posix_open", "path": path_posix, "posix_flags": posix_flags, "mode": oct(mode_int)}
    confidence = "high" if path_posix else "low"
    notes = "Algorithmic: map sys.file.* -> open(2)/read/write/close templates"
    return {"json_repr": json_repr, "code_c": code_c, "code_objc": None, "confidence": confidence, "notes": notes}


def translate_file_read_template(params: Dict[str, Any]) -> Dict[str, Any]:
    # simple read wrapper using fd or handle
    fd = params.get("fd") or params.get("handle") or "<fd>"
    size = params.get("size") or 1024
    code_c = f'char buf[{size}]; ssize_t r = read({fd}, buf, {size});\n'
    json_repr = {"action": "posix_read", "fd": fd, "size": size}
    return {"json_repr": json_repr, "code_c": code_c, "code_objc": None, "confidence": "medium",
            "notes": "map read -> read(2)"}


def translate_file_write_template(params: Dict[str, Any]) -> Dict[str, Any]:
    fd = params.get("fd") or params.get("handle") or "<fd>"
    data = params.get("data") or "<data>"
    code_c = f'ssize_t w = write({fd}, /*{data}*/ NULL, /*len*/ 0);\n'
    json_repr = {"action": "posix_write", "fd": fd}
    return {"json_repr": json_repr, "code_c": code_c, "code_objc": None, "confidence": "medium",
            "notes": "map write -> write(2)"}


def translate_file_unlink_template(params: Dict[str, Any]) -> Dict[str, Any]:
    path = params.get("path") or "<path>"
    code_c = f'unlink("{path}");\n'
    json_repr = {"action": "posix_unlink", "path": path}
    return {"json_repr": json_repr, "code_c": code_c, "code_objc": None, "confidence": "medium",
            "notes": "map delete -> unlink(2)"}


def translate_module_load_template(params: Dict[str, Any]) -> Dict[str, Any]:
    name = params.get("module_name") or params.get("path") or "<module>"
    code_c = f'void *h = dlopen("{name}", RTLD_LAZY);\n'
    json_repr = {"action": "dlopen", "module_name": name}
    return {"json_repr": json_repr, "code_c": code_c, "code_objc": None, "confidence": "medium",
            "notes": "dlopen as a shim (module name mapping may be manual)"}


def translate_module_get_symbol_template(params: Dict[str, Any]) -> Dict[str, Any]:
    sym = params.get("symbol_name") or (params.get("args") and params["args"][-1]) or "<sym>"
    code_c = f'void *sym = dlsym(handle, "{sym}");\n'
    json_repr = {"action": "dlsym", "symbol": sym}
    return {"json_repr": json_repr, "code_c": code_c, "code_objc": None,
            "confidence": "high" if sym != "<sym>" else "low", "notes": "dlsym mapping"}


def translate_thread_create_template(params: Dict[str, Any]) -> Dict[str, Any]:
    start = params.get("start_routine") or params.get("func") or "thread_func"
    code_c = f'pthread_t t; pthread_create(&t, NULL, (void*(*)(void*)){start}, NULL);\n'
    json_repr = {"action": "pthread_create", "start_routine": start}
    return {"json_repr": json_repr, "code_c": code_c, "code_objc": None, "confidence": "medium",
            "notes": "pthread_create used as shim"}


def translate_process_create_template(params: Dict[str, Any]) -> Dict[str, Any]:
    cmd = params.get("cmdline") or params.get("command") or params.get("argv")
    json_repr = {"action": "posix_spawn", "cmdline": cmd}
    code_c = "// posix_spawn/fork-exec wrapper required (cmdline building omitted)\n"
    return {"json_repr": json_repr, "code_c": code_c, "code_objc": None, "confidence": "low" if not cmd else "medium",
            "notes": "posix_spawn mapping"}


def translate_memory_alloc_template(params: Dict[str, Any]) -> Dict[str, Any]:
    size = params.get("size") or 4096
    code_c = f'void *p = mmap(NULL, {size}, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);\n'
    json_repr = {"action": "mmap", "size": size}
    return {"json_repr": json_repr, "code_c": code_c, "code_objc": None, "confidence": "medium",
            "notes": "map memory allocation to mmap"}


def translate_memory_free_template(params: Dict[str, Any]) -> Dict[str, Any]:
    addr = params.get("addr") or "p"
    size = params.get("size") or 4096
    code_c = f'munmap({addr}, {size});\n'
    json_repr = {"action": "munmap", "addr": addr, "size": size}
    return {"json_repr": json_repr, "code_c": code_c, "code_objc": None, "confidence": "medium",
            "notes": "munmap mapping"}


def translate_net_connect_template(params: Dict[str, Any]) -> Dict[str, Any]:
    host = params.get("host") or params.get("addr") or "127.0.0.1"
    port = params.get("port") or params.get("service") or 0
    code_c = "// socket connect template (address building omitted)\n"
    json_repr = {"action": "socket_connect", "host": host, "port": port}
    return {"json_repr": json_repr, "code_c": code_c, "code_objc": None, "confidence": "medium",
            "notes": "BSD sockets mapping"}


def translate_net_send_template(params: Dict[str, Any]) -> Dict[str, Any]:
    json_repr = {"action": "socket_send", "fd": params.get("fd", "<fd>")}
    code_c = "/* send(fd, buf, len, 0) */\n"
    return {"json_repr": json_repr, "code_c": code_c, "code_objc": None, "confidence": "medium",
            "notes": "send -> send(2)"}


def translate_net_recv_template(params: Dict[str, Any]) -> Dict[str, Any]:
    json_repr = {"action": "socket_recv", "fd": params.get("fd", "<fd>")}
    code_c = "/* recv(fd, buf, len, 0) */\n"
    return {"json_repr": json_repr, "code_c": code_c, "code_objc": None, "confidence": "medium",
            "notes": "recv -> recv(2)"}


def translate_net_default_template(params: Dict[str, Any]) -> Dict[str, Any]:
    return translate_net_connect_template(params)


def translate_ui_message_template(params: Dict[str, Any]) -> Dict[str, Any]:
    title = params.get("title") or ""
    text = params.get("text") or params.get("message") or (params.get("args") and params["args"][0]) or ""
    applescript = f'display dialog {safe_quote(text)} with title {safe_quote(title)}'
    osacmd = f"osascript -e {safe_quote(applescript)}"
    objc = '#import <Cocoa/Cocoa.h>\n/* NSAlert example omitted */\n'
    json_repr = {"action": "osascript_dialog", "title": title, "text": text, "cmd": osacmd}
    return {"json_repr": json_repr, "code_c": None, "code_objc": objc, "confidence": "high" if text else "low",
            "notes": "UI message -> osascript/NSAlert"}


def translate_ui_window_template(params: Dict[str, Any]) -> Dict[str, Any]:
    json_repr = {"action": "nswindow", "params": params}
    return {"json_repr": json_repr, "code_c": None, "code_objc": None, "confidence": "low",
            "notes": "UI window mapping requires app-level integration"}


def translate_ui_generic_template(params: Dict[str, Any]) -> Dict[str, Any]:
    return {"json_repr": {"action": "ui_generic", "params": params}, "code_c": None, "code_objc": None,
            "confidence": "low", "notes": "generic UI mapping"}


def translate_registry_template(params: Dict[str, Any]) -> Dict[str, Any]:
    json_repr = {"action": "cfpreferences_op", "params": params}
    code_c = None
    return {"json_repr": json_repr, "code_c": code_c, "code_objc": None, "confidence": "low",
            "notes": "registry -> CFPreferences/plist mapping (heuristic)"}


def translate_sync_mutex_template(params: Dict[str, Any]) -> Dict[str, Any]:
    json_repr = {"action": "pthread_mutex_init", "params": params}
    code_c = "pthread_mutex_t m; pthread_mutex_init(&m, NULL);\n"
    return {"json_repr": json_repr, "code_c": code_c, "code_objc": None, "confidence": "medium",
            "notes": "mutex -> pthread_mutex"}


def translate_sync_wait_template(params: Dict[str, Any]) -> Dict[str, Any]:
    json_repr = {"action": "pthread_cond_wait", "params": params}
    code_c = "// pthread cond wait template\n"
    return {"json_repr": json_repr, "code_c": code_c, "code_objc": None, "confidence": "low",
            "notes": "condition/wait mapping"}


def translate_sync_generic_template(params: Dict[str, Any]) -> Dict[str, Any]:
    return {"json_repr": {"action": "sync_generic", "params": params}, "code_c": None, "code_objc": None,
            "confidence": "low", "notes": "generic sync"}


def translate_simple_action(name: str, params: Dict[str, Any]) -> Dict[str, Any]:
    return {"json_repr": {"action": name, "params": params}, "code_c": None, "code_objc": None, "confidence": "high",
            "notes": "simple action"}


def translate_foreign_template(params: Dict[str, Any]) -> Dict[str, Any]:
    return {"json_repr": {"action": "foreign.call", "params": params}, "code_c": None, "code_objc": None,
            "confidence": "low", "notes": "fallback foreign.call"}


def translate_process_kill_template(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Template per terminare/killare un processo su macOS (Apple Silicon).
    Accetta parametri possibili:
      - pid / process_id (int or numeric string)
      - handle (numeric)  -- fallback: treated as pid if numeric
      - force (bool) -- if True use SIGKILL, otherwise SIGTERM
      - signal (int or str) -- explicit signal to send (e.g., 9 or "SIGKILL")
      - process_name / name / cmd (string) -- fallback to pkill/killall if pid missing
      - wait (bool) -- whether to wait for child termination (default True for pid-based)
    Ritorna dict con:
      - json_repr: struttura canonica
      - code_c: snippet C (uses kill + waitpid when pid available)
      - code_objc: None
      - confidence: high/medium/low
      - notes: spiegazione / avvertenze
    """

    # Normalizza input
    pid = None
    for k in ("pid", "process_id", "pid_int", "handle"):
        if k in params and params[k] is not None:
            try:
                # allow numeric strings
                pid = int(params[k])
                break
            except Exception:
                # not numeric, skip
                pid = None

    force_flag = bool(params.get("force", False))
    sig = params.get("signal", None)
    proc_name = params.get("process_name") or params.get("name") or params.get("cmd")

    # Decide signal to use
    sig_num = None
    sig_name = None
    if sig is not None:
        # accept int or strings like "SIGKILL" or "9"
        try:
            sig_num = int(sig)
            sig_name = f"SIG{sig_num}"
        except Exception:
            s = str(sig).upper()
            if s.startswith("SIG"):
                sig_name = s
                # map common signals to numbers conservatively
                if s == "SIGKILL":
                    sig_num = 9
                elif s == "SIGTERM":
                    sig_num = 15
                elif s == "SIGINT":
                    sig_num = 2
                else:
                    sig_num = None
            else:
                # unknown string
                sig_num = None
                sig_name = s

    if sig_num is None:
        # default: SIGKILL if forced else SIGTERM
        if force_flag:
            sig_num = 9
            sig_name = "SIGKILL"
        else:
            sig_num = 15
            sig_name = "SIGTERM"

    # Build json_repr and code snippets
    if pid is not None:
        # High-confidence path: use kill(pid, sig)
        json_repr = {"action": "kill", "pid": pid, "signal": sig_name, "signal_num": sig_num}
        code_c = (
            "#include <signal.h>\n"
            "#include <sys/wait.h>\n"
            "#include <errno.h>\n"
            "#include <stdio.h>\n\n"
            f"int target_pid = {pid};\n"
            f"int rc = kill(target_pid, {sig_num});\n"
            "if (rc != 0) {\n"
            "  perror(\"kill\");\n"
            "  // handle error (EPERM if insufficient privileges, ESRCH if no such process)\n"
            "}\n"
            "/* optionally wait for process termination */\n"
            "int status = 0;\n"
            "pid_t w = waitpid(target_pid, &status, 0);\n"
            "if (w == -1) { perror(\"waitpid\"); }\n"
        )
        confidence = "high"
        notes = ("Used pid -> sending signal via kill(). Requires appropriate privileges; "
                 "SIGKILL (9) forces termination, SIGTERM (15) requests graceful termination.")
    elif proc_name:
        # Medium-confidence path: use pkill / killall heuristics
        # Recommend pkill -f (match full command line) or killall depending on need.
        json_repr = {"action": "kill_by_name", "process_name": proc_name, "signal": sig_name}
        # Use pkill -f "name" as default; warn about collateral kills
        safe_name = proc_name.replace('"', '\\"')
        code_c = (
            f'/* Attempt to kill by name - system() wrapper (less safe). Prefer to resolve PID precisely when possible. */\n'
            f'int rc = system("pkill -f \\"{safe_name}\\"");\n'
            "if (rc == -1) { perror(\"system\"); }\n"
        )
        confidence = "medium"
        notes = ("No pid provided; using pkill/killall by name which may match multiple processes. "
                 "This is less precise and may require elevated privileges. Prefer pid when possible.")
    else:
        # Low-confidence: nothing to act on
        json_repr = {"action": "kill_unknown", "params": params}
        code_c = (
            "/* No pid or process name provided: cannot perform kill. */\n"
            "/* Provide 'pid' or 'process_name' in params. */\n"
        )
        confidence = "low"
        notes = "No pid or process_name found in params; cannot reliably terminate process."

    # Construct return dict (same shape as other translate_*_template functions)
    return {
        "json_repr": json_repr,
        "code_c": code_c,
        "code_objc": None,
        "confidence": confidence,
        "notes": notes
    }
