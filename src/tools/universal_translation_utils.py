import posixpath

# --------------------------------------------------------------------
# Map CreateFile flags (heuristics) -> POSIX open flags
# We can't fully emulate Windows semantics; we make a best-effort mapping.
WIN_ACCESS_TO_POSIX = {
    # heuristics: presence of GENERIC_WRITE => O_WRONLY|O_CREAT
    "GENERIC_READ": "O_RDONLY",
    "GENERIC_WRITE": "O_WRONLY",
    "GENERIC_READ_WRITE": "O_RDWR"
}

WIN_CREATION_TO_POSIX = {
    "CREATE_NEW": ["O_CREAT", "O_EXCL"],
    "CREATE_ALWAYS": ["O_CREAT", "O_TRUNC"],
    "OPEN_EXISTING": [],
    "OPEN_ALWAYS": ["O_CREAT"],
    "TRUNCATE_EXISTING": ["O_TRUNC"]
}


# ---------- Helpers: path & flag normalization ----------
def normalize_windows_path_to_posix(win_path: str) -> str:
    """
    Convert Windows-style path to a POSIX style suggestion for macOS.
    Heuristics:
    - C:\\foo\\bar -> /foo/bar  (drop drive letter)
    - \\server\\share -> /Volumes/server/share  (approximation)
    - backslashes -> slashes
    - ensure UTF-8 string (assume already decoded)
    """
    if not isinstance(win_path, str):
        return win_path
    p = win_path.replace("\\", "/")
    # network UNC
    if p.startswith("//") or p.startswith("\\\\"):
        p = p.lstrip("/\\")
        # place under /Volumes as a pragmatic mapping
        p = "/Volumes/" + p
    # drive letter
    if len(p) >= 2 and p[1] == ":":
        # drop drive letter; keep leading slash for absolute path
        p = p[2:]
        if not p.startswith("/"):
            p = "/" + p
    # collapse repeated slashes
    p = posixpath.normpath(p)
    return p


def clean_dictionary(dictionary: dict[any, any]) -> str:
    """
    Escapes each string in a dictionary for printing
    """
    s = str(dictionary)
    return s.replace('\"', '\\"')


# C code building

# Template wrappers
MAIN_HEADER = r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Used calls declarations
{funcs}

int main(int argc, char **argv) {{
    (void)argc; (void)argv;
    printf("Starting generated binary...\n");
{calls}
    printf("Finished.\n");
    return 0;
}}
"""

C_STUB_WRAPPER = r"""
// ---- auto-generated function: {fn_name} ----
void {fn_name}(void) {{
{body}
}}
"""

OBJC_BRIDGE_HEADER = r"""#ifdef __cplusplus
extern "C" {{
#endif
{decls}
#ifdef __cplusplus
}}
#endif
"""
