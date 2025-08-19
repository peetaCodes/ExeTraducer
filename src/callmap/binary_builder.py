#!/usr/bin/env python3
"""
callmap/binary_builder.py

Input:
  - compact_trace.json
  - translation_plan.json

Output (in out/project):
  - trace.script        (line-based simplified trace)
  - replayer.c          (interpreter main)
  - wrappers.c          (implementazioni semplici delle API mappate)
  - CMakeLists.txt
  - (opzionale) build via cmake/make se --build

Nota: il replayer non esegue il codice originale, interpreta la sequenza di chiamate
      e invoca wrapper POSIX/macOS per le API mappate (ReadFile/WriteFile/CreateFile/CloseHandle/LoadLibrary/GetProcAddress).
"""
import os
import json
import argparse
from pathlib import Path
from collections import Counter

# ---------- helpers ----------
def load_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def tally_compact(compact):
    cnt = Counter()
    for th in compact.get("threads", []):
        for c in th.get("calls", []):
            key = f"{c['module'].upper()}!{c['function']}"
            cnt[key] += 1
    return cnt

def check_plan_vs_trace(plan, compact_counts):
    mismatches = []
    for item in plan.get("plan", []):
        key = item["win_api"]
        plan_count = item.get("count", 0)
        trace_count = compact_counts.get(key, 0)
        if plan_count != trace_count:
            mismatches.append((key, plan_count, trace_count))
    return mismatches

# ---------- produce script ----------
def make_trace_script(compact, out_script_path):
    """
    Trace script format (one call per line):
      MODULE!Function|retval|arg0,arg1,arg2,...
    where each arg is 'null' or a decimal integer.
    """
    with open(out_script_path, 'w', encoding='utf-8') as f:
        for th in compact.get("threads", []):
            tid = th.get("tid")
            for c in th.get("calls", []):
                key = f"{c['module'].upper()}!{c['function']}"
                retval = c.get("retval", "")
                if retval is None:
                    retval = ""
                args = []
                for a in c.get("args", []):
                    v = a.get("value")
                    if v is None:
                        args.append("null")
                    else:
                        # store integers (handles/pointers) as decimal
                        args.append(str(v))
                line = f"{key}|{retval}|{','.join(args)}\n"
                f.write(line)

# ---------- generate wrappers.c and replayer.c ----------
WRAPPERS_C = r'''// wrappers.c - minimal wrappers used by the replayer
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

// Simple mapping from win-handle (uint64) -> POSIX fd
typedef unsigned long long win_handle_t;
#define MAX_MAP 65536

struct handle_entry {
    win_handle_t wh;
    int fd;
};

static struct handle_entry handle_map[MAX_MAP];
static int handle_map_count = 0;

static void map_set(win_handle_t wh, int fd) {
    for (int i=0;i<handle_map_count;i++){
        if (handle_map[i].wh == wh) { handle_map[i].fd = fd; return; }
    }
    if (handle_map_count < MAX_MAP) {
        handle_map[handle_map_count].wh = wh;
        handle_map[handle_map_count].fd = fd;
        handle_map_count++;
    }
}
static int map_get(win_handle_t wh) {
    for (int i=0;i<handle_map_count;i++){
        if (handle_map[i].wh == wh) return handle_map[i].fd;
    }
    return -1;
}
static void map_unset(win_handle_t wh){
    for (int i=0;i<handle_map_count;i++){
        if (handle_map[i].wh == wh) {
            // remove by swap
            handle_map[i] = handle_map[handle_map_count-1];
            handle_map_count--;
            return;
        }
    }
}

// Implementazione rudimentale di CreateFile* -> open()
// Per path non fornito nel trace, crea un temp file basato sul handle value.
win_handle_t win_CreateFile_stub(unsigned long long retval_hint) {
    // create a temp file named /tmp/translated_<retval_hint>
    char path[256];
    snprintf(path, sizeof(path), "/tmp/translated_%llu.bin", retval_hint);
    int fd = open(path, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        perror("open");
        return 0;
    }
    map_set((win_handle_t)retval_hint, fd);
    return (win_handle_t)retval_hint;
}

int win_CloseHandle_stub(unsigned long long wh) {
    int fd = map_get((win_handle_t)wh);
    if (fd >= 0) {
        close(fd);
        map_unset((win_handle_t)wh);
        return 1; // success
    }
    return 0; // fail
}

// ReadFile(handle, buf, count, out_read, overlapped)
int win_ReadFile_stub(unsigned long long wh, unsigned long long buf_ptr, unsigned long long count) {
    int fd = map_get((win_handle_t)wh);
    if (fd < 0) return 0;
    // simulate read: read into temp buffer and discard
    size_t toread = (size_t)count;
    // allocate but avoid huge allocations
    size_t chunk = toread;
    if (chunk > 65536) chunk = 65536;
    char *tmp = malloc(chunk);
    if (!tmp) return 0;
    ssize_t total = 0;
    size_t remaining = toread;
    while (remaining) {
        size_t now = (remaining > chunk) ? chunk : remaining;
        ssize_t r = read(fd, tmp, now);
        if (r <= 0) break;
        total += r;
        remaining -= (size_t)r;
    }
    free(tmp);
    // return 1 for success (as Windows returns nonzero true)
    return total > 0 ? 1 : 0;
}

// WriteFile(handle, buf, count, out_written, overlapped)
int win_WriteFile_stub(unsigned long long wh, unsigned long long buf_ptr, unsigned long long count) {
    int fd = map_get((win_handle_t)wh);
    if (fd < 0) return 0;
    // we don't have original buffer contents, so write zero bytes to simulate
    size_t towrite = (size_t)count;
    size_t chunk = towrite;
    if (chunk > 65536) chunk = 65536;
    char *tmp = calloc(1, chunk);
    if (!tmp) return 0;
    ssize_t total = 0;
    size_t remaining = towrite;
    while (remaining) {
        size_t now = (remaining > chunk) ? chunk : remaining;
        ssize_t w = write(fd, tmp, now);
        if (w <= 0) break;
        total += w;
        remaining -= (size_t)w;
    }
    free(tmp);
    return total == (ssize_t)towrite ? 1 : 0;
}

// LoadLibrary -> stub (returns the retval_hint as handle)
unsigned long long win_LoadLibrary_stub(unsigned long long retval_hint) {
    // we don't know the DLL path here; just return the same handle id
    return retval_hint;
}

// GetProcAddress -> stub (returns the retval hint back)
unsigned long long win_GetProcAddress_stub(unsigned long long retval_hint) {
    return retval_hint;
}
'''

REPLAYER_C = r'''// replayer.c - read trace.script and call wrappers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern unsigned long long win_CreateFile_stub(unsigned long long retval_hint);
extern int win_CloseHandle_stub(unsigned long long wh);
extern int win_ReadFile_stub(unsigned long long wh, unsigned long long buf_ptr, unsigned long long count);
extern int win_WriteFile_stub(unsigned long long wh, unsigned long long buf_ptr, unsigned long long count);
extern unsigned long long win_LoadLibrary_stub(unsigned long long retval_hint);
extern unsigned long long win_GetProcAddress_stub(unsigned long long retval_hint);

static void trim_newline(char *s) {
    size_t L = strlen(s);
    while (L>0 && (s[L-1]=='\n' || s[L-1]=='\r')) { s[L-1]=0; L--; }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s trace.script\n", argv[0]);
        return 2;
    }
    const char *tracefile = argv[1];
    FILE *f = fopen(tracefile, "r");
    if (!f) { perror("fopen"); return 3; }

    char *line = NULL;
    size_t len = 0;
    ssize_t readl;
    unsigned long long lineno = 0;
    while ((readl = getline(&line, &len, f)) != -1) {
        lineno++;
        trim_newline(line);
        if (line[0] == 0) continue;
        // format: MODULE!Func|retval|arg0,arg1,...
        char *p1 = strchr(line, '|');
        if (!p1) continue;
        *p1 = 0;
        char *api = line; // MODULE!Func
        char *p2 = p1 + 1;
        char *p3 = strchr(p2, '|');
        char *retval_s = NULL;
        char *args_s = NULL;
        if (p3) {
            *p3 = 0;
            retval_s = p2;
            args_s = p3 + 1;
        } else {
            retval_s = p2;
            args_s = "";
        }
        unsigned long long retval = 0;
        if (retval_s && retval_s[0]) retval = strtoull(retval_s, NULL, 10);

        // parse args
        unsigned long long args[8];
        int nargs = 0;
        if (args_s && args_s[0]) {
            char *tok = strtok(args_s, ",");
            while (tok && nargs < 8) {
                if (strcmp(tok, "null")==0) args[nargs++] = 0;
                else args[nargs++] = strtoull(tok, NULL, 10);
                tok = strtok(NULL, ",");
            }
        }

        // dispatch on api
        if (strcmp(api, "KERNEL32!CreateFileW")==0 || strcmp(api, "KERNEL32!CreateFileA")==0) {
            win_CreateFile_stub(retval);
        } else if (strcmp(api, "KERNEL32!CloseHandle")==0) {
            unsigned long long h = (nargs>0) ? args[0] : retval;
            win_CloseHandle_stub(h);
        } else if (strcmp(api, "KERNEL32!ReadFile")==0) {
            unsigned long long h = (nargs>0) ? args[0] : 0;
            unsigned long long buf = (nargs>1) ? args[1] : 0;
            unsigned long long cnt = (nargs>2) ? args[2] : 0;
            win_ReadFile_stub(h, buf, cnt);
        } else if (strcmp(api, "KERNEL32!WriteFile")==0) {
            unsigned long long h = (nargs>0) ? args[0] : 0;
            unsigned long long buf = (nargs>1) ? args[1] : 0;
            unsigned long long cnt = (nargs>2) ? args[2] : 0;
            win_WriteFile_stub(h, buf, cnt);
        } else if (strcmp(api, "KERNEL32!LoadLibraryA")==0 || strcmp(api, "KERNEL32!LoadLibraryW")==0 || strcmp(api, "KERNEL32!LoadLibraryExW")==0 || strcmp(api, "KERNEL32!LoadLibraryExA")==0) {
            win_LoadLibrary_stub(retval);
        } else if (strcmp(api, "KERNEL32!GetProcAddress")==0) {
            win_GetProcAddress_stub(retval);
        } else {
            // unmapped: just log
            fprintf(stderr, "[replayer] unmapped api %s (line %llu)\\n", api, lineno);
        }
    }

    free(line);
    fclose(f);
    return 0;
}
'''

CMAKETXT = r'''cmake_minimum_required(VERSION 3.15)
project(translated_replayer C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_OSX_ARCHITECTURES "arm64")
set(SOURCES
    replayer.c
    wrappers.c
)

add_executable(translated_replayer ${SOURCES})
target_link_libraries(translated_replayer
    "-framework CoreFoundation"  # if needed for wide-string impl later
)
'''

# ---------- main builder ----------
def build_project(compact_path, plan_path, out_dir, auto_build=False):
    compact = load_json(compact_path)
    plan = load_json(plan_path)

    # verify expected structure
    if "threads" not in compact:
        raise RuntimeError("compact_trace.json missing 'threads' key")
    if "plan" not in plan:
        raise RuntimeError("translation_plan.json missing 'plan' key")

    # tally and compare
    compact_counts = tally_compact(compact)
    mismatches = check_plan_vs_trace(plan, compact_counts)

    Path(out_dir).mkdir(parents=True, exist_ok=True)
    trace_script = Path(out_dir) / "trace.script"
    make_trace_script(compact, trace_script)

    # write source files
    (Path(out_dir) / "wrappers.c").write_text(WRAPPERS_C)
    (Path(out_dir) / "replayer.c").write_text(REPLAYER_C)
    (Path(out_dir) / "CMakeLists.txt").write_text(CMAKETXT)

    # report
    print(f"[+] Project generated in {out_dir}")
    print(f"    - trace script: {trace_script}")
    print("    - sources: replayer.c, wrappers.c, CMakeLists.txt")

    if mismatches:
        print("[!] MISMATCHES between translation_plan counts and compact_trace:")
        for k, pcount, tcount in mismatches:
            print(f"    - {k}: plan={pcount}, trace={tcount}")
    else:
        print("[+] translation_plan counts match compact_trace tallies for listed APIs.")

    if auto_build:
        # try to run cmake & make (only on macOS with cmake available)
        cur = os.getcwd()
        try:
            os.chdir(out_dir)
            print("[*] Running cmake...")
            os.system("cmake .")
            print("[*] Running make...")
            os.system("make -j4")
            print("[+] Build finished (if tools present).")
        finally:
            os.chdir(cur)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build a macOS replayer project from compact_trace + translation_plan")
    parser.add_argument("compact_trace", help="compact_trace.json")
    parser.add_argument("translation_plan", help="translation_plan.json")
    parser.add_argument("--out", default="out/project", help="output project dir")
    parser.add_argument("--build", action="store_true", help="run cmake && make after generation (if available)")
    args = parser.parse_args()

    build_project(args.compact_trace, args.translation_plan, args.out, auto_build=args.build)
