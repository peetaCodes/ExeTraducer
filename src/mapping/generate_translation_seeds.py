#!/usr/bin/env python3
# tools/generate_all_winapi_functions_txt.py
"""
Scarica e aggrega liste di funzioni Windows API da più fonti (Wine, Microsoft docs, gist, ReactOS)
e scrive out/all_winapi_functions.txt (una funzione per riga). Produce anche out/all_winapi_functions.sources.json
che mappa ciascuna funzione alle fonti trovate.

Dependencies:
    pip install requests beautifulsoup4

Usage:
    python tools/generate_all_winapi_functions_txt.py --out out/all_winapi_functions.txt --verbose

Notes:
 - The script searches for the most recent source (usually Wine / Microsoft) and prefers the most recent it could find in case of multiple sources.
 - Some pages (es. Microsoft Docs) non espongono facilmente singole funzioni in forma grezza; lo script fa il massimo per estrarre nomi.
 - Se vuoi, puoi disabilitare scraping di Microsoft e ReactOS e fidarti solo di Wine+Gist con le opzioni CLI.
"""

from __future__ import annotations
import requests
from bs4 import BeautifulSoup
import re, json, os, argparse, time
from typing import Dict, Set, List, Tuple
from urllib.parse import urljoin

# --- Config sorgenti ---
WINE_ROOT = "https://source.winehq.org/WineAPI/"
GIST_RAW = "https://gist.githubusercontent.com/ssell/19cf1f96ac84be7f15545e6a0da5d741/raw/544ed6dc4d667926ceb6afe74fd9ab2ccc6f64ee/gistfile1.txt"
MS_API_INDEX = "https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list"

HEADERS = {"User-Agent": "WinAPI-Aggregator/1.0 (+https://github.com/your-repo)"}


def fetch_url(url: str, timeout=20) -> Tuple[int, str]:
    r = requests.get(url, headers=HEADERS, timeout=timeout)
    r.raise_for_status()
    return r.status_code, r.text


# ---------- Extraction helpers ----------
def extract_from_gist(gist_raw_url: str, verbose=False) -> Dict[str, Set[str]]:
    """
    Download raw gist file and parse one function name per token.
    Return mapping func_key -> {source_info}
    """
    out = {}
    try:
        _, txt = fetch_url(gist_raw_url)
        lines = txt.splitlines()
        for ln in lines:
            s = ln.strip()
            if not s:
                continue
            # remove comments in-line
            if s.startswith("#") or s.startswith("//"):
                continue
            # token may have multiple names separated by spaces
            tokens = re.split(r'[\s,;]+', s)
            for t in tokens:
                t = t.strip()
                if not t: continue
                # filter weird tokens
                if len(t) < 2: continue
                key = t
                out.setdefault(key, set()).add("gist(ssell)")
    except Exception as e:
        if verbose: print("Gist fetch failed:", e)
    return out


def parse_wine_dll_page(html: str) -> List[str]:
    """Extract candidate function names from a Wine dll page. Very permissive."""
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ", strip=True)
    # find function-like tokens (letters, digits, underscore, optionally ending with A/W)
    candidates = set()
    # Look for 'EXPORTS' block - but fallback to global text search
    for m in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]{1,100}(?:A|W)?)\b', text):
        name = m.group(1)
        # crude heuristics to avoid common words: names usually have mixed case or end with typical windows suffix
        if len(name) < 3:
            continue
        # exclude all-uppercase short tokens that are unlikely function names (e.g., HTTP)
        candidates.add(name)
    # Return sorted
    return sorted(candidates)


def extract_from_wine_root(root_url: str, verbose=False) -> Dict[str, Set[str]]:
    """
    1) fetch root page that lists DLLs
    2) for each dll, fetch dll page and parse function tokens
    returns map func -> set(sources like 'wine:kernel32')
    """
    results = {}
    try:
        _, html = fetch_url(root_url)
    except Exception as e:
        if verbose: print("Wine root fetch fail:", e)
        return results
    soup = BeautifulSoup(html, "html.parser")
    # collect dll links - anchors with href that look like 'kernel32'
    dll_links = []
    for a in soup.find_all("a", href=True):
        href = a['href']
        text = a.get_text(strip=True)
        # heuristic: many dll anchors are short and lowercase; filter some noise
        if href and not href.startswith("http") and len(text) > 1 and len(text) < 64:
            # create absolute URL
            url = urljoin(root_url, href)
            dll_links.append((text, url))
    # dedupe keep unique by lower name
    seen = set();
    cleaned = []
    for name, url in dll_links:
        key = name.lower()
        if key in seen: continue
        seen.add(key)
        cleaned.append((name, url))
    if verbose: print(f"[wine] Found {len(cleaned)} dll candidates.")
    # iterate dlls (be polite)
    for name, url in cleaned:
        try:
            if verbose: print("  fetching", name, url)
            _, page = fetch_url(url)
            funcs = parse_wine_dll_page(page)
            # heuristics: functions near 'EXPORTS' often capitalized - try to reduce noise by filtering short lowercase words
            for fn in funcs:
                # skip obvious non-function words
                if fn.lower() in ("the", "and", "exports", "forward", "stub"): continue
                # accept typical names: contain letters and at least one lower->upper or end with A/W or contain 'Get'/'Create' etc
                if re.search(
                        r'(create|get|set|find|open|close|read|write|load|free|delete|enum|register|connect|send|recv|socket|message|process|thread)',
                        fn, re.I) or fn.endswith("A") or fn.endswith("W") or re.search(r'[A-Z][a-z]', fn):
                    key = fn
                    results.setdefault(key, set()).add(f"wine:{name}")
        except Exception as e:
            if verbose: print("   failed", name, e)
            continue
    return results


def extract_from_microsoft_index(ms_index_url: str, verbose=False) -> Dict[str, Set[str]]:
    """
    Try to extract function names from MS API index page.
    This page is category-based, not a flat function dump; we try to find links that look like function references.
    This is best-effort.
    """
    out = {}
    try:
        _, html = fetch_url(ms_index_url)
        soup = BeautifulSoup(html, "html.parser")
    except Exception as e:
        if verbose: print("MS docs fetch failed:", e); return out
    text = soup.get_text(" ", strip=True)
    # look for tokens resembling function names in the content
    for m in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]{2,100}(?:A|W)?)\b', text):
        fn = m.group(1)
        if len(fn) > 2 and re.search(
                r'(create|get|set|find|open|close|read|write|load|free|delete|enum|register|connect|send|recv|socket|message|process|thread)',
                fn, re.I):
            out.setdefault(fn, set()).add("microsoft:apiindex")
    return out


def extract_from_reactos_exports(verbose=False) -> Dict[str, Set[str]]:
    """
    Use ReactOS wiki pages (or do nothing if offline). Best-effort simple fetch from an index page.
    """
    out = {}
    try:
        _, html = fetch_url("https://reactos.org/wiki/Techwiki%3AWin32k/exports")
        soup = BeautifulSoup(html, "html.parser")
        text = soup.get_text(" ", strip=True)
        for m in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]{2,100}(?:A|W)?)\b', text):
            fn = m.group(1)
            if len(fn) > 2:
                out.setdefault(fn, set()).add("reactos:win32k_exports")
    except Exception as e:
        if verbose: print("ReactOS fetch failed:", e)
    return out


# ---------- Merge / normalize ----------
def normalize_name(raw: str) -> str:
    s = raw.strip()
    # remove trailing commas/parentheses etc
    s = re.sub(r'[\(\),;]+$', '', s)
    # keep case as-is but strip weird invisible chars
    s = "".join(ch for ch in s if ord(ch) >= 32)
    return s


def build_aggregated_list(sources_map: List[Dict[str, set]], prefer_sources: List[str] = None, verbose=False) -> Tuple[
    List[str], Dict[str, List[str]]]:
    """
    sources_map: list of dict mapping func->set(sources)
    prefer_sources: list of source substrings in priority order (e.g. ["microsoft","wine","reactos","gist"])
    Returns sorted list of unique normalized names and a map func->list(sources)
    """
    merged: Dict[str, Set[str]] = {}
    for sm in sources_map:
        for fn, sset in sm.items():
            name = normalize_name(fn)
            if not name: continue
            merged.setdefault(name, set()).update(sset)

    # Prefer deterministic ordering: functions in canonical form "DLL!Func" if found - but many entries are bare names
    funcs = sorted(merged.keys(), key=lambda s: s.lower())
    # produce sources list
    sources_out = {f: sorted(list(merged[f])) for f in funcs}
    return funcs, sources_out


# ---------- Main CLI ----------
def main():
    parser = argparse.ArgumentParser(
        description="Aggregate WinAPI function names from multiple online sources and produce a single .txt (one function per line).")
    parser.add_argument("--out", "-o", default="./mapping/all_winapi_functions.txt")
    parser.add_argument("--sources-json", default="out/all_winapi_functions.sources.json")
    parser.add_argument("--no-microsoft", action="store_true",
                        help="Disable Microsoft Docs fetch (slower/unreliable scraping).")
    parser.add_argument("--no-reactos", action="store_true", help="Disable ReactOS fetch.")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    aggregated_sources = []

    if args.verbose: print("Fetching gist list...")
    gist_map = extract_from_gist(GIST_RAW, verbose=args.verbose)
    aggregated_sources.append(gist_map)

    if args.verbose: print("Fetching Wine API index and per-DLL pages... (this can be a bit slow)")
    wine_map = extract_from_wine_root(WINE_ROOT, verbose=args.verbose)
    aggregated_sources.append(wine_map)

    if not args.no_microsoft:
        if args.verbose: print("Scanning Microsoft API index (best-effort)...")
        ms_map = extract_from_microsoft_index(MS_API_INDEX, verbose=args.verbose)
        aggregated_sources.append(ms_map)

    if not args.no_reactos:
        if args.verbose: print("Fetching ReactOS exports (best-effort)...")
        ro_map = extract_from_reactos_exports(verbose=args.verbose)
        aggregated_sources.append(ro_map)

    # Merge and dedupe
    funcs, sources = build_aggregated_list(aggregated_sources, verbose=args.verbose)

    # Write output file: one function per line + optional source info as comment JSON (simple)
    with open(args.out, "w", encoding="utf-8") as f:
        for fn in funcs:
            f.write(fn + "\n")

    with open(args.sources_json, "w", encoding="utf-8") as f:
        json.dump({"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "count": len(funcs),
                   "sources": sources}, f, indent=2, ensure_ascii=False)

    print(f"Wrote {len(funcs)} functions to {args.out}")
    print(f"Wrote sources metadata to {args.sources_json}")


if __name__ == "__main__":
    main()
