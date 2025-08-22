#!/usr/bin/env python3
"""
For debugging purposes only. Never used as part of the pipeline
"""
import json
from pathlib import Path
from collections import Counter
import sys


def load_callmap(path):
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if isinstance(data, dict) and 'callmap' in data:
        data = data['callmap']
    if not isinstance(data, list):
        raise RuntimeError("callmap must be a list")
    return data


def canonical_json(obj):
    try:
        return json.dumps(obj, sort_keys=True, ensure_ascii=False)
    except Exception:
        return str(obj)


def diagnose(path):
    callmap = load_callmap(path)
    print("Entries:", len(callmap))
    jslist = []
    ids = []
    for i, e in enumerate(callmap):
        jr = e.get('json_repr') or e.get('params') or e.get('action_type') or {}
        js = canonical_json(jr)
        jslist.append(js)
        # also collect id() to see if same object is reused
        ids.append(id(jr))

    cnt = Counter(jslist)
    idcnt = Counter(ids)
    print("Unique json_repr strings:", len(cnt))
    print("Top 10 most common json_repr values:")
    for j, c in cnt.most_common(10):
        print(f"  count={c}  example: {j[:200]}")
    # show how many distinct object identities
    print("Distinct json_repr object identities:", len(idcnt))
    print("Top 5 object ids counts:")
    for oid, c in idcnt.most_common(5):
        print(f"  id={oid} count={c}")
    # Show samples where json_repr is the most frequent
    if cnt:
        most_common_js = cnt.most_common(1)[0][0]
        print("\nShowing up to 5 sample entries that have the most common json_repr:")
        shown = 0
        for i, e in enumerate(callmap):
            jr = e.get('json_repr') or e.get('params') or e.get('action_type') or {}
            if canonical_json(jr) == most_common_js:
                print("INDEX:", i, "IR:", e.get('ir'), "DLL/FUNC:", e.get('dll'), e.get('func'), "CONF:",
                      e.get('confidence'))
                print("  json_repr:", jr)
                shown += 1
                if shown >= 5:
                    break


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: diagnose_callmap.py path/to/callmap.json")
        sys.exit(2)
    diagnose(sys.argv[1])
