# callmap/builder.py
from __future__ import annotations
import json
from typing import Dict, List, Any, Tuple, Set

class CallMap:
    def __init__(self, metadata: Dict[str, Any]):
        self.metadata = metadata
        self.threads: Dict[str, List[Dict[str, Any]]] = {}
        self.by_function: Dict[str, List[Tuple[str, str]]] = {}  # key -> [(tid, call_id)]
        self.adj: Dict[str, Set[str]] = {}  # call_id -> set(child_call_id)

    def add_thread_calls(self, tid: str, calls: List[Dict[str, Any]]):
        self.threads[tid] = calls
        for c in calls:
            key = f"{c['module'].upper()}!{c['function']}"
            self.by_function.setdefault(key, []).append((tid, c["id"]))
            self.adj.setdefault(c["id"], set())
            # children non sono presenti nel compact, quindi deriviamo l’ordine sequenziale
            # L’ordine sequenziale è utile per pattern mining basato su Markov/grammi
        # Crea archi sequenziali (ordine temporale) per thread:
        for i in range(len(calls)-1):
            a = calls[i]["id"]
            b = calls[i+1]["id"]
            self.adj.setdefault(a, set()).add(b)

    def hot_functions(self, top_n: int = 50) -> List[Tuple[str, int]]:
        items = [(k, len(v)) for k, v in self.by_function.items()]
        items.sort(key=lambda kv: kv[1], reverse=True)
        return items[:top_n]

    def to_json(self) -> Dict[str, Any]:
        return {
            "metadata": self.metadata,
            "threads": {tid: [c["id"] for c in calls] for tid, calls in self.threads.items()},
            "by_function": {k: v for k, v in self.by_function.items()},
            "graph": {k: sorted(list(v)) for k, v in self.adj.items()},
        }


def build_callmap_from_compact(compact_json_path: str) -> CallMap:
    with open(compact_json_path, "r") as f:
        data = json.load(f)

    cm = CallMap(metadata=data.get("metadata", {}))
    for th in data.get("threads", []):
        tid = th["tid"]
        calls = th["calls"]
        cm.add_thread_calls(tid, calls)

    return cm


def save_callmap(cm: CallMap, out_path: str):
    with open(out_path, "w") as f:
        json.dump(cm.to_json(), f, indent=2)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Costruisce una callmap da una compact trace")
    ap.add_argument("compact_trace", help="compact_trace.json")
    ap.add_argument("--out", default="reports/callmaps/callmap.json", help="Output JSON callmap")
    args = ap.parse_args()

    cm = build_callmap_from_compact(args.compact_trace)
    save_callmap(cm, args.out)
    print(f"[+] Callmap salvata in {args.out}")
