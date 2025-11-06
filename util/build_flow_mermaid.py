#!/usr/bin/env python3
"""
Build a Mermaid domain flow graph from requests.jsonl using only local data.

Creates <case>/derived/flow.mmd showing edges RefererHost --> TargetHost with counts.

Usage:
  python PAW/util/build_flow_mermaid.py cases/<case-id>
"""
from __future__ import annotations
import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse


def load_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def host_of(url: str | None) -> str | None:
    if not url:
        return None
    try:
        m = urlparse(url)
        host = (m.netloc or "").split("@").pop().split(":")[0]
        return host or None
    except Exception:
        return None


def build(case_dir: Path) -> str:
    req_path = case_dir / "detonation" / "requests.jsonl"
    edges = defaultdict(int)
    nodes = set()

    for ev in load_jsonl(req_path):
        url = ev.get("url")
        thost = host_of(url)
        if not thost:
            continue
        hdrs = ev.get("headers") or {}
        ref = None
        if isinstance(hdrs, dict):
            ref = hdrs.get("referer") or hdrs.get("Referer")
        rhost = host_of(ref) or "(no-ref)"
        edges[(rhost, thost)] += 1
        nodes.add(rhost)
        nodes.add(thost)

    # write Mermaid
    out_dir = case_dir / "derived"
    out_dir.mkdir(parents=True, exist_ok=True)
    mmd_path = out_dir / "flow.mmd"
    lines = ["graph LR"]
    nid_map = {}
    for n in sorted(nodes):
        nid = re.sub(r"[^a-zA-Z0-9_]", "_", n)[:120]
        nid_map[n] = nid
        label = n.replace("\"", "'")
        lines.append(f"  {nid}[\"{label}\"]")
    for (a, b), cnt in sorted(edges.items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"  {nid_map[a]} -- {cnt} --> {nid_map[b]}")
    mmd_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(mmd_path)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("case_dir", type=Path)
    args = ap.parse_args(argv)
    case_dir: Path = args.case_dir
    if not case_dir.exists():
        print(f"[!] Case not found: {case_dir}")
        return 2
    out = build(case_dir)
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
