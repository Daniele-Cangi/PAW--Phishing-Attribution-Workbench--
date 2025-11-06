#!/usr/bin/env python3
"""
Offline static mapper for phishing kit artifacts in a PAW case directory.

Scans only local files, no network calls.

Sources:
- <case>/detonation/phishing_kit/**/* (HTML/JS/CSS/images)
- <case>/deobfuscation_results.json (if present)
- <case>/input.eml (for URLs/emails)

Outputs (under <case>/derived):
- indicators_from_kit.csv: type,value,file,context
- kit_graph.json: minimal graph of file->url/ip/email relationships
- kit_graph.mmd: Mermaid diagram of relationships (file -> indicator nodes)

Usage:
  python PAW/util/kit_static_mapper.py cases/<case-id>
"""
from __future__ import annotations
import argparse
import base64
import csv
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote


URL_RE = re.compile(r"https?://[\w\-._~%:/?#\[\]@!$&'()*+,;=]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,24}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}")
BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


def safe_read_text(p: Path, max_bytes: int = 1024 * 1024) -> str:
    try:
        data = p.read_bytes()[:max_bytes]
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def b64_candidates(text: str) -> list[str]:
    cands = []
    for m in BASE64_RE.finditer(text):
        s = m.group(0)
        # Heuristic: length multiple of 4 and decodes to mostly printable
        if len(s) % 4 != 0:
            continue
        try:
            raw = base64.b64decode(s, validate=False)
            if not raw:
                continue
            ascii_ratio = sum(32 <= b < 127 or b in (9, 10, 13) for b in raw) / len(raw)
            if ascii_ratio >= 0.85:
                cands.append(raw.decode("utf-8", errors="replace"))
        except Exception:
            continue
    return cands


def extract_indicators(text: str) -> dict[str, set[str]]:
    inds: dict[str, set[str]] = {
        "url": set(),
        "domain": set(),
        "ip": set(),
        "email": set(),
    }
    for u in URL_RE.findall(text):
        inds["url"].add(unquote(u))
    for d in DOMAIN_RE.findall(text):
        # Heuristics to reduce code-token noise: must be lowercase and not end with a dot
        if d.endswith("."):
            continue
        if d.lower() != d:
            continue
        inds["domain"].add(d)
    for ip in IP_RE.findall(text):
        # filter out obviously invalid octets >255
        try:
            if all(0 <= int(o) <= 255 for o in ip.split(".")):
                inds["ip"].add(ip)
        except Exception:
            pass
    for em in EMAIL_RE.findall(text):
        inds["email"].add(em)
    return inds


def scan_case(case_dir: Path) -> tuple[list[dict], dict]:
    kit_dir = case_dir / "detonation" / "phishing_kit"
    results: list[dict] = []
    graph = {"nodes": {}, "edges": []}  # nodes: id->{label,type}

    def add_node(node_id: str, label: str, ntype: str):
        graph["nodes"].setdefault(node_id, {"label": label, "type": ntype})

    def add_edge(src: str, dst: str, etype: str):
        graph["edges"].append({"from": src, "to": dst, "type": etype})

    # Scan kit files
    if kit_dir.exists():
        for p in kit_dir.rglob("*"):
            if not p.is_file():
                continue
            rel = str(p.relative_to(case_dir))
            text = safe_read_text(p)
            if not text:
                continue
            inds = extract_indicators(text)
            decoded_texts = b64_candidates(text)
            for dt in decoded_texts:
                di = extract_indicators(dt)
                for k, vs in di.items():
                    inds[k].update(vs)

            # record indicators
            if any(inds.values()):
                add_node(rel, rel, "file")
            for typ, vals in inds.items():
                for v in sorted(vals):
                    results.append({"type": typ, "value": v, "file": rel, "context": "kit"})
                    node_id = f"{typ}:{v}"
                    add_node(node_id, v, typ)
                    add_edge(rel, node_id, "mentions")

    # input.eml
    eml = case_dir / "input.eml"
    if eml.exists():
        text = safe_read_text(eml)
        inds = extract_indicators(text)
        if any(inds.values()):
            rel = str(eml.relative_to(case_dir))
            add_node(rel, rel, "file")
            for typ, vals in inds.items():
                for v in sorted(vals):
                    results.append({"type": typ, "value": v, "file": rel, "context": "eml"})
                    node_id = f"{typ}:{v}"
                    add_node(node_id, v, typ)
                    add_edge(rel, node_id, "mentions")

    # deobfuscation_results.json
    deob = case_dir / "deobfuscation_results.json"
    if deob.exists():
        try:
            data = json.loads(safe_read_text(deob))
            blob = json.dumps(data)
            inds = extract_indicators(blob)
            rel = str(deob.relative_to(case_dir))
            if any(inds.values()):
                add_node(rel, rel, "file")
                for typ, vals in inds.items():
                    for v in sorted(vals):
                        results.append({"type": typ, "value": v, "file": rel, "context": "deob"})
                        node_id = f"{typ}:{v}"
                        add_node(node_id, v, typ)
                        add_edge(rel, node_id, "mentions")
        except Exception:
            pass

    return results, graph


def write_outputs(case_dir: Path, indicators: list[dict], graph: dict):
    out_dir = case_dir / "derived"
    out_dir.mkdir(parents=True, exist_ok=True)

    # CSV
    csv_path = out_dir / "indicators_from_kit.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["type", "value", "file", "context"])
        w.writeheader()
        for row in indicators:
            w.writerow(row)

    # Graph JSON
    (out_dir / "kit_graph.json").write_text(json.dumps(graph, indent=2), encoding="utf-8")

    # Mermaid
    mmd_lines = ["graph LR"]
    # nodes
    for node_id, meta in graph.get("nodes", {}).items():
        label = meta.get("label", node_id).replace("\"", "'")
        # sanitize node id for mermaid
        nid = re.sub(r"[^a-zA-Z0-9_]", "_", node_id)[:120]
        mmd_lines.append(f"  {nid}[\"{label}\"]")
        meta["_nid"] = nid
    # edges
    for e in graph.get("edges", []):
        s = graph["nodes"].get(e["from"], {}).get("_nid")
        t = graph["nodes"].get(e["to"], {}).get("_nid")
        if s and t:
            mmd_lines.append(f"  {s} --> {t}")
    (out_dir / "kit_graph.mmd").write_text("\n".join(mmd_lines) + "\n", encoding="utf-8")

    print(str(csv_path))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("case_dir", type=Path)
    args = ap.parse_args(argv)

    case_dir: Path = args.case_dir
    if not case_dir.exists():
        print(f"[!] Case not found: {case_dir}", file=sys.stderr)
        return 2

    indicators, graph = scan_case(case_dir)
    write_outputs(case_dir, indicators, graph)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
