#!/usr/bin/env python3
"""
Analyze trackers and campaign identifiers from requests.jsonl without network.

Parses <case>/detonation/requests.jsonl and extracts:
- Known tracker domains (linkedin, demdex/adobee, doubleclick, demandbase, rlcdn, cookielaw, datadog, tremorhub, rubicon, eyeota, pardot, gtm)
- Campaign/query IDs (utm_*, gclid, fbclid, msclkid, li_fat_id, pid, orgid, tuuid, demdex id, adobeOrg)
- Referer host to build context

Outputs (under <case>/derived):
- trackers.csv: ts,method,status,domain,url,referer_host,tracker_type,ids(json)
- tracker_ids.json: aggregated tracker_id -> occurrences

Usage:
  python PAW/util/analyze_trackers.py cases/<case-id>
"""
from __future__ import annotations
import argparse
import csv
import json
import re
from pathlib import Path
from urllib.parse import urlparse, parse_qs


TRACKER_PATTERNS = [
    (re.compile(r"(^|\.)px\.ads\.linkedin\.com$"), "linkedin"),
    (re.compile(r"(^|\.)snap\.licdn\.com$"), "linkedin"),
    (re.compile(r"(^|\.)demdex\.net$"), "adobe_demdex"),
    (re.compile(r"(^|\.)assets\.adobedtm\.com$"), "adobe_launch"),
    (re.compile(r"(^|\.)doubleclick\.net$|(^|\.)g\.doubleclick\.net$"), "google_doubleclick"),
    (re.compile(r"(^|\.)rlcdn\.com$"), "live_ramp"),
    (re.compile(r"(^|\.)demandbase\.com$|(^|\.)company-target\.com$"), "demandbase"),
    (re.compile(r"(^|\.)cookielaw\.org$|(^|\.)onetrust\.com$"), "onetrust"),
    (re.compile(r"(^|\.)datadoghq\.(com|eu)$"), "datadog"),
    (re.compile(r"(^|\.)tremorhub\.com$"), "tremor"),
    (re.compile(r"(^|\.)rubiconproject\.com$"), "rubicon"),
    (re.compile(r"(^|\.)eyeota\.net$"), "eyeota"),
    (re.compile(r"(^|\.)pardot\.com$"), "pardot"),
    (re.compile(r"(^|\.)googletagmanager\.com$|(^|\.)gtm\.js$"), "gtm"),
]

ID_KEYS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "gclid", "fbclid", "msclkid", "li_fat_id", "pid", "orgid", "tuuid", "d_uuid"}


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


def classify_tracker(host: str) -> str | None:
    for pat, label in TRACKER_PATTERNS:
        if pat.search(host):
            return label
    return None


def analyze(case_dir: Path):
    req_path = case_dir / "detonation" / "requests.jsonl"
    out_dir = case_dir / "derived"
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    id_agg: dict[str, int] = {}

    for ev in load_jsonl(req_path):
        url = ev.get("url")
        if not url:
            continue
        m = urlparse(url)
        host = (m.netloc or "").split("@").pop().split(":")[0]
        tracker_type = classify_tracker(host)
        if not tracker_type:
            # also check path fragment for gtm.js pattern
            if "gtm.js" in (m.path or ""):
                tracker_type = "gtm"
            else:
                continue

        ref = None
        hdrs = ev.get("headers") or {}
        if isinstance(hdrs, dict):
            ref = hdrs.get("referer") or hdrs.get("Referer")
        ref_host = urlparse(ref).netloc if ref else None

        q = parse_qs(m.query)
        ids: dict[str, str] = {}
        for k in ID_KEYS:
            if k in q and q[k]:
                ids[k] = q[k][0]
        # special patterns in path
        if tracker_type == "linkedin":
            # pid in query or path
            if not ids.get("pid"):
                m_pid = re.search(r"pid=(\d+)", url)
                if m_pid:
                    ids["pid"] = m_pid.group(1)
        if tracker_type in ("adobe_demdex", "adobe_launch"):
            m_org = re.search(r"([A-Z0-9]{10,})%40AdobeOrg", url)
            if m_org:
                ids["AdobeOrg"] = m_org.group(1)
            m_demdex = re.search(r"demdex=([0-9]+)", url)
            if m_demdex:
                ids["demdex"] = m_demdex.group(1)

        for v in ids.values():
            id_agg[v] = id_agg.get(v, 0) + 1

        rows.append({
            "ts": ev.get("ts"),
            "method": ev.get("method"),
            "status": ev.get("status"),
            "domain": host,
            "url": url,
            "referer_host": ref_host,
            "tracker_type": tracker_type,
            "ids": json.dumps(ids, ensure_ascii=False),
        })

    # write CSV
    csv_path = out_dir / "trackers.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["ts", "method", "status", "domain", "url", "referer_host", "tracker_type", "ids"])
        w.writeheader()
        for r in rows:
            w.writerow(r)

    # write aggregated IDs
    (out_dir / "tracker_ids.json").write_text(json.dumps(id_agg, indent=2), encoding="utf-8")
    print(str(csv_path))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("case_dir", type=Path)
    args = ap.parse_args(argv)
    case_dir: Path = args.case_dir
    if not case_dir.exists():
        print(f"[!] Case not found: {case_dir}")
        return 2
    analyze(case_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
