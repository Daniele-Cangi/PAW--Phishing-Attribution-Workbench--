#!/usr/bin/env python3
"""
Derive a host→IP→ASN CSV from a PAW case directory using only local artifacts:
- detonation_endpoints.json (host→ips)
- hunt_enrichments.json (per-IP asn_info, reverse_dns, whois)

Usage:
  python PAW/util/derive_host_ip_asn.py cases/<case-id> [--out <csv_path>]

Outputs:
  <case>/derived/host_ip_asn.csv by default (directories created if needed)
"""
from __future__ import annotations
import argparse
import csv
import json
import sys
from pathlib import Path


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def build_ip_index(hunt_enrichments: list[dict]) -> dict[str, dict]:
    idx = {}
    for entry in hunt_enrichments:
        ip = entry.get("ip")
        if not ip:
            continue
        idx[ip] = entry
    return idx


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("case_dir", type=Path)
    p.add_argument("--out", type=Path, default=None)
    args = p.parse_args(argv)

    case_dir: Path = args.case_dir
    if not case_dir.exists():
        print(f"[!] Case directory not found: {case_dir}", file=sys.stderr)
        return 2

    detonation_endpoints_path = case_dir / "detonation_endpoints.json"
    hunt_enrichments_path = case_dir / "hunt_enrichments.json"
    if not detonation_endpoints_path.exists():
        print(f"[!] Missing {detonation_endpoints_path}", file=sys.stderr)
        return 2
    if not hunt_enrichments_path.exists():
        print(f"[!] Missing {hunt_enrichments_path}", file=sys.stderr)
        return 2

    endpoints = load_json(detonation_endpoints_path)
    enrich = load_json(hunt_enrichments_path)
    ip_index = build_ip_index(enrich)

    out_path = args.out
    if out_path is None:
        out_dir = case_dir / "derived"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "host_ip_asn.csv"

    # CSV headers
    headers = [
        "host", "ip", "asn", "org", "asn_country", "reverse_ptr", "whois_org",
        "http_status", "http_server", "http_block", "http_banner_snippet",
        "endpoint_count", "endpoint_methods", "evidence_files"
    ]

    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for ep in endpoints:
            host = ep.get("host")
            ips = ep.get("ips", [])
            count = ep.get("count")
            methods = ",".join(ep.get("methods", [])) if isinstance(ep.get("methods"), list) else ep.get("methods")
            for ip in ips:
                enr = ip_index.get(ip, {})
                asn_info = enr.get("asn_info", {}) if isinstance(enr, dict) else {}
                asn = asn_info.get("asn")
                asn_country = asn_info.get("country")
                whois = enr.get("whois", {})
                whois_org = whois.get("organization") if isinstance(whois, dict) else None
                rdns = enr.get("reverse_dns", {})
                reverse_ptr = rdns.get("ptr") if isinstance(rdns, dict) else None
                org = None
                # Try to infer org: prefer whois_org if present, otherwise use asn org if available (not in sample)
                org = whois_org

                # service banner parsing
                status = None
                server = None
                block = None
                snippet = None
                try:
                    banners = enr.get("service_banners", {}) or {}
                    banner = None
                    # prefer 80 then 443
                    if isinstance(banners, dict):
                        banner = banners.get("80") or banners.get(80) or banners.get("443") or banners.get(443)
                    if banner and isinstance(banner, str):
                        snippet = banner.splitlines()[0][:120]
                        import re as _re
                        m = _re.search(r"HTTP/\d\.\d\s+(\d{3})", banner)
                        if m:
                            status = m.group(1)
                        m2 = _re.search(r"^Server:\s*([^\r\n]+)", banner, _re.IGNORECASE | _re.MULTILINE)
                        if m2:
                            server = m2.group(1)
                        bl = banner.lower()
                        if status == "403" and ("cloudflare" in bl):
                            block = "waf_cloudflare_403"
                        elif status == "403" and ("cloudfront" in bl):
                            block = "waf_cloudfront_403"
                        elif status == "451":
                            block = "legal_denied_451"
                        elif status in ("301", "302") and ("location: https://" in bl):
                            block = "redirect_https"
                except Exception:
                    pass

                w.writerow({
                    "host": host,
                    "ip": ip,
                    "asn": asn,
                    "org": org,
                    "asn_country": asn_country,
                    "reverse_ptr": reverse_ptr,
                    "whois_org": whois_org,
                    "http_status": status,
                    "http_server": server,
                    "http_block": block,
                    "http_banner_snippet": snippet,
                    "endpoint_count": count,
                    "endpoint_methods": methods,
                    "evidence_files": "detonation_endpoints.json;hunt_enrichments.json",
                })

    print(str(out_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
