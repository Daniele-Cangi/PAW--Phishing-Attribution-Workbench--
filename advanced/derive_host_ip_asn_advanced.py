#!/usr/bin/env python3
"""
ADVANCED Host→IP→ASN Enricher (standalone, offline-only)

Reads <case>/derived/host_ip_asn.csv (from base util) and derives:
- threat_intel_enriched.csv: Adds risk_score, risk_level, provider_type, notes
- threat_assessment_report.json: Roll-up counts, high-risk entries, provider blocks

Heuristics are conservative and offline. No external lookups.
"""
from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path
from typing import Dict, Any, List


CDN_ASNS = {
    '13335': 'Cloudflare',
    '15169': 'Google',
    '14618': 'AWS',
    '16509': 'AWS',
    '8075': 'Microsoft',
    '32934': 'Facebook',
}

BRAND_TOKENS = [
    'microsoft', 'office', 'o365', 'paypal', 'apple', 'google', 'facebook', 'poste', 'banque',
    'bank', 'login', 'secure', 'verification', 'verify', 'update', 'password', 'support'
]


def provider_type(asn: str, org: str) -> str:
    if asn in CDN_ASNS:
        return f"cdn:{CDN_ASNS[asn]}"
    if org:
        orgl = org.lower()
        if 'cloud' in orgl or 'hosting' in orgl or 'vps' in orgl:
            return 'cloud/hosting'
    return 'unknown'


def compute_risk(row: Dict[str, str]) -> Dict[str, Any]:
    score = 0
    notes: List[str] = []

    http_block = (row.get('http_block') or '').lower()
    http_status = row.get('http_status') or ''
    host = (row.get('host') or '').lower()
    asn = (row.get('asn') or '')
    org = row.get('org') or row.get('organization') or ''

    if 'waf_cloudflare_403' in http_block or 'waf_cloudfront_403' in http_block:
        score += 2
        notes.append('provider_waf_block_403')
    if 'legal_denied_451' in http_block or http_status == '451':
        score += 3
        notes.append('legal_denied_451')
    if any(tok in host for tok in BRAND_TOKENS):
        score += 1
        notes.append('brandlike_host_token')

    ptype = provider_type(asn, org)
    if ptype.startswith('cdn:'):
        notes.append('via_cdn_visibility_limited')

    level = 'LOW'
    if score >= 5:
        level = 'HIGH'
    elif score >= 3:
        level = 'MEDIUM'

    return {'risk_score': score, 'risk_level': level, 'notes': ';'.join(notes), 'provider_type': ptype}


def enrich(case_dir: Path) -> Dict[str, Any]:
    derived = case_dir / 'derived'
    src = derived / 'host_ip_asn.csv'
    out_csv = derived / 'threat_intel_enriched.csv'
    report_json = derived / 'threat_assessment_report.json'

    rows: List[Dict[str, str]] = []
    if not src.exists():
        raise FileNotFoundError(f"Missing input: {src}")
    with src.open('r', encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)

    enriched: List[Dict[str, Any]] = []
    summary = {
        'total': 0,
        'by_risk': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
        'provider_blocks': {'waf_403': 0, 'legal_451': 0},
        'cdn_links': 0,
        'high_risk_examples': [],
    }

    for r in rows:
        meta = compute_risk(r)
        combined = {**r, **meta}
        enriched.append(combined)
        summary['total'] += 1
        summary['by_risk'][meta['risk_level']] += 1
        hb = (r.get('http_block') or '').lower()
        if 'waf_cloudflare_403' in hb or 'waf_cloudfront_403' in hb:
            summary['provider_blocks']['waf_403'] += 1
        if 'legal_denied_451' in hb or (r.get('http_status') or '') == '451':
            summary['provider_blocks']['legal_451'] += 1
        if meta['provider_type'].startswith('cdn:'):
            summary['cdn_links'] += 1
        if meta['risk_level'] == 'HIGH' and len(summary['high_risk_examples']) < 10:
            summary['high_risk_examples'].append({k: combined.get(k, '') for k in ['host','ip','asn','org','http_status','http_block','risk_score','notes']})

    # Write outputs
    if enriched:
        with out_csv.open('w', encoding='utf-8', newline='') as f:
            fieldnames = list(enriched[0].keys())
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(enriched)
    else:
        out_csv.write_text('', encoding='utf-8')

    report_json.write_text(json.dumps(summary, indent=2), encoding='utf-8')
    return {'csv': str(out_csv), 'report': str(report_json)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('case_dir', type=Path)
    args = ap.parse_args()
    res = enrich(args.case_dir)
    print(res['csv'])


if __name__ == '__main__':
    main()
