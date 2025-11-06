#!/usr/bin/env python3
"""
ADVANCED Tracker Analytics (standalone, offline-only)

Inputs under <case>/derived (from base util):
- trackers.csv (domain, count, ids?, etc.)
- tracker_ids.json (optional rich IDs)

Outputs:
- behavioral_fingerprint.json: which trackers, how often, role hint
- campaign_intelligence.json: extracted campaign IDs and groupings
- audience_targeting.json: inferred categories (very conservative)
"""
from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path
from typing import Dict, Any


TRACKER_ROLES = {
    'linkedin.com': 'b2b_social',
    'licdn.com': 'b2b_social',
    'demdex.net': 'dmp',
    'everesttech.net': 'ad',
    'doubleclick.net': 'ad',
    'googletagmanager.com': 'tag_manager',
    'googlesyndication.com': 'ad',
    'rlcdn.com': 'identity',
    'onetrust.com': 'consent',
    'demandbase.com': 'abm',
}


def load_trackers(case_dir: Path):
    derived = case_dir / 'derived'
    tcsv = derived / 'trackers.csv'
    tids = derived / 'tracker_ids.json'
    trackers = []
    if tcsv.exists():
        with tcsv.open('r', encoding='utf-8', newline='') as f:
            reader = csv.DictReader(f)
            for r in reader:
                trackers.append(r)
    ids = {}
    if tids.exists():
        try:
            ids = json.loads(tids.read_text(encoding='utf-8') or '{}')
        except Exception:
            ids = {}
    return trackers, ids


def behavioral_fingerprint(trackers, ids_map) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        'total_domains': 0,
        'top_domains': [],
        'roles': {},
        'domains': {},
    }
    counts = {}
    for r in trackers:
        dom = (r.get('domain') or r.get('host') or '').lower()
        try:
            c = int(r.get('count') or 1)
        except Exception:
            c = 1
        counts[dom] = counts.get(dom, 0) + c
        role = TRACKER_ROLES.get(dom, 'unknown')
        summary['roles'][role] = summary['roles'].get(role, 0) + c
        if dom not in summary['domains']:
            summary['domains'][dom] = {'count': 0, 'role': role, 'ids': ids_map.get(dom, {})}
        summary['domains'][dom]['count'] += c
    summary['total_domains'] = len(counts)
    summary['top_domains'] = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
    return summary


def campaign_intel(ids_map) -> Dict[str, Any]:
    # Flatten known IDs and group by type
    intel = {'by_type': {}, 'all_ids': []}
    for dom, sub in ids_map.items():
        if isinstance(sub, dict):
            for k, v in sub.items():
                intel['by_type'].setdefault(k, []).append({'domain': dom, 'value': v})
                intel['all_ids'].append({'domain': dom, 'type': k, 'value': v})
    return intel


def audience_targeting(summary) -> Dict[str, Any]:
    categories = []
    roles = summary.get('roles', {})
    if roles.get('b2b_social', 0) + roles.get('abm', 0) >= 2:
        categories.append('B2B_focus')
    if roles.get('ad', 0) >= 2 and roles.get('tag_manager', 0) >= 1:
        categories.append('Marketing_optimized')
    if roles.get('identity', 0) >= 1:
        categories.append('Identity_graph_leverage')
    if not categories:
        categories.append('Unclear')
    return {'categories': categories, 'evidence_roles': roles}


def write_outputs(case_dir: Path, behav, intel, aud):
    derived = case_dir / 'derived'
    derived.mkdir(parents=True, exist_ok=True)
    (derived / 'behavioral_fingerprint.json').write_text(json.dumps(behav, indent=2), encoding='utf-8')
    (derived / 'campaign_intelligence.json').write_text(json.dumps(intel, indent=2), encoding='utf-8')
    (derived / 'audience_targeting.json').write_text(json.dumps(aud, indent=2), encoding='utf-8')
    print(str(derived / 'behavioral_fingerprint.json'))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('case_dir', type=Path)
    args = ap.parse_args()
    trackers, ids = load_trackers(args.case_dir)
    behav = behavioral_fingerprint(trackers, ids)
    intel = campaign_intel(ids)
    aud = audience_targeting(behav)
    write_outputs(args.case_dir, behav, intel, aud)


if __name__ == '__main__':
    main()
