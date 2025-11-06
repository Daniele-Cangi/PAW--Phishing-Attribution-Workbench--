#!/usr/bin/env python3
"""
OPERATIONAL PATTERN PREDICTOR - Predictive Threat Intelligence (offline)

Reads derived artifacts from a case and predicts next operational moves:
- threat_actor_timeline.json
- infrastructure_evolution.json
- next_targets_prediction.json
- countermeasure_effectiveness.json

Inputs (optional, best-effort):
- <case>/derived/threat_intel_enriched.csv
- <case>/derived/threat_actor_profile.json
- <case>/derived/behavioral_fingerprint.json
- <case>/derived/ttp_analysis.json
"""
from __future__ import annotations
import argparse
import csv
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, UTC
from pathlib import Path
from typing import Dict, List, Any, Tuple


def load_json(p: Path, default):
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        return default


def load_enriched_hosts(case_dir: Path) -> List[Dict[str, Any]]:
    src = case_dir / 'derived' / 'threat_intel_enriched.csv'
    rows: List[Dict[str, Any]] = []
    if not src.exists():
        return rows
    with src.open('r', encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)
    return rows


def asn_diversity(rows: List[Dict[str, Any]]) -> int:
    return len({(r.get('asn') or '').strip() for r in rows if r.get('asn')})


def avg_risk(rows: List[Dict[str, Any]]) -> float:
    vals: List[float] = []
    for r in rows:
        try:
            score = float(r.get('risk_score') or 0.0)
        except Exception:
            score = 0.0
        vals.append(score)
    if not vals:
        return 0.0
    # Normalize by a conservative max 6.0 (from our heuristics range)
    return min(sum(vals) / len(vals) / 6.0, 1.0)


def classify_actor(rows: List[Dict[str, Any]]) -> str:
    diversity = asn_diversity(rows)
    risk = avg_risk(rows)
    if diversity > 3 and risk > 0.7:
        return 'bulletproof_rotation'
    if diversity <= 2 and risk > 0.5:
        return 'apt_stealth'
    return 'unknown_organized'


def rotation_schedule(actor: str, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if actor == 'bulletproof_rotation':
        days_pattern = [7, 14, 30]
    elif actor == 'apt_stealth':
        days_pattern = [30, 60, 90]
    else:
        days_pattern = [30]

    current_asns = sorted({(r.get('asn') or '').strip() for r in rows if r.get('asn')})
    base_conf = 0.8 if actor != 'unknown_organized' else 0.6
    out = []
    for i, d in enumerate(days_pattern):
        when = datetime.now(UTC) + timedelta(days=d)
        out.append({
            'predicted_rotation_date': when.isoformat(),
            'days_from_now': d,
            'likely_new_asns': predict_new_asns(current_asns),
            'rotation_confidence': max(base_conf - i * 0.15, 0.3)
        })
    return out


def predict_new_asns(current_asns: List[str]) -> List[str]:
    # Heuristic migration paths (offline, generic)
    common = {
        '13335': ['16509', '15169'],  # Cloudflare -> AWS/Google
        '16509': ['13335', '8075'],   # AWS -> Cloudflare/Microsoft
        '8075': ['13335', '16509'],   # Microsoft -> Cloudflare/AWS
    }
    pred: List[str] = []
    for asn in current_asns:
        pred.extend(common.get(asn, []))
    return sorted(set(pred))


def likely_new_providers(rows: List[Dict[str, Any]]) -> List[str]:
    orgs = {(r.get('org') or r.get('organization') or '').lower() for r in rows}
    hints = []
    if any('cloudflare' in o for o in orgs):
        hints += ['AWS', 'Google Cloud']
    if any('amazon' in o or 'aws' in o for o in orgs):
        hints += ['Cloudflare', 'Microsoft']
    if any('microsoft' in o for o in orgs):
        hints += ['Cloudflare', 'AWS']
    return sorted(set(hints)) or ['Cloud/Hosting (generic)']


def expansion_probability(rows: List[Dict[str, Any]]) -> float:
    # More domains + waf blocks indicates likely expansion/pivot attempts
    domains = {(r.get('host') or '').split(':')[0] for r in rows}
    waf = sum(1 for r in rows if 'waf_' in (r.get('http_block') or '').lower())
    base = min(len(domains) / 50.0, 1.0)
    bonus = min(waf / 100.0, 0.2)
    return round(min(base + bonus, 1.0), 2)


def takedown_resistance(rows: List[Dict[str, Any]]) -> str:
    # CDN usage and WAF blocks increase resistance
    cdn = sum(1 for r in rows if (r.get('provider_type') or '').startswith('cdn:'))
    waf = sum(1 for r in rows if 'waf_' in (r.get('http_block') or '').lower())
    score = 0
    if cdn > 0:
        score += 2
    if waf > 0:
        score += 1
    return 'HIGH' if score >= 3 else 'MEDIUM' if score == 2 else 'LOW'


def build_evolution(case_dir: Path) -> Dict[str, Any]:
    rows = load_enriched_hosts(case_dir)
    actor = classify_actor(rows)
    evolution = {
        'predicted_actor_type': actor,
        'infrastructure_lifespan_days': 45 if actor == 'bulletproof_rotation' else 180 if actor == 'apt_stealth' else 60,
        'next_asn_rotation': rotation_schedule(actor, rows),
        'likely_new_providers': likely_new_providers(rows),
        'infrastructure_expansion_probability': expansion_probability(rows),
        'predicted_takedown_resistance': takedown_resistance(rows),
    }
    # Evolution timeline (milestones)
    start = datetime.now(UTC)
    evolution['evolution_timeline'] = [
        {'date': (start + timedelta(days=0)).isoformat(), 'event': 'Stabilize current kit and trackers'},
        {'date': (start + timedelta(days=7)).isoformat(), 'event': 'Rotate CDN/WAF edges to bypass blocks'},
        {'date': (start + timedelta(days=14)).isoformat(), 'event': 'Register new domains with similar branding'},
        {'date': (start + timedelta(days=30)).isoformat(), 'event': 'Shift assets to alternate provider'},
    ]
    return evolution


def build_actor_timeline(case_dir: Path) -> List[Dict[str, Any]]:
    # Predict operational steps from now
    now = datetime.now(UTC)
    return [
        {'t': (now + timedelta(days=0)).isoformat(), 'op': 'Refine kit and testing'},
        {'t': (now + timedelta(days=3)).isoformat(), 'op': 'Campaign pulse to new audience segments'},
        {'t': (now + timedelta(days=7)).isoformat(), 'op': 'Rotate ASN/CDN; refresh trackers'},
        {'t': (now + timedelta(days=14)).isoformat(), 'op': 'Pivot infrastructure; spin up mirrors'},
        {'t': (now + timedelta(days=30)).isoformat(), 'op': 'Broaden targeting; add new brands'},
    ]


def predict_targets(case_dir: Path) -> Dict[str, Any]:
    behav = load_json(case_dir / 'derived' / 'behavioral_fingerprint.json', {})
    top = [d for d, _ in behav.get('top_domains', [])]
    hints = []
    if any('linkedin' in d for d in top) or any('pardot' in d for d in top) or any('demandbase' in d for d in top):
        hints.append('B2B (finance/enterprise)')
    if any('londonstockexchange' in d for d in top):
        hints.append('Finance (equities/market)')
    if any('onetrust' in d for d in top):
        hints.append('Consent/Privacy tooling (enterprise-grade)')
    likely_regions = ['EU', 'UK'] if any('onetrust' in d for d in top) else ['Global']
    return {
        'likely_verticals': sorted(set(hints)) or ['Unknown'],
        'likely_regions': likely_regions,
        'supporting_domains': top[:10]
    }


def countermeasure_effectiveness(case_dir: Path) -> Dict[str, Any]:
    rows = load_enriched_hosts(case_dir)
    waf = sum(1 for r in rows if 'waf_' in (r.get('http_block') or '').lower())
    cdn = sum(1 for r in rows if (r.get('provider_type') or '').startswith('cdn:'))
    # Score 0..1
    scores = {
        'provider_abuse_and_waf_escalation': min((waf / max(len(rows), 1)) + 0.2, 1.0),
        'registrar_takedown': 0.7,
        'kit_signature_blocking': 0.6,
        'tracker-based disruption': 0.5 if cdn else 0.6,
        'sinkholing_redirects': 0.4,
    }
    return {'measures': scores, 'notes': 'Heuristic effectiveness based on WAF/CDN presence and known kit patterns'}


def write_outputs(case_dir: Path, evolution: Dict[str, Any], timeline: List[Dict[str, Any]], targets: Dict[str, Any], cm: Dict[str, Any]):
    d = case_dir / 'derived'
    d.mkdir(parents=True, exist_ok=True)
    (d / 'infrastructure_evolution.json').write_text(json.dumps(evolution, indent=2), encoding='utf-8')
    (d / 'threat_actor_timeline.json').write_text(json.dumps(timeline, indent=2), encoding='utf-8')
    (d / 'next_targets_prediction.json').write_text(json.dumps(targets, indent=2), encoding='utf-8')
    (d / 'countermeasure_effectiveness.json').write_text(json.dumps(cm, indent=2), encoding='utf-8')
    print(str(d / 'infrastructure_evolution.json'))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('case_dir', type=Path)
    args = ap.parse_args()
    evolution = build_evolution(args.case_dir)
    timeline = build_actor_timeline(args.case_dir)
    targets = predict_targets(args.case_dir)
    cm = countermeasure_effectiveness(args.case_dir)
    write_outputs(args.case_dir, evolution, timeline, targets, cm)


if __name__ == '__main__':
    main()
