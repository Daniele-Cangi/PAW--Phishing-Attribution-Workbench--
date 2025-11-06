#!/usr/bin/env python3
"""
DECEPTION COUNTERMEASURE ENGINE - Active Defense Planning (offline)

Generates:
- deception_plan.json
- counter_intelligence_ops.json
- adversary_manipulation.json

Inputs (optional):
- <case>/derived/threat_actor_profile.json
- <case>/derived/behavioral_fingerprint.json
- <case>/derived/threat_intel_enriched.csv
"""
from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path
from typing import Dict, List, Any


def load_json(p: Path, default):
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        return default


def load_hosts(case_dir: Path) -> List[Dict[str, Any]]:
    src = case_dir / 'derived' / 'threat_intel_enriched.csv'
    rows: List[Dict[str, Any]] = []
    if not src.exists():
        return rows
    with src.open('r', encoding='utf-8', newline='') as f:
        rows = list(csv.DictReader(f))
    return rows


def create_honeytokens(profile: Dict[str, Any], case_dir: Path) -> List[Dict[str, Any]]:
    ttps = {'credential_harvesting', 'reconnaissance'}
    tokens: List[Dict[str, Any]] = []
    cred_sink = case_dir / 'derived' / 'honey_cred_events.jsonl'
    doc_sink = case_dir / 'derived' / 'honey_doc_events.jsonl'
    # Ensure sink files exist so references are real
    cred_sink.parent.mkdir(parents=True, exist_ok=True)
    if not cred_sink.exists():
        cred_sink.write_text('', encoding='utf-8')
    if not doc_sink.exists():
        doc_sink.write_text('', encoding='utf-8')

    if 'credential_harvesting' in ttps:
        tokens.append({
            'type': 'email_credential',
            'username': f"admin_{profile.get('sophistication_level','x').lower()}@target-org.local",
            'password': 'P@ssw0rd123!',
            'placement_strategy': 'controlled_public_leak',  # to be executed by analyst
            'monitoring_endpoints': [str(cred_sink)],
            'expected_callback_timing': '24-72_hours',
            'confidence_mislead': 0.85
        })
    if 'reconnaissance' in ttps:
        tokens.append({
            'type': 'document_beacon',
            'title': 'Q4-Budget.xlsx',
            'beacon': 'beacon-id-001',
            'monitoring_endpoints': [str(doc_sink)],
            'confidence_mislead': 0.7
        })
    return tokens


def design_deception_network(hosts: List[Dict[str, Any]], case_dir: Path) -> Dict[str, Any]:
    mirrors: List[Dict[str, str]] = []
    for h in hosts[:10]:
        dom = (h.get('host') or '').split(':')[0]
        if not dom:
            continue
        candidates = [
            f"login-{dom}",
            f"secure-{dom}",
            dom.replace('.', '-') + '.com'
        ]
        mirrors.extend({'original': dom, 'deception': c} for c in candidates[:2])
    redirect_log = case_dir / 'derived' / 'redirects.log'
    if not redirect_log.exists():
        redirect_log.write_text('', encoding='utf-8')
    return {
        'mirror_domains': mirrors,
        'traffic_redirectors': [str(redirect_log)],
        'behavioral_snares': ['csrf-decoy', 'invalid-session-loop']
    }


def counter_intel_ops(behav: Dict[str, Any]) -> List[Dict[str, Any]]:
    ops = []
    top = [d for d, _ in behav.get('top_domains', [])]
    if any('linkedin' in d for d in top):
        ops.append({'op': 'seed-false-b2b-signals', 'target_platforms': ['linkedin'], 'risk': 'LOW'})
    if any('pardot' in d for d in top):
        ops.append({'op': 'poison-campaign-params', 'target_platforms': ['pardot'], 'risk': 'LOW'})
    return ops or [{'op': 'generic_distraction', 'risk': 'LOW'}]


def adversary_manipulation() -> Dict[str, Any]:
    return {
        'tactics': [
            {'name': 'Latency_Inflation', 'effect': 'Raise cost of probing'},
            {'name': 'False_Brand_Signals', 'effect': 'Wasted resource on wrong brand'},
            {'name': 'Kit_Signature_Noise', 'effect': 'Reduce classifier precision'}
        ]
    }


def write_outputs(case_dir: Path, tokens, net, ops, manip):
    d = case_dir / 'derived'
    d.mkdir(parents=True, exist_ok=True)
    (d / 'deception_plan.json').write_text(json.dumps({'honeytokens': tokens}, indent=2), encoding='utf-8')
    (d / 'counter_intelligence_ops.json').write_text(json.dumps({'operations': ops}, indent=2), encoding='utf-8')
    (d / 'adversary_manipulation.json').write_text(json.dumps(manip, indent=2), encoding='utf-8')
    print(str(d / 'deception_plan.json'))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('case_dir', type=Path)
    args = ap.parse_args()
    profile = load_json(args.case_dir / 'derived' / 'threat_actor_profile.json', {})
    behav = load_json(args.case_dir / 'derived' / 'behavioral_fingerprint.json', {})
    hosts = load_hosts(args.case_dir)
    tokens = create_honeytokens(profile, args.case_dir)
    net = design_deception_network(hosts, args.case_dir)
    ops = counter_intel_ops(behav)
    manip = adversary_manipulation()
    write_outputs(args.case_dir, tokens, net, ops, manip)


if __name__ == '__main__':
    main()
