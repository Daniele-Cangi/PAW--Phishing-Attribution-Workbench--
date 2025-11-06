#!/usr/bin/env python3
"""
Strategic Correlator (standalone, offline)

Unifies base + advanced outputs into a single dossier answering:
- da dove è partito tutto (where it started)
 - come siamo arrivati alla segnalazione geografica (path to location signal)
- blocco provider (provider-level blocks)

Outputs under <case>/derived:
- dossier.json
- dossier.md
"""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Union


def read_json(p: Path, default):
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        return default


def earliest_request(case_dir: Path) -> Dict[str, Any]:
    req = case_dir / 'detonation' / 'requests.jsonl'
    earliest = None
    if not req.exists():
        return {'note': 'requests.jsonl missing'}
    try:
        with req.open('r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                ts = obj.get('ts') or obj.get('time') or obj.get('timestamp')
                if earliest is None or (ts and str(ts) < str(earliest.get('ts'))):
                    earliest = obj
    except Exception:
        pass
    return earliest or {'note': 'no parsable entries'}


def find_place_signals(case_dir: Path) -> List[Dict[str, Any]]:
    # Backwards-compatible placeholder.
    # Historically this code attempted to surface country-specific tokens.
    # That hard-coded approach is incorrect for a global forensic pipeline.
    # Keep compatibility: this function now delegates to the general place-mention
    # extractor when called explicitly by newer logic. By default it returns an
    # empty list so older runs remain unchanged.
    return []


def load_place_tokens(tokens_path: Path) -> Union[List[str], Dict[str, str]]:
    """Load place tokens from a JSON file.

    Accepts either a list of tokens (e.g. ["city_name", "country_name"]) or a map
    token->country (e.g. {"city_name": "COUNTRY_CODE"}). This function does not
    perform attribution; it only provides tokens used for extraction.
    """
    if not tokens_path or not tokens_path.exists():
        return []
    try:
        data = json.loads(tokens_path.read_text(encoding='utf-8'))
        if isinstance(data, dict) or isinstance(data, list):
            return data
    except Exception:
        pass
    return []


def find_place_mentions(case_dir: Path, tokens: Union[List[str], Dict[str, str]]) -> List[Dict[str, Any]]:
    """Search case detonation artifacts for mentions of place tokens.

    This function only extracts textual mentions and records file/offset
    context. It does NOT perform automatic country attribution. If a tokens
    mapping is provided (token->country) the mapping is returned alongside the
    mention as a suggestion for manual review.
    """
    if not tokens:
        return []
    # normalize tokens to list and lowercase
    mapping: Dict[str, str] = {}
    token_list: List[str] = []
    if isinstance(tokens, dict):
        mapping = {k.lower(): v for k, v in tokens.items()}
        token_list = list(mapping.keys())
    else:
        token_list = [t.lower() for t in tokens]

    det_dir = case_dir / 'detonation'
    mentions: List[Dict[str, Any]] = []
    if not det_dir.exists():
        return mentions

    # walk text files and search for tokens (case-insensitive, word boundaries)
    for p in det_dir.rglob('*'):
        if p.is_file():
            try:
                text = p.read_text(encoding='utf-8', errors='ignore')
            except Exception:
                continue
            lower = text.lower()
            for token in token_list:
                if not token:
                    continue
                # simple whole-word search
                if re.search(r"\b" + re.escape(token) + r"\b", lower, flags=re.I):
                    # capture a short snippet for context
                    m = re.search(r"(.{0,60}" + re.escape(token) + r".{0,60})", lower, flags=re.I)
                    snippet = m.group(1) if m else ''
                    # count simple occurrences in this file for basic heuristics
                    occ = lower.count(token)
                    mention: Dict[str, Any] = {
                        'token': token,
                        'file': str(p.relative_to(case_dir)),
                        'snippet': snippet,
                        'occurrence_count': occ,
                        'provenance': ['text_search'],
                    }
                    if token in mapping:
                        mention['suggested_country'] = mapping[token]
                        mention['suggestion_note'] = 'suggested by token->country mapping; requires manual review'
                        mention['provenance'].append('token_map')
                    mentions.append(mention)
    # post-process mentions to compute a lightweight confidence and add
    # multi-file / co-occurrence provenance hints.
    if mentions:
        # counts per token
        token_files: Dict[str, set] = {}
        token_total_occ: Dict[str, int] = {}
        for m in mentions:
            t = m['token']
            token_files.setdefault(t, set()).add(m['file'])
            token_total_occ[t] = token_total_occ.get(t, 0) + int(m.get('occurrence_count', 1))

        for m in mentions:
            t = m['token']
            files_count = len(token_files.get(t, []))
            total_occ = token_total_occ.get(t, 0)

            # base confidence: higher if token->country mapping exists
            base = 0.4 if (isinstance(tokens, dict) and t in mapping) else 0.15

            # heuristics: multi-file presence is a strong signal, multiple occurrences moderate
            conf = base
            if files_count >= 2:
                conf += 0.35
                if 'multi_file_cooccurrence' not in m['provenance']:
                    m['provenance'].append('multi_file_cooccurrence')
            elif total_occ >= 5:
                conf += 0.2
                if 'high_occurrence' not in m['provenance']:
                    m['provenance'].append('high_occurrence')

            # clamp and round
            conf = min(conf, 0.95)
            m['confidence'] = round(conf, 2)

    return mentions


def provider_blocks(summary_json: Path, enriched_csv: Path) -> Dict[str, Any]:
    # Prefer advanced report
    s = read_json(summary_json, {}) if summary_json.exists() else {}
    if s:
        return {
            'counts': s.get('provider_blocks', {}),
            'by_risk': s.get('by_risk', {}),
            'high_risk_examples': s.get('high_risk_examples', []),
            'note': 'from threat_assessment_report.json',
        }
    # Fallback minimal
    return {'note': 'no advanced report available'}


def build_dossier(case_dir: Path, enable_country_detection: bool = True, place_tokens_file: Optional[Path] = None) -> Dict[str, Any]:
    derived = case_dir / 'derived'
    dossier: Dict[str, Any] = {}

    # Base + Advanced artifacts
    dossier['ttp_analysis'] = read_json(derived / 'ttp_analysis.json', [])
    dossier['criminal_fingerprint'] = read_json(derived / 'criminal_fingerprint.json', {})
    dossier['deobfuscation_cascade'] = read_json(derived / 'deobfuscation_cascade.json', [])
    dossier['threat_actor_profile'] = read_json(derived / 'threat_actor_profile.json', {})
    dossier['behavioral_fingerprint'] = read_json(derived / 'behavioral_fingerprint.json', {})
    dossier['campaign_intelligence'] = read_json(derived / 'campaign_intelligence.json', {})
    dossier['audience_targeting'] = read_json(derived / 'audience_targeting.json', {})
    dossier['threat_assessment'] = provider_blocks(derived / 'threat_assessment_report.json', derived / 'threat_intel_enriched.csv')

    # Narrative answers
    start = earliest_request(case_dir)
    # By default we do not perform automatic country attribution. If an analyst
    # enables country detection and provides a tokens file, we will extract
    # mentions and return them as evidence suggestions (manual review required).
    country_attr_note = {'note': 'automatic country attribution is disabled; any country suggestion requires manual validation'}
    evidence_mentions: List[Dict[str, Any]] = []
    if enable_country_detection:
        if place_tokens_file:
            tokens = load_place_tokens(place_tokens_file)
            evidence_mentions = find_place_mentions(case_dir, tokens)
        else:
            # Country-detection is enabled, but no tokens file was provided.
            # We deliberately avoid using a built-in hard-coded token list to
            # prevent implicit country attribution. Analysts should provide a
            # tokens file (list or token->country map) when they want extraction.
            country_attr_note['note'] += ' (enabled, but no tokens file provided; no mentions extracted)'

    dossier['forensic_narrative'] = {
        'da_dove_e_partito_tutto': start,
        'country_attribution': country_attr_note,
        'evidence_mentions': evidence_mentions,
        'blocco_provider': dossier['threat_assessment']
    }
    return dossier


def write_markdown(case_dir: Path, dossier: Dict[str, Any]):
    md = [
        f"# Strategic Dossier for case: {case_dir.name}",
        "",
        "## Forensic narrative",
        "- Da dove è partito tutto: " + (json.dumps(dossier.get('forensic_narrative', {}).get('da_dove_e_partito_tutto'))),
        "- Country attribution: automatic country attribution is disabled; any country suggestion requires manual validation",
        "- Blocco provider: " + json.dumps(dossier.get('forensic_narrative', {}).get('blocco_provider')),
        "",
        "### Location / country signals",
        "(country-level attribution disabled; mentions extracted are suggestions only and require manual review)",
    ]
    # include extracted mentions if present
    mentions = dossier.get('forensic_narrative', {}).get('evidence_mentions', [])
    if mentions:
        md.append("")
        md.append("## Extracted place mentions (suggestions)")
        md.append("Note: these are textual mentions extracted from artifacts; they do NOT constitute proven attribution.")
        for m in mentions:
            md.append(f"- token: {m.get('token')}  file: {m.get('file')}")
            # show confidence and provenance when available
            if m.get('confidence') is not None:
                md.append(f"  confidence: {m.get('confidence')}")
            if m.get('provenance'):
                md.append(f"  provenance: {', '.join(m.get('provenance'))}")
            if m.get('suggested_country'):
                md.append(f"  suggested_country: {m.get('suggested_country')} ({m.get('suggestion_note')})")
            snip = m.get('snippet') or ''
            if snip:
                md.append(f"  snippet: {snip[:200]}")
    else:
        # keep placeholder compatibility; there will be no entries listed here
        md += ["", "(no place mentions extracted)"]
    md += [
        "",
        "## Threat actor profile",
        json.dumps(dossier.get('threat_actor_profile', {}), indent=2),
        "",
        "## MITRE ATT&CK (selected)",
        json.dumps(dossier.get('ttp_analysis', []), indent=2),
        "",
        "## Criminal infrastructure",
        json.dumps(dossier.get('criminal_fingerprint', {}), indent=2),
        "",
        "## Behavioral fingerprint",
        json.dumps(dossier.get('behavioral_fingerprint', {}), indent=2),
    ]
    out = case_dir / 'derived' / 'dossier.md'
    out.write_text('\n'.join(md), encoding='utf-8')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('case_dir', type=Path)
    ap.add_argument('--disable-country-detection', action='store_true', default=False, help='Disable extraction of place tokens from artifacts (enabled by default).')
    ap.add_argument('--place-tokens-file', type=Path, default=None, help='JSON file with place tokens (list or token->country map)')
    args = ap.parse_args()
    enable_country = not bool(args.disable_country_detection)
    dossier = build_dossier(args.case_dir, enable_country_detection=enable_country, place_tokens_file=args.place_tokens_file)
    derived = args.case_dir / 'derived'
    derived.mkdir(parents=True, exist_ok=True)
    (derived / 'dossier.json').write_text(json.dumps(dossier, indent=2), encoding='utf-8')
    write_markdown(args.case_dir, dossier)
    print(str(derived / 'dossier.json'))


if __name__ == '__main__':
    main()
