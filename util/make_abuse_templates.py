#!/usr/bin/env python3
"""
Generate provider/CERT abuse templates with anchored evidence from a PAW case.

Reads:
- transmitting_server.json
- derived/host_ip_asn.csv
- detonation/requests.jsonl (for earliest ts)

Outputs:
- derived/abuse_template_en.txt
- derived/abuse_template_it.txt
"""
from __future__ import annotations
import argparse
import csv
import json
import time
from pathlib import Path


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def earliest_ts(req_jsonl: Path) -> float | None:
    try:
        with req_jsonl.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                ev = json.loads(line)
                ts = ev.get("ts")
                if isinstance(ts, (int, float)):
                    return float(ts)
    except Exception:
        return None
    return None


def summarize_blocks(csv_path: Path):
    blocks = {}
    with csv_path.open("r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            b = row.get("http_block")
            if not b:
                continue
            blocks[b] = blocks.get(b, 0) + 1
    return blocks


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("case_dir", type=Path)
    args = ap.parse_args(argv)
    case_dir: Path = args.case_dir

    tx = load_json(case_dir / "transmitting_server.json")
    host_ip_asn_csv = case_dir / "derived" / "host_ip_asn.csv"
    req_jsonl = case_dir / "detonation" / "requests.jsonl"
    blocks = summarize_blocks(host_ip_asn_csv) if host_ip_asn_csv.exists() else {}
    first_ts = earliest_ts(req_jsonl)
    first_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(first_ts)) if first_ts else "N/A"

    out_dir = case_dir / "derived"
    out_dir.mkdir(parents=True, exist_ok=True)

    en = f"""
To: {', '.join(a.get('value') for a in tx.get('abuse', [])) if tx.get('abuse') else 'abuse@provider'}
Subject: Abuse report – phishing/impersonation campaign evidence (IP {tx.get('ip')}, ASN {tx.get('asn')})

Hello,

We are reporting a phishing/impersonation campaign observed and preserved offline. We request account/infrastructure review and relevant HTTP/email logs around the times indicated below.

Key facts
- Sending IP: {tx.get('ip')} (ASN {tx.get('asn')}, ORG {tx.get('org')}, CC {tx.get('cc')}) – file: transmitting_server.json
- Email sent time (server): {tx.get('time_utc')} – file: transmitting_server.json
- Earliest client HTTP activity (sandbox): {first_iso} – file: detonation/requests.jsonl (first line)
- Provider-level denials observed (counts) from derived/host_ip_asn.csv: {json.dumps(blocks)}

Evidence (paths and how to verify)
1) transmitting_server.json – includes IP/ASN/org/abuse contact and PTR
2) detonation/requests.jsonl – line 1 shows the first HTTP GET to campers.diycarhire.com.au (404), subsequent images from file.garden (200), then londonstockexchange.com assets
3) derived/host_ip_asn.csv – maps every host to IP→ASN and records WAF/legal blocks
4) derived/indicators_from_kit.csv – indicators extracted only from local phishing kit files
5) derived/flow.mmd – Mermaid diagram of request flows (referer→target)

Request
- Please review any account/VM associated with IP {tx.get('ip')} (PTR {tx.get('ptr')}) around {tx.get('time_utc')} and provide HTTP/SMTP logs relevant to the above indicators.
- If this IP is part of your VPS/hosting, please suspend abusive activity and share standard post-incident metadata (instance id, create time, auth methods).

We confirm that no active probing was performed; all artifacts are from offline/email analysis and sandbox page loads of public sites.

Regards,

""".strip()

    it = f"""
A: {', '.join(a.get('value') for a in tx.get('abuse', [])) if tx.get('abuse') else 'abuse@provider'}
Oggetto: Segnalazione abuso – campagna di phishing/impersonificazione (IP {tx.get('ip')}, ASN {tx.get('asn')})

Buongiorno,

segnaliamo una campagna di phishing/impersonificazione, preservata offline. Richiediamo verifica dell'account/infra e log HTTP/email nelle finestre temporali sotto.

Fatti principali
- IP mittente: {tx.get('ip')} (ASN {tx.get('asn')}, ORG {tx.get('org')}, CC {tx.get('cc')}) – file: transmitting_server.json
- Orario invio email (server): {tx.get('time_utc')} – file: transmitting_server.json
- Prima attività HTTP lato client (sandbox): {first_iso} – file: detonation/requests.jsonl (prima riga)
- Negazioni a livello provider (conteggi) da derived/host_ip_asn.csv: {json.dumps(blocks)}

Evidenze (percorsi e come verificare)
1) transmitting_server.json – IP/ASN/org/contatto abuse e PTR
2) detonation/requests.jsonl – riga 1: primo GET a campers.diycarhire.com.au (404), poi immagini da file.garden (200), quindi asset di londonstockexchange.com
3) derived/host_ip_asn.csv – mappa host→IP→ASN e registra WAF/legal blocks
4) derived/indicators_from_kit.csv – indicatori estratti solo da file del kit locale
5) derived/flow.mmd – diagramma Mermaid dei flussi (referer→target)

Richiesta
- Verificare qualsiasi account/VM associato a {tx.get('ip')} (PTR {tx.get('ptr')}) intorno a {tx.get('time_utc')} e fornire log HTTP/SMTP pertinenti.
- Se IP appartiene a VPS/hosting, sospendere l'attività abusiva e condividere i metadati standard post-incidente (id istanza, creazione, metodi di autenticazione).

Confermiamo assenza di attività di probing attivo; tutti gli artefatti provengono da analisi offline/email e caricamenti in sandbox di siti pubblici.

Cordiali saluti,

""".strip()

    (out_dir / "abuse_template_en.txt").write_text(en, encoding="utf-8")
    (out_dir / "abuse_template_it.txt").write_text(it, encoding="utf-8")
    print(str(out_dir / "abuse_template_en.txt"))
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main())
