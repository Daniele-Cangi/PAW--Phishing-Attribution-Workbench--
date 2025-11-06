#!/usr/bin/env python3
import sqlite3, json

DB = 'sentinel.db'
CASE_ID = 'case-2025-11-05T212057Z-88b5'

def main():
    conn = sqlite3.connect(DB)
    cur = conn.execute("""
SELECT id, victim_ip, attacker_correlation, risk_score, interaction_type, interaction_confidence
FROM victim_intelligence
WHERE case_id = ?
ORDER BY created_at DESC
LIMIT 50
""", (CASE_ID,))
    rows = []
    for r in cur:
        try:
            ac = json.loads(r[2]) if r[2] else None
        except Exception:
            ac = r[2]
        rows.append({
            'id': r[0],
            'victim_ip': r[1],
            'attacker_correlation': ac,
            'risk_score': r[3],
            'interaction_type': r[4],
            'interaction_confidence': r[5]
        })
    conn.close()
    print(json.dumps(rows, indent=2, default=str))

if __name__ == '__main__':
    main()
