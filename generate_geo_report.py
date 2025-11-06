#!/usr/bin/env python3
from paw.sentinel.intelligence_analyzer import IntelligenceAnalyzer
import json, time, os

CASE_ID = "case-2025-11-05T212057Z-88b5"

def main():
    ia = IntelligenceAnalyzer(db_path="sentinel.db", use_proxy=False)
    report = ia.generate_geographic_report(case_id=CASE_ID)
    out_dir = os.path.join("PAW","reports","geographic")
    os.makedirs(out_dir, exist_ok=True)
    fn = os.path.join(out_dir, f"geographic_report_{CASE_ID}_{int(time.time())}.json")
    with open(fn, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print("Wrote", fn)

if __name__ == '__main__':
    main()
