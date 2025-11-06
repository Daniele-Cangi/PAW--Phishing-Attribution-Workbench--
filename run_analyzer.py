from paw.sentinel.intelligence_analyzer import IntelligenceAnalyzer
import json

CASE_ID = "case-2025-11-05T212057Z-88b5"

if __name__ == '__main__':
	ia = IntelligenceAnalyzer(db_path="sentinel.db", use_proxy=False)
	result = ia.analyze_unanalyzed_victims(max_workers=3, case_id=CASE_ID)
	print(json.dumps(result, indent=2))
