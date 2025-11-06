#!/usr/bin/env python3
"""Check victims in Sentinel database"""
import sys
import os
os.chdir(r'C:\Users\dacan\OneDrive\Desktop\SentinelV1_paw\PAW')
sys.path.insert(0, '.')

from paw.sentinel.database import CampaignDatabase

db = CampaignDatabase()
victims = db.get_victim_intelligence()

print(f"\n📊 Total victims in database: {len(victims)}\n")

if victims:
    print("Last 5 victims:")
    for v in victims[-5:]:
        ip = v.get('ip_address', 'N/A')
        ua = v.get('user_agent', 'N/A')[:60]
        ts = v.get('timestamp', 'N/A')
        case = v.get('case_id', 'N/A')
        print(f"  • Case: {case}")
        print(f"    IP: {ip}")
        print(f"    UA: {ua}...")
        print(f"    Time: {ts}\n")
else:
    print("No victims recorded yet.")
