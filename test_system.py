#!/usr/bin/env python3
"""
Complete End-to-End Test of PAW + Canary + Sentinel System
Tests the full workflow from phishing analysis to victim tracking
"""
import sys
import os
import time
import json
from datetime import datetime

os.chdir(r'C:\Users\dacan\OneDrive\Desktop\SentinelV1_paw\PAW')
sys.path.insert(0, '.')

print("=" * 80)
print("🧪 PAW COMPLETE SYSTEM TEST - End-to-End Workflow")
print("=" * 80)
print()

# ============================================================================
# TEST 1: Verify Canary Server is Running
# ============================================================================
print("📋 TEST 1: Canary Server Status")
print("-" * 80)

import socket
def check_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

canary_running = check_port('localhost', 8787)
print(f"  Canary Server (port 8787): {'✅ RUNNING' if canary_running else '❌ NOT RUNNING'}")

if not canary_running:
    print("  ⚠️  Please start Canary server first: python start_canary.py CASE-2024-001 8787")
    print()

# ============================================================================
# TEST 2: Verify Ngrok Tunnel
# ============================================================================
print("\n📋 TEST 2: Ngrok Tunnel Status")
print("-" * 80)

try:
    import urllib.request
    response = urllib.request.urlopen('http://localhost:4040/api/tunnels', timeout=2)
    data = json.loads(response.read().decode())
    
    if data['tunnels']:
        tunnel = data['tunnels'][0]
        public_url = tunnel['public_url']
        local_addr = tunnel['config']['addr']
        print(f"  Ngrok Status: ✅ ACTIVE")
        print(f"  Public URL: {public_url}")
        print(f"  Local Address: {local_addr}")
    else:
        print(f"  Ngrok Status: ❌ NO TUNNELS")
except Exception as e:
    print(f"  Ngrok Status: ❌ NOT RUNNING")
    print(f"  Error: {str(e)}")

# ============================================================================
# TEST 3: Sentinel Database Status
# ============================================================================
print("\n📋 TEST 3: Sentinel Database Status")
print("-" * 80)

try:
    from paw.sentinel.database import CampaignDatabase
    
    db = CampaignDatabase()
    campaigns = db.get_active_campaigns()
    victims = db.get_victim_intelligence()
    
    print(f"  Database: ✅ CONNECTED")
    print(f"  Active Campaigns: {len(campaigns)}")
    print(f"  Total Victims: {len(victims)}")
    
    if campaigns:
        print(f"\n  📊 Active Campaigns:")
        for camp in campaigns[:3]:
            print(f"    • {camp['case_id']}: {camp['url']}")
    
except Exception as e:
    print(f"  Database: ❌ ERROR")
    print(f"  Error: {str(e)}")

# ============================================================================
# TEST 4: Canary Hits File
# ============================================================================
print("\n📋 TEST 4: Canary Tracking Data")
print("-" * 80)

hits_file = r"cases\CASE-2024-001\canary\hits.jsonl"
if os.path.exists(hits_file):
    with open(hits_file, 'r') as f:
        hits = [json.loads(line) for line in f if line.strip()]
    
    print(f"  Hits File: ✅ EXISTS")
    print(f"  Total Hits: {len(hits)}")
    
    if hits:
        print(f"\n  📊 Last 3 Hits:")
        for hit in hits[-3:]:
            ts = datetime.fromtimestamp(hit['ts']).strftime('%Y-%m-%d %H:%M:%S')
            ip = hit.get('ip', 'N/A')
            token = hit.get('token', 'N/A')
            action = hit.get('action', 'N/A')
            print(f"    • {ts} | {ip} | {token} | {action}")
else:
    print(f"  Hits File: ❌ NOT FOUND")

# ============================================================================
# TEST 5: Simulate Victim Click (if Canary is running)
# ============================================================================
if canary_running:
    print("\n📋 TEST 5: Simulate Victim Click")
    print("-" * 80)
    
    try:
        import urllib.request
        
        # Simulate click with realistic User-Agent
        test_token = f"test-system-check-{int(time.time())}"
        url = f"http://localhost:8787/c/{test_token}"
        
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
        )
        
        print(f"  Sending test click to: /c/{test_token}")
        response = urllib.request.urlopen(req, timeout=5)
        status = response.getcode()
        
        print(f"  Response Status: ✅ {status}")
        
        # Wait a moment for file write
        time.sleep(1)
        
        # Check if click was recorded
        if os.path.exists(hits_file):
            with open(hits_file, 'r') as f:
                hits = [json.loads(line) for line in f if line.strip()]
            
            latest_hit = hits[-1] if hits else None
            if latest_hit and latest_hit.get('token') == test_token:
                print(f"  Click Recorded: ✅ YES")
                print(f"    - IP: {latest_hit.get('ip')}")
                print(f"    - User-Agent: {latest_hit.get('ua')[:60]}...")
            else:
                print(f"  Click Recorded: ⚠️  NOT FOUND IN FILE")
        
    except Exception as e:
        print(f"  Test Click: ❌ FAILED")
        print(f"  Error: {str(e)}")

# ============================================================================
# TEST 6: Geographic Intelligence
# ============================================================================
print("\n📋 TEST 6: Geographic Intelligence Analysis")
print("-" * 80)

try:
    from paw.sentinel.database import CampaignDatabase
    
    db = CampaignDatabase()
    victims = db.get_victim_intelligence()
    
    # Filter victims with valid geolocation data
    geolocated = [v for v in victims if v.get('country')]
    
    print(f"  Total Victims: {len(victims)}")
    print(f"  With Geolocation: {len(geolocated)}")
    
    if geolocated:
        countries = {}
        for v in geolocated:
            country = v.get('country', 'Unknown')
            countries[country] = countries.get(country, 0) + 1
        
        print(f"\n  📊 Geographic Distribution:")
        for country, count in sorted(countries.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"    • {country}: {count} victim(s)")
    
except Exception as e:
    print(f"  Geographic Analysis: ❌ ERROR")
    print(f"  Error: {str(e)}")

# ============================================================================
# SUMMARY
# ============================================================================
print("\n" + "=" * 80)
print("📊 TEST SUMMARY")
print("=" * 80)

components = [
    ("Canary Server", canary_running),
    ("Ngrok Tunnel", 'public_url' in locals()),
    ("Sentinel Database", 'campaigns' in locals()),
    ("Tracking Data", os.path.exists(hits_file)),
]

print()
for component, status in components:
    status_icon = "✅" if status else "❌"
    print(f"  {status_icon} {component}")

print("\n" + "=" * 80)
print("🎯 Test Complete!")
print("=" * 80)
