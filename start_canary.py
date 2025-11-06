#!/usr/bin/env python3
"""Quick launcher for Canary server"""
import sys
import os

# Set working directory
os.chdir(r'C:\Users\dacan\OneDrive\Desktop\SentinelV1_paw\PAW')
sys.path.insert(0, '.')

from paw.canary.server import run_canary

if __name__ == "__main__":
    case_id = sys.argv[1] if len(sys.argv) > 1 else "CASE-2024-001"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8787
    
    print(f"[launcher] Starting Canary server for case {case_id} on port {port}...")
    try:
        run_canary(case_id, port)
    except Exception as e:
        print(f"[launcher] ERROR: {e}")
        import traceback
        traceback.print_exc()
        input("Press Enter to exit...")
