#!/usr/bin/env python3
"""
Complete End-to-End Real Test - From Scratch
Analyzes a real phishing EML file and sets up complete tracking system
"""
import sys
import os

# Set working directory FIRST
os.chdir(r'C:\Users\dacan\OneDrive\Desktop\SentinelV1_paw\PAW')
sys.path.insert(0, '.')

# Now import PAW modules
from paw.__main__ import main

# Set command line arguments for analysis
sys.argv = [
    'paw',
    'analyze',
    r'C:\Users\dacan\OneDrive\Desktop\SentinelV1_paw\SAVE\PAW\inbox\appuntamento dentista.eml'
]

print("=" * 80)
print("🧪 STARTING REAL END-TO-END TEST FROM SCRATCH")
print("=" * 80)
print()
print("📧 Analyzing: appuntamento dentista.eml")
print()

# Execute PAW analysis
main()
