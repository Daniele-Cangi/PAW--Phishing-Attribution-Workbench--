#!/usr/bin/env python3
"""
Wrapper to run the advanced Quantum-Resistant Forensics module.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import runpy


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('case_dir', type=Path)
    args = ap.parse_args()
    adv = Path(__file__).resolve().parents[1] / 'advanced' / 'quantum_resistant_forensics.py'
    runpy.run_path(str(adv), run_name='__main__')


if __name__ == '__main__':
    main()
