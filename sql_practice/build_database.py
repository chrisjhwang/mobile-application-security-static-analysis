#!/usr/bin/env python3
"""
build_database.py — Parse results/*_report.txt (real output from `mobsec batch`)
into a normalized SQLite database for SQL practice.

Usage:
    python build_database.py

Reads:  ../results/*_report.txt
Writes: compliance_findings.db

Thin wrapper: the actual parsing logic lives in mobsec_scan.db, which is
also what `mobsec build-db` calls, so there is one parser to maintain.
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from mobsec_scan.db import build_database  # noqa: E402

RESULTS_DIR = HERE.parent / "results"
DB_PATH = HERE / "compliance_findings.db"


def main() -> None:
    summary = build_database(RESULTS_DIR, DB_PATH)
    print("\n--- Load summary ---")
    for label, count in summary.items():
        print(f"  {label:36} {count}")
    print(f"\nDatabase written to {DB_PATH}")


if __name__ == "__main__":
    main()
