#!/usr/bin/env python3
"""
analyze.py — Run RQ checks across all APKs in the apks/ folder.

Usage:
    python analyze.py
    python analyze.py --limit 5

To change which RQs run, edit the ACTIVE_RQS list below.

Output (written to ../results/):
    <app>_report.txt  — per-app findings
    summary.csv       — one row per app, one column per RQ
    flagged.txt       — summary of all flagged apps

Re-running resumes automatically — already-processed APKs are skipped.
"""

import sys
import csv
import argparse
import logging
import traceback
from pathlib import Path
from datetime import datetime

try:
    from androguard.misc import AnalyzeAPK
except ImportError:
    print("[ERROR] androguard not installed. Run: pip install androguard")
    sys.exit(1)

# ── Import RQ scripts ─────────────────────────────────────────────────────────
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

import rq4, rq5, rq7

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURE HERE — comment out any RQs you don't want to run
# ─────────────────────────────────────────────────────────────────────────────
ACTIVE_RQS = {
   # "rq1": rq1.check,
   # "rq2": rq2.check,
    "rq4": rq4.check,
    "rq5": rq5.check,
    "rq7": rq7.check,
}

RQ_LABELS = {
   # "rq1": "RQ1 — Hardcoded HTTP URLs",
 #   "rq2": "RQ2 — Unsafe Hostname Verifier",
    "rq4": "RQ4 — Internet + PII Permissions",
    "rq5": "RQ5 — Unused Permissions",
    "rq7": "RQ7 — Unprotected Exported Activities",
}
# ─────────────────────────────────────────────────────────────────────────────

APKS_DIR    = _HERE.parent / "apks"
RESULTS_DIR = _HERE.parent / "results"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Per-APK analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyze_apk(apk_path: Path) -> dict:
    result = {"apk": apk_path.name, "error": None}
    for key in ACTIVE_RQS:
        result[key] = None

    try:
        apk, d, dx = AnalyzeAPK(str(apk_path))
        dex_list = d if isinstance(d, list) else [d]

        for key, fn in ACTIVE_RQS.items():
            try:
                result[key] = fn(apk, dex_list, dx)
            except Exception as e:
                result[key] = {"found": False, "error": str(e), "notes": f"Check failed: {e}"}
                logger.warning(f"  {key.upper()} failed on {apk_path.name}: {e}")

    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        logger.error(f"  Could not load {apk_path.name}: {e}")
        logger.debug(traceback.format_exc())

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _found(r) -> bool:
    return bool((r or {}).get("found", False))

def _status(r, risk=False):
    if r is None:
        return "ERROR"
    if "error" in r:
        return "ERROR"
    if not r.get("found"):
        return "CLEAN"
    if risk:
        level = r.get("risk_level", "")
        if level == "high":   return "HIGH RISK"
        if level == "medium": return "MEDIUM RISK"
    return "VULNERABLE"


# ─────────────────────────────────────────────────────────────────────────────
# Per-app report
# ─────────────────────────────────────────────────────────────────────────────

def format_report(app_name: str, apk_file: str, res: dict) -> str:
    SEP  = "=" * 80
    DASH = "-" * 80
    lines = [
        SEP,
        f"APP    : {app_name}",
        f"FILE   : {apk_file}",
        f"DATE   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"RQs run: {', '.join(ACTIVE_RQS.keys()).upper()}",
        SEP, "",
    ]

    def section(key, title):
        r = res.get(key)
        lines.extend([DASH, f"[{key.upper()}] {title}", DASH])
        if r is None:
            lines.append("  Not run.")
        elif "error" in r:
            lines.append(f"  Status : ERROR — {r['error']}")
        else:
            if key != "rq4":
                lines.append(f"  Status : {_status(r)}")
            notes = r.get("notes", "")
            if notes:
                lines.append(f"  Notes  : {notes}")
            # RQ-specific detail
            if key == "rq1":
                for url in r.get("urls", [])[:10]:
                    lines.append(f"    {url}")
            elif key == "rq2":
                for c in r.get("classes", [])[:5]:
                    lines.append(f"    {c['class']} — {c['reason']}")
            elif key == "rq4":
                lines.append(f"  Internet  : {'YES' if r.get('has_internet') else 'NO'}")
                normal_perms = r.get("normal_permissions", [])
                dangerous_perms = r.get("dangerous_permissions", [])
                hard_restricted = r.get("hard_restricted", [])
                code_locations = r.get("code_locations", {})
                lines.append(f"  Normal permissions found with INTERNET ({len(normal_perms)}):")
                if normal_perms:
                    for p in normal_perms:
                        lines.append(f"    {p}")
                else:
                    lines.append("    (none)")
                lines.append(f"  Dangerous permissions found with INTERNET ({len(dangerous_perms)}):")
                if dangerous_perms:
                    for p in dangerous_perms:
                        flag = "  [HARD RESTRICTED]" if p in hard_restricted else ""
                        lines.append(f"    {p}{flag}")
                        for loc in code_locations.get(p, []):
                            lines.append(f"        @ {loc}")
                else:
                    lines.append("    (none)")
                risk = r.get("risk_level", "none")
                lines.append(f"  Risk level: {risk.upper()}")
                lines.append( "  Benchmark — HIGH   : dangerous permissions present + at least one is hard restricted")
                lines.append( "               MEDIUM : dangerous permissions present, none hard restricted")
                lines.append( "               LOW    : only normal permissions alongside INTERNET")
                lines.append( "               NONE   : INTERNET absent or no categorized permissions found")
            elif key == "rq5":
                evidence = r.get("evidence", {})
                for p in r.get("unused_permissions", []):
                    lines.append(f"    - {p}")
                used = r.get("used_permissions", [])
                if used:
                    lines.append(f"  Used permissions ({len(used)}) — call-site evidence for manual review:")
                    for p in used:
                        lines.append(f"    + {p}")
                        for loc in evidence.get(p, []):
                            lines.append(f"        @ {loc}")
            elif key == "rq7":
                for c in r.get("vulnerable", []):
                    perm = f"  [permission: {c['permission']}]" if c.get("permission") else ""
                    lines.append(f"    [UNPROTECTED {c['type'].upper()}] {c['name']}")
                    lines.append(f"      export : {c['export_how']}{perm}")
                    lines.append(f"      reason : {c['reason']}")
                    if c.get("xml_snippet"):
                        lines.append("      manifest snippet:")
                        for xml_line in c["xml_snippet"].splitlines():
                            lines.append(f"        {xml_line}")
                safe = r.get("safe_exports", [])
                if safe:
                    lines.append(f"    Safe-by-design exports ({len(safe)}):")
                    for c in safe:
                        lines.append(f"      [{c['type'].upper()}] {c['name']}")
                        lines.append(f"        {c['safe_reason']}")
        lines.append("")

    for key, label in RQ_LABELS.items():
        if key in ACTIVE_RQS:
            section(key, label)

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# CSV
# ─────────────────────────────────────────────────────────────────────────────

def _csv_row(res: dict) -> dict:
    row = {"app_name": res["apk"], "error": res.get("error") or ""}
    for key in ACTIVE_RQS:
        r = res.get(key) or {}
        row[f"{key}_found"]  = _found(r)
        row[f"{key}_status"] = _status(r, risk=(key == "rq4"))
        # Extra detail columns
        if key == "rq1": row["rq1_url_count"]           = len(r.get("urls", []))
        if key == "rq2": row["rq2_class_count"]          = len(r.get("classes", []))
        if key == "rq4":
            row["rq4_normal_count"]    = len(r.get("normal_permissions", []))
            row["rq4_dangerous_count"] = len(r.get("dangerous_permissions", []))
        if key == "rq5": row["rq5_unused_count"]         = len(r.get("unused_permissions", []))
        if key == "rq7":
            row["rq7_vulnerable_count"]  = len(r.get("vulnerable", []))
            row["rq7_safe_export_count"] = len(r.get("safe_exports", []))
    return row

def _csv_fieldnames() -> list:
    base = ["app_name"]
    for key in ACTIVE_RQS:
        base += [f"{key}_found", f"{key}_status"]
        if key == "rq1": base.append("rq1_url_count")
        if key == "rq2": base.append("rq2_class_count")
        if key == "rq4": base += ["rq4_normal_count", "rq4_dangerous_count"]
        if key == "rq5": base.append("rq5_unused_count")
        if key == "rq7": base += ["rq7_vulnerable_count", "rq7_safe_export_count"]
    base.append("error")
    return base


# ─────────────────────────────────────────────────────────────────────────────
# Flagged summary
# ─────────────────────────────────────────────────────────────────────────────

def write_flagged(all_results: list, out_path: Path):
    total = len(all_results)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("  Android APK Security Analysis — Flagged Findings\n")
        f.write(f"  Generated     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Apps analyzed : {total}\n")
        f.write(f"  RQs run       : {', '.join(ACTIVE_RQS.keys()).upper()}\n")
        f.write("=" * 70 + "\n\n")

        f.write("── SUMMARY ──────────────────────────────────────────────────────\n")
        for key, label in RQ_LABELS.items():
            if key not in ACTIVE_RQS:
                continue
            count = sum(1 for r in all_results if _found(r.get(key)))
            pct   = 100 * count / total if total else 0
            f.write(f"  {label:<48}  {count:>3}/{total}  ({pct:.1f}%)\n")
        errors = [r for r in all_results if r.get("error")]
        f.write(f"\n  Errors: {len(errors)}\n\n")

        for key, label in RQ_LABELS.items():
            if key not in ACTIVE_RQS:
                continue
            flagged = [r for r in all_results if _found(r.get(key))]
            f.write(f"── {label} ({len(flagged)} apps) ──\n")
            for r in flagged:
                notes = (r.get(key) or {}).get("notes", "")
                f.write(f"  • {r['apk']}\n")
                if notes:
                    f.write(f"    {notes}\n")
            f.write("\n")

        if errors:
            f.write("── ERRORS ───────────────────────────────────────────────────────\n")
            for r in errors:
                f.write(f"  • {r['apk']}: {r['error']}\n")

    logger.info(f"Flagged report → {out_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Android APK static security analysis")
    parser.add_argument("--limit", type=int, default=None, help="Only process first N APKs")
    args = parser.parse_args()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    apk_files = sorted(APKS_DIR.glob("*.apk"))
    if args.limit:
        apk_files = apk_files[:args.limit]

    if not apk_files:
        print(f"No APKs found in {APKS_DIR}")
        sys.exit(1)

    already_done = [a for a in apk_files if (RESULTS_DIR / f"{a.stem}_report.txt").exists()]
    remaining    = [a for a in apk_files if a not in already_done]

    print(f"\nFound {len(apk_files)} APK(s) — {len(already_done)} already done, {len(remaining)} to process.")
    print(f"Active RQs : {', '.join(ACTIVE_RQS.keys()).upper()}")
    print(f"Results    → {RESULTS_DIR.resolve()}\n")

    new_results = []

    for i, apk_path in enumerate(apk_files, 1):
        report_path = RESULTS_DIR / f"{apk_path.stem}_report.txt"
        if report_path.exists():
            print(f"[{i:3}/{len(apk_files)}] {apk_path.name} — skipped")
            continue

        print(f"[{i:3}/{len(apk_files)}] {apk_path.name} ...", end=" ", flush=True)
        res = analyze_apk(apk_path)
        report_path.write_text(format_report(apk_path.stem, apk_path.name, res), encoding="utf-8")
        new_results.append(res)
        print("done" if not res["error"] else f"ERROR")

    # Append new rows to summary.csv
    if new_results:
        csv_path   = RESULTS_DIR / "summary.csv"
        write_mode = "a" if csv_path.exists() else "w"
        fields     = _csv_fieldnames()
        with open(csv_path, write_mode, newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            if write_mode == "w":
                writer.writeheader()
            writer.writerows([_csv_row(r) for r in new_results])
        logger.info(f"CSV → {csv_path}")
        write_flagged(new_results, RESULTS_DIR / "flagged.txt")

    # Console summary
    total = len(new_results)
    if total:
        print("\n" + "=" * 50)
        print(f"  DONE — {total} new APK(s) analyzed")
        print("=" * 50)
        for key, label in RQ_LABELS.items():
            if key not in ACTIVE_RQS:
                continue
            count = sum(1 for r in new_results if _found(r.get(key)))
            print(f"  {label:<48}: {count}/{total}")
        print("=" * 50)
    else:
        print(f"\nAll APKs already processed. Results in: {RESULTS_DIR.resolve()}")


if __name__ == "__main__":
    main()