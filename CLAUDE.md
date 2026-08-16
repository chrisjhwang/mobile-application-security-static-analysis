# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

A CSCI 445 (Mobile Application Security) research project: four Androguard-based static analysis scripts scanned against 199 real-world Android APKs, with an LLM-triage + manual-verification pipeline layered on top to measure each check's false-positive rate. See `README.md` for the full research questions, precision results, and risk-mapping table, and `hwang-skibinski-report.pdf` for the full write-up. Don't re-derive or restate that content here — read the README when context is needed.

The core finding that shapes how this codebase should be extended: automated detectors have wildly different precision (RQ3 ~99.5% vs RQ4/unused-permissions ~15.4%), so any new check should be designed with an explicit notion of confidence/risk tiering rather than a flat found/not-found flag.

**The APK corpus itself (`apks/`) is not in this repo** — course-licensed, not redistributable. Only script output (`results/*.txt`, `summary.csv`, `flagged.txt`) is checked in. Scripts that expect an `apks/` directory will not find one here; don't try to create or download one.

## Commands

```bash
pip install androguard          # only external dependency

# Run one detector standalone against a single APK
python ssl_tls_misuse_scan.py -f path/to/app.apk
python internet_pii_permissions.py path/to/app.apk
python unused_permissions.py path/to/app.apk
python exported_components.py path/to/app.apk

# Batch mode
python ssl_tls_misuse_scan.py -d path/to/apk_dir -o reports/     # SSL/TLS scan, own CLI/report format
python run_batch_analysis.py                                     # RQ4 + RQ5 + RQ7 orchestrator → results/
python run_batch_analysis.py --limit 5                           # only process first N APKs

# SQL practice DB (derived from results/, for querying findings with SQL)
cd sql_practice
python build_database.py        # rebuild compliance_findings.db from ../results/*_report.txt
sqlite3 compliance_findings.db
```

There is no test suite, linter, or build step in this repo — it's a set of standalone analysis scripts plus their output.

## Architecture

Each detection script (`ssl_tls_misuse_scan.py`, `internet_pii_permissions.py`, `unused_permissions.py`, `exported_components.py`) is independently runnable via its own `if __name__ == "__main__"` block, **and** exposes a `check(apk, dex_list, dx=None) -> dict` function (all except the SSL script, which predates that convention and has its own batch CLI/report format) that `run_batch_analysis.py` imports and calls uniformly across the corpus.

- **`run_batch_analysis.py`** is the orchestrator for RQ4/RQ5/RQ7 (`ssl_tls_misuse_scan.py`/RQ1-2 is run separately via its own CLI, not wired into this orchestrator — see the commented-out `rq1`/`rq2` entries). It decompiles each APK once with `androguard.misc.AnalyzeAPK`, calls each active check's `check()` against the shared `apk, dex_list, dx`, then writes a per-app `.txt` report, appends a row to `results/summary.csv`, and rewrites `results/flagged.txt`. **It's resumable by design** — it skips any APK whose `results/<name>_report.txt` already exists, so re-running after interruption or after adding new APKs only processes what's missing. To change which checks run, edit `ACTIVE_RQS` and `RQ_LABELS` at the top of the file (they must stay in sync).
- **`unused_permissions.py`** owns `PERMISSION_API_MAP` (permission → API-pattern signatures) and `_find_evidence()` — `internet_pii_permissions.py` imports both from it to locate call-site evidence for dangerous permissions, so the two scripts are not fully independent despite each having a standalone CLI.
- **Risk tiering is a first-class output**, not a boolean: `ssl_tls_misuse_scan.py` classifies HIGH vs LOW by tracing whether a suspect `TrustManager`/`HostnameVerifier` is actually reachable from a real TLS setup call (`SSLContext.init`, OkHttp's `sslSocketFactory`, etc.) — a naive/empty `checkServerTrusted` alone is only LOW risk. `internet_pii_permissions.py` assigns HIGH/MEDIUM/LOW/NONE based on whether flagged permissions are dangerous and/or hard-restricted. `exported_components.py` explicitly separates `vulnerable` from `safe_exports` using allowlists of known-safe patterns (`MAIN`/`VIEW` launcher intents, signature-level `BIND_*` permissions, system-only broadcast actions, `FileProvider`-style classes) rather than flagging every exported component.
- **`sql_practice/`** is a self-contained teaching artifact: `build_database.py` parses the plaintext reports in `../results/` into a normalized SQLite schema (`apps` fanning out to `rq4_scan`/`rq5_scan`/`rq7_scan` and their per-finding child tables). It's a reshaping of real scan output, not synthetic data — see `sql_practice/README.md` for the schema diagram before writing queries or exercises against it.

## Working with new detection scripts

If adding a new RQ/check, follow the existing `check(apk, dex_list, dx=None) -> dict` contract (`found`, a `notes` string, and check-specific detail keys) so it plugs into `run_batch_analysis.py`'s report/CSV/flagged-summary generation without changes to the orchestrator's rendering logic — `format_report()`, `_csv_row()`, `_csv_fieldnames()`, and `write_flagged()` all key off `ACTIVE_RQS`/`RQ_LABELS` and per-check dict shape.
