# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

`mobsec` — a CSCI 445 (Mobile Application Security) research project packaged as an
installable CLI tool: four Androguard-based static analysis detectors scanned against
199 real-world Android APKs, with an automated LLM-triage + manual-verification
pipeline layered on top to measure each check's false-positive rate. See `README.md`
for the full research questions, precision results, risk-mapping table, and skills
breakdown, and `hwang-skibinski-report.pdf` for the full write-up. Don't re-derive or
restate that content here — read the README when context is needed.

The core finding that shapes how this codebase should be extended: automated detectors
have wildly different precision (RQ3 ~99.5% vs RQ4/unused-permissions ~15.4%), so any
new check should be designed with an explicit notion of confidence/risk tiering rather
than a flat found/not-found flag.

**The APK corpus itself (`apks/`) is not in this repo** — course-licensed, not
redistributable. Only downstream output is checked in: `results/*.txt`, `summary.csv`,
`flagged.txt`, `sql_practice/compliance_findings.db`, `results/analysis/*`. Commands
that expect an `apks/` directory will not find one here; don't try to create or
download one. Because of this, tests and any new detector logic must be verified
against fixtures/mocks, not a real APK.

## Commands

```bash
pip install -e .              # core: CLI, config, build-db, analyze — no androguard needed
pip install -e '.[scan]'      # + androguard, for `mobsec scan` / `mobsec batch`
pip install -e '.[triage]'    # + google-genai, for `mobsec triage`
pip install -e '.[dash]'      # + streamlit, for `mobsec dashboard`
pip install -e '.[dev]'       # + pytest, ruff
pip install -e '.[all]'       # everything (what the Dockerfile installs)

mobsec show-config             # print resolved config
mobsec scan path/to/app.apk    # run every enabled detector against one APK
mobsec batch                   # resumable batch run over the configured APK corpus
mobsec batch --limit 5
mobsec build-db                # parse results/*_report.txt into SQLite
mobsec triage --dry-run        # print Gemini prompts without calling the API
mobsec triage --limit 20
mobsec analyze                 # pandas stats + matplotlib charts + ANALYSIS.md
mobsec dashboard                # Streamlit app

pytest -v                      # 24 tests, no APK corpus or androguard needed
ruff check src tests

docker build -t mobsec .
docker run --rm mobsec --help
```

`sql_practice/build_database.py` still works standalone (`cd sql_practice && python
build_database.py`) — it's a thin wrapper around `mobsec_scan.db`'s parser, kept for
backward compatibility with that directory's existing workflow.

## Architecture

```
src/mobsec_scan/
├── cli.py            # Typer app: scan / batch / build-db / triage / analyze / dashboard
├── config.py          # loads config.yaml + .env; Config.active_detectors is the
│                       # single source of truth for which checks run
├── logging_config.py
├── pipeline.py         # scan/batch orchestration — decompiles once via AnalyzeAPK,
│                       # runs every enabled detector, writes report/CSV/flagged.txt
├── detectors/
│   ├── ssl_tls_misuse.py            # RQ1-2
│   ├── internet_pii_permissions.py  # RQ3
│   ├── unused_permissions.py        # RQ4
│   └── exported_components.py       # RQ5
├── db.py              # parses results/*_report.txt into normalized SQLite
├── triage.py           # Gemini-based TP/FP triage of un-triaged DB findings
├── analysis.py          # pandas stats + matplotlib charts + ANALYSIS.md
└── dashboard.py          # Streamlit app
```

- Each detector exposes `check(apk, dex_list, dx=None) -> dict` (`found`, a `notes`
  string, plus check-specific detail keys) so `pipeline.py` calls all of them
  uniformly. `ssl_tls_misuse.py`'s `check()` is a wrapper around its own pre-existing
  `_check_all`/`_analyze_apk` internals (it predates the convention).
- **Which detectors run is entirely config-driven** (`config.yaml`'s `detectors:`
  block → `Config.active_detectors`) — flip `enabled: true/false`, no code change.
  This is what `ACTIVE_RQS`/`RQ_LABELS` used to be before the Phase 1-8 migration
  documented in `PLAN.md`.
- **`pipeline.py`** decompiles each APK once with `androguard.misc.AnalyzeAPK`, calls
  every active detector's `check()` against the shared `apk, dex_list, dx`, writes a
  per-app `.txt` report, appends a row to `results/summary.csv`, and rewrites
  `results/flagged.txt`. **Resumable by design** — skips any APK whose
  `results/<name>_report.txt` already exists.
- **`unused_permissions.py`** owns `PERMISSION_API_MAP` (permission → API-pattern
  signatures) and `_find_evidence()` — `internet_pii_permissions.py` imports both from
  it, so the two detectors are not fully independent despite each having a standalone
  CLI mode.
- **Risk tiering is a first-class output**, not a boolean: `ssl_tls_misuse.py`
  classifies HIGH vs LOW by tracing whether a suspect `TrustManager`/`HostnameVerifier`
  is actually reachable from a real TLS setup call — a naive/empty `checkServerTrusted`
  alone is only LOW risk. `internet_pii_permissions.py` assigns HIGH/MEDIUM/LOW/NONE
  based on whether flagged permissions are dangerous and/or hard-restricted.
  `exported_components.py` explicitly separates `vulnerable` from `safe_exports` using
  allowlists of known-safe patterns (`MAIN`/`VIEW` launcher intents, signature-level
  `BIND_*` permissions, system-only broadcast actions, `FileProvider`-style classes)
  rather than flagging every exported component.
- **`db.py`** is the single source of truth for parsing `results/*_report.txt` into
  SQLite (schema: `apps` fanning out to `rq4_scan`/`rq5_scan`/`rq7_scan` and their
  per-finding child tables, plus `triage_results`). `sql_practice/build_database.py`
  calls into it rather than duplicating the parser — **if you change
  `pipeline.py`'s report text layout, you must keep `db.py`'s regex parsing in sync**;
  `tests/test_db.py` round-trips `format_report()`'s real output through
  `build_database()` specifically to catch that class of drift (it already caught one
  real regression this way — see the Phase 7 commit).
- **`triage.py`** reads un-triaged findings straight out of the database (one review
  unit per detector: one per flagged RQ4 app, one per RQ5 unused permission, one per
  RQ7 unprotected component), sends each through Gemini with the prompt in
  `config.yaml`, and writes verdicts to `triage_results`. Resumable — a finding already
  triaged (unique on `rq` + `finding_ref`) is skipped on rerun.
- **`sql_practice/`** is a self-contained teaching artifact reshaping the same real
  scan output into a normalized schema for SQL practice — see `sql_practice/README.md`
  for the schema diagram before writing queries or exercises against it.

## Working with new detectors

If adding a new RQ/check, follow the existing `check(apk, dex_list, dx=None) -> dict`
contract so it plugs into `pipeline.py`'s report/CSV/flagged-summary generation
without touching the orchestrator: add the module to
`detectors/__init__.py`'s `DETECTOR_MODULES` map, add a `config.yaml` entry, and (if
its report section needs custom rendering beyond a generic found/notes dump) a branch
in `pipeline._section_lines()`. If it should be triage-able or DB-backed, also extend
`db.py`'s schema/parser and `triage.py`'s pending-findings queries — both are
per-detector by design, not generic, so a new check needs explicit wiring in each.

## Testing

`tests/` uses hand-built fakes (`tests/conftest.py`) implementing only the subset of
androguard's APK/DEX interface each detector actually calls — no APK corpus or
`androguard` install needed to run the suite. `tests/test_db.py` is deliberately an
integration test across `pipeline.py` and `db.py` rather than a parser-only unit test,
for the drift reason above. Run `pytest -v` and `ruff check src tests`; both run in CI
(`.github/workflows/ci.yml`) on every push/PR.
