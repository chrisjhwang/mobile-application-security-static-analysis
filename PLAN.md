# Consolidate into a unified CLI pipeline + automated triage + data analysis/dashboard

## Context

This repo is currently four independent Androguard scripts (`ssl_tls_misuse_scan.py`, `internet_pii_permissions.py`, `unused_permissions.py`, `exported_components.py`) plus a separate orchestrator (`run_batch_analysis.py`) and a standalone `sql_practice/build_database.py` that re-parses text reports into SQLite. It's functionally solid (documented in `CLAUDE.md`/`README.md`) but reads as "a pile of scripts," and the LLM-triage step described in the README is entirely manual (copy/paste into Gemini).

Goal: turn this into one presentable, installable tool — a single CLI with subcommands — that demonstrates workflows relevant to cyber compliance / analyst / systems engineer / FDE roles: config-driven pipelines, structured logging, automated AI-assisted triage via a real API, a data-analysis/reporting layer on top of raw findings, an interactive dashboard, tests, CI, and containerization. This is also a learning vehicle — the plan is phased so each piece can be built, run, and understood before moving to the next.

Confirmed constraints: no local APK corpus right now (detector-logic tests must use fixtures/mocks, not real APKs), and a real Gemini API key will be obtained to test triage for real. No existing `pyproject.toml`/`requirements.txt`/tests/CI — this is a clean build, not a migration of existing infra.

## Target structure

```
mobile-application-security-static-analysis/
├── pyproject.toml              # deps + console_script entry point `mobsec`
├── config.yaml                 # active checks, paths, gemini model/prompt, thresholds
├── .env.example                # GEMINI_API_KEY=
├── Dockerfile / .dockerignore
├── .github/workflows/ci.yml    # pytest + lint on push/PR
├── src/mobsec_scan/
│   ├── cli.py                  # Typer app: scan / batch / triage / build-db / analyze / dashboard
│   ├── config.py                # loads config.yaml + .env
│   ├── logging_config.py
│   ├── pipeline.py              # batch orchestration (replaces run_batch_analysis.py)
│   ├── detectors/
│   │   ├── ssl_tls_misuse.py
│   │   ├── internet_pii_permissions.py
│   │   ├── unused_permissions.py
│   │   └── exported_components.py
│   ├── triage.py                # Gemini API-based TP/FP triage
│   ├── db.py                    # builds/refreshes SQLite from results/ (supersedes sql_practice/build_database.py logic)
│   ├── analysis.py              # pandas stats + matplotlib charts + markdown report
│   └── dashboard.py              # Streamlit app
├── tests/
│   ├── conftest.py              # fake AndroidManifest XML, fake apk/dex fixtures
│   ├── test_exported_components.py
│   ├── test_internet_pii_permissions.py
│   ├── test_unused_permissions.py
│   ├── test_db.py
│   └── test_analysis.py
├── docs/DASHBOARD_DESIGN_NOTES.md   # design-principle notes (learning artifact)
├── results/                      # unchanged output sink
├── sql_practice/                 # unchanged; build_database.py refactored to call db.py's parser (no duplicate logic)
└── README.md                     # rewritten for the unified workflow
```

`detectors/*.py` keep the existing `check(apk, dex_list, dx=None) -> dict` contract unchanged — just relocated and import-adjusted — so all existing logic (risk tiering, safe-export allowlists, `PERMISSION_API_MAP`) carries over as-is. `ssl_tls_misuse.py` gets a thin `check()`-shaped wrapper added around its existing `_check_all`/`_analyze_apk` internals so it plugs into the same pipeline instead of having its own separate batch CLI.

## Phased build

**Phase 1 — Packaging skeleton.** `pyproject.toml` (deps: androguard, typer, pyyaml, python-dotenv, pandas, matplotlib, google-generativeai, streamlit, pytest; console script `mobsec = mobsec_scan.cli:app`), `src/mobsec_scan/` package layout, `git mv` the 4 detector scripts into `detectors/` with import fixes, `config.py` + `config.yaml`, `logging_config.py`. Verify: `pip install -e .` succeeds, `mobsec --help` lists subcommands.

**Phase 2 — Pipeline commands.** Port `run_batch_analysis.py` into `pipeline.py`; CLI gets `mobsec scan <apk>` (single-APK, all 4 checks, prints/saves one unified report) and `mobsec batch` (resumable batch over an `--apks-dir`, same skip-if-report-exists behavior, writes `results/summary.csv` + `flagged.txt` via `logging` instead of `print`). Verify: unit tests on detector functions using fixtures (hand-built manifest XML for `exported_components`, mocked `apk.get_permissions()`/fake dex corpus for the permission checks) since there's no local APK corpus to run against; `mobsec batch --help` / `mobsec scan --help` work.

**Phase 3 — `db.py` + `mobsec build-db`.** Move/generalize `sql_practice/build_database.py`'s parsing logic into `db.py` (same schema: `apps`, `rq4_scan`/`rq5_scan`/`rq7_scan` + child tables), add a `triage_results` table (app_id, rq, finding_ref, verdict, confidence, rationale, model, timestamp). Point `sql_practice/build_database.py` at the shared parser so there's one source of truth. Verify: `mobsec build-db` against the existing `results/*_report.txt` in the repo reproduces the current `compliance_findings.db` schema plus the new empty `triage_results` table.

**Phase 4 — Automated Gemini triage (`triage.py`, `mobsec triage`).** Reads un-triaged findings from the DB, sends each through the `google-generativeai` client using the same fixed prompt the README describes ("does this alert seem to be a false positive..."), parses TP/FP + short rationale, writes to `triage_results`, resumable (skips already-triaged rows), rate-limit/retry handling, reads `GEMINI_API_KEY` from `.env`. Verify: run for real against a handful of existing findings once the user has a key; confirm rows land in `triage_results` and are skipped on re-run.

**Phase 5 — Data analysis layer (`analysis.py`, `mobsec analyze`).** Pandas queries over the SQLite DB: per-RQ flag rate and (once triage data exists) precision, risk-level distribution, most common vulnerable permissions/components, apps with the most findings. Outputs matplotlib charts (PNG) + a generated `results/analysis/ANALYSIS.md` summary — this is the concrete "extra analysis step" deliverable. Verify: `mobsec analyze` runs against the DB built in Phase 3 from existing results and produces sensible, non-empty output.

**Phase 6 — Interactive dashboard (`dashboard.py`, `mobsec dashboard`).** Streamlit app: top KPI row (apps scanned, % flagged per RQ, precision once available), sidebar filters (RQ, risk level, app name search), a filterable findings table, and a drill-down view showing one app's full finding detail. `docs/DASHBOARD_DESIGN_NOTES.md` captures *why* it's laid out this way (KPIs-first, filter-then-drill-down, avoid overplotting) as the explicit dashboard-design learning artifact requested. Verify: `mobsec dashboard` launches Streamlit locally against the existing DB; manually click through filters/drill-down.

**Phase 7 — Tests, CI, Docker.** Flesh out `tests/` (detector logic via fixtures, `db.py` parsing, `analysis.py` stat functions) with pytest; `.github/workflows/ci.yml` runs `pytest` (+ `ruff check`) on push/PR; `Dockerfile` installs the package and its deps and sets `mobsec` as entrypoint. Verify: `pytest` green locally, CI workflow file is valid, `docker build .` succeeds and `docker run <image> mobsec --help` works.

**Phase 8 — README/docs pass.** Rewrite `README.md` around the unified `mobsec` CLI and the new architecture; keep the research write-up content (results table, methodology, precision numbers) intact but reframe the "Repository structure" section around the new package layout; note in the LLM-triage section that it's now automated via `mobsec triage`.

## Verification summary

- Detector correctness: pytest fixtures (no real APKs available), run in CI.
- Pipeline/DB/analysis correctness: run against the real, already-committed `results/*_report.txt` and `summary.csv` — no APKs needed for this.
- Triage correctness: real Gemini API call once the user adds `GEMINI_API_KEY` to `.env`.
- Dashboard: manual local click-through via `mobsec dashboard`.
- Packaging/CI/Docker: `pip install -e .`, `pytest`, `docker build`, and the GitHub Actions workflow syntax.
