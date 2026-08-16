# mobsec — Android Static Analysis, AI Triage & Reporting

[![CI](https://github.com/chrisjhwang/mobile-application-security-static-analysis/actions/workflows/ci.yml/badge.svg)](https://github.com/chrisjhwang/mobile-application-security-static-analysis/actions/workflows/ci.yml)

A packaged CLI tool (`mobsec`) that scans Android APKs for four classes of common,
high-impact vulnerabilities, automates a second-pass true/false-positive triage step
with Google Gemini, and turns the result into queryable data — a SQLite database, a
generated statistics report with charts, and an interactive dashboard.

It started as a CSCI 445 (Mobile Application Security) research project evaluating
**199 real-world Android APKs**, built with **Christine Hwang** and **Mia Skibinski**.
The research question and results below are unchanged from that project; what's new is
the delivery — a single installable tool instead of four standalone scripts, with the
LLM-triage step (previously manual copy/paste into Gemini) now a real API integration.

Full research write-up: [`hwang-skibinski-report.pdf`](hwang-skibinski-report.pdf)

## Why this project

Static analysis tools are core to mobile AppSec and vendor risk assessment programs,
but they are also notorious for false positives — and a compliance program that can't
distinguish a real control gap from benign noise doesn't hold up under audit. This
project treats that problem as the central research question rather than an
afterthought: every automated finding is run through a second-pass classification step
and a portion is hand-verified, and the resulting precision rate is reported alongside
the raw finding count for every check. That three-stage structure —
**automated detection → LLM triage → manual sampling** — mirrors how a
controls-testing or vulnerability-management program is expected to validate tooling
output before it goes into a risk register.

## What this project demonstrates

The same codebase supports two different ways of reading it:

**As a data/security analytics workflow** — a static analysis pipeline whose output is
explicitly treated as a hypothesis to validate rather than ground truth: measured
precision per check (RQ3 ~99.5% vs. RQ4 ~15.4%, a 6x spread on the same corpus),
risk-tiered findings (HIGH/MEDIUM/LOW, not a flat found/not-found flag), a normalized
SQLite schema built from real scan output for SQL analysis (`sql_practice/`), a
pandas/matplotlib statistics layer (`mobsec analyze`), and an interactive Streamlit
dashboard for filtering and drilling into findings (`mobsec dashboard`).

**As a packaged, operable tool** — `pip install`-able via a `pyproject.toml` with a
real console-script entry point, config-driven behavior (`config.yaml` — no code edits
needed to change which checks run), structured logging instead of `print`, a resumable
batch pipeline that survives interruption, a real third-party API integration
(Gemini) with retry/backoff and resumable state, 24 unit/integration tests runnable
without a real APK corpus, a GitHub Actions CI pipeline, and a Dockerfile.

See [Skills demonstrated](#skills-demonstrated) below for the detailed breakdown.

## Install

```bash
pip install -e .              # core: CLI, config, build-db, analyze
pip install -e '.[scan]'      # + androguard, for `mobsec scan` / `mobsec batch`
pip install -e '.[triage]'    # + google-genai, for `mobsec triage`
pip install -e '.[dash]'      # + streamlit, for `mobsec dashboard`
pip install -e '.[dev]'       # + pytest, ruff
pip install -e '.[all]'       # everything (what the Dockerfile installs)
```

Core dependencies are deliberately light — everything except APK decompilation itself
(`scan`/`batch`) runs without `androguard`, so `build-db`/`analyze`/tests work in a
minimal install.

For `mobsec triage`, copy `.env.example` to `.env` and add a Gemini API key from
[aistudio.google.com/apikey](https://aistudio.google.com/apikey):

```bash
cp .env.example .env
# edit .env: GEMINI_API_KEY=AIzaSy...
```

## Commands

```bash
mobsec show-config              # print resolved config — which checks are on, paths, etc.

mobsec scan path/to/app.apk     # run every enabled detector against one APK

mobsec batch                    # resumable batch run over the configured APK corpus
mobsec batch --limit 5          # only process the first N
mobsec batch --apks-dir DIR     # override the configured APK directory

mobsec build-db                 # parse results/*_report.txt into SQLite

mobsec triage --dry-run         # print Gemini prompts without calling the API
mobsec triage --limit 20        # triage the next 20 un-triaged findings

mobsec analyze                  # pandas stats + matplotlib charts + results/analysis/ANALYSIS.md

mobsec dashboard                # launch the interactive Streamlit dashboard
```

Which checks run, and where things get written, is controlled by `config.yaml` —
flip a detector's `enabled` flag there, no code change required. `mobsec batch` and
`mobsec build-db` are both resumable: interrupting and re-running only processes
what's missing.

**Not included in this repo:** the 199-APK dataset (provided under course license by
the instructor, not redistributable). Scripts that expect an `apks/` directory won't
find one here — everything downstream of the scan (`results/`, the SQLite database,
the analysis charts) is checked in as real output, generated from the actual corpus.

## Research questions and risk mapping

| # | Research question | Relevant framework / control mapping |
|---|---|---|
| 1–2 | Do apps disable TLS certificate/hostname validation via custom `TrustManager` / `HostnameVerifier` implementations? | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) (Improper Certificate Validation); OWASP MASVS-NETWORK |
| 3 | Do apps request `INTERNET` alongside dangerous/PII-adjacent permissions? | Attack-surface / data-exfiltration risk; OWASP MASVS-PRIVACY |
| 4 | Do apps declare permissions their code never actually uses? | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) (Unnecessary Privilege); principle of least privilege ([NIST 800-53 AC-6](https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-6/)) |
| 5 | Are exported Activities/Services/Receivers/Providers missing a real permission guard? | [CWE-926](https://cwe.mitre.org/data/definitions/926.html) (Improper Export of Android Application Components); OWASP MASVS-PLATFORM |

## Methodology

1. **Parse** — Each APK is decompiled with [Androguard](https://github.com/androguard/androguard) to expose its bytecode, manifest, and call graph.
2. **Detect** — A purpose-built detector per research question flags candidate findings against a defined ruleset (e.g., a class implementing `X509TrustManager` whose `checkServerTrusted` body is empty or trivially returns).
3. **Classify severity** — Where possible, findings are downgraded/upgraded automatically based on *reachability*: a custom `TrustManager` is only labeled **HIGH risk** if the analysis can trace it into a real TLS configuration call (`SSLContext.init(...)`, OkHttp's `sslSocketFactory(...)`, etc.). Otherwise it's **LOW risk** — syntactically suspicious but unconfirmed at runtime.
4. **LLM triage** — Every flagged alert is sent through `mobsec triage` to Google Gemini with a fixed prompt (*"does this alert seem to be a false positive, meaning the vulnerability is not actually exploitable..."*) and logged as a true/false positive in the database. This step was originally a manual copy/paste workflow; it is now a real, resumable API integration (`src/mobsec_scan/triage.py`).
5. **Manual validation** — A random ~10% sample of apps is hand-reviewed (via JADX-decompiled source) to compute how often the LLM's true/false-positive labels agree with human judgment — i.e., a **precision rate for the precision rate**.

## Results

| Experiment | Script output flagged | LLM true positives | Precision (LLM) | Precision (manual sample) |
|---|---|---|---|---|
| SSL/TLS misuse (RQ1–2) | 67/199 apps (33.67%) vulnerable | 69/199 apps (34.67%) | — | 86.15% of alerts agreed with manual review |
| Internet + PII permissions (RQ3) | 188 flagged instances (95% of apps) | 187 TP / 2 FP | 99.5% | Matched LLM analysis exactly |
| Unused/over-privileged permissions (RQ4) | 1,018 flagged instances (98% of apps) | 157 TP / 861 FP | 15.4% | 22.4% |
| Unprotected exported components (RQ5) | 1,100 flagged instances (66.3% of apps) | 906 TP / 178 FP | 82.4% | 92% |

The headline takeaway isn't "X% of apps are vulnerable" — it's the spread in those
precision numbers. Internet+PII combinations were almost always a real finding
(99.5%), but the unused-permissions check was wrong five times more often than it was
right (15.4% precision), largely because it didn't account for permissions satisfied
by third-party SDKs (OkHttp, Firebase, etc.) rather than app code directly. That gap
is the difference between a finding a risk register can act on and one that just
generates alert fatigue — and it's the reason the paper's own conclusion is that
**static findings need interpretation, not blind trust.** Full discussion, related
work (FlowDroid, TaintDroid, Stowaway), and limitations are in the
[paper](hwang-skibinski-report.pdf).

`mobsec analyze` recomputes flag rates and (as more findings get triaged) live
precision numbers straight from the database — `results/analysis/ANALYSIS.md` is
generated output, not hand-transcribed, so it can't drift from what's actually in
`sql_practice/compliance_findings.db`.

## Architecture

```
src/mobsec_scan/
├── cli.py          # Typer app: scan / batch / build-db / triage / analyze / dashboard
├── config.py        # loads config.yaml + .env
├── logging_config.py
├── pipeline.py       # scan/batch orchestration — decompiles once, runs every enabled detector
├── detectors/
│   ├── ssl_tls_misuse.py           # RQ1-2
│   ├── internet_pii_permissions.py # RQ3
│   ├── unused_permissions.py       # RQ4
│   └── exported_components.py      # RQ5
├── db.py            # parses results/*_report.txt into normalized SQLite
├── triage.py         # Gemini-based TP/FP triage of un-triaged findings
├── analysis.py        # pandas stats + matplotlib charts + ANALYSIS.md
└── dashboard.py        # Streamlit app
```

Each detector exposes a uniform `check(apk, dex_list, dx=None) -> dict` contract
(`found`, a `notes` string, plus check-specific detail keys) so `pipeline.py` can call
all of them the same way regardless of what they check. Risk tiering is a first-class
output, not a boolean — see `CLAUDE.md` for the detail on how each detector's
HIGH/MEDIUM/LOW/NONE classification works. Which detectors are active is entirely
config-driven (`config.yaml`); adding a fifth check means writing a `check()` function
and one config entry, not touching the orchestrator.

`sql_practice/` is a self-contained teaching artifact — `build_database.py` there is a
thin wrapper around `mobsec_scan.db`'s parser (one parser, two entry points), reshaping
the same real scan output into a normalized schema for SQL practice. See
`sql_practice/README.md` for the schema diagram and `sql_practice/EXERCISES.md` for 20
SQL exercises (Tier 1 SELECT/WHERE through Tier 6 CTEs/window functions) against real
data, not synthetic tables.

`docs/DASHBOARD_DESIGN_NOTES.md` documents the *why* behind the dashboard's layout
(KPIs-first, filter-then-drill-down as two separate views, no charts in the
interactive surface since `analyze`'s static report already owns that job).

## Testing, CI & Docker

```bash
pytest -v                 # 24 tests — detector logic, DB parsing, stats — no APK corpus needed
ruff check src tests      # linting

docker build -t mobsec .
docker run --rm mobsec --help
```

Tests run against hand-built fixtures (`tests/conftest.py`) that implement the exact
subset of androguard's APK/DEX interface each detector touches, rather than needing a
real APK — the same corpus-unavailability constraint that shapes `CLAUDE.md`. GitHub
Actions (`.github/workflows/ci.yml`) runs `ruff check` and `pytest` on every push/PR
across Python 3.10 and 3.12.

## Tools & stack

- **Python 3** / **[Androguard](https://github.com/androguard/androguard)** — APK decompilation, bytecode/manifest/call-graph analysis
- **Typer** — the `mobsec` CLI
- **Google Gemini** (`google-genai`) — automated second-pass true/false-positive classification
- **pandas / matplotlib** — statistics and charts (`mobsec analyze`)
- **Streamlit** — the interactive findings dashboard
- **SQLite** — normalized findings database, queryable directly or via `sql_practice/`
- **pytest / ruff** — tests and linting, enforced in CI
- **Docker / GitHub Actions** — containerized runtime, CI on every push/PR
- **JADX** — decompilation for manual verification
- Static analysis techniques adapted from **Mallodroid** (SSL/TLS misuse detection) and [DroidAnalysis](https://github.com/NDJSec/DroidAnalysis)

## Skills demonstrated

**Security & data analysis**
- Translating abstract security requirements (least privilege, certificate validation, component-level access control) into concrete, automatable detection rules
- Risk tiering findings (HIGH/MEDIUM/LOW/NONE) based on evidence strength rather than pattern-match alone
- Treating automated tool output as a hypothesis to validate, not a verdict — quantifying false-positive rates with a real LLM-assisted triage pipeline and stating precision alongside raw finding counts
- Normalizing unstructured tool output (plaintext reports) into a relational schema suited to SQL analysis, then building a statistics/reporting layer (pandas, matplotlib) and an interactive filtering/drill-down dashboard (Streamlit) on top of it
- Recognizing where a control mechanically "checks out" but isn't a real vulnerability (e.g., `MAIN`/`VIEW` launcher activities that must be exported, signature-level `BIND_*` service permissions) — the kind of contextual judgment that separates a compliance checklist from an effective assessment

**Systems & platform engineering**
- Packaging a set of standalone scripts into an installable tool with a real console-script entry point, layered optional dependencies, and config-driven behavior (no code edits to change what runs)
- Designing for fault isolation and resumability: a batch pipeline that survives interruption and skips completed work, a triage loop with per-item retry/backoff that doesn't let one failed API call abort a multi-hundred-item run, idempotent-by-full-rebuild database construction where that's the simpler correct choice
- Integrating a real third-party API (Gemini) end-to-end — prompt construction, structured-response parsing, retry/backoff, and persisted state — rather than mocking the integration
- Structured logging over `print`, so batch runs produce output that can be filtered, leveled, and redirected
- A test suite that runs without the corpus or heavy dependencies the full tool needs (verified directly, not assumed), an integration test written specifically to catch drift between two independently-editable modules — which caught a real regression before it shipped — and CI enforcing both lint and tests on every push
- Containerization and reproducible environment setup (Dockerfile, `.dockerignore`, optional-dependency groups)
