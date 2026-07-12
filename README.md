# Android Static Analysis: SSL/TLS Misuse, Permission Risk, and Exported Component Exposure

A CSCI 445 (Mobile Application Security) research project evaluating **199 real-world Android APKs** for four classes of common, high-impact vulnerabilities. Built with **Christine Hwang** and **Mia Skibinski**.

The project pairs custom Androguard-based static analysis with LLM-assisted triage (Google Gemini) and manual verification, to answer a question that matters as much for compliance as it does for engineering: *when a scanner flags something, how much of that is a real finding versus noise?*

Full write-up: [`hwang-skibinski-report.pdf`](hwang-skibinski-report.pdf)

## Why this project

Static analysis tools are core to mobile AppSec and vendor risk assessment programs, but they are also notorious for false positives — and a compliance program that can't distinguish a real control gap from benign noise doesn't hold up under audit. This project treats that problem as the central research question rather than an afterthought: every automated finding is run through a second-pass classification step and a portion is hand-verified, and the resulting precision rate is reported alongside the raw finding count for every check. That three-stage structure — **automated detection → LLM triage → manual sampling** — mirrors how a controls-testing or vulnerability-management program is expected to validate tooling output before it goes into a risk register.

## Research questions and risk mapping

| # | Research question | Relevant framework / control mapping |
|---|---|---|
| 1–2 | Do apps disable TLS certificate/hostname validation via custom `TrustManager` / `HostnameVerifier` implementations? | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) (Improper Certificate Validation); OWASP MASVS-NETWORK |
| 3 | Do apps request `INTERNET` alongside dangerous/PII-adjacent permissions? | Attack-surface / data-exfiltration risk; OWASP MASVS-PRIVACY |
| 4 | Do apps declare permissions their code never actually uses? | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) (Unnecessary Privilege); principle of least privilege ([NIST 800-53 AC-6](https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-6/)) |
| 5 | Are exported Activities/Services/Receivers/Providers missing a real permission guard? | [CWE-926](https://cwe.mitre.org/data/definitions/926.html) (Improper Export of Android Application Components); OWASP MASVS-PLATFORM |

## Methodology

1. **Parse** — Each APK is decompiled with [Androguard](https://github.com/androguard/androguard) to expose its bytecode, manifest, and call graph.
2. **Detect** — A purpose-built script per research question flags candidate findings against a defined ruleset (e.g., a class implementing `X509TrustManager` whose `checkServerTrusted` body is empty or trivially returns).
3. **Classify severity** — Where possible, findings are downgraded/upgraded automatically based on *reachability*: a custom `TrustManager` is only labeled **HIGH risk** if the analysis can trace it into a real TLS configuration call (`SSLContext.init(...)`, OkHttp's `sslSocketFactory(...)`, etc.). Otherwise it's **LOW risk** — syntactically suspicious but unconfirmed at runtime.
4. **LLM triage** — Every flagged alert is sent to Google Gemini with a fixed prompt (e.g., *"does this alert seem to be a false positive, meaning the vulnerability is not actually exploitable..."*) and logged as a true/false positive.
5. **Manual validation** — A random ~10% sample of apps is hand-reviewed (via JADX-decompiled source) to compute how often the LLM's true/false-positive labels agree with human judgment — i.e., a **precision rate for the precision rate**.

## Results

| Experiment | Script output flagged | LLM true positives | Precision (LLM) | Precision (manual sample) |
|---|---|---|---|---|
| SSL/TLS misuse (RQ1–2) | 67/199 apps (33.67%) vulnerable | 69/199 apps (34.67%) | — | 86.15% of alerts agreed with manual review |
| Internet + PII permissions (RQ3) | 188 flagged instances (95% of apps) | 187 TP / 2 FP | 99.5% | Matched LLM analysis exactly |
| Unused/over-privileged permissions (RQ4) | 1,018 flagged instances (98% of apps) | 157 TP / 861 FP | 15.4% | 22.4% |
| Unprotected exported components (RQ5) | 1,100 flagged instances (66.3% of apps) | 906 TP / 178 FP | 82.4% | 92% |

The headline takeaway isn't "X% of apps are vulnerable" — it's the spread in those precision numbers. Internet+PII combinations were almost always a real finding (99.5%), but the unused-permissions check was wrong five times more often than it was right (15.4% precision), largely because it didn't account for permissions satisfied by third-party SDKs (OkHttp, Firebase, etc.) rather than app code directly. That gap is the difference between a finding a risk register can act on and one that just generates alert fatigue — and it's the reason the paper's own conclusion is that **static findings need interpretation, not blind trust.** Full discussion, related work (FlowDroid, TaintDroid, Stowaway), and limitations are in the [paper](hwang-skibinski-report.pdf).

## Repository structure

| File | Research question | What it does |
|---|---|---|
| [`ssl_tls_misuse_scan.py`](ssl_tls_misuse_scan.py) | RQ1–2 | Detects custom `TrustManager`/`HostnameVerifier` classes, classifies them HIGH/LOW risk based on traced runtime reachability into TLS setup code, and writes a per-APK findings report (adapted from [DroidAnalysis](https://github.com/NDJSec/DroidAnalysis), which builds on [Mallodroid](https://github.com/sfahl/mallodroid)). Has its own CLI for single-file or batch (directory) runs. |
| [`internet_pii_permissions.py`](internet_pii_permissions.py) | RQ3 | Flags apps combining `INTERNET` with normal/dangerous/hard-restricted permissions and assigns a HIGH/MEDIUM/LOW/NONE risk level; optionally locates call-site evidence for each dangerous permission. |
| [`unused_permissions.py`](unused_permissions.py) | RQ4 | Maps each declared permission to the API patterns that would prove it's actually used, then flags permissions declared but never referenced in code. |
| [`exported_components.py`](exported_components.py) | RQ5 | Parses `AndroidManifest.xml` for exported Activities/Services/Receivers/Providers, filters out well-known safe-by-design export patterns (e.g., `MAIN`/`VIEW` launcher intents, signature-level `BIND_*` permissions), and flags what's left. |
| [`run_batch_analysis.py`](run_batch_analysis.py) | RQ3–5 | Orchestrator that runs the three scripts above across every APK in `apks/`, writing a per-app report, a `summary.csv`, and a `flagged.txt` rollup to `results/`. Resumable — already-processed APKs are skipped on rerun. |
| [`hwang-skibinski-report.pdf`](hwang-skibinski-report.pdf) | — | Full paper: methodology, related work, complete results tables, and discussion of limitations. |

Each of the four detection scripts also runs standalone against a single APK (`python <script>.py path/to/app.apk`) for spot-checking one app without a full batch run.

**Not included in this repo:** the 199-APK dataset (provided under course license by the instructor, not redistributable) and the LLM-triage step (done by manually prompting Gemini with each script's plaintext output — not an automated API integration in this codebase).

## Tools & stack

- **Python 3** / **[Androguard](https://github.com/androguard/androguard)** — APK decompilation, bytecode/manifest/call-graph analysis
- **Google Gemini** — second-pass true/false-positive classification (manual prompting workflow)
- **JADX** — decompilation for manual verification
- Static analysis techniques adapted from **Mallodroid** (SSL/TLS misuse detection)

## Skills demonstrated

- Translating abstract security requirements (least privilege, certificate validation, component-level access control) into concrete, automatable detection rules
- Risk tiering findings (HIGH/MEDIUM/LOW/NONE) based on evidence strength rather than pattern-match alone
- Treating automated tool output as a hypothesis to validate, not a verdict — quantifying false-positive rates and stating them alongside the findings
- Structured, reproducible reporting (per-app findings, CSV rollups, batch summaries) suited to audit trails and evidence collection
- Recognizing where a control mechanically "checks out" but isn't a real vulnerability (e.g., `MAIN`/`VIEW` launcher activities that must be exported, signature-level `BIND_*` service permissions) — the kind of contextual judgment that separates a compliance checklist from an effective assessment
