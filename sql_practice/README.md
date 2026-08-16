# SQL Practice — Compliance Findings Database

A SQLite database built directly from this project's real scan output
(`results/*_report.txt`, 199 Android APKs), for practicing SQL against realistic,
messy, security-compliance-flavored data.

## Contents

| File | What it is |
|---|---|
| `build_database.py` | Parses `../results/*_report.txt` into `compliance_findings.db`. Re-run anytime — it rebuilds from scratch. |
| `compliance_findings.db` | The SQLite database (10 tables, ~4,600 finding rows across 199 apps). |
| `EXERCISES.md` | 20 SQL exercises, Tier 1 (SELECT/WHERE) through Tier 6 (CTEs, window functions, audit-style reporting). |
| `ANSWERS.sql` | Worked solutions for every exercise — verified to run against this database. |

## Provenance

This is **not** synthetic data. It's a direct parse of the plaintext reports that
`run_batch_analysis.py` already writes to `results/` — same findings, same permission
names, same exported-component names, just reshaped into normalized tables instead of
per-app text files. Nothing was invented; a few numbers (like RQ7's 66.3% flag rate)
land exactly on the figures reported in the paper because this results set is the same
underlying scan, just structured for querying.

This particular `results/` run only has RQ4, RQ5, and RQ7 (no SSL/TLS/RQ1-2 data,
since `ACTIVE_RQS` in `run_batch_analysis.py` had those commented out for this run) —
so the database reflects that scope.

## Quick start

```bash
cd sql_practice
sqlite3 compliance_findings.db
.tables
.schema rq7_vulnerable_components
SELECT app_name, risk_level FROM apps JOIN rq4_scan USING(app_id) LIMIT 5;
```

Then work through `EXERCISES.md`.

## Schema at a glance

```
apps (app_id, app_name, file_name, analyzed_at)
  │
  ├─ rq4_scan (app_id, has_internet, normal_count, dangerous_count, risk_level, notes)
  │    ├─ rq4_permissions (app_id, permission, permission_type)
  │    └─ rq4_permission_evidence (app_id, permission, call_site)
  │
  ├─ rq5_scan (app_id, status, notes)
  │    ├─ rq5_unused_permissions (app_id, permission)
  │    ├─ rq5_used_permissions (app_id, permission)
  │    └─ rq5_used_permission_evidence (app_id, permission, call_site)
  │
  └─ rq7_scan (app_id, status, notes)
       ├─ rq7_vulnerable_components (app_id, component_type, component_name, export_type, reason)
       └─ rq7_safe_exports (app_id, component_type, component_name, safe_reason)
```

Every `*_scan` table is one row per app (the summary). Every other table is one row per
individual finding — that's where the JOINs and GROUP BYs in the exercises come from.
