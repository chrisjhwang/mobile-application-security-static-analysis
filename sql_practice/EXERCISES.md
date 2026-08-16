# SQL Practice — Compliance Findings Database

This database (`compliance_findings.db`) is built from the **real** per-app output of
`run_batch_analysis.py` — 199 Android APKs, each scanned for three risks (see the main
[README](../README.md)):

| Check | What it flags | Tables |
|---|---|---|
| RQ4 | `INTERNET` combined with normal/dangerous PII-adjacent permissions | `rq4_scan`, `rq4_permissions`, `rq4_permission_evidence` |
| RQ5 | Declared permissions with no matching API call found in code (over-privileged) | `rq5_scan`, `rq5_unused_permissions`, `rq5_used_permissions`, `rq5_used_permission_evidence` |
| RQ7 | `android:exported="true"` components with no real permission guard | `rq7_scan`, `rq7_vulnerable_components`, `rq7_safe_exports` |

Every app also has one row in `apps`. Rebuild anytime with `python build_database.py`
(safe to re-run — it drops and recreates the file).

**Note on data quality:** this is real static-analysis output, not a cleaned teaching
dataset — permissions like `INTERNET` and `ACCESS_NETWORK_STATE` show up hundreds of
times in `rq5_unused_permissions` because the detector doesn't know they're satisfied by
third-party SDKs (OkHttp, Firebase, etc.), exactly as the paper's own limitations section
describes. That's a feature for this exercise: a GRC analyst's job is partly to notice
when a "finding" is really a tooling gap, and you'll see that noise directly in your
query results.

## How to open it

```bash
sqlite3 compliance_findings.db
.tables
.schema apps
```

Or use any GUI SQLite browser (DB Browser for SQLite, TablePlus, DataGrip, VS Code SQLite
extension). Everything below works in plain SQLite.

---

## Tier 1 — SELECT, WHERE, ORDER BY

1. List all columns from `apps` for the first 10 apps, alphabetically by name.
2. Find every app where `rq4_scan.risk_level = 'HIGH'`.
3. Find every unique `permission` value in `rq5_unused_permissions` that contains the
   word `LOCATION`.
4. How many rows are in `rq7_vulnerable_components` where `component_type = 'provider'`?
   (Content providers are the highest-impact export type — think database/file access.)
5. List the 10 apps with the fewest total permissions requested via `rq4_scan`
   (`normal_count + dangerous_count`), ascending.

## Tier 2 — Aggregates, GROUP BY, HAVING

6. Count how many apps fall into each `rq4_scan.risk_level` bucket. Which bucket has the
   most apps?
7. For each `component_type` in `rq7_vulnerable_components`, count total flagged
   instances. Which component type is unguarded most often — and does that match your
   intuition about which one matters most (a provider vs. a launcher activity)?
8. Find the 10 permissions that appear most often in `rq5_unused_permissions`
   (`GROUP BY permission ORDER BY COUNT(*) DESC`). Do any of these look like they're
   probably satisfied by a third-party SDK rather than genuinely unused? (Compare against
   the README's discussion of RQ4's false-positive cause.)
9. Using `HAVING`, find apps in `rq7_vulnerable_components` with more than 20 flagged
   exported components. These are your highest-priority remediation targets — a real risk
   register would triage these first.

## Tier 3 — JOINs

10. Join `apps` to `rq4_scan` and list app name + risk level for every app with
    `risk_level = 'HIGH'`.
11. Join `apps` to `rq7_vulnerable_components`, and count unguarded components per app.
    Show the top 10 apps, app name next to count (you did a version of this as a sanity
    check in the build script — now write it yourself with an explicit `JOIN`).
12. Join `rq4_permissions` to `rq4_permission_evidence` on `app_id` AND `permission` to
    see which dangerous permissions have actual call-site evidence attached versus which
    ones don't (`LEFT JOIN` + `IS NULL` check). A permission with no call-site evidence in
    this dataset is a weaker finding — flag it as needing manual review, the same
    reasoning the report's methodology used before sending anything to Gemini.

## Tier 4 — Subqueries & set logic

13. Find apps that appear in `rq5_scan` with `status = 'VULNERABLE'` **and** in
    `rq7_scan` with `status = 'VULNERABLE'` — i.e., apps with *compounding* risk across
    two independent checks — using a subquery (`WHERE app_id IN (SELECT ...)`).
14. Do the same query as #13 but using `INTERSECT` instead of a subquery. Compare the
    two approaches.
15. Find apps that are flagged `VULNERABLE` on RQ7 but have **zero** rows in
    `rq7_safe_exports` — meaning every single exported component in that app is
    unguarded, with no safe-by-design exceptions at all. These are candidates for "is
    this app doing anything sensible with exports at all?"

## Tier 5 — CTEs & window functions

16. Write a CTE that computes, per app, the count of flagged findings across all three
    checks (RQ4 HIGH/MEDIUM, RQ5 unused count, RQ7 vulnerable count), then rank apps by
    total finding count using `RANK() OVER (ORDER BY total_findings DESC)`. This is your
    "risk register," sorted by combined exposure — the artifact a GRC analyst would
    actually hand to an engineering lead.
17. Using a window function, compute what percentage of all `rq5_unused_permissions`
    rows each individual permission accounts for (`COUNT(*) OVER ()` as the denominator).
    Which single permission is responsible for the largest share of "findings" in this
    check — and does that concentration change how you'd interpret the check's 15.4%
    precision rate reported in the paper?
18. For each `component_type`, use `PERCENT_RANK()` or `NTILE(4)` to bucket apps into
    quartiles by how many vulnerable components of that type they have.

## Tier 6 — Building compliance artifacts

19. Write a single query that produces a "control testing summary" table: one row per
    RQ (RQ4/RQ5/RQ7), with columns for apps tested, apps flagged, and flag rate as a
    percentage. This should reproduce the percentages the paper/README report
    (95%, 98%, 66.3%) — see if your numbers land close, and if they differ, investigate
    why (this results folder is a partial re-run using only RQ4/RQ5/RQ7, not the
    original 199-app SSL/TLS pass — a good example of why an auditor always checks
    the population before trusting a percentage).
20. Write a query an auditor could actually use: for a given `app_name` (parameterize
    it), return every finding across all three checks in one result set (`UNION ALL`
    across the three finding tables, normalized to `app_id, check_name, finding_detail`
    columns). This is the shape of a real "evidence export" for a single control test.

---

Answers are in [`ANSWERS.sql`](ANSWERS.sql) — try each exercise yourself first, running it
against `compliance_findings.db`, before checking.
