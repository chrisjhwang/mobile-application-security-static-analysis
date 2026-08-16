# Dashboard design notes

Why `dashboard.py` is laid out the way it is, not just what it does. Written as a
design-principle record, same spirit as `docs/GLOSSARY.md`.

## KPIs first, not charts first

The top of the page is five `st.metric()` numbers — apps scanned, % flagged per check,
triage precision — before any table or chart. The instinct to lead with a chart is
strong, but a chart forces the viewer to *find* the number themselves by reading axes;
a KPI row states it. Anyone glancing at this dashboard for five seconds (a reviewer,
an instructor, a hiring manager) should walk away with the headline numbers without
scrolling or interpreting anything. Detail is available below for whoever wants it,
but it's opt-in, not the first thing on screen.

## Filter, then drill down — never both at once

The findings table (filterable, one row per finding, all checks mixed together) and
the single-app detail view are two different jobs, kept in two different sections
rather than merged into one clever mega-widget:

- The **findings table** answers "show me findings matching X" — a search/filter task
  over the whole corpus. Its output is necessarily flat and denormalized (one row per
  finding, `rq`/`app_name`/`detail`/`risk_or_status`) because filtering only works
  cleanly against a uniform shape.
- The **drill-down** answers a completely different question — "tell me everything
  about *this one app*" — which needs the *opposite* shape: three separate,
  structured views (one per check) side by side, because RQ4/RQ5/RQ7 findings aren't
  comparable to each other and shouldn't be forced into the same columns.

Trying to make one widget do both (e.g. a giant sortable table with expandable rows)
would compromise both jobs — the flat table would carry columns that are empty for
most rows, and the detail view would lose the per-check structure that makes it
readable. Splitting them is deliberate, not incidental.

## Avoid overplotting

There's exactly one chart-shaped decision made anywhere in this file: none. All
numeric summaries here are `st.metric()` or `st.dataframe()`, not `st.bar_chart()` —
that's a deliberate difference from `analysis.py`, which *does* render matplotlib bar
charts for the same underlying stats. The reasoning: `mobsec analyze`'s output
(`ANALYSIS.md` + PNGs) is a **static artifact** meant to be read once, linearly, like
a report — charts communicate a distribution shape well in that format. The
**dashboard** is interactive and filtered live by the user; a chart that redraws on
every keystroke in the search box is distracting motion for no informational gain
when a number or a table row count already says the same thing more precisely. Same
underlying numbers, different presentation because the two surfaces are read
differently.

## One source of truth for the numbers

`dashboard.py` doesn't recompute anything `analysis.py` already computes — the KPI
row uses the same `risk_level != 'NONE'` / `status == 'VULNERABLE'` logic against the
same tables. Verified directly: `mobsec analyze`'s flag-rate table and the
dashboard's KPI row agree exactly (98% / 98% / 66.3%) against the same database
snapshot. If they ever disagreed, that would mean a bug in one of the two, not two
legitimately different numbers — so keeping the query logic simple and consistent
between the static report and the live dashboard is worth the small duplication
of the actual SQL, rather than trying to share code across two tools with very
different execution models (a batch script vs. a script Streamlit re-executes on
every UI interaction).

## Caching is about the database file, not the session

`_load()` is wrapped in `st.cache_data`, keyed on `(db_path, db_path.stat().st_mtime)`
rather than just the path. Streamlit re-runs this entire script top-to-bottom on
every widget interaction (every filter change, every drill-down selection) — without
caching, that means re-reading and re-joining ~2,400 rows from SQLite on every
keystroke in the search box. Keying the cache on mtime rather than caching forever
means the moment someone re-runs `mobsec build-db` (new scan results, or after
`mobsec triage` adds verdicts), the dashboard picks up the fresh data on its next
interaction instead of serving a stale snapshot from before the rebuild.
