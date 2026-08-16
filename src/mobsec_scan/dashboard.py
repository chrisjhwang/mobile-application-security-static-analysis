"""Streamlit dashboard over the findings database.

Launched via `mobsec dashboard`, which shells out to `streamlit run` against
this file (Streamlit apps are their own runner — they re-execute this whole
script top-to-bottom on every interaction, which is why the DB reads below
are wrapped in `st.cache_data` keyed on the database's mtime).

Layout follows docs/DASHBOARD_DESIGN_NOTES.md: KPIs first, then
filter-before-you-drill-down, then a single-app detail view. Nothing here
computes new statistics — it's a UI over exactly the same queries
analysis.py already runs, so the numbers agree with `mobsec analyze` by
construction rather than by coincidence.
"""

from __future__ import annotations

import sqlite3

import pandas as pd
import streamlit as st

# `streamlit run` executes this file as a standalone script, not as part of
# the mobsec_scan package, so a relative import here would fail — the
# package still has to be import-able as an installed distribution.
from mobsec_scan.config import load_config

st.set_page_config(page_title="mobsec — findings dashboard", layout="wide")

cfg = load_config()


@st.cache_data(show_spinner=False)
def _load(db_path: str, _mtime: float) -> dict[str, pd.DataFrame]:
    conn = sqlite3.connect(db_path)
    try:
        tables = {
            "apps": "SELECT * FROM apps",
            "rq4_scan": "SELECT * FROM rq4_scan",
            "rq5_scan": "SELECT * FROM rq5_scan",
            "rq5_unused": "SELECT * FROM rq5_unused_permissions",
            "rq7_scan": "SELECT * FROM rq7_scan",
            "rq7_vulnerable": "SELECT * FROM rq7_vulnerable_components",
            "rq7_safe": "SELECT * FROM rq7_safe_exports",
            "triage": "SELECT * FROM triage_results",
        }
        return {name: pd.read_sql(query, conn) for name, query in tables.items()}
    finally:
        conn.close()


def _unified_findings(data: dict[str, pd.DataFrame]) -> pd.DataFrame:
    """One row per finding across all three checks, for the filterable table."""
    apps = data["apps"][["app_id", "app_name"]]
    rows = []

    rq4_flagged = data["rq4_scan"][data["rq4_scan"]["risk_level"] != "NONE"]
    rq4 = rq4_flagged.merge(apps, on="app_id")
    for _, r in rq4.iterrows():
        rows.append(
            {
                "rq": "rq4", "app_name": r["app_name"],
                "detail": f"INTERNET + {r['dangerous_count']} dangerous permission(s)",
                "risk_or_status": r["risk_level"],
            }
        )

    rq5 = data["rq5_unused"].merge(apps, on="app_id")
    for _, r in rq5.iterrows():
        rows.append(
            {"rq": "rq5", "app_name": r["app_name"], "detail": r["permission"], "risk_or_status": "UNUSED"}
        )

    rq7 = data["rq7_vulnerable"].merge(apps, on="app_id")
    for _, r in rq7.iterrows():
        rows.append(
            {
                "rq": "rq7", "app_name": r["app_name"],
                "detail": f"{r['component_type']}: {r['component_name']}",
                "risk_or_status": "UNPROTECTED",
            }
        )

    return pd.DataFrame(rows, columns=["rq", "app_name", "detail", "risk_or_status"])


def _kpi_row(data: dict[str, pd.DataFrame]) -> None:
    total = len(data["apps"])
    cols = st.columns(5)
    cols[0].metric("Apps scanned", total)

    rq4_pct = 100 * (data["rq4_scan"]["risk_level"] != "NONE").sum() / total if total else 0
    rq5_pct = 100 * (data["rq5_scan"]["status"] == "VULNERABLE").sum() / total if total else 0
    rq7_pct = 100 * (data["rq7_scan"]["status"] == "VULNERABLE").sum() / total if total else 0
    cols[1].metric("RQ4 flagged", f"{rq4_pct:.0f}%")
    cols[2].metric("RQ5 flagged", f"{rq5_pct:.0f}%")
    cols[3].metric("RQ7 flagged", f"{rq7_pct:.0f}%")

    triage = data["triage"]
    if triage.empty:
        cols[4].metric("Triage precision", "—", help="Run `mobsec triage` to populate this.")
    else:
        tp = (triage["verdict"] == "TP").sum()
        cols[4].metric("Triage precision", f"{100 * tp / len(triage):.0f}%", help=f"{len(triage)} findings triaged")


def _findings_table(data: dict[str, pd.DataFrame]) -> None:
    st.subheader("Findings")
    unified = _unified_findings(data)

    with st.sidebar:
        st.header("Filters")
        rq_choice = st.multiselect("Check", options=["rq4", "rq5", "rq7"], default=["rq4", "rq5", "rq7"])
        search = st.text_input("App name contains")

    filtered = unified[unified["rq"].isin(rq_choice)]
    if search:
        filtered = filtered[filtered["app_name"].str.contains(search, case=False, na=False)]

    st.caption(f"{len(filtered)} of {len(unified)} findings shown")
    st.dataframe(filtered, width="stretch", height=400)


def _drilldown(data: dict[str, pd.DataFrame]) -> None:
    st.subheader("App detail")
    app_names = sorted(data["apps"]["app_name"].unique())
    if not app_names:
        st.info("No apps in the database yet. Run `mobsec build-db` first.")
        return

    choice = st.selectbox("Pick an app", app_names)
    app_row = data["apps"][data["apps"]["app_name"] == choice].iloc[0]
    app_id = app_row["app_id"]

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("**RQ4 — Internet + PII**")
        rq4 = data["rq4_scan"][data["rq4_scan"]["app_id"] == app_id]
        if rq4.empty:
            st.write("Not run.")
        else:
            r = rq4.iloc[0]
            st.write(f"Risk level: **{r['risk_level']}**")
            st.write(f"Internet: {'yes' if r['has_internet'] else 'no'}")
            st.caption(r["notes"] or "")

    with col2:
        st.markdown("**RQ5 — Unused permissions**")
        rq5 = data["rq5_unused"][data["rq5_unused"]["app_id"] == app_id]
        if rq5.empty:
            st.write("None flagged.")
        else:
            st.dataframe(rq5[["permission"]], hide_index=True, width="stretch")

    with col3:
        st.markdown("**RQ7 — Unprotected exports**")
        rq7 = data["rq7_vulnerable"][data["rq7_vulnerable"]["app_id"] == app_id]
        if rq7.empty:
            st.write("None flagged.")
        else:
            st.dataframe(
                rq7[["component_type", "component_name", "reason"]], hide_index=True, width="stretch"
            )

    triage = data["triage"][data["triage"]["app_id"] == app_id]
    if not triage.empty:
        st.markdown("**Triage verdicts for this app**")
        st.dataframe(
            triage[["rq", "finding_ref", "verdict", "confidence", "rationale"]],
            hide_index=True, width="stretch",
        )


def main() -> None:
    st.title("mobsec — compliance findings dashboard")

    if not cfg.database.exists():
        st.error(f"No database at {cfg.database}. Run `mobsec build-db` first.")
        return

    data = _load(str(cfg.database), cfg.database.stat().st_mtime)

    _kpi_row(data)
    st.divider()
    _findings_table(data)
    st.divider()
    _drilldown(data)


main()
