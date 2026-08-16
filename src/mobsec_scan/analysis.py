"""Statistics, charts and a markdown summary over the findings database.

Everything here reads `cfg.database` (built by `mobsec build-db`) with
pandas and writes to `cfg.analysis_dir`: a handful of PNG charts plus a
generated `ANALYSIS.md` that links them alongside the same summary tables in
plain markdown. This is the "extra analysis layer" on top of raw per-app
reports — flag rates, risk distribution, the most commonly implicated
permissions/components, and (once `mobsec triage` has run) measured
precision per detector, the same number the paper reports but computed live
off however much of the corpus has actually been triaged so far.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # headless — this runs from a CLI, never a GUI session
import matplotlib.pyplot as plt
import pandas as pd

from .config import Config
from .logging_config import get_logger

logger = get_logger("analysis")

_RQ_LABELS = {
    "rq4": "RQ4 — Internet + PII Permissions",
    "rq5": "RQ5 — Unused Permissions",
    "rq7": "RQ7 — Unprotected Exported Components",
}


def _flag_rates(conn: sqlite3.Connection) -> pd.DataFrame:
    total = pd.read_sql("SELECT COUNT(*) AS n FROM apps", conn).iloc[0]["n"]
    rows = []
    for rq, query in [
        ("rq4", "SELECT COUNT(*) AS n FROM rq4_scan WHERE risk_level != 'NONE'"),
        ("rq5", "SELECT COUNT(*) AS n FROM rq5_scan WHERE status = 'VULNERABLE'"),
        ("rq7", "SELECT COUNT(*) AS n FROM rq7_scan WHERE status = 'VULNERABLE'"),
    ]:
        flagged = pd.read_sql(query, conn).iloc[0]["n"]
        rows.append(
            {
                "rq": rq,
                "label": _RQ_LABELS[rq],
                "flagged": int(flagged),
                "total": int(total),
                "flag_rate_pct": round(100 * flagged / total, 1) if total else 0.0,
            }
        )
    return pd.DataFrame(rows)


def _risk_distribution(conn: sqlite3.Connection) -> pd.DataFrame:
    return pd.read_sql(
        "SELECT risk_level, COUNT(*) AS n FROM rq4_scan GROUP BY risk_level ORDER BY n DESC", conn
    )


def _top_unused_permissions(conn: sqlite3.Connection, n: int = 10) -> pd.DataFrame:
    return pd.read_sql(
        "SELECT permission, COUNT(*) AS n FROM rq5_unused_permissions "
        "GROUP BY permission ORDER BY n DESC LIMIT ?",
        conn,
        params=(n,),
    )


def _top_vulnerable_components(conn: sqlite3.Connection, n: int = 10) -> pd.DataFrame:
    return pd.read_sql(
        "SELECT component_type, COUNT(*) AS n FROM rq7_vulnerable_components "
        "GROUP BY component_type ORDER BY n DESC LIMIT ?",
        conn,
        params=(n,),
    )


def _apps_with_most_findings(conn: sqlite3.Connection, n: int = 10) -> pd.DataFrame:
    return pd.read_sql(
        """
        SELECT a.app_name,
               COALESCE(u.unused, 0) AS rq5_unused,
               COALESCE(v.vulnerable, 0) AS rq7_vulnerable,
               COALESCE(u.unused, 0) + COALESCE(v.vulnerable, 0) AS total_findings
        FROM apps a
        LEFT JOIN (
            SELECT app_id, COUNT(*) AS unused FROM rq5_unused_permissions GROUP BY app_id
        ) u ON u.app_id = a.app_id
        LEFT JOIN (
            SELECT app_id, COUNT(*) AS vulnerable FROM rq7_vulnerable_components GROUP BY app_id
        ) v ON v.app_id = a.app_id
        ORDER BY total_findings DESC
        LIMIT ?
        """,
        conn,
        params=(n,),
    )


def _precision(conn: sqlite3.Connection) -> pd.DataFrame:
    df = pd.read_sql(
        "SELECT rq, verdict, COUNT(*) AS n FROM triage_results GROUP BY rq, verdict", conn
    )
    if df.empty:
        return pd.DataFrame(columns=["rq", "label", "tp", "fp", "triaged", "precision_pct"])

    pivot = df.pivot_table(index="rq", columns="verdict", values="n", fill_value=0)
    for col in ("TP", "FP"):
        if col not in pivot.columns:
            pivot[col] = 0
    pivot = pivot.reset_index()
    pivot["triaged"] = pivot["TP"] + pivot["FP"]
    pivot["precision_pct"] = (100 * pivot["TP"] / pivot["triaged"]).round(1)
    pivot["label"] = pivot["rq"].map(_RQ_LABELS)
    return pivot.rename(columns={"TP": "tp", "FP": "fp"})[
        ["rq", "label", "tp", "fp", "triaged", "precision_pct"]
    ]


def compute_stats(db_path: Path) -> dict[str, pd.DataFrame]:
    conn = sqlite3.connect(db_path)
    try:
        return {
            "flag_rates": _flag_rates(conn),
            "risk_distribution": _risk_distribution(conn),
            "top_unused_permissions": _top_unused_permissions(conn),
            "top_vulnerable_components": _top_vulnerable_components(conn),
            "apps_with_most_findings": _apps_with_most_findings(conn),
            "precision": _precision(conn),
        }
    finally:
        conn.close()


# ── Charts ───────────────────────────────────────────────────────────────────

def _save_bar(df: pd.DataFrame, x: str, y: str, title: str, xlabel: str, out_path: Path, horizontal: bool = False) -> None:
    fig, ax = plt.subplots(figsize=(8, 5))
    if horizontal:
        ax.barh(df[x].astype(str), df[y])
        ax.invert_yaxis()
        ax.set_xlabel(xlabel)
    else:
        ax.bar(df[x].astype(str), df[y])
        ax.set_ylabel(xlabel)
        plt.xticks(rotation=20, ha="right")
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def render_charts(stats: dict[str, pd.DataFrame], out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    charts: dict[str, Path] = {}

    if not stats["flag_rates"].empty:
        path = out_dir / "flag_rates.png"
        _save_bar(stats["flag_rates"], "rq", "flag_rate_pct", "Flag rate by check (%)", "% of apps flagged", path)
        charts["flag_rates"] = path

    if not stats["risk_distribution"].empty:
        path = out_dir / "rq4_risk_distribution.png"
        _save_bar(stats["risk_distribution"], "risk_level", "n", "RQ4 risk level distribution", "Apps", path)
        charts["risk_distribution"] = path

    if not stats["top_unused_permissions"].empty:
        path = out_dir / "top_unused_permissions.png"
        _save_bar(
            stats["top_unused_permissions"], "permission", "n",
            "Most common unused permissions (RQ5)", "Occurrences", path, horizontal=True,
        )
        charts["top_unused_permissions"] = path

    if not stats["top_vulnerable_components"].empty:
        path = out_dir / "top_vulnerable_components.png"
        _save_bar(
            stats["top_vulnerable_components"], "component_type", "n",
            "Unprotected exported components by type (RQ7)", "Occurrences", path,
        )
        charts["top_vulnerable_components"] = path

    if not stats["precision"].empty:
        path = out_dir / "precision.png"
        _save_bar(stats["precision"], "rq", "precision_pct", "Measured LLM triage precision (%)", "Precision %", path)
        charts["precision"] = path

    return charts


# ── Markdown report ──────────────────────────────────────────────────────────

def _df_to_markdown(df: pd.DataFrame) -> str:
    if df.empty:
        return "_No data yet._\n"
    return df.to_markdown(index=False) + "\n"


def write_markdown(stats: dict[str, pd.DataFrame], charts: dict[str, Path], out_path: Path) -> None:
    lines = ["# Analysis summary", ""]

    lines += ["## Flag rate by check", "", _df_to_markdown(stats["flag_rates"])]
    if "flag_rates" in charts:
        lines += [f"![Flag rates]({charts['flag_rates'].name})", ""]

    lines += ["## RQ4 risk level distribution", "", _df_to_markdown(stats["risk_distribution"])]
    if "risk_distribution" in charts:
        lines += [f"![RQ4 risk distribution]({charts['risk_distribution'].name})", ""]

    lines += ["## Most common unused permissions (RQ5)", "", _df_to_markdown(stats["top_unused_permissions"])]
    if "top_unused_permissions" in charts:
        lines += [f"![Top unused permissions]({charts['top_unused_permissions'].name})", ""]

    lines += ["## Unprotected exported components by type (RQ7)", "", _df_to_markdown(stats["top_vulnerable_components"])]
    if "top_vulnerable_components" in charts:
        lines += [f"![Top vulnerable components]({charts['top_vulnerable_components'].name})", ""]

    lines += ["## Apps with the most findings", "", _df_to_markdown(stats["apps_with_most_findings"])]

    lines += ["## Measured triage precision", ""]
    if stats["precision"].empty:
        lines += ["_No findings triaged yet — run `mobsec triage`._", ""]
    else:
        lines += [_df_to_markdown(stats["precision"])]
        if "precision" in charts:
            lines += [f"![Precision]({charts['precision'].name})", ""]

    out_path.write_text("\n".join(lines), encoding="utf-8")


def run_analysis(cfg: Config) -> dict[str, Path]:
    if not cfg.database.exists():
        raise RuntimeError(f"No database at {cfg.database}. Run `mobsec build-db` first.")

    stats = compute_stats(cfg.database)
    charts = render_charts(stats, cfg.analysis_dir)
    md_path = cfg.analysis_dir / "ANALYSIS.md"
    write_markdown(stats, charts, md_path)
    logger.info("Analysis written to %s (%d chart(s))", md_path, len(charts))
    return {"markdown": md_path, **charts}
