from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from mobsec_scan import analysis, db


def _build_test_db(tmp_path: Path) -> Path:
    """Two apps, hand-inserted directly against db.SCHEMA — one flagged on
    every check, one clean — so flag-rate math has a known answer (50%)."""
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(db.SCHEMA)

    conn.execute("INSERT INTO apps VALUES (1, 'FlaggedApp', 'flagged.apk', '2026-01-01 00:00:00')")
    conn.execute("INSERT INTO apps VALUES (2, 'CleanApp', 'clean.apk', '2026-01-01 00:00:00')")

    conn.execute(
        "INSERT INTO rq4_scan VALUES (1, 1, 0, 1, 'HIGH', 'flagged')"
    )
    conn.execute(
        "INSERT INTO rq4_scan VALUES (2, 1, 0, 0, 'NONE', 'clean')"
    )

    conn.execute("INSERT INTO rq5_scan VALUES (1, 'VULNERABLE', 'flagged')")
    conn.execute("INSERT INTO rq5_scan VALUES (2, 'CLEAN', 'clean')")
    conn.execute(
        "INSERT INTO rq5_unused_permissions (app_id, permission) VALUES (1, 'android.permission.CAMERA')"
    )

    conn.execute("INSERT INTO rq7_scan VALUES (1, 'VULNERABLE', 'flagged')")
    conn.execute("INSERT INTO rq7_scan VALUES (2, 'CLEAN', 'clean')")
    conn.execute(
        "INSERT INTO rq7_vulnerable_components (app_id, component_type, component_name, export_type, reason) "
        "VALUES (1, 'activity', '.Leaky', 'explicit', 'no guard')"
    )

    conn.execute(
        "INSERT INTO triage_results (app_id, rq, finding_ref, verdict, confidence, rationale, model, created_at) "
        "VALUES (1, 'rq4', 'rq4_scan:1', 'TP', 0.9, 'real issue', 'test-model', ?)",
        (datetime.now(timezone.utc).isoformat(),),
    )
    conn.execute(
        "INSERT INTO triage_results (app_id, rq, finding_ref, verdict, confidence, rationale, model, created_at) "
        "VALUES (1, 'rq4', 'rq4_scan:2', 'FP', 0.4, 'benign', 'test-model', ?)",
        (datetime.now(timezone.utc).isoformat(),),
    )

    conn.commit()
    conn.close()
    return db_path


def test_flag_rates_match_known_data(tmp_path):
    db_path = _build_test_db(tmp_path)
    stats = analysis.compute_stats(db_path)

    rates = stats["flag_rates"].set_index("rq")["flag_rate_pct"]
    assert rates["rq4"] == 50.0
    assert rates["rq5"] == 50.0
    assert rates["rq7"] == 50.0


def test_precision_computed_from_triage_results(tmp_path):
    db_path = _build_test_db(tmp_path)
    stats = analysis.compute_stats(db_path)

    precision = stats["precision"].set_index("rq")
    assert precision.loc["rq4", "tp"] == 1
    assert precision.loc["rq4", "fp"] == 1
    assert precision.loc["rq4", "precision_pct"] == 50.0


def test_precision_is_empty_dataframe_when_nothing_triaged(tmp_path):
    db_path = tmp_path / "empty.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(db.SCHEMA)
    conn.execute("INSERT INTO apps VALUES (1, 'App', 'app.apk', '2026-01-01')")
    conn.execute("INSERT INTO rq4_scan VALUES (1, 1, 0, 0, 'NONE', '')")
    conn.commit()
    conn.close()

    stats = analysis.compute_stats(db_path)
    assert stats["precision"].empty


def test_render_charts_and_markdown_produce_files(tmp_path):
    db_path = _build_test_db(tmp_path)
    stats = analysis.compute_stats(db_path)

    out_dir = tmp_path / "analysis"
    charts = analysis.render_charts(stats, out_dir)
    assert charts  # at least one chart, since flag_rates is non-empty
    for path in charts.values():
        assert path.exists()
        assert path.stat().st_size > 0

    md_path = out_dir / "ANALYSIS.md"
    analysis.write_markdown(stats, charts, md_path)
    text = md_path.read_text(encoding="utf-8")
    assert "Flag rate by check" in text
    assert "FlaggedApp" in text  # apps-with-most-findings table should surface it
