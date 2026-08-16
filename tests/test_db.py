"""Round-trips pipeline.format_report()'s output through db.build_database().

This is deliberately an integration test across two modules rather than a
unit test of the regex parser alone: db.py's parser and pipeline.py's report
writer must agree on the report's exact text layout, and nothing in either
module's type signature enforces that — only a test exercising both together
would catch one of them drifting (see the Phase 3 commit, which found and
fixed exactly this kind of drift in the original sql_practice parser).
"""

from __future__ import annotations

from pathlib import Path

from mobsec_scan import db
from mobsec_scan.config import Config, Detector
from mobsec_scan.pipeline import ApkResult, format_report


def _cfg(tmp_path: Path) -> Config:
    return Config(
        root=tmp_path,
        apks_dir=tmp_path / "apks",
        results_dir=tmp_path / "results",
        database=tmp_path / "test.db",
        analysis_dir=tmp_path / "analysis",
        detectors={
            "rq4": Detector("rq4", "RQ4 — Internet + PII Permissions", True),
            "rq5": Detector("rq5", "RQ5 — Unused Permissions", True),
            "rq7": Detector("rq7", "RQ7 — Unprotected Exported Activities", True),
        },
    )


def _write_sample_report(cfg: Config) -> None:
    cfg.results_dir.mkdir(parents=True)
    result = ApkResult(
        apk="sample.apk",
        error=None,
        findings={
            "rq4": {
                "found": True,
                "has_internet": True,
                "normal_permissions": ["android.permission.BLUETOOTH"],
                "dangerous_permissions": ["android.permission.CAMERA"],
                "hard_restricted": [],
                "code_locations": {"android.permission.CAMERA": ["Lcom/example/Cam; -> open"]},
                "risk_level": "medium",
                "notes": "INTERNET combined with 1 normal permission(s) and 1 dangerous permission(s).",
            },
            "rq5": {
                "found": True,
                "unused_permissions": ["android.permission.READ_CONTACTS"],
                "used_permissions": ["android.permission.INTERNET"],
                "evidence": {"android.permission.INTERNET": ["Lcom/example/Net; -> fetch"]},
                "total_declared": 3,
                "total_checkable": 2,
                "notes": "1 of 2 checkable permission(s) appear unused.",
            },
            "rq7": {
                "found": True,
                "vulnerable": [
                    {
                        "name": ".LeakyActivity", "type": "activity",
                        "export_how": "explicit (android:exported=true)",
                        "permission": None, "reason": "Exported without a meaningful permission guard.",
                    }
                ],
                "safe_exports": [
                    {"name": ".MainActivity", "type": "activity", "safe_reason": "Has expected public intent action(s): android.intent.action.MAIN"},
                ],
                "totals": {"activity": 2, "service": 0, "receiver": 0, "provider": 0},
                "notes": "1 component(s) exported without meaningful protection (of 2 total). 1 safe-by-design export(s) excluded from count.",
            },
        },
    )
    report = format_report("sample", "sample.apk", result, cfg)
    (cfg.results_dir / "sample_report.txt").write_text(report, encoding="utf-8")


def test_build_database_round_trips_a_real_pipeline_report(tmp_path):
    cfg = _cfg(tmp_path)
    _write_sample_report(cfg)

    summary = db.build_database(cfg.results_dir, cfg.database)

    assert summary == {
        "apps": 1,
        "rq4_scan": 1,
        "rq4_permissions": 2,
        "rq5_scan": 1,
        "rq5_unused_permissions": 1,
        "rq7_scan": 1,
        "rq7_vulnerable_components": 1,
        "skipped": 0,
    }

    import sqlite3

    conn = sqlite3.connect(cfg.database)
    app = conn.execute("SELECT app_name, file_name FROM apps").fetchone()
    assert app == ("sample", "sample.apk")

    rq4 = conn.execute("SELECT has_internet, risk_level FROM rq4_scan").fetchone()
    assert rq4 == (1, "MEDIUM")

    perms = {
        row[0] for row in conn.execute(
            "SELECT permission FROM rq4_permissions WHERE permission_type = 'dangerous'"
        )
    }
    assert perms == {"android.permission.CAMERA"}

    unused = conn.execute("SELECT permission FROM rq5_unused_permissions").fetchone()
    assert unused == ("android.permission.READ_CONTACTS",)

    vuln = conn.execute(
        "SELECT component_type, component_name FROM rq7_vulnerable_components"
    ).fetchone()
    assert vuln == ("activity", ".LeakyActivity")

    safe = conn.execute(
        "SELECT component_name, safe_reason FROM rq7_safe_exports"
    ).fetchone()
    assert safe[0] == ".MainActivity"
    assert "MAIN" in safe[1]

    conn.close()


def test_build_database_skips_files_without_a_header(tmp_path):
    cfg = _cfg(tmp_path)
    cfg.results_dir.mkdir(parents=True)
    (cfg.results_dir / "garbage_report.txt").write_text("not a real report", encoding="utf-8")

    summary = db.build_database(cfg.results_dir, cfg.database)
    assert summary["apps"] == 0
    assert summary["skipped"] == 1


def test_build_database_is_idempotent_full_rebuild(tmp_path):
    cfg = _cfg(tmp_path)
    _write_sample_report(cfg)

    first = db.build_database(cfg.results_dir, cfg.database)
    second = db.build_database(cfg.results_dir, cfg.database)
    assert first == second
