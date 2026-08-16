"""Batch/single-APK orchestration — the ``mobsec scan`` / ``mobsec batch`` engine.

Supersedes ``run_batch_analysis.py``: instead of a hand-edited ``ACTIVE_RQS``
dict, which detectors run comes from ``config.yaml`` (:attr:`Config.active_detectors`),
and progress/errors go through the ``mobsec`` logger instead of bare ``print``.
Resumability is unchanged — an APK is skipped if its ``<stem>_report.txt``
already exists in the results directory.
"""

from __future__ import annotations

import csv
import traceback
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .config import Config
from .detectors import load_detector
from .logging_config import get_logger

logger = get_logger("pipeline")


@dataclass
class ApkResult:
    apk: str
    error: str | None
    findings: dict[str, dict]


def analyze_apk(apk_path: Path, cfg: Config) -> ApkResult:
    """Decompile one APK and run every enabled detector against it."""
    try:
        from androguard.misc import AnalyzeAPK
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError(
            "APK scanning needs androguard, which is an optional extra.\n"
            "Install it with:  pip install -e '.[scan]'"
        ) from exc

    findings: dict[str, dict] = {key: None for key in cfg.active_detectors}
    error: str | None = None

    try:
        apk, d, dx = AnalyzeAPK(str(apk_path))
        dex_list = d if isinstance(d, list) else [d]

        for key in cfg.active_detectors:
            try:
                findings[key] = load_detector(key)(apk, dex_list, dx)
            except Exception as exc:  # noqa: BLE001 - one bad detector shouldn't kill the run
                findings[key] = {"found": False, "error": str(exc), "notes": f"Check failed: {exc}"}
                logger.warning("%s failed on %s: %s", key.upper(), apk_path.name, exc)

    except Exception as exc:  # noqa: BLE001 - decompile failures are per-APK, not fatal
        error = f"{type(exc).__name__}: {exc}"
        logger.error("Could not load %s: %s", apk_path.name, exc)
        logger.debug(traceback.format_exc())

    return ApkResult(apk=apk_path.name, error=error, findings=findings)


# ── Status/found helpers ────────────────────────────────────────────────────

def _found(r: dict | None) -> bool:
    return bool((r or {}).get("found", False))


def _status(r: dict | None, risk: bool = False) -> str:
    if r is None or "error" in r:
        return "ERROR"
    if not r.get("found"):
        return "CLEAN"
    if risk:
        level = r.get("risk_level", "")
        if level == "high":
            return "HIGH RISK"
        if level == "medium":
            return "MEDIUM RISK"
        if level == "low":
            return "LOW RISK"
    return "VULNERABLE"


_RISK_KEYS = {"rq1_2", "rq4"}  # detectors whose "found" carries a risk_level worth surfacing


# ── Per-app report ───────────────────────────────────────────────────────────

def _section_lines(key: str, r: dict | None) -> list[str]:
    lines: list[str] = []
    if r is None:
        lines.append("  Not run.")
        return lines
    if "error" in r:
        lines.append(f"  Status : ERROR — {r['error']}")
        return lines

    lines.append(f"  Status : {_status(r, risk=(key in _RISK_KEYS))}")
    notes = r.get("notes", "")
    if notes:
        lines.append(f"  Notes  : {notes}")

    if key == "rq1_2":
        for kind, title in (("trustmanager", "TrustManager"), ("customhostnameverifier", "HostnameVerifier")):
            items = r.get(kind, [])
            if not items:
                continue
            lines.append(f"  Custom {title} findings ({len(items)}):")
            for f in items:
                naive = f" — {f['naive_note']}" if f.get("naive_note") else ""
                lines.append(f"    [{f['risk']}] {f['class']}{naive}")
    elif key == "rq4":
        lines.append(f"  Internet  : {'YES' if r.get('has_internet') else 'NO'}")
        normal_perms = r.get("normal_permissions", [])
        dangerous_perms = r.get("dangerous_permissions", [])
        hard_restricted = r.get("hard_restricted", [])
        code_locations = r.get("code_locations", {})
        lines.append(f"  Normal permissions found with INTERNET ({len(normal_perms)}):")
        lines += [f"    {p}" for p in normal_perms] or ["    (none)"]
        lines.append(f"  Dangerous permissions found with INTERNET ({len(dangerous_perms)}):")
        if dangerous_perms:
            for p in dangerous_perms:
                flag = "  [HARD RESTRICTED]" if p in hard_restricted else ""
                lines.append(f"    {p}{flag}")
                for loc in code_locations.get(p, []):
                    lines.append(f"        @ {loc}")
        else:
            lines.append("    (none)")
    elif key == "rq5":
        evidence = r.get("evidence", {})
        for p in r.get("unused_permissions", []):
            lines.append(f"    - {p}")
        used = r.get("used_permissions", [])
        if used:
            lines.append(f"  Used permissions ({len(used)}) — call-site evidence for manual review:")
            for p in used:
                lines.append(f"    + {p}")
                for loc in evidence.get(p, []):
                    lines.append(f"        @ {loc}")
    elif key == "rq7":
        for c in r.get("vulnerable", []):
            perm = f"  [permission: {c['permission']}]" if c.get("permission") else ""
            lines.append(f"    [UNPROTECTED {c['type'].upper()}] {c['name']}")
            lines.append(f"      export : {c['export_how']}{perm}")
            lines.append(f"      reason : {c['reason']}")
        safe = r.get("safe_exports", [])
        if safe:
            lines.append(f"    Safe-by-design exports ({len(safe)}):")
            for c in safe:
                lines.append(f"      [{c['type'].upper()}] {c['name']} — {c['safe_reason']}")

    return lines


def format_report(app_name: str, apk_file: str, result: ApkResult, cfg: Config) -> str:
    sep, dash = "=" * 80, "-" * 80
    lines = [
        sep,
        f"APP    : {app_name}",
        f"FILE   : {apk_file}",
        f"DATE   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Checks run: {', '.join(cfg.active_detectors).upper()}",
        sep, "",
    ]
    for key, det in cfg.active_detectors.items():
        lines += [dash, f"[{key.upper()}] {det.label}", dash]
        lines += _section_lines(key, result.findings.get(key))
        lines.append("")
    return "\n".join(lines)


# ── CSV ──────────────────────────────────────────────────────────────────────

def _csv_row(result: ApkResult, cfg: Config) -> dict:
    row = {"app_name": result.apk, "error": result.error or ""}
    for key in cfg.active_detectors:
        r = result.findings.get(key) or {}
        row[f"{key}_found"] = _found(r)
        row[f"{key}_status"] = _status(r, risk=(key in _RISK_KEYS))
        if key == "rq1_2":
            row["rq1_2_high_risk_count"] = sum(
                1 for f in r.get("trustmanager", []) + r.get("customhostnameverifier", []) if f.get("risk") == "HIGH"
            )
        if key == "rq4":
            row["rq4_normal_count"] = len(r.get("normal_permissions", []))
            row["rq4_dangerous_count"] = len(r.get("dangerous_permissions", []))
        if key == "rq5":
            row["rq5_unused_count"] = len(r.get("unused_permissions", []))
        if key == "rq7":
            row["rq7_vulnerable_count"] = len(r.get("vulnerable", []))
            row["rq7_safe_export_count"] = len(r.get("safe_exports", []))
    return row


def _csv_fieldnames(cfg: Config) -> list[str]:
    base = ["app_name"]
    for key in cfg.active_detectors:
        base += [f"{key}_found", f"{key}_status"]
        if key == "rq1_2":
            base.append("rq1_2_high_risk_count")
        if key == "rq4":
            base += ["rq4_normal_count", "rq4_dangerous_count"]
        if key == "rq5":
            base.append("rq5_unused_count")
        if key == "rq7":
            base += ["rq7_vulnerable_count", "rq7_safe_export_count"]
    base.append("error")
    return base


# ── Flagged summary ──────────────────────────────────────────────────────────

def write_flagged(results: list[ApkResult], cfg: Config, out_path: Path) -> None:
    total = len(results)
    with out_path.open("w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("  Android APK Security Analysis — Flagged Findings\n")
        f.write(f"  Generated     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Apps analyzed : {total}\n")
        f.write(f"  Checks run    : {', '.join(cfg.active_detectors).upper()}\n")
        f.write("=" * 70 + "\n\n")

        f.write("── SUMMARY ──────────────────────────────────────────────────────\n")
        for key, det in cfg.active_detectors.items():
            count = sum(1 for r in results if _found(r.findings.get(key)))
            pct = 100 * count / total if total else 0
            f.write(f"  {det.label:<55}  {count:>3}/{total}  ({pct:.1f}%)\n")
        errors = [r for r in results if r.error]
        f.write(f"\n  Errors: {len(errors)}\n\n")

        for key, det in cfg.active_detectors.items():
            flagged = [r for r in results if _found(r.findings.get(key))]
            f.write(f"── {det.label} ({len(flagged)} apps) ──\n")
            for r in flagged:
                notes = (r.findings.get(key) or {}).get("notes", "")
                f.write(f"  • {r.apk}\n")
                if notes:
                    f.write(f"    {notes}\n")
            f.write("\n")

        if errors:
            f.write("── ERRORS ───────────────────────────────────────────────────────\n")
            for r in errors:
                f.write(f"  • {r.apk}: {r.error}\n")

    logger.info("Flagged report → %s", out_path)


# ── Batch driver ─────────────────────────────────────────────────────────────

def run_batch(cfg: Config, apks_dir: Path | None = None, limit: int | None = None) -> list[ApkResult]:
    apks_dir = apks_dir or cfg.apks_dir
    results_dir = cfg.results_dir
    results_dir.mkdir(parents=True, exist_ok=True)

    apk_files = sorted(apks_dir.glob("*.apk"))
    if limit:
        apk_files = apk_files[:limit]

    if not apk_files:
        logger.error("No APKs found in %s", apks_dir)
        return []

    remaining = [a for a in apk_files if not (results_dir / f"{a.stem}_report.txt").exists()]
    logger.info(
        "Found %d APK(s) — %d already done, %d to process. Checks: %s",
        len(apk_files), len(apk_files) - len(remaining), len(remaining),
        ", ".join(cfg.active_detectors).upper(),
    )

    new_results: list[ApkResult] = []
    for i, apk_path in enumerate(apk_files, 1):
        report_path = results_dir / f"{apk_path.stem}_report.txt"
        if report_path.exists():
            logger.debug("[%3d/%d] %s — skipped", i, len(apk_files), apk_path.name)
            continue

        logger.info("[%3d/%d] %s ...", i, len(apk_files), apk_path.name)
        result = analyze_apk(apk_path, cfg)
        report_path.write_text(format_report(apk_path.stem, apk_path.name, result, cfg), encoding="utf-8")
        new_results.append(result)
        logger.info("  -> %s", "ERROR" if result.error else "done")

    if new_results:
        csv_path = results_dir / "summary.csv"
        write_mode = "a" if csv_path.exists() else "w"
        fields = _csv_fieldnames(cfg)
        with csv_path.open(write_mode, newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            if write_mode == "w":
                writer.writeheader()
            writer.writerows([_csv_row(r, cfg) for r in new_results])
        logger.info("CSV → %s", csv_path)
        write_flagged(new_results, cfg, results_dir / "flagged.txt")

    return new_results
