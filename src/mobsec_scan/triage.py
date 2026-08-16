"""AI-assisted true/false-positive triage of findings already in the database.

Automates the step the README describes as manual today ("copy/paste into
Gemini"): read findings out of the tables `db.py` populates, ask a Gemini
model the same fixed question for each one, and record the verdict in
`triage_results`. Resumable — a finding already present in `triage_results`
(unique on ``(rq, finding_ref)``) is skipped on the next run, same pattern as
`pipeline.run_batch`'s skip-if-report-exists.

One "finding" per detector is the unit a human would actually review:

* RQ4 — one per app whose INTERNET+permission combination was flagged
  (a row in ``rq4_scan`` with ``risk_level != 'NONE'``), not one per permission.
* RQ5 — one per declared-but-unused permission (a row in ``rq5_unused_permissions``).
* RQ7 — one per unprotected exported component (a row in ``rq7_vulnerable_components``).
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from .config import Config
from .logging_config import get_logger

logger = get_logger("triage")


@dataclass
class Finding:
    app_id: int
    rq: str
    finding_ref: str
    description: str


# ── Pulling un-triaged findings out of the DB ───────────────────────────────

def _pending_rq4(conn: sqlite3.Connection) -> list[Finding]:
    rows = conn.execute(
        """
        SELECT s.app_id, a.app_name, s.risk_level, s.notes
        FROM rq4_scan s
        JOIN apps a ON a.app_id = s.app_id
        WHERE s.risk_level != 'NONE'
          AND NOT EXISTS (
              SELECT 1 FROM triage_results t
              WHERE t.rq = 'rq4' AND t.finding_ref = 'rq4_scan:' || s.app_id
          )
        """
    ).fetchall()
    findings = []
    for app_id, app_name, risk_level, notes in rows:
        perms = conn.execute(
            "SELECT permission FROM rq4_permissions WHERE app_id = ? AND permission_type = 'dangerous'",
            (app_id,),
        ).fetchall()
        perm_list = ", ".join(p[0] for p in perms) or "(none listed)"
        description = (
            f"App '{app_name}' declares the INTERNET permission alongside dangerous "
            f"permissions: {perm_list}. Automated risk level: {risk_level}. "
            f"Scanner notes: {notes or '(none)'}"
        )
        findings.append(Finding(app_id, "rq4", f"rq4_scan:{app_id}", description))
    return findings


def _pending_rq5(conn: sqlite3.Connection) -> list[Finding]:
    rows = conn.execute(
        """
        SELECT u.id, u.app_id, a.app_name, u.permission
        FROM rq5_unused_permissions u
        JOIN apps a ON a.app_id = u.app_id
        WHERE NOT EXISTS (
            SELECT 1 FROM triage_results t
            WHERE t.rq = 'rq5' AND t.finding_ref = 'rq5_unused_permissions:' || u.id
        )
        """
    ).fetchall()
    findings = []
    for finding_id, app_id, app_name, permission in rows:
        description = (
            f"App '{app_name}' declares permission '{permission}' in its manifest, "
            "but the static scanner found no API call site in the app's own code "
            "that would explain why it's needed. It may be used by a bundled "
            "third-party SDK instead of app code directly."
        )
        findings.append(Finding(app_id, "rq5", f"rq5_unused_permissions:{finding_id}", description))
    return findings


def _pending_rq7(conn: sqlite3.Connection) -> list[Finding]:
    rows = conn.execute(
        """
        SELECT v.id, v.app_id, a.app_name, v.component_type, v.component_name,
               v.export_type, v.reason
        FROM rq7_vulnerable_components v
        JOIN apps a ON a.app_id = v.app_id
        WHERE NOT EXISTS (
            SELECT 1 FROM triage_results t
            WHERE t.rq = 'rq7' AND t.finding_ref = 'rq7_vulnerable_components:' || v.id
        )
        """
    ).fetchall()
    findings = []
    for finding_id, app_id, app_name, component_type, component_name, export_type, reason in rows:
        description = (
            f"App '{app_name}' exports a {component_type} ('{component_name}') "
            f"via {export_type or 'an unspecified mechanism'} without a permission guard. "
            f"Scanner reason: {reason or '(none given)'}"
        )
        findings.append(
            Finding(app_id, "rq7", f"rq7_vulnerable_components:{finding_id}", description)
        )
    return findings


_PENDING_FETCHERS = {"rq4": _pending_rq4, "rq5": _pending_rq5, "rq7": _pending_rq7}


def pending_findings(conn: sqlite3.Connection) -> list[Finding]:
    findings: list[Finding] = []
    for fetch in _PENDING_FETCHERS.values():
        findings.extend(fetch(conn))
    return findings


# ── Gemini call ──────────────────────────────────────────────────────────────

_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


def build_prompt(base_prompt: str, finding: Finding) -> str:
    return f"{base_prompt}\nFinding:\n{finding.description}\n"


def _parse_verdict(text: str) -> dict:
    match = _JSON_RE.search(text)
    if not match:
        raise ValueError(f"No JSON object found in model response: {text!r}")
    data = json.loads(match.group(0))
    verdict = str(data.get("verdict", "")).upper()
    if verdict not in ("TP", "FP"):
        raise ValueError(f"Unexpected verdict {verdict!r} in response: {text!r}")
    return {
        "verdict": verdict,
        "confidence": data.get("confidence"),
        "rationale": data.get("rationale", ""),
    }


def _call_with_retry(client, model: str, prompt: str, max_retries: int, backoff_seconds: int) -> dict:
    last_exc: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            resp = client.models.generate_content(model=model, contents=prompt)
            return _parse_verdict(resp.text)
        except Exception as exc:  # noqa: BLE001 - retry on any transient API/parse error
            last_exc = exc
            logger.warning("Attempt %d/%d failed: %s", attempt, max_retries, exc)
            if attempt < max_retries:
                time.sleep(backoff_seconds * attempt)
    raise RuntimeError(f"Gemini call failed after {max_retries} attempts") from last_exc


# ── Driver ───────────────────────────────────────────────────────────────────

def run_triage(cfg: Config, limit: int | None = None, dry_run: bool = False) -> dict[str, int]:
    conn = sqlite3.connect(cfg.database)
    findings = pending_findings(conn)
    if limit:
        findings = findings[:limit]

    logger.info("%d finding(s) pending triage", len(findings))
    base_prompt = cfg.triage.get("prompt", "").strip()
    model = cfg.triage.get("model", "gemini-flash-latest")
    max_retries = int(cfg.triage.get("max_retries", 4))
    backoff_seconds = int(cfg.triage.get("retry_backoff_seconds", 5))

    if dry_run:
        for f in findings:
            _print_prompt(build_prompt(base_prompt, f))
        conn.close()
        return {"pending": len(findings), "triaged": 0, "failed": 0}

    if not findings:
        conn.close()
        return {"pending": 0, "triaged": 0, "failed": 0}

    api_key = cfg.gemini_api_key
    if not api_key:
        conn.close()
        raise RuntimeError("GEMINI_API_KEY is not set. Add it to .env and try again.")

    from google import genai

    client = genai.Client(api_key=api_key)

    triaged = 0
    failed = 0
    for i, finding in enumerate(findings, 1):
        prompt = build_prompt(base_prompt, finding)
        logger.info("[%d/%d] %s ...", i, len(findings), finding.finding_ref)
        try:
            result = _call_with_retry(client, model, prompt, max_retries, backoff_seconds)
        except Exception as exc:  # noqa: BLE001 - one bad finding shouldn't kill the run
            logger.error("Giving up on %s: %s", finding.finding_ref, exc)
            failed += 1
            continue

        conn.execute(
            "INSERT INTO triage_results (app_id, rq, finding_ref, verdict, confidence, rationale, model, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                finding.app_id, finding.rq, finding.finding_ref,
                result["verdict"], result["confidence"], result["rationale"], model,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
        triaged += 1

    conn.close()
    return {"pending": len(findings), "triaged": triaged, "failed": failed}


def _print_prompt(text: str) -> None:
    """Print without importing typer — triage.py has no CLI-framework dependency."""
    print(text)
    print("-" * 80)
